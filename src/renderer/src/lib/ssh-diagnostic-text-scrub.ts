// The capture-side scrub for the copy-diagnostics payload. Deliberately NOT in
// `src/shared/observability-redactor.ts`: that module is a *secrets* scrubber
// whose own comment keeps hosts for debug context, and three other lanes
// (tracer sink-write, bundle collection, server ingest) depend on that
// contract. §7's "dropped entirely" list is this pass's job.
//
// Accepted cost: the FQDN rule also eats non-identifying tokens (`github.com`,
// `openssh.com`, `repo.git`). That is the correct side of the trade for a
// payload designed to be pasted into a public issue tracker. It is narrowed
// only where the dotted token IS the diagnosis and no host can be confused for
// it: a source/config filename, an RPC method inside the `Request "…"` template
// (`Request "<host>" timed out` is unfileable), and a stack frame's qualified
// function name.
//
// Every rule emits a typed placeholder rather than deleting the span, so the
// error grammar survives (`connect ECONNREFUSED <ip>:22`) and stays triageable.
// Placeholders contain `<` and `>`, which every rule's character class excludes
// (the prose rules instead replay the same placeholder) — that is what keeps
// the whole pass idempotent.
import { redactString } from '../../../shared/observability-redactor'

/** Free text is redacted first, then cut — see `scrubDiagnosticText`. */
export const MAX_FREE_TEXT_CHARS = 512

const PATH_PLACEHOLDER = '<path>'
const HOST_PLACEHOLDER = '<host>'
const IP_PLACEHOLDER = '<ip>'

// A word that may continue a spaced path segment. No `~` or `/`, so a trailing
// `… and ~/bin/ssh` cannot be swallowed into the preceding path.
const SPACED = String.raw`(?: [A-Za-z0-9._$&()+-]+)*`
const NO_SEP = String.raw`[^\s'"\`<>|\\/]`
const NO_SPACE = String.raw`[^\s'"\`<>|]`
// A segment of a spaced path. Excludes `:` so OpenSSH's own verdict survives:
// `…\id_rsa: bad permissions` keeps the ": bad permissions".
const SEGMENT = String.raw`[^\s'"\`<>|\\/:]`
// Any segment may carry spaces, *including the last* — a space-free terminal is
// what republished `/Users/John Smith` as `<path> Smith`.
const SPACED_BODY = String.raw`(?:${SEGMENT}+${SPACED}[\\/])*(?:${SEGMENT}+${SPACED})?`

const PATH_PATTERNS: RegExp[] = [
  // A quoted span opening on a path root is a path in full, spaces included —
  // the only reliable way to keep `"C:\Users\John Smith\…"` from splitting at
  // the space and publishing the surname in the surviving tail.
  /(['"])(?:[A-Za-z]:[\\/]|\\\\|~|\/)[^'"\n]*\1/g,
  // UNC. Interior segments may carry spaces; the tail may not, so trailing
  // prose stays out. `(?![\\/])` stops a spaced run from eating `… \\other`.
  new RegExp(
    String.raw`\\\\[A-Za-z0-9._$-]+[\\/](?:${NO_SEP}+${SPACED}[\\/](?![\\/]))*${NO_SPACE}*`,
    'g'
  ),
  // Every drive root, not only `Users` / `Documents and Settings`: a corporate
  // mapped home (`E:\Home Dirs\jsmith`) carries the same names.
  new RegExp(String.raw`\b[A-Za-z]:[\\/]${SPACED_BODY}`, 'g'),
  // `.\keys\Jane Smith\id_rsa` — a relative path names people too. The
  // lookbehind keeps `v18.1/x` and `1.5/2` out.
  new RegExp(String.raw`(?<![\w.])\.{1,2}[\\/]${SPACED_BODY}`, 'g'),
  // POSIX profile roots, same reasoning as the drive rule.
  new RegExp(String.raw`\/(?:Users|home|Volumes|mnt|media)\/${SPACED_BODY}`, 'g'),
  // The account name is inside the match: `~jane.doe/` leaks it otherwise.
  /~[A-Za-z0-9._-]*(?:\/[A-Za-z0-9._~@%+-]*)+/g,
  // Two segments minimum and an alphabetic first segment, so `and/or`,
  // `ratio 1/2/3`, and `2026/08/04` are left intact.
  /\/{1,3}[A-Za-z._~][A-Za-z0-9._~@%+-]*(?:\/[A-Za-z0-9._~@%+-]*)+/g
]

const FINGERPRINT_PATTERNS: RegExp[] = [
  /\bMD5:(?:[0-9a-f]{2}:){5,}[0-9a-f]{2}/gi,
  /\b(?:SHA512|SHA256|SHA1|MD5):[A-Za-z0-9+/=]{20,}/g
]

// Keeps the scheme (diagnostic) and drops the authority (the identifier). Runs
// before the path rules, which would otherwise mangle it into `https:<path>`.
// The scheme is length-bounded for the same reason `USER_AT_HOST` is: greedy and
// unbounded, it rescans a dotted `.x.x.x…` error to the end from every offset.
const URL_PATTERN = /\b([A-Za-z][A-Za-z0-9+.-]{0,15}):\/\/([^\s'"`<>|/]+)([^\s'"`<>|]*)/g

// Before the bare-host rule so `user@host` collapses as one span. Both halves
// carry their RFC length bound: an unbounded local part rescans to end-of-string
// from every offset in an error that holds no `@` at all.
const USER_AT_HOST = /[A-Za-z0-9._%+~$-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?/g

const IP_PATTERNS: RegExp[] = [
  /\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
  // Two colon groups minimum, so a bracketed `[12:00]` timestamp is not an IP.
  /\[[0-9A-Fa-f.]{0,4}(?::[0-9A-Fa-f.]{0,4}){2,7}\]/g,
  /(?<![\w:.])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![\w:])/g,
  /(?<![\w:.])(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?(?![\w:])/g
]

// Label and depth bounds are DNS's own (63 chars, and nothing sane is 12 deep).
// They also keep the match linear: an unbounded `*` here makes a pathological
// `.x.x.x…` error quadratic in a synchronous click handler.
const FQDN = /\b[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,12}\.[A-Za-z]{2,63}\b/g

// Final labels that name a file, not a host. Ambiguous ccTLDs (`sh`, `io`, `md`,
// `cc`, `co`, `me`, `tv`, `ai`, `zip`, `dev`, `app`) are deliberately absent —
// a host wins the tie in a payload that has to be safe to paste.
const FILE_EXTENSIONS = new Set([
  'bak',
  'bat',
  'bz2',
  'cfg',
  'cmd',
  'conf',
  'cpp',
  'crt',
  'csr',
  'css',
  'csv',
  'dll',
  'dylib',
  'env',
  'exe',
  'gif',
  'gz',
  'hpp',
  'htm',
  'html',
  'ini',
  'jpeg',
  'jpg',
  'js',
  'json',
  'jsonc',
  'jsx',
  'key',
  'lock',
  'log',
  'map',
  'mjs',
  'cjs',
  'msi',
  'node',
  'pem',
  'pid',
  'plist',
  'png',
  'ps1',
  'pub',
  'py',
  'rb',
  'scss',
  'snap',
  'sock',
  'sql',
  'svg',
  'tgz',
  'tmp',
  'toml',
  'ts',
  'tsx',
  'txt',
  'wasm',
  'xml',
  'xz',
  'yaml',
  'yml'
])

// `pty.open` and `acme.com` are indistinguishable on their own, so the two
// exemptions below key on the surrounding template, not on the token. A quoted
// `'db.internal'` outside those templates is still a host.
const REQUEST_CARRIER = 'Request "'
// Anchored on the newline + indent a V8 frame always has, so a mid-sentence
// `failed at gitlab.acme.com (retry)` is still a host.
const FRAME_CARRIER = /[\r\n][ \t]{1,20}at $/
const FRAME_CARRIER_WINDOW = 24
// No hyphen and no leading digit — the two things a code identifier cannot have
// and a hostname routinely does.
const DOTTED_IDENTIFIER = /^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+$/

function namesCodeNotAHost(match: string, offset: number, text: string): boolean {
  if (FILE_EXTENSIONS.has(match.slice(match.lastIndexOf('.') + 1).toLowerCase())) {
    return true
  }
  if (!DOTTED_IDENTIFIER.test(match)) {
    return false
  }
  const end = offset + match.length
  // `Request "pty.open" timed out` — the method name IS the diagnosis
  // (ssh-channel-multiplexer.ts:56).
  if (
    text.slice(Math.max(0, offset - REQUEST_CARRIER.length), offset) === REQUEST_CARRIER &&
    text.startsWith('"', end)
  ) {
    return true
  }
  // A V8 frame's qualified function name: `at SshChannelMultiplexer.request (…)`.
  return (
    FRAME_CARRIER.test(text.slice(Math.max(0, offset - FRAME_CARRIER_WINDOW), offset)) &&
    text.startsWith(' (', end)
  )
}

// Non-ASCII is in the class so an IDN host does not pass whole.
const HOST_CHARS = String.raw`A-Za-z0-9\u0080-\uFFFF`
const HOST_LABEL = String.raw`[${HOST_CHARS}](?:[${HOST_CHARS}._-]{0,253}[${HOST_CHARS}])?`
// OpenSSH quotes the host as often as it does not.
const QUOTED_OR_BARE = String.raw`(?:'[^'\n]{0,255}'|"[^"\n]{0,255}"|${HOST_LABEL})`
// Words that follow a carrier phrase in OpenSSH prose and name no host —
// `Connection reset by peer` and `Host key verification failed` are diagnoses,
// not identifiers. The trailing lookahead makes the word have to *be* the whole
// token, so a host actually called `a-host` or `not-prod` is still redacted.
const NOT_A_HOST = String.raw`(?:key|keys|identification|name|is|was|are|has|have|not|and|or|for|the|a|an|this|your|our|address|port|peer|remote|user|users|server|authenticating|IP)(?![^\s.,:;!?])`

// The config alias / label carrier: `ssh-connection-manager.ts` interpolates
// `target.label` into this exact sentence. A label is free-form user text —
// spaces included — so only its fixed surrounding phrase makes it findable, and
// it has to run before the single-token carriers below.
const LABEL_IN_PROSE = /\b(Connection to )(.+?)( is already in progress)/gi

// Single-label hosts and config aliases (`Could not resolve hostname prod-db-01`)
// have no shape of their own, so they are only reachable through the fixed prose
// that names them. Each carrier states its own phrase: the previous single rule
// anchored on a bare `host`/`hostname` word and therefore needed a
// digit/dot/hyphen lookahead to spare `Host key verification failed` — which let
// `devbox`, `nas`, and every `Permanently added '…'` through. Order matters:
// the specific carriers must consume their host before the bare `host` rule
// sees the phrase.
const HOST_IN_PROSE: readonly (readonly [RegExp, string])[] = [
  // `ssh: Could not resolve hostname bastion: Name or service not known`
  [
    new RegExp(String.raw`\b(hostname[ \t]+)(?!${NOT_A_HOST})(${HOST_LABEL})`, 'gi'),
    `$1${HOST_PLACEHOLDER}`
  ],
  // `getaddrinfo ENOTFOUND buildbox`
  [
    new RegExp(String.raw`\b((?:ENOTFOUND|EAI_AGAIN|EAI_NONAME)[ \t]+)(${HOST_LABEL})`, 'g'),
    `$1${HOST_PLACEHOLDER}`
  ],
  // `Connection closed by nas port 22`. `remote host` is the anonymous form.
  [
    new RegExp(
      String.raw`\b(Connection (?:closed|reset|refused) by[ \t]+)(?!${NOT_A_HOST})(${HOST_LABEL})`,
      'gi'
    ),
    `$1${HOST_PLACEHOLDER}`
  ],
  // `Connection to prod-db closed by remote host.`
  [
    new RegExp(String.raw`\b(Connection to[ \t]+)(?!${NOT_A_HOST})(${HOST_LABEL})`, 'gi'),
    `$1${HOST_PLACEHOLDER}`
  ],
  // `Warning: Permanently added 'prod-db-01' (ED25519) to the list of known hosts.`
  [
    new RegExp(String.raw`\b(Permanently added[ \t]+)(?!${NOT_A_HOST})${QUOTED_OR_BARE}`, 'gi'),
    `$1${HOST_PLACEHOLDER}`
  ],
  // `Host key for prod-db-01 has changed and you have requested strict checking.`
  [
    new RegExp(String.raw`\b(host key for[ \t]+)(?!${NOT_A_HOST})${QUOTED_OR_BARE}`, 'gi'),
    `$1${HOST_PLACEHOLDER}`
  ],
  // `Connection closed by authenticating user root 10.0.0.5 port 22` — sshd
  // names the account, and §7 drops usernames as well as hosts.
  [
    new RegExp(String.raw`\b((?:invalid|authenticating) user[ \t]+)(${HOST_LABEL})`, 'gi'),
    '$1<user>'
  ],
  // `ssh: connect to host devbox port 22: Connection refused`, and whatever
  // other prose puts a name straight after the word.
  [
    new RegExp(String.raw`\b(host[ \t]+)(?!${NOT_A_HOST})(${HOST_LABEL})`, 'gi'),
    `$1${HOST_PLACEHOLDER}`
  ]
]

/** Replace POSIX / Windows-drive / UNC / `~` / relative / quoted paths with a placeholder. Idempotent. */
export function redactPaths(input: string): string {
  let out = input
  for (const pattern of PATH_PATTERNS) {
    out = out.replace(pattern, PATH_PLACEHOLDER)
  }
  return out
}

/**
 * Drop every §7 identifier the free-text error can carry: host-key
 * fingerprints, `user@host`, IPs, FQDNs, single-label hosts named by OpenSSH
 * prose, and paths. Order is load-bearing — fingerprints before the path rules
 * (a base64 digest contains `/`), URLs before them too, `user@host` before the
 * bare-host rule, and the spaced-label carrier before the single-token ones.
 * Idempotent.
 */
export function redactSshIdentifiers(input: string): string {
  let out = input
  for (const pattern of FINGERPRINT_PATTERNS) {
    out = out.replace(pattern, '<fingerprint>')
  }
  out = out.replace(URL_PATTERN, (_match, scheme: string, authority: string, rest: string) => {
    const host = authority.includes('@') ? `<user>@${HOST_PLACEHOLDER}` : HOST_PLACEHOLDER
    return `${scheme}://${host}${rest ? PATH_PLACEHOLDER : ''}`
  })
  out = redactPaths(out)
  out = out.replace(USER_AT_HOST, `<user>@${HOST_PLACEHOLDER}`)
  for (const pattern of IP_PATTERNS) {
    out = out.replace(pattern, IP_PLACEHOLDER)
  }
  out = out.replace(FQDN, (match: string, offset: number, text: string) =>
    namesCodeNotAHost(match, offset, text) ? match : HOST_PLACEHOLDER
  )
  out = out.replace(LABEL_IN_PROSE, `$1${HOST_PLACEHOLDER}$3`)
  for (const [pattern, replacement] of HOST_IN_PROSE) {
    out = out.replace(pattern, replacement)
  }
  return out
}

// Slicing UTF-16 code units can strand a high surrogate, which `JSON.stringify`
// then emits as a lone `\ud83d` in the pasted payload.
function truncateFreeText(text: string): string {
  if (text.length <= MAX_FREE_TEXT_CHARS) {
    return text
  }
  let end = MAX_FREE_TEXT_CHARS - 1
  const lastCode = text.charCodeAt(end - 1)
  if (lastCode >= 0xd8_00 && lastCode <= 0xdb_ff) {
    end -= 1
  }
  return `${text.slice(0, end)}…`
}

/**
 * The one scrub every free-text field takes. Order is load-bearing: several
 * redactor rules match a whole span and the PEM rule is anchored on its
 * `-----END` terminator, so truncating first would strand the head of a key.
 */
export function scrubDiagnosticText(input: string): string {
  return truncateFreeText(redactSshIdentifiers(redactString(input)))
}

/** First line only — OpenSSH stderr is routinely multi-line, and CRLF-terminated on Windows. */
export function firstLine(text: string): string {
  return text.split(/\r?\n/)[0] ?? ''
}
