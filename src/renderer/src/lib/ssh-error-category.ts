// A stable machine-readable key for the free-text SSH error, so triage keeps a
// bucket even after `scrubDiagnosticText` eats the hostname the message names.
//
// Why a local copy of the fragment tables rather than importing
// `src/main/ssh/ssh-reconnect-error-classification.ts`: that module exposes
// only booleans (no category), and it is not in `config/tsconfig.tc.web.json`'s
// include list — it reaches `ssh-connection-utils` and from there the `ssh2`
// graph, so importing it would mean widening the web program.

export type SshErrorCategory =
  | 'dns'
  | 'refused'
  | 'timeout'
  | 'unreachable'
  | 'reset'
  | 'auth'
  | 'passphrase'
  | 'host-key'
  | 'key-file'
  | 'relay'
  | 'other'

// First match wins, so the specific buckets precede the general ones.
const CATEGORY_FRAGMENTS: { category: SshErrorCategory; fragments: string[] }[] = [
  {
    category: 'dns',
    fragments: [
      'enotfound',
      'eai_again',
      'could not resolve hostname',
      'nodename nor servname',
      'name or service not known',
      'temporary failure in name resolution'
    ]
  },
  { category: 'passphrase', fragments: ['passphrase', 'encrypted key', 'bad decrypt'] },
  {
    category: 'host-key',
    fragments: [
      'host key verification failed',
      'remote host identification has changed',
      'known_hosts',
      'host key for',
      'no matching host key type'
    ]
  },
  {
    category: 'auth',
    fragments: [
      'permission denied',
      'authentication failed',
      'all configured authentication methods failed',
      'too many authentication failures',
      'publickey'
    ]
  },
  { category: 'refused', fragments: ['econnrefused', 'connection refused'] },
  {
    category: 'unreachable',
    fragments: [
      'ehostunreach',
      'enetunreach',
      'no route to host',
      'network is unreachable',
      'network is down',
      'host is down'
    ]
  },
  {
    category: 'timeout',
    fragments: ['etimedout', 'timed out', 'operation timed out', 'timeout']
  },
  {
    category: 'reset',
    fragments: [
      'econnreset',
      'epipe',
      'connection reset',
      'broken pipe',
      'lost connection',
      'remote end closed',
      'connection closed by remote',
      'kex_exchange_identification',
      'ssh_exchange_identification'
    ]
  },
  { category: 'key-file', fragments: ['bad permissions', 'load key', 'no such file'] },
  { category: 'relay', fragments: ['relay'] }
]

/** Classify from the RAW error, before scrubbing — redaction must not move the bucket. */
export function classifySshErrorCategory(error: unknown): SshErrorCategory | null {
  if (typeof error !== 'string' || error.length === 0) {
    return null
  }
  const message = error.toLowerCase()
  for (const { category, fragments } of CATEGORY_FRAGMENTS) {
    if (fragments.some((fragment) => message.includes(fragment))) {
      return category
    }
  }
  return 'other'
}
