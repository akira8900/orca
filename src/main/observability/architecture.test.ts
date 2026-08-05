// Architectural-invariant test (telemetry-error-tracking.md §Architecture):
//
//   "Nothing in `src/main/telemetry/` imports from `src/main/observability/`
//    or vice versa. The two lanes never share a code path."
//
// Cross-contamination is the failure mode the entire two-lane split is
// counter-designed against. oxlint's plugin set does not include
// `import-x`, and adding eslint just for this rule is a heavier lift than
// the rule warrants. A vitest test that grep-scans the two directories is
// adequate, runs in <50 ms, and fails CI loudly if a future PR adds the
// wrong import.
//
// What it catches:
//   - any `from '../observability'` / `from '../observability/...'` inside
//     `src/main/telemetry/`
//   - any `from '../telemetry'` / `from '../telemetry/...'` inside
//     `src/main/observability/`
//   - the same with deeper relative paths (`../../observability/...`)
//   - the same with absolute-from-src forms if anyone introduces them
//   - a `src/shared/observability-*.ts` file importing *either* lane. The
//     redactor lives in `src/shared/` so the renderer can import it, which puts
//     it outside both lane directories; without this root it is a free
//     smuggling route between the lanes.
//   - `src/shared/observability-redactor.ts` growing any import at all. Zero
//     imports is what keeps it renderer-safe, and it is also what makes the
//     lane-neutrality above hold transitively.
//   - any `src/shared/observability-*.ts` module reaching for a Node-only API.
//     The checks are keyed on the prefix rather than on the one filename, so a
//     second shared observability module inherits them instead of arriving
//     uncovered.
//
// Specifiers are resolved to repo-relative paths and matched on the `main/<lane>`
// path segments rather than by substring, so `src/main/telemetry/` importing the
// lane-neutral `'../../shared/observability-redactor'` is allowed — that spec
// contains the word but resolves outside the observability lane.
//
// What it does NOT catch:
//   - `import()` / `require()` with a computed (non-literal) specifier —
//     only a literal string is visible to a regex scan. Neither lane builds
//     specifiers at runtime.
//   - re-exports through a third module. The simplest workaround
//     (re-export `observability` from a "neutral" module) is the same
//     anti-pattern this test is preventing; reviewers should reject it.
//
// Both directions of the rule are checked symmetrically — the asymmetric
// alternative (only one-way) leaves the door open to a `setOptIn` →
// `bundle` callback chain that smuggles consent state across the boundary.

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { describe, expect, it } from 'vitest'

const REPO_ROOT = join(__dirname, '..', '..', '..')
const TELEMETRY_DIR = join(REPO_ROOT, 'src', 'main', 'telemetry')
const OBSERVABILITY_DIR = join(REPO_ROOT, 'src', 'main', 'observability')
const SHARED_DIR = join(REPO_ROOT, 'src', 'shared')
const SHARED_REDACTOR = join(SHARED_DIR, 'observability-redactor.ts')

// Match `from '<path>'`, `from "<path>"`, side-effect `import '<path>'`, dynamic
// `import('<path>')` and `require('<path>')`. The `<path>` capture is what we
// inspect. Side-effect imports count: a lane module's side effects are exactly
// what the isolation rule exists to keep out.
const IMPORT_RE = /\b(?:from|import|require)\s*\(?\s*(['"])([^'"]+)\1/g

// Non-global: `test` on a /g regex is stateful across calls.
const NODE_ONLY_APIS: { name: string; re: RegExp }[] = [
  { name: 'process', re: /\bprocess\s*\./ },
  { name: 'require', re: /\brequire\s*\(/ },
  { name: '__dirname/__filename', re: /\b__(?:dirname|filename)\b/ },
  { name: 'Buffer', re: /\bBuffer\b/ },
  { name: 'node: builtin', re: /['"]node:/ },
  { name: 'import.meta', re: /\bimport\s*\.\s*meta\b/ }
]

function listTsFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      out.push(...listTsFiles(full))
    } else if (entry.endsWith('.ts') || entry.endsWith('.tsx')) {
      out.push(full)
    }
  }
  return out
}

/** The `src/shared/observability-*` files — lane-neutral by contract, so they get scanned too. */
function listSharedObservabilityFiles(): string[] {
  return readdirSync(SHARED_DIR)
    .filter((entry) => /^observability-.*\.tsx?$/.test(entry))
    .map((entry) => join(SHARED_DIR, entry))
}

function importSpecifiers(text: string): string[] {
  return [...text.matchAll(IMPORT_RE)].map((m) => m[2])
}

/** Relative specs resolve to a real repo path; bare/aliased ones are read as written so absolute-from-src forms still trip. */
function specifierSegments(file: string, spec: string): string[] {
  const path = spec.startsWith('.')
    ? relative(REPO_ROOT, resolve(dirname(file), spec))
    : spec.replace(/^@/, '')
  return path.split(sep).join('/').split('/')
}

type Lane = 'telemetry' | 'observability'

function importsLane(file: string, spec: string, forbiddenLane: Lane): boolean {
  const segments = specifierSegments(file, spec)
  return segments.some((seg, i) => seg === 'main' && segments[i + 1] === forbiddenLane)
}

function findOffendingImports(file: string, forbiddenLane: Lane): string[] {
  const specs = importSpecifiers(readFileSync(file, 'utf8'))
  return specs.filter((spec) => importsLane(file, spec, forbiddenLane))
}

describe('architectural invariant — telemetry / observability lane isolation', () => {
  it('no file in src/main/telemetry/ imports from observability', () => {
    const files = listTsFiles(TELEMETRY_DIR)
    expect(files.length).toBeGreaterThan(0) // sanity: directory exists
    const violations = files.flatMap((f) => {
      const bad = findOffendingImports(f, 'observability')
      return bad.map((spec) => `${relative(REPO_ROOT, f)}: imports '${spec}'`)
    })
    expect(violations, violations.join('\n')).toEqual([])
  })

  it('scopes the match to the lane directory, not the word "observability"', () => {
    // The shared redactor is lane-neutral: importing it is legitimate, importing the lane is not.
    const telemetryFile = join(TELEMETRY_DIR, 'consent.ts')
    expect(importsLane(telemetryFile, '../../shared/observability-redactor', 'observability')).toBe(
      false
    )
    expect(importsLane(telemetryFile, '../observability/bundle', 'observability')).toBe(true)
    expect(importsLane(telemetryFile, 'src/main/observability/bundle', 'observability')).toBe(true)
  })

  it('no file in src/main/observability/ imports from telemetry', () => {
    const files = listTsFiles(OBSERVABILITY_DIR)
    expect(files.length).toBeGreaterThan(0)
    const violations = files.flatMap((f) => {
      // Allow this very file — its header quotes example specifiers, and the
      // whitelist is one specific filename rather than a directory exemption.
      if (f.endsWith('architecture.test.ts')) {
        return []
      }
      const bad = findOffendingImports(f, 'telemetry')
      return bad.map((spec) => `${relative(REPO_ROOT, f)}: imports '${spec}'`)
    })
    expect(violations, violations.join('\n')).toEqual([])
  })

  // Both lanes, not just telemetry: `shared` is outside either directory, so a
  // shared file importing *either* one is a route between them.
  it('no src/shared/observability-* file imports from either lane', () => {
    const files = listSharedObservabilityFiles()
    expect(files.length).toBeGreaterThan(0) // sanity: the shared redactor is still there
    const violations = files.flatMap((f) =>
      (['telemetry', 'observability'] as Lane[]).flatMap((lane) =>
        findOffendingImports(f, lane).map(
          (spec) => `${relative(REPO_ROOT, f)}: imports '${spec}' (${lane} lane)`
        )
      )
    )
    expect(violations, violations.join('\n')).toEqual([])
  })

  it('src/shared/observability-redactor.ts stays import-free', () => {
    const specs = importSpecifiers(readFileSync(SHARED_REDACTOR, 'utf8'))
    expect(specs, `redactor must stay import-free; found: ${specs.join(', ')}`).toEqual([])
  })

  // Every shared observability module, not only the redactor: the renderer
  // imports this prefix, so a second file here inherits the same constraint.
  // Zero imports alone would not prove it either — a bare Node global breaks it.
  it('no src/shared/observability-* module uses a Node-only API', () => {
    const violations = listSharedObservabilityFiles()
      .filter((f) => !f.endsWith('.test.ts') && !f.endsWith('.test.tsx'))
      .flatMap((f) => {
        const text = readFileSync(f, 'utf8')
        return NODE_ONLY_APIS.filter(({ re }) => re.test(text)).map(
          ({ name }) => `${relative(REPO_ROOT, f)}: uses ${name}`
        )
      })
    expect(violations, violations.join('\n')).toEqual([])
  })
})
