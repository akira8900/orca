// Copy-diagnostics payload for the SSH reconnect overlay. Every source is read
// from renderer memory and every read is synchronous: the report exists for the
// case where the IPC channel is dead, so assembly must never round-trip.
import { useAppStore } from '@/store'
import type {
  SshConnectionState,
  SshConnectionStatus,
  SshRemotePlatform
} from '../../../shared/ssh-types'
import { getRendererAppPlatform } from './renderer-app-platform'
import { firstLine, scrubDiagnosticText } from './ssh-diagnostic-text-scrub'
import { classifySshErrorCategory, type SshErrorCategory } from './ssh-error-category'
import { snapshotSshStatusTimeline, type SshStatusTimelineEntry } from './ssh-status-timeline'

export {
  MAX_FREE_TEXT_CHARS,
  MAX_SCRUB_INPUT_CHARS,
  redactPaths,
  redactSshIdentifiers,
  scrubDiagnosticText
} from './ssh-diagnostic-text-scrub'

export type SshDiagnosticReport = {
  captureId: string
  capturedAt: string
  /** Null until the module cache primes; never worth an await (§4.2). */
  appVersion: string | null
  /** The device rendering this report — NOT the machine running the SSH client. */
  clientPlatform: string
  live: {
    status: SshConnectionStatus | null
    /**
     * False when the store held no entry for the target. The overlay defaults
     * the same lookup to `disconnected` (`selectRuntimeAwareSshStatus`), so the
     * report defaults with it and says here that it did.
     */
    liveStatePresent: boolean
    error: string | null
    /** Classified from the raw error, so it survives the scrub eating the host. */
    errorCategory: SshErrorCategory | null
    reconnectAttempt: number | null
    connectionGeneration: number | null
    remotePlatform: SshRemotePlatform | null
    supportsFolderDownload: boolean | null
    targetRemoved: boolean
    runtimeOwned: boolean
  }
  timeline: SshStatusTimelineEntry[]
  sectionErrors: Record<string, string>
}

let cachedAppVersion: string | null = null

/**
 * Fire-and-forget prime of the app-version cache. `updater.getVersion()` is the
 * only accessor and it is async, so capture reads this cache rather than
 * awaiting IPC it may not get an answer from.
 */
export function primeSshDiagnosticAppVersion(): void {
  void window.api?.updater
    ?.getVersion?.()
    .then((version) => {
      cachedAppVersion = version
    })
    .catch(() => undefined)
}

export function resetSshDiagnosticAppVersionForTests(): void {
  cachedAppVersion = null
}

function newCaptureId(): string {
  // A correlation token for "diagnostic 4f2a", not a secret.
  return Math.random().toString(36).slice(2, 10).padEnd(8, '0')
}

function readLiveState(targetId: string, environmentId: string | null): SshConnectionState | null {
  const store = useAppStore.getState()
  if (environmentId === null) {
    return store.sshConnectionStates.get(targetId) ?? null
  }
  // Deliberately the raw bucket, not `selectRuntimeAwareSshStatus`: a report
  // that hides an un-hydrated bucket's state would hide the failure itself.
  return store.sshStateByEnvironment.get(environmentId)?.connectionStates.get(targetId) ?? null
}

// Why guard past the declared type: these states cross IPC, so a malformed
// payload must degrade to null rather than put junk on the clipboard.
function stringOrNull<T extends string>(value: unknown): T | null {
  return typeof value === 'string' ? (value as T) : null
}

function emptyLive(
  targetRemoved: boolean,
  runtimeOwned: boolean,
  status: SshConnectionStatus | null
): SshDiagnosticReport['live'] {
  return {
    status,
    liveStatePresent: false,
    error: null,
    errorCategory: null,
    reconnectAttempt: null,
    connectionGeneration: null,
    remotePlatform: null,
    supportsFolderDownload: null,
    targetRemoved,
    runtimeOwned
  }
}

/**
 * Run one section, recording a scrubbed one-liner in `sectionErrors` instead of
 * sinking the whole report — a throwing section is itself a diagnostic.
 */
function section<T>(
  sectionErrors: Record<string, string>,
  name: string,
  build: () => T,
  fallback: T
): T {
  try {
    return build()
  } catch (error) {
    // Renderer throws routinely carry `file:///Users/<name>/…` module URLs, so
    // this takes the identical scrub as `error`.
    sectionErrors[name] = firstLine(scrubDiagnosticText(String(error)))
    return fallback
  }
}

export function buildSshDiagnosticReport(input: {
  targetId: string
  targetRemoved: boolean
  environmentId: string | null
}): SshDiagnosticReport {
  const sectionErrors: Record<string, string> = {}
  const runtimeOwned = input.environmentId !== null
  const live = section(
    sectionErrors,
    'live',
    () => {
      const state = readLiveState(input.targetId, input.environmentId)
      if (!state) {
        return emptyLive(input.targetRemoved, runtimeOwned, 'disconnected')
      }
      return {
        status: stringOrNull<SshConnectionStatus>(state.status),
        liveStatePresent: true,
        error: typeof state.error === 'string' ? scrubDiagnosticText(state.error) : null,
        errorCategory: classifySshErrorCategory(state.error),
        reconnectAttempt:
          typeof state.reconnectAttempt === 'number' ? state.reconnectAttempt : null,
        connectionGeneration:
          typeof state.connectionGeneration === 'number' ? state.connectionGeneration : null,
        remotePlatform: stringOrNull<SshRemotePlatform>(state.remotePlatform),
        supportsFolderDownload:
          typeof state.supportsFolderDownload === 'boolean' ? state.supportsFolderDownload : null,
        targetRemoved: input.targetRemoved,
        runtimeOwned
      }
    },
    // A throwing store is not a `disconnected` target: leave the status unknown.
    emptyLive(input.targetRemoved, runtimeOwned, null)
  )
  const timeline = section<SshStatusTimelineEntry[]>(
    sectionErrors,
    'timeline',
    () =>
      // New objects, never an in-place edit: the ring's snapshot is shallow
      // (pty-delivery-diagnostics.ts:51-53), so mutating here would scrub the
      // retained history and make a second capture disagree with the first.
      snapshotSshStatusTimeline(input.targetId, input.environmentId).map((entry) => ({
        ...entry,
        error: typeof entry.error === 'string' ? scrubDiagnosticText(entry.error) : null
      })),
    []
  )
  return {
    captureId: section(sectionErrors, 'captureId', newCaptureId, 'unknown'),
    capturedAt: section(sectionErrors, 'capturedAt', () => new Date().toISOString(), ''),
    appVersion: section(sectionErrors, 'appVersion', () => cachedAppVersion, null),
    clientPlatform: section<string>(
      sectionErrors,
      'clientPlatform',
      getRendererAppPlatform,
      'unknown'
    ),
    live,
    timeline,
    sectionErrors
  }
}

function describeAttempt(attempt: number | null): string {
  return attempt === null ? '' : ` (attempt ${attempt})`
}

function describeTimelineSpan(timeline: SshStatusTimelineEntry[]): string {
  const first = timeline[0]
  const last = timeline.at(-1)
  if (!first || !last) {
    return ''
  }
  // `atMs` is a folded run's LAST arrival, so the first entry's own run started
  // `runMs` earlier — without that the header understates the covered window.
  const spanMs = last.atMs - (first.atMs - (first.runMs ?? 0))
  if (spanMs <= 0) {
    return ''
  }
  // Sub-second windows are real flap evidence; rounding them to `0s` hides it.
  return spanMs < 1000 ? `, spanning ${spanMs}ms` : `, spanning ${Math.round(spanMs / 1000)}s`
}

function describeOptional(value: string | boolean | null): string {
  return value === null ? 'unknown' : String(value)
}

function describeLastError(live: SshDiagnosticReport['live']): string {
  if (live.error === null) {
    return 'Last error: none'
  }
  // First line only — the JSON block below keeps the whole value, and a
  // multi-line OpenSSH stderr here would break the rest of the header off.
  return `Last error [${live.errorCategory ?? 'unclassified'}]: ${firstLine(live.error)}`
}

/**
 * Human header plus the JSON in a fence, so it pastes into an issue intact and
 * collapses. Pure, and every header line is derived from `report` — there is no
 * second assembly path that could disagree with the JSON below it.
 */
export function formatSshDiagnosticReport(report: SshDiagnosticReport): string {
  const failed = Object.keys(report.sectionErrors)
  const header = [
    `SSH diagnostics ${report.captureId}`,
    `Captured: ${report.capturedAt || 'unknown'}`,
    `App: ${report.appVersion ?? 'unknown'} · Client platform: ${report.clientPlatform} (this device, not the SSH host)`,
    `Status: ${report.live.status ?? 'unknown'}${describeAttempt(report.live.reconnectAttempt)}${report.live.liveStatePresent ? '' : ' (no live state — defaulted)'}`,
    `Connection generation: ${report.live.connectionGeneration ?? 'unknown'}`,
    `Remote platform: ${describeOptional(report.live.remotePlatform)} · Folder download: ${describeOptional(report.live.supportsFolderDownload)}`,
    `Target removed: ${report.live.targetRemoved} · Runtime-owned: ${report.live.runtimeOwned}`,
    `Timeline: ${report.timeline.length} ${report.timeline.length === 1 ? 'entry' : 'entries'}${describeTimelineSpan(report.timeline)}`,
    describeLastError(report.live),
    `Section errors: ${failed.length === 0 ? 'none' : failed.join(', ')}`
  ].join('\n')
  return `${header}\n\n\`\`\`json\n${JSON.stringify(report, null, 2)}\n\`\`\`\n`
}
