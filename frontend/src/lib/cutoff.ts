// The cutoff of the project review (ADR 0015). A cutoff is a date
// `YYYY-MM-DD` (UTC, the whole day included) or `<N>d`, N days before today;
// the mode says whether findings dated on or before it ('before') or after it
// ('after') are listed; the basis says which date: 'published' (by the
// source, earliest across aliases; the default) or 'attributed' (first
// attributed to the component in any version of the project). The server
// (dtvp/first_seen.py) decides; these helpers format, parse and mirror it for
// the list without a task.

export type CutoffMode = 'before' | 'after'
export type CutoffBasis = 'published' | 'attributed'

export const CUTOFF_BASIS_OPTIONS: ReadonlyArray<{ value: CutoffBasis, label: string, purpose: string, detail: string, help: string }> = [
    {
        value: 'published',
        label: 'Published (premarket)',
        purpose: 'premarket: what was publicly known by the date',
        detail: 'When the source published the vulnerability (earliest across aliases): for a release or submission, what was publicly known by the date',
        help: 'FDA premarket guidance (Feb 2026, §V.A.4): a submission should identify all known vulnerabilities of the device and its software components. Use to scope a release or submission by publication date.',
    },
    {
        value: 'attributed',
        label: 'First attributed (postmarket)',
        purpose: 'postmarket: since when monitoring knows of it',
        detail: 'When Dependency-Track first attributed it to the component in any version of the project: since when monitoring knows of it, which starts the 30/60-day clocks',
        help: 'FDA postmarket guidance (Dec 2016, §VI.B): for uncontrolled risk, communicate within 30 days and fix within 60 days of learning of a vulnerability. Use to track what monitoring found after a date.',
    },
]

/** Shown with the control and in the docs. */
export const CUTOFF_NOTE = 'A cutoff is a planning aid, not a compliance boundary: before a submission, review with the cutoff at the submission date or without one.'
export const CUTOFF_DISCLAIMER = 'According to the FDA guidance; DTVP supports these processes, it is not regulatory advice.'
export const CUTOFF_DOCS_URL = 'https://git.baer.one/phbaer/dtvp/src/branch/main/docs/review-workflows.md#cutoff-and-the-fda-guidance'

/** The purpose of a basis, for titles (the chip). */
export const cutoffPurpose = (basis: CutoffBasis): string =>
    CUTOFF_BASIS_OPTIONS.find(option => option.value === basis)?.purpose || ''

export const normalizeCutoffBasis = (value: unknown): CutoffBasis =>
    String(value ?? '').toLowerCase() === 'attributed' ? 'attributed' : 'published'

const DAY_MS = 24 * 60 * 60 * 1000
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/
const RELATIVE_PATTERN = /^(\d{1,5})d$/

/** The canonical cutoff text, or '' when the value is none or invalid. */
export const normalizeCutoff = (value: unknown): string => {
    const text = String(value ?? '').trim().toLowerCase()
    if (!text) return ''
    const relative = RELATIVE_PATTERN.exec(text)
    if (relative) return `${Number(relative[1])}d`
    if (!DATE_PATTERN.test(text)) return ''
    const parsed = new Date(`${text}T00:00:00Z`)
    if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== text) return ''
    return text
}

export const normalizeCutoffMode = (value: unknown): CutoffMode =>
    String(value ?? '').toLowerCase() === 'after' ? 'after' : 'before'

/** The retired attribution-age parameters as a cutoff. */
export const legacyCutoff = (days: unknown, mode: unknown): { cutoff: string; cutoffMode: CutoffMode; cutoffBasis: CutoffBasis } | null => {
    const number = Math.floor(Number(days))
    if (!Number.isFinite(number) || number < 1) return null
    return {
        cutoff: `${number}d`,
        cutoffMode: String(mode ?? '').toLowerCase() === 'younger' ? 'after' : 'before',
        cutoffBasis: 'attributed',
    }
}

export const isRelativeCutoff = (cutoff: string) => RELATIVE_PATTERN.test(cutoff)

/** The cutoff day as `YYYY-MM-DD` (a relative cutoff resolved for today). */
export const cutoffDate = (cutoff: string, now: number = Date.now()): string => {
    const normalized = normalizeCutoff(cutoff)
    if (!normalized) return ''
    if (!isRelativeCutoff(normalized)) return normalized
    const days = Number(normalized.slice(0, -1))
    return new Date(now - days * DAY_MS).toISOString().slice(0, 10)
}

/** The first millisecond after the cutoff day; null without a cutoff. */
export const cutoffEndMs = (cutoff: string, now: number = Date.now()): number | null => {
    const day = cutoffDate(cutoff, now)
    if (!day) return null
    return Date.parse(`${day}T00:00:00Z`) + DAY_MS
}

export const cutoffLabel = (cutoff: string, mode: CutoffMode, basis: CutoffBasis = 'published'): string => {
    const normalized = normalizeCutoff(cutoff)
    if (!normalized) return ''
    const when = isRelativeCutoff(normalized)
        ? `${normalized.slice(0, -1)} days ago`
        : normalized
    const name = basis === 'attributed' ? 'First attributed' : 'Published'
    return `${name} ${mode === 'after' ? 'after' : 'by'} ${when}`
}

/** A finding's date on a basis. */
export const findingCutoffDate = (
    finding: { published_ms?: number | null, first_seen_ms?: number | null },
    basis: CutoffBasis,
): number | null => (basis === 'attributed' ? finding.first_seen_ms : finding.published_ms) ?? null

/** Whether a finding's first-seen time is beyond the cutoff (shown marked). */
export const isAfterCutoff = (firstSeenMs: number | null | undefined, cutoff: string, now: number = Date.now()) => {
    const end = cutoffEndMs(cutoff, now)
    return end != null && firstSeenMs != null && firstSeenMs >= end
}

/**
 * Whether a vulnerability passes the cutoff, from its list metadata: 'known'
 * when a finding in scope matches, 'unknown' when only an undated one does,
 * null when it is hidden. Mirrors dtvp/first_seen.py:cutoff_match.
 */
export const cutoffMatch = (
    byVersion: Record<string, readonly number[]> | undefined,
    unknownVersions: readonly string[] | undefined,
    cutoff: string,
    mode: CutoffMode,
    versions: readonly string[] = [],
    now: number = Date.now(),
): 'known' | 'unknown' | null => {
    const end = cutoffEndMs(cutoff, now)
    if (end == null) return 'known'
    const scope = versions.length ? new Set(versions.map(version => version.toLowerCase())) : null
    for (const [label, bounds] of Object.entries(byVersion || {})) {
        if (scope && !scope.has(label.toLowerCase())) continue
        const [low, high] = bounds
        if (mode === 'after' ? (high ?? -Infinity) >= end : (low ?? Infinity) < end) return 'known'
    }
    return (unknownVersions || []).some(label => !scope || scope.has(label.toLowerCase())) ? 'unknown' : null
}
