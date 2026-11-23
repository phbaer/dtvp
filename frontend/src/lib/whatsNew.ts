// "What's new": which releases a user has not seen yet, and how prominently
// to show them. The backend turns the changelog into releases
// (dtvp/release_notes.py); this module decides when and what to show.

export type ReleaseGroup = 'breaking' | 'new' | 'faster' | 'fixed'

export interface ReleaseEntry {
    text: string
    scope: string | null
    pr: number | null
    breaking: boolean
    note: string | null
}

export interface Release {
    version: string | null
    date: string | null
    prerelease: boolean
    unreleased: boolean
    groups: Record<ReleaseGroup, ReleaseEntry[]>
}

export type UpgradeSize = 'first' | 'none' | 'major' | 'minor' | 'patch'

export interface SeenRecord {
    // The last version the user was shown (or that was current on a first visit).
    version: string
    // The last final (not pre-release) version they had; pre-releases are sized
    // against it, so 1.x -> 2.0.0rc4 counts as a major upgrade.
    final: string | null
}

export const GROUP_ORDER: ReleaseGroup[] = ['breaking', 'new', 'faster', 'fixed']
export const PULL_REQUEST_URL = 'https://git.baer.one/phbaer/dtvp/pulls/'

// The browser-wide key of earlier versions; read once as a starting point.
const LEGACY_KEY = 'dtvp_last_seen_version'
const keyFor = (username: string) => `dtvp_whats_new:${username}`

interface ParsedVersion {
    numbers: [number, number, number]
    pre: { tag: string; number: number } | null
}

const PRE_ORDER: Record<string, number> = { a: 0, b: 1, rc: 2 }

export const parseVersion = (value: string | null | undefined): ParsedVersion | null => {
    const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-?(a|b|rc)\.?(\d+))?$/i.exec(
        String(value ?? '').trim(),
    )
    if (!match) return null
    return {
        numbers: [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)],
        pre: match[4] ? { tag: match[4].toLowerCase(), number: Number(match[5]) } : null,
    }
}

export const isFinal = (value: string | null | undefined) => {
    const parsed = parseVersion(value)
    return parsed !== null && parsed.pre === null
}

// Negative when a < b. Unparseable versions sort first.
export const compareVersions = (a: string | null | undefined, b: string | null | undefined): number => {
    const left = parseVersion(a)
    const right = parseVersion(b)
    if (!left || !right) return (left ? 1 : 0) - (right ? 1 : 0)
    for (let index = 0; index < 3; index++) {
        const diff = left.numbers[index] - right.numbers[index]
        if (diff !== 0) return diff
    }
    if (!left.pre || !right.pre) return (left.pre ? -1 : 0) - (right.pre ? -1 : 0)
    const tag = (PRE_ORDER[left.pre.tag] ?? 0) - (PRE_ORDER[right.pre.tag] ?? 0)
    return tag !== 0 ? tag : left.pre.number - right.pre.number
}

export const upgradeSize = (seen: SeenRecord | null, current: string): UpgradeSize => {
    if (!parseVersion(current)) return 'none'
    if (!seen) return 'first'
    if (compareVersions(current, seen.version) <= 0) return 'none'
    const base = parseVersion(seen.final ?? seen.version)
    const target = parseVersion(current)!
    if (!base) return 'major'
    if (target.numbers[0] > base.numbers[0]) return 'major'
    if (target.numbers[0] === base.numbers[0] && target.numbers[1] > base.numbers[1]) return 'minor'
    return 'patch'
}

export const nextSeen = (seen: SeenRecord | null, current: string): SeenRecord => {
    const previousFinal = seen ? (seen.final ?? (isFinal(seen.version) ? seen.version : null)) : null
    return { version: current, final: isFinal(current) ? current : previousFinal }
}

export const loadSeen = (username: string): SeenRecord | null => {
    try {
        const stored = localStorage.getItem(keyFor(username))
        if (stored) {
            const parsed = JSON.parse(stored)
            if (parsed && typeof parsed.version === 'string') {
                return { version: parsed.version, final: typeof parsed.final === 'string' ? parsed.final : null }
            }
        }
        const legacy = localStorage.getItem(LEGACY_KEY)
        if (legacy) return { version: legacy, final: isFinal(legacy) ? legacy : null }
    } catch {
        // Storage unavailable or corrupt: behave like a first visit.
    }
    return null
}

export const saveSeen = (username: string, record: SeenRecord) => {
    try {
        localStorage.setItem(keyFor(username), JSON.stringify(record))
    } catch {
        // Storage unavailable: the dialog shows again next time.
    }
}

export const entryCount = (release: Release) =>
    GROUP_ORDER.reduce((sum, group) => sum + (release.groups?.[group]?.length ?? 0), 0)

// Released versions after `seen` up to and including `current`, newest first,
// that list anything for users.
export const releasesSince = (releases: Release[], seen: string | null, current: string): Release[] =>
    releases
        .filter(release =>
            release.version !== null
            && (seen === null || compareVersions(release.version, seen) > 0)
            && compareVersions(release.version, current) <= 0
            && entryCount(release) > 0,
        )
        .sort((a, b) => compareVersions(b.version, a.version))

export interface VersionedEntry extends ReleaseEntry {
    version: string | null
}

// Entries of several releases, per group, newest release first.
export const mergeGroups = (releases: Release[]): Record<ReleaseGroup, VersionedEntry[]> => {
    const merged = { breaking: [], new: [], faster: [], fixed: [] } as Record<ReleaseGroup, VersionedEntry[]>
    for (const release of releases) {
        for (const group of GROUP_ORDER) {
            for (const entry of release.groups?.[group] ?? []) {
                merged[group].push({ ...entry, version: release.version })
            }
        }
    }
    return merged
}

// The first `limit` entries, most important group first.
export const topEntries = (releases: Release[], limit: number): VersionedEntry[] => {
    const merged = mergeGroups(releases)
    return GROUP_ORDER.flatMap(group => merged[group]).slice(0, limit)
}
