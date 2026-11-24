// What the team mapping editor shows about entries: what a selector
// matches in the stored components (the report's inventory), whether a
// more specific entry overrides it, and its weak spots. The report is
// built by the server (dtvp/team_mapping_report.py); matching uses the
// same engine as the server (./team-mapping.ts).
import {
    findTeamMappingMatch,
    parseTeamMappingKey,
    purlPackageIdentity,
    selectorMatchesIdentity,
    type ComponentIdentity,
    type TeamMapping,
    type TeamMappingSelector,
} from './team-mapping'
import { type Team, type TeamDocument } from './team-config'

// -- the server's payloads ------------------------------------------------

export interface TeamMappingTeamsResponse {
    format: 'teams' | 'selectors'
    teams: TeamDocument
    warnings: string[]
}

export interface ReportProject {
    name: string
    versions: { uuid: string; version: string }[]
    findings: number
    unmapped: number
    owned_by: Record<string, number>
    fallback_key: string | null
    root: { name: string; group: string; purl: string }
}

export interface UnmappedRow {
    kind: 'root' | 'component'
    name: string
    group: string
    purl: string
    in_bom: boolean
    findings: number
    projects: { name: string; findings: number; versions: string[] }[]
    suggested_key: string
    suggestion_reason: string
}

export interface NearDuplicate {
    token: string
    teams: string[]
    entries: { key: string; team: string }[]
}

/** [name, group, purl base, [[project index, findings below, unowned below, flags], ...]] */
export type InventoryRow = [string, string, string, [number, number, number, number][]]

export interface MappingReport {
    totals: {
        versions: number
        projects: number
        findings: number
        owned_by_component: number
        owned_by_project: number
        unmapped: number
    }
    projects: ReportProject[]
    entries: Record<string, { findings: number; projects: { name: string; findings: number }[] }>
    unmapped: UnmappedRow[]
    unmapped_total: number
    near_duplicates: NearDuplicate[]
    missing_versions: { project_uuid: string; project: string; version: string }[]
    inventory: { projects: string[]; components: InventoryRow[]; total: number; truncated: boolean }
}

export interface TeamMappingReportResponse {
    status: 'building' | 'ready' | 'failed'
    stale: boolean
    built_at: string | null
    error: string | null
    report: MappingReport | null
}

export interface TreeOwner {
    team: string
    kind: 'component' | 'inherited' | 'project' | 'wildcard' | 'none'
    key: string | null
    from?: string[]
}

export interface TreeNode {
    ref: string
    name: string
    group: string
    purl: string
    root: boolean
    unlinked: boolean
    children: number
    findings_here: number
    findings: number
    unowned: number
    owner: TreeOwner
    /** The owner under the saved mapping, when a draft tree changes it. */
    saved_owner?: TreeOwner
}

export interface MappingTreeLevel {
    project_uuid: string
    project: string
    version: string
    findings: number
    findings_outside_bom: number
    root?: TreeNode | null
    parent?: string
    nodes?: TreeNode[]
    total?: number
}

export interface MappingPreview {
    findings: number
    changed: number
    moves: { from: string; to: string; findings: number }[]
    projects: { name: string; changed: number }[]
}

// -- the inventory --------------------------------------------------------

export const FLAG_ROOT = 1
export const FLAG_TOP_LEVEL = 2

export interface InventoryItem {
    name: string
    group: string
    purl: string
    project: string
    below: number
    unownedBelow: number
    flags: number
}

export interface Inventory {
    items: InventoryItem[]
    byName: Map<string, InventoryItem[]>
    byPurl: Map<string, InventoryItem[]>
    projects: string[]
    truncated: boolean
}

const lower = (value: string | undefined | null) => String(value || '').trim().toLowerCase()

const purlBase = (purl: string): string => {
    const text = purl.trim().split('#', 1)[0].split('?', 1)[0]
    const slash = text.lastIndexOf('/')
    const last = text.slice(slash + 1)
    if (!last.includes('@')) return text
    return text.slice(0, slash + 1) + last.slice(0, last.lastIndexOf('@'))
}

const push = <K, V>(map: Map<K, V[]>, key: K, value: V) => {
    const list = map.get(key)
    if (list) list.push(value)
    else map.set(key, [value])
}

/** Every component of the report per project, indexed by name (its own
 * and the package name its purl names) and by purl. */
export const buildInventory = (report: MappingReport | null | undefined): Inventory => {
    const inventory: Inventory = {
        items: [],
        byName: new Map(),
        byPurl: new Map(),
        projects: report?.inventory.projects || [],
        truncated: Boolean(report?.inventory.truncated),
    }
    for (const [name, group, purl, perProject] of report?.inventory.components || []) {
        for (const [projectIndex, below, unownedBelow, flags] of perProject) {
            const item: InventoryItem = {
                name, group, purl,
                project: inventory.projects[projectIndex] || '',
                below, unownedBelow, flags,
            }
            inventory.items.push(item)
            push(inventory.byName, lower(name), item)
            if (purl) {
                push(inventory.byPurl, lower(purl), item)
                const pkg = purlPackageIdentity({ name, group, purl, groupKnown: true })
                if (pkg) push(inventory.byName, lower(pkg.name), item)
            }
        }
    }
    return inventory
}

const identityOf = (item: InventoryItem): ComponentIdentity => ({
    name: item.name, group: item.group, purl: item.purl, groupKnown: true,
})

const candidatesFor = (selector: TeamMappingSelector, inventory: Inventory): InventoryItem[] => {
    if (selector.purl !== undefined) return inventory.byPurl.get(lower(purlBase(selector.purl))) || []
    return inventory.byName.get(lower(selector.name)) || []
}

/** Whether a component selector matches an inventory component, by its own
 * identity or by the package its purl names. */
export const selectorMatchesItem = (selector: TeamMappingSelector, item: InventoryItem): boolean => {
    const identity = identityOf(item)
    if (selectorMatchesIdentity(selector, identity, false, item.project)) return true
    const pkg = item.purl
        ? purlPackageIdentity({ name: item.name, group: item.group, purl: item.purl, groupKnown: true })
        : null
    return Boolean(pkg && selectorMatchesIdentity(selector, pkg, false, item.project))
}

export interface SelectorPreview {
    selector: TeamMappingSelector
    /** Components (per project) it matches. */
    matched: InventoryItem[]
    projects: string[]
    /** Matched components another entry owns instead, by that entry. */
    overriddenBy: Map<string, number>
    wins: number
    /** Findings below the matched components; of those, falling to "*". */
    findingsBelow: number
    unownedBelow: number
}

/** What a selector (saved or being typed) matches in the inventory, with
 * ``mapping`` deciding who wins each component. */
export const previewSelector = (
    key: string,
    inventory: Inventory,
    mapping: TeamMapping,
): SelectorPreview => {
    const selector = parseTeamMappingKey(key)
    const result: SelectorPreview = {
        selector,
        matched: [],
        projects: [],
        overriddenBy: new Map(),
        wins: 0,
        findingsBelow: 0,
        unownedBelow: 0,
    }
    if (selector.error || selector.wildcard || selector.projectFallback) return result
    const projects = new Set<string>()
    for (const item of candidatesFor(selector, inventory)) {
        if (result.matched.includes(item) || !selectorMatchesItem(selector, item)) continue
        result.matched.push(item)
        projects.add(item.project)
        result.findingsBelow += item.below
        result.unownedBelow += item.unownedBelow
        const winner = findTeamMappingMatch(mapping, identityOf(item), false, item.project)
        if (!winner || winner.key === key) {
            result.wins += 1
        } else {
            result.overriddenBy.set(winner.key, (result.overriddenBy.get(winner.key) || 0) + 1)
        }
    }
    result.projects = [...projects].sort((left, right) => left.localeCompare(right))
    return result
}

// -- weak spots -----------------------------------------------------------

export type EntryFlagKind = 'stale' | 'broad' | 'shadowed' | 'duplicate' | 'disagreement' | 'invalid'

export interface EntryFlag {
    kind: EntryFlagKind
    message: string
    /** The other entries of a duplicate or a disagreement. */
    related?: EntryRef[]
}

/** Entries naming 5 or more projects, or 2 or more different packages,
 * with a plain name are broad. */
export const BROAD_PROJECTS = 5

/** The same selector up to case (when not case-sensitive), the
 * ``group/name`` and ``group:name`` forms, and a redundant ``ci``. */
export const canonicalSelector = (key: string): string => {
    const selector = parseTeamMappingKey(key)
    if (selector.wildcard) return '*'
    const fold = (text: string | undefined) => selector.caseSensitive ? (text || '') : lower(text)
    return [
        lower(selector.project),
        selector.projectFallback ? 'P' : '',
        selector.caseSensitive ? 'cs' : '',
        selector.requireNoGroup ? 'ng' : '',
        selector.purl !== undefined ? fold(purlBase(selector.purl)) : '',
        fold(selector.group),
        fold(selector.name),
    ].join('\u0000')
}

/** Mirrors ``_loose_token`` (dtvp/team_mapping_report.py): the name with
 * case and separators ignored, a purl read as its package name. */
export const looseToken = (key: string): string => {
    const selector = parseTeamMappingKey(key)
    let name = selector.name
    if (selector.purl !== undefined) {
        name = purlPackageIdentity({ name: '', group: '', purl: selector.purl, groupKnown: true })?.name || ''
    }
    return lower(name).replace(/[^a-z0-9]/g, '')
}

export interface EntryRef {
    team: string
    key: string
}

export interface EntryInsight {
    preview: SelectorPreview
    flags: EntryFlag[]
}

/** Every component entry's preview and flags. ``mapping`` is the selector
 * mapping of ``teams``; ``ready`` says whether the inventory can tell a
 * stale entry (a report exists and was not cut). */
export const entryInsights = (
    teams: Team[],
    inventory: Inventory,
    mapping: TeamMapping,
    ready: boolean,
): Map<string, EntryInsight> => {
    const entries: EntryRef[] = teams.flatMap(team =>
        team.components.map(key => ({ team: team.name, key })))
    const byCanonical = new Map<string, EntryRef[]>()
    const byToken = new Map<string, EntryRef[]>()
    for (const entry of entries) {
        const selector = parseTeamMappingKey(entry.key)
        if (selector.wildcard || selector.error) continue
        push(byCanonical, canonicalSelector(entry.key), entry)
        const token = looseToken(entry.key)
        if (token && !selector.projectFallback) push(byToken, `${lower(selector.project)}\u0000${token}`, entry)
    }

    const insights = new Map<string, EntryInsight>()
    for (const entry of entries) {
        const preview = previewSelector(entry.key, inventory, mapping)
        const flags: EntryFlag[] = []
        const selector = preview.selector
        if (selector.error) {
            flags.push({ kind: 'invalid', message: selector.error })
        } else if (!selector.wildcard && !selector.projectFallback) {
            if (ready && !inventory.truncated && preview.matched.length === 0) {
                flags.push({ kind: 'stale', message: 'Matches no stored component' })
            }
            const plain = selector.purl === undefined && selector.group === undefined && selector.project === undefined
            const packages = new Set(preview.matched.filter(item => item.purl).map(item => lower(item.purl)))
            if (plain && (preview.projects.length >= BROAD_PROJECTS || packages.size >= 2)) {
                flags.push({
                    kind: 'broad',
                    message: packages.size >= 2
                        ? `A plain name matching ${packages.size} different packages`
                        : `A plain name matching components in ${preview.projects.length} projects`,
                })
            }
            if (preview.matched.length > 0 && preview.wins === 0) {
                const [winner] = [...preview.overriddenBy.entries()].sort((left, right) => right[1] - left[1])
                flags.push({ kind: 'shadowed', message: `Never wins; ${winner?.[0] ?? 'another entry'} owns its matches` })
            }
            for (const other of byCanonical.get(canonicalSelector(entry.key)) || []) {
                if (other === entry) continue
                flags.push({
                    kind: 'duplicate',
                    message: `Same selector as ${other.key}${other.team !== entry.team ? ` (${other.team})` : ''}`,
                    related: [other],
                })
            }
            const token = looseToken(entry.key)
            const disagreeing = token
                ? (byToken.get(`${lower(selector.project)}\u0000${token}`) || [])
                    // A duplicate of another team is already flagged as one.
                    .filter(other => other.team !== entry.team
                        && canonicalSelector(other.key) !== canonicalSelector(entry.key))
                : []
            if (disagreeing.length) {
                flags.push({
                    kind: 'disagreement',
                    message: `Nearly the same as ${disagreeing.map(other => `${other.key} (${other.team})`).join(', ')}`,
                    related: disagreeing,
                })
            }
        }
        insights.set(`${entry.team}\u0000${entry.key}`, { preview, flags })
    }
    return insights
}

export const insightKey = (team: string, key: string) => `${team}\u0000${key}`

// -- suggestions ----------------------------------------------------------

export interface SuggestedEntry {
    kind: 'project' | 'component'
    value: string
}

/** The entry that would own a node of the coverage browser: the project for
 * a root, the package its purl names, ``group:name``, or the name scoped
 * to the project. Mirrors ``suggest_key`` (dtvp/team_mapping_report.py). */
export const suggestEntry = (
    node: { name: string; group: string; purl: string; root?: boolean },
    project: string,
): SuggestedEntry => {
    if (node.root) return { kind: 'project', value: project }
    if (node.purl) {
        const pkg = purlPackageIdentity({ name: node.name, group: node.group, purl: node.purl, groupKnown: true })
        const name = (pkg ? pkg.name : node.name) || node.name
        const group = (pkg ? pkg.group : node.group) || ''
        const key = group ? `${group}:${name}` : name
        const selector = parseTeamMappingKey(key)
        if (!selector.error) return { kind: 'component', value: key }
        return { kind: 'component', value: `purl::${node.purl}` }
    }
    if (node.group) return { kind: 'component', value: `${node.group}:${node.name}` }
    return { kind: 'component', value: `project:${project}::${node.name}` }
}

/** A suggestion of the server (``suggested_key``) as an entry. */
export const entryFromKey = (key: string): SuggestedEntry => {
    const selector = parseTeamMappingKey(key)
    return selector.projectFallback && selector.project
        ? { kind: 'project', value: selector.project }
        : { kind: 'component', value: key }
}

/** Adds entries to a team (created when new); returns new teams. */
export const assignEntries = (teams: Team[], teamName: string, entries: SuggestedEntry[]): Team[] => {
    const name = teamName.trim()
    const next = teams.map(team => ({ ...team, projects: [...team.projects], components: [...team.components] }))
    let team = next.find(item => lower(item.name) === lower(name))
    if (!team) {
        team = { name, aliases: [], projects: [], components: [] }
        next.push(team)
    }
    for (const entry of entries) {
        const list = entry.kind === 'project' ? team.projects : team.components
        if (!list.some(item => item === entry.value)) list.push(entry.value)
    }
    return next
}

// -- autocomplete -----------------------------------------------------------

/** Selector completions for typed text: names, group:name and purl::
 * forms of stored components, and project-scoped forms when the text starts
 * with ``project:<name>::``. */
export const componentCompletions = (text: string, inventory: Inventory, limit = 30): string[] => {
    const typed = text.trim()
    let prefix = ''
    let query = typed
    const scoped = /^project:([^:]+)::(.*)$/i.exec(typed)
    if (scoped) {
        prefix = `project:${scoped[1]}::`
        query = scoped[2]
    }
    const needle = lower(query.replace(/^purl::/i, ''))
    if (!needle) return []
    const seen = new Set<string>()
    const result: string[] = []
    const add = (value: string) => {
        const full = prefix + value
        if (!seen.has(full) && result.length < limit) {
            seen.add(full)
            result.push(full)
        }
    }
    const ranked = [...inventory.items]
        .filter(item => !scoped || lower(item.project) === lower(scoped[1]))
        .filter(item => lower(item.name).includes(needle) || lower(item.group).includes(needle) || lower(item.purl).includes(needle))
        .sort((left, right) => (Number(!lower(left.name).startsWith(needle)) - Number(!lower(right.name).startsWith(needle)))
            || right.below - left.below)
    for (const item of ranked) {
        if (result.length >= limit) break
        if (lower(item.name).includes(needle)) add(item.group ? `${item.group}:${item.name}` : item.name)
        if (item.purl && lower(item.purl).includes(needle)) add(`purl::${item.purl}`)
    }
    return result
}

export const projectCompletions = (text: string, projects: string[], limit = 30): string[] => {
    const needle = lower(text)
    return projects.filter(name => !needle || lower(name).includes(needle)).slice(0, limit)
}

// -- colours ----------------------------------------------------------------

const TEAM_COLOURS = [
    'bg-sky-900/60 text-sky-200 border-sky-700',
    'bg-emerald-900/60 text-emerald-200 border-emerald-700',
    'bg-violet-900/60 text-violet-200 border-violet-700',
    'bg-teal-900/60 text-teal-200 border-teal-700',
    'bg-indigo-900/60 text-indigo-200 border-indigo-700',
    'bg-fuchsia-900/60 text-fuchsia-200 border-fuchsia-700',
    'bg-cyan-900/60 text-cyan-200 border-cyan-700',
    'bg-lime-900/60 text-lime-200 border-lime-700',
]

/** A stable colour per team. The catch-all and no owner are neutral and
 * dashed: they are a state (unowned), not a team; the chip names them and
 * carries an icon, so colour is never the only cue. */
export const teamColour = (team: string, kind?: TreeOwner['kind']): string => {
    if (kind === 'wildcard' || kind === 'none' || !team) return 'border-dashed bg-transparent text-amber-100 border-amber-500/70'
    let hash = 0
    for (const char of team.toLowerCase()) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
    return TEAM_COLOURS[hash % TEAM_COLOURS.length]
}
