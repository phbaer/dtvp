// What the team mapping editor needs besides matching: a plain-language
// description of an entry, the changes of a draft against the saved
// mapping, and the checks grouped by kind with the fixes they offer
// (ADR 0012). Pure functions over ``Team`` lists; the editor owns the draft.
import { type Team } from './team-config'
import { parseTeamMappingKey } from './team-mapping'
import { insightKey, type EntryInsight, type EntryRef, type MappingReport } from './team-mapping-insights'

const lower = (value: string | undefined | null) => String(value || '').trim().toLowerCase()
const plural = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`

export { plural }

// -- what an entry matches --------------------------------------------------

export interface EntryDescription {
    kind: 'project' | 'component' | 'catch-all'
    text: string
    error?: string
}

/** What an entry (selector syntax; ``project::X`` for a project) owns, in
 * the words of the editor. */
export const describeEntry = (key: string): EntryDescription => {
    const selector = parseTeamMappingKey(key)
    if (selector.wildcard) {
        return { kind: 'catch-all', text: 'The catch-all: every finding no other entry or project owns' }
    }
    if (selector.error) return { kind: 'component', text: '', error: selector.error }
    if (selector.projectFallback) {
        return {
            kind: 'project',
            text: `The project ${selector.project}: its findings no component entry owns`,
        }
    }
    let what: string
    if (selector.purl !== undefined) {
        what = `Components with the package URL ${selector.purl}`
    } else if (selector.group !== undefined) {
        what = `Components named ${selector.name} in group ${selector.group}`
    } else if (selector.requireNoGroup) {
        what = `Components named ${selector.name} without a group`
    } else {
        what = `Components named ${selector.name}, or whose package URL names it`
    }
    if (selector.caseSensitive) what += ' (exact case)'
    what += selector.project ? `, only in ${selector.project}` : ', in every project'
    return { kind: 'component', text: `${what}, and what they contain` }
}

// -- changes of the draft -----------------------------------------------------

export type TeamField = 'aliases' | 'projects' | 'components'

export interface TeamChange {
    kind: 'team-added' | 'team-removed' | 'team-renamed' | 'added' | 'removed'
    team: string
    field?: TeamField
    value?: string
    /** The former name of a renamed team. */
    from?: string
}

const FIELDS: TeamField[] = ['aliases', 'projects', 'components']
const sameContent = (left: Team, right: Team) =>
    FIELDS.every(field => JSON.stringify([...left[field]].sort()) === JSON.stringify([...right[field]].sort()))

/** The changes from ``saved`` to ``draft``: teams added, removed or
 * renamed (same content, new name), and entries added or removed per team
 * and field. Teams are matched by name, ignoring case. */
export const diffTeams = (saved: Team[], draft: Team[]): TeamChange[] => {
    const changes: TeamChange[] = []
    const draftTeams = draft.filter(team => team.name.trim())
    const savedByName = new Map(saved.map(team => [lower(team.name), team]))
    const draftByName = new Map(draftTeams.map(team => [lower(team.name), team]))
    const removed = saved.filter(team => !draftByName.has(lower(team.name)))
    const added = draftTeams.filter(team => !savedByName.has(lower(team.name)))
    for (const team of added) {
        const index = removed.findIndex(old => sameContent(old, team))
        if (index >= 0) {
            changes.push({ kind: 'team-renamed', team: team.name, from: removed[index].name })
            removed.splice(index, 1)
            continue
        }
        changes.push({ kind: 'team-added', team: team.name })
        for (const field of FIELDS) {
            for (const value of team[field]) changes.push({ kind: 'added', team: team.name, field, value })
        }
    }
    for (const team of removed) changes.push({ kind: 'team-removed', team: team.name })
    for (const team of draftTeams) {
        const before = savedByName.get(lower(team.name))
        if (!before) continue
        if (before.name !== team.name) changes.push({ kind: 'team-renamed', team: team.name, from: before.name })
        for (const field of FIELDS) {
            for (const value of team[field]) {
                if (!before[field].includes(value)) changes.push({ kind: 'added', team: team.name, field, value })
            }
            for (const value of before[field]) {
                if (!team[field].includes(value)) changes.push({ kind: 'removed', team: team.name, field, value })
            }
        }
    }
    return changes
}

const FIELD_NOUN: Record<TeamField, string> = { aliases: 'alias', projects: 'project', components: 'entry' }

export const describeChange = (change: TeamChange): string => {
    switch (change.kind) {
        case 'team-added': return `New team ${change.team}`
        case 'team-removed': return `Team ${change.team} removed`
        case 'team-renamed': return `Team ${change.from} renamed to ${change.team}`
        case 'added': return `${change.team}: added ${FIELD_NOUN[change.field!]} ${change.value}`
        case 'removed': return `${change.team}: removed ${FIELD_NOUN[change.field!]} ${change.value}`
    }
}

// -- edits ------------------------------------------------------------------

export interface EditAction {
    type: 'add' | 'remove'
    team: string
    field: TeamField
    value: string
}

/** Applies edits to a copy of ``teams``; an added value creates the team
 * when it does not exist. Values compare exactly, projects ignoring case. */
export const applyEdits = (teams: Team[], actions: EditAction[]): Team[] => {
    const next = teams.map(team => ({
        ...team,
        aliases: [...team.aliases],
        projects: [...team.projects],
        components: [...team.components],
    }))
    const same = (field: TeamField, left: string, right: string) =>
        field === 'components' ? left === right : lower(left) === lower(right)
    for (const action of actions) {
        let team = next.find(item => lower(item.name) === lower(action.team))
        if (action.type === 'remove') {
            if (team) team[action.field] = team[action.field].filter(value => !same(action.field, value, action.value))
            continue
        }
        if (!team) {
            team = { name: action.team.trim(), aliases: [], projects: [], components: [] }
            next.push(team)
        }
        if (!team[action.field].some(value => same(action.field, value, action.value))) {
            team[action.field].push(action.value)
        }
    }
    return next
}

// -- checks -----------------------------------------------------------------

export type CheckKind =
    | 'conflict'
    | 'invalid'
    | 'alias'
    | 'coverage'
    | 'disagreement'
    | 'duplicate'
    | 'shadowed'
    | 'broad'
    | 'stale'
    | 'converted'

export interface CheckTarget {
    team?: string
    entry?: string
    project?: string
}

export interface CheckFix {
    label: string
    actions: EditAction[]
}

export interface CheckItem {
    id: string
    message: string
    /** Findings it concerns, for sorting. */
    impact: number
    target?: CheckTarget
    fixes: CheckFix[]
    /** Offer assigning the project (unowned findings of a project). */
    assignProject?: string
}

export interface CheckGroup {
    kind: CheckKind
    level: 'error' | 'warning'
    title: string
    help: string
    items: CheckItem[]
}

const GROUPS: Record<CheckKind, { level: 'error' | 'warning'; title: string; help: string }> = {
    conflict: {
        level: 'error',
        title: 'Listed under two teams',
        help: 'An entry, a project or the catch-all belongs to one team. Pick the team that keeps it.',
    },
    invalid: { level: 'error', title: 'Invalid entries and teams', help: 'Correct or remove them.' },
    alias: {
        level: 'error',
        title: 'Alias clashes',
        help: 'An alias (a former team name) may not be another team’s name or alias.',
    },
    coverage: {
        level: 'warning',
        title: 'Projects with unowned findings',
        help: 'Findings no entry or project owns fall to the catch-all. Assign the project or its components.',
    },
    disagreement: {
        level: 'warning',
        title: 'Near-duplicates given to different teams',
        help: 'Entries that differ only in case or separators (VPStatsApp, vp-stats-app) but name different teams.',
    },
    duplicate: {
        level: 'warning',
        title: 'Duplicate entries',
        help: 'The same entry up to case or form (group/name and group:name). One is enough.',
    },
    shadowed: {
        level: 'warning',
        title: 'Entries that never win',
        help: 'A more specific entry owns everything they match; removing them changes nothing.',
    },
    broad: {
        level: 'warning',
        title: 'Broad entries',
        help: 'A plain name matching many projects or different packages. Consider group:name, a purl or project:<project>::name.',
    },
    stale: {
        level: 'warning',
        title: 'Stale entries',
        help: 'They match no stored component; removing them changes nothing today.',
    },
    converted: {
        level: 'warning',
        title: 'Converted from the older format',
        help: 'What the conversion of the selector file could not keep as it was.',
    },
}

const ORDER: CheckKind[] = [
    'conflict', 'invalid', 'alias', 'coverage', 'disagreement', 'duplicate', 'shadowed', 'broad', 'stale', 'converted',
]

const teamInMessage = (text: string, teams: Team[]): string | undefined => {
    const quoted = [...text.matchAll(/'([^']+)'/g)].map(match => match[1])
    return quoted.find(name => teams.some(team => team.name === name))
}

/** The entries that disagree with ``start``, and those that disagree
 * with them, sorted. */
const disagreementSet = (start: EntryRef, insights: Map<string, EntryInsight>): EntryRef[] => {
    const seen = new Map<string, EntryRef>()
    const stack = [start]
    while (stack.length) {
        const current = stack.pop()!
        const id = `${current.team}\u0000${current.key}`
        if (seen.has(id)) continue
        seen.set(id, current)
        for (const flag of insights.get(insightKey(current.team, current.key))?.flags || []) {
            if (flag.kind === 'disagreement') stack.push(...(flag.related || []))
        }
    }
    return [...seen.values()].sort((left, right) =>
        left.team.localeCompare(right.team) || left.key.localeCompare(right.key))
}

export interface ChecksInput {
    teams: Team[]
    errors: string[]
    insights: Map<string, EntryInsight>
    report: MappingReport | null
    conversionWarnings: string[]
}

/** Every problem of the draft, grouped by kind (errors first, then by the
 * findings concerned), each with the fixes that are unambiguous. */
export const buildChecks = ({ teams, errors, insights, report, conversionWarnings }: ChecksInput): CheckGroup[] => {
    const items = new Map<CheckKind, CheckItem[]>()
    const add = (kind: CheckKind, item: CheckItem) => {
        const list = items.get(kind)
        if (list) list.push(item)
        else items.set(kind, [item])
    }
    const owned = (key: string) => report?.entries[key]?.findings || 0
    const named = teams.filter(team => team.name.trim())

    // Listed under two teams: pick the team that keeps it.
    const owners = new Map<string, { field: TeamField; value: string; teams: string[] }>()
    for (const team of named) {
        for (const value of team.components) {
            const selector = parseTeamMappingKey(value)
            if (selector.error) continue
            const field: TeamField = selector.projectFallback ? 'projects' : 'components'
            const id = selector.projectFallback ? `p\u0000${lower(selector.project)}` : `c\u0000${value}`
            const entry = owners.get(id) || { field, value, teams: [] }
            if (!entry.teams.includes(team.name)) entry.teams.push(team.name)
            owners.set(id, entry)
        }
        for (const value of team.projects) {
            const id = `p\u0000${lower(value)}`
            const entry = owners.get(id) || { field: 'projects' as TeamField, value, teams: [] }
            if (!entry.teams.includes(team.name)) entry.teams.push(team.name)
            owners.set(id, entry)
        }
    }
    for (const [id, entry] of owners) {
        if (entry.teams.length < 2) continue
        const project = id.startsWith('p')
        const what = entry.value === '*' ? 'The catch-all *' : project ? `Project ${entry.value}` : `Entry ${entry.value}`
        add('conflict', {
            id: `conflict:${id}`,
            message: `${what} is listed under ${entry.teams.join(' and ')}`,
            impact: project ? 0 : owned(entry.value),
            target: { team: entry.teams[0], ...(project ? { project: entry.value } : { entry: entry.value }) },
            fixes: entry.teams.map(keeper => ({
                label: `Keep in ${keeper}`,
                actions: entry.teams.filter(team => team !== keeper).flatMap((team) => {
                    const holder = named.find(item => item.name === team)!
                    // A project may be listed as a project or as project::X.
                    return [
                        ...holder.projects.filter(value => project && lower(value) === lower(entry.value))
                            .map(value => ({ type: 'remove' as const, team, field: 'projects' as TeamField, value })),
                        ...holder.components.filter(value => project
                            ? lower(parseTeamMappingKey(value).projectFallback ? parseTeamMappingKey(value).project : '') === lower(entry.value)
                            : value === entry.value)
                            .map(value => ({ type: 'remove' as const, team, field: 'components' as TeamField, value })),
                    ]
                }),
            })),
        })
    }

    // The remaining errors, as the server words them.
    for (const text of errors) {
        if (/is listed under teams|owned by teams/.test(text)) continue
        const team = teamInMessage(text, named)
        const selector = /selector '([^']+)'/.exec(text)?.[1]
        add(/^Alias/.test(text) ? 'alias' : 'invalid', {
            id: `error:${text}`,
            message: text,
            impact: 0,
            target: team ? { team, ...(selector ? { entry: selector } : {}) } : undefined,
            fixes: team && selector
                ? [{ label: 'Remove entry', actions: [{ type: 'remove', team, field: 'components', value: selector }] }]
                : [],
        })
    }

    // Flags of the entries.
    const seenPairs = new Set<string>()
    const seenTokens = new Set<string>()
    for (const team of named) {
        for (const key of team.components) {
            const insight = insights.get(insightKey(team.name, key))
            for (const flag of insight?.flags || []) {
                const remove: CheckFix = {
                    label: 'Remove entry',
                    actions: [{ type: 'remove', team: team.name, field: 'components', value: key }],
                }
                const target = { team: team.name, entry: key }
                if (flag.kind === 'invalid') continue
                if (flag.kind === 'stale' || flag.kind === 'shadowed') {
                    add(flag.kind, {
                        id: `${flag.kind}:${team.name}:${key}`,
                        message: `${team.name}: ${key} — ${flag.message}`,
                        impact: owned(key),
                        target,
                        fixes: [remove],
                    })
                } else if (flag.kind === 'broad') {
                    add('broad', {
                        id: `broad:${team.name}:${key}`,
                        message: `${team.name}: ${key} — ${flag.message}`,
                        impact: owned(key),
                        target,
                        fixes: [],
                    })
                } else if (flag.kind === 'duplicate') {
                    // One item per pair: keep one of the two.
                    const other = flag.related?.[0]
                    if (!other) continue
                    const otherKey = other.key
                    const otherTeam = other.team
                    const pair = [`${team.name}\u0000${key}`, `${otherTeam}\u0000${otherKey}`].sort().join('\u0001')
                    // The same entry under two teams is a conflict, listed above.
                    if (seenPairs.has(pair) || (otherKey === key && otherTeam !== team.name)) continue
                    seenPairs.add(pair)
                    const sameTeam = otherTeam === team.name
                    add('duplicate', {
                        id: `duplicate:${pair}`,
                        message: sameTeam
                            ? `${team.name}: ${key} and ${otherKey} are the same entry`
                            : `${key} (${team.name}) and ${otherKey} (${otherTeam}) are the same entry`,
                        impact: owned(key) + owned(otherKey),
                        target,
                        fixes: [
                            { label: sameTeam ? `Keep ${otherKey}` : `Keep in ${otherTeam}`, actions: remove.actions },
                            {
                                label: sameTeam ? `Keep ${key}` : `Keep in ${team.name}`,
                                actions: [{ type: 'remove', team: otherTeam, field: 'components', value: otherKey }],
                            },
                        ],
                    })
                } else if (flag.kind === 'disagreement') {
                    // One item per set of near-duplicates: give them all to one team.
                    const members = disagreementSet({ key, team: team.name }, insights)
                    const token = members.map(item => `${item.team}\u0000${item.key}`).sort().join('\u0001')
                    if (seenTokens.has(token)) continue
                    seenTokens.add(token)
                    const memberTeams = [...new Set(members.map(item => item.team))]
                    add('disagreement', {
                        id: `disagreement:${token}`,
                        message: members.map(item => `${item.key} (${item.team})`).join(' and '),
                        impact: members.reduce((sum, item) => sum + owned(item.key), 0),
                        target,
                        fixes: memberTeams.map(keeper => ({
                            label: `${keeper} owns all`,
                            actions: members.filter(item => item.team !== keeper).flatMap(item => [
                                { type: 'remove' as const, team: item.team, field: 'components' as TeamField, value: item.key },
                                { type: 'add' as const, team: keeper, field: 'components' as TeamField, value: item.key },
                            ]),
                        })),
                    })
                }
            }
        }
    }

    for (const text of conversionWarnings) {
        add('converted', { id: `converted:${text}`, message: text, impact: 0, fixes: [] })
    }

    for (const project of report?.projects || []) {
        if (project.unmapped <= 0) continue
        add('coverage', {
            id: `coverage:${project.name}`,
            message: `${project.name}: ${plural(project.unmapped, 'finding')} of ${project.findings} unowned`,
            impact: project.unmapped,
            target: { project: project.name },
            fixes: [],
            assignProject: project.name,
        })
    }

    return ORDER.filter(kind => items.get(kind)?.length).map(kind => ({
        kind,
        ...GROUPS[kind],
        items: [...items.get(kind)!].sort((left, right) => right.impact - left.impact),
    }))
}

export const checkCounts = (groups: CheckGroup[]) => ({
    errors: groups.filter(group => group.level === 'error').reduce((sum, group) => sum + group.items.length, 0),
    warnings: groups.filter(group => group.level === 'warning').reduce((sum, group) => sum + group.items.length, 0),
})
