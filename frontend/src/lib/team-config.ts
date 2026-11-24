// The team mapping file organised by team (ADR 0012); mirrors
// dtvp/team_config.py. A team owns aliases, projects (Dependency-Track
// project names) and components (selectors, see ./team-mapping.ts); a
// string or list value is shorthand for components; "*" is a component
// entry of the team owning the catch-all. The matcher reads the selector
// mapping ``selectorMappingFromTeams`` derives, where a project X is the
// selector ``project::X``.
import { parseTeamMappingKey, type TeamMapping, type TeamRosterEntry } from './team-mapping'

export interface TeamEntry {
    aliases?: string[]
    projects?: string[]
    components?: string[]
}
export type TeamDocumentValue = TeamEntry | string | string[]
export type TeamDocument = Record<string, TeamDocumentValue>

export interface Team {
    name: string
    aliases: string[]
    projects: string[]
    components: string[]
}

const TEAM_FIELDS = ['aliases', 'projects', 'components'] as const

const strings = (value: unknown): string[] => {
    const items = typeof value === 'string' ? [value] : Array.isArray(value) ? value : []
    const result: string[] = []
    for (const item of items) {
        const text = typeof item === 'string' ? item.trim() : ''
        if (text && !result.includes(text)) result.push(text)
    }
    return result
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
    Boolean(value) && typeof value === 'object' && !Array.isArray(value)

/** Mirrors ``is_team_format``: an object value, or a team owning "*". */
export const isTeamFormat = (document: unknown): boolean => {
    if (!isPlainObject(document)) return false
    return Object.values(document).some(value => isPlainObject(value)
        || (typeof value === 'string' && value.trim() === '*')
        || (Array.isArray(value) && value.some(item => typeof item === 'string' && item.trim() === '*')))
}

export const teamFromValue = (name: string, value: unknown): Team => isPlainObject(value)
    ? {
        name,
        aliases: strings(value.aliases),
        projects: strings(value.projects),
        components: strings(value.components),
    }
    : { name, aliases: [], projects: [], components: strings(value) }

export const teamsFromDocument = (document: TeamDocument): Team[] =>
    Object.entries(document || {}).map(([name, value]) => teamFromValue(name.trim(), value))

/** The document a save writes: objects, empty fields left out. */
export const documentFromTeams = (teams: Team[]): Record<string, TeamEntry> => {
    const document: Record<string, TeamEntry> = {}
    for (const team of teams) {
        const name = team.name.trim()
        if (!name) continue
        const entry: TeamEntry = {}
        for (const field of TEAM_FIELDS) {
            const items = strings(team[field])
            if (items.length) entry[field] = items
        }
        document[name] = entry
    }
    return document
}

/** Mirrors ``team_config_errors``: what blocks a save. */
export const teamConfigErrors = (document: unknown): string[] => {
    if (!isPlainObject(document)) return ['Team mapping must be a JSON object']
    const errors: string[] = []
    const teams: Team[] = []
    for (const [rawName, value] of Object.entries(document)) {
        const name = rawName.trim()
        if (!name) {
            errors.push('A team name is empty')
            continue
        }
        if (isPlainObject(value)) {
            const unknown = Object.keys(value).filter(key => !(TEAM_FIELDS as readonly string[]).includes(key))
            if (unknown.length) {
                errors.push(`Team '${name}': unknown field '${unknown[0]}'; use aliases, projects and components`)
            }
            for (const field of TEAM_FIELDS) {
                const items = value[field] ?? []
                if (!Array.isArray(items) || !items.every(item => typeof item === 'string')) {
                    errors.push(`Team '${name}': ${field} must be a list of strings`)
                }
            }
        } else if (typeof value !== 'string'
            && !(Array.isArray(value) && value.every(item => typeof item === 'string'))) {
            errors.push(`Team '${name}': the value must be an object, a selector or a list of selectors`)
        }
        teams.push(teamFromValue(name, value))
    }

    const teamNames = new Map<string, string>()
    for (const team of teams) {
        const key = team.name.toLowerCase()
        if (teamNames.has(key)) {
            errors.push(`Teams '${teamNames.get(key)}' and '${team.name}' differ only by case`)
        } else {
            teamNames.set(key, team.name)
        }
    }

    const aliasOwner = new Map<string, string>()
    const selectorOwner = new Map<string, string>()
    const projectOwner = new Map<string, string>()
    let wildcardOwner: string | null = null
    for (const team of teams) {
        for (const alias of team.aliases) {
            const lowered = alias.toLowerCase()
            if (lowered === team.name.toLowerCase()) continue
            if (teamNames.has(lowered)) {
                errors.push(`Alias '${alias}' of team '${team.name}' is the name of team '${teamNames.get(lowered)}'`)
            } else if (aliasOwner.has(lowered) && aliasOwner.get(lowered) !== team.name) {
                errors.push(`Alias '${alias}' is listed for teams '${aliasOwner.get(lowered)}' and '${team.name}'`)
            }
            if (!aliasOwner.has(lowered)) aliasOwner.set(lowered, team.name)
        }
        const projects = [...team.projects]
        for (const component of team.components) {
            if (component === '*') {
                if (wildcardOwner !== null && wildcardOwner !== team.name) {
                    errors.push(`'*' is owned by teams '${wildcardOwner}' and '${team.name}'; at most one team owns it`)
                }
                wildcardOwner = wildcardOwner ?? team.name
                continue
            }
            const selector = parseTeamMappingKey(component)
            if (selector.error) {
                errors.push(`Team '${team.name}': selector '${component}': ${selector.error}`)
                continue
            }
            if (selector.projectFallback && selector.project) {
                projects.push(selector.project)
                continue
            }
            const owner = selectorOwner.get(component)
            if (owner !== undefined && owner !== team.name) {
                errors.push(`Selector '${component}' is listed under teams '${owner}' and '${team.name}'`)
            }
            if (!selectorOwner.has(component)) selectorOwner.set(component, team.name)
        }
        for (const project of projects) {
            if (project.includes('::') && project.toLowerCase().startsWith('project')) {
                errors.push(`Team '${team.name}': project '${project}': give the project name only`)
            }
            const owner = projectOwner.get(project.toLowerCase())
            if (owner !== undefined && owner !== team.name) {
                errors.push(`Project '${project}' is listed under teams '${owner}' and '${team.name}'`)
            }
            if (!projectOwner.has(project.toLowerCase())) projectOwner.set(project.toLowerCase(), team.name)
        }
    }
    return errors
}

/** Mirrors ``selector_mapping``: the selector mapping the matcher reads.
 * A document in the older selector format is returned as it is. */
export const selectorMappingFromDocument = (document: unknown): TeamMapping => {
    if (!isPlainObject(document)) return {}
    if (!isTeamFormat(document)) return document as TeamMapping
    const mapping: TeamMapping = {}
    for (const [rawName, value] of Object.entries(document)) {
        const team = teamFromValue(rawName.trim(), value)
        if (!team.name) continue
        const aliases = team.aliases.filter(alias => alias.toLowerCase() !== team.name.toLowerCase())
        const tags = aliases.length ? [team.name, ...aliases] : team.name
        for (const component of team.components) {
            if (!(component in mapping)) mapping[component] = tags
        }
        for (const project of team.projects) {
            const key = `project::${project}`
            if (!(key in mapping)) mapping[key] = tags
        }
    }
    return mapping
}

export const selectorMappingFromTeams = (teams: Team[]): TeamMapping =>
    selectorMappingFromDocument(documentFromTeams(teams))

/** Every team with its aliases, in document order: the team list for
 * team groups, filters and alias resolution. Unlike the selector mapping it
 * includes teams that own only projects or nothing yet. */
export const teamRoster = (teams: Team[]): TeamRosterEntry[] => {
    const seen = new Set<string>()
    const roster: TeamRosterEntry[] = []
    for (const team of teams) {
        const name = team.name.trim()
        if (!name || seen.has(name.toLowerCase())) continue
        seen.add(name.toLowerCase())
        roster.push({ name, aliases: team.aliases.filter(alias => alias.toLowerCase() !== name.toLowerCase()) })
    }
    return roster
}

export const teamRosterFromDocument = (document: TeamDocument): TeamRosterEntry[] =>
    teamRoster(teamsFromDocument(document))
