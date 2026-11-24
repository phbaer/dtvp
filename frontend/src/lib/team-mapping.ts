export type TeamMappingValue = string | string[]
export type TeamMapping = Record<string, TeamMappingValue>

export interface ComponentIdentity {
    name?: string | null
    group?: string | null
    purl?: string | null
    groupKnown?: boolean
}

export interface TeamMappingSelector {
    rawKey: string
    name: string
    group?: string
    purl?: string
    requireNoGroup: boolean
    caseSensitive: boolean
    wildcard: boolean
    /** ``project:<name>::<selector>``: the component selector applies only
     * in this Dependency-Track project. For ``project::<name>`` the name. */
    project?: string
    /** ``project::<name>``: owns the project's findings no component
     * selector owns. */
    projectFallback?: boolean
    /** Why the key is not a valid selector; saving rejects it. */
    error?: string
}

export interface TeamMappingMatch {
    key: string
    value: TeamMappingValue
    selector: TeamMappingSelector
    tags: string[]
}

interface CompiledTeamMapping {
    entries: TeamMappingMatch[]
    matches: Map<string, TeamMappingMatch | null>
    canonicalTeamNames: Map<string, string>
}

const compiledTeamMappings = new WeakMap<TeamMapping, CompiledTeamMapping>()

export const normalizeTeamValues = (value: TeamMappingValue): string[] => {
    const values = Array.isArray(value) ? value : [value]
    const seen = new Set<string>()
    const result: string[] = []
    values.forEach((entry) => {
        const text = String(entry || '').trim()
        if (!text || seen.has(text)) return
        result.push(text)
        seen.add(text)
    })
    return result
}

/** A team and its aliases, from the team document (``teamRoster`` in
 * ./team-config.ts). Unlike the selector mapping it lists every team,
 * also one without any entry. */
export interface TeamRosterEntry {
    name: string
    aliases: string[]
}

export const buildTeamAliasGroups = (
    teamMapping: TeamMapping | undefined,
    roster?: TeamRosterEntry[],
): Record<string, string[]> => {
    const groups = new Map<string, {
        primary: string
        aliases: Map<string, string>
    }>()
    const values: TeamMappingValue[] = [
        ...(roster || []).map(team => [team.name, ...team.aliases]),
        ...Object.values(teamMapping || {}),
    ]
    values.forEach((value) => {
        const [primary, ...aliases] = normalizeTeamValues(value)
        if (!primary) return
        const key = primary.toLowerCase()
        const group = groups.get(key) || {
            primary,
            aliases: new Map<string, string>(),
        }
        aliases.forEach((alias) => {
            const aliasKey = alias.toLowerCase()
            if (aliasKey !== key && !group.aliases.has(aliasKey)) {
                group.aliases.set(aliasKey, alias)
            }
        })
        groups.set(key, group)
    })
    return Object.fromEntries(
        [...groups.values()]
            .sort((left, right) => left.primary.localeCompare(
                right.primary,
                undefined,
                { numeric: true, sensitivity: 'base' },
            ))
            .map(group => [
                group.primary,
                [...group.aliases.values()].sort((left, right) =>
                    left.localeCompare(
                        right,
                        undefined,
                        { numeric: true, sensitivity: 'base' },
                    )
                ),
            ]),
    )
}

const CASE_SENSITIVE_MODIFIERS = new Set(['cs', 'case', 'case-sensitive', 'case_sensitive'])
const CASE_INSENSITIVE_MODIFIERS = new Set(['ci', 'case-insensitive', 'case_insensitive'])
const NO_GROUP_MODIFIERS = new Set(['nogroup', 'no-group', 'no_group'])
const PURL_MODIFIERS = new Set(['purl', 'package-url', 'package_url', 'packageurl'])
const PROJECT_PREFIX = 'project:'

const isKnownModifier = (modifier: string) => CASE_SENSITIVE_MODIFIERS.has(modifier)
    || CASE_INSENSITIVE_MODIFIERS.has(modifier)
    || NO_GROUP_MODIFIERS.has(modifier)
    || PURL_MODIFIERS.has(modifier)

const splitOnce = (text: string, separator: string): [string, string] => {
    const index = text.indexOf(separator)
    return [text.slice(0, index), text.slice(index + separator.length)]
}

const parseComponentKey = (
    rawKey: string,
    source: string,
    project: string | undefined,
): TeamMappingSelector => {
    let remaining = source
    let caseSensitive = false
    let requireNoGroup = false
    let matchPurl = false
    let error: string | undefined

    if (remaining.includes('::')) {
        const [modifierPart, identityPart] = splitOnce(remaining, '::')
        const modifiers = modifierPart
            .replaceAll('+', ',')
            .split(',')
            .map(token => token.trim().toLowerCase())
            .filter(Boolean)
        const unknown = modifiers.filter(modifier => !isKnownModifier(modifier))
        if (modifiers.length === 0) {
            error = "Nothing before '::'; use a modifier such as cs, nogroup or purl"
        } else if (unknown.length > 0) {
            error = unknown[0] === 'project'
                ? "'project::<name>' cannot be combined with other modifiers"
                : `Unknown modifier '${unknown[0]}' before '::'`
        } else {
            const has = (set: Set<string>) => modifiers.some(modifier => set.has(modifier))
            if (has(CASE_SENSITIVE_MODIFIERS) && has(CASE_INSENSITIVE_MODIFIERS)) {
                error = 'Modifiers cs and ci contradict each other'
            } else if (has(PURL_MODIFIERS) && has(NO_GROUP_MODIFIERS)) {
                error = 'Modifier nogroup does not apply to a purl selector'
            }
            modifiers.forEach((modifier) => {
                if (CASE_SENSITIVE_MODIFIERS.has(modifier)) caseSensitive = true
                else if (CASE_INSENSITIVE_MODIFIERS.has(modifier)) caseSensitive = false
                else if (NO_GROUP_MODIFIERS.has(modifier)) requireNoGroup = true
                else if (PURL_MODIFIERS.has(modifier)) matchPurl = true
            })
            remaining = identityPart
        }
    }

    let group: string | undefined
    let purl: string | undefined
    let name = remaining.trim()
    if (matchPurl) {
        purl = remaining.trim()
        name = ''
        if (!error && !purl.toLowerCase().startsWith('pkg:')) {
            error = 'A purl selector needs a package URL starting with pkg:'
        }
    } else if (!requireNoGroup && remaining.includes(':')) {
        const [groupPart, namePart] = splitOnce(remaining, ':')
        if (groupPart.trim()) {
            group = groupPart.trim()
            name = namePart.trim()
        }
    } else if (!requireNoGroup && remaining.includes('/')) {
        const separator = remaining.lastIndexOf('/')
        const groupPart = remaining.slice(0, separator).trim()
        const namePart = remaining.slice(separator + 1).trim()
        if (groupPart && namePart) {
            group = groupPart
            name = namePart
        }
    }

    if (!error && !matchPurl && !name) error = 'The selector names no component'

    return {
        rawKey,
        name,
        group,
        purl,
        requireNoGroup,
        caseSensitive,
        wildcard: false,
        ...(project !== undefined ? { project } : {}),
        ...(error ? { error } : {}),
    }
}

/** Parse a mapping key; mirrors ``parse_team_mapping_key``
 * (dtvp/team_mapping.py). Forms: ``*``, ``project::<project>``,
 * ``project:<project>::<selector>`` and the component selectors ``name``,
 * ``group:name``, ``group/name`` with the optional modifiers ``cs``, ``ci``,
 * ``nogroup`` and ``purl`` before ``::``. */
export const parseTeamMappingKey = (key: string): TeamMappingSelector => {
    const rawKey = String(key || '').trim()
    const base = {
        rawKey,
        name: '',
        requireNoGroup: false,
        caseSensitive: false,
        wildcard: false,
    }
    if (rawKey === '*') return { ...base, wildcard: true }
    if (!rawKey) return { ...base, error: 'The key is empty' }

    if (rawKey.includes('::')) {
        const [head, rest] = splitOnce(rawKey, '::')
        const headText = head.trim()
        if (headText.toLowerCase() === 'project') {
            const projectName = rest.trim()
            return {
                ...base,
                ...(projectName ? { project: projectName } : { error: "'project::' needs a project name" }),
                projectFallback: true,
            }
        }
        if (headText.toLowerCase().startsWith(PROJECT_PREFIX)) {
            const projectName = headText.slice(PROJECT_PREFIX.length).trim()
            const inner = rest.trim()
            if (!projectName) {
                return { ...base, error: "'project:<name>::' needs a project name" }
            }
            if (inner === '*') {
                return {
                    ...base,
                    project: projectName,
                    error: `Use 'project::${projectName}' for the project's own findings`,
                }
            }
            const innerHead = inner.includes('::') ? splitOnce(inner, '::')[0].trim().toLowerCase() : ''
            if (innerHead === 'project' || innerHead.startsWith(PROJECT_PREFIX)) {
                return {
                    ...base,
                    project: projectName,
                    error: 'A project selector cannot contain another project selector',
                }
            }
            return parseComponentKey(rawKey, inner, projectName)
        }
    }
    return parseComponentKey(rawKey, rawKey, undefined)
}

/** Why a key is not a valid selector, or null. */
export const teamMappingKeyError = (key: string): string | null =>
    parseTeamMappingKey(key).error || null

const sameProject = (selectorProject: string | undefined, project: string | null | undefined): boolean => {
    if (!selectorProject || !project) return false
    return selectorProject.trim().toLowerCase() === String(project).trim().toLowerCase()
}

const matchesText = (selectorText: string, actualText: string, caseSensitive: boolean): boolean => {
    if (caseSensitive) return selectorText === actualText
    return selectorText.toLowerCase() === actualText.toLowerCase()
}

const purlWithoutVersionQualifiersOrSubpath = (value: string): string => {
    const withoutSubpath = value.trim().split('#', 1)[0]
    const text = withoutSubpath.split('?', 1)[0]
    const lastSegment = text.split('/').pop() || ''
    if (lastSegment.includes('@')) {
        return text.slice(0, text.lastIndexOf('@'))
    }
    return text
}

const purlRequestsExactVersion = (value: string): boolean => {
    const text = value.trim()
    const base = text.split('#', 1)[0].split('?', 1)[0]
    return (base.split('/').pop() || '').includes('@') || text.includes('?') || text.includes('#')
}

const matchesPurl = (selectorPurl: string, actualPurl: string, caseSensitive: boolean): boolean => {
    const selector = selectorPurl.trim()
    const actual = actualPurl.trim()
    if (!selector || !actual) return false
    if (purlRequestsExactVersion(selector)) {
        return matchesText(selector, actual, caseSensitive)
    }
    return matchesText(
        purlWithoutVersionQualifiersOrSubpath(selector),
        purlWithoutVersionQualifiersOrSubpath(actual),
        caseSensitive,
    )
}

const exactCaseMatch = (selector: TeamMappingSelector, identity: Required<ComponentIdentity>): boolean => {
    if (selector.wildcard || selector.projectFallback) return false
    if (selector.purl !== undefined) {
        return matchesPurl(selector.purl, identity.purl || '', true)
    }
    if (selector.name !== identity.name) return false
    if (selector.group !== undefined) {
        return identity.groupKnown && selector.group === identity.group
    }
    return true
}

/** Whether a component selector matches the component; ``project`` is the
 * Dependency-Track project it is in (project-scoped selectors match only
 * there). ``project::`` selectors and ``*`` are fallbacks. */
export const selectorMatchesIdentity = (
    selector: TeamMappingSelector,
    identity: ComponentIdentity,
    includeWildcard = false,
    project?: string | null,
): boolean => {
    const normalizedIdentity: Required<ComponentIdentity> = {
        name: String(identity.name || '').trim(),
        group: String(identity.group || '').trim(),
        purl: String(identity.purl || '').trim(),
        groupKnown: Boolean(identity.groupKnown),
    }

    if (selector.wildcard) return includeWildcard
    if (selector.projectFallback) return false
    if (selector.project !== undefined && !sameProject(selector.project, project)) return false
    if (selector.purl !== undefined) {
        return matchesPurl(selector.purl, normalizedIdentity.purl || '', selector.caseSensitive)
    }
    if (!selector.name || !normalizedIdentity.name) return false
    if (!matchesText(selector.name, normalizedIdentity.name, selector.caseSensitive)) return false

    if (selector.requireNoGroup) {
        return normalizedIdentity.groupKnown && !normalizedIdentity.group
    }

    if (selector.group !== undefined) {
        return Boolean(
            normalizedIdentity.groupKnown
            && normalizedIdentity.group
            && matchesText(selector.group, normalizedIdentity.group, selector.caseSensitive)
        )
    }

    if (normalizedIdentity.groupKnown && normalizedIdentity.group) return false
    return true
}

const selectorSpecificity = (selector: TeamMappingSelector): number => {
    if (selector.wildcard) return 0
    if (selector.purl !== undefined) return 5
    if (selector.group !== undefined) return 4
    if (selector.requireNoGroup) return 3
    return 2
}

const compareMatches = (identity: Required<ComponentIdentity>) => (left: TeamMappingMatch, right: TeamMappingMatch): number => {
    const leftScore = [
        left.selector.project !== undefined ? 1 : 0,
        selectorSpecificity(left.selector),
        left.selector.caseSensitive ? 1 : 0,
        exactCaseMatch(left.selector, identity) ? 1 : 0,
    ]
    const rightScore = [
        right.selector.project !== undefined ? 1 : 0,
        selectorSpecificity(right.selector),
        right.selector.caseSensitive ? 1 : 0,
        exactCaseMatch(right.selector, identity) ? 1 : 0,
    ]
    for (let index = 0; index < leftScore.length; index += 1) {
        if (leftScore[index] !== rightScore[index]) return rightScore[index] - leftScore[index]
    }
    return left.selector.rawKey.localeCompare(right.selector.rawKey)
}

const compiledTeamMapping = (teamMapping: TeamMapping): CompiledTeamMapping => {
    const cached = compiledTeamMappings.get(teamMapping)
    if (cached) return cached

    const entries: TeamMappingMatch[] = Object.entries(teamMapping).flatMap(([key, value]) => {
        const tags = normalizeTeamValues(value)
        if (tags.length === 0) return []
        return [{
            key,
            value,
            selector: parseTeamMappingKey(key),
            tags,
        }]
    })
    const canonicalTeamNames = new Map<string, string>()
    for (const entry of entries) {
        const primary = entry.tags[0]
        entry.tags.forEach(team => canonicalTeamNames.set(team.toLocaleLowerCase(), primary))
    }
    const compiled: CompiledTeamMapping = {
        entries,
        matches: new Map<string, TeamMappingMatch | null>(),
        canonicalTeamNames,
    }
    compiledTeamMappings.set(teamMapping, compiled)
    return compiled
}

export const resolveCanonicalTeamName = (
    teamMapping: TeamMapping | undefined,
    requestedTeam: string,
    roster?: TeamRosterEntry[],
): string => {
    const requested = String(requestedTeam || '').trim()
    const lowered = requested.toLocaleLowerCase()
    const listed = (roster || []).find(team => team.name.toLocaleLowerCase() === lowered
        || team.aliases.some(alias => alias.toLocaleLowerCase() === lowered))
    if (listed) return listed.name
    if (!requested || !teamMapping) return requested
    return compiledTeamMapping(teamMapping).canonicalTeamNames.get(
        requested.toLocaleLowerCase(),
    ) || requested
}

const teamMappingMatchCacheKey = (
    identity: Required<ComponentIdentity>,
    includeWildcard: boolean,
    project: string,
) => [
    includeWildcard ? '1' : '0',
    project.toLowerCase(),
    identity.groupKnown ? '1' : '0',
    identity.name,
    identity.group,
    identity.purl,
].join('\u0000')

const safeDecode = (value: string): string => {
    try {
        return decodeURIComponent(value)
    } catch {
        return value
    }
}

/** The identity the component's package URL names: its package name and
 * namespace (as the group). Null without a package URL, or when it names
 * the component's own name and group. Mirrors the server's
 * ``purl_package_identity`` (dtvp/team_mapping.py). */
export const purlPackageIdentity = (
    identity: Required<ComponentIdentity>,
): Required<ComponentIdentity> | null => {
    const text = String(identity.purl || '').trim()
    if (!text.toLowerCase().startsWith('pkg:')) return null
    const path = text.slice(4).split('#', 1)[0].split('?', 1)[0].replace(/^\/+|\/+$/g, '')
    const segments = path.split('/')
    if (segments.length < 2) return null
    let last = segments[segments.length - 1]
    if (last.includes('@')) last = last.slice(0, last.lastIndexOf('@'))
    const name = safeDecode(last).trim()
    const namespace = segments.slice(1, -1).map(safeDecode).join('/').trim()
    if (!name) return null
    if (
        name.toLowerCase() === String(identity.name || '').toLowerCase()
        && namespace.toLowerCase() === String(identity.group || '').toLowerCase()
    ) return null
    return { name, group: namespace, purl: identity.purl, groupKnown: true }
}

const bestMatchFor = (
    entries: TeamMappingMatch[],
    identity: Required<ComponentIdentity>,
    includeWildcard: boolean,
    project?: string | null,
): TeamMappingMatch | null => {
    const compare = compareMatches(identity)
    let bestMatch: TeamMappingMatch | null = null
    for (const candidate of entries) {
        if (!selectorMatchesIdentity(candidate.selector, identity, includeWildcard, project)) continue
        if (!bestMatch || compare(candidate, bestMatch) < 0) {
            bestMatch = candidate
        }
    }
    return bestMatch
}

const normalizeIdentity = (identity: ComponentIdentity): Required<ComponentIdentity> => ({
    name: String(identity.name || '').trim(),
    group: String(identity.group || '').trim(),
    purl: String(identity.purl || '').trim(),
    groupKnown: Boolean(identity.groupKnown),
})

const projectFallbackFor = (
    entries: TeamMappingMatch[],
    project: string | null | undefined,
): TeamMappingMatch | null => {
    if (!project) return null
    const candidates = entries
        .filter(entry => entry.selector.projectFallback && sameProject(entry.selector.project, project))
        .sort((left, right) => {
            const leftExact = (left.selector.project || '').trim() === project.trim() ? 0 : 1
            const rightExact = (right.selector.project || '').trim() === project.trim() ? 0 : 1
            if (leftExact !== rightExact) return leftExact - rightExact
            return left.selector.rawKey < right.selector.rawKey ? -1 : left.selector.rawKey > right.selector.rawKey ? 1 : 0
        })
    return candidates[0] || null
}

/** The ``project::<project>`` entry of a project; mirrors
 * ``project_fallback_match``. */
export const findProjectFallbackMatch = (
    teamMapping: TeamMapping | undefined,
    project: string | null | undefined,
): TeamMappingMatch | null => {
    if (!teamMapping) return null
    return projectFallbackFor(compiledTeamMapping(teamMapping).entries, project)
}

/** The mapping entry for a component; mirrors ``find_team_mapping_match``.
 * Precedence: a selector scoped to ``project``, a component selector, the
 * package its purl names; with ``includeWildcard`` then
 * ``project::<project>`` and last ``*``. */
export const findTeamMappingMatch = (
    teamMapping: TeamMapping | undefined,
    identity: ComponentIdentity,
    includeWildcard = false,
    project?: string | null,
): TeamMappingMatch | null => {
    if (!teamMapping) return null
    const normalizedIdentity = normalizeIdentity(identity)
    const projectName = String(project || '').trim()
    const compiled = compiledTeamMapping(teamMapping)
    const cacheKey = teamMappingMatchCacheKey(normalizedIdentity, includeWildcard, projectName)
    if (compiled.matches.has(cacheKey)) {
        return compiled.matches.get(cacheKey) || null
    }

    const bestMatch = bestMatchFor(compiled.entries, normalizedIdentity, false, projectName)
        ?? (() => {
            const pkg = purlPackageIdentity(normalizedIdentity)
            return pkg ? bestMatchFor(compiled.entries, pkg, false, projectName) : null
        })()
        ?? (includeWildcard ? projectFallbackFor(compiled.entries, projectName) : null)
        ?? (includeWildcard ? bestMatchFor(compiled.entries, normalizedIdentity, true) : null)

    compiled.matches.set(cacheKey, bestMatch)
    return bestMatch
}

export const getTeamMappingTags = (
    teamMapping: TeamMapping | undefined,
    identity: ComponentIdentity,
    includeWildcard = false,
    project?: string | null,
): string[] => findTeamMappingMatch(teamMapping, identity, includeWildcard, project)?.tags || []

export const getPrimaryTeamForComponent = (
    componentName: string | undefined | null,
    teamMapping: TeamMapping | undefined,
    componentGroup?: string | null,
    groupKnown = false,
    componentPurl?: string | null,
    project?: string | null,
): string => getTeamMappingTags(
    teamMapping,
    {
        name: componentName,
        group: componentGroup,
        purl: componentPurl,
        groupKnown,
    },
    false,
    project,
)[0] || ''
