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
}

export interface TeamMappingMatch {
    key: string
    value: TeamMappingValue
    selector: TeamMappingSelector
    tags: string[]
}

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

export const parseTeamMappingKey = (key: string): TeamMappingSelector => {
    const rawKey = String(key || '').trim()
    if (rawKey === '*') {
        return {
            rawKey,
            name: '',
            requireNoGroup: false,
            caseSensitive: false,
            wildcard: true,
        }
    }

    let remaining = rawKey
    let caseSensitive = false
    let requireNoGroup = false
    let matchPurl = false

    if (remaining.includes('::')) {
        const [modifierPart, ...identityParts] = remaining.split('::')
        const modifiers = modifierPart
            .replaceAll('+', ',')
            .split(',')
            .map(token => token.trim().toLowerCase())
            .filter(Boolean)
        const knownModifiers = new Set([
            'cs',
            'case',
            'case-sensitive',
            'case_sensitive',
            'ci',
            'case-insensitive',
            'case_insensitive',
            'nogroup',
            'no-group',
            'no_group',
            'purl',
            'package-url',
            'package_url',
            'packageurl',
        ])

        if (modifiers.length > 0 && modifiers.every(modifier => knownModifiers.has(modifier))) {
            modifiers.forEach((modifier) => {
                if ([
                    'cs',
                    'case',
                    'case-sensitive',
                    'case_sensitive',
                ].includes(modifier)) {
                    caseSensitive = true
                } else if ([
                    'ci',
                    'case-insensitive',
                    'case_insensitive',
                ].includes(modifier)) {
                    caseSensitive = false
                } else if ([
                    'nogroup',
                    'no-group',
                    'no_group',
                ].includes(modifier)) {
                    requireNoGroup = true
                } else if ([
                    'purl',
                    'package-url',
                    'package_url',
                    'packageurl',
                ].includes(modifier)) {
                    matchPurl = true
                }
            })
            remaining = identityParts.join('::')
        }
    }

    let group: string | undefined
    let purl: string | undefined
    let name = remaining.trim()
    if (matchPurl) {
        purl = remaining.trim()
        name = ''
    } else if (!requireNoGroup && remaining.includes(':')) {
        const [groupPart, ...nameParts] = remaining.split(':')
        if (groupPart.trim()) {
            group = groupPart.trim()
            name = nameParts.join(':').trim()
        }
    }

    return {
        rawKey,
        name,
        group,
        purl,
        requireNoGroup,
        caseSensitive,
        wildcard: false,
    }
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
    if (selector.wildcard) return false
    if (selector.purl !== undefined) {
        return matchesPurl(selector.purl, identity.purl || '', true)
    }
    if (selector.name !== identity.name) return false
    if (selector.group !== undefined) {
        return identity.groupKnown && selector.group === identity.group
    }
    return true
}

export const selectorMatchesIdentity = (
    selector: TeamMappingSelector,
    identity: ComponentIdentity,
    includeWildcard = false,
): boolean => {
    const normalizedIdentity: Required<ComponentIdentity> = {
        name: String(identity.name || '').trim(),
        group: String(identity.group || '').trim(),
        purl: String(identity.purl || '').trim(),
        groupKnown: Boolean(identity.groupKnown),
    }

    if (selector.wildcard) return includeWildcard
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
        selectorSpecificity(left.selector),
        left.selector.caseSensitive ? 1 : 0,
        exactCaseMatch(left.selector, identity) ? 1 : 0,
    ]
    const rightScore = [
        selectorSpecificity(right.selector),
        right.selector.caseSensitive ? 1 : 0,
        exactCaseMatch(right.selector, identity) ? 1 : 0,
    ]
    for (let index = 0; index < leftScore.length; index += 1) {
        if (leftScore[index] !== rightScore[index]) return rightScore[index] - leftScore[index]
    }
    return left.selector.rawKey.localeCompare(right.selector.rawKey)
}

export const findTeamMappingMatch = (
    teamMapping: TeamMapping | undefined,
    identity: ComponentIdentity,
    includeWildcard = false,
): TeamMappingMatch | null => {
    const normalizedIdentity: Required<ComponentIdentity> = {
        name: String(identity.name || '').trim(),
        group: String(identity.group || '').trim(),
        purl: String(identity.purl || '').trim(),
        groupKnown: Boolean(identity.groupKnown),
    }
    const matches: TeamMappingMatch[] = []

    Object.entries(teamMapping || {}).forEach(([key, value]) => {
        const selector = parseTeamMappingKey(key)
        if (!selectorMatchesIdentity(selector, normalizedIdentity, includeWildcard)) return
        const tags = normalizeTeamValues(value)
        if (tags.length === 0) return
        matches.push({ key, value, selector, tags })
    })

    if (matches.length === 0) return null
    return [...matches].sort(compareMatches(normalizedIdentity))[0]
}

export const getTeamMappingTags = (
    teamMapping: TeamMapping | undefined,
    identity: ComponentIdentity,
    includeWildcard = false,
): string[] => findTeamMappingMatch(teamMapping, identity, includeWildcard)?.tags || []

export const getPrimaryTeamForComponent = (
    componentName: string | undefined | null,
    teamMapping: TeamMapping | undefined,
    componentGroup?: string | null,
    groupKnown = false,
    componentPurl?: string | null,
): string => getTeamMappingTags(
    teamMapping,
    {
        name: componentName,
        group: componentGroup,
        purl: componentPurl,
        groupKnown,
    },
)[0] || ''
