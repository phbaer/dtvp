import type { Instance, TagValue, Tags } from '../types'
import { tagToString } from './assessment-helpers'

export type TeamMapping = Record<string, string | string[]>
export const DEFAULT_REPRESENTATIVE_PATH_LIMIT = 10

const normalizeName = (name: string): string => name.trim().toLowerCase()

export const getPrimaryTeamForComponent = (
    componentName: string | undefined,
    teamMapping: TeamMapping | undefined,
): string => {
    if (!componentName || !teamMapping) return ''

    const targetName = normalizeName(componentName)
    for (const [key, value] of Object.entries(teamMapping)) {
        if (key === '*') continue
        if (normalizeName(key) !== targetName) continue
        if (Array.isArray(value)) return value[0] || ''
        return typeof value === 'string' ? value : ''
    }

    return ''
}

export const getPathParts = (path: string): string[] => {
    const rawParts = path.split(' -> ').map(part => part.trim()).filter(Boolean)
    return rawParts.filter((part, index) => {
        if (index === 0) return true
        return normalizeName(part) !== normalizeName(rawParts[index - 1])
    })
}

export const normalizePath = (path: string): string => {
    return getPathParts(path).map(normalizeName).join(' -> ')
}

export const getFirstMappedTeamOnPath = (
    parts: string[],
    teamMapping: TeamMapping | undefined,
): { team: string; component: string; index: number } | null => {
    for (let index = 1; index < parts.length; index += 1) {
        const team = getPrimaryTeamForComponent(parts[index], teamMapping)
        if (team) {
            return {
                team,
                component: parts[index],
                index,
            }
        }
    }
    return null
}

export const selectRepresentativePaths = (
    paths: string[] | undefined,
    teamMapping: TeamMapping | undefined,
    limit: number = DEFAULT_REPRESENTATIVE_PATH_LIMIT,
): string[] => {
    const deduped = new Map<string, string[]>()
    for (const rawPath of paths || []) {
        const parts = getPathParts(rawPath)
        if (parts.length <= 1) continue
        const normalized = normalizePath(rawPath)
        if (!normalized || deduped.has(normalized)) continue
        deduped.set(normalized, parts)
    }

    const teamPathMap = new Map<string, string[]>()
    const unmappedPaths: string[][] = []

    for (const parts of deduped.values()) {
        const firstMapped = getFirstMappedTeamOnPath(parts, teamMapping)
        if (!firstMapped) {
            unmappedPaths.push(parts)
            continue
        }

        const existing = teamPathMap.get(firstMapped.team)
        if (!existing) {
            teamPathMap.set(firstMapped.team, parts)
            continue
        }

        const existingMapped = getFirstMappedTeamOnPath(existing, teamMapping)
        const shouldReplace = !existingMapped
            || firstMapped.index < existingMapped.index
            || (firstMapped.index === existingMapped.index && parts.length < existing.length)
            || (firstMapped.index === existingMapped.index
                && parts.length === existing.length
                && parts.join(' -> ') < existing.join(' -> '))

        if (shouldReplace) {
            teamPathMap.set(firstMapped.team, parts)
        }
    }

    const selected = teamPathMap.size > 0
        ? Array.from(teamPathMap.values())
        : unmappedPaths

    return selected
        .sort((left, right) => {
            const leftMapped = getFirstMappedTeamOnPath(left, teamMapping)
            const rightMapped = getFirstMappedTeamOnPath(right, teamMapping)
            const leftIndex = leftMapped?.index ?? Number.MAX_SAFE_INTEGER
            const rightIndex = rightMapped?.index ?? Number.MAX_SAFE_INTEGER
            if (leftIndex !== rightIndex) return leftIndex - rightIndex
            if (left.length !== right.length) return left.length - right.length
            return left.join(' -> ').localeCompare(right.join(' -> '))
        })
        .slice(0, limit)
        .map(parts => parts.join(' -> '))
}

export const getAffectedTeamsFromPaths = (
    paths: string[] | undefined,
    teamMapping: TeamMapping | undefined,
    limit: number = DEFAULT_REPRESENTATIVE_PATH_LIMIT,
): string[] => {
    const teams = new Set<string>()
    selectRepresentativePaths(paths, teamMapping, limit).forEach((path) => {
        const firstMapped = getFirstMappedTeamOnPath(getPathParts(path), teamMapping)
        if (firstMapped?.team) teams.add(firstMapped.team)
    })
    return Array.from(teams)
}

export const getClosestAffectedTeamsForInstance = (
    inst: Pick<Instance, 'component_name' | 'dependency_chains'>,
    teamMapping: TeamMapping | undefined,
): string[] => {
    const directTeam = getPrimaryTeamForComponent(inst.component_name, teamMapping)
    if (directTeam) return [directTeam]

    return getAffectedTeamsFromPaths(inst.dependency_chains, teamMapping)
}

export const getClosestAffectedTeamsForInstances = (
    instances: Array<Pick<Instance, 'component_name' | 'dependency_chains'>>,
    teamMapping: TeamMapping | undefined,
): string[] => {
    const teams = new Set<string>()
    instances.forEach((inst) => {
        getClosestAffectedTeamsForInstance(inst, teamMapping).forEach(team => teams.add(team))
    })
    return Array.from(teams)
}

export const normalizeLegacyTags = (
    tags: Tags | undefined,
    teamMapping: TeamMapping | undefined,
): string[] => {
    if (!tags) return []
    if (!teamMapping) return tags.map(tagToString).filter(Boolean)

    const result = new Set<string>()
    tags.forEach((tag: TagValue) => {
        const strTag = tagToString(tag)
        if (!strTag) return

        let foundPrimary = strTag
        for (const [, mappingVal] of Object.entries(teamMapping)) {
            if (Array.isArray(mappingVal) && mappingVal.length > 1) {
                const primary = mappingVal[0]
                const aliases = mappingVal.slice(1)
                if (aliases.includes(strTag)) {
                    foundPrimary = primary
                    break
                }
            }
        }
        result.add(foundPrimary)
    })
    return Array.from(result)
}