import { computed, type ComputedRef, type Ref } from 'vue'
import type { GroupedVuln, Instance } from '../types'
import {
    getClosestAffectedTeamsForInstance,
    getClosestAffectedTeamsForInstances,
    getFirstMappedTeamOnPath,
    getPathParts,
    getPrimaryTeamForComponent,
    normalizeLegacyTags,
    selectRepresentativePaths,
} from './dependency-team-selection'
import { sortVersions } from './version'

export type DependencyRelationship = 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'

interface TaggedComponentInfo {
    name: string
    versions: string[]
    tag: string
}

export interface TriggeringTaggedComponentInfo {
    name: string
    versions: string[]
    tag: string
}

interface UseVulnDependencyInfoOptions {
    group: ComputedRef<GroupedVuln> | Ref<GroupedVuln>
    teamMapping: Ref<Record<string, string | string[]>>
    refreshCounter?: Ref<number>
}

const normalizeComponentName = (value: string) => {
    return value?.trim().toLowerCase() || ''
}

const sortComponentVersions = (versions: Set<string>) => {
    return Array.from(versions).sort((left, right) => left.localeCompare(right, undefined, { numeric: true }))
}

const sortTaggedComponents = (items: Map<string, { versions: Set<string>; tag: string }>): TaggedComponentInfo[] => {
    return Array.from(items.entries())
        .map(([name, data]) => ({
            name,
            versions: sortComponentVersions(data.versions),
            tag: data.tag,
        }))
        .sort((left, right) => left.name.localeCompare(right.name, undefined, { sensitivity: 'base', numeric: true }))
}

export function getTriggeringTaggedComponentsForGroup(
    group: GroupedVuln,
    mapping: Record<string, string | string[]>,
): TriggeringTaggedComponentInfo[] {
    const allInstances = (group.affected_versions || []).flatMap(version => version.components || [])
    const taggedComponents = new Map<string, { versions: Set<string>; tag: string }>()
    const paths = allInstances.flatMap(instance => instance.dependency_chains || [])
    const selectedPaths = selectRepresentativePaths(paths, mapping, 100)

    for (const selectedPath of selectedPaths) {
        const parts = getPathParts(selectedPath)
        const firstMapped = getFirstMappedTeamOnPath(parts, mapping)
        if (!firstMapped) continue

        const triggerName = firstMapped.component || 'Unknown'
        if (!taggedComponents.has(triggerName)) {
            taggedComponents.set(triggerName, { versions: new Set(), tag: firstMapped.team })
        }
    }

    for (const instance of allInstances) {
        const name = instance.component_name || 'Unknown'
        const directTag = getPrimaryTeamForComponent(name, mapping)
        if (!directTag) continue

        if (!taggedComponents.has(name)) {
            taggedComponents.set(name, { versions: new Set(), tag: directTag })
        }

        if (instance.component_version) {
            taggedComponents.get(name)?.versions.add(instance.component_version)
        }
    }

    return sortTaggedComponents(taggedComponents)
}

export function hasCodeAnalysisAvailableForGroup(
    group: GroupedVuln,
    mapping: Record<string, string | string[]>,
): boolean {
    return getTriggeringTaggedComponentsForGroup(group, mapping).length > 0
}

export function useVulnDependencyInfo({ group, teamMapping, refreshCounter }: UseVulnDependencyInfoOptions) {
    const allInstances = computed(() => {
        refreshCounter?.value
        return group.value.affected_versions?.flatMap(version => version.components) || []
    })

    const getInstanceTeamKey = (instance: Partial<Instance>, index: number) => {
        return instance.finding_uuid || `${instance.project_uuid || ''}:${instance.component_uuid || ''}:${index}`
    }

    const instanceTeams = computed(() => {
        const teamsByInstance = new Map<string, string[]>()
        allInstances.value.forEach((instance, index) => {
            teamsByInstance.set(
                getInstanceTeamKey(instance, index),
                getClosestAffectedTeamsForInstance(instance, teamMapping.value || {}),
            )
        })
        return teamsByInstance
    })

    const effectiveTags = computed(() => {
        const derived = getClosestAffectedTeamsForInstances(allInstances.value, teamMapping.value || {})
        if (derived.length > 0) return derived
        return normalizeLegacyTags(group.value.tags, teamMapping.value)
    })

    const dependencyRelationship = computed<DependencyRelationship>(() => {
        const flags = new Set(
            allInstances.value
                .map(instance => instance.is_direct_dependency)
                .filter((value): value is boolean => typeof value === 'boolean'),
        )

        if (flags.has(true)) return 'DIRECT'
        if (flags.has(false)) return 'TRANSITIVE'
        return 'UNKNOWN'
    })

    const sortedAffectedProjectVersions = computed(() => {
        const versions = (group.value.affected_versions || [])
            .map(version => version.project_version)
            .filter((version): version is string => !!version)

        return sortVersions(Array.from(new Set(versions)), true)
    })

    const uniqueComponents = computed(() => {
        const components = new Map<string, Set<string>>()
        for (const instance of allInstances.value) {
            if (!components.has(instance.component_name)) {
                components.set(instance.component_name, new Set())
            }
            components.get(instance.component_name)?.add(instance.component_version)
        }

        return Array.from(components.entries()).map(([name, versions]) => ({
            name,
            versions: sortComponentVersions(versions),
        }))
    })

    const findMappingValue = (componentName: string) => {
        const lookup = normalizeComponentName(componentName)
        if (!lookup) return undefined
        for (const [key, value] of Object.entries(teamMapping.value || {})) {
            if (normalizeComponentName(key) === lookup) {
                return value
            }
        }
        return undefined
    }

    const affectedTaggedComponents = computed(() => {
        const taggedComponents = new Map<string, { versions: Set<string>; tag: string }>()
        for (const version of group.value.affected_versions || []) {
            for (const component of version.components || []) {
                const name = component.component_name || 'Unknown'
                const mappingValue = findMappingValue(name)
                if (!mappingValue) continue

                const tag = Array.isArray(mappingValue) ? mappingValue[0] : mappingValue
                if (!tag) continue

                if (!taggedComponents.has(name)) {
                    taggedComponents.set(name, { versions: new Set(), tag })
                }

                if (component.component_version) {
                    taggedComponents.get(name)?.versions.add(component.component_version)
                }
            }
        }

        return sortTaggedComponents(taggedComponents)
    })

    const triggeringTaggedComponents = computed(() => {
        return getTriggeringTaggedComponentsForGroup(group.value, teamMapping.value)
    })

    const normalizedTags = computed(() => effectiveTags.value)

    return {
        allInstances,
        getInstanceTeamKey,
        instanceTeams,
        effectiveTags,
        dependencyRelationship,
        sortedAffectedProjectVersions,
        uniqueComponents,
        affectedTaggedComponents,
        triggeringTaggedComponents,
        normalizedTags,
    }
}