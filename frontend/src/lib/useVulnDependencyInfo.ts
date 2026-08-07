import { computed, type ComputedRef, type Ref } from 'vue'
import type { GroupedVuln, Instance } from '../types'
import {
    findTeamMappingEntryForComponent,
    getAffectedTeamsFromPaths,
    getFirstMappedTeamOnPath,
    getPathParts,
    normalizeLegacyTags,
    selectRepresentativePaths,
} from './dependency-team-selection'
import { resolveCanonicalTeamName } from './team-mapping'
import { sortVersions } from './version'

export type DependencyRelationship = 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'

interface TaggedComponentInfo {
    name: string
    versions: string[]
    tag: string
}

interface UseVulnDependencyInfoOptions {
    group: ComputedRef<GroupedVuln> | Ref<GroupedVuln>
    teamMapping: Ref<Record<string, string | string[]>>
    refreshCounter?: Ref<number>
    teamFilter?: ComputedRef<string> | Ref<string>
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

export function useVulnDependencyInfo({ group, teamMapping, refreshCounter, teamFilter }: UseVulnDependencyInfoOptions) {
    const allInstances = computed(() => {
        refreshCounter?.value
        return group.value.affected_versions?.flatMap(version => version.components) || []
    })

    const getInstanceTeamKey = (instance: Partial<Instance>, index: number) => {
        return instance.finding_uuid || `${instance.project_uuid || ''}:${instance.component_uuid || ''}:${index}`
    }

    const instanceOwnership = computed(() => {
        const mapping = teamMapping.value || {}
        return allInstances.value.map((instance, index) => {
            const directMapping = findTeamMappingEntryForComponent(
                instance.component_name,
                mapping,
                instance.component_group,
                'component_group' in instance,
                instance.component_purl,
            )
            const directTeam = directMapping?.tags[0] || ''
            return {
                instance,
                key: getInstanceTeamKey(instance, index),
                directTeam,
                teams: directTeam
                    ? [directTeam]
                    : getAffectedTeamsFromPaths(instance.dependency_chains, mapping),
            }
        })
    })

    const instanceTeams = computed(() => {
        return new Map(instanceOwnership.value.map(ownership => [
            ownership.key,
            ownership.teams,
        ]))
    })

    const activeTeam = computed(() => {
        const requested = String(teamFilter?.value || '').trim()
        if (!requested) return ''
        return resolveCanonicalTeamName(teamMapping.value, requested)
    })

    const visibleOwnership = computed(() => {
        const active = activeTeam.value.toLocaleLowerCase()
        if (!active) return instanceOwnership.value
        return instanceOwnership.value.filter(ownership =>
            ownership.teams.some(team => team.toLocaleLowerCase() === active)
        )
    })

    const visibleInstances = computed(() => {
        return visibleOwnership.value.map(ownership => ownership.instance)
    })

    const visibleInstanceSet = computed(() => new Set(visibleInstances.value))

    const effectiveTags = computed(() => {
        const derived = Array.from(new Set(
            instanceOwnership.value.flatMap(ownership => ownership.teams),
        ))
        if (derived.length > 0) return derived
        return normalizeLegacyTags(group.value.tags, teamMapping.value)
    })

    const dependencyRelationship = computed<DependencyRelationship>(() => {
        const flags = new Set(
            visibleInstances.value
                .map(instance => instance.is_direct_dependency)
                .filter((value): value is boolean => typeof value === 'boolean'),
        )

        if (flags.has(true)) return 'DIRECT'
        if (flags.has(false)) return 'TRANSITIVE'
        return 'UNKNOWN'
    })

    const sortedAffectedProjectVersions = computed(() => {
        const versions = (group.value.affected_versions || [])
            .filter(version => !activeTeam.value || (version.components || []).some(component =>
                visibleInstanceSet.value.has(component)
            ))
            .map(version => version.project_version)
            .filter((version): version is string => !!version)

        return sortVersions(Array.from(new Set(versions)), true)
    })

    const uniqueComponents = computed(() => {
        const components = new Map<string, Set<string>>()
        for (const instance of visibleInstances.value) {
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

    const affectedTaggedComponents = computed(() => {
        const taggedComponents = new Map<string, { versions: Set<string>; tag: string }>()
        for (const { instance: component, directTeam } of visibleOwnership.value) {
            const name = component.component_name || 'Unknown'
            if (!directTeam) continue

            if (!taggedComponents.has(name)) {
                taggedComponents.set(name, { versions: new Set(), tag: directTeam })
            }

            if (component.component_version) {
                taggedComponents.get(name)?.versions.add(component.component_version)
            }
        }

        return sortTaggedComponents(taggedComponents)
    })

    const triggeringTaggedComponents = computed(() => {
        const taggedComponents = new Map<string, { versions: Set<string>; tag: string }>()
        const paths = visibleInstances.value.flatMap(instance => instance.dependency_chains || [])
        const selectedPaths = selectRepresentativePaths(paths, teamMapping.value, 100)

        for (const selectedPath of selectedPaths) {
            const parts = getPathParts(selectedPath)
            const firstMapped = getFirstMappedTeamOnPath(parts, teamMapping.value)
            if (!firstMapped) continue

            const triggerName = firstMapped.component || 'Unknown'
            if (!taggedComponents.has(triggerName)) {
                taggedComponents.set(triggerName, { versions: new Set(), tag: firstMapped.team })
            }
        }

        for (const { instance, directTeam } of visibleOwnership.value) {
            const name = instance.component_name || 'Unknown'
            if (!directTeam) continue

            if (!taggedComponents.has(name)) {
                taggedComponents.set(name, { versions: new Set(), tag: directTeam })
            }

            if (instance.component_version) {
                taggedComponents.get(name)?.versions.add(instance.component_version)
            }
        }

        return sortTaggedComponents(taggedComponents)
    })

    const normalizedTags = computed(() => effectiveTags.value)

    return {
        allInstances,
        visibleInstances,
        activeTeam,
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
