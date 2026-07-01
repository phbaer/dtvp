import type { VulnListItem } from './vulnListIndex'

export interface VulnListFacets {
    ids: string[]
    components: string[]
    teams: string[]
    assignees: string[]
    availableVersions: string[]
}

export interface VulnListFacetAccumulator {
    ids: Set<string>
    components: Set<string>
    teams: Set<string>
    assignees: Set<string>
    availableVersions: Set<string>
}

export interface VulnListTaskFacetCounts {
    ids?: Record<string, number>
    components?: Record<string, number>
    tags?: Record<string, number>
    assignees?: Record<string, number>
    versions?: Record<string, number>
}

const cleanFacetValue = (value: unknown) => String(value || '').trim()

const addFacetValue = (values: Set<string>, value: unknown) => {
    const cleaned = cleanFacetValue(value)
    if (cleaned) values.add(cleaned)
}

const sortFacetValues = (values: Set<string>) => {
    return Array.from(values)
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }))
}

const sortFacetCountKeys = (values: Record<string, number> | undefined) => {
    const accumulator = new Set<string>()
    Object.keys(values || {}).forEach(value => addFacetValue(accumulator, value))
    return sortFacetValues(accumulator)
}

export const createVulnListFacetAccumulator = (): VulnListFacetAccumulator => ({
    ids: new Set<string>(),
    components: new Set<string>(),
    teams: new Set<string>(),
    assignees: new Set<string>(),
    availableVersions: new Set<string>(),
})

export const addVulnListFacetItem = (
    accumulator: VulnListFacetAccumulator,
    item: VulnListItem,
) => {
    addFacetValue(accumulator.ids, item.id)
    item.group.aliases?.forEach(alias => addFacetValue(accumulator.ids, alias))
    item.componentNames.forEach(component => addFacetValue(accumulator.components, component))
    item.normalizedTags.forEach(team => addFacetValue(accumulator.teams, team))
    item.group.assignees?.forEach(assignee => addFacetValue(accumulator.assignees, assignee))
    item.versions.forEach(version => addFacetValue(accumulator.availableVersions, version))
}

export const finalizeVulnListFacets = (
    accumulator: VulnListFacetAccumulator,
): VulnListFacets => ({
    ids: sortFacetValues(accumulator.ids),
    components: sortFacetValues(accumulator.components),
    teams: sortFacetValues(accumulator.teams),
    assignees: sortFacetValues(accumulator.assignees),
    availableVersions: sortFacetValues(accumulator.availableVersions),
})

export const deriveVulnListFacets = (items: readonly VulnListItem[]): VulnListFacets => {
    const accumulator = createVulnListFacetAccumulator()
    for (const item of items) {
        addVulnListFacetItem(accumulator, item)
    }

    return finalizeVulnListFacets(accumulator)
}

export const deriveVulnListFacetsFromTaskCounts = (
    counts: VulnListTaskFacetCounts,
): VulnListFacets => ({
    ids: sortFacetCountKeys(counts.ids),
    components: sortFacetCountKeys(counts.components),
    teams: sortFacetCountKeys(counts.tags),
    assignees: sortFacetCountKeys(counts.assignees),
    availableVersions: sortFacetCountKeys(counts.versions),
})
