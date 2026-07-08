import type { FilterCounts, TeamCounts } from './group-classifier'
import type { VulnListFacets } from './vulnListFacets'
import {
    addVulnListFacetItem,
    createVulnListFacetAccumulator,
    finalizeVulnListFacets,
} from './vulnListFacets'
import type {
    AutomaticAssessmentFilter,
    DependencyRelationship,
    ParsedVulnSearchQuery,
    TMRescoreProposalFilter,
    VulnListItem,
} from './vulnListIndex'
import {
    compileVulnListFilters,
    compileVulnStateFilters,
    matchesCompiledAttributionAgeFilter,
    matchesCompiledDependencySelection,
    matchesCompiledLifecycleFilter,
    matchesCompiledListFilters,
    matchesCompiledAutomaticAssessmentSelection,
    matchesCompiledStateFilters,
    matchesCompiledTMRescoreSelection,
} from './vulnListIndex'

export interface VulnListViewFilters {
    smartSearch?: ParsedVulnSearchQuery | string
    tagFilter?: string
    idFilter?: string
    componentFilter?: string
    assigneeFilter?: string
    dependencyFilter: DependencyRelationship[]
    tmrescoreProposalFilter: TMRescoreProposalFilter[]
    automaticAssessmentFilter: AutomaticAssessmentFilter[]
    versionFilterList: readonly string[]
    cvssVersionMismatchOnly: boolean
    attributionAgeDays: number | null
    attributionAgeMode: 'older' | 'younger'
    lifecycleFilters: string[]
    analysisFilters: string[]
    sortBy: string
    sortOrder: 'asc' | 'desc'
}

export type VulnListFilterModelFilters = Omit<VulnListViewFilters, 'sortBy' | 'sortOrder'>

export interface VulnListStaticStats {
    filterCounts: FilterCounts
    cvssVersionMismatchCount: number
    teamTagCounts: Record<string, TeamCounts>
    needsApprovalGroups: VulnListItem['group'][]
    incompleteGroups: VulnListItem['group'][]
}

export interface VulnListFilterModel extends VulnListStaticStats {
    preFilteredItems: VulnListItem[]
    matchingItems: VulnListItem[]
    dependencyFilterCounts: RelationshipCounts
    dependencyRelationshipCounts: RelationshipCounts
    tmrescoreProposalCounts: Record<TMRescoreProposalFilter, number>
    automaticAssessmentCounts: Record<AutomaticAssessmentFilter, number>
    attributionAgeCount: number
    analysisCounts: Record<string, number>
}

export interface VulnListViewModel extends VulnListFilterModel {
    sortedItems: VulnListItem[]
}

export interface VulnListGroupLookup {
    groups: VulnListItem['group'][]
    groupById: Map<string, VulnListItem['group']>
}

export interface VulnListBaseIndex {
    facets: VulnListFacets
    staticStats: VulnListStaticStats
    groupLookup: VulnListGroupLookup
}

export interface RelationshipCounts {
    direct: number
    transitive: number
    unknown: number
}

const ANALYSIS_STATE_ORDER: Record<string, number> = {
    EXPLOITABLE: 0,
    IN_TRIAGE: 1,
    NOT_SET: 2,
    RESOLVED: 3,
    FALSE_POSITIVE: 4,
    NOT_AFFECTED: 5,
}

const createFilterCounts = (): FilterCounts => ({
    OPEN: 0,
    ASSESSED: 0,
    ASSESSED_LEGACY: 0,
    INCOMPLETE: 0,
    INCONSISTENT: 0,
    NOT_SET: 0,
    EXPLOITABLE: 0,
    IN_TRIAGE: 0,
    RESOLVED: 0,
    FALSE_POSITIVE: 0,
    NOT_AFFECTED: 0,
    NEEDS_APPROVAL: 0,
})

const createRelationshipCounts = (): RelationshipCounts => ({
    direct: 0,
    transitive: 0,
    unknown: 0,
})

const createAnalysisCounts = (): Record<string, number> => ({
    EXPLOITABLE: 0,
    IN_TRIAGE: 0,
    NOT_SET: 0,
    RESOLVED: 0,
    FALSE_POSITIVE: 0,
    NOT_AFFECTED: 0,
    NEEDS_APPROVAL: 0,
})

const createTMRescoreCounts = (): Record<TMRescoreProposalFilter, number> => ({
    WITH_PROPOSAL: 0,
    WITHOUT_PROPOSAL: 0,
})

const createAutomaticAssessmentCounts = (): Record<AutomaticAssessmentFilter, number> => ({
    WITH_AUTOMATIC_ASSESSMENT: 0,
    WITHOUT_AUTOMATIC_ASSESSMENT: 0,
})

const incrementRelationship = (counts: RelationshipCounts, relationship: DependencyRelationship) => {
    counts[relationship.toLowerCase() as keyof RelationshipCounts]++
}

const updateStaticFilterCounts = (
    counts: FilterCounts,
    item: VulnListItem,
) => {
    if (item.isOpen) counts.OPEN++
    if (item.lifecycle === 'ASSESSED') counts.ASSESSED++
    if (item.lifecycle === 'ASSESSED_LEGACY') counts.ASSESSED_LEGACY++
    if (item.lifecycle === 'INCOMPLETE') counts.INCOMPLETE++
    if (item.lifecycle === 'INCONSISTENT') counts.INCONSISTENT++
    if (item.isPending) counts.NEEDS_APPROVAL++
}

const updateTechnicalStateCounts = (
    counts: FilterCounts,
    item: VulnListItem,
    stateFilters: ReturnType<typeof compileVulnStateFilters>,
) => {
    if (stateFilters.lifecycleFilters.length === 0 || matchesCompiledLifecycleFilter(item, stateFilters)) {
        counts[item.technicalState] = (counts[item.technicalState] || 0) + 1
    }
}

const updateTeamCounts = (
    counts: Record<string, TeamCounts>,
    item: VulnListItem,
) => {
    for (const team of item.normalizedTags) {
        if (!counts[team]) counts[team] = { open: 0, assessed: 0 }
        if (item.isOpen) {
            counts[team].open++
        } else {
            counts[team].assessed++
        }
    }
}

export const sortVulnListItems = (
    items: readonly VulnListItem[],
    sortBy: string,
    sortOrder: 'asc' | 'desc',
): VulnListItem[] => {
    const result = [...items]

    result.sort((a, b) => {
        let comparison = 0

        switch (sortBy) {
            case 'analysis':
                comparison = (ANALYSIS_STATE_ORDER[a.technicalState] ?? 99) -
                    (ANALYSIS_STATE_ORDER[b.technicalState] ?? 99)
                break
            case 'tags':
                comparison = a.firstTag.localeCompare(b.firstTag)
                break
            case 'severity':
                comparison = b.baseSeverityRank - a.baseSeverityRank
                break
            case 'rescored-severity':
                comparison = b.rescoredSeverityRank - a.rescoredSeverityRank
                break
            case 'score':
                comparison = a.baseScore - b.baseScore
                break
            case 'rescored':
                comparison = a.rescoredScore - b.rescoredScore
                break
            case 'id':
                comparison = a.id.localeCompare(b.id)
                break
        }

        if (comparison === 0) return a.id.localeCompare(b.id)
        return sortOrder === 'asc' ? comparison : -comparison
    })

    return result
}

export const deriveVulnListGroupLookup = (
    items: readonly VulnListItem[],
): VulnListGroupLookup => {
    const groups: VulnListItem['group'][] = []
    const groupById = new Map<string, VulnListItem['group']>()

    for (const item of items) {
        groups.push(item.group)
        groupById.set(item.id, item.group)
    }

    return { groups, groupById }
}

export const deriveVulnListBaseIndex = (
    items: readonly VulnListItem[],
): VulnListBaseIndex => {
    const facetAccumulator = createVulnListFacetAccumulator()
    const filterCounts = createFilterCounts()
    const teamTagCounts: Record<string, TeamCounts> = {}
    const needsApprovalGroups: VulnListItem['group'][] = []
    const incompleteGroups: VulnListItem['group'][] = []
    const groups: VulnListItem['group'][] = []
    const groupById = new Map<string, VulnListItem['group']>()
    let cvssVersionMismatchCount = 0

    for (const item of items) {
        addVulnListFacetItem(facetAccumulator, item)
        updateStaticFilterCounts(filterCounts, item)
        updateTeamCounts(teamTagCounts, item)
        groups.push(item.group)
        groupById.set(item.id, item.group)
        if (item.cvssVersionMismatch) cvssVersionMismatchCount++
        if (item.lifecycle === 'NEEDS_APPROVAL') needsApprovalGroups.push(item.group)
        if (item.lifecycle === 'INCOMPLETE') incompleteGroups.push(item.group)
    }

    return {
        facets: finalizeVulnListFacets(facetAccumulator),
        staticStats: {
            filterCounts,
            cvssVersionMismatchCount,
            teamTagCounts,
            needsApprovalGroups,
            incompleteGroups,
        },
        groupLookup: { groups, groupById },
    }
}

const cloneFilterCounts = (counts: FilterCounts): FilterCounts => ({
    ...createFilterCounts(),
    ...counts,
})

export const deriveVulnListStaticStats = (
    items: readonly VulnListItem[],
): VulnListStaticStats => {
    const filterCounts = createFilterCounts()
    const teamTagCounts: Record<string, TeamCounts> = {}
    const needsApprovalGroups: VulnListItem['group'][] = []
    const incompleteGroups: VulnListItem['group'][] = []
    let cvssVersionMismatchCount = 0

    for (const item of items) {
        updateStaticFilterCounts(filterCounts, item)
        updateTeamCounts(teamTagCounts, item)
        if (item.cvssVersionMismatch) cvssVersionMismatchCount++
        if (item.lifecycle === 'NEEDS_APPROVAL') needsApprovalGroups.push(item.group)
        if (item.lifecycle === 'INCOMPLETE') incompleteGroups.push(item.group)
    }

    return {
        filterCounts,
        cvssVersionMismatchCount,
        teamTagCounts,
        needsApprovalGroups,
        incompleteGroups,
    }
}

export const deriveVulnListFilterModel = (
    items: readonly VulnListItem[],
    filters: VulnListFilterModelFilters,
    staticStats: VulnListStaticStats = deriveVulnListStaticStats(items),
): VulnListFilterModel => {
    const preFilteredItems: VulnListItem[] = []
    const matchingItems: VulnListItem[] = []
    const filterCounts = cloneFilterCounts(staticStats.filterCounts)
    const dependencyFilterCounts = createRelationshipCounts()
    const dependencyRelationshipCounts = createRelationshipCounts()
    const tmrescoreProposalCounts = createTMRescoreCounts()
    const automaticAssessmentCounts = createAutomaticAssessmentCounts()
    const analysisCounts = createAnalysisCounts()
    let attributionAgeCount = 0

    const listFilterInput = compileVulnListFilters({
        smartSearch: filters.smartSearch,
        tagFilter: filters.tagFilter,
        idFilter: filters.idFilter,
        componentFilter: filters.componentFilter,
        assigneeFilter: filters.assigneeFilter,
        dependencyFilter: filters.dependencyFilter,
        tmrescoreProposalFilter: filters.tmrescoreProposalFilter,
        automaticAssessmentFilter: filters.automaticAssessmentFilter,
        versionFilterList: filters.versionFilterList,
        cvssVersionMismatchOnly: filters.cvssVersionMismatchOnly,
        attributionAgeDays: filters.attributionAgeDays,
        attributionAgeMode: filters.attributionAgeMode,
    })

    const stateFilterInput = compileVulnStateFilters({
        lifecycleFilters: filters.lifecycleFilters,
        analysisFilters: filters.analysisFilters,
    })

    for (const item of items) {
        updateTechnicalStateCounts(filterCounts, item, stateFilterInput)

        const matchesLifecycle = stateFilterInput.lifecycleFilters.length === 0 ||
            matchesCompiledLifecycleFilter(item, stateFilterInput)

        if (matchesLifecycle) {
            incrementRelationship(dependencyFilterCounts, item.dependencyRelationship)

            if (matchesCompiledDependencySelection(item, listFilterInput, true)) {
                if (item.hasTmrescoreProposal) tmrescoreProposalCounts.WITH_PROPOSAL++
                else tmrescoreProposalCounts.WITHOUT_PROPOSAL++

                if (matchesCompiledTMRescoreSelection(item, listFilterInput, true)) {
                    if (item.hasAutomaticAssessment) automaticAssessmentCounts.WITH_AUTOMATIC_ASSESSMENT++
                    else automaticAssessmentCounts.WITHOUT_AUTOMATIC_ASSESSMENT++

                    if (!matchesCompiledAutomaticAssessmentSelection(item, listFilterInput, true)) {
                        continue
                    }

                    const matchesAge = matchesCompiledAttributionAgeFilter(item, listFilterInput)

                    if (listFilterInput.attributionAgeActive && matchesAge) {
                        attributionAgeCount++
                    }

                    if (matchesAge) {
                        analysisCounts[item.technicalState] = (analysisCounts[item.technicalState] || 0) + 1
                    }
                }
            }
        }

        if (!matchesCompiledListFilters(item, listFilterInput)) continue
        preFilteredItems.push(item)

        if (!matchesCompiledStateFilters(item, stateFilterInput)) continue
        matchingItems.push(item)
        incrementRelationship(dependencyRelationshipCounts, item.dependencyRelationship)
    }

    return {
        preFilteredItems,
        matchingItems,
        filterCounts,
        cvssVersionMismatchCount: staticStats.cvssVersionMismatchCount,
        teamTagCounts: staticStats.teamTagCounts,
        dependencyFilterCounts,
        dependencyRelationshipCounts,
        tmrescoreProposalCounts,
        automaticAssessmentCounts,
        attributionAgeCount,
        analysisCounts,
        needsApprovalGroups: staticStats.needsApprovalGroups,
        incompleteGroups: staticStats.incompleteGroups,
    }
}

export const deriveVulnListViewModel = (
    items: readonly VulnListItem[],
    filters: VulnListViewFilters,
): VulnListViewModel => {
    const filterModel = deriveVulnListFilterModel(items, filters)
    return {
        ...filterModel,
        sortedItems: sortVulnListItems(filterModel.matchingItems, filters.sortBy, filters.sortOrder),
    }
}
