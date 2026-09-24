import type { FilterCounts, TeamCounts } from './group-classifier'
import { evidenceSources } from './evidence'
import { expandLifecycleSelection, VISIBLE_LIFECYCLE_FILTERS } from './projectLifecycleFilters'
import type { TaskVulnGroupListCounts } from './api'
import type { InconsistencyReason } from '../types'
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
    teamAssessmentStatus,
    compileVulnListFilters,
    compileVulnStateFilters,
    matchesCompiledAttributionAgeFilter,
    matchesCompiledDependencySelection,
    matchesCompiledLifecycleFilter,
    parseVulnSearchQuery,
    matchesCompiledListFilters,
    matchesCompiledAutomaticAssessmentSelection,
    matchesCompiledAutomaticAssessmentFacetSelection,
    matchesCompiledStateFilters,
    matchesCompiledTMRescoreSelection,
} from './vulnListIndex'
import { AUTOMATIC_ASSESSMENT_OUTCOME_OPTIONS, AUTOMATIC_ASSESSMENT_RESCORE_OPTIONS } from './automaticAssessmentFilters'
import type {
    AutomaticAssessmentOutcome,
    AutomaticAssessmentRescoreState,
} from './automaticAssessmentFilters'

export interface VulnListViewFilters {
    originalSeverityFilters?: string[]
    ssvcFilters?: string[]
    evidenceFilters?: string[]
    smartSearch?: ParsedVulnSearchQuery | string
    teamFilters?: readonly string[]
    tagFilter?: string
    idFilter?: string
    componentFilter?: string
    assigneeFilter?: string
    dependencyFilter: DependencyRelationship[]
    tmrescoreProposalFilter: TMRescoreProposalFilter[]
    automaticAssessmentFilter: AutomaticAssessmentFilter[]
    automaticAssessmentOutcomeFilter: AutomaticAssessmentOutcome[]
    automaticAssessmentRescoreFilter: AutomaticAssessmentRescoreState[]
    teamAssessmentFilter?: string
    inconsistencyReasonFilter?: InconsistencyReason[]
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
    assessmentRestoreCount: number
    assessmentRestoreRecoverableCount: number
    inconsistencyReasonCounts: Record<InconsistencyReason, number>
    teamTagCounts: Record<string, TeamCounts>
    needsApprovalGroups: VulnListItem['group'][]
    incompleteGroups: VulnListItem['group'][]
    assessmentRestoreGroups: VulnListItem['group'][]
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

const incrementResultCount = (counts: Record<string, number>, value: unknown) => {
    const key = String(value || '').trim()
    if (key) counts[key] = (counts[key] || 0) + 1
}

const incrementUniqueResultCounts = (
    counts: Record<string, number>,
    values: readonly unknown[],
) => {
    const seen = new Set<string>()
    for (const value of values) {
        const key = String(value || '').trim()
        const normalized = key.toLowerCase()
        if (!key || seen.has(normalized)) continue
        seen.add(normalized)
        incrementResultCount(counts, key)
    }
}

/**
 * Build the same count shape as a backend task window from an already-filtered
 * local list. This keeps the pre-task and legacy list paths aligned with the
 * server-owned filtered counter contract.
 */
export const deriveVulnListResultCounts = (
    items: readonly VulnListItem[],
): TaskVulnGroupListCounts => {
    const counts: TaskVulnGroupListCounts = {
        original_severity: {},
        ssvc: {},
        evidence: {},
        total: items.length,
        lifecycle: {
            OPEN: 0,
            ASSESSED: 0,
            ASSESSED_LEGACY: 0,
            INCOMPLETE: 0,
            INCONSISTENT: 0,
            NEEDS_APPROVAL: 0,
            READY_FOR_APPROVAL: 0,
        },
        inconsistency_reason: createInconsistencyReasonCounts(),
        analysis: createAnalysisCounts(),
        dependency_relationship: createRelationshipCounts(),
        cvss_version_mismatch: 0,
        ids: {},
        versions: {},
        tags: {},
        assignees: {},
        components: {},
        team_tags: {},
        canonical_team_tags: {},
        tmrescore: createTMRescoreCounts(),
        automatic_assessment: createAutomaticAssessmentCounts(),
        automatic_assessment_outcome: createAutomaticAssessmentOutcomeCounts(),
        automatic_assessment_rescore: createAutomaticAssessmentRescoreCounts(),
        assessment_restore: {
            WITH_RESTORE: 0,
            RECOVERABLE: 0,
            AMBIGUOUS: 0,
            NO_HISTORY: 0,
        },
        attribution_age: items.length,
    }

    for (const item of items) {
        if (item.lifecycle === 'OPEN') counts.lifecycle.OPEN++
        else if (item.lifecycle in counts.lifecycle && item.lifecycle !== 'NEEDS_APPROVAL') {
            counts.lifecycle[item.lifecycle]++
        }
        if (item.lifecycle === 'ASSESSED_LEGACY') counts.lifecycle.ASSESSED++
        if (item.isPending) counts.lifecycle.NEEDS_APPROVAL++
        if (item.isApprovalReady) counts.lifecycle.READY_FOR_APPROVAL++

        incrementResultCount(counts.analysis, item.technicalState)
        counts.dependency_relationship[item.dependencyRelationship.toLowerCase() as keyof RelationshipCounts]++
        incrementResultCount(counts.original_severity!, item.originalSeverity)
        incrementResultCount(counts.ssvc!, item.group.ssvc_summary?.status || 'UNASSESSED')
        incrementUniqueResultCounts(counts.evidence!, evidenceSources(item.group))
        if (item.cvssVersionMismatch) counts.cvss_version_mismatch++

        incrementUniqueResultCounts(counts.ids!, [item.id, ...(item.group.aliases || [])])
        incrementUniqueResultCounts(counts.versions, item.versions)
        incrementUniqueResultCounts(counts.tags, item.normalizedTags)
        incrementUniqueResultCounts(counts.assignees, item.group.assignees || [])
        incrementUniqueResultCounts(counts.components, item.componentNames)

        for (const team of new Set(item.normalizedTags)) {
            const teamCounts = counts.team_tags![team] ||= { open: 0, assessed: 0 }
            const canonicalTeamCounts = counts.canonical_team_tags![team] ||= { open: 0, assessed: 0 }
            if (item.isOpen) teamCounts.open++
            else teamCounts.assessed++
            if (item.isOpen) canonicalTeamCounts.open++
            else canonicalTeamCounts.assessed++
        }
        for (const reason of item.inconsistencyReasons) {
            incrementResultCount(counts.inconsistency_reason!, reason)
        }

        if (item.hasTmrescoreProposal) counts.tmrescore!.WITH_PROPOSAL++
        else counts.tmrescore!.WITHOUT_PROPOSAL++
        if (item.hasAutomaticAssessment) {
            counts.automatic_assessment!.WITH_AUTOMATIC_ASSESSMENT++
        } else {
            counts.automatic_assessment!.WITHOUT_AUTOMATIC_ASSESSMENT++
        }
        if (item.automaticAssessmentOutcome) {
            counts.automatic_assessment_outcome![item.automaticAssessmentOutcome]++
        }
        if (item.automaticAssessmentRescore) {
            counts.automatic_assessment_rescore![item.automaticAssessmentRescore]++
        }

        if (item.assessmentRestoreCount > 0) {
            counts.assessment_restore!.WITH_RESTORE++
            switch (item.assessmentRestoreStatus) {
                case 'RECOVERABLE':
                    counts.assessment_restore!.RECOVERABLE++
                    break
                case 'AMBIGUOUS':
                    counts.assessment_restore!.AMBIGUOUS++
                    break
                case 'NO_HISTORY':
                    counts.assessment_restore!.NO_HISTORY++
                    break
            }
        }
    }

    return counts
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
    READY_FOR_APPROVAL: 0,
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

const createAutomaticAssessmentOutcomeCounts = (): Record<AutomaticAssessmentOutcome, number> => ({
    AFFECTED: 0,
    PROBABLY_AFFECTED: 0,
    NOT_AFFECTED: 0,
    INCONCLUSIVE: 0,
})

const createAutomaticAssessmentRescoreCounts = (): Record<AutomaticAssessmentRescoreState, number> => ({
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
    NO_RESCORE: 0,
    UNSCORED: 0,
})

const createInconsistencyReasonCounts = (): Record<InconsistencyReason, number> => ({
    MISSING_RESCORING_VECTOR: 0,
    ANALYSIS_STATE_MISMATCH: 0,
    TEAM_ASSESSMENT_MISMATCH: 0,
    ASSESSMENT_DETAILS_MISMATCH: 0,
})

const incrementRelationship = (counts: RelationshipCounts, relationship: DependencyRelationship) => {
    counts[relationship.toLowerCase() as keyof RelationshipCounts]++
}

const updateStaticFilterCounts = (
    counts: FilterCounts,
    item: VulnListItem,
) => {
    if (item.lifecycle === 'OPEN') counts.OPEN++
    if (['ASSESSED', 'ASSESSED_LEGACY'].includes(item.lifecycle)) counts.ASSESSED++
    if (item.lifecycle === 'ASSESSED_LEGACY') counts.ASSESSED_LEGACY++
    if (item.lifecycle === 'INCOMPLETE') counts.INCOMPLETE++
    if (item.lifecycle === 'INCONSISTENT') counts.INCONSISTENT++
    if (item.isPending) counts.NEEDS_APPROVAL++
    if (item.isApprovalReady) counts.READY_FOR_APPROVAL++
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
    const assessmentRestoreGroups: VulnListItem['group'][] = []
    const groups: VulnListItem['group'][] = []
    const groupById = new Map<string, VulnListItem['group']>()
    let cvssVersionMismatchCount = 0
    let assessmentRestoreCount = 0
    let assessmentRestoreRecoverableCount = 0
    const inconsistencyReasonCounts = createInconsistencyReasonCounts()

    for (const item of items) {
        addVulnListFacetItem(facetAccumulator, item)
        updateStaticFilterCounts(filterCounts, item)
        updateTeamCounts(teamTagCounts, item)
        groups.push(item.group)
        groupById.set(item.id, item.group)
        if (item.cvssVersionMismatch) cvssVersionMismatchCount++
        if (item.assessmentRestoreCount > 0) {
            assessmentRestoreCount++
            assessmentRestoreGroups.push(item.group)
        }
        if (item.assessmentRestoreRecoverableCount > 0) {
            assessmentRestoreRecoverableCount++
        }
        for (const reason of item.inconsistencyReasons) inconsistencyReasonCounts[reason]++
        if (item.lifecycle === 'NEEDS_APPROVAL') needsApprovalGroups.push(item.group)
        if (item.lifecycle === 'INCOMPLETE') incompleteGroups.push(item.group)
    }

    return {
        facets: finalizeVulnListFacets(facetAccumulator),
        staticStats: {
            filterCounts,
            cvssVersionMismatchCount,
            assessmentRestoreCount,
            assessmentRestoreRecoverableCount,
            inconsistencyReasonCounts,
            teamTagCounts,
            needsApprovalGroups,
            incompleteGroups,
            assessmentRestoreGroups,
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
    const assessmentRestoreGroups: VulnListItem['group'][] = []
    let cvssVersionMismatchCount = 0
    let assessmentRestoreCount = 0
    let assessmentRestoreRecoverableCount = 0
    const inconsistencyReasonCounts = createInconsistencyReasonCounts()

    for (const item of items) {
        updateStaticFilterCounts(filterCounts, item)
        updateTeamCounts(teamTagCounts, item)
        if (item.cvssVersionMismatch) cvssVersionMismatchCount++
        if (item.assessmentRestoreCount > 0) {
            assessmentRestoreCount++
            assessmentRestoreGroups.push(item.group)
        }
        if (item.assessmentRestoreRecoverableCount > 0) {
            assessmentRestoreRecoverableCount++
        }
        for (const reason of item.inconsistencyReasons) inconsistencyReasonCounts[reason]++
        if (item.lifecycle === 'NEEDS_APPROVAL') needsApprovalGroups.push(item.group)
        if (item.lifecycle === 'INCOMPLETE') incompleteGroups.push(item.group)
    }

    return {
        filterCounts,
        cvssVersionMismatchCount,
        assessmentRestoreCount,
        assessmentRestoreRecoverableCount,
        inconsistencyReasonCounts,
        teamTagCounts,
        needsApprovalGroups,
        incompleteGroups,
        assessmentRestoreGroups,
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
        originalSeverityFilters: filters.originalSeverityFilters,
        ssvcFilters: filters.ssvcFilters,
        evidenceFilters: filters.evidenceFilters,
        smartSearch: filters.smartSearch,
        teamAssessmentFilter: filters.teamAssessmentFilter,
        tagFilter: filters.tagFilter,
        teamFilters: filters.teamFilters,
        idFilter: filters.idFilter,
        componentFilter: filters.componentFilter,
        assigneeFilter: filters.assigneeFilter,
        dependencyFilter: filters.dependencyFilter,
        tmrescoreProposalFilter: filters.tmrescoreProposalFilter,
        automaticAssessmentFilter: filters.automaticAssessmentFilter,
        automaticAssessmentOutcomeFilter: filters.automaticAssessmentOutcomeFilter,
        automaticAssessmentRescoreFilter: filters.automaticAssessmentRescoreFilter,
        inconsistencyReasonFilter: filters.inconsistencyReasonFilter,
        versionFilterList: filters.versionFilterList,
        cvssVersionMismatchOnly: filters.cvssVersionMismatchOnly,
        attributionAgeDays: filters.attributionAgeDays,
        attributionAgeMode: filters.attributionAgeMode,
    })

    const parsedSearch = typeof filters.smartSearch === 'string'
        ? parseVulnSearchQuery(filters.smartSearch)
        : filters.smartSearch
    const stateFilterInput = compileVulnStateFilters({
        lifecycleFilters: expandLifecycleSelection(filters.lifecycleFilters),
        analysisFilters: filters.analysisFilters,
        teamScope: { teams: filters.teamFilters || (filters.tagFilter ? [filters.tagFilter] : []) },
        teamAssessmentFilter: filters.teamAssessmentFilter,
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
                    if (!matchesCompiledAutomaticAssessmentFacetSelection(item, listFilterInput, true)) {
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

        if (parsedSearch?.teamTerms.length || !matchesCompiledListFilters(item, listFilterInput)) continue
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
        assessmentRestoreRecoverableCount: staticStats.assessmentRestoreRecoverableCount,
        assessmentRestoreCount: staticStats.assessmentRestoreCount,
        inconsistencyReasonCounts: staticStats.inconsistencyReasonCounts,
        assessmentRestoreGroups: staticStats.assessmentRestoreGroups,
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

// Each option count applies the other selections, excluding its own category.
export const deriveVulnListFacetCounts = (
    items: readonly VulnListItem[], filters: VulnListFilterModelFilters,
    staticStats: VulnListStaticStats,
): TaskVulnGroupListCounts => {
    const count = (overrides: Partial<VulnListFilterModelFilters>) => deriveVulnListResultCounts(
        deriveVulnListFilterModel(items, { ...filters, ...overrides }, staticStats).matchingItems,
    )
    const result = count({})
    const facets: [keyof TaskVulnGroupListCounts, Partial<VulnListFilterModelFilters>][] = [
        ['lifecycle', { lifecycleFilters: VISIBLE_LIFECYCLE_FILTERS }],
        ['analysis', { analysisFilters: ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED'] }],
        ['inconsistency_reason', { inconsistencyReasonFilter: [] }],
        ['original_severity', { originalSeverityFilters: [] }],
        ['ssvc', { ssvcFilters: [] }],
        ['evidence', { evidenceFilters: [] }],
        ['dependency_relationship', { dependencyFilter: ['DIRECT', 'TRANSITIVE', 'UNKNOWN'] }],
        ['tmrescore', { tmrescoreProposalFilter: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'] }],
        ['automatic_assessment', { automaticAssessmentFilter: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'] }],
        ['automatic_assessment_outcome', { automaticAssessmentOutcomeFilter: AUTOMATIC_ASSESSMENT_OUTCOME_OPTIONS.map(option => option.value) }],
        ['automatic_assessment_rescore', { automaticAssessmentRescoreFilter: AUTOMATIC_ASSESSMENT_RESCORE_OPTIONS.map(option => option.value) }],
        ['cvss_version_mismatch', { cvssVersionMismatchOnly: false }],
    ]
    const parsed = typeof filters.smartSearch === 'string' ? parseVulnSearchQuery(filters.smartSearch) : filters.smartSearch
    const searchOverrides: Partial<Record<keyof TaskVulnGroupListCounts, Partial<ParsedVulnSearchQuery>>> = {
        lifecycle: { lifecycleTerms: [] }, analysis: { analysisTerms: [] },
        dependency_relationship: { dependencyTerms: [] }, tmrescore: { tmrescoreTerms: [] },
        cvss_version_mismatch: { cvssMismatchOnly: false },
    }
    for (const [field, overrides] of facets) {
        const smartSearch = parsed ? { ...parsed, ...searchOverrides[field] } : undefined
        Object.assign(result, { [field]: count({ ...overrides, smartSearch })[field] })
    }
    const coverageItems = deriveVulnListFilterModel(items, { ...filters, teamAssessmentFilter: 'ANY' }, staticStats).matchingItems
    result.team_assessment = { MISSING: 0, DOCUMENTED: 0 }
    for (const item of coverageItems) {
        const status = teamAssessmentStatus(item, { teams: filters.teamFilters || (filters.tagFilter ? [filters.tagFilter] : []) })
        if (status) result.team_assessment[status]++
    }
    return result
}
