import type { TaskVulnGroupListQuery } from './api'
import type { InconsistencyReason, TMRescoreProposal } from '../types'
import {
    isMeaningfulTMRescoreProposalCandidate,
    type AutomaticAssessmentFilter,
    type DependencyRelationship,
    type ParsedVulnSearchQuery,
    type TMRescoreProposalFilter,
} from './vulnListIndex'

export const NO_MATCH_FILTER = '__NO_MATCH__'

export interface BuildTaskVulnGroupListQueryInput {
    parsedSearch: ParsedVulnSearchQuery
    filtersReady: boolean
    lifecycleFilters: readonly string[]
    inconsistencyReasonFilters?: readonly InconsistencyReason[]
    defaultLifecycleFilters: readonly string[]
    analysisFilters: readonly string[]
    defaultAnalysisFilters: readonly string[]
    tagFilter: string
    idFilter: string
    componentFilter: string
    assigneeFilter: string
    dependencyFilters: readonly DependencyRelationship[]
    versionFilters: readonly string[]
    cvssVersionMismatchOnly: boolean
    attributionAgeDays: number | null
    attributionAgeMode: 'older' | 'younger'
    tmrescoreFilters: readonly TMRescoreProposalFilter[]
    allTMRescoreFilterValues: readonly TMRescoreProposalFilter[]
    meaningfulTMRescoreProposalIds: readonly string[]
    automaticAssessmentFilters: readonly AutomaticAssessmentFilter[]
    allAutomaticAssessmentFilterValues: readonly AutomaticAssessmentFilter[]
    automaticAssessmentIds: readonly string[]
    sortBy: string
    sortOrder: 'asc' | 'desc'
}

export const uniqueStrings = (values: Array<string | null | undefined>) => {
    const result: string[] = []
    const seen = new Set<string>()
    for (const value of values) {
        const text = String(value || '').trim()
        const key = text.toLowerCase()
        if (!text || seen.has(key)) continue
        result.push(text)
        seen.add(key)
    }
    return result
}

const joinSearchTerms = (values: Array<string | null | undefined>) => uniqueStrings(values).join(' ')

const intersectIfRestricted = <T extends string>(
    base: readonly T[],
    restriction: readonly T[],
): string[] => {
    if (restriction.length === 0) return [...base]
    const restrictionSet = new Set(restriction)
    const intersection = base.filter(value => restrictionSet.has(value))
    return intersection.length > 0 ? intersection : [NO_MATCH_FILTER]
}

const noMatchWhenEmpty = (values: readonly string[]) => values.length > 0 ? [...values] : [NO_MATCH_FILTER]

const hasSameStringSet = (a: readonly string[], b: readonly string[]) => {
    if (a.length !== b.length) return false
    const set = new Set(a)
    return b.every(value => set.has(value))
}

export function buildMeaningfulTMRescoreProposalIds(
    proposals: Record<string, TMRescoreProposal>,
): string[] {
    const ids: string[] = []
    const seen = new Set<string>()
    for (const [id, proposal] of Object.entries(proposals)) {
        if (!isMeaningfulTMRescoreProposalCandidate(proposal)) continue
        for (const candidate of [id, proposal.vuln_id]) {
            const text = String(candidate || '').trim()
            const key = text.toLowerCase()
            if (!text || seen.has(key)) continue
            ids.push(text)
            seen.add(key)
        }
    }
    return ids
}

export function buildTaskVulnGroupListQuery({
    parsedSearch,
    filtersReady,
    lifecycleFilters,
    inconsistencyReasonFilters = [],
    defaultLifecycleFilters,
    analysisFilters,
    defaultAnalysisFilters,
    tagFilter,
    idFilter,
    componentFilter,
    assigneeFilter,
    dependencyFilters,
    versionFilters,
    cvssVersionMismatchOnly,
    attributionAgeDays,
    attributionAgeMode,
    tmrescoreFilters,
    allTMRescoreFilterValues,
    meaningfulTMRescoreProposalIds,
    automaticAssessmentFilters,
    allAutomaticAssessmentFilterValues,
    automaticAssessmentIds,
    sortBy,
    sortOrder,
}: BuildTaskVulnGroupListQueryInput): TaskVulnGroupListQuery {
    const lifecycleBase = lifecycleFilters.length > 0 || filtersReady
        ? lifecycleFilters
        : defaultLifecycleFilters
    const analysisBase = analysisFilters.length > 0 || filtersReady
        ? analysisFilters
        : defaultAnalysisFilters
    const lifecycle = noMatchWhenEmpty(intersectIfRestricted(lifecycleBase, parsedSearch.lifecycleTerms))
    const analysis = noMatchWhenEmpty(intersectIfRestricted(analysisBase, parsedSearch.analysisTerms))
    const dependency = noMatchWhenEmpty(intersectIfRestricted(dependencyFilters, parsedSearch.dependencyTerms))
    const tmrescore = noMatchWhenEmpty(intersectIfRestricted(tmrescoreFilters, parsedSearch.tmrescoreTerms))
    const isTMRescoreRestricted = !hasSameStringSet(tmrescore, allTMRescoreFilterValues)
    const automaticAssessment = noMatchWhenEmpty(automaticAssessmentFilters)
    const isAutomaticAssessmentRestricted = !hasSameStringSet(automaticAssessment, allAutomaticAssessmentFilterValues)

    return {
        q: parsedSearch.textTerms.join(' '),
        lifecycle,
        inconsistency_reason: [...inconsistencyReasonFilters],
        analysis,
        tag: joinSearchTerms(parsedSearch.teamTerms),
        team: tagFilter,
        id: joinSearchTerms([idFilter, ...parsedSearch.idTerms]),
        component: joinSearchTerms([componentFilter, ...parsedSearch.componentTerms]),
        assignee: joinSearchTerms([assigneeFilter, ...parsedSearch.assigneeTerms]),
        dependency,
        versions: uniqueStrings([...versionFilters, ...parsedSearch.versionTerms]),
        cvss_mismatch: cvssVersionMismatchOnly || parsedSearch.cvssMismatchOnly,
        attributed_before_days: attributionAgeDays,
        attribution_mode: attributionAgeMode,
        tmrescore: isTMRescoreRestricted ? tmrescore : [],
        // Proposal IDs are also needed when the selection is unrestricted so
        // the backend can return accurate WITH/WITHOUT facet counts.
        tmrescore_proposal_ids: [...meaningfulTMRescoreProposalIds],
        automatic_assessment: isAutomaticAssessmentRestricted ? automaticAssessment : [],
        automatic_assessment_ids: [...automaticAssessmentIds],
        sort: sortBy,
        order: sortOrder,
    }
}
