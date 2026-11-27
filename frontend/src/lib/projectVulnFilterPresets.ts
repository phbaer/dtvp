import type { InconsistencyReason } from '../types'
import type {
    AutomaticAssessmentOutcome,
    AutomaticAssessmentRescoreState,
} from './automaticAssessmentFilters'
import { ANALYST_WORK_FILTERS, VISIBLE_LIFECYCLE_FILTERS } from './projectLifecycleFilters'

/** The project view's filter selection, as the sidebar edits it. */
export interface FilterState {
    originalSeverityFilters?: string[]
    ssvcFilters?: string[]
    evidenceFilters?: string[]
    sortBy: string
    sortOrder: 'asc' | 'desc'
    dependencyFilter: Array<'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'>
    tmrescoreFilter: Array<'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL'>
    automaticAssessmentFilter: Array<'WITH_AUTOMATIC_ASSESSMENT' | 'WITHOUT_AUTOMATIC_ASSESSMENT'>
    automaticAssessmentOutcomeFilter: AutomaticAssessmentOutcome[]
    automaticAssessmentRescoreFilter: AutomaticAssessmentRescoreState[]
    idFilter: string
    teamFilters?: string[]
    tagFilter: string
    teamAssessmentFilter?: string
    componentFilter: string
    assigneeFilter: string
    versionFilterInput: string
    lifecycleFilters: string[]
    inconsistencyReasonFilters?: InconsistencyReason[]
    analysisFilters: string[]
    cvssVersionMismatchOnly: boolean
    notRescoredOnly?: boolean
    newFindingsOnly?: boolean
    awaitingReviewOnly?: boolean
    changesRequestedOnly?: boolean
    mcpAssessmentsOnly?: boolean
    /** First-seen cutoff (ADR 0015): `YYYY-MM-DD`, `<N>d`, or ''. */
    cutoff: string
    cutoffMode: 'before' | 'after'
    /** Which date the cutoff compares: published (default) or first attributed. */
    cutoffBasis: 'published' | 'attributed'
}

export interface FilterOption {
    value: string
    label: string
    color: string
    description?: string
}

export type FilterPresetKey =
    | 'needs-assessment'
    | 'awaiting-review'
    | 'changes-requested'
    | 'conflicting'
    | 'new-findings'
    | 'all'

export interface FilterPreset {
    key: FilterPresetKey
    label: string
    detail: string
}

/**
 * Presets for the common jobs. A preset sets the status part of the
 * selection (status, awaiting review, conflicts, new findings and the
 * selected teams' assessment) and keeps the scope: search, teams, versions
 * and every filter under More filters.
 */
export const FILTER_PRESETS: readonly FilterPreset[] = [
    { key: 'needs-assessment', label: 'Needs my assessment', detail: 'Open or incomplete; with teams selected, theirs is missing' },
    { key: 'awaiting-review', label: 'Awaiting review', detail: 'Submitted, not yet approved' },
    { key: 'changes-requested', label: 'Changes requested', detail: 'A reviewer requested changes to a team assessment' },
    { key: 'conflicting', label: 'Conflicting', detail: 'Assessments disagree or need repair' },
    { key: 'new-findings', label: 'New findings', detail: 'Reported after the assessment' },
    { key: 'all', label: 'All', detail: 'Every status' },
]

interface PresetContext {
    /** Every inconsistency reason: all of them selected means "any conflict". */
    inconsistencyReasons: readonly InconsistencyReason[]
}

const hasTeams = (state: FilterState) => !!(state.teamFilters?.length || state.tagFilter)

const presetStatus = (key: FilterPresetKey, state: FilterState, context: PresetContext) => {
    const status = {
        lifecycleFilters: [...VISIBLE_LIFECYCLE_FILTERS],
        awaitingReviewOnly: false,
        changesRequestedOnly: false,
        inconsistencyReasonFilters: [] as InconsistencyReason[],
        newFindingsOnly: false,
        teamAssessmentFilter: 'ANY',
    }
    if (key === 'needs-assessment') {
        status.lifecycleFilters = [...ANALYST_WORK_FILTERS]
        if (hasTeams(state)) status.teamAssessmentFilter = 'MISSING'
    } else if (key === 'awaiting-review') {
        status.awaitingReviewOnly = true
    } else if (key === 'changes-requested') {
        status.changesRequestedOnly = true
    } else if (key === 'conflicting') {
        status.inconsistencyReasonFilters = [...context.inconsistencyReasons]
    } else if (key === 'new-findings') {
        status.newFindingsOnly = true
    }
    return status
}

export const applyFilterPreset = (
    state: FilterState,
    key: FilterPresetKey,
    context: PresetContext,
): FilterState => ({ ...state, ...presetStatus(key, state, context) })

const sameSet = (left: readonly string[], right: readonly string[]) =>
    left.length === right.length && left.every(value => right.includes(value))

/** The preset the selection equals, if any. */
export const activeFilterPreset = (
    state: FilterState,
    context: PresetContext,
): FilterPresetKey | undefined => FILTER_PRESETS.find(({ key }) => {
    if (key === 'conflicting' && !context.inconsistencyReasons.length) return false
    const status = presetStatus(key, state, context)
    return sameSet(state.lifecycleFilters, status.lifecycleFilters)
        && !!state.awaitingReviewOnly === status.awaitingReviewOnly
        && !!state.changesRequestedOnly === status.changesRequestedOnly
        && sameSet(state.inconsistencyReasonFilters || [], status.inconsistencyReasonFilters)
        && !!state.newFindingsOnly === status.newFindingsOnly
        && (state.teamAssessmentFilter || 'ANY') === status.teamAssessmentFilter
})?.key
