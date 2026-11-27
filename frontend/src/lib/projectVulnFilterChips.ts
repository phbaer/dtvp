import { cutoffLabel, cutoffPurpose } from './cutoff'
import type { AutomaticAssessmentFilter, DependencyRelationship, TMRescoreProposalFilter } from './vulnListIndex'
import type { InconsistencyReason } from '../types'
import { evidenceLabel } from './evidence'
import type {
    AutomaticAssessmentOutcome,
    AutomaticAssessmentRescoreState,
} from './automaticAssessmentFilters'

export type ActiveFilterChipKey =
    | 'originalSeverity'
    | 'ssvc'
    | 'evidence'
    | 'lifecycle'
    | 'analysis'
    | 'inconsistencyReason'
    | 'teamAssessment'
    | 'dependency'
    | 'id'
    | 'tag'
    | 'component'
    | 'assignee'
    | 'versions'
    | 'tmrescore'
    | 'automaticAssessment'
    | 'automaticAssessmentOutcome'
    | 'automaticAssessmentRescore'
    | 'cvss'
    | 'notRescored'
    | 'newFindings'
    | 'awaitingReview'
    | 'changesRequested'
    | 'cutoff'

export interface ActiveFilterChip {
    key: ActiveFilterChipKey
    label: string
    /** Longer explanation, for the chip's title. */
    title?: string
}

export interface ProjectVulnFilterOption {
    value: string
    label: string
}

export interface BuildActiveFilterChipsInput {
    originalSeverityFilters?: readonly string[]
    ssvcFilters?: readonly string[]
    evidenceFilters?: readonly string[]
    lifecycleFilters: readonly string[]
    lifecycleOptions: readonly ProjectVulnFilterOption[]
    teamAssessmentFilter?: string
    inconsistencyReasonFilters?: readonly InconsistencyReason[]
    inconsistencyReasonOptions?: readonly ProjectVulnFilterOption[]
    analysisFilters: readonly string[]
    analysisOptions: readonly ProjectVulnFilterOption[]
    dependencyFilters: readonly DependencyRelationship[]
    dependencyOptions: readonly ProjectVulnFilterOption[]
    idFilter: string
    teamFilters?: readonly string[]
    tagFilter: string
    componentFilter: string
    assigneeFilter: string
    versionFilters: readonly string[]
    tmrescoreFilters: readonly TMRescoreProposalFilter[]
    tmrescoreOptions: readonly ProjectVulnFilterOption[]
    automaticAssessmentFilters: readonly AutomaticAssessmentFilter[]
    automaticAssessmentOptions: readonly ProjectVulnFilterOption[]
    automaticAssessmentOutcomeFilters: readonly AutomaticAssessmentOutcome[]
    automaticAssessmentOutcomeOptions: readonly ProjectVulnFilterOption[]
    automaticAssessmentRescoreFilters: readonly AutomaticAssessmentRescoreState[]
    automaticAssessmentRescoreOptions: readonly ProjectVulnFilterOption[]
    cvssVersionMismatchOnly: boolean
    notRescoredOnly?: boolean
    newFindingsOnly?: boolean
    awaitingReviewOnly?: boolean
    changesRequestedOnly?: boolean
    cutoff: string
    cutoffMode: 'before' | 'after'
    cutoffBasis?: 'published' | 'attributed'
}

export interface HasCustomProjectVulnFilterStateInput {
    defaultTeamAssessmentFilter?: string
    /** Reviewers start on Awaiting review. */
    defaultAwaitingReviewOnly?: boolean
    originalSeverityFilters?: readonly string[]
    ssvcFilters?: readonly string[]
    evidenceFilters?: readonly string[]
    smartSearchInput: string
    idFilter: string
    teamFilters?: readonly string[]
    tagFilter: string
    componentFilter: string
    assigneeFilter: string
    versionFilters: readonly string[]
    cvssVersionMismatchOnly: boolean
    notRescoredOnly?: boolean
    newFindingsOnly?: boolean
    awaitingReviewOnly?: boolean
    changesRequestedOnly?: boolean
    cutoff: string
    sortBy: string
    sortOrder: 'asc' | 'desc'
    lifecycleFilters: readonly string[]
    teamAssessmentFilter?: string
    inconsistencyReasonFilters?: readonly InconsistencyReason[]
    defaultLifecycleFilters: readonly string[]
    analysisFilters: readonly string[]
    defaultAnalysisFilters: readonly string[]
    dependencyFilters: readonly DependencyRelationship[]
    defaultDependencyFilters: readonly DependencyRelationship[]
    tmrescoreFilters: readonly TMRescoreProposalFilter[]
    defaultTMRescoreFilters: readonly TMRescoreProposalFilter[]
    automaticAssessmentFilters: readonly AutomaticAssessmentFilter[]
    defaultAutomaticAssessmentFilters: readonly AutomaticAssessmentFilter[]
    automaticAssessmentOutcomeFilters: readonly AutomaticAssessmentOutcome[]
    defaultAutomaticAssessmentOutcomeFilters: readonly AutomaticAssessmentOutcome[]
    automaticAssessmentRescoreFilters: readonly AutomaticAssessmentRescoreState[]
    defaultAutomaticAssessmentRescoreFilters: readonly AutomaticAssessmentRescoreState[]
}

export const optionLabel = (
    value: string,
    options: ReadonlyArray<ProjectVulnFilterOption>,
) => options.find(option => option.value === value)?.label || value.replace(/_/g, ' ')

export const sameStringSet = (a: readonly string[], b: readonly string[]) => {
    if (a.length !== b.length) return false
    const set = new Set(a)
    return b.every(value => set.has(value))
}

const summarizedSelection = (
    values: readonly string[],
    options: ReadonlyArray<ProjectVulnFilterOption>,
    allLabel: string,
) => {
    if (values.length === 0) return 'None'
    if (values.length === options.length) return allLabel
    return values.map(value => optionLabel(value, options)).join(', ')
}

const hasAllOptionsSelected = (
    values: readonly string[],
    options: ReadonlyArray<ProjectVulnFilterOption>,
) => {
    if (values.length !== options.length) return false
    const selected = new Set(values)
    return options.every(option => selected.has(option.value))
}

// Chips follow the sidebar: the primary filters first, then More filters,
// then the legacy ones. Each label starts with the sidebar section's name.
export function buildActiveFilterChips({
    originalSeverityFilters = [],
    ssvcFilters = [],
    evidenceFilters = [],
    lifecycleFilters,
    lifecycleOptions,
    teamAssessmentFilter = 'ANY',
    inconsistencyReasonFilters = [],
    inconsistencyReasonOptions = [],
    analysisFilters,
    analysisOptions,
    dependencyFilters,
    dependencyOptions,
    idFilter,
    tagFilter,
    teamFilters = [],
    componentFilter,
    assigneeFilter,
    versionFilters,
    tmrescoreFilters,
    tmrescoreOptions,
    automaticAssessmentFilters,
    automaticAssessmentOptions,
    automaticAssessmentOutcomeFilters,
    automaticAssessmentOutcomeOptions,
    automaticAssessmentRescoreFilters,
    automaticAssessmentRescoreOptions,
    cvssVersionMismatchOnly,
    notRescoredOnly,
    newFindingsOnly,
    awaitingReviewOnly,
    changesRequestedOnly,
    cutoff,
    cutoffMode,
    cutoffBasis = 'published',
}: BuildActiveFilterChipsInput): ActiveFilterChip[] {
    const chips: ActiveFilterChip[] = []
    if (awaitingReviewOnly) chips.push({ key: 'awaitingReview', label: 'Awaiting review' })
    if (changesRequestedOnly) chips.push({ key: 'changesRequested', label: 'Changes requested' })
    if (!hasAllOptionsSelected(lifecycleFilters, lifecycleOptions)) {
        chips.push({ key: 'lifecycle', label: `Status: ${summarizedSelection(lifecycleFilters, lifecycleOptions, 'All')}` })
    }
    if (teamFilters.length) chips.push({ key: 'tag', label: `Teams: ${teamFilters.join(', ')}` })
    else if (tagFilter) chips.push({ key: 'tag', label: `Team: ${tagFilter}` })
    if (teamAssessmentFilter !== 'ANY') chips.push({
        key: 'teamAssessment',
        label: `Team assessment: ${teamAssessmentFilter === 'DOCUMENTED' ? 'Recorded' : 'Not recorded'}`,
    })
    if (!hasAllOptionsSelected(analysisFilters, analysisOptions)) {
        chips.push({ key: 'analysis', label: `Analysis: ${summarizedSelection(analysisFilters, analysisOptions, 'All')}` })
    }
    if (versionFilters.length) chips.push({ key: 'versions', label: `Versions: ${versionFilters.join(', ')}` })
    if (idFilter) chips.push({ key: 'id', label: `ID: ${idFilter}` })
    if (componentFilter) chips.push({ key: 'component', label: `Component: ${componentFilter}` })
    if (assigneeFilter) chips.push({ key: 'assignee', label: `Assignee: ${assigneeFilter}` })

    if (inconsistencyReasonFilters.length > 0) {
        chips.push({
            key: 'inconsistencyReason',
            label: inconsistencyReasonOptions.length && hasAllOptionsSelected(inconsistencyReasonFilters, inconsistencyReasonOptions)
                ? 'Conflicting'
                : `Conflict: ${summarizedSelection(inconsistencyReasonFilters, inconsistencyReasonOptions, 'Any reason')}`,
        })
    }
    if (newFindingsOnly) chips.push({ key: 'newFindings', label: 'New findings' })
    if (originalSeverityFilters.length) chips.push({ key: 'originalSeverity', label: `Original severity: ${originalSeverityFilters.join(', ')}` })
    if (ssvcFilters.length) chips.push({ key: 'ssvc', label: `SSVC: ${ssvcFilters.map(v => v.replaceAll('_', ' ')).join(', ')}` })
    if (evidenceFilters.length) chips.push({ key: 'evidence', label: `Evidence: ${evidenceFilters.map(evidenceLabel).join(', ')}` })
    if (!hasAllOptionsSelected(dependencyFilters, dependencyOptions)) {
        chips.push({ key: 'dependency', label: `Dependency: ${summarizedSelection(dependencyFilters, dependencyOptions, 'All')}` })
    }
    if (notRescoredOnly) chips.push({ key: 'notRescored', label: 'CVSS: not rescored' })
    if (cvssVersionMismatchOnly) chips.push({ key: 'cvss', label: 'CVSS: version mismatch' })
    if (cutoff) chips.push({ key: 'cutoff', label: cutoffLabel(cutoff, cutoffMode, cutoffBasis), title: `${cutoffLabel(cutoff, cutoffMode, cutoffBasis)}: ${cutoffPurpose(cutoffBasis)} (according to the FDA guidance)` })

    // Legacy, removed in 2.1.0 (#342).
    if (tmrescoreFilters.length !== tmrescoreOptions.length) {
        chips.push({ key: 'tmrescore', label: `Threat-model proposal: ${summarizedSelection(tmrescoreFilters, tmrescoreOptions, 'All')}` })
    }
    if (automaticAssessmentFilters.length !== automaticAssessmentOptions.length) {
        chips.push({ key: 'automaticAssessment', label: `Automatic assessment: ${summarizedSelection(automaticAssessmentFilters, automaticAssessmentOptions, 'All')}` })
    }
    if (automaticAssessmentOutcomeFilters.length !== automaticAssessmentOutcomeOptions.length) {
        chips.push({
            key: 'automaticAssessmentOutcome',
            label: `Auto outcome: ${summarizedSelection(automaticAssessmentOutcomeFilters, automaticAssessmentOutcomeOptions, 'All')}`,
        })
    }
    if (automaticAssessmentRescoreFilters.length !== automaticAssessmentRescoreOptions.length) {
        chips.push({
            key: 'automaticAssessmentRescore',
            label: `Auto rescore: ${summarizedSelection(automaticAssessmentRescoreFilters, automaticAssessmentRescoreOptions, 'All')}`,
        })
    }

    return chips
}

export function hasCustomProjectVulnFilterState({
    originalSeverityFilters = [],
    ssvcFilters = [],
    evidenceFilters = [],
    smartSearchInput,
    idFilter,
    tagFilter,
    teamFilters = [],
    componentFilter,
    assigneeFilter,
    versionFilters,
    cvssVersionMismatchOnly,
    notRescoredOnly,
    newFindingsOnly,
    awaitingReviewOnly,
    changesRequestedOnly,
    defaultAwaitingReviewOnly = false,
    cutoff,
    sortBy,
    sortOrder,
    lifecycleFilters,
    teamAssessmentFilter = 'ANY',
    defaultTeamAssessmentFilter = 'ANY',
    inconsistencyReasonFilters = [],
    defaultLifecycleFilters,
    analysisFilters,
    defaultAnalysisFilters,
    dependencyFilters,
    defaultDependencyFilters,
    tmrescoreFilters,
    defaultTMRescoreFilters,
    automaticAssessmentFilters,
    defaultAutomaticAssessmentFilters,
    automaticAssessmentOutcomeFilters,
    defaultAutomaticAssessmentOutcomeFilters,
    automaticAssessmentRescoreFilters,
    defaultAutomaticAssessmentRescoreFilters,
}: HasCustomProjectVulnFilterStateInput): boolean {
    return !!smartSearchInput.trim()
        || originalSeverityFilters.length > 0
        || ssvcFilters.length > 0
        || evidenceFilters.length > 0
        || !!idFilter
        || teamFilters.length > 0
        || !!tagFilter
        || !!componentFilter
        || !!assigneeFilter
        || versionFilters.length > 0
        || cvssVersionMismatchOnly
        || notRescoredOnly
        || newFindingsOnly
        || changesRequestedOnly
        || !!awaitingReviewOnly !== defaultAwaitingReviewOnly
        || !!cutoff
        || sortBy !== 'rescored-severity'
        || sortOrder !== 'desc'
        || !sameStringSet(lifecycleFilters, defaultLifecycleFilters)
        || teamAssessmentFilter !== defaultTeamAssessmentFilter
        || inconsistencyReasonFilters.length > 0
        || !sameStringSet(analysisFilters, defaultAnalysisFilters)
        || !sameStringSet(dependencyFilters, defaultDependencyFilters)
        || !sameStringSet(tmrescoreFilters, defaultTMRescoreFilters)
        || !sameStringSet(automaticAssessmentFilters, defaultAutomaticAssessmentFilters)
        || !sameStringSet(automaticAssessmentOutcomeFilters, defaultAutomaticAssessmentOutcomeFilters)
        || !sameStringSet(automaticAssessmentRescoreFilters, defaultAutomaticAssessmentRescoreFilters)
}
