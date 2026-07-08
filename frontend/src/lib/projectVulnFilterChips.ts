import type { AutomaticAssessmentFilter, DependencyRelationship, TMRescoreProposalFilter } from './vulnListIndex'

export type ActiveFilterChipKey =
    | 'lifecycle'
    | 'analysis'
    | 'dependency'
    | 'id'
    | 'tag'
    | 'component'
    | 'assignee'
    | 'versions'
    | 'tmrescore'
    | 'automaticAssessment'
    | 'cvss'
    | 'attributionAge'

export interface ActiveFilterChip {
    key: ActiveFilterChipKey
    label: string
}

export interface ProjectVulnFilterOption {
    value: string
    label: string
}

export interface BuildActiveFilterChipsInput {
    lifecycleFilters: readonly string[]
    lifecycleOptions: readonly ProjectVulnFilterOption[]
    analysisFilters: readonly string[]
    analysisOptions: readonly ProjectVulnFilterOption[]
    dependencyFilters: readonly DependencyRelationship[]
    dependencyOptions: readonly ProjectVulnFilterOption[]
    idFilter: string
    tagFilter: string
    componentFilter: string
    assigneeFilter: string
    versionFilters: readonly string[]
    tmrescoreFilters: readonly TMRescoreProposalFilter[]
    tmrescoreOptions: readonly ProjectVulnFilterOption[]
    automaticAssessmentFilters: readonly AutomaticAssessmentFilter[]
    automaticAssessmentOptions: readonly ProjectVulnFilterOption[]
    cvssVersionMismatchOnly: boolean
    attributionAgeDays: number | null
    attributionAgeMode: 'older' | 'younger'
}

export interface HasCustomProjectVulnFilterStateInput {
    smartSearchInput: string
    idFilter: string
    tagFilter: string
    componentFilter: string
    assigneeFilter: string
    versionFilters: readonly string[]
    cvssVersionMismatchOnly: boolean
    attributionAgeDays: number | null
    sortBy: string
    sortOrder: 'asc' | 'desc'
    lifecycleFilters: readonly string[]
    defaultLifecycleFilters: readonly string[]
    analysisFilters: readonly string[]
    defaultAnalysisFilters: readonly string[]
    dependencyFilters: readonly DependencyRelationship[]
    defaultDependencyFilters: readonly DependencyRelationship[]
    tmrescoreFilters: readonly TMRescoreProposalFilter[]
    defaultTMRescoreFilters: readonly TMRescoreProposalFilter[]
    automaticAssessmentFilters: readonly AutomaticAssessmentFilter[]
    defaultAutomaticAssessmentFilters: readonly AutomaticAssessmentFilter[]
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

export function buildActiveFilterChips({
    lifecycleFilters,
    lifecycleOptions,
    analysisFilters,
    analysisOptions,
    dependencyFilters,
    dependencyOptions,
    idFilter,
    tagFilter,
    componentFilter,
    assigneeFilter,
    versionFilters,
    tmrescoreFilters,
    tmrescoreOptions,
    automaticAssessmentFilters,
    automaticAssessmentOptions,
    cvssVersionMismatchOnly,
    attributionAgeDays,
    attributionAgeMode,
}: BuildActiveFilterChipsInput): ActiveFilterChip[] {
    const chips: ActiveFilterChip[] = []

    if (!hasAllOptionsSelected(lifecycleFilters, lifecycleOptions)) {
        chips.push({ key: 'lifecycle', label: `Lifecycle: ${summarizedSelection(lifecycleFilters, lifecycleOptions, 'All lifecycle')}` })
    }
    if (!hasAllOptionsSelected(analysisFilters, analysisOptions)) {
        chips.push({ key: 'analysis', label: `State: ${summarizedSelection(analysisFilters, analysisOptions, 'All states')}` })
    }
    if (!hasAllOptionsSelected(dependencyFilters, dependencyOptions)) {
        chips.push({ key: 'dependency', label: `Dependency: ${summarizedSelection(dependencyFilters, dependencyOptions, 'All dependencies')}` })
    }

    if (idFilter) chips.push({ key: 'id', label: `ID: ${idFilter}` })
    if (tagFilter) chips.push({ key: 'tag', label: `Team: ${tagFilter}` })
    if (componentFilter) chips.push({ key: 'component', label: `Component: ${componentFilter}` })
    if (assigneeFilter) chips.push({ key: 'assignee', label: `Assignee: ${assigneeFilter}` })
    if (versionFilters.length) chips.push({ key: 'versions', label: `Versions: ${versionFilters.join(', ')}` })
    if (tmrescoreFilters.length !== tmrescoreOptions.length) {
        chips.push({ key: 'tmrescore', label: `TM: ${summarizedSelection(tmrescoreFilters, tmrescoreOptions, 'All proposals')}` })
    }
    if (automaticAssessmentFilters.length !== automaticAssessmentOptions.length) {
        chips.push({ key: 'automaticAssessment', label: `Auto: ${summarizedSelection(automaticAssessmentFilters, automaticAssessmentOptions, 'All automatic assessments')}` })
    }
    if (cvssVersionMismatchOnly) chips.push({ key: 'cvss', label: 'CVSS mismatch' })
    if (attributionAgeDays != null) {
        const verb = attributionAgeMode === 'younger' ? 'younger' : 'older'
        chips.push({ key: 'attributionAge', label: `Attributed ${verb} than ${attributionAgeDays}d` })
    }

    return chips
}

export function hasCustomProjectVulnFilterState({
    smartSearchInput,
    idFilter,
    tagFilter,
    componentFilter,
    assigneeFilter,
    versionFilters,
    cvssVersionMismatchOnly,
    attributionAgeDays,
    sortBy,
    sortOrder,
    lifecycleFilters,
    defaultLifecycleFilters,
    analysisFilters,
    defaultAnalysisFilters,
    dependencyFilters,
    defaultDependencyFilters,
    tmrescoreFilters,
    defaultTMRescoreFilters,
    automaticAssessmentFilters,
    defaultAutomaticAssessmentFilters,
}: HasCustomProjectVulnFilterStateInput): boolean {
    return !!smartSearchInput.trim()
        || !!idFilter
        || !!tagFilter
        || !!componentFilter
        || !!assigneeFilter
        || versionFilters.length > 0
        || cvssVersionMismatchOnly
        || attributionAgeDays != null
        || sortBy !== 'rescored-severity'
        || sortOrder !== 'desc'
        || !sameStringSet(lifecycleFilters, defaultLifecycleFilters)
        || !sameStringSet(analysisFilters, defaultAnalysisFilters)
        || !sameStringSet(dependencyFilters, defaultDependencyFilters)
        || !sameStringSet(tmrescoreFilters, defaultTMRescoreFilters)
        || !sameStringSet(automaticAssessmentFilters, defaultAutomaticAssessmentFilters)
}
