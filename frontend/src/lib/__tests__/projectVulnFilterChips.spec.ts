import { describe, expect, it } from 'vitest'
import {
    buildActiveFilterChips,
    hasCustomProjectVulnFilterState,
    optionLabel,
    sameStringSet,
} from '../projectVulnFilterChips'
import {
    DEFAULT_ANALYSIS_FILTERS,
    DEFAULT_REVIEWER_LIFECYCLE_FILTERS,
} from '../useProjectVulnFilters'

const lifecycleOptions = [
    { value: 'OPEN', label: 'Open' },
    { value: 'ASSESSED', label: 'Assessed' },
    { value: 'ASSESSED_LEGACY', label: 'Assessed (Legacy)' },
    { value: 'INCOMPLETE', label: 'Incomplete' },
    { value: 'INCONSISTENT', label: 'Inconsistent' },
    { value: 'NEEDS_APPROVAL', label: 'Needs Approval' },
]

const analysisOptions = DEFAULT_ANALYSIS_FILTERS.map(value => ({
    value,
    label: value.replace(/_/g, ' '),
}))

const dependencyOptions = [
    { value: 'DIRECT', label: 'Direct' },
    { value: 'TRANSITIVE', label: 'Transitive' },
    { value: 'UNKNOWN', label: 'Unknown' },
]

const tmrescoreOptions = [
    { value: 'WITH_PROPOSAL', label: 'with' },
    { value: 'WITHOUT_PROPOSAL', label: 'without' },
]

const automaticAssessmentOptions = [
    { value: 'WITH_AUTOMATIC_ASSESSMENT', label: 'available' },
    { value: 'WITHOUT_AUTOMATIC_ASSESSMENT', label: 'missing' },
]

describe('projectVulnFilterChips', () => {
    it('builds labels for only the active non-default filters', () => {
        const chips = buildActiveFilterChips({
            lifecycleFilters: ['OPEN'],
            lifecycleOptions,
            analysisFilters: DEFAULT_ANALYSIS_FILTERS,
            analysisOptions,
            dependencyFilters: ['DIRECT', 'UNKNOWN'],
            dependencyOptions,
            idFilter: 'CVE-2026-0001',
            tagFilter: 'platform',
            componentFilter: '',
            assigneeFilter: 'alice',
            versionFilters: ['1.0.0', '2.0.0'],
            tmrescoreFilters: ['WITH_PROPOSAL'],
            tmrescoreOptions,
            automaticAssessmentFilters: ['WITH_AUTOMATIC_ASSESSMENT'],
            automaticAssessmentOptions,
            cvssVersionMismatchOnly: true,
            attributionAgeDays: 14,
            attributionAgeMode: 'younger',
        })

        expect(chips).toEqual([
            { key: 'lifecycle', label: 'Lifecycle: Open' },
            { key: 'dependency', label: 'Dependency: Direct, Unknown' },
            { key: 'id', label: 'ID: CVE-2026-0001' },
            { key: 'tag', label: 'Team: platform' },
            { key: 'assignee', label: 'Assignee: alice' },
            { key: 'versions', label: 'Versions: 1.0.0, 2.0.0' },
            { key: 'tmrescore', label: 'TM: with' },
            { key: 'automaticAssessment', label: 'Auto: available' },
            { key: 'cvss', label: 'CVSS mismatch' },
            { key: 'attributionAge', label: 'Attributed younger than 14d' },
        ])
    })

    it('detects default versus customized filter state', () => {
        const defaultInput = {
            smartSearchInput: '',
            idFilter: '',
            tagFilter: '',
            componentFilter: '',
            assigneeFilter: '',
            versionFilters: [],
            cvssVersionMismatchOnly: false,
            attributionAgeDays: null,
            sortBy: 'rescored-severity',
            sortOrder: 'desc' as const,
            lifecycleFilters: DEFAULT_REVIEWER_LIFECYCLE_FILTERS,
            defaultLifecycleFilters: DEFAULT_REVIEWER_LIFECYCLE_FILTERS,
            analysisFilters: DEFAULT_ANALYSIS_FILTERS,
            defaultAnalysisFilters: DEFAULT_ANALYSIS_FILTERS,
            dependencyFilters: ['DIRECT', 'TRANSITIVE', 'UNKNOWN'] as const,
            defaultDependencyFilters: ['DIRECT', 'TRANSITIVE', 'UNKNOWN'] as const,
            tmrescoreFilters: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'] as const,
            defaultTMRescoreFilters: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'] as const,
            automaticAssessmentFilters: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'] as const,
            defaultAutomaticAssessmentFilters: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'] as const,
        }

        expect(hasCustomProjectVulnFilterState(defaultInput)).toBe(false)
        expect(hasCustomProjectVulnFilterState({
            ...defaultInput,
            sortBy: 'id',
        })).toBe(true)
        expect(hasCustomProjectVulnFilterState({
            ...defaultInput,
            lifecycleFilters: ['OPEN'],
        })).toBe(true)
        expect(hasCustomProjectVulnFilterState({
            ...defaultInput,
            automaticAssessmentFilters: ['WITH_AUTOMATIC_ASSESSMENT'],
        })).toBe(true)
    })

    it('matches option labels and unordered string sets', () => {
        expect(optionLabel('NEEDS_APPROVAL', lifecycleOptions)).toBe('Needs Approval')
        expect(optionLabel('UNKNOWN_VALUE', lifecycleOptions)).toBe('UNKNOWN VALUE')
        expect(sameStringSet(['OPEN', 'ASSESSED'], ['ASSESSED', 'OPEN'])).toBe(true)
        expect(sameStringSet(['OPEN'], ['OPEN', 'ASSESSED'])).toBe(false)
    })
})
