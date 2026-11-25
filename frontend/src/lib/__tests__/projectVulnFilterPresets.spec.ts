import { describe, expect, it } from 'vitest'
import {
    FILTER_PRESETS,
    activeFilterPreset,
    applyFilterPreset,
    type FilterState,
} from '../projectVulnFilterPresets'
import type { InconsistencyReason } from '../../types'

const reasons: InconsistencyReason[] = ['ANALYSIS_STATE_MISMATCH', 'ASSESSMENT_DETAILS_MISMATCH']
const context = { inconsistencyReasons: reasons }

const state = (overrides: Partial<FilterState> = {}): FilterState => ({
    sortBy: 'rescored-severity',
    sortOrder: 'desc',
    dependencyFilter: ['DIRECT'],
    tmrescoreFilter: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'],
    automaticAssessmentFilter: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'],
    automaticAssessmentOutcomeFilter: [],
    automaticAssessmentRescoreFilter: [],
    idFilter: 'CVE-1',
    tagFilter: '',
    teamFilters: [],
    teamAssessmentFilter: 'ANY',
    componentFilter: '',
    assigneeFilter: '',
    versionFilterInput: '2.0',
    lifecycleFilters: ['OPEN'],
    inconsistencyReasonFilters: [],
    analysisFilters: ['NOT_SET'],
    cvssVersionMismatchOnly: true,
    attributionAgeDays: null,
    attributionAgeMode: 'older',
    ...overrides,
})

describe('project filter presets', () => {
    it('sets only the status part and keeps the scope and More filters', () => {
        const before = state({ newFindingsOnly: true })
        const after = applyFilterPreset(before, 'awaiting-review', context)
        expect(after).toMatchObject({
            lifecycleFilters: ['OPEN', 'INCOMPLETE', 'READY_FOR_APPROVAL', 'ASSESSED'],
            awaitingReviewOnly: true,
            newFindingsOnly: false,
            inconsistencyReasonFilters: [],
            teamAssessmentFilter: 'ANY',
            // Kept:
            idFilter: 'CVE-1',
            versionFilterInput: '2.0',
            analysisFilters: ['NOT_SET'],
            dependencyFilter: ['DIRECT'],
            cvssVersionMismatchOnly: true,
        })
        expect(activeFilterPreset(after, context)).toBe('awaiting-review')
    })

    it('narrows Needs my assessment to the selected teams missing an assessment', () => {
        expect(applyFilterPreset(state(), 'needs-assessment', context)).toMatchObject({
            lifecycleFilters: ['OPEN', 'INCOMPLETE'], teamAssessmentFilter: 'ANY',
        })
        const withTeams = applyFilterPreset(state({ teamFilters: ['Core'] }), 'needs-assessment', context)
        expect(withTeams.teamAssessmentFilter).toBe('MISSING')
        expect(activeFilterPreset(withTeams, context)).toBe('needs-assessment')
    })

    it('treats every conflict reason as Conflicting', () => {
        const conflicting = applyFilterPreset(state(), 'conflicting', context)
        expect(conflicting.inconsistencyReasonFilters).toEqual(reasons)
        expect(activeFilterPreset(conflicting, context)).toBe('conflicting')
        expect(activeFilterPreset(state({ inconsistencyReasonFilters: [reasons[0]!] }), context)).toBeUndefined()
    })

    it('recognises each preset after applying it, and a custom selection as none', () => {
        for (const { key } of FILTER_PRESETS) {
            expect(activeFilterPreset(applyFilterPreset(state(), key, context), context)).toBe(key)
        }
        expect(activeFilterPreset(state({ lifecycleFilters: ['ASSESSED'] }), context)).toBeUndefined()
        expect(activeFilterPreset(state({
            lifecycleFilters: ['OPEN', 'INCOMPLETE', 'READY_FOR_APPROVAL', 'ASSESSED'],
            awaitingReviewOnly: true,
            newFindingsOnly: true,
        }), context)).toBeUndefined()
    })
})
