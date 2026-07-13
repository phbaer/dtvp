import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import StatsSidebar, { type FilterState } from '../StatsSidebar.vue'

const filters = (): FilterState => ({
    sortBy: 'id',
    sortOrder: 'asc',
    dependencyFilter: ['DIRECT', 'TRANSITIVE', 'UNKNOWN'],
    tmrescoreFilter: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'],
    automaticAssessmentFilter: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'],
    idFilter: '',
    tagFilter: '',
    componentFilter: '',
    versionFilterInput: '',
    lifecycleFilters: [],
    inconsistencyReasonFilters: [],
    analysisFilters: [],
    cvssVersionMismatchOnly: false,
    assigneeFilter: '',
    attributionAgeDays: null,
    attributionAgeMode: 'older',
})

const mountSidebar = () => mount(StatsSidebar, {
    props: {
        filters: filters(),
        filterCounts: { INCONSISTENT: 2 },
        availableVersions: [],
        lifecycleOptions: [{
            value: 'INCONSISTENT',
            label: 'Inconsistent',
            color: 'bg-indigo-500',
        }],
        inconsistencyReasonOptions: [{
            value: 'ANALYSIS_STATE_MISMATCH',
            label: 'Analysis states differ',
            description: 'States differ.',
        }],
        inconsistencyReasonCounts: {
            MISSING_RESCORING_VECTOR: 0,
            ANALYSIS_STATE_MISMATCH: 1,
            TEAM_ASSESSMENT_MISMATCH: 0,
            ASSESSMENT_DETAILS_MISMATCH: 0,
        },
        analysisOptions: [],
        copiedUrl: false,
        filteredCount: 2,
        dependencyCounts: { direct: 0, transitive: 0, unknown: 0 },
        dependencyFilterCounts: { direct: 0, transitive: 0, unknown: 0 },
        tmrescoreCounts: {},
        automaticAssessmentCounts: {},
        analysisCounts: {},
        teamTagList: [],
        cacheStatusState: 'unknown',
        cacheStatusLabel: 'Unknown',
        cacheStatusAge: '',
        cacheStatusTooltip: '',
        cacheStatusDetail: null,
        sortOptions: [{ value: 'id', label: 'ID' }],
        dependencyOptions: [],
        tmrescoreOptions: [],
        automaticAssessmentOptions: [],
    },
})

describe('StatsSidebar inconsistency reasons', () => {
    it('adds the inconsistent lifecycle and clears reasons when it is removed', async () => {
        const wrapper = mountSidebar()
        const reasonButton = wrapper.findAll('button')
            .find(button => button.text().includes('Analysis states differ'))
        await reasonButton?.trigger('click')

        const firstUpdate = wrapper.emitted('update:filters')?.at(-1)?.[0] as FilterState
        expect(firstUpdate.lifecycleFilters).toContain('INCONSISTENT')
        expect(firstUpdate.inconsistencyReasonFilters).toEqual(['ANALYSIS_STATE_MISMATCH'])

        await wrapper.setProps({ filters: firstUpdate })
        const lifecycleButton = wrapper.findAll('button')
            .find(button => button.text().includes('Inconsistent'))
        await lifecycleButton?.trigger('click')

        const secondUpdate = wrapper.emitted('update:filters')?.at(-1)?.[0] as FilterState
        expect(secondUpdate.lifecycleFilters).not.toContain('INCONSISTENT')
        expect(secondUpdate.inconsistencyReasonFilters).toEqual([])
    })
})
