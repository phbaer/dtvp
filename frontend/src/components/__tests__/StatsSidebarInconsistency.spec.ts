import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import StatsSidebar, { type FilterState } from '../StatsSidebar.vue'
import type { TaskVulnGroupListCounts } from '../../lib/api'

const filters = (): FilterState => ({
    sortBy: 'id',
    sortOrder: 'asc',
    dependencyFilter: ['DIRECT', 'TRANSITIVE', 'UNKNOWN'],
    tmrescoreFilter: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'],
    automaticAssessmentFilter: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'],
    automaticAssessmentOutcomeFilter: ['AFFECTED', 'PROBABLY_AFFECTED', 'NOT_AFFECTED', 'INCONCLUSIVE'],
    automaticAssessmentRescoreFilter: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NO_RESCORE', 'UNSCORED'],
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

const resultCounts: TaskVulnGroupListCounts = {
    evidence: { KEV: 2, CISA_SSVC: 1, NOT_CHECKED: 1 },
    total: 2,
    lifecycle: { INCONSISTENT: 2 },
    inconsistency_reason: {
        MISSING_RESCORING_VECTOR: 0,
        ANALYSIS_STATE_MISMATCH: 1,
        TEAM_ASSESSMENT_MISMATCH: 0,
        ASSESSMENT_DETAILS_MISMATCH: 0,
    },
    analysis: {},
    dependency_relationship: { direct: 0, transitive: 0, unknown: 0 },
    cvss_version_mismatch: 0,
    versions: {},
    tags: {},
    assignees: {},
    components: {},
}

const mountSidebar = () => mount(StatsSidebar, {
    props: {
        filters: filters(),
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
        analysisOptions: [],
        copiedUrl: false,
        resultCounts,
        countsUpdating: false,
        teamOptions: [],
        teamAliases: {},
        cacheStatusState: 'unknown',
        cacheStatusLabel: 'Unknown',
        cacheStatusAge: '',
        cacheStatusTooltip: '',
        cacheStatusDetail: null,
        sortOptions: [{ value: 'id', label: 'ID' }],
        dependencyOptions: [],
        tmrescoreOptions: [],
        automaticAssessmentOptions: [],
        automaticAssessmentOutcomeOptions: [],
        automaticAssessmentRescoreOptions: [],
    },
})

describe('StatsSidebar inconsistency reasons', () => {
    it('shows evidence counts and toggles each selection without changing lifecycle', async () => {
        const wrapper = mountSidebar()
        const buttons = wrapper.get('[data-testid="evidenceFilters"]').findAll('button')
        const kev = buttons.find(button => button.text().includes('KEV listed'))!
        const cisa = buttons.find(button => button.text().includes('CISA SSVC available'))!
        expect(kev.text()).toContain('2')
        expect(cisa.text()).toContain('1')
        expect(wrapper.text()).toContain('Unchecked is not')
        await kev.trigger('click')
        let update = wrapper.emitted('update:filters')!.at(-1)![0] as FilterState
        expect(update.evidenceFilters).toEqual(['KEV'])
        expect(update.lifecycleFilters).toEqual([])
        await wrapper.setProps({ filters: update })
        expect(kev.attributes('aria-pressed')).toBe('true')
        await cisa.trigger('click')
        update = wrapper.emitted('update:filters')!.at(-1)![0] as FilterState
        expect(update.evidenceFilters).toEqual(['KEV', 'CISA_SSVC'])
        await wrapper.setProps({ filters: update })
        await kev.trigger('click')
        expect((wrapper.emitted('update:filters')!.at(-1)![0] as FilterState).evidenceFilters).toEqual(['CISA_SSVC'])
        wrapper.unmount()
    })
    it('preserves lifecycle when reasons change and preserves reasons when lifecycle changes', async () => {
        const wrapper = mountSidebar()
        const reasonButton = wrapper.findAll('button')
            .find(button => button.text().includes('Analysis states differ'))
        await reasonButton?.trigger('click')

        const firstUpdate = wrapper.emitted('update:filters')?.at(-1)?.[0] as FilterState
        expect(firstUpdate.lifecycleFilters).toEqual([])
        expect(firstUpdate.inconsistencyReasonFilters).toEqual(['ANALYSIS_STATE_MISMATCH'])

        await wrapper.setProps({ filters: { ...firstUpdate, lifecycleFilters: ['INCONSISTENT'] } })
        const lifecycleButton = wrapper.findAll('button')
            .find(button => button.text().includes('Inconsistent'))
        await lifecycleButton?.trigger('click')

        const secondUpdate = wrapper.emitted('update:filters')?.at(-1)?.[0] as FilterState
        expect(secondUpdate.lifecycleFilters).not.toContain('INCONSISTENT')
        expect(secondUpdate.inconsistencyReasonFilters).toEqual(['ANALYSIS_STATE_MISMATCH'])
    })
})
