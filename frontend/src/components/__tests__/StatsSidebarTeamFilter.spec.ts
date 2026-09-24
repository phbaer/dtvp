import { afterEach, describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import StatsSidebar, { type FilterOption, type FilterState, type TeamEntry } from '../StatsSidebar.vue'
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

const teamTagList: TeamEntry[] = [
    { team: 'Platform Security', open: 2, assessed: 1 },
    { team: '3rd Party', open: 1, assessed: 2 },
    ...Array.from({ length: 9 }, (_, index) => ({
        team: `Team ${index + 1}`,
        open: index + 1,
        assessed: index,
    })),
    { team: 'Platform', open: 4, assessed: 3 },
]

const resultCounts: TaskVulnGroupListCounts = {
    total: 42,
    lifecycle: {},
    inconsistency_reason: {},
    analysis: {},
    dependency_relationship: { direct: 0, transitive: 0, unknown: 0 },
    cvss_version_mismatch: 0,
    versions: {},
    tags: {},
    assignees: {},
    components: {},
    automatic_assessment_outcome: {
        AFFECTED: 4,
        PROBABLY_AFFECTED: 3,
        NOT_AFFECTED: 2,
        INCONCLUSIVE: 1,
    },
    automatic_assessment_rescore: {
        CRITICAL: 1,
        HIGH: 2,
        MEDIUM: 3,
        LOW: 4,
        INFO: 1,
        NO_RESCORE: 2,
        UNSCORED: 1,
    },
    team_tags: Object.fromEntries(teamTagList
        .filter(({ team }) => team !== 'Team 9')
        .map(({ team, open, assessed }) => [team, { open, assessed }])),
    team_groups: {
        'Core-MUC': { open: 5, assessed: 4 },
        Engineering: { open: 6, assessed: 5 },
    },
    team_group_structure: {
        'Core-MUC': {
            teams: ['Core-MUC', '3rd Party'],
            groups: [],
        },
        Engineering: {
            teams: ['Runtime'],
            groups: ['Core-MUC'],
        },
    },
}

const mountSidebar = (
    counts: TaskVulnGroupListCounts = resultCounts,
    lifecycleOptions: FilterOption[] = [],
) => mount(StatsSidebar, {
    attachTo: document.body,
    global: {
        stubs: {
            teleport: false,
        },
    },
    props: {
        filters: filters(),
        availableVersions: [],
        lifecycleOptions,
        inconsistencyReasonOptions: [],
        analysisOptions: [],
        copiedUrl: false,
        resultCounts: counts,
        countsUpdating: false,
        teamOptions: teamTagList.map(entry => entry.team),
        teamAliases: {
            'Platform Security': ['Platform', 'Platform Sec'],
        },
        cacheStatusState: 'unknown',
        cacheStatusLabel: 'Unknown',
        cacheStatusAge: '',
        cacheStatusTooltip: '',
        cacheStatusDetail: null,
        sortOptions: [{ value: 'id', label: 'ID' }],
        dependencyOptions: [],
        tmrescoreOptions: [],
        automaticAssessmentOptions: [],
        automaticAssessmentOutcomeOptions: [
            { value: 'AFFECTED', label: 'Affected' },
            { value: 'PROBABLY_AFFECTED', label: 'Probably affected' },
            { value: 'NOT_AFFECTED', label: 'Not affected' },
            { value: 'INCONCLUSIVE', label: 'Uncertain' },
        ],
        automaticAssessmentRescoreOptions: [
            { value: 'CRITICAL', label: 'Critical' },
            { value: 'HIGH', label: 'High' },
            { value: 'MEDIUM', label: 'Medium' },
            { value: 'LOW', label: 'Low' },
            { value: 'INFO', label: 'Info' },
            { value: 'NO_RESCORE', label: 'No rescore' },
            { value: 'UNSCORED', label: 'Unscored' },
        ],
    },
})

describe('StatsSidebar team filter', () => {
    afterEach(() => {
        document.body.innerHTML = ''
    })

    it('shows selectable workflow views and identifies custom status selections', async () => {
        const options = ['OPEN', 'INCOMPLETE', 'READY_FOR_APPROVAL', 'ASSESSED']
            .map(value => ({ value, label: value, color: 'bg-blue-500' }))
        const wrapper = mountSidebar(resultCounts, options)
        const analyst = wrapper.get('[data-testid="workflow-view-analyst-work"]')
        const approval = wrapper.get('[data-testid="workflow-view-approval"]')
        expect(wrapper.text()).toContain('Custom selection')
        await analyst.trigger('click')
        expect((wrapper.emitted('update:filters')?.at(-1)?.[0] as FilterState).lifecycleFilters)
            .toEqual(['OPEN', 'INCOMPLETE'])
        await wrapper.setProps({ filters: { ...filters(), lifecycleFilters: ['OPEN', 'INCOMPLETE'] } })
        expect(analyst.attributes('aria-pressed')).toBe('true')
        expect(wrapper.text()).not.toContain('Custom selection')
        await approval.trigger('click')
        expect((wrapper.emitted('update:filters')?.at(-1)?.[0] as FilterState).lifecycleFilters)
            .toEqual(['READY_FOR_APPROVAL'])
        wrapper.unmount()
    })

    it('searches canonical teams and keeps teams with no results selectable', async () => {
        const wrapper = mountSidebar()
        const menu = wrapper.get('[data-testid="team-filter-select"]')
        expect(menu.findAll('input[type="checkbox"]')).toHaveLength(teamTagList.length - 1)
        expect(menu.text()).toContain('Team 9')
        await menu.get('input[type="search"]').setValue('platform')
        expect(menu.findAll('input[type="checkbox"]')).toHaveLength(1)
        expect(menu.text()).toContain('Platform Security')
        await menu.get('input[type="search"]').setValue('Platform Sec')
        expect(menu.findAll('input[type="checkbox"]')).toHaveLength(1)
        expect(wrapper.get('[data-testid="team-assessment-filter"]').attributes('disabled')).toBeDefined()
        wrapper.unmount()
    })

    it('shows shared automatic outcome and rescore facets with counts', async () => {
        const wrapper = mountSidebar()
        const outcomes = wrapper.findAll('[data-testid="automatic-assessment-outcome-filters"] button')
        const rescores = wrapper.findAll('[data-testid="automatic-assessment-rescore-filters"] button')

        expect(outcomes.map(button => button.text())).toEqual([
            'Affected 4',
            'Probably affected 3',
            'Not affected 2',
            'Uncertain 1',
        ])
        expect(rescores.map(button => button.text())).toContain('Low 4')

        await outcomes[0].trigger('click')
        const updates = wrapper.emitted('update:filters') || []
        const updatedFilters = updates.at(-1)?.[0] as FilterState
        expect(updatedFilters.automaticAssessmentOutcomeFilter).toEqual([
            'PROBABLY_AFFECTED',
            'NOT_AFFECTED',
            'INCONCLUSIVE',
        ])
    })

    it('groups aliases into the canonical team row and shows them dimmed below', async () => {
        const wrapper = mountSidebar({
            ...resultCounts,
            team_groups: {},
            team_group_structure: {},
        })
        const statisticsTab = wrapper.findAll('button')
            .find(button => button.text().trim() === 'Results')
        await statisticsTab?.trigger('click')
        await nextTick()

        const rows = wrapper.findAll('[data-testid="per-team-statistics"] tbody tr')
        const teamNames = rows.map(row => row.find('td > div:first-child').text())
        expect(teamNames).toContain('Platform Security')
        expect(teamNames).not.toContain('Platform')

        const canonicalRow = rows.find(row =>
            row.find('td > div:first-child').text() === 'Platform Security'
        )
        expect(canonicalRow?.findAll('td').map(cell => cell.text())).toEqual([
            'Platform SecurityPlatform · Platform Sec',
            '6',
            '4',
        ])
        const aliases = wrapper.get('[data-testid="team-aliases-Platform Security"]')
        expect(aliases.text()).toBe('Platform · Platform Sec')
        expect(aliases.classes()).toContain('text-gray-600')
    })

    it('shows parent-group and subgroup statistics at the same time', async () => {
        const wrapper = mountSidebar()
        const statisticsTab = wrapper.findAll('button')
            .find(button => button.text().trim() === 'Results')
        await statisticsTab?.trigger('click')
        await nextTick()

        const groupTable = wrapper.get('[data-testid="per-group-statistics"]')
        const rows = groupTable.findAll('[data-testid="team-group-stat-row"]')
        const row = (kind: string, name: string) => rows.find(candidate =>
            candidate.attributes('data-entry-kind') === kind
            && candidate.attributes('data-entry-name') === name
        )

        expect(row('group', 'Engineering')?.attributes('data-entry-depth')).toBe('0')
        expect(row('group', 'Core-MUC')?.attributes('data-entry-depth')).toBe('1')
        expect(row('group', 'Core-MUC')?.findAll('td').map(cell => cell.text())).toEqual([
            'Core-MUCgroup',
            '5',
            '4',
        ])
        expect(row('team', 'Core-MUC')?.attributes('data-entry-depth')).toBe('2')
        expect(row('team', '3rd Party')?.attributes('data-entry-depth')).toBe('2')
        expect(row('team', '3rd Party')?.findAll('td').map(cell => cell.text())).toEqual([
            '3rd Partyteam',
            '1',
            '2',
        ])
        expect(row('team', 'Runtime')?.attributes('data-entry-depth')).toBe('1')
        expect(row('team', 'Platform Security')?.attributes('data-entry-depth')).toBe('0')
        expect(wrapper.find('[data-testid="per-team-statistics"]').exists()).toBe(false)
    })

    it('emits explicit multiple canonical teams and supports clearing', async () => {
        const wrapper = mountSidebar()
        const menu = wrapper.get('[data-testid="team-filter-select"]')
        const platform = menu.findAll('label').find(label => label.text().trim() === 'Platform Security')!
        await platform.get('input').setValue(true)
        let update = wrapper.emitted('update:filters')!.at(-1)![0] as FilterState
        expect(update.teamFilters).toEqual(['Platform Security'])
        await wrapper.setProps({ filters: update })
        const other = menu.findAll('label').find(label => label.text().trim() === '3rd Party')!
        await other.get('input').setValue(true)
        update = wrapper.emitted('update:filters')!.at(-1)![0] as FilterState
        expect(update.teamFilters).toEqual(['Platform Security', '3rd Party'])
        await wrapper.setProps({ filters: update })
        expect(wrapper.get('[data-testid="team-assessment-filter"]').attributes('disabled')).toBeUndefined()
        await menu.get('button').trigger('click')
        expect((wrapper.emitted('update:filters')!.at(-1)![0] as FilterState).teamFilters).toEqual([])
        wrapper.unmount()
    })
})
