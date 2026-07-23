import { afterEach, describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import StatsSidebar, { type FilterState, type TeamEntry } from '../StatsSidebar.vue'
import type { TaskVulnGroupListCounts } from '../../lib/api'

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

const teamTagList: TeamEntry[] = [
    { team: 'Platform Security', open: 2, assessed: 1 },
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
    team_tags: Object.fromEntries(teamTagList
        .filter(({ team }) => team !== 'Team 9')
        .map(({ team, open, assessed }) => [team, { open, assessed }])),
}

const mountSidebar = () => mount(StatsSidebar, {
    attachTo: document.body,
    global: {
        stubs: {
            teleport: false,
        },
    },
    props: {
        filters: filters(),
        availableVersions: [],
        lifecycleOptions: [],
        inconsistencyReasonOptions: [],
        analysisOptions: [],
        copiedUrl: false,
        resultCounts,
        countsUpdating: false,
        teamOptions: teamTagList.map(entry => entry.team),
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

describe('StatsSidebar team filter', () => {
    afterEach(() => {
        document.body.innerHTML = ''
    })

    it('shows and searches the complete team list, including counts', async () => {
        const wrapper = mountSidebar()

        await wrapper.find('[data-testid="team-filter-select"]').trigger('click')
        await nextTick()

        const menu = document.body.querySelector('[data-testid="custom-select-menu"]') as HTMLElement
        expect(menu.querySelectorAll('button')).toHaveLength(teamTagList.length + 1)
        expect(menu.textContent).toContain('7 vulnerabilities')
        expect(menu.textContent).toContain('4 open · 3 assessed')
        const zeroResultTeam = Array.from(menu.querySelectorAll('button'))
            .find(button => button.textContent?.includes('Team 9'))
        expect(zeroResultTeam?.textContent).toContain('0 vulnerabilities')
        const platformOption = Array.from(menu.querySelectorAll('button'))
            .find(button => button.textContent?.includes('Platform Security'))
        const optionText = platformOption?.querySelector(':scope > span')
        expect(optionText?.children[0]?.textContent).toBe('Platform Security')
        expect(optionText?.children[1]?.textContent?.trim())
            .toBe('3 vulnerabilities · 2 open · 1 assessed')

        const search = menu.querySelector('input[placeholder="Search teams..."]') as HTMLInputElement
        search.value = 'platform'
        search.dispatchEvent(new Event('input', { bubbles: true }))
        await nextTick()

        expect(menu.querySelectorAll('button')).toHaveLength(2)
        expect(menu.textContent).toContain('Platform Security')
        expect(menu.textContent).toContain('Platform')

        wrapper.unmount()
    })

    it('emits the exact selected team name', async () => {
        const wrapper = mountSidebar()

        await wrapper.find('[data-testid="team-filter-select"]').trigger('click')
        await nextTick()

        const option = Array.from(document.body.querySelectorAll('[data-testid="custom-select-menu"] button'))
            .find(button => button.querySelector(':scope > span > span:first-child')?.textContent?.trim() === 'Platform') as HTMLElement
        option.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
        await nextTick()

        const update = wrapper.emitted('update:filters')?.at(-1)?.[0] as FilterState
        expect(update.tagFilter).toBe('Platform')

        wrapper.unmount()
    })
})
