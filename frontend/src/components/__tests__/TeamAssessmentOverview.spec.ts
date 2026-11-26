import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'
import TeamAssessmentOverview from '../TeamAssessmentOverview.vue'
import VulnGroupCard from '../VulnGroupCard.vue'
import { buildTeamOverview, type TeamOverviewInput } from '../../lib/teamOverview'
import type { AssessmentBlock } from '../../lib/assessment-helpers'
import ssvcModel from '../../../../dtvp/resources/ssvc/deployer-1.0.0.json'

vi.mock('../../lib/api', () => ({
    getSsvcModels: vi.fn(() => Promise.resolve([ssvcModel])),
    getSsvcExploitation: vi.fn(() => Promise.resolve({ enabled: true, sources: [], suggestion: null, auto_fill: false, retry_after: 0 })),
    updateAssessment: vi.fn(() => Promise.resolve([])),
    getDependencyChains: vi.fn().mockResolvedValue({ paths: [], total: 0, limit: 10, offset: 0 }),
    getAssessmentDetails: vi.fn(() => Promise.resolve([])),
    getKnownUsers: vi.fn(() => Promise.resolve([])),
}))

vi.mock('../DependencyChainViewer.vue', () => ({
    default: { template: '<div />', props: ['projectUuid', 'componentUuid', 'projectName'] },
}))

const block = (team: string, state: string, details = `${team} rationale.`): AssessmentBlock => ({
    team, state, details, user: 'alice', justification: 'NOT_SET', timestamp: 1_700_000_000_000,
})
const input = (team: string, state: string, details = `${team} rationale.`): TeamOverviewInput => ({
    team, state, details, justification: 'NOT_SET', source: state === 'NOT_SET' ? 'missing' : 'team',
})

const overviewOf = (teams: [string, string][], extraBlocks: AssessmentBlock[] = []) => buildTeamOverview({
    teams: teams.map(([team, state]) => input(team, state)),
    blocks: [...teams.filter(([, state]) => state !== 'NOT_SET').map(([team, state]) => block(team, state)), ...extraBlocks],
    componentsByTeam: new Map([['a', ['lib-a', 'lib-b']]]),
    pendingReview: true,
})

describe('TeamAssessmentOverview', () => {
    it('lists the teams with state, status, components and the rationale', async () => {
        const wrapper = mount(TeamAssessmentOverview, {
            props: { overview: overviewOf([['A', 'NOT_AFFECTED'], ['B', 'EXPLOITABLE'], ['C', 'NOT_AFFECTED'], ['D', 'NOT_SET']]) },
        })
        expect(wrapper.get('[data-testid="team-overview-summary"]').text())
            .toBe('4 teams: 2 Not affected, 1 Exploitable (B) · 1 missing (D)')
        const rows = wrapper.findAll('[data-testid="team-overview-row"]')
        expect(rows.map(row => row.attributes('data-team'))).toEqual(['B', 'D', 'A', 'C'])
        expect(rows[0]!.attributes('data-disagrees')).toBe('true')
        expect(rows[0]!.classes()).toContain('bg-amber-950/25')
        expect(rows[1]!.get('[data-testid="team-overview-status"]').text()).toBe('no assessment')
        expect(rows[2]!.get('[data-testid="team-overview-status"]').text()).toBe('pending review')
        const components = rows[2]!.get('[data-testid="team-overview-components"]')
        expect(components.text()).toBe('2 components')
        expect(components.attributes('title')).toBe('lib-a, lib-b')
        expect(rows[2]!.get('[data-testid="team-overview-rationale"]').text()).toBe('A rationale.')
        expect(rows[1]!.get('[data-testid="team-overview-use"]').attributes('disabled')).toBeDefined()
    })

    it('emits open and use-as-global for a row', async () => {
        const wrapper = mount(TeamAssessmentOverview, {
            props: { overview: overviewOf([['A', 'NOT_AFFECTED'], ['B', 'EXPLOITABLE']]) },
        })
        const row = wrapper.find('[data-team="A"]')
        await row.get('[data-testid="team-overview-open"]').trigger('click')
        await row.get('[data-testid="team-overview-use"]').trigger('click')
        expect(wrapper.emitted('open')).toEqual([['A']])
        expect(wrapper.emitted('use-as-global')![0]![0]).toMatchObject({ team: 'A', state: 'NOT_AFFECTED' })
    })

    it('expands a long rationale inline', async () => {
        const overview = buildTeamOverview({
            teams: [input('A', 'NOT_AFFECTED', 'First line.\nSecond line.')],
            blocks: [block('A', 'NOT_AFFECTED', 'First line.\nSecond line.')],
        })
        const wrapper = mount(TeamAssessmentOverview, { props: { overview } })
        await wrapper.get('[data-testid="team-overview-expand"]').trigger('click')
        expect(wrapper.get('[data-testid="team-overview-rationale-full"]').text()).toBe('First line.\nSecond line.')
        expect(wrapper.find('[data-testid="team-overview-rationale"]').exists()).toBe(false)
    })

    it('collapses more than five teams to the rows that need a look', async () => {
        const teams: [string, string][] = ['A', 'B', 'C', 'D', 'E', 'F'].map(team => [team, 'NOT_AFFECTED'])
        teams.push(['G', 'EXPLOITABLE'], ['H', 'NOT_SET'])
        const wrapper = mount(TeamAssessmentOverview, { props: { overview: overviewOf(teams) } })
        expect(wrapper.findAll('[data-testid="team-overview-row"]').map(row => row.attributes('data-team'))).toEqual(['G', 'H'])
        const toggle = wrapper.get('[data-testid="team-overview-show-all"]')
        expect(toggle.text()).toBe('Show all 8 teams (6 agreeing hidden)')
        await toggle.trigger('click')
        expect(wrapper.findAll('[data-testid="team-overview-row"]')).toHaveLength(8)
    })

    it('notes former team assessments and the worst state', async () => {
        const wrapper = mount(TeamAssessmentOverview, {
            props: {
                overview: overviewOf([['A', 'NOT_AFFECTED']], [{ ...block('Old', 'EXPLOITABLE'), historical: true }]),
                worstState: 'NOT_AFFECTED',
            },
        })
        expect(wrapper.findAll('[data-testid="team-overview-row"]')).toHaveLength(1)
        await wrapper.get('[data-testid="team-overview-former"]').trigger('click')
        await wrapper.get('[data-testid="use-effective-assessment-summary"]').trigger('click')
        expect(wrapper.get('[data-testid="team-overview-former"]').text()).toBe('1 former team assessment')
        expect(wrapper.emitted('show-former')).toHaveLength(1)
        expect(wrapper.emitted('use-worst')).toHaveLength(1)
    })
})

describe('the team overview on the Global assessment of VulnGroupCard', () => {
    const SECURITY = '--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: bob] [Justification: CODE_NOT_REACHABLE] ---\nNot reachable from the API.'
    const RUNTIME = '--- [Team: Runtime] [State: EXPLOITABLE] [Assessed By: carol] [Justification: NOT_SET] ---\nReachable in the worker.'
    const component = (name: string, uuid: string, team: string) => ({
        project_name: 'App1',
        project_version: '1.0',
        project_uuid: 'p1',
        component_name: name,
        component_version: '1.0',
        component_uuid: uuid,
        vulnerability_uuid: 'v1',
        finding_uuid: `f-${uuid}`,
        analysis_state: 'EXPLOITABLE',
        analysis_details: `${SECURITY}\n\n${RUNTIME}\n\n[Status: Pending Review]`,
        is_suppressed: false,
        analysis_comments: [],
        tags: [team],
        is_direct_dependency: false,
    })
    const group = {
        id: 'CVE-2023-1234',
        title: 'Test Vulnerability',
        description: 'A bad vulnerability',
        severity: 'HIGH',
        cvss: 9.8,
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        tags: ['Security', 'Runtime'],
        aliases: [],
        affected_versions: [{
            project_name: 'App1',
            project_version: '1.0',
            project_uuid: 'p1',
            components: [component('lib', 'c1', 'Security'), component('worker', 'c2', 'Runtime')],
        }],
    }

    const mountCard = async (role = 'REVIEWER') => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: group as any },
            global: {
                provide: {
                    user: ref({ role, username: 'rita' }),
                    teamMapping: ref({ lib: ['Security'], worker: ['Runtime'] }),
                },
                stubs: { teleport: true },
            },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        await wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))?.trigger('click')
        await flushPromises()
        ;(wrapper.vm as any).chooseTeamTab('')
        await flushPromises()
        return wrapper
    }

    beforeEach(() => vi.clearAllMocks())

    it('shows the overview only on the Global tab of a reviewer', async () => {
        const wrapper = await mountCard()
        const overview = wrapper.get('[data-testid="team-assessment-overview"]')
        expect(overview.get('[data-testid="team-overview-summary"]').text())
            .toBe('2 teams: 1 Exploitable (Runtime), 1 Not affected (Security) · 1 differs from Global Exploitable')
        expect(overview.findAll('[data-testid="team-overview-row"]').every(row => row.attributes('data-disagrees') === 'true')).toBe(true)
        expect(wrapper.find('[data-testid="effective-team-assessment-summary"]').exists()).toBe(false)

        ;(wrapper.vm as any).chooseTeamTab('Security')
        await flushPromises()
        expect(wrapper.find('[data-testid="team-assessment-overview"]').exists()).toBe(false)
        wrapper.unmount()

        const analyst = await mountCard('ANALYST')
        expect(analyst.find('[data-testid="team-assessment-overview"]').exists()).toBe(false)
        analyst.unmount()
    })

    it('Use as Global fills state and justification but keeps the text, without saving', async () => {
        const wrapper = await mountCard()
        const vm = wrapper.vm as any
        vm.details = 'My Global rationale.'
        await wrapper.vm.$nextTick()
        await wrapper.get('[data-team="Security"] [data-testid="team-overview-use"]').trigger('click')
        await flushPromises()
        expect(vm.selectedTeam).toBe('')
        expect(vm.state).toBe('NOT_AFFECTED')
        expect(vm.justification).toBe('CODE_NOT_REACHABLE')
        expect(vm.details).toBe('My Global rationale.')
        expect(vm.formTouched).toBe(true)
        const { updateAssessment } = await import('../../lib/api')
        expect(updateAssessment).not.toHaveBeenCalled()
        wrapper.unmount()
    })

    it('Open switches to the team tab and the Global draft survives the way back', async () => {
        const wrapper = await mountCard()
        const vm = wrapper.vm as any
        vm.state = 'IN_TRIAGE'
        vm.details = 'Global draft.'
        await wrapper.vm.$nextTick()

        await wrapper.get('[data-team="Runtime"] [data-testid="team-overview-open"]').trigger('click')
        await flushPromises()
        expect(vm.selectedTeam).toBe('Runtime')
        expect(vm.teamTabChosen).toBe(true)
        expect(vm.details).toBe('Reachable in the worker.')

        vm.chooseTeamTab('')
        await flushPromises()
        expect(vm.state).toBe('IN_TRIAGE')
        expect(vm.details).toBe('Global draft.')
        wrapper.unmount()
    })
})
