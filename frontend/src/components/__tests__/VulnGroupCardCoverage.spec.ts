import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'

// Mock api
vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(),
    getAssessmentDetails: vi.fn(() => Promise.resolve([])),
    getDependencyChains: vi.fn().mockResolvedValue([])
}))

// Mock Icons
vi.mock('lucide-vue-next', () => ({
    ChevronDown: { template: '<span />' },
    ChevronUp: { template: '<span />' },
    Shield: { template: '<span />' },
    Calculator: { template: '<span />' },
    ExternalLink: { template: '<span />' },
    RefreshCw: { template: '<span />' },
    CheckCircle: { template: '<span />' },
    AlertTriangle: { template: '<span />' },
    RotateCcw: { template: '<span />' },
    History: { template: '<span />' },
    Package: { template: '<span />' },
    Layers: { template: '<span />' },
    ShieldOff: { template: '<span />' },
    Zap: { template: '<span />' },
    CircleDot: { template: '<span />' },
    Search: { template: '<span />' },
    ShieldCheck: { template: '<span />' },
    Bug: { template: '<span />' },
    GitBranch: { template: '<span />' },
    Eye: { template: '<span />' },
    ClipboardCopy: { template: '<span />' },
    Plus: { template: '<span />' }
}))



describe('VulnGroupCard Coverage Edge Cases', () => {
    const mockGroup = {
        id: 'CVE-1',
        title: 'T',
        severity: 'HIGH',
        affected_versions: []
    }

    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('renders tags when present', async () => {
        const taggedGroup = {
            ...mockGroup,
            tags: ['Tag1', 'Tag2'],
            affected_versions: [{
                project_uuid: 'p1',
                project_name: 'P1',
                project_version: '1.0',
                components: [
                    { component_uuid: 'c1', component_name: 'C1', component_version: '1.0', tags: ['Tag1', 'Tag2'] }
                ]
            }]
        }
        const wrapper = mount(VulnGroupCard, { props: { group: taggedGroup as any } })

        const tags = wrapper.findAll('[data-testid="team-tag"]')
        expect(tags.length).toBe(2)
        if (tags.length >= 2) {
            expect(tags[0]!.text()).toContain('Tag1')
            expect(tags[1]!.text()).toContain('Tag2')
        }
    })

    it('shows only closest tagged teams in the header tags', async () => {
        const group = {
            ...mockGroup,
            tags: ['TEAM-A', 'TEAM-B'],
            affected_versions: [{
                project_uuid: 'p1',
                project_name: 'P1',
                project_version: '1.0',
                components: [
                    {
                        component_uuid: 'c1',
                        component_name: 'log4j-core',
                        component_version: '2.0',
                        dependency_chains: ['log4j-core -> team-a-comp -> team-b-comp -> Vulnerable Project'],
                    }
                ]
            }]
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group: group as any },
            global: {
                provide: {
                    teamMapping: { value: { 'team-a-comp': ['TEAM-A'], 'team-b-comp': ['TEAM-B'] } }
                }
            }
        })

        const tags = wrapper.findAll('[data-testid="team-tag"]')
        expect(tags.length).toBe(1)
        expect(tags[0]!.text()).toContain('TEAM-A')
        expect(wrapper.text()).not.toContain('TEAM-B')
    })

    it('does not include a deeper tagged component when another tagged component is closer to the source', async () => {
        const group = {
            ...mockGroup,
            tags: ['TEAM-A', 'TEAM-B'],
            affected_versions: [{
                project_uuid: 'p1',
                project_name: 'P1',
                project_version: '1.0',
                components: [
                    {
                        component_uuid: 'c1',
                        component_name: 'log4j-core',
                        component_version: '2.0',
                        dependency_chains: ['log4j-core -> team-b-comp -> team-a-comp -> Vulnerable Project'],
                    }
                ]
            }]
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group: group as any },
            global: {
                provide: {
                    teamMapping: { value: { 'team-a-comp': ['TEAM-A'], 'team-b-comp': ['TEAM-B'] } }
                }
            }
        })

        const tags = wrapper.findAll('[data-testid="team-tag"]')
        expect(tags.length).toBe(1)
        expect(tags[0]!.text()).toContain('TEAM-B')
        expect(wrapper.text()).not.toContain('TEAM-A')
    })

    it('merges duplicate components with the same assessment state', async () => {
        const group = {
            id: 'V1',
            affected_versions: [{
                project_uuid: 'p1', project_name: 'P1',
                components: [
                    { component_uuid: 'c1', component_name: 'C1', component_version: '1.0', is_direct_dependency: true, analysis_state: 'S1' },
                    { component_uuid: 'c1', component_name: 'C1', component_version: '1.0', is_direct_dependency: false, analysis_state: 'S1' }
                ]
            }]
        }
        const wrapper = mount(VulnGroupCard, { props: { group: group as any } })
        await wrapper.find('.cursor-pointer').trigger('click')

        const instanceBlocks = wrapper.findAll('[data-testid="grouped-assessment"]')
        expect(instanceBlocks.length).toBe(1)
    })

    it('updates form when a team is selected', async () => {
        const aggregatedDetails = 'Global info\n\n--- [Team: Security] [State: EXPLOITABLE] [Assessed By: user] [Justification: CODE_NOT_PRESENT] ---\nTeam info'
        const group = {
            id: 'V1',
            tags: ['Security'],
            affected_versions: [{
                project_uuid: 'p1',
                components: [{
                    component_uuid: 'c1',
                    analysis_details: aggregatedDetails
                }]
            }]
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group: group as any },
            global: { provide: { user: { value: { role: 'REVIEWER' } } } }
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        // Default state (no team selected)
        expect((wrapper.find('textarea').element as HTMLTextAreaElement).value).toBe('Global info')

        // Select Security team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()
        await flushPromises()

        // Should show team info
        expect((wrapper.find('textarea').element as HTMLTextAreaElement).value).toBe('Team info')
        expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
    })
})
