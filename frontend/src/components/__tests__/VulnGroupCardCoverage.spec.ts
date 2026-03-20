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
    RotateCcw: { template: '<span />' }
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
            tags: ['Tag1', 'Tag2']
        }
        const wrapper = mount(VulnGroupCard, { props: { group: taggedGroup } })

        const container = wrapper.find('.border-l.border-white\\/5')
        const tags = container.findAll('.rounded-lg.font-black')
        expect(tags.length).toBe(2)
        if (tags.length >= 2) {
            expect(tags[0]!.text()).toBe('Tag1')
            expect(tags[1]!.text()).toBe('Tag2')
        }
    })

    it('merges duplicate components and specific usage paths', async () => {
        const group = {
            id: 'V1',
            affected_versions: [{
                project_uuid: 'p1', project_name: 'P1',
                components: [
                    { component_uuid: 'c1', component_name: 'C1', component_version: '1.0', usage_paths: ['PathA'], analysis_state: 'S1' },
                    { component_uuid: 'c1', component_name: 'C1', component_version: '1.0', usage_paths: ['PathB'], analysis_state: 'S1' }
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
        await wrapper.find('select').setValue('Security')
        await flushPromises()

        // Should show team info
        expect((wrapper.find('textarea').element as HTMLTextAreaElement).value).toBe('Team info')
        expect((wrapper.findAll('select')[1]?.element as HTMLSelectElement).value).toBe('EXPLOITABLE')
    })
})
