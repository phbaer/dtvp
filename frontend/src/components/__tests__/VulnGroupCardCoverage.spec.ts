import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
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
    AlertTriangle: { template: '<span />' }
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

        const tags = wrapper.findAll('.bg-blue-900\\/40')
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

        const instanceBlocks = wrapper.findAll('.mb-2.bg-gray-900')
        expect(instanceBlocks.length).toBe(1)
    })
})
