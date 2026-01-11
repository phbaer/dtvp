import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import DependencyPathList from '../DependencyPathList.vue'
import VulnGroupCard from '../VulnGroupCard.vue'

// Mock icons
vi.mock('lucide-vue-next', () => ({
    ChevronDown: { template: '<span />' },
    ChevronUp: { template: '<span />' },
    Shield: { template: '<span />' },
    Calculator: { template: '<span />' },
    ExternalLink: { template: '<span />' },
    Box: { template: '<span />' },
    ShieldAlert: { template: '<span />' }
}))

describe('Coverage Extras', () => {
    it('DependencyPathList handles single node path (hides it)', () => {
        const wrapper = mount(DependencyPathList, {
            props: { paths: ['OnlyComponent'] }
        })
        expect(wrapper.findAll('.relative.flex.items-center').length).toBe(0)
    })

    it('VulnGroupCard severity colors (INFO and default)', async () => {
        const infoGroup = {
            id: 'G1', severity: 'INFO', affected_versions: [],
            cvss: 0, cvss_score: 0, tags: []
        }
        const wrapper = mount(VulnGroupCard, { props: { group: infoGroup } })

        const badge = wrapper.find('.ring-1')
        expect(badge.classes()).toContain('bg-blue-600')

        const otherGroup = {
            id: 'G2', severity: 'UNKNOWN', affected_versions: [],
            cvss: 0, cvss_score: 0, tags: []
        }
        const wrapper2 = mount(VulnGroupCard, { props: { group: otherGroup } })
        expect(wrapper2.find('.rounded-full').classes()).toContain('bg-gray-600')
    })

    it('VulnGroupCard aggregates paths for same component', async () => {
        const group = {
            id: 'V1',
            severity: 'HIGH',
            cvss: 0,
            cvss_score: 0,
            tags: [],
            affected_versions: [
                {
                    project_uuid: 'P1',
                    project_name: 'Proj',
                    project_version: '1.0',
                    components: [
                        {
                            component_uuid: 'C1',
                            component_name: 'Comp',
                            component_version: '1.0',
                            usage_paths: ['Comp -> Parent1 -> Project']
                        },
                        {
                            component_uuid: 'C1',
                            component_name: 'Comp',
                            component_version: '1.0',
                            usage_paths: ['Comp -> Parent2 -> Project']
                        }
                    ]
                }
            ]
        } as any
        const wrapper = mount(VulnGroupCard, { props: { group } })
        await wrapper.find('.cursor-pointer').trigger('click')

        const componentBlocks = wrapper.findAll('.bg-gray-900.p-3.rounded')
        expect(componentBlocks.length).toBe(1)

        expect(wrapper.text()).toContain('Parent1')
        expect(wrapper.text()).toContain('Parent2')
    })
})
