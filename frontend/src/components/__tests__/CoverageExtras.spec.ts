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
    ShieldAlert: { template: '<span />' },
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

vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(),
    getAssessmentDetails: vi.fn(() => Promise.resolve([])),
    getDependencyChains: vi.fn().mockResolvedValue([
        'Comp -> Parent1 -> Project',
        'Comp -> Parent2 -> Project'
    ]),
    getKnownUsers: vi.fn(() => Promise.resolve([]))
}))

describe('Coverage Extras', () => {
    it('DependencyPathList handles single node path (hides it)', () => {
        const wrapper = mount(DependencyPathList, {
            props: { paths: ['OnlyComponent'], projectName: 'Proj' }
        })
        expect(wrapper.findAll('.clip-start').length + wrapper.findAll('.clip-middle').length).toBe(0)
    })

    it('VulnGroupCard severity colors (INFO and default)', async () => {
        const infoGroup = {
            id: 'G1', severity: 'INFO', affected_versions: [],
            cvss: 0, cvss_score: 0, tags: []
        }
        const wrapper = mount(VulnGroupCard, { props: { group: infoGroup } })

        const polygon = wrapper.find('[data-testid="severity-badge"] polygon')
        expect(polygon.attributes('fill')).toBe('rgba(37, 99, 235, 0.4)')
        expect(wrapper.find('[data-testid="severity-badge"]').text()).toBe('INFO')

        const otherGroup = {
            id: 'G2', severity: 'UNKNOWN', affected_versions: [],
            tags: []
        }
        const wrapper2 = mount(VulnGroupCard, { props: { group: otherGroup } })
        const polygon2 = wrapper2.find('[data-testid="severity-badge"] polygon')
        expect(polygon2.attributes('fill')).toBe('rgba(75, 85, 99, 0.4)')
        expect(wrapper2.find('[data-testid="severity-badge"]').text()).toBe('UNKNOWN')
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
                            component_version: '1.0'
                        },
                        {
                            component_uuid: 'C1',
                            component_name: 'Comp',
                            component_version: '1.0'
                        }
                    ]
                }
            ]
        } as any
        const wrapper = mount(VulnGroupCard, { props: { group } })
        await wrapper.find('.cursor-pointer').trigger('click')

        const componentBlocks = wrapper.findAll('[data-testid="grouped-assessment"]')
        expect(componentBlocks.length).toBe(1) // Should group components

        // Open dependency chains
        const toggleBtn = wrapper.find('button.text-blue-400')
        if (toggleBtn.exists()) {
            await toggleBtn.trigger('click')
            // Wait for async loading
            await new Promise(resolve => setTimeout(resolve, 10))
            await wrapper.vm.$nextTick()

            expect(wrapper.text()).toContain('Parent2')
        }
    })

    it('VulnGroupCard renders CvssVectorDisplay for rescored vectors', async () => {
        const group = {
            id: 'V1', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:H',
            affected_versions: [], severity: 'MEDIUM', cvss_score: 5
        } as any
        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'test' } } } }
        })
        // Card mounts without errors; expand to reveal vector details
        const headerEl = wrapper.find('[ref="headerEl"]').exists()
            ? wrapper.find('[ref="headerEl"]')
            : wrapper.find('.cursor-pointer')
        await headerEl.trigger('click')
        await wrapper.vm.$nextTick()
        const html = wrapper.html()
        // Should render the CvssVectorDisplay component with metric breakdown
        expect(html).toContain('Exploitability')
        expect(html).toContain('Impact')
    })
})
