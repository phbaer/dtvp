import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'

vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(),
    getAssessmentDetails: vi.fn(() => Promise.resolve([])),
    getDependencyChains: vi.fn().mockResolvedValue([])
}))

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

// Mock types to satisfy linting
const createMockComponent = (uuid: string, name: string, version: string, isDirect: boolean | null) => ({
    component_uuid: uuid,
    component_name: name,
    component_version: version,
    is_direct_dependency: isDirect,
    // Add missing properties required by AffectedVersion component type
    project_name: 'Project A',
    project_version: '1.0',
    project_uuid: 'p1',
    finding_uuid: 'f-' + uuid,
    vulnerability_uuid: 'v-test',
    analysis_state: 'NOT_SET',
    analysis_details: '',
    analysis_comments: [],
    is_suppressed: false
})

describe('VulnGroupCard Helper Logic', () => {

    it('handles duplicate component versions without duplicating the summary text', async () => {
        const groupData = {
            id: 'CVE-TEST',
            affected_versions: [
                {
                    project_name: 'Project A',
                    project_version: '1.0',
                    project_uuid: 'p1',
                    components: [
                        createMockComponent('uuid-1', 'LibA', '1.0', true),
                        createMockComponent('uuid-1', 'LibA', '1.0', false)
                    ]
                }
            ]
        }

        const wrapper = mount(VulnGroupCard, {
            props: {
                group: groupData as any,
            },
            global: {
                stubs: {}
            }
        })

        // Expand the card to see component names in details
        await wrapper.find('.cursor-pointer').trigger('click')

        // Two duplicate LibA@1.0 components should be grouped into one assessment block
        const instanceBlocks = wrapper.findAll('[data-testid="grouped-assessment"]')
        expect(instanceBlocks.length).toBe(1)
    })

    it('handles unknown dependency relationship gracefully', async () => {
        const groupData = {
            id: 'CVE-TEST-2',
            affected_versions: [
                {
                    project_name: 'Project A',
                    project_version: '1.0',
                    project_uuid: 'p1',
                    components: [
                        createMockComponent('uuid-2', 'LibB', '2.0', null)
                    ]
                }
            ]
        }

        const wrapper = mount(VulnGroupCard, {
            props: {
                group: groupData as any,
            },
            global: {
                stubs: {}
            }
        })

        // Expand the card to see component names in details
        await wrapper.find('.cursor-pointer').trigger('click')

        // Should not crash and show component name
        const cardText = wrapper.text()
        expect(cardText).toContain('LibB')
    })
})
