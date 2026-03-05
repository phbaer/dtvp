
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'


vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(() => Promise.resolve([])),
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
    AlertTriangle: { template: '<span />' }
}))

describe('VulnGroupCard Branch Coverage', () => {
    // Helper to allow simple confirm
    beforeEach(() => {
        vi.clearAllMocks()
        global.confirm = vi.fn(() => true)
        global.alert = vi.fn()
    })

    const baseGroup = {
        id: 'CVE-1',
        title: 'T',
        severity: 'HIGH',
        affected_versions: []
    }



    it('handles initialization with empty/partial affected versions', () => {
        // Case: affected_versions undefined (if possible via prop bypass or data issue)
        // Prop type expects it, but we can pass object.
        const g1 = { ...baseGroup, affected_versions: undefined }
        const w1 = mount(VulnGroupCard, { props: { group: g1 as any } })
        // Should not crash and allInstances should be empty
        expect((w1.vm as any).allInstances).toEqual([])

        // Case: affected_versions empty
        const g2 = { ...baseGroup, affected_versions: [] }
        const w2 = mount(VulnGroupCard, { props: { group: g2 as any } })
        // State should be defaulted
        expect((w2.vm as any).state).toBe('NOT_SET')

        // Case: version with no components
        const g3 = { ...baseGroup, affected_versions: [{ components: [] }] }
        const w3 = mount(VulnGroupCard, { props: { group: g3 as any } })
        expect((w3.vm as any).state).toBe('NOT_SET')
    })



    it('correctly reports Mixed display state', () => {
        const group = {
            ...baseGroup,
            affected_versions: [
                {
                    project_uuid: 'p1', project_name: 'P1',
                    components: [{ component_uuid: 'c1', component_name: 'C1', component_version: '1.0', analysis_state: 'EXPLOITABLE' }]
                },
                {
                    project_uuid: 'p2', project_name: 'P2',
                    components: [{ component_uuid: 'c2', component_name: 'C2', component_version: '1.0', analysis_state: 'NOT_AFFECTED' }]
                }
            ]
        }
        const wrapper = mount(VulnGroupCard, { props: { group: group as any } })
        expect((wrapper.vm as any).displayState).toBe('EXPLOITABLE')
    })
})
