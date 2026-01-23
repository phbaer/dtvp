
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'
import { updateAssessment } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(() => Promise.resolve([]))
}))

vi.mock('lucide-vue-next', () => ({
    ChevronDown: { template: '<span />' },
    ChevronUp: { template: '<span />' },
    Shield: { template: '<span />' },
    Calculator: { template: '<span />' },
    ExternalLink: { template: '<span />' }
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

    it('handles initialization with different score priorities and nulls', () => {
        // Case 1: rescored_cvss present
        const g1 = { ...baseGroup, rescored_cvss: 8.0, cvss_score: 9.0, cvss: 7.0 }
        const w1 = mount(VulnGroupCard, { props: { group: g1 as any } })
        expect((w1.vm as any).pendingScore).toBe(8.0)

        // Case 2: rescored missing, cvss_score present
        const g2 = { ...baseGroup, rescored_cvss: null, cvss_score: 9.0, cvss: 7.0 }
        const w2 = mount(VulnGroupCard, { props: { group: g2 as any } })
        expect((w2.vm as any).pendingScore).toBe(9.0)

        // Case 3: Both missing, cvss present
        const g3 = { ...baseGroup, rescored_cvss: undefined, cvss_score: undefined, cvss: 7.0 }
        const w3 = mount(VulnGroupCard, { props: { group: g3 as any } })
        expect((w3.vm as any).pendingScore).toBe(7.0)

        // Case 4: All missing
        const g4 = { ...baseGroup, rescored_cvss: undefined, cvss_score: undefined, cvss: undefined }
        const w4 = mount(VulnGroupCard, { props: { group: g4 as any } })
        expect((w4.vm as any).pendingScore).toBe(null)
    })

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

    it('constructs details correctly with different tag combinations', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: {
                    ...baseGroup,
                    affected_versions: [{
                        project_uuid: 'p1', project_name: 'P1',
                        components: [{
                            component_uuid: 'c1', component_name: 'C1', component_version: '1.0',
                            analysis_details: 'Existing details'
                        }]
                    }]
                } as any
            }
        })

        await wrapper.find('.cursor-pointer').trigger('click')

        // Helper to submit and check details
        const submitAndCheck = async (score: number | null, vector: string, expectedStart: string) => {
            // Access internals to set state directly for speed, or set via UI
            (wrapper.vm as any).pendingScore = score;
            (wrapper.vm as any).pendingVector = vector;

            await wrapper.vm.$nextTick()

            // Find valid button - re-expand if needed (update collapses card)
            let btn = wrapper.findAll('button').find(b => b.text().includes('Apply to All'))
            if (!btn) {
                await wrapper.find('.cursor-pointer').trigger('click')
                btn = wrapper.findAll('button').find(b => b.text().includes('Apply to All'))
            }
            if (!btn) throw new Error('Apply button not found')
            await btn.trigger('click')

            // Check if mock was called
            const calls = vi.mocked(updateAssessment).mock.calls
            if (calls.length === 0) throw new Error('updateAssessment not called')
            const call = calls[calls.length - 1]![0]
            expect(call.details).toContain(expectedStart)

            // Check preservation of clean details
            expect(call.details).toContain('Existing details')
        }

        // ... (rest of the test logic remains same, but I need to include it in replacement chunks if I replace the whole test block. 
        // Or I can just replace the setup part.

        // 1. Only Score
        vi.mocked(updateAssessment).mockClear()
        await submitAndCheck(5.5, '', '[Rescored: 5.5]')
        const call1 = vi.mocked(updateAssessment).mock.calls[0]![0]
        expect(call1.details).not.toContain('Rescored Vector')

        // 2. Only Vector
        vi.mocked(updateAssessment).mockClear()
        await submitAndCheck(null, 'CVSS:3.1/...', '[Rescored Vector: CVSS:3.1/...]')
        const call2 = vi.mocked(updateAssessment).mock.calls[0]![0]
        expect(call2.details).not.toContain('[Rescored: ')

        // 3. Both
        vi.mocked(updateAssessment).mockClear()
        await submitAndCheck(6.0, 'CVSS:3.1/BOTH', '[Rescored: 6]')
        const call3 = vi.mocked(updateAssessment).mock.calls[0]![0]
        expect(call3.details).toContain('[Rescored Vector: CVSS:3.1/BOTH]')

        // 4. Neither (Clean update)
        vi.mocked(updateAssessment).mockClear()
        await submitAndCheck(null, '', 'Existing details')
        const call4 = vi.mocked(updateAssessment).mock.calls[0]![0]
        expect(call4.details).not.toContain('[Rescored:')
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
        expect((wrapper.vm as any).displayState).toBe('MIXED')
    })
})
