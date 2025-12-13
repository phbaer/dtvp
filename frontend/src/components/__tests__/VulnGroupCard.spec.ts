import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'

// Mock API
vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(() => Promise.resolve([]))
}))

// Mock Icons
vi.mock('lucide-vue-next', () => ({
    ChevronDown: { template: '<span class="icon-down" />' },
    ChevronUp: { template: '<span class="icon-up" />' },
    Shield: { template: '<span class="icon-shield" />' },
    Calculator: { template: '<span class="icon-calc" />' },
    ExternalLink: { template: '<span class="icon-link" />' }
}))

import { updateAssessment } from '../../lib/api'

describe('VulnGroupCard', () => {
    const mockComponents = [
        {
            project_name: 'App1',
            project_version: '1.0',
            project_uuid: 'p1',
            component_name: 'lib',
            component_version: '1.0',
            component_uuid: 'c1',
            vulnerability_uuid: 'v1',
            finding_uuid: 'f1',
            analysis_state: 'NOT_SET',
            is_suppressed: false
        }
    ]

    const mockGroup = {
        id: 'CVE-2023-1234',
        title: 'Test Vulnerability',
        description: 'A bad vulnerability',
        severity: 'HIGH',
        cvss: 9.8,
        affected_versions: [
            {
                project_name: 'App1',
                project_version: '1.0',
                project_uuid: 'p1',
                components: mockComponents
            }
        ]
    }

    beforeEach(() => {
        vi.clearAllMocks()
        // Mock browser alerts/confirms
        global.confirm = vi.fn(() => true)
        global.alert = vi.fn()
    })

    it('renders vulnerability details', () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        expect(wrapper.text()).toContain('CVE-2023-1234')
        expect(wrapper.text()).toContain('HIGH')
        expect(wrapper.text()).toContain('9.8')
        expect(wrapper.text()).toContain('Test Vulnerability')
    })

    it('toggles expansion on click', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        // Initially not expanded (description not visible)
        expect(wrapper.text()).not.toContain('A bad vulnerability')

        // Click header
        await wrapper.find('.cursor-pointer').trigger('click')

        // Expanded
        expect(wrapper.text()).toContain('A bad vulnerability')
        expect(wrapper.text()).toContain('1.0') // Version should be shown
    })

    it('submits assessment update', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        // Expand
        await wrapper.find('.cursor-pointer').trigger('click')

        // Fill form
        await wrapper.find('select').setValue('NOT_AFFECTED')
        await wrapper.find('textarea').setValue('False positive')

        // Click Apply
        const applyBtn = wrapper.findAll('button').find(b => b.text().includes('Apply to All'))
        await applyBtn?.trigger('click')

        // Verify API call
        expect(global.confirm).toHaveBeenCalled()
        expect(updateAssessment).toHaveBeenCalledWith({
            instances: mockComponents,
            state: 'NOT_AFFECTED',
            details: `[Rescored: 9.8]\n\nFalse positive`,
            comment: '',
            suppressed: false
        })

        // Should emit update:assessment
        expect(wrapper.emitted()).toHaveProperty('update:assessment')
    })

    it('opens and closes visual calculator', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        // Expand
        await wrapper.find('.cursor-pointer').trigger('click')

        // Click visual calculator
        await wrapper.find('button.text-blue-400').trigger('click')
        await wrapper.vm.$nextTick()
        expect(wrapper.text()).toContain('CVSS v3.1 Calculator')
        expect(wrapper.text()).toContain('Done')

        // Close modal
        const doneBtn = wrapper.findAll('button').find(b => b.text() === 'Done')
        await doneBtn?.trigger('click')
        await wrapper.vm.$nextTick()
        expect(wrapper.text()).not.toContain('CVSS v3.1 Calculator')
    })

    it('handles assessment update errors', async () => {
        // Mock API failure
        vi.mocked(updateAssessment).mockResolvedValueOnce([{ status: 'error', message: 'Failed' }])

        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        const applyBtn = wrapper.findAll('button').find(b => b.text().includes('Apply to All'))
        await applyBtn?.trigger('click')

        expect(global.alert).toHaveBeenCalledWith(expect.stringContaining('errors'))
    })

    it('resets vector to original', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: {
                    ...mockGroup,
                    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                }
            }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await wrapper.find('button.text-blue-400').trigger('click')

        // Reset
        const resetBtn = wrapper.findAll('button').find(b => b.text().includes('Reset to Original'))
        await resetBtn?.trigger('click')

        // Should have the original vector in output (check pendingVector internally or just UI)
        expect((wrapper.find('input[type="text"]').element as HTMLInputElement).value).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L')
    })

    it('covers color branches', () => {
        const criticalGroup = { ...mockGroup, severity: 'CRITICAL' }
        const wrapper = mount(VulnGroupCard, {
            props: { group: criticalGroup }
        })
        // Find by text HIGH/CRITICAL and check class
        expect(wrapper.find('span.rounded').classes()).toContain('bg-red-900')

        const lowGroup = { ...mockGroup, severity: 'LOW' }
        const wrapper2 = mount(VulnGroupCard, {
            props: { group: lowGroup }
        })
        expect(wrapper2.find('span.rounded').classes()).toContain('bg-blue-900')
    })

    it('handles CVSS 4.0 vector parsing', async () => {
        const v4Group = {
            ...mockGroup,
            cvss_vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group: v4Group }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await wrapper.find('button.text-blue-400').trigger('click')
        await wrapper.vm.$nextTick()

        // Should initialize with v4.0
        expect((wrapper.vm as any).activeVersion).toBe('4.0')
    })

    it('handles CVSS 2.0 vector parsing', async () => {
        const v2Group = {
            ...mockGroup,
            cvss_vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group: v2Group }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await wrapper.find('button.text-blue-400').trigger('click')
        await wrapper.vm.$nextTick()

        // Should initialize with v2.0
        expect((wrapper.vm as any).activeVersion).toBe('2.0')
    })

    it('handles invalid CVSS vector gracefully', async () => {
        const invalidGroup = {
            ...mockGroup,
            cvss_vector: 'INVALID_VECTOR'
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group: invalidGroup }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await wrapper.find('button.text-blue-400').trigger('click')
        await wrapper.vm.$nextTick()

        // Should fallback to v3.1
        expect((wrapper.vm as any).activeVersion).toBe('3.1')
    })

    it('handles missing cvss_vector in reset', async () => {
        const noVectorGroup = { ...mockGroup, cvss_vector: undefined }
        const wrapper = mount(VulnGroupCard, {
            props: { group: noVectorGroup }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await wrapper.find('button.text-blue-400').trigger('click')
        await wrapper.vm.$nextTick()

        // Try to reset
        const resetBtn = wrapper.findAll('button').find(b => b.text().includes('Reset to Original'))
        await resetBtn?.trigger('click')

        // Should show alert
        expect(global.alert).toHaveBeenCalledWith('No original vector available for this vulnerability.')
    })

    it('handles user canceling confirmation', async () => {
        global.confirm = vi.fn(() => false)

        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        const applyBtn = wrapper.findAll('button').find(b => b.text().includes('Apply to All'))
        await applyBtn?.trigger('click')

        // Should not call API
        expect(updateAssessment).not.toHaveBeenCalled()
    })
})
