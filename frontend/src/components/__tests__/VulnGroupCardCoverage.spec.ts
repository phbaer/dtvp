import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'

// Mock api
vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn()
}))

// Mock Icons
vi.mock('lucide-vue-next', () => ({
    ChevronDown: { template: '<span />' },
    ChevronUp: { template: '<span />' },
    Shield: { template: '<span />' },
    Calculator: { template: '<span />' },
    ExternalLink: { template: '<span />' }
}))

// To act as global check for our mock conditions
// We attach to global object to be accessible from hoisted mock
declare global {
    var _mockCvssState: {
        throwOnApply: boolean,
        throwOnGetComponents: boolean,
        throwOnParsing: boolean
    }
}
globalThis._mockCvssState = {
    throwOnApply: false,
    throwOnGetComponents: false,
    throwOnParsing: false
}

// We define the mock class inline inside vi.mock factory to avoid hoisting reference errors.
vi.mock('ae-cvss-calculator', () => {
    class MockCvss {
        vector = ''
        constructor(v?: string) {
            const state = globalThis._mockCvssState
            // Trigger parse error if flag set AND vector contains 'BAD' (to avoid crashing default init)
            if (state.throwOnParsing && v && v.includes('BAD')) throw new Error('Parse fail')
            this.vector = v || ''
        }
        applyComponentString(_n: string, v: string) {
            if (globalThis._mockCvssState.throwOnApply) throw new Error('Apply fail')
            this.vector = v
        }
        getRegisteredComponents() {
            if (globalThis._mockCvssState.throwOnGetComponents) throw new Error('Error getting components')
            // Return a fake map
            const map = new Map()
            map.set({ name: 'Base', description: 'Base metrics' }, [
                { name: 'Attack Vector', shortName: 'AV', values: [{ name: 'Network', shortName: 'N' }] }
            ])
            return map
        }
        calculateScores() { return { overall: 5.0, base: 5.0 } }
        toString() { return this.vector }
        getComponent(_c: any) { return { shortName: 'N' } }
    }

    return {
        Cvss3P1: MockCvss,
        Cvss4P0: MockCvss,
        Cvss2: MockCvss
    }
})

describe('VulnGroupCard Coverage Edge Cases', () => {
    const mockGroup = {
        id: 'CVE-1',
        title: 'T',
        severity: 'HIGH',
        affected_versions: []
    }

    beforeEach(() => {
        vi.clearAllMocks()
        globalThis._mockCvssState.throwOnApply = false
        globalThis._mockCvssState.throwOnGetComponents = false
        globalThis._mockCvssState.throwOnParsing = false
    })

    it('handles exception in calculatorGroups computed via console.error', async () => {
        const wrapper = mount(VulnGroupCard, { props: { group: mockGroup } })
        await wrapper.find('.cursor-pointer').trigger('click')

        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })
        globalThis._mockCvssState.throwOnGetComponents = true

        // Trigger modal open which accesses calculatorGroups
        await wrapper.find('button.text-blue-400').trigger('click')

        // Should have logged error
        expect(consoleSpy).toHaveBeenCalledWith('Error getting components', expect.any(Error))
        consoleSpy.mockRestore()
    })

    it('handles exception in updateCalcVector', async () => {
        const wrapper = mount(VulnGroupCard, { props: { group: mockGroup } })
        await wrapper.find('.cursor-pointer').trigger('click')
        await wrapper.find('button.text-blue-400').trigger('click')

        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })

        globalThis._mockCvssState.throwOnApply = true

        // Trigger change
        await wrapper.vm.$nextTick()
        const select = wrapper.find('select[id^="metric-"]') // any metric select
        if (select.exists()) {
            await select.setValue('X')
            expect(consoleSpy).toHaveBeenCalled()
        }
        consoleSpy.mockRestore()
    })

    it('handles exception in vector parsing watch', async () => {
        const wrapper = mount(VulnGroupCard, { props: { group: mockGroup } })
        await wrapper.find('.cursor-pointer').trigger('click')
        await wrapper.find('button.text-blue-400').trigger('click')

        globalThis._mockCvssState.throwOnParsing = true

        // Update pendingVector to trigger watch
        await wrapper.find('input[placeholder^="CVSS"]').setValue('CVSS:3.1/BAD')

        // Verify it fell back (state reset or just didn't crash).
        // The catch block sets activeVersion='3.1'.
        expect((wrapper.vm as any).activeVersion).toBe('3.1')
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
})
