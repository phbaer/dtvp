import { describe, it, expect, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import AnalysisQueueIndicator from '../AnalysisQueueIndicator.vue'

describe('AnalysisQueueIndicator', () => {
    afterEach(() => {
        vi.restoreAllMocks()
        document.body.innerHTML = ''
    })

    it('renders the queue popup in a high fixed body overlay', async () => {
        const wrapper = mount(AnalysisQueueIndicator, {
            attachTo: document.body,
            global: {
                stubs: {
                    teleport: false,
                },
            },
        })

        expect(wrapper.find('[data-testid="analysis-queue-trigger"]').text()).toContain('Auto sweep')

        const trigger = wrapper.find('[data-testid="analysis-queue-trigger"]')
        vi.spyOn(trigger.element, 'getBoundingClientRect').mockReturnValue({
            x: 220,
            y: 40,
            left: 220,
            right: 330,
            top: 40,
            bottom: 72,
            width: 110,
            height: 32,
            toJSON: () => ({}),
        } as DOMRect)

        await trigger.trigger('click')
        await nextTick()

        const panel = document.body.querySelector('[data-testid="analysis-queue-panel"]') as HTMLElement | null

        expect(panel).not.toBeNull()
        expect(panel?.style.position).toBe('fixed')
        expect(panel?.style.left).toBe('220px')
        expect(panel?.style.right).toBe('')
        expect(Number(panel?.style.zIndex)).toBeGreaterThan(10000)

        wrapper.unmount()
    })

    it('closes the queue popup when clicking outside it', async () => {
        const wrapper = mount(AnalysisQueueIndicator, {
            attachTo: document.body,
            global: {
                stubs: {
                    teleport: false,
                },
            },
        })

        await wrapper.find('[data-testid="analysis-queue-trigger"]').trigger('click')
        await nextTick()
        expect(document.body.querySelector('[data-testid="analysis-queue-panel"]')).not.toBeNull()

        document.body.dispatchEvent(new Event('pointerdown', { bubbles: true }))
        await nextTick()

        expect(document.body.querySelector('[data-testid="analysis-queue-panel"]')).toBeNull()

        wrapper.unmount()
    })
})
