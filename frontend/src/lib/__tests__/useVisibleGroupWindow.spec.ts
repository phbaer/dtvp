import { mount } from '@vue/test-utils'
import { computed, defineComponent, nextTick, ref } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useVisibleGroupWindow } from '../useVisibleGroupWindow'

const setClientHeight = (element: Element, height: number) => {
    Object.defineProperty(element, 'clientHeight', {
        configurable: true,
        value: height,
    })
}

describe('useVisibleGroupWindow', () => {
    afterEach(() => {
        vi.unstubAllGlobals()
    })

    it('exposes the initial fallback window before a scroll container is measured', () => {
        const Harness = defineComponent({
            setup() {
                const items = ref([1, 2, 3, 4, 5])
                const isActive = ref(true)
                return useVisibleGroupWindow({
                    items: computed(() => items.value),
                    isActive,
                    batchSize: 2,
                    estimatedItemHeight: 10,
                    overscan: 1,
                })
            },
            template: `
                <div>
                    <span data-testid="visible-count">{{ visibleItems.length }}</span>
                    <span data-testid="first-item">{{ visibleItems[0] }}</span>
                </div>
            `,
        })

        const wrapper = mount(Harness)

        expect(wrapper.get('[data-testid="visible-count"]').text()).toBe('4')
        expect(wrapper.get('[data-testid="first-item"]').text()).toBe('1')
    })

    it('renders only the viewport window plus overscan as the container scrolls', async () => {
        vi.stubGlobal('ResizeObserver', undefined)
        const items = Array.from({ length: 20 }, (_, index) => index + 1)

        const Harness = defineComponent({
            setup() {
                const isActive = ref(true)
                return useVisibleGroupWindow({
                    items: computed(() => items),
                    isActive,
                    batchSize: 2,
                    estimatedItemHeight: 10,
                    overscan: 1,
                })
            },
            template: `
                <div ref="scrollContainer" data-testid="scroll">
                    <span data-testid="visible-count">{{ visibleItems.length }}</span>
                    <span data-testid="first-item">{{ visibleItems[0] }}</span>
                    <span data-testid="start-index">{{ visibleStartIndex }}</span>
                    <span data-testid="top-pad">{{ virtualPaddingTop }}</span>
                    <span data-testid="bottom-pad">{{ virtualPaddingBottom }}</span>
                </div>
            `,
        })

        const wrapper = mount(Harness)
        await nextTick()

        const scroll = wrapper.get('[data-testid="scroll"]').element as HTMLElement
        setClientHeight(scroll, 50)
        scroll.dispatchEvent(new Event('scroll'))
        await nextTick()

        expect(wrapper.get('[data-testid="visible-count"]').text()).toBe('7')
        expect(wrapper.get('[data-testid="first-item"]').text()).toBe('1')
        expect(wrapper.get('[data-testid="bottom-pad"]').text()).toBe('130')

        scroll.scrollTop = 80
        scroll.dispatchEvent(new Event('scroll'))
        await nextTick()

        expect(wrapper.get('[data-testid="start-index"]').text()).toBe('7')
        expect(wrapper.get('[data-testid="first-item"]').text()).toBe('8')
        expect(wrapper.get('[data-testid="top-pad"]').text()).toBe('70')
    })

    it('resets to the top of the virtual list', async () => {
        vi.stubGlobal('ResizeObserver', undefined)
        const sourceItems = ref(Array.from({ length: 20 }, (_, index) => index + 1))

        const Harness = defineComponent({
            setup() {
                const isActive = ref(true)
                return {
                    ...useVisibleGroupWindow({
                        items: computed(() => sourceItems.value),
                        isActive,
                        batchSize: 2,
                        estimatedItemHeight: 10,
                        overscan: 1,
                    }),
                }
            },
            template: `
                <div ref="scrollContainer" data-testid="scroll">
                    <span data-testid="first-item">{{ visibleItems[0] }}</span>
                    <button data-testid="reset" @click="resetVisibleItems">Reset</button>
                </div>
            `,
        })

        const wrapper = mount(Harness)
        await nextTick()

        const scroll = wrapper.get('[data-testid="scroll"]').element as HTMLElement
        setClientHeight(scroll, 50)
        scroll.scrollTop = 80
        scroll.dispatchEvent(new Event('scroll'))
        await nextTick()

        expect(wrapper.get('[data-testid="first-item"]').text()).toBe('8')

        await wrapper.get('[data-testid="reset"]').trigger('click')
        await nextTick()

        expect(scroll.scrollTop).toBe(0)
        expect(wrapper.get('[data-testid="first-item"]').text()).toBe('1')
    })
})
