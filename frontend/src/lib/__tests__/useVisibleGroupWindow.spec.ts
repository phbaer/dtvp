import { mount } from '@vue/test-utils'
import { computed, defineComponent, nextTick, ref } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useVisibleGroupWindow } from '../useVisibleGroupWindow'

class MockIntersectionObserver {
    static instances: MockIntersectionObserver[] = []

    callback: IntersectionObserverCallback
    observedElements: Element[] = []

    constructor(callback: IntersectionObserverCallback) {
        this.callback = callback
        MockIntersectionObserver.instances.push(this)
    }

    observe(element: Element) {
        this.observedElements.push(element)
    }

    disconnect() {
        this.observedElements = []
    }

    unobserve(_element: Element) {
        return undefined
    }

    takeRecords(): IntersectionObserverEntry[] {
        return []
    }

    trigger(isIntersecting = true) {
        const [target] = this.observedElements
        if (!target) return
        this.callback([
            {
                isIntersecting,
                target,
                boundingClientRect: target.getBoundingClientRect(),
                intersectionRatio: isIntersecting ? 1 : 0,
                intersectionRect: target.getBoundingClientRect(),
                isVisible: isIntersecting,
                rootBounds: null,
                time: Date.now(),
            } as IntersectionObserverEntry,
        ], this as unknown as IntersectionObserver)
    }
}

describe('useVisibleGroupWindow', () => {
    beforeEach(() => {
        MockIntersectionObserver.instances = []
        vi.stubGlobal('IntersectionObserver', MockIntersectionObserver)
    })

    afterEach(() => {
        vi.unstubAllGlobals()
    })

    it('exposes the initial batch and grows when the observer intersects', async () => {
        const Harness = defineComponent({
            setup() {
                const items = ref([1, 2, 3, 4, 5])
                const isActive = ref(true)
                return useVisibleGroupWindow({
                    items: computed(() => items.value),
                    isActive,
                    batchSize: 2,
                })
            },
            template: `
                <div>
                    <span data-testid="visible-count">{{ visibleItems.length }}</span>
                    <div ref="loadMoreTrigger"></div>
                </div>
            `,
        })

        const wrapper = mount(Harness)
        await nextTick()

        expect(wrapper.get('[data-testid="visible-count"]').text()).toBe('2')
        expect(MockIntersectionObserver.instances).toHaveLength(1)

        MockIntersectionObserver.instances[0]?.trigger(true)
        await nextTick()

        expect(wrapper.get('[data-testid="visible-count"]').text()).toBe('4')
    })

    it('clamps the visible count when the source list shrinks', async () => {
        const sourceItems = ref([1, 2, 3, 4, 5])

        const Harness = defineComponent({
            setup() {
                const isActive = ref(true)
                return {
                    sourceItems,
                    ...useVisibleGroupWindow({
                        items: computed(() => sourceItems.value),
                        isActive,
                        batchSize: 2,
                    }),
                }
            },
            template: `
                <div>
                    <span data-testid="visible-count">{{ visibleItems.length }}</span>
                    <div ref="loadMoreTrigger"></div>
                </div>
            `,
        })

        const wrapper = mount(Harness)
        await nextTick()

        MockIntersectionObserver.instances[0]?.trigger(true)
        await nextTick()
        expect(wrapper.get('[data-testid="visible-count"]').text()).toBe('4')

        sourceItems.value = [1]
        await nextTick()

        expect(wrapper.get('[data-testid="visible-count"]').text()).toBe('1')
    })
})