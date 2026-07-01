import { computed, nextTick, onUnmounted, ref, watch, type ComputedRef, type Ref } from 'vue'

interface VisibleGroupWindowOptions<T> {
    items: ComputedRef<T[]>
    isActive: Ref<boolean> | ComputedRef<boolean>
    batchSize?: number
    estimatedItemHeight?: number
    overscan?: number
}

const getBrowserWindow = (): (Window & typeof globalThis) | undefined => {
    return globalThis.window as (Window & typeof globalThis) | undefined
}

export function useVisibleGroupWindow<T>({
    items,
    isActive,
    batchSize = 20,
    estimatedItemHeight = 84,
    overscan = 6,
}: VisibleGroupWindowOptions<T>) {
    const scrollContainer = ref<HTMLElement | null>(null)
    const scrollTop = ref(0)
    const viewportHeight = ref(0)

    let activeScrollElement: HTMLElement | null = null
    let resizeObserver: ResizeObserver | null = null

    const measureViewport = () => {
        const element = scrollContainer.value
        if (!element) {
            viewportHeight.value = 0
            return
        }

        const measured = element.clientHeight || element.getBoundingClientRect().height || 0
        viewportHeight.value = Math.max(0, Math.floor(measured))
    }

    const handleScroll = () => {
        const element = scrollContainer.value
        scrollTop.value = element?.scrollTop || 0
        measureViewport()
    }

    const detachScrollListeners = () => {
        if (activeScrollElement) {
            activeScrollElement.removeEventListener('scroll', handleScroll)
            activeScrollElement = null
        }
        if (resizeObserver) {
            resizeObserver.disconnect()
            resizeObserver = null
        }
        getBrowserWindow()?.removeEventListener('resize', measureViewport)
    }

    const attachScrollListeners = () => {
        detachScrollListeners()
        const element = scrollContainer.value
        if (!element || !isActive.value) return

        activeScrollElement = element
        activeScrollElement.addEventListener('scroll', handleScroll, { passive: true })

        if (typeof ResizeObserver !== 'undefined') {
            resizeObserver = new ResizeObserver(measureViewport)
            resizeObserver.observe(element)
        } else {
            getBrowserWindow()?.addEventListener('resize', measureViewport)
        }

        handleScroll()
    }

    const effectiveItemHeight = computed(() => Math.max(1, estimatedItemHeight))
    const viewportItemCount = computed(() => {
        if (viewportHeight.value <= 0) return batchSize
        return Math.max(batchSize, Math.ceil(viewportHeight.value / effectiveItemHeight.value))
    })

    const visibleStartIndex = computed(() => {
        if (!isActive.value || items.value.length === 0) return 0
        return Math.max(0, Math.floor(scrollTop.value / effectiveItemHeight.value) - overscan)
    })

    const visibleEndIndex = computed(() => {
        if (!isActive.value) return Math.min(items.value.length, batchSize)
        return Math.min(
            items.value.length,
            visibleStartIndex.value + viewportItemCount.value + overscan * 2,
        )
    })

    const visibleItems = computed(() => {
        return items.value.slice(visibleStartIndex.value, visibleEndIndex.value)
    })

    const virtualPaddingTop = computed(() => visibleStartIndex.value * effectiveItemHeight.value)
    const virtualPaddingBottom = computed(() => {
        return Math.max(0, (items.value.length - visibleEndIndex.value) * effectiveItemHeight.value)
    })

    const hasMoreItems = computed(() => visibleEndIndex.value < items.value.length)
    const visibleItemCount = computed(() => visibleItems.value.length)

    const resetVisibleItems = () => {
        scrollTop.value = 0
        if (scrollContainer.value) {
            scrollContainer.value.scrollTop = 0
            measureViewport()
        }
    }

    watch([
        () => scrollContainer.value,
        () => isActive.value,
    ], ([, active]) => {
        if (!active) {
            detachScrollListeners()
            return
        }

        void nextTick(() => {
            attachScrollListeners()
        })
    }, { immediate: true })

    watch(() => items.value.length, () => {
        if (visibleStartIndex.value >= items.value.length) {
            resetVisibleItems()
        }
    })

    onUnmounted(() => {
        detachScrollListeners()
    })

    return {
        visibleItems,
        hasMoreItems,
        visibleItemCount,
        visibleStartIndex,
        visibleEndIndex,
        virtualPaddingTop,
        virtualPaddingBottom,
        scrollContainer,
        resetVisibleItems,
    }
}
