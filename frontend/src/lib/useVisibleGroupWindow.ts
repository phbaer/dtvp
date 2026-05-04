import { computed, nextTick, onUnmounted, ref, watch, type ComputedRef, type Ref } from 'vue'

type TimeoutHandle = ReturnType<typeof setTimeout>

type IdleCapableWindow = Window & typeof globalThis & {
    requestIdleCallback?: (callback: () => void, options?: { timeout?: number }) => number
    cancelIdleCallback?: (handle: number) => void
}

interface VisibleGroupWindowOptions<T> {
    items: ComputedRef<T[]>
    isActive: Ref<boolean> | ComputedRef<boolean>
    batchSize?: number
    rootMargin?: string
}

const getBrowserWindow = (): IdleCapableWindow | undefined => {
    return globalThis.window as IdleCapableWindow | undefined
}

export function useVisibleGroupWindow<T>({
    items,
    isActive,
    batchSize = 20,
    rootMargin = '400px',
}: VisibleGroupWindowOptions<T>) {
    const visibleItemCount = ref(batchSize)
    const loadMoreTrigger = ref<HTMLElement | null>(null)
    const loadMoreObserver = ref<IntersectionObserver | null>(null)
    const backgroundLoadHandle = ref<number | TimeoutHandle | null>(null)
    const backgroundLoadMode = ref<'idle' | 'timeout' | null>(null)

    const visibleItems = computed(() => {
        return items.value.slice(0, visibleItemCount.value)
    })

    const hasMoreItems = computed(() => {
        return visibleItemCount.value < items.value.length
    })

    const cancelBackgroundLoad = () => {
        if (backgroundLoadHandle.value === null) return

        const browserWindow = getBrowserWindow()
        if (backgroundLoadMode.value === 'idle' && browserWindow?.cancelIdleCallback) {
            browserWindow.cancelIdleCallback(backgroundLoadHandle.value as number)
        } else if (browserWindow) {
            browserWindow.clearTimeout(backgroundLoadHandle.value as number)
        } else {
            clearTimeout(backgroundLoadHandle.value as TimeoutHandle)
        }
        backgroundLoadHandle.value = null
        backgroundLoadMode.value = null
    }

    const loadMoreItems = () => {
        if (visibleItemCount.value >= items.value.length) return
        visibleItemCount.value = Math.min(items.value.length, visibleItemCount.value + batchSize)
        if (hasMoreItems.value) {
            scheduleBackgroundLoad()
        }
    }

    const scheduleBackgroundLoad = () => {
        if (backgroundLoadHandle.value !== null || !hasMoreItems.value) return

        const callback = () => {
            backgroundLoadHandle.value = null
            if (!hasMoreItems.value) return
            loadMoreItems()
        }

        const browserWindow = getBrowserWindow()
        if (browserWindow?.requestIdleCallback) {
            backgroundLoadHandle.value = browserWindow.requestIdleCallback(callback, { timeout: 1000 })
            backgroundLoadMode.value = 'idle'
        } else if (browserWindow) {
            backgroundLoadHandle.value = browserWindow.setTimeout(callback, 250)
            backgroundLoadMode.value = 'timeout'
        } else {
            backgroundLoadHandle.value = setTimeout(callback, 250)
            backgroundLoadMode.value = 'timeout'
        }
    }

    const disconnectLoadMoreObserver = () => {
        if (!loadMoreObserver.value) return
        loadMoreObserver.value.disconnect()
        loadMoreObserver.value = null
    }

    const attachLoadMoreObserver = () => {
        disconnectLoadMoreObserver()
        if (!loadMoreTrigger.value || !isActive.value) return

        loadMoreObserver.value = new IntersectionObserver((entries) => {
            for (const entry of entries) {
                if (entry.isIntersecting && hasMoreItems.value) {
                    loadMoreItems()
                }
            }
        }, {
            rootMargin,
        })

        loadMoreObserver.value.observe(loadMoreTrigger.value)
    }

    const resetVisibleItems = () => {
        visibleItemCount.value = batchSize
        scheduleBackgroundLoad()
    }

    watch([
        () => items.value.length,
        () => isActive.value,
    ], ([, active]) => {
        if (active) {
            resetVisibleItems()
            void nextTick(() => {
                attachLoadMoreObserver()
            })
            return
        }

        disconnectLoadMoreObserver()
        cancelBackgroundLoad()
    }, { immediate: true })

    watch(items, () => {
        if (visibleItemCount.value > items.value.length) {
            visibleItemCount.value = Math.min(items.value.length, batchSize)
        }
        scheduleBackgroundLoad()
    })

    watch(loadMoreTrigger, () => {
        if (!isActive.value) return
        void nextTick(() => {
            attachLoadMoreObserver()
        })
    })

    onUnmounted(() => {
        disconnectLoadMoreObserver()
        cancelBackgroundLoad()
    })

    return {
        visibleItems,
        hasMoreItems,
        loadMoreTrigger,
        visibleItemCount,
        loadMoreItems,
        resetVisibleItems,
    }
}