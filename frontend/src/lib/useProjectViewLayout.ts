import { computed, onMounted, onUnmounted, ref, type ComputedRef, type Ref } from 'vue'

export const DETAIL_INSPECTOR_MIN_VIEWPORT = 1360
export const FILTER_RAIL_MIN_VIEWPORT = 1280
export const FILTER_RAIL_WITH_DETAIL_MIN_VIEWPORT = 1680

interface UseProjectViewLayoutOptions {
    viewMode: Ref<string>
    selectedGroup: ComputedRef<unknown>
    selectedGroupLoading: Ref<boolean> | ComputedRef<boolean>
}

export function useProjectViewLayout({
    viewMode,
    selectedGroup,
    selectedGroupLoading,
}: UseProjectViewLayoutOptions) {
    const viewportWidth = ref(typeof window === 'undefined' ? FILTER_RAIL_MIN_VIEWPORT : window.innerWidth)
    const isDesktopInspector = computed(() => viewportWidth.value >= DETAIL_INSPECTOR_MIN_VIEWPORT)
    const isDesktopDetailOpen = computed(() =>
        (!!selectedGroup.value || selectedGroupLoading.value)
        && viewMode.value === 'analysis'
        && isDesktopInspector.value
    )
    const isFilterRailVisible = computed(() => {
        const requiredWidth = isDesktopDetailOpen.value
            ? FILTER_RAIL_WITH_DETAIL_MIN_VIEWPORT
            : FILTER_RAIL_MIN_VIEWPORT
        return viewportWidth.value >= requiredWidth
    })

    const updateViewportWidth = () => {
        if (typeof window === 'undefined') return
        viewportWidth.value = window.innerWidth
    }

    onMounted(() => {
        updateViewportWidth()
        window.addEventListener('resize', updateViewportWidth)
    })

    onUnmounted(() => {
        if (typeof window === 'undefined') return
        window.removeEventListener('resize', updateViewportWidth)
    })

    return {
        viewportWidth,
        isDesktopInspector,
        isDesktopDetailOpen,
        isFilterRailVisible,
        updateViewportWidth,
    }
}
