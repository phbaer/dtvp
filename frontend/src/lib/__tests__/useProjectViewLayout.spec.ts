import { mount } from '@vue/test-utils'
import { computed, defineComponent, ref } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
    DETAIL_INSPECTOR_MIN_VIEWPORT,
    FILTER_RAIL_MIN_VIEWPORT,
    FILTER_RAIL_WITH_DETAIL_MIN_VIEWPORT,
    useProjectViewLayout,
} from '../useProjectViewLayout'

const setViewportWidth = (width: number) => {
    Object.defineProperty(window, 'innerWidth', {
        configurable: true,
        writable: true,
        value: width,
    })
}

const mountHarness = (options: {
    width?: number
    mode?: string
    selected?: boolean
    loading?: boolean
} = {}) => {
    setViewportWidth(options.width ?? FILTER_RAIL_MIN_VIEWPORT)
    const viewMode = ref(options.mode || 'analysis')
    const selectedGroup = ref(options.selected ? { id: 'CVE-1' } : null)
    const selectedGroupLoading = ref(!!options.loading)
    let layout!: ReturnType<typeof useProjectViewLayout>

    const Harness = defineComponent({
        setup() {
            layout = useProjectViewLayout({
                viewMode,
                selectedGroup: computed(() => selectedGroup.value),
                selectedGroupLoading,
            })
            return {}
        },
        template: '<div />',
    })

    const wrapper = mount(Harness)
    return {
        wrapper,
        viewMode,
        selectedGroup,
        selectedGroupLoading,
        layout,
    }
}

describe('useProjectViewLayout', () => {
    afterEach(() => {
        vi.restoreAllMocks()
    })

    it('tracks desktop inspector and filter rail breakpoints without detail open', () => {
        const { layout, wrapper } = mountHarness({ width: FILTER_RAIL_MIN_VIEWPORT - 1 })

        expect(layout.isDesktopInspector.value).toBe(false)
        expect(layout.isFilterRailVisible.value).toBe(false)

        setViewportWidth(FILTER_RAIL_MIN_VIEWPORT)
        window.dispatchEvent(new Event('resize'))

        expect(layout.viewportWidth.value).toBe(FILTER_RAIL_MIN_VIEWPORT)
        expect(layout.isFilterRailVisible.value).toBe(true)

        setViewportWidth(DETAIL_INSPECTOR_MIN_VIEWPORT)
        window.dispatchEvent(new Event('resize'))

        expect(layout.isDesktopInspector.value).toBe(true)

        wrapper.unmount()
    })

    it('requires the wider filter rail breakpoint when the desktop detail inspector is open', () => {
        const { layout, selectedGroup, wrapper } = mountHarness({
            width: DETAIL_INSPECTOR_MIN_VIEWPORT,
            selected: true,
        })

        expect(layout.isDesktopDetailOpen.value).toBe(true)
        expect(layout.isFilterRailVisible.value).toBe(false)

        setViewportWidth(FILTER_RAIL_WITH_DETAIL_MIN_VIEWPORT)
        window.dispatchEvent(new Event('resize'))

        expect(layout.isFilterRailVisible.value).toBe(true)

        selectedGroup.value = null

        expect(layout.isDesktopDetailOpen.value).toBe(false)
        expect(layout.isFilterRailVisible.value).toBe(true)

        wrapper.unmount()
    })

    it('hides the desktop detail pane outside analysis mode and removes resize listeners on unmount', () => {
        const removeSpy = vi.spyOn(window, 'removeEventListener')
        const { layout, viewMode, wrapper } = mountHarness({
            width: DETAIL_INSPECTOR_MIN_VIEWPORT,
            selected: true,
        })

        expect(layout.isDesktopDetailOpen.value).toBe(true)

        viewMode.value = 'statistics'

        expect(layout.isDesktopDetailOpen.value).toBe(false)

        wrapper.unmount()

        expect(removeSpy).toHaveBeenCalledWith('resize', expect.any(Function))
    })
})
