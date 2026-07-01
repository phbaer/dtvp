import { mount } from '@vue/test-utils'
import { defineComponent, nextTick, reactive } from 'vue'
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { describe, expect, it, vi } from 'vitest'
import { useProjectVulnSelection } from '../useProjectVulnSelection'

type ProjectVulnSelection = ReturnType<typeof useProjectVulnSelection>

const mountHarness = (query: LocationQuery = {}) => {
    const route = reactive({
        query: { ...query },
    })
    const router = {
        replace: vi.fn((location: { query: LocationQueryRaw }) => Promise.resolve(location)),
    }
    let selection!: ProjectVulnSelection

    const Harness = defineComponent({
        setup() {
            selection = useProjectVulnSelection({
                route,
                router,
            })
            return {}
        },
        template: '<div />',
    })

    const wrapper = mount(Harness)
    return { wrapper, route, router, selection }
}

describe('useProjectVulnSelection', () => {
    it('hydrates the selected vulnerability from the route query', () => {
        const { selection, wrapper } = mountHarness({ vuln: 'CVE-1' })

        expect(selection.selectedGroupId.value).toBe('CVE-1')

        wrapper.unmount()
    })

    it('keeps selection in sync when the route query changes', async () => {
        const { route, selection, wrapper } = mountHarness({ vuln: 'CVE-1' })

        route.query.vuln = 'CVE-2'
        await nextTick()

        expect(selection.selectedGroupId.value).toBe('CVE-2')

        delete route.query.vuln
        await nextTick()

        expect(selection.selectedGroupId.value).toBeNull()

        wrapper.unmount()
    })

    it('writes selected and closed vulnerability IDs back to the route', () => {
        const { router, selection, wrapper } = mountHarness({ q: 'spring' })

        selection.selectGroup({ id: 'CVE-3', affected_versions: [] })

        expect(selection.selectedGroupId.value).toBe('CVE-3')
        expect(router.replace).toHaveBeenCalledWith({
            query: { q: 'spring', vuln: 'CVE-3' },
        })

        selection.closeSelectedGroup()

        expect(selection.selectedGroupId.value).toBeNull()
        expect(router.replace).toHaveBeenLastCalledWith({
            query: { q: 'spring' },
        })

        wrapper.unmount()
    })
})
