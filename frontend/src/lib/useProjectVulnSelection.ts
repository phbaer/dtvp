import { ref, watch } from 'vue'
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import type { GroupedVuln } from '../types'

interface ProjectRouteLike {
    query: LocationQuery
}

interface ProjectRouterLike {
    replace: (location: { query: LocationQueryRaw }) => Promise<unknown>
}

interface UseProjectVulnSelectionOptions {
    route: ProjectRouteLike
    router: ProjectRouterLike
    isRouteActive?: () => boolean
}

const routeVulnId = (value: unknown): string | null =>
    typeof value === 'string' && value.trim() ? value : null

export function useProjectVulnSelection({
    route,
    router,
    isRouteActive,
}: UseProjectVulnSelectionOptions) {
    const selectedGroupId = ref<string | null>(routeVulnId(route.query.vuln))
    const shouldSyncFromRoute = () => isRouteActive?.() ?? true
    const syncSelectedGroupFromRoute = () => {
        if (!shouldSyncFromRoute()) return
        selectedGroupId.value = routeVulnId(route.query.vuln)
    }

    const updateVulnQuery = (id: string | null) => {
        const query: LocationQueryRaw = { ...route.query }
        if (id) query.vuln = id
        else delete query.vuln
        router.replace({ query }).catch(() => {})
    }

    const selectGroup = (group: GroupedVuln) => {
        selectedGroupId.value = group.id
        updateVulnQuery(group.id)
    }

    const closeSelectedGroup = () => {
        selectedGroupId.value = null
        updateVulnQuery(null)
    }

    watch(() => route.query.vuln, () => {
        syncSelectedGroupFromRoute()
    })

    return {
        selectedGroupId,
        selectGroup,
        closeSelectedGroup,
        updateVulnQuery,
        syncSelectedGroupFromRoute,
    }
}
