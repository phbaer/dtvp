import { computed, ref } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useTaskGroupDetails } from '../useTaskGroupDetails'
import type { GroupedVuln } from '../../types'

vi.mock('../api', () => ({
    getTaskVulnGroup: vi.fn(),
}))

const group = (id: string, summary = false): GroupedVuln => ({
    id,
    title: summary ? 'summary' : 'full',
    affected_versions: [],
    ...(summary ? { list_metadata: { lifecycle: 'OPEN' } } : {}),
})

const createHarness = (
    initialGroups: Record<string, GroupedVuln>,
    initialTaskId: string | null = 'task-1',
) => {
    const currentTaskId = ref<string | null>(initialTaskId)
    const selectedGroupId = ref<string | null>(Object.keys(initialGroups)[0] || null)
    const listGroups = ref(initialGroups)
    const selectedListGroup = computed(() => {
        if (!selectedGroupId.value) return null
        return listGroups.value[selectedGroupId.value] || null
    })
    const details = useTaskGroupDetails({
        currentTaskId,
        selectedGroupId,
        selectedListGroup,
        findListGroup: id => listGroups.value[id] || null,
    })

    return {
        currentTaskId,
        selectedGroupId,
        listGroups,
        details,
    }
}

describe('useTaskGroupDetails', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('returns a full list group directly when no task detail endpoint is active', async () => {
        const api = await import('../api')
        const fullGroup = group('CVE-1')
        const { details } = createHarness({ 'CVE-1': fullGroup }, null)

        await expect(details.ensureFullGroup('CVE-1')).resolves.toEqual(fullGroup)

        expect(details.selectedGroup.value).toEqual(fullGroup)
        expect(api.getTaskVulnGroup).not.toHaveBeenCalled()
    })

    it('coalesces duplicate full-group requests and caches the hydrated group', async () => {
        const api = await import('../api')
        const hydratedGroup = group('CVE-1')
        let resolveDetails: (value: GroupedVuln) => void = () => {}
        vi.mocked(api.getTaskVulnGroup).mockReturnValue(new Promise(resolve => {
            resolveDetails = resolve
        }))

        const { details } = createHarness({ 'CVE-1': group('CVE-1', true) })

        const firstRequest = details.ensureFullGroup('CVE-1')
        const secondRequest = details.ensureFullGroup('CVE-1', { showLoading: false })
        expect(details.selectedGroupLoading.value).toBe(true)
        expect(api.getTaskVulnGroup).toHaveBeenCalledTimes(1)

        resolveDetails(hydratedGroup)
        const [first, second] = await Promise.all([firstRequest, secondRequest])

        expect(first).toBe(hydratedGroup)
        expect(second).toBe(hydratedGroup)
        expect(details.fullGroupCache.value['CVE-1']).toEqual(hydratedGroup)
        expect(details.selectedGroup.value).toEqual(hydratedGroup)
        expect(details.selectedGroupLoading.value).toBe(false)
    })

    it('force-refreshes a cached full group from the task detail endpoint', async () => {
        const api = await import('../api')
        const cachedGroup = group('CVE-1')
        const refreshedGroup = { ...group('CVE-1'), title: 'fresh' }
        vi.mocked(api.getTaskVulnGroup).mockResolvedValue(refreshedGroup)

        const { details } = createHarness({ 'CVE-1': group('CVE-1', true) })
        details.cacheGroup(cachedGroup)

        await expect(details.ensureFullGroup('CVE-1')).resolves.toEqual(cachedGroup)
        await expect(details.refreshGroup('CVE-1', { showLoading: false })).resolves.toEqual(refreshedGroup)

        expect(api.getTaskVulnGroup).toHaveBeenCalledTimes(1)
        expect(api.getTaskVulnGroup).toHaveBeenCalledWith('task-1', 'CVE-1')
        expect(details.fullGroupCache.value['CVE-1']).toEqual(refreshedGroup)
        expect(details.selectedGroup.value).toEqual(refreshedGroup)
    })

    it('ignores a stale detail response after reset', async () => {
        const api = await import('../api')
        let resolveDetails: (value: GroupedVuln) => void = () => {}
        vi.mocked(api.getTaskVulnGroup).mockReturnValue(new Promise(resolve => {
            resolveDetails = resolve
        }))

        const { details } = createHarness({ 'CVE-1': group('CVE-1', true) })

        const request = details.ensureFullGroup('CVE-1')
        details.reset()
        resolveDetails(group('CVE-1'))
        const result = await request

        expect(result).toBeNull()
        expect(details.fullGroupCache.value).toEqual({})
        expect(details.selectedGroupLoading.value).toBe(false)
    })

    it('keeps a newer in-flight request when an older reset request settles', async () => {
        const api = await import('../api')
        let resolveFirst: (value: GroupedVuln) => void = () => {}
        let resolveSecond: (value: GroupedVuln) => void = () => {}
        vi.mocked(api.getTaskVulnGroup)
            .mockReturnValueOnce(new Promise(resolve => {
                resolveFirst = resolve
            }))
            .mockReturnValueOnce(new Promise(resolve => {
                resolveSecond = resolve
            }))

        const { details } = createHarness({ 'CVE-1': group('CVE-1', true) })

        const staleRequest = details.ensureFullGroup('CVE-1')
        details.reset()
        const activeRequest = details.ensureFullGroup('CVE-1')

        resolveFirst(group('CVE-stale'))
        await staleRequest
        const coalescedRequest = details.ensureFullGroup('CVE-1', { showLoading: false })

        expect(api.getTaskVulnGroup).toHaveBeenCalledTimes(2)

        const hydratedGroup = group('CVE-1')
        resolveSecond(hydratedGroup)
        const [active, coalesced] = await Promise.all([activeRequest, coalescedRequest])

        expect(active).toBe(hydratedGroup)
        expect(coalesced).toBe(hydratedGroup)
        expect(details.fullGroupCache.value['CVE-1']).toEqual(hydratedGroup)
    })
})
