import { effectScope, ref } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useTaskLease } from '../useTaskLease'
import { getTaskStatus } from '../api'

vi.mock('../api', () => ({
    getTaskStatus: vi.fn(),
}))

describe('useTaskLease', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.useFakeTimers()
    })

    afterEach(() => {
        vi.useRealTimers()
    })

    it('renews an active task without downloading its result', async () => {
        vi.mocked(getTaskStatus).mockResolvedValue({
            task_id: 'task-1',
            status: 'completed',
            message: 'Completed',
            progress: 100,
        })
        const scope = effectScope()
        scope.run(() => {
            useTaskLease({
                taskId: ref('task-1'),
                intervalMs: 1_000,
                onExpired: vi.fn(),
            })
        })

        await vi.advanceTimersByTimeAsync(1_000)

        expect(getTaskStatus).toHaveBeenCalledWith('task-1', { includeResult: false })
        scope.stop()
    })

    it('rebuilds a task that expired while the page was idle', async () => {
        vi.mocked(getTaskStatus).mockResolvedValue({ status: 'not_found' })
        const onExpired = vi.fn()
        const scope = effectScope()
        scope.run(() => {
            useTaskLease({
                taskId: ref('task-1'),
                intervalMs: 1_000,
                onExpired,
            })
        })

        await vi.advanceTimersByTimeAsync(1_000)

        expect(onExpired).toHaveBeenCalledWith('task-1')
        scope.stop()
    })

    it('does not renew an inactive project route', async () => {
        const scope = effectScope()
        scope.run(() => {
            useTaskLease({
                taskId: ref('task-1'),
                isActive: () => false,
                intervalMs: 1_000,
                onExpired: vi.fn(),
            })
        })

        await vi.advanceTimersByTimeAsync(1_000)

        expect(getTaskStatus).not.toHaveBeenCalled()
        scope.stop()
    })
})
