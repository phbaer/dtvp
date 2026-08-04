import { onScopeDispose, type Ref } from 'vue'
import { getTaskStatus } from './api'

const DEFAULT_TASK_LEASE_INTERVAL_MS = 4 * 60 * 1000

interface UseTaskLeaseOptions {
    taskId: Ref<string | null>
    isActive?: () => boolean
    onExpired: (taskId: string) => void | Promise<void>
    intervalMs?: number
}

export const useTaskLease = ({
    taskId,
    isActive = () => true,
    onExpired,
    intervalMs = DEFAULT_TASK_LEASE_INTERVAL_MS,
}: UseTaskLeaseOptions) => {
    let renewalInFlight = false

    const renew = async () => {
        const leasedTaskId = taskId.value
        if (!leasedTaskId || !isActive() || renewalInFlight) return

        renewalInFlight = true
        try {
            const status = await getTaskStatus(leasedTaskId, { includeResult: false })
            if (taskId.value === leasedTaskId && status.status === 'not_found') {
                await onExpired(leasedTaskId)
            }
        } catch (error) {
            // Authentication failures are handled centrally. Transient network
            // errors should not discard an otherwise usable task lease.
            console.warn('Failed to renew grouped vulnerability task lease.', error)
        } finally {
            renewalInFlight = false
        }
    }

    const timer = globalThis.setInterval(() => {
        void renew()
    }, Math.max(1_000, intervalMs))

    const handleVisibilityChange = () => {
        if (globalThis.document?.visibilityState === 'visible') {
            void renew()
        }
    }
    globalThis.document?.addEventListener('visibilitychange', handleVisibilityChange)

    onScopeDispose(() => {
        globalThis.clearInterval(timer)
        globalThis.document?.removeEventListener('visibilitychange', handleVisibilityChange)
    })

    return { renew }
}
