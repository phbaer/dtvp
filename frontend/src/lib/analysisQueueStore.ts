import { shallowRef, computed } from 'vue'
import {
    analysisQueueList,
    analysisQueueStatus,
    analysisQueueSubmit,
    analysisQueueSubmitFollowUp,
    analysisQueueGet,
    analysisQueueCancel,
    analysisQueueClear,
    analysisQueueCancelQueued,
} from './api'
import type {
    AnalysisQueueItem,
    CodeAnalysisAssessResponse,
    CodeAnalysisAutoSweepStatus,
} from './api'
import { buildVersionStore, checkForUpdate } from './buildVersion'

const items = shallowRef<AnalysisQueueItem[]>([])
const countsByStatus = shallowRef<Record<string, number>>({})
const sweepStatus = shallowRef<CodeAnalysisAutoSweepStatus | null>(null)
const polling = shallowRef(false)
let pollTimer: ReturnType<typeof setTimeout> | null = null
let statusRefreshInFlight: Promise<void> | null = null
const ACTIVE_POLL_INTERVAL = 5000
const IDLE_POLL_INTERVAL = 30000
const POLL_JITTER_RATIO = 0.1
const MAX_RESULT_CACHE_ENTRIES = 50

// Callbacks keyed by queue_id for when items complete
type CompletionCallback = (result: CodeAnalysisAssessResponse, item: AnalysisQueueItem) => void

const completionCallbacks = new Map<string, CompletionCallback>()
const failureCallbacks = new Map<string, (error: string) => void>()

// Cache fetched results by queue_id so they survive component unmount/remount
const resultCache = new Map<string, CodeAnalysisAssessResponse>()

function parseQueueTimestamp(value?: string): number {
    if (!value) {
        return 0
    }

    const timestamp = Date.parse(value)
    return Number.isNaN(timestamp) ? 0 : timestamp
}

function sortQueueItemsLatestFirst(queueItems: AnalysisQueueItem[]): AnalysisQueueItem[] {
    return queueItems
        .map((item, index) => ({ item, index }))
        .sort((left, right) => {
            const submittedDiff = parseQueueTimestamp(right.item.submitted_at) - parseQueueTimestamp(left.item.submitted_at)
            if (submittedDiff !== 0) {
                return submittedDiff
            }

            return left.index - right.index
        })
        .map(({ item }) => item)
}

function cacheResult(queueId: string, result: CodeAnalysisAssessResponse) {
    if (resultCache.has(queueId)) {
        resultCache.delete(queueId)
    }
    resultCache.set(queueId, result)
    if (resultCache.size > MAX_RESULT_CACHE_ENTRIES) {
        const oldestKey = resultCache.keys().next().value
        if (oldestKey !== undefined) {
            resultCache.delete(oldestKey)
        }
    }
}

const activeCount = computed(() => (
    (countsByStatus.value.queued ?? 0) + (countsByStatus.value.running ?? 0)
))

const runningItem = computed(() =>
    items.value.find(i => i.status === 'running') ?? null
)

const queuedItems = computed(() =>
    items.value.filter(i => i.status === 'queued')
)

const hasActivity = computed(() => activeCount.value > 0)

const activeVulnerabilityIds = computed(() => {
    const ids = new Set<string>()
    for (const item of items.value) {
        if (item.status !== 'queued' && item.status !== 'running') continue
        const vulnerabilityId = String(item.vuln_id || '').trim().toLocaleLowerCase()
        if (vulnerabilityId) ids.add(vulnerabilityId)
    }
    return ids
})

async function refresh() {
    try {
        items.value = sortQueueItemsLatestFirst(await analysisQueueList())
        countsByStatus.value = countQueueItems(items.value)
    } catch {
        // Detailed queue loading is best-effort.
    }
}

function countQueueItems(queueItems: AnalysisQueueItem[]): Record<string, number> {
    const counts: Record<string, number> = {}
    for (const item of queueItems) {
        counts[item.status] = (counts[item.status] ?? 0) + 1
    }
    return counts
}

function isDocumentVisible(): boolean {
    return typeof document === 'undefined' || document.visibilityState !== 'hidden'
}

async function loadTrackedItemsMissingFromStatus(statusItems: AnalysisQueueItem[]) {
    const presentIds = new Set(statusItems.map(item => item.queue_id))
    const trackedIds = new Set([
        ...completionCallbacks.keys(),
        ...failureCallbacks.keys(),
    ])
    const missingIds = [...trackedIds].filter(queueId => !presentIds.has(queueId))
    if (missingIds.length === 0) return statusItems

    const trackedItems = await Promise.all(missingIds.map(async queueId => {
        try {
            return await analysisQueueGet(queueId)
        } catch {
            return null
        }
    }))
    return [
        ...statusItems,
        ...trackedItems.filter((item): item is AnalysisQueueItem => item !== null),
    ]
}

async function refreshStatus() {
    if (statusRefreshInFlight) return statusRefreshInFlight
    statusRefreshInFlight = (async () => {
        try {
            const status = await analysisQueueStatus()
            const statusItems = await loadTrackedItemsMissingFromStatus(status.items)
            items.value = sortQueueItemsLatestFirst(statusItems)
            countsByStatus.value = status.counts_by_status
            sweepStatus.value = status.auto_sweep
        } catch {
            // Global status polling is best-effort.
        } finally {
            statusRefreshInFlight = null
        }
    })()
    return statusRefreshInFlight
}

async function startPolling() {
    if (polling.value) return
    polling.value = true
    document.addEventListener('visibilitychange', handleVisibilityChange)
    if (isDocumentVisible()) {
        await pollStatus()
    } else {
        scheduleNext(IDLE_POLL_INTERVAL)
    }
}

function getPollInterval(): number {
    return activeCount.value > 0
        ? ACTIVE_POLL_INTERVAL
        : IDLE_POLL_INTERVAL
}

function jitteredDelay(delay: number): number {
    const jitter = delay * POLL_JITTER_RATIO
    return Math.round(delay - jitter + Math.random() * jitter * 2)
}

async function handleCompletedItem(item: AnalysisQueueItem) {
    try {
        const full = await analysisQueueGet(item.queue_id)
        if (full.result) {
            cacheResult(item.queue_id, full.result)
            completionCallbacks.get(item.queue_id)?.(full.result, full)
            completionCallbacks.delete(item.queue_id)
            failureCallbacks.delete(item.queue_id)
            return
        }
    } catch {
        // Silently ignore result fetch errors
    }
}

function handleFailedItem(item: AnalysisQueueItem) {
    const callback = failureCallbacks.get(item.queue_id)
    if (callback) {
        callback(item.error || 'Analysis failed')
    }
    completionCallbacks.delete(item.queue_id)
    failureCallbacks.delete(item.queue_id)
}

async function processStatusTransitions(previousStatuses: Map<string, AnalysisQueueItem['status']>) {
    for (const item of items.value) {
        const previousStatus = previousStatuses.get(item.queue_id)
        const statusChanged = Boolean(previousStatus && previousStatus !== item.status)
        const hasCallback = completionCallbacks.has(item.queue_id) || failureCallbacks.has(item.queue_id)
        if (!statusChanged && !hasCallback) continue

        if (item.status === 'completed') {
            await handleCompletedItem(item)
            continue
        }

        if (item.status === 'failed') {
            handleFailedItem(item)
        }
    }
}

async function pollStatus() {
    const previousItems = new Map(items.value.map(item => [item.queue_id, item.status]))
    if (isDocumentVisible()) {
        await checkForUpdate()
        if (buildVersionStore.updateAvailable.value) {
            // This tab is running a superseded bundle. Stop here so a stale tab
            // cannot keep loading the server until someone reloads it.
            stopPolling()
            return
        }
        await refreshStatus()
        await processStatusTransitions(previousItems)
    }
    if (polling.value) {
        scheduleNext(getPollInterval())
    }
}

function scheduleNext(delay: number) {
    if (!polling.value) return
    if (pollTimer) clearTimeout(pollTimer)
    pollTimer = setTimeout(pollStatus, jitteredDelay(delay))
}

function handleVisibilityChange() {
    if (!polling.value || !isDocumentVisible()) return
    if (pollTimer) {
        clearTimeout(pollTimer)
        pollTimer = null
    }
    void pollStatus()
}

function stopPolling() {
    polling.value = false
    document.removeEventListener('visibilitychange', handleVisibilityChange)
    if (pollTimer) {
        clearTimeout(pollTimer)
        pollTimer = null
    }
}

async function submit(
    vulnId: string,
    componentName: string,
    projectName?: string,
    cvssVector?: string,
    userGuidance?: string,
    onComplete?: CompletionCallback,
    onError?: (error: string) => void,
    projectVersions?: string[],
    source: 'manual' | 'benchmark' | string = 'manual',
): Promise<AnalysisQueueItem> {
    const item = await analysisQueueSubmit({
        vuln_id: vulnId,
        component_name: componentName,
        project_name: projectName,
        cvss_vector: cvssVector,
        user_guidance: userGuidance,
        project_versions: projectVersions,
        source,
    })
    if (onComplete) completionCallbacks.set(item.queue_id, onComplete)
    if (onError) failureCallbacks.set(item.queue_id, onError)
    const previousStatuses = new Map(items.value.map(existing => [existing.queue_id, existing.status]))
    previousStatuses.set(item.queue_id, item.status)
    items.value = sortQueueItemsLatestFirst([
        item,
        ...items.value.filter(existing => existing.queue_id !== item.queue_id),
    ])
    await refreshStatus()
    await processStatusTransitions(previousStatuses)
    if (!polling.value) startPolling()
    return item
}

async function submitFollowUp(
    parentRunId: string,
    question: string,
    componentName?: string,
    projectName?: string,
    cvssVector?: string,
    userGuidance?: string,
    onComplete?: CompletionCallback,
    onError?: (error: string) => void,
): Promise<AnalysisQueueItem> {
    const item = await analysisQueueSubmitFollowUp({
        parent_run_id: parentRunId,
        question,
        component_name: componentName,
        project_name: projectName,
        cvss_vector: cvssVector,
        user_guidance: userGuidance,
    })
    if (onComplete) completionCallbacks.set(item.queue_id, onComplete)
    if (onError) failureCallbacks.set(item.queue_id, onError)
    const previousStatuses = new Map(items.value.map(existing => [existing.queue_id, existing.status]))
    previousStatuses.set(item.queue_id, item.status)
    items.value = sortQueueItemsLatestFirst([
        item,
        ...items.value.filter(existing => existing.queue_id !== item.queue_id),
    ])
    await refreshStatus()
    await processStatusTransitions(previousStatuses)
    if (!polling.value) startPolling()
    return item
}

async function cancel(queueId: string) {
    await analysisQueueCancel(queueId)
    completionCallbacks.delete(queueId)
    failureCallbacks.delete(queueId)
    await refreshStatus()
}

async function dismiss(queueId: string) {
    try {
        await analysisQueueCancel(queueId) // DELETE removes finished items too
    } catch { /* ignore */ }
    completionCallbacks.delete(queueId)
    failureCallbacks.delete(queueId)
    resultCache.delete(queueId)
    await refreshStatus()
}

async function clearFinished(statuses?: string[]) {
    await analysisQueueClear(statuses)
    await refreshStatus()
}

async function cancelQueued() {
    await analysisQueueCancelQueued()
    await refreshStatus()
}

function getItemForVuln(vulnId: string, componentName: string): AnalysisQueueItem | undefined {
    return items.value.find(
        i => i.vuln_id === vulnId
            && i.component_name === componentName
            && (i.status === 'queued' || i.status === 'running')
    )
}

function getPositionForVuln(vulnId: string, componentName: string): number {
    const item = getItemForVuln(vulnId, componentName)
    return item?.position ?? 0
}

/** Get completed queue items for a given vuln (optionally filtered by component) */
function getCompletedForVuln(vulnId: string, componentName?: string): AnalysisQueueItem[] {
    return items.value.filter(
        i => i.vuln_id === vulnId
            && i.status === 'completed'
            && (!componentName || i.component_name === componentName)
    )
}

/** Get cached result for a queue item. Returns undefined if not yet fetched. */
function getCachedResult(queueId: string): CodeAnalysisAssessResponse | undefined {
    return resultCache.get(queueId)
}

/** Fetch and cache result for a completed queue item */
async function fetchResult(queueId: string): Promise<CodeAnalysisAssessResponse | undefined> {
    const cached = resultCache.get(queueId)
    if (cached) return cached
    try {
        const full = await analysisQueueGet(queueId)
        if (full.result) {
            cacheResult(queueId, full.result)
            return full.result
        }
    } catch { /* ignore */ }
    return undefined
}

export const analysisQueueStore = {
    items,
    countsByStatus,
    sweepStatus,
    activeCount,
    runningItem,
    queuedItems,
    hasActivity,
    activeVulnerabilityIds,
    refresh,
    refreshStatus,
    startPolling,
    stopPolling,
    submit,
    submitFollowUp,
    cancel,
    dismiss,
    clearFinished,
    cancelQueued,
    getItemForVuln,
    getPositionForVuln,
    getCompletedForVuln,
    getCachedResult,
    fetchResult,
}
