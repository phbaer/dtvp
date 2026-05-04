import { shallowRef, computed } from 'vue'
import {
    analysisQueueList,
    analysisQueueSubmit,
    analysisQueueGet,
    analysisQueueCancel,
} from './api'
import type { AnalysisQueueItem, CodeAnalysisAssessResponse } from './api'

const items = shallowRef<AnalysisQueueItem[]>([])
const polling = shallowRef(false)
let pollTimer: ReturnType<typeof setTimeout> | null = null
const ACTIVE_POLL_INTERVAL = 3000
const IDLE_POLL_INTERVAL = 10000
const MAX_RESULT_CACHE_ENTRIES = 50

// Callbacks keyed by queue_id for when items complete
const completionCallbacks = new Map<string, (result: CodeAnalysisAssessResponse) => void>()
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

const activeCount = computed(() =>
    items.value.filter(i => i.status === 'queued' || i.status === 'running').length
)

const runningItem = computed(() =>
    items.value.find(i => i.status === 'running') ?? null
)

const queuedItems = computed(() =>
    items.value.filter(i => i.status === 'queued')
)

const hasActivity = computed(() => activeCount.value > 0)

async function refresh() {
    try {
        items.value = sortQueueItemsLatestFirst(await analysisQueueList())
    } catch {
        // Silently ignore polling errors
    }
}

async function startPolling() {
    if (polling.value) return
    polling.value = true
    await refresh()
    scheduleNext(getPollInterval(items.value))
}

function getPollInterval(queueItems: AnalysisQueueItem[]): number {
    return queueItems.some(item => item.status === 'queued' || item.status === 'running')
        ? ACTIVE_POLL_INTERVAL
        : IDLE_POLL_INTERVAL
}

async function handleCompletedItem(item: AnalysisQueueItem) {
    try {
        const full = await analysisQueueGet(item.queue_id)
        if (full.result) {
            cacheResult(item.queue_id, full.result)
            completionCallbacks.get(item.queue_id)?.(full.result)
        }
    } catch {
        // Silently ignore result fetch errors
    }
    completionCallbacks.delete(item.queue_id)
    failureCallbacks.delete(item.queue_id)
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
        if (!previousStatus || previousStatus === item.status) continue

        if (item.status === 'completed') {
            await handleCompletedItem(item)
            continue
        }

        if (item.status === 'failed') {
            handleFailedItem(item)
        }
    }
}

function scheduleNext(delay: number) {
    if (!polling.value) return
    pollTimer = setTimeout(async () => {
        const previousItems = new Map(items.value.map(item => [item.queue_id, item.status]))
        await refresh()
        await processStatusTransitions(previousItems)

        if (polling.value) {
            scheduleNext(getPollInterval(items.value))
        }
    }, delay)
}

function stopPolling() {
    polling.value = false
    if (pollTimer) {
        clearTimeout(pollTimer)
        pollTimer = null
    }
}

async function submit(
    vulnId: string,
    componentName: string,
    cvssVector?: string,
    userGuidance?: string,
    onComplete?: (result: CodeAnalysisAssessResponse) => void,
    onError?: (error: string) => void,
): Promise<AnalysisQueueItem> {
    const item = await analysisQueueSubmit({
        vuln_id: vulnId,
        component_name: componentName,
        cvss_vector: cvssVector,
        user_guidance: userGuidance,
    })
    if (onComplete) completionCallbacks.set(item.queue_id, onComplete)
    if (onError) failureCallbacks.set(item.queue_id, onError)
    await refresh()
    if (!polling.value) startPolling()
    return item
}

async function cancel(queueId: string) {
    await analysisQueueCancel(queueId)
    completionCallbacks.delete(queueId)
    failureCallbacks.delete(queueId)
    await refresh()
}

async function dismiss(queueId: string) {
    try {
        await analysisQueueCancel(queueId) // DELETE removes finished items too
    } catch { /* ignore */ }
    completionCallbacks.delete(queueId)
    failureCallbacks.delete(queueId)
    resultCache.delete(queueId)
    await refresh()
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
    activeCount,
    runningItem,
    queuedItems,
    hasActivity,
    refresh,
    startPolling,
    stopPolling,
    submit,
    cancel,
    dismiss,
    getItemForVuln,
    getPositionForVuln,
    getCompletedForVuln,
    getCachedResult,
    fetchResult,
}
