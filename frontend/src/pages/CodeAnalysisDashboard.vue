<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import {
    Activity,
    AlertTriangle,
    Ban,
    CheckCircle,
    Clock,
    Cpu,
    ExternalLink,
    HardDrive,
    Loader2,
    RefreshCw,
    Server,
    Settings2,
    Terminal,
    Trash2,
    XCircle,
    Zap,
} from 'lucide-vue-next'
import {
    analysisQueueCancel,
    analysisQueueCancelQueued,
    analysisQueueClear,
    codeAnalysisGetDashboardStatus,
    codeAnalysisRunAutoSweep,
    type AnalysisQueueItem,
    type CodeAnalysisDashboardStatus,
    type CodeAnalysisResultRecord,
} from '../lib/api'

const status = ref<CodeAnalysisDashboardStatus | null>(null)
const loading = ref(false)
const actionBusy = ref('')
const error = ref('')
const message = ref('')
const expandedLogQueueIds = ref<Set<string>>(new Set())
const queueLogScrollElements = new Map<string, HTMLElement>()
let pollTimer: ReturnType<typeof setInterval> | null = null

const queueItems = computed(() => status.value?.queue.items || [])
const externalJobs = computed(() => status.value?.external.jobs || [])
const activeAgents = computed(() => status.value?.active_agents || [])
const recentResults = computed(() => status.value?.recent_results || [])
const resultCache = computed(() => status.value?.result_cache || null)
const activeQueueItem = computed(() =>
    status.value?.queue.active_item || queueItems.value.find(item => item.status === 'running') || null
)
const activeExternalJob = computed(() =>
    externalJobs.value.find(job => job.status === 'running' || job.status === 'pending') || null
)
const asRecord = (value: unknown): Record<string, any> | null => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null
    return value as Record<string, any>
}
const firstRecord = (...values: unknown[]) => {
    for (const value of values) {
        const record = asRecord(value)
        if (record) return record
    }
    return null
}
const serviceConfiguration = computed(() =>
    firstRecord(
        status.value?.external.configuration,
        status.value?.external.health?.configuration,
        activeExternalJob.value?.configuration,
    )
)
const backendInformation = computed(() =>
    firstRecord(
        status.value?.external.backend,
        status.value?.external.health?.backend,
        activeExternalJob.value?.backend,
    )
)
const llmInfo = computed(() =>
    firstRecord(
        backendInformation.value?.llm,
        status.value?.external.health?.llm,
        activeExternalJob.value?.llm,
    )
)
const repositoryConfiguration = computed(() => asRecord(serviceConfiguration.value?.repositories))
const repositoryBackend = computed(() => asRecord(backendInformation.value?.repositories))
const jobsBackend = computed(() => asRecord(backendInformation.value?.jobs))
const serviceName = computed(() =>
    serviceConfiguration.value?.service_name || status.value?.external.health?.service_name || 'not reported'
)
const serviceVersion = computed(() =>
    serviceConfiguration.value?.service_version || status.value?.external.health?.service_version || 'not reported'
)
const formatLabel = (key: string) => key.replace(/_/g, ' ')
const formatDisplayValue = (value: unknown) => {
    if (value === true) return 'yes'
    if (value === false) return 'no'
    if (value === null || typeof value === 'undefined' || value === '') return '-'
    if (Array.isArray(value)) return value.length ? value.join(', ') : '-'
    if (typeof value === 'object') return JSON.stringify(value)
    return String(value)
}
const featureEntries = computed(() =>
    Object.entries(asRecord(serviceConfiguration.value?.features) || {}).slice(0, 8)
)
const statusCountEntries = computed(() =>
    Object.entries(asRecord(jobsBackend.value?.status_counts) || {})
)
const dtvpAvailableSlots = computed(() => status.value?.queue.available_slots ?? 0)
const analyzerCapacity = computed(() =>
    status.value?.external.capacity ?? jobsBackend.value?.max_concurrent_jobs ?? null
)
const analyzerRunningJobs = computed(() =>
    status.value?.external.running_jobs ?? jobsBackend.value?.running_jobs ?? null
)
const analyzerQueuedJobs = computed(() =>
    status.value?.external.queued_jobs ?? jobsBackend.value?.queued_jobs ?? null
)
const analyzerAvailableSlots = computed(() =>
    status.value?.external.available_slots ?? jobsBackend.value?.available_slots ?? null
)
const queuedCount = computed(() => status.value?.queue.counts_by_status.queued || 0)
const runningCount = computed(() => status.value?.queue.running_count ?? status.value?.queue.counts_by_status.running ?? 0)
const terminalCount = computed(() =>
    (status.value?.queue.counts_by_status.completed || 0)
    + (status.value?.queue.counts_by_status.failed || 0)
    + (status.value?.queue.counts_by_status.cancelled || 0)
)
const modelLabel = computed(() =>
    status.value?.model || activeQueueItem.value?.model || llmInfo.value?.model || 'not reported'
)
const llmBackendLabel = computed(() => {
    const parts = [
        status.value?.llm_provider || llmInfo.value?.provider,
        status.value?.llm_backend || llmInfo.value?.host || llmInfo.value?.backend,
    ].filter(Boolean)
    return parts.length ? parts.join(' / ') : 'not reported'
})
const canRunSweep = computed(() =>
    Boolean(status.value?.auto_sweep.active && !status.value.auto_sweep.running && actionBusy.value !== 'sweep')
)

const queueItemVulnRoute = (item: AnalysisQueueItem) => ({
    path: `/project/${encodeURIComponent(item.project_name || '_all_')}`,
    query: { vuln: item.vuln_id },
})

const resultVulnRoute = (record: CodeAnalysisResultRecord) => ({
    path: `/project/${encodeURIComponent(record.project_name || '_all_')}`,
    query: { vuln: record.vuln_id },
})

const loadStatus = async () => {
    loading.value = true
    try {
        status.value = await codeAnalysisGetDashboardStatus()
        error.value = ''
        scrollQueueLogsToLatest()
    } catch (err: any) {
        error.value = err?.message || 'Unable to load code analysis status.'
    } finally {
        loading.value = false
    }
}

const runAction = async (name: string, fn: () => Promise<unknown>, success: string) => {
    actionBusy.value = name
    message.value = ''
    error.value = ''
    try {
        await fn()
        message.value = success
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Action failed.'
    } finally {
        actionBusy.value = ''
        await loadStatus()
    }
}

const runSweep = () => runAction('sweep', codeAnalysisRunAutoSweep, 'Automatic sweep started.')
const cancelQueued = () => runAction('cancel-queued', analysisQueueCancelQueued, 'Queued analyses cancelled.')
const clearFinished = () => runAction('clear-finished', () => analysisQueueClear(), 'Finished analyses cleared.')
const cancelItem = (item: AnalysisQueueItem) =>
    runAction(`cancel-${item.queue_id}`, () => analysisQueueCancel(item.queue_id), item.status === 'running' ? 'Abort requested.' : 'Queue item updated.')

const formatTimestamp = (value?: string | null) => {
    if (!value) return 'never'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return 'unknown'
    return date.toLocaleString([], {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    })
}

const formatLogTimestamp = (value?: string) => {
    if (!value) return '-'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value
    return date.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    })
}

const formatPercent = (value?: number) => {
    if (typeof value !== 'number') return ''
    return `${Math.max(0, Math.min(100, value))}%`
}

type QueueLogEntry = {
    key: string
    timestamp?: string
    level: 'error' | 'warning' | 'success' | 'running' | 'queued' | 'info'
    levelLabel: string
    source: string
    message: string
}

const normalizeLogLevel = (level: string, message: string): QueueLogEntry['level'] => {
    const text = `${level} ${message}`.toLowerCase()
    if (/(error|failed|failure|exception|refused|traceback)/.test(text)) return 'error'
    if (/(warn|abort|cancelled|canceled|cancel)/.test(text)) return 'warning'
    if (/(complete|completed|success|succeeded|accepted|finished)/.test(text)) return 'success'
    if (/(running|started|scanning|submitting|processing|analyzing|analysing)/.test(text)) return 'running'
    if (/(queued|pending|waiting)/.test(text)) return 'queued'
    return 'info'
}

const inferLogSource = (message: string, explicitSource?: string) => {
    if (explicitSource) return explicitSource
    const sourceMatch = message.match(/^([A-Za-z][\w.-]{1,40}):\s+(.+)$/)
    if (sourceMatch) return sourceMatch[1]
    if (/^dtvp\b/i.test(message) || /submitting scan|abort/i.test(message)) return 'DTVP'
    if (/^analyzer\b|assessment|repository|pipeline|job/i.test(message)) return 'analyzer'
    return 'scan'
}

const stripLogSourcePrefix = (message: string, source: string) => {
    const prefix = `${source}:`
    return message.startsWith(prefix) ? message.slice(prefix.length).trim() : message
}

const parseLogEntry = (entry: unknown, index: number): QueueLogEntry | null => {
    let timestamp = ''
    let rawLevel = ''
    let source = ''
    let message = ''

    if (typeof entry === 'string') {
        message = entry.trim()
    } else if (entry && typeof entry === 'object') {
        const record = entry as Record<string, unknown>
        timestamp = String(record.timestamp || record.time || record.created_at || '')
        rawLevel = String(record.level || record.status || '')
        source = String(record.source || record.agent || record.step || '')
        message = String(record.message || record.msg || record.text || record.event || record.activity || '')
        if (!message) message = JSON.stringify(record)
    } else {
        message = String(entry ?? '').trim()
    }

    if (!message) return null

    const timestampMatch = message.match(/^(\d{4}-\d{2}-\d{2}[T ][^\s]+)\s+(.+)$/)
    if (!timestamp && timestampMatch) {
        timestamp = timestampMatch[1]
        message = timestampMatch[2]
    }

    const levelMatch = message.match(/^(debug|info|warning|warn|error|failed|failure|running|queued|pending|completed|cancelled|canceled|success|ok)\s+(.+)$/i)
    if (!rawLevel && levelMatch) {
        rawLevel = levelMatch[1]
        message = levelMatch[2]
    }

    source = inferLogSource(message, source)
    message = stripLogSourcePrefix(message, source)

    const level = normalizeLogLevel(rawLevel, message)
    const levelLabel = {
        error: 'Error',
        warning: 'Warn',
        success: 'Done',
        running: 'Run',
        queued: 'Wait',
        info: 'Info',
    }[level]

    return {
        key: `${index}-${timestamp}-${rawLevel}-${source}-${message}`,
        timestamp,
        level,
        levelLabel,
        source,
        message,
    }
}

const buildQueueLogEntries = (item: AnalysisQueueItem): QueueLogEntry[] => {
    const entries: unknown[] = [...(item.logs || [])]
    if (entries.length === 0 && item.progress?.current_activity) {
        entries.push({
            status: item.status,
            agent: item.progress.current_agent,
            timestamp: item.progress.last_updated_at,
            message: item.progress.current_activity,
        })
    }
    return entries
        .map(parseLogEntry)
        .filter((entry): entry is QueueLogEntry => Boolean(entry))
}

const queueLogEntriesById = computed(() => {
    const entriesById = new Map<string, QueueLogEntry[]>()
    for (const item of queueItems.value) {
        entriesById.set(item.queue_id, buildQueueLogEntries(item))
    }
    return entriesById
})

const queueLogEntries = (item: AnalysisQueueItem): QueueLogEntry[] =>
    queueLogEntriesById.value.get(item.queue_id) || []

const isQueueLogExpanded = (queueId: string) => expandedLogQueueIds.value.has(queueId)

const setQueueLogScrollElement = (queueId: string, element: Element | null) => {
    if (element instanceof HTMLElement) {
        queueLogScrollElements.set(queueId, element)
        element.scrollTop = element.scrollHeight
        return
    }
    queueLogScrollElements.delete(queueId)
}

const scrollQueueLogsToLatest = (queueId?: string) => {
    void nextTick(() => {
        const queueIds = queueId ? [queueId] : Array.from(expandedLogQueueIds.value)
        for (const id of queueIds) {
            const element = queueLogScrollElements.get(id)
            if (element) {
                element.scrollTop = element.scrollHeight
            }
        }
    })
}

const toggleQueueLog = (queueId: string) => {
    const next = new Set(expandedLogQueueIds.value)
    const opening = !next.has(queueId)
    if (next.has(queueId)) {
        next.delete(queueId)
    } else {
        next.add(queueId)
    }
    expandedLogQueueIds.value = next
    if (opening) {
        scrollQueueLogsToLatest(queueId)
    }
}

const logMessageClass = (level: QueueLogEntry['level']) => {
    if (level === 'error') return 'text-red-200'
    if (level === 'warning') return 'text-yellow-200'
    if (level === 'success') return 'text-emerald-200'
    if (level === 'running') return 'text-blue-200'
    if (level === 'queued') return 'text-amber-200'
    return 'text-gray-200'
}

const logLevelClass = (level: QueueLogEntry['level']) => {
    if (level === 'error') return 'text-red-300'
    if (level === 'warning') return 'text-yellow-300'
    if (level === 'success') return 'text-emerald-300'
    if (level === 'running') return 'text-blue-300'
    if (level === 'queued') return 'text-amber-300'
    return 'text-gray-400'
}

const stateClass = (state?: string) => {
    if (state === 'running') return 'border-blue-700/50 bg-blue-900/20 text-blue-200'
    if (state === 'queued' || state === 'pending') return 'border-yellow-700/50 bg-yellow-900/20 text-yellow-200'
    if (state === 'completed' || state === 'idle' || state === 'ok') return 'border-emerald-700/50 bg-emerald-900/20 text-emerald-200'
    if (state === 'failed' || state === 'unavailable') return 'border-red-700/50 bg-red-900/20 text-red-200'
    if (state === 'disabled' || state === 'cancelled') return 'border-gray-700 bg-gray-800 text-gray-300'
    return 'border-gray-700 bg-gray-900 text-gray-300'
}

const statusIcon = (state?: string) => {
    if (state === 'running') return Loader2
    if (state === 'queued' || state === 'pending') return Clock
    if (state === 'completed' || state === 'idle' || state === 'ok') return CheckCircle
    if (state === 'failed' || state === 'unavailable') return XCircle
    return AlertTriangle
}

onMounted(() => {
    loadStatus()
    pollTimer = setInterval(loadStatus, 5000)
})

onBeforeUnmount(() => {
    if (pollTimer) {
        clearInterval(pollTimer)
        pollTimer = null
    }
})
</script>

<template>
    <div class="w-full px-6 sm:px-8 py-6 space-y-5">
        <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
                <h2 class="text-2xl font-bold">Code Analysis</h2>
                <div class="mt-1 text-xs text-gray-500">
                    Updated {{ formatTimestamp(status?.updated_at) }}
                </div>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <button
                    type="button"
                    class="inline-flex h-8 items-center gap-2 rounded border border-gray-700 bg-gray-900 px-3 text-xs font-bold uppercase text-gray-200 transition-colors hover:bg-gray-800 disabled:cursor-wait disabled:opacity-50"
                    :disabled="loading"
                    @click="loadStatus"
                >
                    <RefreshCw :size="13" :class="{ 'animate-spin': loading }" />
                    Refresh
                </button>
                <span
                    class="inline-flex h-8 items-center gap-2 rounded border px-3 text-xs font-bold uppercase"
                    :class="stateClass(status?.overall_state)"
                >
                    <component
                        :is="statusIcon(status?.overall_state)"
                        :size="13"
                        :class="{ 'animate-spin': status?.overall_state === 'running' }"
                    />
                    {{ status?.overall_state || 'loading' }}
                </span>
            </div>
        </div>

        <div v-if="error || message" class="rounded border px-3 py-2 text-sm"
            :class="error ? 'border-red-800 bg-red-900/25 text-red-200' : 'border-emerald-800 bg-emerald-900/20 text-emerald-200'"
            role="status"
        >
            {{ error || message }}
        </div>

        <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <div class="rounded border border-gray-800 bg-gray-900/70 p-3">
                <div class="flex items-center justify-between text-[10px] font-bold uppercase tracking-widest text-gray-500">
                    <span>DTVP Worker</span>
                    <Zap :size="14" class="text-cyan-400" />
                </div>
                <div class="mt-3 text-2xl font-bold text-white">{{ status?.queue.dtvp_worker_busy ? 'Busy' : 'Idle' }}</div>
                <div class="mt-1 text-xs text-gray-500">
                    {{ dtvpAvailableSlots }} free of {{ status?.queue.capacity || 1 }}
                </div>
            </div>
            <div class="rounded border border-gray-800 bg-gray-900/70 p-3">
                <div class="flex items-center justify-between text-[10px] font-bold uppercase tracking-widest text-gray-500">
                    <span>Queue</span>
                    <Clock :size="14" class="text-yellow-400" />
                </div>
                <div class="mt-3 text-2xl font-bold text-white">{{ queuedCount }}</div>
                <div class="mt-1 text-xs text-gray-500">{{ status?.queue.waiting_for_slot ? 'waiting for slot' : 'no wait' }}</div>
            </div>
            <div class="rounded border border-gray-800 bg-gray-900/70 p-3">
                <div class="flex items-center justify-between text-[10px] font-bold uppercase tracking-widest text-gray-500">
                    <span>External</span>
                    <Server :size="14" class="text-blue-400" />
                </div>
                <div class="mt-3 text-2xl font-bold text-white">{{ status?.external.busy ? 'Busy' : status?.configured ? 'Ready' : 'Off' }}</div>
                <div class="mt-1 truncate text-xs text-gray-500">
                    <template v-if="analyzerCapacity !== null">{{ analyzerAvailableSlots ?? 0 }} analyzer slots free</template>
                    <template v-else>{{ status?.external.health_error || status?.external.jobs_error || 'healthy' }}</template>
                </div>
            </div>
            <div class="rounded border border-gray-800 bg-gray-900/70 p-3">
                <div class="flex items-center justify-between text-[10px] font-bold uppercase tracking-widest text-gray-500">
                    <span>Model</span>
                    <Activity :size="14" class="text-purple-400" />
                </div>
                <div class="mt-3 truncate text-xl font-bold text-white">{{ modelLabel }}</div>
                <div class="mt-1 text-xs text-gray-500">{{ status?.model_source || 'not_reported' }}</div>
            </div>
            <div class="rounded border border-gray-800 bg-gray-900/70 p-3">
                <div class="flex items-center justify-between text-[10px] font-bold uppercase tracking-widest text-gray-500">
                    <span>LLM Backend</span>
                    <Cpu :size="14" class="text-emerald-400" />
                </div>
                <div class="mt-3 truncate text-xl font-bold text-white">{{ llmBackendLabel }}</div>
                <div class="mt-1 truncate text-xs text-gray-500">
                    provider {{ status?.llm_provider_source || 'not_reported' }}, backend {{ status?.llm_backend_source || 'not_reported' }}
                </div>
            </div>
        </div>

        <div class="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
            <section class="space-y-4 xl:contents">
                <div class="rounded border border-gray-800 bg-gray-900/60 xl:col-span-2">
                    <div class="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
                        <div>
                            <h3 class="text-sm font-bold uppercase tracking-wider text-gray-200">DTVP Queue</h3>
                            <div class="mt-1 text-xs text-gray-500">
                                {{ runningCount }} running, {{ queuedCount }} queued, {{ terminalCount }} finished
                            </div>
                        </div>
                        <div class="flex flex-wrap items-center gap-2">
                            <button
                                type="button"
                                class="inline-flex h-8 items-center gap-2 rounded border border-yellow-700/50 bg-yellow-900/20 px-3 text-xs font-bold uppercase text-yellow-100 transition-colors hover:bg-yellow-900/35 disabled:cursor-not-allowed disabled:opacity-50"
                                :disabled="queuedCount === 0 || actionBusy === 'cancel-queued'"
                                @click="cancelQueued"
                            >
                                <Ban :size="13" />
                                Cancel queued
                            </button>
                            <button
                                type="button"
                                class="inline-flex h-8 items-center gap-2 rounded border border-gray-700 bg-gray-900 px-3 text-xs font-bold uppercase text-gray-200 transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-50"
                                :disabled="terminalCount === 0 || actionBusy === 'clear-finished'"
                                @click="clearFinished"
                            >
                                <Trash2 :size="13" />
                                Clear finished
                            </button>
                        </div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full text-left text-xs">
                            <thead class="border-b border-gray-800 text-[10px] uppercase tracking-widest text-gray-500">
                                <tr>
                                    <th class="px-4 py-2 font-semibold">State</th>
                                    <th class="px-4 py-2 font-semibold">Vulnerability</th>
                                    <th class="px-4 py-2 font-semibold">Component</th>
                                    <th class="px-4 py-2 font-semibold">Source</th>
                                    <th class="px-4 py-2 font-semibold">Progress</th>
                                    <th class="px-4 py-2 font-semibold">Submitted</th>
                                    <th class="px-4 py-2 text-right font-semibold">Action</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-800">
                                <tr v-if="queueItems.length === 0">
                                    <td colspan="7" class="px-4 py-8 text-center text-gray-500">No queue items</td>
                                </tr>
                                <template v-for="item in queueItems" :key="item.queue_id">
                                    <tr class="align-top">
                                        <td class="px-4 py-3">
                                            <span class="inline-flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] font-bold uppercase" :class="stateClass(item.status)">
                                                <component :is="statusIcon(item.status)" :size="11" :class="{ 'animate-spin': item.status === 'running' }" />
                                                {{ item.status }}
                                            </span>
                                            <div v-if="item.abort_requested" class="mt-1 text-[10px] text-yellow-300">abort requested</div>
                                            <div v-if="item.abort_error" class="mt-1 max-w-[180px] text-[10px] text-red-300">{{ item.abort_error }}</div>
                                            <div v-if="item.status === 'queued' && item.position" class="mt-1 text-[10px] text-yellow-300">#{{ item.position }}</div>
                                        </td>
                                        <td class="px-4 py-3 font-mono text-gray-200">{{ item.vuln_id }}</td>
                                        <td class="px-4 py-3">
                                            <div class="font-mono text-gray-300">{{ item.component_name }}</div>
                                            <div v-if="item.project_name" class="mt-1 truncate text-[10px] text-gray-500">{{ item.project_name }}</div>
                                        </td>
                                        <td class="px-4 py-3">
                                            <span class="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[10px] font-bold uppercase text-gray-300">{{ item.source || 'manual' }}</span>
                                        </td>
                                        <td class="px-4 py-3">
                                            <div v-if="item.progress" class="min-w-[160px]">
                                                <div class="flex items-center gap-2">
                                                    <div class="h-1.5 flex-1 overflow-hidden rounded bg-gray-800">
                                                        <div class="h-full rounded bg-cyan-400" :style="{ width: formatPercent(item.progress.percent) }"></div>
                                                    </div>
                                                    <span class="font-mono text-[10px] text-cyan-300">{{ formatPercent(item.progress.percent) }}</span>
                                                </div>
                                                <div class="mt-1 truncate text-[10px] text-gray-500">{{ item.progress.current_activity || item.progress.current_title }}</div>
                                            </div>
                                            <span v-else class="text-gray-600">-</span>
                                            <div v-if="queueLogEntries(item).length" class="mt-1 text-[10px] text-gray-500">{{ queueLogEntries(item).length }} log lines</div>
                                        </td>
                                        <td class="px-4 py-3 text-gray-500">{{ formatTimestamp(item.submitted_at) }}</td>
                                        <td class="px-4 py-3 text-right">
                                            <div class="flex flex-wrap justify-end gap-2">
                                                <router-link
                                                    :to="queueItemVulnRoute(item)"
                                                    class="inline-flex h-7 items-center gap-1 rounded border border-blue-700/50 bg-blue-900/20 px-2 text-[10px] font-bold uppercase text-blue-100 transition-colors hover:bg-blue-900/35"
                                                    :data-testid="`queue-open-vuln-${item.queue_id}`"
                                                >
                                                    <ExternalLink :size="12" />
                                                    Open vuln
                                                </router-link>
                                                <button
                                                    type="button"
                                                    class="inline-flex h-7 items-center gap-1 rounded border border-cyan-700/50 bg-cyan-900/20 px-2 text-[10px] font-bold uppercase text-cyan-100 transition-colors hover:bg-cyan-900/35"
                                                    :aria-expanded="isQueueLogExpanded(item.queue_id)"
                                                    :data-testid="`queue-log-toggle-${item.queue_id}`"
                                                    @click="toggleQueueLog(item.queue_id)"
                                                >
                                                    <Terminal :size="12" />
                                                    {{ isQueueLogExpanded(item.queue_id) ? 'Hide log' : 'Log' }}
                                                </button>
                                                <button
                                                    v-if="item.status === 'queued' || item.status === 'running'"
                                                    type="button"
                                                    class="inline-flex h-7 items-center gap-1 rounded border border-red-700/50 bg-red-900/20 px-2 text-[10px] font-bold uppercase text-red-100 transition-colors hover:bg-red-900/35 disabled:cursor-wait disabled:opacity-50"
                                                    :disabled="actionBusy === `cancel-${item.queue_id}`"
                                                    @click="cancelItem(item)"
                                                >
                                                    <Ban :size="12" />
                                                    {{ item.status === 'running' ? 'Abort' : 'Cancel' }}
                                                </button>
                                                <button
                                                    v-else
                                                    type="button"
                                                    class="inline-flex h-7 items-center gap-1 rounded border border-gray-700 bg-gray-900 px-2 text-[10px] font-bold uppercase text-gray-200 transition-colors hover:bg-gray-800 disabled:cursor-wait disabled:opacity-50"
                                                    :disabled="actionBusy === `cancel-${item.queue_id}`"
                                                    @click="cancelItem(item)"
                                                >
                                                    <Trash2 :size="12" />
                                                    Dismiss
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr v-if="isQueueLogExpanded(item.queue_id)" class="bg-gray-950/60">
                                        <td colspan="7" class="px-4 pb-4 pt-0">
                                            <div
                                                class="bg-gray-950/80 p-3"
                                                :data-testid="`queue-log-panel-${item.queue_id}`"
                                            >
                                                <div class="mb-2 flex flex-wrap items-center justify-between gap-2">
                                                    <div class="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-gray-300">
                                                        <Terminal :size="14" class="text-cyan-400" />
                                                        Scan Log
                                                    </div>
                                                    <div class="font-mono text-[10px] text-gray-500">
                                                        {{ item.component_name }} / {{ item.vuln_id }}
                                                    </div>
                                                </div>
                                                <div v-if="queueLogEntries(item).length === 0" class="px-3 py-5 text-center text-xs text-gray-500">
                                                    No log output reported yet
                                                </div>
                                                <div
                                                    v-else
                                                    :ref="(element) => setQueueLogScrollElement(item.queue_id, element as Element | null)"
                                                    class="max-h-[420px] overflow-auto"
                                                    :data-testid="`queue-log-scroll-${item.queue_id}`"
                                                >
                                                    <div class="min-w-[760px]">
                                                        <div class="grid grid-cols-[9rem_5rem_8rem_minmax(0,1fr)] gap-3 px-3 text-[10px] font-bold uppercase tracking-widest text-gray-500">
                                                            <div>Time</div>
                                                            <div>Level</div>
                                                            <div>Source</div>
                                                            <div>Message</div>
                                                        </div>
                                                        <div
                                                            v-for="entry in queueLogEntries(item)"
                                                            :key="entry.key"
                                                            class="grid grid-cols-[9rem_5rem_8rem_minmax(0,1fr)] gap-3 px-3 py-1.5 font-mono text-[11px] leading-relaxed"
                                                            :data-testid="`queue-log-entry-${item.queue_id}`"
                                                            :data-log-level="entry.level"
                                                        >
                                                            <div class="text-gray-400">{{ formatLogTimestamp(entry.timestamp) }}</div>
                                                            <div class="text-[10px] font-bold uppercase" :class="logLevelClass(entry.level)">{{ entry.levelLabel }}</div>
                                                            <div class="truncate text-gray-300">{{ entry.source }}</div>
                                                            <div class="whitespace-pre-wrap break-words" :class="logMessageClass(entry.level)">{{ entry.message }}</div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="rounded border border-gray-800 bg-gray-900/60">
                    <div class="border-b border-gray-800 px-4 py-3">
                        <h3 class="text-sm font-bold uppercase tracking-wider text-gray-200">Latest Results</h3>
                        <div class="mt-1 text-xs text-gray-500">{{ recentResults.length }} saved analysis runs</div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full text-left text-xs">
                            <thead class="border-b border-gray-800 text-[10px] uppercase tracking-widest text-gray-500">
                                <tr>
                                    <th class="px-4 py-2 font-semibold">Verdict</th>
                                    <th class="px-4 py-2 font-semibold">Vulnerability</th>
                                    <th class="px-4 py-2 font-semibold">Component</th>
                                    <th class="px-4 py-2 font-semibold">Source</th>
                                    <th class="px-4 py-2 font-semibold">Finished</th>
                                    <th class="px-4 py-2 text-right font-semibold">Action</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-800">
                                <tr v-if="recentResults.length === 0">
                                    <td colspan="6" class="px-4 py-8 text-center text-gray-500">No saved analysis results</td>
                                </tr>
                                <tr v-for="record in recentResults" :key="record.analysis_run_id" class="align-top">
                                    <td class="px-4 py-3">
                                        <span class="inline-flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] font-bold uppercase" :class="record.summary?.affected ? stateClass('failed') : stateClass('completed')">
                                            <component :is="record.summary?.affected ? AlertTriangle : CheckCircle" :size="11" />
                                            {{ record.summary?.verdict || record.status || 'saved' }}
                                        </span>
                                        <div v-if="record.summary?.confidence" class="mt-1 text-[10px] text-gray-500">{{ record.summary.confidence }} confidence</div>
                                    </td>
                                    <td class="px-4 py-3 font-mono text-gray-200">{{ record.vuln_id }}</td>
                                    <td class="px-4 py-3">
                                        <div class="font-mono text-gray-300">{{ record.component_name }}</div>
                                        <div v-if="record.project_name" class="mt-1 truncate text-[10px] text-gray-500">{{ record.project_name }}</div>
                                    </td>
                                    <td class="px-4 py-3">
                                        <span class="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[10px] font-bold uppercase text-gray-300">{{ record.source || 'manual' }}</span>
                                    </td>
                                    <td class="px-4 py-3 text-gray-500">{{ formatTimestamp(record.finished_at || record.recorded_at) }}</td>
                                    <td class="px-4 py-3 text-right">
                                        <router-link
                                            :to="resultVulnRoute(record)"
                                            class="inline-flex h-7 items-center gap-1 rounded border border-blue-700/50 bg-blue-900/20 px-2 text-[10px] font-bold uppercase text-blue-100 transition-colors hover:bg-blue-900/35"
                                            :data-testid="`result-open-vuln-${record.analysis_run_id}`"
                                        >
                                            <ExternalLink :size="12" />
                                            Open vuln
                                        </router-link>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="rounded border border-gray-800 bg-gray-900/60">
                    <div class="border-b border-gray-800 px-4 py-3">
                        <h3 class="text-sm font-bold uppercase tracking-wider text-gray-200">External Jobs</h3>
                        <div class="mt-1 text-xs text-gray-500">{{ externalJobs.length }} reported by API</div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full text-left text-xs">
                            <thead class="border-b border-gray-800 text-[10px] uppercase tracking-widest text-gray-500">
                                <tr>
                                    <th class="px-4 py-2 font-semibold">State</th>
                                    <th class="px-4 py-2 font-semibold">Job</th>
                                    <th class="px-4 py-2 font-semibold">Target</th>
                                    <th class="px-4 py-2 font-semibold">Progress</th>
                                    <th class="px-4 py-2 font-semibold">Created</th>
                                    <th class="px-4 py-2 font-semibold">Finished</th>
                                    <th class="px-4 py-2 font-semibold">Error</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-800">
                                <tr v-if="externalJobs.length === 0">
                                    <td colspan="7" class="px-4 py-8 text-center text-gray-500">{{ status?.external.jobs_error || 'No external jobs' }}</td>
                                </tr>
                                <tr v-for="job in externalJobs" :key="job.job_id" class="align-top">
                                    <td class="px-4 py-3">
                                        <span class="inline-flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] font-bold uppercase" :class="stateClass(job.status)">
                                            <component :is="statusIcon(job.status)" :size="11" :class="{ 'animate-spin': job.status === 'running' }" />
                                            {{ job.status }}
                                        </span>
                                    </td>
                                    <td class="px-4 py-3 font-mono text-gray-200">{{ job.job_id }}</td>
                                    <td class="px-4 py-3">
                                        <div class="font-mono text-gray-300">{{ job.request?.component_name || '-' }}</div>
                                        <div class="mt-1 font-mono text-[10px] text-gray-500">{{ job.request?.vuln_id || job.model || '' }}</div>
                                    </td>
                                    <td class="px-4 py-3">
                                        <div v-if="job.progress">
                                            <span class="text-cyan-300">{{ formatPercent(job.progress.percent) }}</span>
                                            <div class="mt-1 max-w-[220px] truncate text-[10px] text-gray-500">
                                                {{ job.progress.current_activity || job.progress.current_title }}
                                            </div>
                                        </div>
                                        <span v-else class="text-gray-600">-</span>
                                    </td>
                                    <td class="px-4 py-3 text-gray-500">{{ formatTimestamp(job.created_at) }}</td>
                                    <td class="px-4 py-3 text-gray-500">{{ formatTimestamp(job.finished_at) }}</td>
                                    <td class="px-4 py-3 text-red-300">{{ job.error || '' }}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <aside class="space-y-4">
                <div class="rounded border border-gray-800 bg-gray-900/60 p-4">
                    <div class="flex items-start justify-between gap-3">
                        <div class="min-w-0">
                            <h3 class="text-sm font-bold uppercase tracking-wider text-gray-200">Analyzer Configuration</h3>
                            <div class="mt-1 truncate text-xs text-gray-500">
                                {{ serviceName }} / {{ serviceVersion }}
                            </div>
                        </div>
                        <Settings2 :size="16" class="mt-0.5 shrink-0 text-blue-400" />
                    </div>
                    <dl class="mt-4 grid grid-cols-2 gap-3 text-xs">
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Components</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(repositoryConfiguration?.component_count) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Template</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(repositoryConfiguration?.default_template_configured) }}</dd>
                        </div>
                        <div class="col-span-2">
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Config dir</dt>
                            <dd class="mt-1 break-all font-mono text-[11px] text-gray-300">{{ formatDisplayValue(serviceConfiguration?.config_dir) }}</dd>
                        </div>
                        <div class="col-span-2">
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Repos config</dt>
                            <dd class="mt-1 break-all font-mono text-[11px] text-gray-300">{{ formatDisplayValue(serviceConfiguration?.repos_config_path) }}</dd>
                        </div>
                        <div class="col-span-2">
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Workspace</dt>
                            <dd class="mt-1 break-all font-mono text-[11px] text-gray-300">{{ formatDisplayValue(repositoryConfiguration?.workspace_dir) }}</dd>
                        </div>
                    </dl>
                    <div v-if="featureEntries.length" class="mt-3 flex flex-wrap gap-1.5">
                        <span
                            v-for="entry in featureEntries"
                            :key="entry[0]"
                            class="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[10px] text-gray-300"
                        >
                            {{ formatLabel(entry[0]) }}: {{ formatDisplayValue(entry[1]) }}
                        </span>
                    </div>
                    <div v-if="!serviceConfiguration" class="mt-3 rounded border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-gray-500">
                        No analyzer configuration reported
                    </div>
                </div>

                <div class="rounded border border-gray-800 bg-gray-900/60 p-4">
                    <div class="flex items-start justify-between gap-3">
                        <div class="min-w-0">
                            <h3 class="text-sm font-bold uppercase tracking-wider text-gray-200">Analyzer Backend</h3>
                            <div class="mt-1 truncate text-xs text-gray-500">
                                {{ formatDisplayValue(llmInfo?.provider || status?.llm_provider) }}
                            </div>
                        </div>
                        <HardDrive :size="16" class="mt-0.5 shrink-0 text-emerald-400" />
                    </div>
                    <dl class="mt-4 grid grid-cols-2 gap-3 text-xs">
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">LLM Backend</dt>
                            <dd class="mt-1 truncate text-gray-300">{{ formatDisplayValue(llmInfo?.backend || status?.llm_backend) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Healthy</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(llmInfo?.healthy) }}</dd>
                        </div>
                        <div class="col-span-2">
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Host</dt>
                            <dd class="mt-1 break-all font-mono text-[11px] text-gray-300">{{ formatDisplayValue(llmInfo?.host) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Model</dt>
                            <dd class="mt-1 truncate text-gray-300">{{ modelLabel }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Override</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(llmInfo?.supports_model_override) }}</dd>
                        </div>
                        <div class="col-span-2">
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Repository backend</dt>
                            <dd class="mt-1 break-all font-mono text-[11px] text-gray-300">{{ formatDisplayValue(repositoryBackend?.workspace_dir) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Reuse</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(repositoryBackend?.reuse_strategy) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Update</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(repositoryBackend?.update_strategy) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Job store</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(jobsBackend?.job_store) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Known jobs</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(jobsBackend?.known_jobs) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Capacity</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(analyzerCapacity) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Slots free</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(analyzerAvailableSlots) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Running jobs</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(analyzerRunningJobs) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Queued jobs</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(analyzerQueuedJobs) }}</dd>
                        </div>
                    </dl>
                    <div v-if="statusCountEntries.length" class="mt-3 flex flex-wrap gap-1.5">
                        <span
                            v-for="entry in statusCountEntries"
                            :key="entry[0]"
                            class="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[10px] text-gray-300"
                        >
                            {{ formatLabel(entry[0]) }}: {{ entry[1] }}
                        </span>
                    </div>
                    <div v-if="llmInfo?.last_error" class="mt-3 rounded border border-red-800 bg-red-900/20 px-3 py-2 text-xs text-red-200">
                        {{ llmInfo.last_error }}
                    </div>
                    <div v-if="!backendInformation" class="mt-3 rounded border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-gray-500">
                        No backend information reported
                    </div>
                </div>

                <div class="rounded border border-gray-800 bg-gray-900/60 p-4">
                    <div class="flex items-start justify-between gap-3">
                        <div class="min-w-0">
                            <h3 class="text-sm font-bold uppercase tracking-wider text-gray-200">Result Cache</h3>
                            <div class="mt-1 truncate text-xs text-gray-500">
                                {{ resultCache ? `${resultCache.record_count ?? 0} saved runs` : 'not reported' }}
                            </div>
                        </div>
                        <HardDrive :size="16" class="mt-0.5 shrink-0 text-cyan-400" />
                    </div>
                    <dl class="mt-4 grid grid-cols-2 gap-3 text-xs">
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Max records</dt>
                            <dd class="mt-1 text-gray-300">{{ formatDisplayValue(resultCache?.max_records) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Retention</dt>
                            <dd class="mt-1 text-gray-300">{{ resultCache?.retention_days ? `${resultCache.retention_days} days` : 'unlimited' }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Freshness</dt>
                            <dd class="mt-1 text-gray-300">{{ resultCache?.freshness_days ? `${resultCache.freshness_days} days` : 'fingerprint only' }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Guidance</dt>
                            <dd class="mt-1 text-gray-300">{{ resultCache?.store_guidance === false ? 'redacted' : 'stored' }}</dd>
                        </div>
                        <div class="col-span-2">
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Path</dt>
                            <dd class="mt-1 break-all font-mono text-[11px] text-gray-300">{{ formatDisplayValue(resultCache?.path) }}</dd>
                        </div>
                    </dl>
                </div>

                <div class="rounded border border-gray-800 bg-gray-900/60 p-4">
                    <div class="flex items-start justify-between gap-3">
                        <div>
                            <h3 class="text-sm font-bold uppercase tracking-wider text-gray-200">Automatic Sweep</h3>
                            <div class="mt-1 text-xs text-gray-500">
                                {{ status?.auto_sweep.active ? 'active' : status?.auto_sweep.enabled ? 'not configured' : 'disabled' }}
                            </div>
                        </div>
                        <button
                            type="button"
                            class="inline-flex h-8 items-center gap-2 rounded border border-cyan-700/50 bg-cyan-900/20 px-3 text-xs font-bold uppercase text-cyan-100 transition-colors hover:bg-cyan-900/35 disabled:cursor-not-allowed disabled:opacity-50"
                            :disabled="!canRunSweep"
                            @click="runSweep"
                        >
                            <RefreshCw :size="13" :class="{ 'animate-spin': actionBusy === 'sweep' || status?.auto_sweep.running }" />
                            Run now
                        </button>
                    </div>
                    <dl class="mt-4 grid grid-cols-2 gap-3 text-xs">
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Last started</dt>
                            <dd class="mt-1 text-gray-300">{{ formatTimestamp(status?.auto_sweep.last_started_at) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Last finished</dt>
                            <dd class="mt-1 text-gray-300">{{ formatTimestamp(status?.auto_sweep.last_finished_at) }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Last queued</dt>
                            <dd class="mt-1 text-gray-300">{{ status?.auto_sweep.last_queued_count ?? '-' }}</dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Next run</dt>
                            <dd class="mt-1 text-gray-300">{{ formatTimestamp(status?.auto_sweep.next_run_at) }}</dd>
                        </div>
                    </dl>
                    <div v-if="status?.auto_sweep.last_error" class="mt-3 rounded border border-red-800 bg-red-900/20 px-3 py-2 text-xs text-red-200">
                        {{ status.auto_sweep.last_error }}
                    </div>
                </div>

                <div class="rounded border border-gray-800 bg-gray-900/60 p-4">
                    <h3 class="text-sm font-bold uppercase tracking-wider text-gray-200">Active Agents</h3>
                    <div v-if="activeAgents.length === 0" class="mt-4 text-xs text-gray-500">No active agents</div>
                    <div v-else class="mt-4 space-y-2">
                        <div
                            v-for="agent in activeAgents"
                            :key="`${agent.step}-${agent.agent}`"
                            class="rounded border border-gray-800 bg-gray-950/60 px-3 py-2"
                        >
                            <div class="flex items-center justify-between gap-3">
                                <span class="truncate text-xs font-bold text-gray-200">{{ agent.title || agent.step }}</span>
                                <span class="shrink-0 rounded border border-blue-700/40 bg-blue-900/20 px-2 py-0.5 text-[10px] font-bold uppercase text-blue-200">{{ agent.status }}</span>
                            </div>
                            <div class="mt-1 truncate text-[10px] text-gray-500">{{ agent.agent }}</div>
                            <div v-if="agent.activity" class="mt-1 text-xs text-gray-400">{{ agent.activity }}</div>
                        </div>
                    </div>
                </div>
            </aside>
        </div>
    </div>
</template>
