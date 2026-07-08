<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick, watch, computed } from 'vue'
import { Zap, X, Loader2, CheckCircle, XCircle, Clock, ChevronDown, ChevronUp, AlertTriangle, Activity, RefreshCw } from 'lucide-vue-next'
import { analysisQueueStore } from '../lib/analysisQueueStore'
import {
    codeAnalysisGetAutoSweepStatus,
    codeAnalysisRunAutoSweep,
    type CodeAnalysisAssessResponse,
    type CodeAnalysisAutoSweepStatus,
} from '../lib/api'

const open = ref(false)
const expandedItem = ref<string | null>(null)
const expandedResult = ref<CodeAnalysisAssessResponse | null>(null)
const loadingResult = ref(false)
const sweepStatus = ref<CodeAnalysisAutoSweepStatus | null>(null)
const sweepStatusLoading = ref(false)
const sweepRunLoading = ref(false)
const sweepError = ref<string | null>(null)
const triggerRef = ref<HTMLElement | null>(null)
const panelRef = ref<HTMLElement | null>(null)
const panelStyle = ref<Record<string, string>>({})
const PANEL_WIDTH = 384
const PANEL_MARGIN = 8
const PANEL_GAP = 8
const PANEL_Z_INDEX = '12000'
let sweepStatusTimer: ReturnType<typeof setInterval> | null = null

const updatePanelPosition = () => {
    const trigger = triggerRef.value
    if (!trigger || typeof window === 'undefined') return

    const rect = trigger.getBoundingClientRect()
    const viewportWidth = window.innerWidth
    const viewportHeight = window.innerHeight
    const width = Math.min(PANEL_WIDTH, viewportWidth - PANEL_MARGIN * 2)
    const maxLeft = viewportWidth - width - PANEL_MARGIN
    const left = Math.min(Math.max(PANEL_MARGIN, rect.left), maxLeft)
    const availableBelow = Math.max(120, viewportHeight - rect.bottom - PANEL_GAP - PANEL_MARGIN)
    const availableAbove = Math.max(120, rect.top - PANEL_GAP - PANEL_MARGIN)
    const placeAbove = availableBelow < 260 && availableAbove > availableBelow
    const maxHeight = Math.min(384, placeAbove ? availableAbove : availableBelow)

    panelStyle.value = {
        position: 'fixed',
        left: `${left}px`,
        width: `${width}px`,
        maxHeight: `${maxHeight}px`,
        zIndex: PANEL_Z_INDEX,
        ...(placeAbove
            ? { bottom: `${Math.max(PANEL_MARGIN, viewportHeight - rect.top + PANEL_GAP)}px` }
            : { top: `${Math.min(viewportHeight - maxHeight - PANEL_MARGIN, rect.bottom + PANEL_GAP)}px` }),
    }
}

const toggle = () => {
    open.value = !open.value
    if (!open.value) {
        expandedItem.value = null
        expandedResult.value = null
    } else {
        nextTick(updatePanelPosition)
    }
}

const close = () => {
    open.value = false
    expandedItem.value = null
    expandedResult.value = null
}

const isInsideQueuePopup = (target: Node | null) => (
    Boolean(target && (triggerRef.value?.contains(target) || panelRef.value?.contains(target)))
)

const toggleItemResult = async (queueId: string, status: string) => {
    if (status !== 'completed') return

    if (expandedItem.value === queueId) {
        expandedItem.value = null
        expandedResult.value = null
        return
    }

    expandedItem.value = queueId
    expandedResult.value = null

    // Check cache first
    const cached = analysisQueueStore.getCachedResult(queueId)
    if (cached) {
        expandedResult.value = cached
        return
    }

    // Fetch from backend
    loadingResult.value = true
    try {
        const result = await analysisQueueStore.fetchResult(queueId)
        if (result) expandedResult.value = result
    } finally {
        loadingResult.value = false
    }
}

const statusIcon = (status: string) => {
    if (status === 'running') return Loader2
    if (status === 'completed') return CheckCircle
    if (status === 'failed') return XCircle
    return Clock
}

const statusColor = (status: string) => {
    if (status === 'running') return 'text-blue-400'
    if (status === 'completed') return 'text-green-400'
    if (status === 'failed') return 'text-red-400'
    if (status === 'cancelled') return 'text-gray-500'
    return 'text-yellow-400'
}

const formatDuration = (seconds?: number | null) => {
    if (!seconds) return 'unknown'
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    if (minutes && remainingSeconds) return `${minutes}m ${remainingSeconds}s`
    if (minutes) return `${minutes}m`
    return `${remainingSeconds}s`
}

const formatTimestamp = (value?: string | null) => {
    if (!value) return 'never'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return 'unknown'
    return date.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    })
}

const formatRelativeTimestamp = (value?: string | null) => {
    if (!value) return 'not scheduled'
    const timestamp = Date.parse(value)
    if (Number.isNaN(timestamp)) return 'unknown'
    const deltaSeconds = Math.ceil((timestamp - Date.now()) / 1000)
    if (deltaSeconds <= 0) return 'due now'
    return `in ${formatDuration(deltaSeconds)}`
}

const sweepStatusLabel = computed(() => {
    if (!sweepStatus.value) return sweepStatusLoading.value ? 'Loading' : 'Unknown'
    if (sweepStatus.value.running) return 'Running'
    if (sweepStatus.value.active) return 'Active'
    if (!sweepStatus.value.enabled) return 'Disabled'
    if (!sweepStatus.value.code_analysis_configured) return 'Not configured'
    return 'Inactive'
})

const sweepStatusClass = computed(() => {
    if (sweepStatus.value?.running) return 'bg-blue-900/30 text-blue-300 border-blue-700/40'
    if (sweepStatus.value?.active) return 'bg-emerald-900/30 text-emerald-300 border-emerald-700/40'
    return 'bg-gray-800 text-gray-400 border-gray-700/60'
})

const canRunSweepNow = computed(() =>
    Boolean(sweepStatus.value?.active && !sweepStatus.value.running && !sweepRunLoading.value)
)

const refreshSweepStatus = async () => {
    sweepStatusLoading.value = true
    try {
        sweepStatus.value = await codeAnalysisGetAutoSweepStatus()
        sweepError.value = sweepStatus.value.last_error || null
    } catch (error: any) {
        sweepError.value = error?.message || 'Unable to load automatic sweep status.'
    } finally {
        sweepStatusLoading.value = false
    }
}

const runSweepNow = async () => {
    if (!canRunSweepNow.value) return
    sweepRunLoading.value = true
    sweepError.value = null
    try {
        sweepStatus.value = await codeAnalysisRunAutoSweep()
        sweepError.value = sweepStatus.value.last_error || null
        await analysisQueueStore.refresh()
    } catch (error: any) {
        sweepError.value = error?.message || 'Unable to run automatic sweep.'
    } finally {
        sweepRunLoading.value = false
    }
}

const handleDocumentPointerdown = (event: PointerEvent) => {
    if (!open.value) return
    if (isInsideQueuePopup(event.target as Node | null)) return
    close()
}

onMounted(() => {
    analysisQueueStore.startPolling()
    refreshSweepStatus()
    sweepStatusTimer = setInterval(refreshSweepStatus, 10000)
    window.addEventListener('resize', updatePanelPosition)
    window.addEventListener('scroll', updatePanelPosition, true)
    window.visualViewport?.addEventListener('resize', updatePanelPosition)
    document.addEventListener('pointerdown', handleDocumentPointerdown)
})

onUnmounted(() => {
    analysisQueueStore.stopPolling()
    if (sweepStatusTimer) {
        clearInterval(sweepStatusTimer)
        sweepStatusTimer = null
    }
    window.removeEventListener('resize', updatePanelPosition)
    window.removeEventListener('scroll', updatePanelPosition, true)
    window.visualViewport?.removeEventListener('resize', updatePanelPosition)
    document.removeEventListener('pointerdown', handleDocumentPointerdown)
})

watch(open, (isOpen) => {
    if (isOpen) {
        refreshSweepStatus()
        nextTick(updatePanelPosition)
    }
})

</script>

<template>
    <div class="relative">
        <button
            ref="triggerRef"
            type="button"
            @click="toggle"
            class="relative h-8 px-2.5 inline-flex items-center justify-center gap-1.5 rounded-full border border-white/10 transition-all cursor-pointer"
            :class="analysisQueueStore.hasActivity.value
                ? 'bg-cyan-600/20 text-cyan-300 hover:bg-cyan-600/30 border-cyan-500/40'
                : 'bg-slate-950/20 text-slate-400 hover:bg-slate-950/30 hover:text-slate-200'"
            title="Automatic sweep and analysis queue"
            data-testid="analysis-queue-trigger"
        >
            <Zap :size="14" />
            <span class="text-[10px] font-semibold uppercase tracking-wider">Auto sweep</span>
            <span
                v-if="analysisQueueStore.activeCount.value > 0"
                class="absolute -top-1 -right-1 min-w-[16px] h-4 flex items-center justify-center rounded-full bg-cyan-500 text-[9px] font-bold text-white px-1"
            >
                {{ analysisQueueStore.activeCount.value }}
            </span>
            <span
                v-if="analysisQueueStore.runningItem.value"
                class="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse border border-gray-800"
            ></span>
        </button>

        <!-- Dropdown panel -->
        <Teleport to="body">
            <div
                ref="panelRef"
                v-if="open"
                class="rounded-lg border border-gray-700 bg-gray-900 shadow-2xl overflow-hidden flex flex-col"
                :style="panelStyle"
                data-testid="analysis-queue-panel"
            >
            <div class="flex items-center justify-between p-3 border-b border-gray-700/50">
                <h3 class="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
                    <Zap :size="12" />
                    Analysis Queue
                </h3>
                <button @click="close" class="text-gray-500 hover:text-gray-300 cursor-pointer">
                    <X :size="14" />
                </button>
            </div>

            <div class="p-3 border-b border-gray-700/50 bg-gray-950/40 space-y-2">
                <div class="flex items-center justify-between gap-3">
                    <div class="min-w-0">
                        <div class="flex items-center gap-2">
                            <span class="text-[10px] font-bold uppercase tracking-wider text-gray-400">Automatic sweep</span>
                            <span
                                class="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded border"
                                :class="sweepStatusClass"
                            >
                                {{ sweepStatusLabel }}
                            </span>
                        </div>
                        <div class="mt-1 text-[10px] text-gray-500">
                            Next {{ formatRelativeTimestamp(sweepStatus?.next_run_at) }}
                            <span class="text-gray-700">·</span>
                            every {{ formatDuration(sweepStatus?.interval_seconds) }}
                        </div>
                    </div>
                    <button
                        type="button"
                        class="h-7 shrink-0 inline-flex items-center gap-1.5 rounded border px-2 text-[10px] font-semibold uppercase transition-colors disabled:cursor-not-allowed disabled:opacity-50"
                        :class="canRunSweepNow
                            ? 'border-cyan-700/50 bg-cyan-600/15 text-cyan-300 hover:bg-cyan-600/25'
                            : 'border-gray-700 bg-gray-800 text-gray-500'"
                        :disabled="!canRunSweepNow"
                        @click="runSweepNow"
                    >
                        <RefreshCw :size="11" :class="{ 'animate-spin': sweepRunLoading || sweepStatus?.running }" />
                        Run now
                    </button>
                </div>
                <div class="flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] text-gray-500">
                    <span>Last {{ formatTimestamp(sweepStatus?.last_finished_at) }}</span>
                    <span v-if="sweepStatus?.last_queued_count !== null && sweepStatus?.last_queued_count !== undefined">
                        queued {{ sweepStatus?.last_queued_count }}
                    </span>
                    <span v-if="sweepStatus?.last_trigger">via {{ sweepStatus?.last_trigger }}</span>
                </div>
                <div v-if="sweepError" class="text-[10px] text-red-400">
                    {{ sweepError }}
                </div>
            </div>

            <div class="p-3 border-b border-gray-700/50 bg-gray-950/20">
                <RouterLink
                    to="/code-analysis"
                    class="flex h-8 items-center justify-center rounded border border-cyan-700/40 bg-cyan-600/10 text-[10px] font-bold uppercase tracking-wider text-cyan-200 transition-colors hover:bg-cyan-600/20"
                    @click="close"
                >
                    Open Code Analysis Dashboard
                </RouterLink>
            </div>

            <div v-if="analysisQueueStore.items.value.length === 0" class="p-4 text-center text-xs text-gray-500">
                No analyses in queue
            </div>

            <div v-else class="min-h-0 overflow-y-auto divide-y divide-gray-800">
                <div
                    v-for="item in analysisQueueStore.items.value"
                    :key="item.queue_id"
                    class="transition-colors"
                    :class="item.status === 'completed' ? 'cursor-pointer hover:bg-gray-800/50' : 'hover:bg-gray-800/50'"
                    @click="toggleItemResult(item.queue_id, item.status)"
                >
                    <div class="p-3">
                        <div class="flex items-start justify-between gap-2">
                            <div class="flex items-center gap-2 min-w-0">
                                <component
                                    :is="statusIcon(item.status)"
                                    :size="14"
                                    :class="[statusColor(item.status), item.status === 'running' ? 'animate-spin' : '']"
                                    class="shrink-0"
                                />
                                <div class="min-w-0">
                                    <div class="text-xs font-mono text-gray-200 truncate">{{ item.vuln_id }}</div>
                                    <div class="text-[10px] text-gray-500 truncate">{{ item.component_name }}</div>
                                </div>
                            </div>
                            <div class="flex items-center gap-2 shrink-0">
                                <span
                                    v-if="item.source === 'automatic'"
                                    class="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded bg-cyan-900/30 text-cyan-300 border border-cyan-700/30"
                                >
                                    Auto
                                </span>
                                <span
                                    v-if="item.status === 'queued'"
                                    class="text-[9px] font-bold text-yellow-400 bg-yellow-900/30 px-1.5 py-0.5 rounded"
                                >
                                    #{{ item.position }}
                                </span>
                                <span
                                    class="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded"
                                    :class="{
                                        'text-yellow-300 bg-yellow-900/30': item.status === 'queued',
                                        'text-blue-300 bg-blue-900/30': item.status === 'running',
                                        'text-green-300 bg-green-900/30': item.status === 'completed',
                                        'text-red-300 bg-red-900/30': item.status === 'failed',
                                        'text-gray-400 bg-gray-800': item.status === 'cancelled',
                                    }"
                                >
                                    {{ item.status }}
                                </span>
                                <component
                                    v-if="item.status === 'completed'"
                                    :is="expandedItem === item.queue_id ? ChevronUp : ChevronDown"
                                    :size="12"
                                    class="text-gray-500"
                                />
                                <button
                                    v-if="item.status === 'queued'"
                                    @click.stop="analysisQueueStore.cancel(item.queue_id)"
                                    class="text-gray-600 hover:text-red-400 cursor-pointer"
                                    title="Cancel"
                                >
                                    <X :size="12" />
                                </button>
                                <button
                                    v-if="item.status === 'completed' || item.status === 'failed' || item.status === 'cancelled'"
                                    @click.stop="analysisQueueStore.dismiss(item.queue_id)"
                                    class="text-gray-600 hover:text-gray-300 cursor-pointer"
                                    title="Dismiss"
                                >
                                    <X :size="12" />
                                </button>
                            </div>
                        </div>
                        <div v-if="item.error" class="mt-1 text-[10px] text-red-400 truncate">
                            {{ item.error }}
                        </div>
                        <!-- Progress display for running items -->
                        <div v-if="item.status === 'running' && item.progress" class="mt-1.5 space-y-1">
                            <!-- Progress bar -->
                            <div class="flex items-center gap-2">
                                <div class="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                                    <div
                                        class="h-full bg-cyan-500 rounded-full transition-all duration-500"
                                        :style="{ width: item.progress.percent + '%' }"
                                    ></div>
                                </div>
                                <span class="text-[9px] font-mono text-cyan-400 shrink-0">{{ item.progress.percent }}%</span>
                            </div>
                            <!-- Current activity -->
                            <div v-if="item.progress.current_activity" class="flex items-center gap-1.5 text-[10px] text-gray-400">
                                <Activity :size="10" class="text-cyan-500 shrink-0" />
                                <span class="truncate">{{ item.progress.current_activity }}</span>
                            </div>
                            <!-- Current step title -->
                            <div v-else-if="item.progress.current_title" class="flex items-center gap-1.5 text-[10px] text-gray-400">
                                <Activity :size="10" class="text-cyan-500 shrink-0" />
                                <span class="truncate">{{ item.progress.current_title }}</span>
                            </div>
                            <!-- Step count -->
                            <div class="text-[9px] text-gray-600">
                                Step {{ item.progress.completed_steps }}/{{ item.progress.total_steps }}
                                <span v-if="item.progress.current_step" class="text-gray-500 ml-1">({{ item.progress.current_step }})</span>
                            </div>
                            <!-- Active agents (parallel work) -->
                            <div v-if="item.progress.active_agents && item.progress.active_agents.length > 1" class="mt-1 space-y-0.5">
                                <div
                                    v-for="agent in item.progress.active_agents"
                                    :key="agent.step"
                                    class="flex items-center gap-1.5 text-[9px] text-gray-500"
                                >
                                    <span class="w-1.5 h-1.5 rounded-full shrink-0" :class="{
                                        'bg-blue-400 animate-pulse': agent.status === 'running',
                                        'bg-green-400': agent.status === 'completed',
                                        'bg-gray-500': agent.status !== 'running' && agent.status !== 'completed',
                                    }"></span>
                                    <span class="truncate">{{ agent.title }}: {{ agent.activity }}</span>
                                </div>
                            </div>
                        </div>
                        <!-- Pending status for running items without progress -->
                        <div v-else-if="item.status === 'running' && !item.progress" class="mt-1.5">
                            <div class="flex items-center gap-2">
                                <div class="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                                    <div class="h-full bg-cyan-500/50 rounded-full animate-pulse w-1/3"></div>
                                </div>
                                <span class="text-[9px] text-gray-500">Starting…</span>
                            </div>
                        </div>
                        <div class="mt-1 text-[10px] text-gray-600">
                            by {{ item.submitted_by }}
                        </div>
                    </div>

                    <!-- Expanded result view -->
                    <div
                        v-if="expandedItem === item.queue_id && item.status === 'completed'"
                        class="px-3 pb-3 border-t border-gray-700/30"
                    >
                        <div v-if="loadingResult" class="py-3 text-center">
                            <Loader2 :size="14" class="inline animate-spin text-cyan-400" />
                            <span class="text-[10px] text-gray-500 ml-2">Loading result…</span>
                        </div>
                        <div v-else-if="expandedResult" class="pt-2 space-y-2">
                            <!-- Verdict -->
                            <div class="flex items-center gap-2 p-2 rounded border" :class="{
                                'bg-red-900/20 border-red-700/40': expandedResult.assessment.affected,
                                'bg-green-900/20 border-green-700/40': !expandedResult.assessment.affected,
                            }">
                                <component
                                    :is="expandedResult.assessment.affected ? AlertTriangle : CheckCircle"
                                    :size="14"
                                    :class="expandedResult.assessment.affected ? 'text-red-400' : 'text-green-400'"
                                />
                                <span class="text-xs font-bold" :class="expandedResult.assessment.affected ? 'text-red-400' : 'text-green-400'">
                                    {{ expandedResult.assessment.verdict }}
                                </span>
                                <span class="text-[9px] px-1.5 py-0.5 rounded border ml-auto" :class="{
                                    'bg-green-700/30 text-green-300 border-green-600/40': expandedResult.assessment.confidence.toLowerCase() === 'high',
                                    'bg-yellow-700/30 text-yellow-300 border-yellow-600/40': expandedResult.assessment.confidence.toLowerCase() === 'medium',
                                    'bg-gray-700/30 text-gray-300 border-gray-600/40': expandedResult.assessment.confidence.toLowerCase() === 'low',
                                }">
                                    {{ expandedResult.assessment.confidence }}
                                </span>
                            </div>
                            <!-- Summary -->
                            <div class="text-[10px] text-gray-300 leading-relaxed">{{ expandedResult.assessment.summary }}</div>
                            <div v-if="expandedResult.versions_checked?.length" class="space-y-1">
                                <div class="text-[9px] font-semibold uppercase text-gray-500">Versions Checked</div>
                                <ul class="text-[10px] text-gray-400 list-disc list-inside space-y-0.5">
                                    <li v-for="version in expandedResult.versions_checked" :key="version">{{ version }}</li>
                                </ul>
                            </div>
                            <!-- CVSS adjustment -->
                            <div v-if="expandedResult.assessment.adjusted_cvss" class="flex items-center gap-2 text-[10px]">
                                <span class="text-gray-500">CVSS</span>
                                <span class="font-mono font-bold text-yellow-400">{{ expandedResult.assessment.adjusted_cvss.original_score }}</span>
                                <span class="text-gray-600">→</span>
                                <span class="font-mono font-bold text-purple-400">{{ expandedResult.assessment.adjusted_cvss.adjusted_score }}</span>
                            </div>
                        </div>
                        <div v-else class="py-2 text-[10px] text-gray-500 text-center">
                            Result not available
                        </div>
                    </div>
                </div>
            </div>
            </div>
        </Teleport>
    </div>
</template>
