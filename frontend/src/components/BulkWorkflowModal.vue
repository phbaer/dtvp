<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { AlertTriangle, CheckCircle, Copy, Download, ExternalLink, Layers, Loader2, X } from 'lucide-vue-next'
import {
    applyBulkWorkflow,
    buildBulkWorkflowDocument,
    bulkWorkflowFilters,
    getBulkWorkflowSummary,
    previewBulkWorkflow,
    type BulkWorkflowApplyResponse,
    type BulkWorkflowFilters,
    type BulkWorkflowPreviewItem,
    type BulkWorkflowPreviewResponse,
    type BulkWorkflowSummaryItem,
    type BulkWorkflowTaskStatus,
    type RescoreRuleSyncPreviewFinding,
    type TaskVulnGroupListQuery,
} from '../lib/api'
import { getRuntimeConfig } from '../lib/env'

const props = withDefaults(defineProps<{
    show: boolean
    taskId: string | null
    query?: TaskVulnGroupListQuery
}>(), {
    query: () => ({}),
})

const emit = defineEmits<{
    close: []
    applied: [result: BulkWorkflowApplyResponse]
}>()

const loading = ref(false)
const processing = ref(false)
const error = ref('')
const workflows = ref<BulkWorkflowSummaryItem[]>([])
const selectedWorkflowId = ref('')
const preview = ref<BulkWorkflowPreviewResponse | null>(null)
const selectedIds = ref<Set<string>>(new Set())
const appliedResult = ref<BulkWorkflowApplyResponse | null>(null)
const activeFilters = ref<BulkWorkflowFilters>({})
const documentLoading = ref(false)
const operationMessage = ref('')
const operationProgress = ref(0)
const ticketCopyState = ref<Record<string, 'copied' | 'error'>>({})
const jiraCreateUrl = getRuntimeConfig('DTVP_JIRA_CREATE_URL', '').trim()
const previewCache = new Map<string, BulkWorkflowPreviewResponse>()
let previewRequestId = 0

const selectedWorkflow = computed(() =>
    workflows.value.find(workflow => workflow.id === selectedWorkflowId.value) || null
)
const selectableIds = computed(() => preview.value?.selectable_group_ids || [])
const allSelected = computed(() =>
    selectableIds.value.length > 0
    && selectableIds.value.every(groupId => selectedIds.value.has(groupId))
)
const selectedFindingCount = computed(() =>
    (preview.value?.items || [])
        .filter(item => selectedIds.value.has(item.group_id))
        .reduce((total, item) => total + Number(
            item.eligible_finding_count
            || item.finding_count
            || item.recoverable_finding_count
            || item.syncable_finding_count
            || 0
        ), 0)
)
const activeFilterCount = computed(() => Object.values(activeFilters.value).filter(value =>
    Array.isArray(value) ? value.length > 0 : value !== '' && value != null && value !== false
).length)

const itemSelectable = (item: BulkWorkflowPreviewItem) =>
    selectableIds.value.includes(item.group_id)

const firstRescoreRuleFinding = (item: BulkWorkflowPreviewItem) => {
    const findings = Array.isArray(item.findings)
        ? item.findings as RescoreRuleSyncPreviewFinding[]
        : []
    return findings.find(finding => finding.status === 'ready') || findings[0]
}

const formatCvssScore = (score: number | null | undefined) =>
    score == null ? '—' : Number(score).toFixed(1)

const updateOperationStatus = (status: BulkWorkflowTaskStatus) => {
    operationMessage.value = status.message || ''
    operationProgress.value = Number(status.progress || 0)
}

const itemStatus = (item: BulkWorkflowPreviewItem) => {
    if (selectedWorkflowId.value === 'automatic-assessments') {
        const verdict = String(item.verdict_bucket || 'INCONCLUSIVE')
        return verdict === 'INCONCLUSIVE' ? 'UNCERTAIN' : verdict.replaceAll('_', ' ')
    }
    if (selectedWorkflowId.value === 'incomplete-sync') return item.target_state || 'Ready'
    if (selectedWorkflowId.value === 'assessment-restore') {
        return item.recoverable_finding_count > 0 ? 'Ready' : (item.status || 'Review')
    }
    if (selectedWorkflowId.value === 'rescore-rule-sync') {
        return item.syncable_finding_count > 0 ? 'Ready' : 'Manual review'
    }
    return item.status || 'Ready'
}

const itemDetail = (item: BulkWorkflowPreviewItem) => {
    if (selectedWorkflowId.value === 'automatic-assessments') {
        const runCount = (item.run_ids || []).length
        const replaced = Number(item.preexisting_finding_count || 0)
        return `${item.eligible_finding_count || 0} ready · ${runCount} analysis run${runCount === 1 ? '' : 's'}${replaced ? ` · ${replaced} existing assessment${replaced === 1 ? '' : 's'} will be replaced` : ''}`
    }
    if (selectedWorkflowId.value === 'incomplete-sync') {
        return `${item.finding_count || 0} findings · ${item.block_count || 0} assessment blocks`
    }
    if (selectedWorkflowId.value === 'assessment-restore') {
        return `${item.recoverable_finding_count || 0} recoverable of ${item.finding_count || 0} findings`
    }
    if (selectedWorkflowId.value === 'rescore-rule-sync') {
        return `${item.syncable_finding_count || 0} ready · ${item.review_finding_count || 0} manual review`
    }
    return `${item.finding_count || 0} findings`
}

const loadPreview = async (workflowId: string) => {
    if (!props.taskId) return
    const requestId = ++previewRequestId
    selectedWorkflowId.value = workflowId
    preview.value = null
    selectedIds.value = new Set()
    appliedResult.value = null
    ticketCopyState.value = {}
    error.value = ''
    operationMessage.value = ''
    operationProgress.value = 0
    const cached = previewCache.get(workflowId)
    if (cached) {
        loading.value = false
        preview.value = cached
        selectedIds.value = new Set(cached.selectable_group_ids)
        return
    }
    loading.value = true
    try {
        const result = await previewBulkWorkflow(
            workflowId,
            props.taskId,
            activeFilters.value,
            status => {
                if (requestId === previewRequestId) updateOperationStatus(status)
            },
        )
        if (requestId !== previewRequestId) return
        previewCache.set(workflowId, result)
        preview.value = result
        selectedIds.value = new Set(result.selectable_group_ids)
        workflows.value = workflows.value.map(workflow =>
            workflow.id === workflowId
                ? {
                    ...workflow,
                    candidate_count: result.selectable_group_ids.length,
                    summary: result.summary,
                }
                : workflow
        )
    } catch (err: any) {
        if (requestId !== previewRequestId) return
        error.value = err?.response?.data?.detail || err?.message || 'Unable to preview this workflow.'
    } finally {
        if (requestId === previewRequestId) loading.value = false
    }
}

const loadWorkflows = async () => {
    if (!props.taskId) return
    loading.value = true
    error.value = ''
    activeFilters.value = bulkWorkflowFilters(props.query)
    workflows.value = []
    selectedWorkflowId.value = ''
    preview.value = null
    appliedResult.value = null
    operationMessage.value = ''
    operationProgress.value = 0
    previewCache.clear()
    previewRequestId += 1
    try {
        const response = await getBulkWorkflowSummary(props.taskId, activeFilters.value)
        workflows.value = response.workflows
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Unable to load bulk workflows.'
    } finally {
        loading.value = false
    }
}

const toggleItem = (item: BulkWorkflowPreviewItem) => {
    if (processing.value || !itemSelectable(item)) return
    const next = new Set(selectedIds.value)
    if (next.has(item.group_id)) next.delete(item.group_id)
    else next.add(item.group_id)
    selectedIds.value = next
}

const toggleAll = () => {
    selectedIds.value = allSelected.value ? new Set() : new Set(selectableIds.value)
}

const selectVerdictBuckets = (buckets?: string[]) => {
    if (!preview.value) return
    selectedIds.value = new Set(
        preview.value.items
            .filter(item => itemSelectable(item) && (!buckets || buckets.includes(item.verdict_bucket)))
            .map(item => item.group_id)
    )
}

const copyTicket = async (item: BulkWorkflowPreviewItem) => {
    try {
        await navigator.clipboard.writeText(String(item.ticket_text || ''))
        ticketCopyState.value = { ...ticketCopyState.value, [item.group_id]: 'copied' }
    } catch {
        ticketCopyState.value = { ...ticketCopyState.value, [item.group_id]: 'error' }
    }
}

const createJiraTicket = async (item: BulkWorkflowPreviewItem) => {
    await copyTicket(item)
    if (jiraCreateUrl) window.open(jiraCreateUrl, '_blank', 'noopener,noreferrer')
}

const exportTicketDocument = async () => {
    if (!props.taskId || !preview.value || selectedIds.value.size === 0) return
    documentLoading.value = true
    error.value = ''
    operationMessage.value = ''
    operationProgress.value = 0
    try {
        const markdown = await buildBulkWorkflowDocument(
            preview.value.workflow.id,
            props.taskId,
            activeFilters.value,
            Array.from(selectedIds.value),
            preview.value.preview_token,
            updateOperationStatus,
        )
        const url = URL.createObjectURL(new Blob([markdown], { type: 'text/markdown;charset=utf-8' }))
        const link = document.createElement('a')
        link.href = url
        link.download = 'automatic-assessment-tickets.md'
        link.click()
        URL.revokeObjectURL(url)
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Unable to export ticket drafts.'
    } finally {
        documentLoading.value = false
    }
}

const applySelected = async () => {
    if (!props.taskId || !preview.value || selectedIds.value.size === 0) return
    processing.value = true
    error.value = ''
    operationMessage.value = ''
    operationProgress.value = 0
    try {
        const result = await applyBulkWorkflow(
            preview.value.workflow.id,
            props.taskId,
            activeFilters.value,
            Array.from(selectedIds.value),
            preview.value.preview_token,
            updateOperationStatus,
        )
        appliedResult.value = result
        emit('applied', result)
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Bulk workflow failed.'
    } finally {
        processing.value = false
    }
}

const close = () => {
    if (!processing.value) emit('close')
}

watch(() => props.show, show => {
    if (show) void loadWorkflows()
})
</script>

<template>
    <div v-if="show" class="fixed inset-0 z-[10000] flex items-center justify-center bg-[#0a0a12]/80 p-4 backdrop-blur-md">
        <div class="flex max-h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-2xl border border-white/10 bg-[#12121e] shadow-2xl">
            <header class="flex items-center justify-between border-b border-white/5 bg-blue-500/10 px-8 py-6">
                <div class="flex items-center gap-4">
                    <div class="flex h-12 w-12 items-center justify-center rounded-xl border border-blue-400/30 bg-blue-500/20">
                        <Layers :size="25" class="text-blue-200" />
                    </div>
                    <div>
                        <h2 class="text-2xl font-extrabold text-white">Bulk Changes</h2>
                        <p class="text-xs text-slate-400">Choose one workflow. Every candidate also matches the active vulnerability filters.</p>
                    </div>
                </div>
                <button type="button" class="rounded-full p-2 text-slate-500 hover:bg-white/5 hover:text-white" :disabled="processing" @click="close">
                    <X :size="20" />
                </button>
            </header>

            <div class="grid min-h-0 flex-1 grid-cols-[280px_minmax(0,1fr)] overflow-hidden">
                <aside class="overflow-y-auto border-r border-white/5 bg-black/20 p-4">
                    <div class="mb-3 px-2 text-[10px] font-black uppercase tracking-widest text-slate-600">
                        Workflows · {{ activeFilterCount }} active filter{{ activeFilterCount === 1 ? '' : 's' }}
                    </div>
                    <button
                        v-for="workflow in workflows"
                        :key="workflow.id"
                        type="button"
                        class="mb-2 w-full rounded-xl border p-3 text-left transition-colors"
                        :class="selectedWorkflowId === workflow.id ? 'border-blue-400/40 bg-blue-500/10' : 'border-white/5 bg-white/[0.02] hover:bg-white/[0.05]'"
                        :disabled="processing || !!workflow.unavailable_reason"
                        :data-testid="`bulk-workflow-${workflow.id}`"
                        @click="loadPreview(workflow.id)"
                    >
                        <div class="flex items-center justify-between gap-3">
                            <span class="text-xs font-bold text-white">{{ workflow.label }}</span>
                            <span class="rounded-full bg-black/30 px-2 py-0.5 font-mono text-[10px] text-blue-200">{{ workflow.candidate_count ?? '…' }}</span>
                        </div>
                        <p class="mt-1 text-[10px] leading-relaxed text-slate-500">{{ workflow.unavailable_reason || workflow.description }}</p>
                    </button>
                </aside>

                <main class="flex min-h-0 flex-col gap-4 overflow-hidden p-6">
                    <div v-if="loading" class="flex flex-1 items-center justify-center gap-3 text-sm font-semibold text-blue-200">
                        <Loader2 :size="22" class="animate-spin" />
                        {{ operationMessage || 'Preparing workflow preview' }}
                        <span v-if="operationProgress" class="font-mono text-xs text-blue-300/70">{{ operationProgress }}%</span>
                    </div>
                    <div v-else-if="error" data-testid="bulk-workflow-error" class="rounded-xl border border-red-400/20 bg-red-500/10 p-4 text-sm text-red-100">
                        {{ error }}
                    </div>
                    <div v-else-if="appliedResult" data-testid="bulk-workflow-completion" class="flex flex-1 flex-col items-center justify-center text-center">
                        <CheckCircle :size="44" class="text-emerald-300" />
                        <h3 class="mt-3 text-lg font-bold text-white">{{ appliedResult.workflow.label }} complete</h3>
                        <p class="mt-2 text-xs text-slate-400">
                            {{ appliedResult.summary.succeeded || 0 }} applied · {{ appliedResult.summary.queued || 0 }} queued · {{ appliedResult.summary.failed || 0 }} failed
                        </p>
                    </div>
                    <div v-else-if="!preview" data-testid="bulk-workflow-empty-state" class="flex flex-1 flex-col items-center justify-center text-center">
                        <Layers :size="40" class="text-blue-300" />
                        <h3 class="mt-3 font-bold text-white">Select a bulk workflow</h3>
                        <p class="mt-1 max-w-md text-xs text-slate-500">A preview is prepared only for the workflow you choose. Active vulnerability filters remain in effect.</p>
                    </div>
                    <template v-else-if="preview && selectedWorkflow">
                        <div class="flex items-start justify-between gap-4">
                            <div>
                                <h3 class="text-lg font-bold text-white">{{ selectedWorkflow.label }}</h3>
                                <p class="mt-1 text-xs text-slate-400">{{ selectedWorkflow.description }}</p>
                            </div>
                            <button type="button" class="rounded-lg border border-blue-400/20 bg-blue-500/5 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-blue-200" @click="toggleAll">
                                {{ allSelected ? 'Deselect all' : 'Select all' }}
                            </button>
                        </div>

                        <div v-if="selectedWorkflowId === 'automatic-assessments'" class="flex flex-wrap items-center gap-2" data-testid="automatic-assessment-actions">
                            <span class="mr-1 text-[10px] font-black uppercase tracking-wider text-slate-500">Quick selection</span>
                            <button type="button" class="rounded-lg border border-white/10 px-3 py-1.5 text-[10px] font-bold text-slate-300 hover:bg-white/5" @click="selectVerdictBuckets()">All</button>
                            <button type="button" class="rounded-lg border border-emerald-400/20 px-3 py-1.5 text-[10px] font-bold text-emerald-200 hover:bg-emerald-500/10" @click="selectVerdictBuckets(['NOT_AFFECTED'])">Not affected</button>
                            <button type="button" class="rounded-lg border border-red-400/20 px-3 py-1.5 text-[10px] font-bold text-red-200 hover:bg-red-500/10" @click="selectVerdictBuckets(['AFFECTED', 'PROBABLY_AFFECTED'])">Affected + probable</button>
                            <button type="button" class="rounded-lg border border-amber-400/20 px-3 py-1.5 text-[10px] font-bold text-amber-200 hover:bg-amber-500/10" @click="selectVerdictBuckets(['INCONCLUSIVE'])">Uncertain</button>
                        </div>

                        <div v-if="preview.items.length === 0" class="flex flex-1 flex-col items-center justify-center text-center">
                            <CheckCircle :size="40" class="text-emerald-300" />
                            <h4 class="mt-3 font-bold text-white">No matching changes</h4>
                            <p class="mt-1 text-xs text-slate-500">The active filters and this workflow have no candidates in common.</p>
                            <p
                                v-if="selectedWorkflowId === 'automatic-assessments'"
                                class="mt-3 max-w-xl rounded-lg border border-white/5 bg-black/20 px-3 py-2 font-mono text-[10px] leading-relaxed text-slate-400"
                                data-testid="automatic-assessment-diagnostics"
                            >
                                {{ preview.summary.stored_analysis_results || 0 }} saved result(s) scanned ·
                                {{ preview.summary.usable_assessment_results || 0 }} usable assessment(s) ·
                                {{ preview.summary.matched_analysis_results || 0 }} matched result(s) ·
                                {{ preview.summary.already_applied_findings || 0 }} already-applied finding(s)
                            </p>
                        </div>
                        <div v-else class="min-h-0 flex-1 overflow-y-auto rounded-xl border border-white/5 bg-black/20">
                            <div
                                v-for="item in preview.items"
                                :key="item.group_id"
                                role="button"
                                tabindex="0"
                                class="grid w-full grid-cols-[48px_minmax(0,1fr)_220px] items-center gap-4 border-b border-white/5 px-5 py-4 text-left last:border-0"
                                :class="[
                                    itemSelectable(item) ? 'hover:bg-white/[0.04]' : 'cursor-default opacity-60',
                                    selectedIds.has(item.group_id) ? 'bg-blue-500/10' : '',
                                ]"
                                :data-testid="`bulk-workflow-item-${item.group_id}`"
                                @click="toggleItem(item)"
                                @keydown.space.prevent="toggleItem(item)"
                                @keydown.enter.prevent="toggleItem(item)"
                            >
                                <span class="flex h-5 w-5 items-center justify-center rounded border-2" :class="selectedIds.has(item.group_id) ? 'border-blue-300 bg-blue-500' : 'border-white/10'">
                                    <CheckCircle v-if="selectedIds.has(item.group_id)" :size="12" />
                                </span>
                                <span class="min-w-0">
                                    <span class="block truncate text-sm font-bold text-white">{{ item.group_id }}</span>
                                    <span class="block truncate text-[11px] italic text-slate-500">{{ item.title || itemDetail(item) }}</span>
                                    <span class="mt-1 block text-[10px] text-slate-400">{{ itemDetail(item) }}</span>
                                    <span
                                        v-if="selectedWorkflowId === 'rescore-rule-sync'"
                                        class="mt-3 block space-y-2 rounded-lg border border-white/5 bg-black/20 p-3"
                                        :data-testid="`rescore-rule-change-${item.group_id}`"
                                    >
                                        <span class="grid grid-cols-[64px_minmax(0,1fr)] gap-3">
                                            <span class="text-[9px] font-black uppercase tracking-wider text-slate-500">Original</span>
                                            <span class="min-w-0">
                                                <span class="block font-mono text-[10px] font-bold text-slate-300">Score {{ formatCvssScore(firstRescoreRuleFinding(item)?.current_score) }}</span>
                                                <span class="mt-0.5 block break-all font-mono text-[10px] leading-relaxed text-slate-500">{{ firstRescoreRuleFinding(item)?.current_vector || 'No stored vector' }}</span>
                                            </span>
                                        </span>
                                        <span class="grid grid-cols-[64px_minmax(0,1fr)] gap-3">
                                            <span class="text-[9px] font-black uppercase tracking-wider text-blue-300">Fixed</span>
                                            <span class="min-w-0">
                                                <span class="block font-mono text-[10px] font-bold text-blue-100">Score {{ formatCvssScore(firstRescoreRuleFinding(item)?.proposed_score) }}</span>
                                                <span class="mt-0.5 block break-all font-mono text-[10px] leading-relaxed text-blue-200/80">{{ firstRescoreRuleFinding(item)?.proposed_vector || 'Manual review required' }}</span>
                                            </span>
                                        </span>
                                    </span>
                                </span>
                                <span class="flex flex-col items-end gap-2 text-right">
                                    <span class="inline-block rounded border border-blue-400/20 bg-blue-500/5 px-2 py-1 text-[10px] font-bold uppercase text-blue-200">{{ itemStatus(item) }}</span>
                                    <span v-if="selectedWorkflowId === 'automatic-assessments' && item.ticket_text" class="flex items-center justify-end gap-1.5">
                                        <button type="button" class="inline-flex items-center gap-1 rounded border border-white/10 px-2 py-1 text-[9px] font-bold text-slate-300 hover:bg-white/5" :data-testid="`copy-ticket-${item.group_id}`" @click.stop="copyTicket(item)">
                                            <Copy :size="11" /> {{ ticketCopyState[item.group_id] === 'copied' ? 'Copied' : 'Copy ticket' }}
                                        </button>
                                        <button v-if="jiraCreateUrl" type="button" class="inline-flex items-center gap-1 rounded border border-blue-400/20 px-2 py-1 text-[9px] font-bold text-blue-200 hover:bg-blue-500/10" :data-testid="`jira-ticket-${item.group_id}`" @click.stop="createJiraTicket(item)">
                                            <ExternalLink :size="11" /> Jira
                                        </button>
                                    </span>
                                </span>
                            </div>
                        </div>

                        <div
                            v-if="processing || documentLoading"
                            data-testid="bulk-workflow-operation-status"
                            class="flex items-center gap-3 rounded-xl border border-blue-400/20 bg-blue-500/10 p-3 text-[11px] text-blue-100"
                        >
                            <Loader2 :size="16" class="shrink-0 animate-spin" />
                            <span class="flex-1">{{ operationMessage || 'Starting bulk workflow operation...' }}</span>
                            <span class="font-mono text-[10px] text-blue-200">{{ operationProgress }}%</span>
                        </div>

                        <div class="flex items-center gap-3 rounded-xl border border-amber-400/20 bg-amber-500/10 p-3 text-[11px] text-amber-100">
                            <AlertTriangle :size="18" class="shrink-0" />
                            This applies {{ selectedIds.size }} vulnerability group{{ selectedIds.size === 1 ? '' : 's' }} and approximately {{ selectedFindingCount }} findings. The preview is revalidated before writing.
                        </div>
                    </template>
                </main>
            </div>

            <footer class="flex items-center justify-end gap-3 border-t border-white/5 bg-black/40 px-8 py-5">
                <button type="button" class="px-6 py-2 text-xs font-bold text-slate-500 hover:text-white" :disabled="processing" @click="close">
                    {{ appliedResult ? 'Close' : 'Cancel' }}
                </button>
                <button
                    v-if="preview && !appliedResult && selectedWorkflow?.supports_document"
                    type="button"
                    class="inline-flex items-center gap-2 rounded-xl border border-blue-400/20 bg-blue-500/5 px-5 py-2.5 text-xs font-black uppercase text-blue-200 disabled:opacity-50"
                    :disabled="processing || documentLoading || selectedIds.size === 0"
                    data-testid="bulk-workflow-document"
                    @click="exportTicketDocument"
                >
                    <Loader2 v-if="documentLoading" :size="14" class="animate-spin" />
                    <Download v-else :size="14" /> Export tickets
                </button>
                <button
                    v-if="preview && !appliedResult"
                    type="button"
                    class="inline-flex items-center gap-2 rounded-xl bg-blue-500 px-6 py-2.5 text-xs font-black uppercase text-slate-950 disabled:opacity-50"
                    :disabled="processing || selectedIds.size === 0"
                    data-testid="bulk-workflow-apply"
                    @click="applySelected"
                >
                    <Loader2 v-if="processing" :size="14" class="animate-spin" />
                    Apply selected ({{ selectedIds.size }})
                </button>
            </footer>
        </div>
    </div>
</template>
