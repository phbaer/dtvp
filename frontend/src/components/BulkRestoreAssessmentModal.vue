<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { AlertTriangle, Calculator, CheckCircle, Loader2, X } from 'lucide-vue-next'
import {
    applyAssessmentRestore,
    drainTaskVulnGroups,
    previewAssessmentRestore,
    type AssessmentRestoreApplyResponse,
    type AssessmentRestorePreviewGroup,
    type AssessmentRestorePreviewResponse,
    type TaskVulnGroupListQuery,
} from '../lib/api'

const props = withDefaults(defineProps<{
    show: boolean
    taskId: string | null
    query?: TaskVulnGroupListQuery
}>(), {
    query: () => ({}),
})

const emit = defineEmits<{
    close: []
    applied: [result: AssessmentRestoreApplyResponse]
}>()

const loading = ref(false)
const processing = ref(false)
const error = ref('')
const preview = ref<AssessmentRestorePreviewResponse | null>(null)
const selectedIds = ref<Set<string>>(new Set())
const appliedResult = ref<AssessmentRestoreApplyResponse | null>(null)

const previewItems = computed(() => preview.value?.items || [])
const previewSummary = computed(() => preview.value?.summary || {})
const selectedRecoverableFindings = computed(() =>
    previewItems.value
        .filter(item => selectedIds.value.has(item.group_id))
        .reduce((total, item) => total + item.recoverable_finding_count, 0)
)
const appliedSummary = computed(() => appliedResult.value?.summary || {})
const appliedProblems = computed(() =>
    (appliedResult.value?.results || []).filter(result => result.status === 'error' || result.error)
)

const requestErrorMessage = (err: any, action: string, endpoint: string) => {
    const status = err?.response?.status
    const detail = err?.response?.data?.detail || err?.message
    if (status === 405) {
        return `${action} failed with HTTP 405 for POST ${endpoint}. The frontend and backend routes may be out of sync, or a proxy rejected the method; this is not caused by missing progress updates.`
    }
    return detail || `${action} failed`
}

const loadPreview = async () => {
    if (!props.taskId) return
    loading.value = true
    error.value = ''
    preview.value = null
    selectedIds.value = new Set()
    appliedResult.value = null
    try {
        const matchingGroups = await drainTaskVulnGroups(props.taskId, {
            ...props.query,
            sort: 'id',
            order: 'asc',
        }, { limit: 1000 })
        const result = await previewAssessmentRestore(
            props.taskId,
            matchingGroups.map(group => group.id),
        )
        preview.value = result
        selectedIds.value = new Set(
            result.items
                .filter(item => item.recoverable_finding_count > 0)
                .map(item => item.group_id),
        )
    } catch (err: any) {
        error.value = requestErrorMessage(err, 'Restore preview', '/api/assessments/restore-preview')
    } finally {
        loading.value = false
    }
}

const close = () => {
    if (processing.value) return
    emit('close')
}

const toggleGroup = (group: AssessmentRestorePreviewGroup) => {
    if (processing.value || group.recoverable_finding_count <= 0) return
    const next = new Set(selectedIds.value)
    if (next.has(group.group_id)) next.delete(group.group_id)
    else next.add(group.group_id)
    selectedIds.value = next
}

const toggleAll = () => {
    if (processing.value) return
    const recoverableIds = previewItems.value
        .filter(item => item.recoverable_finding_count > 0)
        .map(item => item.group_id)
    if (selectedIds.value.size === recoverableIds.length) {
        selectedIds.value = new Set()
    } else {
        selectedIds.value = new Set(recoverableIds)
    }
}

const applySelected = async () => {
    if (!props.taskId || selectedIds.value.size === 0) return
    processing.value = true
    error.value = ''
    try {
        const result = await applyAssessmentRestore(props.taskId, Array.from(selectedIds.value))
        appliedResult.value = result
        emit('applied', result)
    } catch (err: any) {
        error.value = requestErrorMessage(err, 'Restore apply', '/api/assessments/restore-apply')
    } finally {
        processing.value = false
    }
}

const statusLabel = (group: AssessmentRestorePreviewGroup) => {
    if (group.recoverable_finding_count > 0) return 'Ready'
    if (group.status === 'ambiguous') return 'Ambiguous'
    if (group.status === 'no_history') return 'No History'
    return group.status || 'Review'
}

const statusClass = (group: AssessmentRestorePreviewGroup) => {
    if (group.recoverable_finding_count > 0) return 'border-cyan-400/30 bg-cyan-500/10 text-cyan-100'
    if (group.status === 'ambiguous') return 'border-amber-400/30 bg-amber-500/10 text-amber-100'
    return 'border-slate-500/30 bg-slate-500/10 text-slate-200'
}

const formatSource = (group: AssessmentRestorePreviewGroup) => {
    const source = group.findings.find(finding => finding.source)?.source
    if (!source) return 'Audit source unavailable'
    const timestamp = source.timestamp ? String(source.timestamp) : 'unknown time'
    const commenter = source.commenter ? ` by ${source.commenter}` : ''
    return `${timestamp}${commenter}`
}

const appliedResultLabel = (result: Record<string, any>) => {
    if (result.queued) return 'Queued for retry'
    if (result.status === 'success') return 'Restored'
    return 'Failed'
}

const appliedResultClass = (result: Record<string, any>) => {
    if (result.queued) return 'border-amber-400/30 bg-amber-500/10 text-amber-100'
    if (result.status === 'success') return 'border-emerald-400/30 bg-emerald-500/10 text-emerald-100'
    return 'border-red-400/30 bg-red-500/10 text-red-100'
}

watch(() => props.show, (show) => {
    if (show) {
        void loadPreview()
    }
})
</script>

<template>
    <div
        v-if="show"
        class="fixed inset-0 z-[10000] flex items-center justify-center bg-[#0a0a12]/80 p-4 backdrop-blur-md"
    >
        <div class="flex max-h-[90vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border border-white/10 bg-[#12121e] shadow-[0_32px_64px_-16px_rgba(0,0,0,0.6)]">
            <div class="flex items-center justify-between border-b border-white/5 bg-cyan-500/10 px-8 py-6">
                <div class="flex items-center gap-4">
                    <div class="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/20">
                        <Calculator class="text-cyan-300" :size="26" />
                    </div>
                    <div>
                        <h3 class="text-2xl font-extrabold tracking-tight text-white">Restore CVSS Rescoring</h3>
                        <p class="text-xs font-medium text-slate-400">Recover missing rescored vectors from Dependency-Track assessment history</p>
                    </div>
                </div>
                <button
                    type="button"
                    class="flex h-10 w-10 items-center justify-center rounded-full text-slate-500 transition-colors hover:bg-white/5 hover:text-white"
                    :disabled="processing"
                    @click="close"
                >
                    <X :size="20" />
                </button>
            </div>

            <div class="flex min-h-0 flex-1 flex-col gap-5 overflow-hidden p-8">
                <div v-if="loading" class="flex flex-1 flex-col items-center justify-center gap-3 py-20 text-cyan-100">
                    <Loader2 :size="30" class="animate-spin" />
                    <span class="text-sm font-semibold uppercase tracking-wider">Loading restore preview</span>
                </div>

                <div v-else-if="processing" data-testid="restore-progress" class="flex flex-1 flex-col items-center justify-center gap-4 py-20 text-center text-cyan-100">
                    <Loader2 :size="36" class="animate-spin" />
                    <div>
                        <div class="text-sm font-black uppercase tracking-wider">Restoring CVSS rescoring</div>
                        <div class="mt-1 text-xs text-slate-400">
                            Applying {{ selectedRecoverableFindings }} finding{{ selectedRecoverableFindings === 1 ? '' : 's' }} and waiting for Dependency-Track
                        </div>
                    </div>
                    <div class="h-1.5 w-full max-w-sm overflow-hidden rounded-full bg-white/10">
                        <div class="h-full w-2/3 animate-pulse rounded-full bg-cyan-400"></div>
                    </div>
                    <div class="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Keep this window open</div>
                </div>

                <div v-else-if="error" data-testid="restore-error" class="rounded-xl border border-red-400/20 bg-red-500/10 p-4 text-sm font-semibold text-red-100">
                    {{ error }}
                </div>

                <div v-else-if="appliedResult" data-testid="restore-completion" class="flex min-h-0 flex-1 flex-col gap-5 overflow-hidden">
                    <div class="flex items-start gap-4 rounded-xl border p-5" :class="appliedProblems.length > 0 ? 'border-amber-400/20 bg-amber-500/10' : 'border-emerald-400/20 bg-emerald-500/10'">
                        <AlertTriangle v-if="appliedProblems.length > 0" :size="28" class="shrink-0 text-amber-300" />
                        <CheckCircle v-else :size="28" class="shrink-0 text-emerald-300" />
                        <div>
                            <h4 class="text-lg font-bold text-white">Restore processing complete</h4>
                            <p class="mt-1 text-xs leading-relaxed text-slate-300">
                                Successful updates are applied immediately. Queued updates will be retried by DTVP; review the details below for rejected requests such as HTTP 405 responses.
                            </p>
                        </div>
                    </div>

                    <div class="grid grid-cols-3 gap-4">
                        <div class="rounded-xl border border-emerald-400/10 bg-emerald-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-[0.12em] text-emerald-300/70">Restored</div>
                            <div class="mt-1 text-2xl font-black text-emerald-200">{{ appliedSummary.succeeded || 0 }}</div>
                        </div>
                        <div class="rounded-xl border border-amber-400/10 bg-amber-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-[0.12em] text-amber-300/70">Queued for Retry</div>
                            <div class="mt-1 text-2xl font-black text-amber-200">{{ appliedSummary.queued || 0 }}</div>
                        </div>
                        <div class="rounded-xl border border-red-400/10 bg-red-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-[0.12em] text-red-300/70">Failed</div>
                            <div class="mt-1 text-2xl font-black text-red-200">{{ appliedSummary.failed || 0 }}</div>
                        </div>
                    </div>

                    <div v-if="appliedProblems.length > 0" class="min-h-0 flex-1 overflow-y-auto rounded-xl border border-white/5 bg-black/20">
                        <div
                            v-for="(result, index) in appliedProblems"
                            :key="String(result.uuid || index)"
                            class="border-b border-white/5 p-4 last:border-b-0"
                        >
                            <div class="flex flex-wrap items-center justify-between gap-2">
                                <span class="font-mono text-xs text-slate-300">{{ result.uuid || 'Unknown finding' }}</span>
                                <span class="rounded-lg border px-2.5 py-1 text-[10px] font-black uppercase tracking-wide" :class="appliedResultClass(result)">
                                    {{ appliedResultLabel(result) }}
                                </span>
                            </div>
                            <div v-if="result.error" class="mt-2 break-words rounded-lg bg-black/30 p-3 font-mono text-[11px] leading-relaxed text-red-200">
                                {{ result.error }}
                            </div>
                        </div>
                    </div>
                </div>

                <div v-else-if="previewItems.length === 0" class="flex flex-1 flex-col items-center justify-center gap-3 py-20 text-center">
                    <CheckCircle :size="42" class="text-emerald-300" />
                    <h4 class="text-lg font-bold text-white">No repairable rescoring gaps found</h4>
                    <button
                        type="button"
                        class="mt-4 rounded-xl border border-white/10 px-6 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 transition-colors hover:bg-white/10 hover:text-white"
                        @click="close"
                    >
                        Close
                    </button>
                </div>

                <template v-else>
                    <div class="grid grid-cols-4 gap-4">
                        <div class="rounded-xl border border-white/5 bg-white/[0.03] p-4">
                            <div class="text-[10px] font-black uppercase tracking-[0.12em] text-slate-500">Groups</div>
                            <div class="mt-1 text-2xl font-black text-white">{{ previewSummary.groups || 0 }}</div>
                        </div>
                        <div class="rounded-xl border border-cyan-400/10 bg-cyan-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-[0.12em] text-cyan-300/70">Recoverable</div>
                            <div class="mt-1 text-2xl font-black text-cyan-200">{{ previewSummary.recoverable_findings || 0 }}</div>
                        </div>
                        <div class="rounded-xl border border-amber-400/10 bg-amber-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-[0.12em] text-amber-300/70">Needs Review</div>
                            <div class="mt-1 text-2xl font-black text-amber-200">
                                {{ (previewSummary.ambiguous_findings || 0) + (previewSummary.no_history_findings || 0) }}
                            </div>
                        </div>
                        <div class="flex items-center justify-end">
                            <button
                                type="button"
                                class="rounded-xl border px-4 py-2 text-xs font-black uppercase tracking-widest transition-colors"
                                :class="selectedIds.size > 0 ? 'border-red-400/20 bg-red-500/5 text-red-300 hover:bg-red-500/10' : 'border-cyan-400/20 bg-cyan-500/5 text-cyan-200 hover:bg-cyan-500/10'"
                                :disabled="processing"
                                @click="toggleAll"
                            >
                                {{ selectedIds.size > 0 ? 'Deselect All' : 'Select All' }}
                            </button>
                        </div>
                    </div>

                    <div class="min-h-0 flex-1 overflow-hidden rounded-xl border border-white/5 bg-black/20">
                        <div class="grid grid-cols-[56px_1fr_120px_120px_220px] gap-4 border-b border-white/5 bg-white/[0.03] px-6 py-4 text-[10px] font-black uppercase tracking-widest text-slate-600">
                            <div class="text-center">Sel</div>
                            <div>Vulnerability</div>
                            <div class="text-center">Findings</div>
                            <div class="text-center">Status</div>
                            <div>Audit Source</div>
                        </div>
                        <div class="max-h-[42vh] overflow-y-auto">
                            <button
                                v-for="group in previewItems"
                                :key="group.group_id"
                                type="button"
                                class="grid w-full grid-cols-[56px_1fr_120px_120px_220px] gap-4 border-b border-white/5 px-6 py-4 text-left transition-colors"
                                :class="[
                                    group.recoverable_finding_count > 0 ? 'cursor-pointer hover:bg-white/[0.04]' : 'cursor-default opacity-75',
                                    selectedIds.has(group.group_id) ? 'bg-cyan-500/10' : 'bg-transparent',
                                ]"
                                @click="toggleGroup(group)"
                            >
                                <div class="flex justify-center">
                                    <span
                                        class="flex h-5 w-5 items-center justify-center rounded-md border-2"
                                        :class="selectedIds.has(group.group_id) ? 'border-cyan-300 bg-cyan-500' : 'border-white/10'"
                                    >
                                        <CheckCircle v-if="selectedIds.has(group.group_id)" :size="12" class="text-white" />
                                    </span>
                                </div>
                                <div class="min-w-0">
                                    <div class="truncate text-sm font-bold text-white">{{ group.group_id }}</div>
                                    <div v-if="group.title" class="truncate text-[11px] italic text-slate-500">{{ group.title }}</div>
                                </div>
                                <div class="text-center text-xs font-bold text-slate-300">
                                    {{ group.recoverable_finding_count }}/{{ group.finding_count }}
                                </div>
                                <div class="flex justify-center">
                                    <span :class="['rounded-lg border px-2.5 py-1 text-[10px] font-black uppercase tracking-wide', statusClass(group)]">
                                        {{ statusLabel(group) }}
                                    </span>
                                </div>
                                <div class="truncate text-[11px] font-medium text-slate-400">
                                    {{ formatSource(group) }}
                                </div>
                            </button>
                        </div>
                    </div>

                    <div class="flex items-center gap-4 rounded-xl border border-amber-400/20 bg-amber-500/10 p-4">
                        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-500/20">
                            <AlertTriangle class="text-amber-300" :size="20" />
                        </div>
                        <p class="text-[11px] font-medium uppercase tracking-[0.02em] text-amber-100/90">
                            This will add missing rescored CVSS tags to {{ selectedRecoverableFindings }} finding{{ selectedRecoverableFindings === 1 ? '' : 's' }} and preserve the current assessment state, justification, suppression, and details text.
                        </p>
                    </div>
                </template>
            </div>

            <div class="flex items-center justify-end gap-4 border-t border-white/5 bg-black/40 px-8 py-6">
                <button
                    type="button"
                    class="rounded-xl border border-transparent px-8 py-3 text-[11px] font-black uppercase tracking-widest text-slate-500 transition-colors hover:border-white/10 hover:text-white"
                    :disabled="processing"
                    @click="close"
                >
                    {{ appliedResult ? 'Close' : 'Cancel' }}
                </button>
                <button
                    v-if="!appliedResult"
                    type="button"
                    class="inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-8 py-3 text-[11px] font-black uppercase tracking-widest text-white shadow-lg shadow-cyan-950/40 transition-colors hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="processing || selectedIds.size === 0 || selectedRecoverableFindings === 0"
                    @click="applySelected"
                >
                    <Loader2 v-if="processing" :size="14" class="animate-spin" />
                    {{ processing ? 'Restoring...' : 'Apply Restore' }}
                </button>
            </div>
        </div>
    </div>
</template>
