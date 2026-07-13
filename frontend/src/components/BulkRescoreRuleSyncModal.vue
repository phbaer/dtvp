<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { AlertTriangle, CheckCircle, Loader2, RefreshCw, X } from 'lucide-vue-next'
import {
    applyRescoreRuleSync,
    previewRescoreRuleSync,
    type RescoreRuleSyncApplyResponse,
    type RescoreRuleSyncPreviewGroup,
    type RescoreRuleSyncPreviewResponse,
} from '../lib/api'

const props = defineProps<{
    show: boolean
    taskId: string | null
}>()

const emit = defineEmits<{
    close: []
    applied: [result: RescoreRuleSyncApplyResponse]
}>()

const loading = ref(false)
const processing = ref(false)
const error = ref('')
const preview = ref<RescoreRuleSyncPreviewResponse | null>(null)
const selectedIds = ref<Set<string>>(new Set())
const appliedResult = ref<RescoreRuleSyncApplyResponse | null>(null)

const items = computed(() => preview.value?.items || [])
const summary = computed(() => preview.value?.summary || {})
const appliedSummary = computed(() => appliedResult.value?.summary || {})
const selectedFindingCount = computed(() =>
    items.value
        .filter(item => selectedIds.value.has(item.group_id))
        .reduce((total, item) => total + item.syncable_finding_count, 0),
)
const syncableGroupIds = computed(() =>
    items.value
        .filter(item => item.syncable_finding_count > 0)
        .map(item => item.group_id),
)
const allSyncableSelected = computed(() =>
    syncableGroupIds.value.length > 0 &&
    syncableGroupIds.value.every(groupId => selectedIds.value.has(groupId)),
)
const appliedProblems = computed(() =>
    (appliedResult.value?.results || []).filter(result => result.status === 'error' || result.error),
)

const requestError = (err: any, fallback: string) =>
    err?.response?.data?.detail || err?.message || fallback

const loadPreview = async () => {
    if (!props.taskId) return
    loading.value = true
    error.value = ''
    preview.value = null
    selectedIds.value = new Set()
    appliedResult.value = null
    try {
        const result = await previewRescoreRuleSync(props.taskId)
        preview.value = result
        selectedIds.value = new Set(
            result.items
                .filter(item => item.syncable_finding_count > 0)
                .map(item => item.group_id),
        )
    } catch (err: any) {
        error.value = requestError(err, 'Could not build the CVSS rule sync preview')
    } finally {
        loading.value = false
    }
}

const close = () => {
    if (!processing.value) emit('close')
}

const toggleGroup = (group: RescoreRuleSyncPreviewGroup) => {
    if (processing.value || group.syncable_finding_count <= 0) return
    const next = new Set(selectedIds.value)
    if (next.has(group.group_id)) next.delete(group.group_id)
    else next.add(group.group_id)
    selectedIds.value = next
}

const toggleAll = () => {
    selectedIds.value = allSyncableSelected.value
        ? new Set()
        : new Set(syncableGroupIds.value)
}

const applySelected = async () => {
    if (!props.taskId || selectedIds.value.size === 0) return
    processing.value = true
    error.value = ''
    try {
        const result = await applyRescoreRuleSync(props.taskId, Array.from(selectedIds.value))
        appliedResult.value = result
        emit('applied', result)
    } catch (err: any) {
        error.value = requestError(err, 'CVSS rule sync failed')
    } finally {
        processing.value = false
    }
}

const firstReadyFinding = (group: RescoreRuleSyncPreviewGroup) =>
    group.findings.find(finding => finding.status === 'ready') || group.findings[0]

const groupReasons = (group: RescoreRuleSyncPreviewGroup) =>
    Array.from(new Set(group.findings.flatMap(finding => finding.reasons))).join(' · ')

watch(() => props.show, show => {
    if (show) void loadPreview()
})
</script>

<template>
    <div
        v-if="show"
        class="fixed inset-0 z-[10000] flex items-center justify-center bg-[#0a0a12]/80 p-4 backdrop-blur-md"
    >
        <div class="flex max-h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-2xl border border-white/10 bg-[#12121e] shadow-[0_32px_64px_-16px_rgba(0,0,0,0.6)]">
            <header class="flex items-center justify-between border-b border-white/5 bg-amber-500/10 px-8 py-6">
                <div class="flex items-center gap-4">
                    <div class="flex h-12 w-12 items-center justify-center rounded-xl border border-amber-400/30 bg-amber-500/20">
                        <RefreshCw :size="25" class="text-amber-200" />
                    </div>
                    <div>
                        <h3 class="text-2xl font-extrabold tracking-tight text-white">Sync CVSS Rescore Rules</h3>
                        <p class="text-xs font-medium text-slate-400">Preview and repair stored vectors that no longer follow the configured metric relationships</p>
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
            </header>

            <main class="flex min-h-0 flex-1 flex-col gap-5 overflow-hidden p-8">
                <div v-if="loading" data-testid="rescore-rule-sync-loading" class="flex flex-1 flex-col items-center justify-center gap-3 py-20 text-amber-100">
                    <Loader2 :size="30" class="animate-spin" />
                    <span class="text-sm font-semibold uppercase tracking-wider">Checking all stored vectors</span>
                </div>

                <div v-else-if="processing" data-testid="rescore-rule-sync-progress" class="flex flex-1 flex-col items-center justify-center gap-4 py-20 text-center text-amber-100">
                    <Loader2 :size="36" class="animate-spin" />
                    <div class="text-sm font-black uppercase tracking-wider">Applying configured CVSS rules</div>
                    <div class="text-xs text-slate-400">Updating {{ selectedFindingCount }} finding{{ selectedFindingCount === 1 ? '' : 's' }} in Dependency-Track</div>
                </div>

                <div v-else-if="error" data-testid="rescore-rule-sync-error" class="rounded-xl border border-red-400/20 bg-red-500/10 p-4 text-sm font-semibold text-red-100">
                    {{ error }}
                </div>

                <div v-else-if="appliedResult" data-testid="rescore-rule-sync-completion" class="flex min-h-0 flex-1 flex-col gap-5 overflow-hidden">
                    <div class="flex items-start gap-4 rounded-xl border p-5" :class="appliedProblems.length ? 'border-amber-400/20 bg-amber-500/10' : 'border-emerald-400/20 bg-emerald-500/10'">
                        <AlertTriangle v-if="appliedProblems.length" :size="28" class="shrink-0 text-amber-300" />
                        <CheckCircle v-else :size="28" class="shrink-0 text-emerald-300" />
                        <div>
                            <h4 class="text-lg font-bold text-white">CVSS rule sync complete</h4>
                            <p class="mt-1 text-xs text-slate-300">Successful updates are visible immediately; queued updates will be retried by DTVP.</p>
                        </div>
                    </div>
                    <div class="grid grid-cols-3 gap-4">
                        <div class="rounded-xl border border-emerald-400/10 bg-emerald-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-wider text-emerald-300/70">Updated</div>
                            <div class="mt-1 text-2xl font-black text-emerald-200">{{ appliedSummary.succeeded || 0 }}</div>
                        </div>
                        <div class="rounded-xl border border-amber-400/10 bg-amber-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-wider text-amber-300/70">Queued</div>
                            <div class="mt-1 text-2xl font-black text-amber-200">{{ appliedSummary.queued || 0 }}</div>
                        </div>
                        <div class="rounded-xl border border-red-400/10 bg-red-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-wider text-red-300/70">Failed</div>
                            <div class="mt-1 text-2xl font-black text-red-200">{{ appliedSummary.failed || 0 }}</div>
                        </div>
                    </div>
                    <div v-if="appliedProblems.length" class="min-h-0 flex-1 overflow-y-auto rounded-xl border border-white/5 bg-black/20">
                        <div v-for="(result, index) in appliedProblems" :key="String(result.uuid || index)" class="border-b border-white/5 p-4 last:border-0">
                            <div class="font-mono text-xs text-slate-300">{{ result.uuid || 'Unknown finding' }}</div>
                            <div class="mt-2 break-words font-mono text-[11px] text-red-200">{{ result.error }}</div>
                        </div>
                    </div>
                </div>

                <div v-else-if="items.length === 0" class="flex flex-1 flex-col items-center justify-center gap-3 py-20 text-center">
                    <CheckCircle :size="42" class="text-emerald-300" />
                    <h4 class="text-lg font-bold text-white">All applicable rescored vectors follow the rules</h4>
                    <p class="text-xs text-slate-400">{{ summary.compliant_findings || 0 }} rule-controlled finding{{ summary.compliant_findings === 1 ? '' : 's' }} checked.</p>
                </div>

                <template v-else>
                    <div class="grid grid-cols-4 gap-4">
                        <div class="rounded-xl border border-white/5 bg-white/[0.03] p-4">
                            <div class="text-[10px] font-black uppercase tracking-wider text-slate-500">Groups</div>
                            <div class="mt-1 text-2xl font-black text-white">{{ summary.groups || 0 }}</div>
                        </div>
                        <div class="rounded-xl border border-amber-400/10 bg-amber-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-wider text-amber-300/70">Ready</div>
                            <div class="mt-1 text-2xl font-black text-amber-200">{{ summary.syncable_findings || 0 }}</div>
                        </div>
                        <div class="rounded-xl border border-red-400/10 bg-red-500/5 p-4">
                            <div class="text-[10px] font-black uppercase tracking-wider text-red-300/70">Manual Review</div>
                            <div class="mt-1 text-2xl font-black text-red-200">{{ summary.review_findings || 0 }}</div>
                        </div>
                        <div class="flex items-center justify-end">
                            <button type="button" class="rounded-xl border border-amber-400/20 bg-amber-500/5 px-4 py-2 text-xs font-black uppercase tracking-wider text-amber-200 hover:bg-amber-500/10" @click="toggleAll">
                                {{ allSyncableSelected ? 'Deselect All' : 'Select All' }}
                            </button>
                        </div>
                    </div>

                    <div class="min-h-0 flex-1 overflow-y-auto rounded-xl border border-white/5 bg-black/20">
                        <button
                            v-for="group in items"
                            :key="group.group_id"
                            type="button"
                            class="grid w-full grid-cols-[48px_minmax(180px,0.8fr)_90px_minmax(300px,1.5fr)] gap-4 border-b border-white/5 px-5 py-4 text-left transition-colors last:border-0"
                            :class="[
                                group.syncable_finding_count ? 'hover:bg-white/[0.04]' : 'cursor-default opacity-75',
                                selectedIds.has(group.group_id) ? 'bg-amber-500/10' : '',
                            ]"
                            @click="toggleGroup(group)"
                        >
                            <div class="flex justify-center pt-1">
                                <span class="flex h-5 w-5 items-center justify-center rounded-md border-2" :class="selectedIds.has(group.group_id) ? 'border-amber-300 bg-amber-500' : 'border-white/10'">
                                    <CheckCircle v-if="selectedIds.has(group.group_id)" :size="12" class="text-white" />
                                </span>
                            </div>
                            <div class="min-w-0">
                                <div class="truncate text-sm font-bold text-white">{{ group.group_id }}</div>
                                <div class="truncate text-[11px] italic text-slate-500">{{ group.title || firstReadyFinding(group)?.state }}</div>
                                <div class="mt-1 text-[10px] font-bold uppercase tracking-wide" :class="group.review_finding_count ? 'text-red-300' : 'text-amber-300'">
                                    {{ group.syncable_finding_count }} ready · {{ group.review_finding_count }} review
                                </div>
                            </div>
                            <div class="pt-1 text-center">
                                <div class="text-[10px] font-black uppercase text-slate-500">CVSS {{ firstReadyFinding(group)?.cvss_version }}</div>
                                <div class="mt-1 font-mono text-sm font-bold text-white">
                                    {{ firstReadyFinding(group)?.current_score ?? '—' }} → {{ firstReadyFinding(group)?.proposed_score ?? '—' }}
                                </div>
                            </div>
                            <div class="min-w-0">
                                <div class="break-all font-mono text-[10px] leading-relaxed text-slate-500">{{ firstReadyFinding(group)?.current_vector || 'No stored vector' }}</div>
                                <div class="my-1 text-[9px] font-black uppercase tracking-widest text-amber-400">↓ configured result</div>
                                <div class="break-all font-mono text-[10px] leading-relaxed text-amber-100">{{ firstReadyFinding(group)?.proposed_vector || 'Manual review required' }}</div>
                                <div class="mt-2 text-[10px] font-medium text-slate-400">{{ groupReasons(group) }}</div>
                            </div>
                        </button>
                    </div>

                    <div class="flex items-center gap-4 rounded-xl border border-amber-400/20 bg-amber-500/10 p-4">
                        <AlertTriangle :size="20" class="shrink-0 text-amber-300" />
                        <p class="text-[11px] font-medium text-amber-100/90">
                            Only previewed rule-controlled fields and the calculated score will change. Assessment state, justification, suppression, and explanatory text are preserved.
                        </p>
                    </div>
                </template>
            </main>

            <footer class="flex items-center justify-end gap-4 border-t border-white/5 bg-black/40 px-8 py-6">
                <button type="button" class="rounded-xl px-8 py-3 text-[11px] font-black uppercase tracking-widest text-slate-500 hover:text-white" :disabled="processing" @click="close">
                    {{ appliedResult ? 'Close' : 'Cancel' }}
                </button>
                <button
                    v-if="!appliedResult && items.length > 0"
                    type="button"
                    class="inline-flex items-center gap-2 rounded-xl bg-amber-500 px-8 py-3 text-[11px] font-black uppercase tracking-widest text-slate-950 transition-colors hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="processing || selectedIds.size === 0"
                    @click="applySelected"
                >
                    <Loader2 v-if="processing" :size="14" class="animate-spin" />
                    Apply Rule Sync ({{ selectedFindingCount }})
                </button>
            </footer>
        </div>
    </div>
</template>
