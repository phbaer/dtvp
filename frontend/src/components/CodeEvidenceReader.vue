<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { ClipboardCheck, Loader2, MoreHorizontal, Trash2, Undo2, X } from '@lucide/vue'
import SafeMarkdown from './SafeMarkdown.vue'
import EvidenceAttachments from './EvidenceAttachments.vue'
import type { CodeAnalysisAssessResponse } from '../lib/api'
import type { EvidenceRow } from '../lib/codeEvidence'
import { formatLocalTime, formatUtcTime } from '../lib/codeEvidence'
import { safeLinkUrl } from '../lib/safeMarkdown'

const props = defineProps<{
    row: EvidenceRow
    /** The full analyzer result, once loaded. */
    result?: CodeAnalysisAssessResponse | null
    loading?: boolean
    /** Analyzer runs: whether the run may be applied. */
    applicable?: boolean
    /** Team whose draft receives the evidence, or "General". */
    targetLabel: string
    currentUser?: string
    isReviewer?: boolean
    /** Findings of this vulnerability that are reported now. */
    reportedFindingUuids?: string[]
    busy?: boolean
}>()

const emit = defineEmits<{
    (e: 'apply', options: { useSuggestion: boolean; summary?: string }): void
    (e: 'withdraw', reason: string): void
    (e: 'remove'): void
    (e: 'close'): void
    (e: 'attachments-change'): void
}>()

const root = ref<HTMLElement | null>(null)
const showAll = ref(false)
const useSuggestion = ref(false)
const moreOpen = ref(false)
const withdrawing = ref(false)
const withdrawReason = ref('')

onMounted(() => {
    void nextTick(() => root.value?.focus())
})

const evidence = computed(() => props.row.evidence)
const assessmentSummary = ref('')
watch(() => props.row.id, () => { assessmentSummary.value = props.row.evidence?.assessment_summary || '' }, { immediate: true })
const record = computed(() => props.row.record)

const SOURCE_LABELS: Record<string, string> = {
    manual: 'manual',
    automatic: 'automatic',
    'follow-up': 'follow-up',
    benchmark: 'benchmark',
}

const addedBy = computed(() => {
    if (evidence.value) {
        const author = evidence.value.author
        return `${author.username} via token ${author.agent_label} (id ${author.token_id}), ${String(author.authority || 'ANALYST').toLocaleLowerCase()} authority`
    }
    const run = record.value
    if (!run) return ''
    return [
        `Agentyzer run ${run.analysis_run_id}`,
        run.model || '',
        SOURCE_LABELS[String(run.source || 'manual')] || String(run.source || ''),
        run.submitted_by ? `started by ${run.submitted_by}` : '',
    ].filter(Boolean).join(' · ')
})

const uniq = (values: Array<string | null | undefined>) =>
    [...new Set(values.map(value => String(value || '').trim()).filter(Boolean))]

const forComponents = computed(() => {
    if (evidence.value) {
        return uniq(evidence.value.targets.map(target =>
            target.component_version ? `${target.component} ${target.component_version}` : target.component,
        ))
    }
    return uniq([record.value?.component_name])
})

const forProjectVersions = computed(() => {
    if (evidence.value) return uniq(evidence.value.targets.map(target => target.project_version))
    const versions = record.value?.context_summary?.project_versions
    return Array.isArray(versions) ? uniq(versions) : []
})

const findingCount = computed(() => {
    if (evidence.value) return evidence.value.targets.length
    const count = Number(record.value?.context_summary?.instance_count)
    return Number.isFinite(count) ? count : null
})

const noLongerReported = computed(() => {
    if (!evidence.value || !props.reportedFindingUuids?.length) return false
    const reported = new Set(props.reportedFindingUuids)
    return !evidence.value.targets.some(target => target.finding_uuid && reported.has(target.finding_uuid))
})

const references = computed(() => (evidence.value?.references || []).map(reference => ({
    text: reference,
    href: safeLinkUrl(reference),
})))

const suggestion = computed(() => {
    if (!evidence.value?.suggested_state) return ''
    return [evidence.value.suggested_state, evidence.value.suggested_justification].filter(Boolean).join(' · ')
})

const canWithdraw = computed(() => Boolean(
    evidence.value
    && !evidence.value.withdrawn
    && (props.isReviewer || (props.currentUser && props.currentUser === evidence.value.author.username)),
))

const applyDisabledReason = computed(() => {
    if (props.row.kind === 'agent') {
        if (evidence.value?.withdrawn) return 'Withdrawn evidence cannot be used.'
        return assessmentSummary.value.trim() ? '' : 'Write an assessment rationale before using this evidence.'
    }
    if (props.loading) return 'The run is loading.'
    return props.applicable ? '' : 'This run is not eligible: rerun analysis to obtain a validated assessment.'
})

const reportMarkdown = computed(() => String(props.result?.assessment?.report_markdown || '').trim())
const executiveSummary = computed(() => props.result?.assessment?.executive_summary || null)

const apply = () => {
    if (applyDisabledReason.value) return
    emit('apply', { useSuggestion: Boolean(suggestion.value && useSuggestion.value), ...(props.row.kind === 'agent' ? { summary: assessmentSummary.value.trim() } : {}) })
}

const confirmWithdraw = () => {
    const reason = withdrawReason.value.trim()
    if (!reason) return
    emit('withdraw', reason)
    withdrawing.value = false
    moreOpen.value = false
}

const headingId = computed(() => `evidence-reader-title-${props.row.key.replace(/[^A-Za-z0-9_-]/g, '-')}`)
</script>

<template>
    <section
        ref="root"
        tabindex="-1"
        role="region"
        :aria-labelledby="headingId"
        data-testid="evidence-reader"
        class="space-y-3 border-l-2 border-cyan-800/70 bg-gray-950/30 px-4 py-3 outline-none focus-visible:ring-1 focus-visible:ring-cyan-600"
        @keydown.esc.stop="emit('close')"
    >
        <div class="flex items-start justify-between gap-2">
            <h5 :id="headingId" class="text-sm font-semibold text-gray-100">{{ row.title }}</h5>
            <div class="flex shrink-0 items-center gap-1">
                <div class="relative">
                    <button
                        type="button"
                        data-testid="evidence-reader-more"
                        :aria-expanded="moreOpen ? 'true' : 'false'"
                        aria-haspopup="menu"
                        class="inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1 text-[10px] font-semibold text-gray-400 hover:text-gray-200"
                        @click="moreOpen = !moreOpen"
                    >
                        <MoreHorizontal :size="12" /> More
                    </button>
                    <div v-if="moreOpen" role="menu" class="absolute right-0 z-20 mt-1 w-48 rounded border border-gray-700 bg-gray-900 py-1 shadow-lg">
                        <button
                            v-if="canWithdraw"
                            type="button"
                            role="menuitem"
                            data-testid="evidence-withdraw"
                            class="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-amber-200 hover:bg-gray-800"
                            @click="withdrawing = true; moreOpen = false"
                        >
                            <Undo2 :size="12" /> Withdraw evidence
                        </button>
                        <button
                            v-if="row.kind === 'analyzer'"
                            type="button"
                            role="menuitem"
                            data-testid="evidence-remove-run"
                            class="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-red-300 hover:bg-gray-800"
                            @click="emit('remove'); moreOpen = false"
                        >
                            <Trash2 :size="12" /> Remove run
                        </button>
                        <p v-if="row.kind === 'agent' && !canWithdraw" class="px-3 py-1.5 text-[11px] text-gray-500">
                            {{ evidence?.withdrawn ? 'Already withdrawn.' : 'Only a reviewer or the author can withdraw this evidence.' }}
                        </p>
                    </div>
                </div>
                <button
                    type="button"
                    data-testid="evidence-reader-close"
                    class="inline-flex h-7 w-7 items-center justify-center rounded text-gray-500 hover:bg-gray-800 hover:text-gray-200"
                    aria-label="Close evidence"
                    @click="emit('close')"
                >
                    <X :size="13" />
                </button>
            </div>
        </div>

        <div v-if="withdrawing" class="space-y-2 rounded border border-amber-800/50 bg-amber-950/15 p-3 text-xs" data-testid="evidence-withdraw-form">
            <label class="block">
                <span class="mb-1 block text-[11px] font-semibold text-amber-200">Why is this evidence withdrawn?</span>
                <input
                    v-model="withdrawReason"
                    maxlength="500"
                    data-testid="evidence-withdraw-reason"
                    class="w-full rounded border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs focus:border-amber-500"
                    @keyup.enter="confirmWithdraw"
                />
            </label>
            <div class="flex gap-2">
                <button
                    type="button"
                    data-testid="evidence-withdraw-confirm"
                    :disabled="!withdrawReason.trim() || busy"
                    class="rounded bg-amber-700 px-2.5 py-1 text-[11px] font-semibold text-white hover:bg-amber-600 disabled:opacity-50"
                    @click="confirmWithdraw"
                >Withdraw</button>
                <button type="button" class="rounded px-2.5 py-1 text-[11px] text-gray-400 hover:text-gray-200" @click="withdrawing = false">Cancel</button>
            </div>
        </div>

        <dl class="grid gap-x-4 gap-y-1 text-[11px] sm:grid-cols-[8rem_minmax(0,1fr)]" data-testid="evidence-provenance">
            <dt class="text-gray-500">Source</dt>
            <dd class="text-gray-200">{{ row.kind === 'agent' ? 'AI agent through MCP' : 'Code analyzer (Agentyzer)' }}</dd>
            <dt class="text-gray-500">Added by</dt>
            <dd class="break-words text-gray-200" data-testid="evidence-added-by">{{ addedBy }}</dd>
            <dt class="text-gray-500">Recorded at</dt>
            <dd class="text-gray-200" :title="formatUtcTime(row.createdAt)">{{ formatLocalTime(row.createdAt) }}</dd>
            <dt class="text-gray-500">For</dt>
            <dd class="text-gray-200" data-testid="evidence-for">
                <span class="font-mono">{{ forComponents.join(', ') || 'unknown component' }}</span>
                <template v-if="forProjectVersions.length"> · project {{ forProjectVersions.join(', ') }}</template>
                <template v-if="findingCount !== null"> · {{ findingCount }} finding{{ findingCount === 1 ? '' : 's' }}</template>
                <span v-if="noLongerReported" class="ml-1 font-semibold text-amber-300">· no longer reported</span>
            </dd>
            <template v-if="row.kind === 'agent' && evidence?.confidence">
                <dt class="text-gray-500">Confidence</dt>
                <dd class="text-gray-200">{{ evidence.confidence }}</dd>
            </template>
            <template v-if="references.length">
                <dt class="text-gray-500">References</dt>
                <dd class="min-w-0">
                    <ul class="space-y-0.5">
                        <li v-for="reference in references" :key="reference.text" class="break-all">
                            <a v-if="reference.href" :href="reference.href" target="_blank" rel="noopener noreferrer" class="text-cyan-300 underline">{{ reference.text }}</a>
                            <span v-else class="text-gray-300">{{ reference.text }}</span>
                        </li>
                    </ul>
                </dd>
            </template>
            <template v-if="evidence?.withdrawn">
                <dt class="text-amber-400">Withdrawn</dt>
                <dd class="text-amber-200" data-testid="evidence-withdrawn">
                    by {{ evidence.withdrawn.by }}, {{ formatLocalTime(evidence.withdrawn.at) }}: {{ evidence.withdrawn.reason }}
                </dd>
            </template>
        </dl>

        <div class="relative">
            <div :class="showAll ? '' : 'max-h-96 overflow-hidden'" data-testid="evidence-body">
                <SafeMarkdown v-if="evidence" :markdown="evidence.body_markdown" />
                <div v-else-if="loading" class="flex items-center gap-2 text-xs text-gray-500">
                    <Loader2 :size="12" class="animate-spin" /> Loading the run
                </div>
                <SafeMarkdown v-else-if="reportMarkdown" :markdown="reportMarkdown" />
                <div v-else-if="executiveSummary" class="space-y-1.5 text-xs leading-relaxed">
                    <p v-if="executiveSummary.vulnerability" class="text-gray-300"><span class="font-semibold text-gray-400">Vulnerability: </span>{{ executiveSummary.vulnerability }}</p>
                    <p v-if="executiveSummary.assessment" class="text-gray-300"><span class="font-semibold text-gray-400">Assessment: </span>{{ executiveSummary.assessment }}</p>
                    <ul v-if="executiveSummary.why?.length" class="list-disc space-y-1 pl-4 text-gray-400">
                        <li v-for="reason in executiveSummary.why" :key="reason">{{ reason }}</li>
                    </ul>
                </div>
                <p v-else-if="result?.assessment" class="text-xs leading-relaxed text-gray-300">
                    {{ result.assessment.summary || result.assessment.reasoning }}
                </p>
            </div>
            <button
                type="button"
                class="mt-1 text-[11px] font-semibold text-cyan-300 hover:text-cyan-200"
                @click="showAll = !showAll"
            >{{ showAll ? 'Show less' : 'Show all' }}</button>
        </div>

        <details v-if="row.kind === 'analyzer' && $slots.details" class="group rounded border border-gray-800 bg-gray-950/30" data-testid="evidence-technical-details">
            <summary class="cursor-pointer list-none px-3 py-2 text-[11px] font-semibold text-gray-400 hover:text-gray-200">
                Technical details
            </summary>
            <div class="border-t border-gray-800 p-2">
                <slot name="details" />
            </div>
        </details>

        <details v-if="evidence?.applications?.length" class="text-xs text-gray-400">
            <summary>Assessment use history</summary>
            <ul><li v-for="(application, index) in evidence.applications" :key="index">
                {{ application.team || 'Legacy scope (not recorded)' }} · revision {{ application.assessment_revision === -1 ? 'not recorded' : application.assessment_revision }} · {{ application.selected === false ? 'deselected' : 'selected' }} · {{ application.applied_by }} · {{ application.applied_at }}
            </li></ul>
        </details>

        <EvidenceAttachments v-if="evidence" :evidence="evidence" :canUpload="canWithdraw" @changed="emit('attachments-change')" />

        <section
            class="rounded-lg border-2 border-emerald-800/60 bg-emerald-950/10 p-3"
            data-testid="evidence-apply-box"
            :aria-labelledby="`${headingId}-apply`"
        >
            <h6 :id="`${headingId}-apply`" class="text-xs font-bold text-emerald-200">Apply to the assessment</h6>
            <p v-if="row.kind === 'agent'" class="mt-1 text-[11px] leading-relaxed text-gray-300">
                Adds the rationale below to the {{ targetLabel }} assessment draft and links the supporting evidence within DTVP. Nothing is saved until you save the assessment.
            </p>
            <p v-else class="mt-1 text-[11px] leading-relaxed text-gray-300">
                Fills the {{ targetLabel }} assessment draft with this run's decision: its state, justification, and CVSS. Nothing is saved until you save the assessment.
            </p>
            <label v-if="row.kind === 'agent'" class="mt-2 block text-xs text-gray-300">
                Assessment rationale
                <textarea v-model="assessmentSummary" required maxlength="10000" rows="5" data-testid="evidence-assessment-summary" class="mt-1 w-full rounded border border-gray-700 bg-gray-950 p-2 text-gray-100" placeholder="Explain the decision, scope, exposure, observations and limitations. This text must stand alone when printed." />
                <span class="text-[11px] text-gray-400">Required before applying. Explain the decision in your own words; the evidence title and report are not copied automatically.</span>
            </label>
            <label v-if="row.kind === 'agent' && suggestion" class="mt-2 flex items-center gap-2 text-[11px] text-gray-200">
                <input v-model="useSuggestion" type="checkbox" data-testid="evidence-use-suggestion" class="accent-emerald-500" :disabled="Boolean(applyDisabledReason)" />
                Also use the suggested decision: <span class="font-mono">{{ suggestion }}</span>
            </label>
            <div class="mt-2 flex flex-wrap items-center gap-2">
                <button
                    type="button"
                    data-testid="evidence-apply"
                    :disabled="Boolean(applyDisabledReason) || busy"
                    class="inline-flex items-center gap-1.5 rounded bg-emerald-700 px-3 py-1.5 text-[11px] font-bold text-white hover:bg-emerald-600 disabled:cursor-not-allowed disabled:opacity-50"
                    @click="apply"
                >
                    <ClipboardCheck :size="12" /> Use in assessment draft
                </button>
                <span v-if="applyDisabledReason" class="text-[11px] text-amber-300" data-testid="evidence-apply-disabled-reason">{{ applyDisabledReason }}</span>
            </div>
        </section>
    </section>
</template>
