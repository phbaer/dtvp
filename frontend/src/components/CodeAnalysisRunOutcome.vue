<script setup lang="ts">
import { AlertTriangle, CheckCircle, Loader2, Send, X } from 'lucide-vue-next'
import type { CodeAnalysisAssessResponse } from '../lib/api'

defineProps<{
    result: CodeAnalysisAssessResponse
    verdictClass?: string
    confidenceClass?: string
    evidenceBadges?: Array<{
        label: string
        detail: string
        className: string
    }>
    runQuestion?: string | null
    canFollowUp?: boolean
    followUpQuestion?: string
    followUpTarget?: string
    followUpBusy?: boolean
}>()

const emit = defineEmits<{
    (event: 'apply'): void
    (event: 'close'): void
    (event: 'follow-up'): void
    (event: 'update:followUpQuestion', value: string): void
    (event: 'update:followUpTarget', value: string): void
}>()
</script>

<template>
    <section
        data-testid="inline-analysis-outcome"
        class="mt-1 border-l-2 px-3 py-2.5"
        :class="result.assessment.affected
            ? 'border-red-500/70 bg-red-950/15'
            : 'border-green-500/70 bg-green-950/10'"
    >
        <div class="flex flex-wrap items-start justify-between gap-2">
            <div class="flex min-w-0 items-start gap-2.5">
                <component
                    :is="result.assessment.affected ? AlertTriangle : CheckCircle"
                    :size="15"
                    class="mt-0.5 shrink-0"
                    :class="verdictClass"
                />
                <div class="min-w-0">
                    <div class="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                        <span class="text-[9px] font-black uppercase tracking-[0.16em] text-gray-500">Run outcome</span>
                        <span class="text-sm font-bold" :class="verdictClass">{{ result.assessment.verdict }}</span>
                    </div>
                    <div v-if="result.assessment.executive_summary" class="mt-2 max-w-4xl space-y-1.5">
                        <div>
                            <div class="text-[9px] font-bold uppercase tracking-wider text-gray-500">Vulnerability</div>
                            <p class="mt-0.5 text-xs leading-relaxed text-gray-300">{{ result.assessment.executive_summary.vulnerability }}</p>
                        </div>
                        <div>
                            <div class="text-[9px] font-bold uppercase tracking-wider text-gray-500">Assessment</div>
                            <p class="mt-0.5 text-xs leading-relaxed text-gray-300">{{ result.assessment.executive_summary.assessment }}</p>
                        </div>
                        <div v-if="result.assessment.executive_summary.why?.length">
                            <div class="text-[9px] font-bold uppercase tracking-wider text-gray-500">Decision rationale</div>
                            <ul class="mt-0.5 space-y-1 pl-4 text-xs leading-relaxed text-gray-400 list-disc">
                                <li v-for="reason in result.assessment.executive_summary.why" :key="reason">{{ reason }}</li>
                            </ul>
                        </div>
                        <div v-else-if="result.assessment.reasoning">
                            <div class="text-[9px] font-bold uppercase tracking-wider text-gray-500">Decision rationale</div>
                            <p class="mt-0.5 text-xs leading-relaxed text-gray-400">{{ result.assessment.reasoning }}</p>
                        </div>
                    </div>
                    <p v-else class="mt-1 max-w-4xl text-xs leading-relaxed text-gray-300">{{ result.assessment.summary }}</p>
                    <div v-if="result.assessment.reasoning && !result.assessment.executive_summary" class="mt-2 max-w-5xl">
                        <div class="text-[9px] font-bold uppercase tracking-wider text-gray-500">Rationale</div>
                        <p class="mt-0.5 text-xs leading-relaxed text-gray-400">{{ result.assessment.reasoning }}</p>
                    </div>
                    <div v-if="runQuestion" class="mt-2 text-[11px] leading-relaxed text-blue-200">
                        <span class="font-semibold text-blue-400">Follow-up run:</span> {{ runQuestion }}
                    </div>
                    <div class="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span class="text-[9px] font-semibold" :class="confidenceClass">
                            {{ result.assessment.confidence }} confidence
                        </span>
                        <span class="text-[10px] text-gray-400">{{ result.assessment.exposure }}</span>
                        <span
                            v-for="badge in evidenceBadges"
                            :key="badge.label"
                            class="text-[9px] font-semibold uppercase tracking-wide"
                            :class="badge.className"
                            :title="badge.detail"
                        >
                            {{ badge.label }}
                        </span>
                    </div>
                </div>
            </div>
            <div class="flex shrink-0 items-center gap-1.5">
                <button
                    type="button"
                    class="inline-flex items-center gap-1 rounded bg-cyan-700/80 px-2.5 py-1.5 text-[10px] font-bold text-white transition-colors hover:bg-cyan-600"
                    @click="emit('apply')"
                >
                    <CheckCircle :size="11" />
                    Use as draft
                </button>
                <button
                    type="button"
                    data-testid="hide-analysis-outcome"
                    class="inline-flex h-7 w-7 items-center justify-center rounded text-gray-500 transition-colors hover:bg-gray-800 hover:text-gray-200"
                    title="Hide selected run details"
                    aria-label="Hide selected run details"
                    @click="emit('close')"
                >
                    <X :size="13" />
                </button>
            </div>
        </div>

        <div
            v-if="canFollowUp"
            class="mt-2 grid items-end gap-2 border-t border-gray-800/70 pt-2 md:grid-cols-[minmax(0,1fr)_minmax(8rem,13rem)_auto]"
            data-testid="analysis-follow-up-controls"
        >
            <label class="min-w-0">
                <span class="mb-1 block text-[9px] font-semibold uppercase tracking-wide text-gray-500">Ask a follow-up</span>
                <input
                    id="code-analysis-follow-up"
                    :value="followUpQuestion"
                    :disabled="followUpBusy"
                    placeholder="e.g. Is the platform package affected?"
                    class="w-full rounded border border-gray-700 bg-gray-950 px-2 py-1.5 text-[11px] focus:border-cyan-500 disabled:opacity-50"
                    @input="emit('update:followUpQuestion', ($event.target as HTMLInputElement).value)"
                    @keyup.enter="emit('follow-up')"
                />
            </label>
            <label class="min-w-0">
                <span class="mb-1 block text-[9px] font-semibold uppercase tracking-wide text-gray-500">Target</span>
                <input
                    id="code-analysis-follow-up-target"
                    :value="followUpTarget"
                    :disabled="followUpBusy"
                    class="w-full rounded border border-gray-700 bg-gray-950 px-2 py-1.5 font-mono text-[11px] focus:border-cyan-500 disabled:opacity-50"
                    @input="emit('update:followUpTarget', ($event.target as HTMLInputElement).value)"
                    @keyup.enter="emit('follow-up')"
                />
            </label>
            <button
                type="button"
                :disabled="followUpBusy || !followUpQuestion?.trim()"
                class="inline-flex items-center justify-center gap-1.5 rounded bg-blue-700 px-2.5 py-1.5 text-[10px] font-bold text-white transition-colors hover:bg-blue-600 disabled:opacity-50"
                @click="emit('follow-up')"
            >
                <Loader2 v-if="followUpBusy" :size="11" class="animate-spin" />
                <Send v-else :size="11" />
                Follow-up
            </button>
        </div>
    </section>
</template>
