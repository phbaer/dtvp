<script setup lang="ts">
import { CheckCircle, ChevronDown, ChevronUp, Eye, History, Loader2, Trash2 } from 'lucide-vue-next'
import type { CodeAnalysisResultRecord } from '../lib/api'

defineProps<{
    record: CodeAnalysisResultRecord
    selected?: boolean
    nested?: boolean
    deleting?: boolean
    canApply?: boolean
    earlierCount?: number
    historyExpanded?: boolean
    team?: string
}>()

const emit = defineEmits<{
    (e: 'select', record: CodeAnalysisResultRecord): void
    (e: 'apply', record: CodeAnalysisResultRecord): void
    (e: 'remove', record: CodeAnalysisResultRecord): void
    (e: 'toggle-history'): void
}>()

const sourceLabel = (source?: string | null) => {
    if (!source || source === 'manual') return 'Manual'
    if (source === 'automatic') return 'Automatic'
    if (source === 'follow-up') return 'Follow-up'
    if (source === 'benchmark') return 'Benchmark'
    return source
}

const sourceClass = (source?: string | null) => {
    if (source === 'automatic') return 'text-cyan-400'
    if (source === 'follow-up') return 'text-blue-400'
    if (source === 'benchmark') return 'text-purple-400'
    return 'text-gray-500'
}

const verdictClass = (record: CodeAnalysisResultRecord) => {
    const verdict = String(record.summary?.verdict || '').toLocaleLowerCase()
    if (verdict === 'affected') return 'text-red-300'
    if (verdict.includes('not affected') || verdict.includes('not_affected')) return 'text-green-300'
    if (verdict) return 'text-yellow-300'
    return 'text-gray-500'
}

const formatTimestamp = (value?: string | null) => {
    if (!value) return 'unknown'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return 'unknown'
    return date.toLocaleString([], {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
    })
}

const formatContextSummary = (record: CodeAnalysisResultRecord) => {
    const summary = record.context_summary || {}
    const versionCount = Array.isArray(summary.project_versions)
        ? summary.project_versions.length
        : null
    const instanceCount = Number.isFinite(Number(summary.instance_count))
        ? Number(summary.instance_count)
        : null
    return [
        versionCount !== null ? `${versionCount} version${versionCount === 1 ? '' : 's'}` : '',
        instanceCount !== null ? `${instanceCount} finding${instanceCount === 1 ? '' : 's'}` : '',
    ].filter(Boolean).join(', ')
}
</script>

<template>
    <div
        data-testid="analysis-history-row"
        :data-run-id="record.analysis_run_id"
        class="grid gap-2 px-3 py-2.5 text-[11px] transition-colors md:grid-cols-[minmax(0,1fr)_auto]"
        :class="[
            selected ? 'bg-cyan-950/25' : 'hover:bg-gray-950/25',
            nested ? 'ml-2' : '',
        ]"
    >
        <div class="min-w-0">
            <div class="flex min-w-0 flex-wrap items-center gap-2">
                <History :size="12" class="shrink-0 text-cyan-400" />
                <span class="min-w-0 truncate font-mono text-gray-200">{{ record.component_name }}</span>
                <span class="shrink-0 text-[9px] uppercase font-semibold" :class="sourceClass(record.source)">
                    {{ sourceLabel(record.source) }}
                </span>
                <span v-if="team" class="shrink-0 text-[9px] font-semibold text-blue-400">{{ team }}</span>
                <span class="shrink-0 uppercase font-semibold" :class="verdictClass(record)">
                    {{ record.summary?.verdict || 'saved' }}
                </span>
                <span class="text-[10px] text-gray-500">{{ formatTimestamp(record.finished_at || record.recorded_at) }}</span>
            </div>
            <div class="mt-0.5 flex min-w-0 flex-wrap gap-x-3 gap-y-0.5 pl-5 text-[10px] text-gray-600">
                <span v-if="record.follow_up_question" class="truncate">{{ record.follow_up_question }}</span>
                <span v-if="formatContextSummary(record)">{{ formatContextSummary(record) }}</span>
                <span v-if="record.context_fingerprint" class="font-mono">ctx {{ record.context_fingerprint.slice(0, 8) }}</span>
            </div>
        </div>
        <div class="flex shrink-0 flex-wrap items-center justify-end gap-1.5">
            <button
                type="button"
                class="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[9px] font-bold uppercase transition-colors"
                :class="selected
                    ? 'bg-cyan-950/45 text-cyan-200'
                    : 'text-cyan-400 hover:bg-cyan-950/20'"
                :aria-expanded="selected ? 'true' : 'false'"
                @click="emit('select', record)"
            >
                <Eye :size="11" />
                {{ selected ? 'Hide' : 'View' }}
            </button>
            <button
                v-if="canApply"
                type="button"
                class="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[9px] font-bold uppercase text-blue-300 transition-colors hover:bg-blue-950/35"
                @click="emit('apply', record)"
            >
                <CheckCircle :size="11" />
                Use as draft
            </button>
            <button
                v-if="!nested && earlierCount"
                type="button"
                class="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[9px] font-bold uppercase text-gray-500 transition-colors hover:bg-gray-800 hover:text-gray-200"
                :aria-expanded="historyExpanded ? 'true' : 'false'"
                @click="emit('toggle-history')"
            >
                <ChevronUp v-if="historyExpanded" :size="11" />
                <ChevronDown v-else :size="11" />
                Earlier runs ({{ earlierCount }})
            </button>
            <button
                type="button"
                class="inline-flex h-6 w-6 items-center justify-center rounded text-gray-600 transition-colors hover:bg-red-950/25 hover:text-red-300 disabled:cursor-wait disabled:opacity-50"
                :disabled="deleting"
                :title="`Remove analysis run ${record.analysis_run_id}`"
                aria-label="Remove analysis run"
                @click.stop="emit('remove', record)"
            >
                <Loader2 v-if="deleting" :size="12" class="animate-spin" />
                <Trash2 v-else :size="12" />
            </button>
        </div>
    </div>
</template>
