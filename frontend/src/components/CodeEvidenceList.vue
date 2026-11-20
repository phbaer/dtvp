<script setup lang="ts">
import { ref } from 'vue'
import { ChevronDown, ChevronRight, CheckCircle, Loader2 } from '@lucide/vue'
import type { EvidenceFilter, EvidenceGroup, EvidenceRow } from '../lib/codeEvidence'
import { formatRelativeTime, formatUtcTime } from '../lib/codeEvidence'

const props = defineProps<{
    groups: EvidenceGroup[]
    filter: EvidenceFilter
    showWithdrawn: boolean
    withdrawnCount: number
    selectedKey?: string | null
    loading?: boolean
}>()

const emit = defineEmits<{
    (e: 'update:filter', value: EvidenceFilter): void
    (e: 'update:showWithdrawn', value: boolean): void
    (e: 'select', row: EvidenceRow): void
}>()

const filters: Array<{ value: EvidenceFilter; label: string }> = [
    { value: 'all', label: 'All' },
    { value: 'analyzer', label: 'Analyzer' },
    { value: 'agent', label: 'Agents' },
]

const openEarlier = ref<Set<string>>(new Set())
const toggleEarlier = (key: string) => {
    const next = new Set(openEarlier.value)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    openEarlier.value = next
}

const readerId = (row: EvidenceRow) => `evidence-reader-${row.key.replace(/[^A-Za-z0-9_-]/g, '-')}`

const decisionClass = (row: EvidenceRow) => {
    const decision = row.decision.toLocaleLowerCase()
    if (decision.includes('not affected') || decision.includes('not_affected') || decision.includes('false_positive')) return 'text-green-300'
    if (decision === 'affected' || decision.includes('exploitable')) return 'text-red-300'
    if (decision) return 'text-yellow-300'
    return 'text-gray-500'
}

const isSelected = (row: EvidenceRow) => props.selectedKey === row.key
</script>

<template>
    <section class="space-y-2" data-testid="code-evidence-list">
        <div class="flex flex-wrap items-center gap-2">
            <div role="group" aria-label="Filter evidence by source" class="inline-flex overflow-hidden rounded border border-gray-700">
                <button
                    v-for="option in filters"
                    :key="option.value"
                    type="button"
                    :data-testid="`evidence-filter-${option.value}`"
                    :aria-pressed="filter === option.value ? 'true' : 'false'"
                    class="px-2.5 py-1 text-[11px] font-semibold transition-colors"
                    :class="filter === option.value ? 'bg-cyan-800/60 text-cyan-100' : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'"
                    @click="emit('update:filter', option.value)"
                >
                    {{ option.label }}
                </button>
            </div>
            <label v-if="withdrawnCount > 0" class="inline-flex items-center gap-1.5 text-[11px] text-gray-400">
                <input
                    type="checkbox"
                    data-testid="evidence-show-withdrawn"
                    class="accent-cyan-500"
                    :checked="showWithdrawn"
                    @change="emit('update:showWithdrawn', ($event.target as HTMLInputElement).checked)"
                />
                Show withdrawn ({{ withdrawnCount }})
            </label>
            <span v-if="loading" class="inline-flex items-center gap-1 text-[11px] text-gray-500" aria-live="polite">
                <Loader2 :size="11" class="animate-spin" /> Loading evidence
            </span>
        </div>

        <p v-if="!loading && groups.length === 0" class="rounded border border-gray-800 bg-gray-950/25 px-3 py-3 text-xs text-gray-500" data-testid="evidence-empty">
            No code evidence for this scope yet.
        </p>

        <div
            v-for="group in groups"
            :key="group.key"
            class="overflow-hidden rounded border border-gray-800/90 bg-gray-950/20"
            data-testid="evidence-group"
            :data-component="group.label"
        >
            <h4 class="border-b border-gray-800/80 bg-gray-950/40 px-3 py-1.5 font-mono text-[11px] font-semibold text-gray-300">
                {{ group.label }}
            </h4>
            <ul class="divide-y divide-gray-800/70">
                <template v-for="row in [...group.rows, ...(openEarlier.has(group.key) ? group.earlier : [])]" :key="row.key">
                    <li :class="group.earlier.includes(row) ? 'bg-gray-950/30 pl-4' : ''">
                        <button
                            type="button"
                            data-testid="evidence-row"
                            :data-kind="row.kind"
                            :data-id="row.id"
                            :aria-expanded="isSelected(row) ? 'true' : 'false'"
                            :aria-controls="readerId(row)"
                            class="flex w-full min-w-0 items-center gap-2 px-3 py-2 text-left text-[11px] transition-colors"
                            :class="[isSelected(row) ? 'bg-cyan-950/30' : 'hover:bg-gray-900/60', row.withdrawn ? 'opacity-60' : '']"
                            @click="emit('select', row)"
                        >
                            <component :is="isSelected(row) ? ChevronDown : ChevronRight" :size="12" class="shrink-0 text-gray-500" />
                            <span
                                class="shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-bold"
                                :class="row.kind === 'agent' ? 'border-fuchsia-700/50 bg-fuchsia-950/30 text-fuchsia-200' : 'border-cyan-700/50 bg-cyan-950/30 text-cyan-200'"
                            >{{ row.sourceLabel }}</span>
                            <span v-if="row.decision" class="shrink-0 font-semibold" :class="decisionClass(row)">
                                {{ row.decision }}<span v-if="row.confidence" class="font-normal text-gray-500"> · {{ row.confidence }}</span>
                            </span>
                            <span class="min-w-0 flex-1 truncate text-gray-200" :class="row.withdrawn ? 'line-through' : ''">{{ row.title }}</span>
                            <span v-if="row.withdrawn" class="shrink-0 text-[10px] font-semibold uppercase text-amber-300">Withdrawn</span>
                            <span v-if="row.used" class="inline-flex shrink-0 items-center gap-1 text-[10px] font-semibold text-emerald-300" data-testid="evidence-used">
                                <CheckCircle :size="10" /> Used in assessment
                            </span>
                            <span class="shrink-0 text-[10px] text-gray-500" :title="formatUtcTime(row.createdAt)">
                                <template v-if="row.author">{{ row.author }} · </template>{{ formatRelativeTime(row.createdAt) }}
                            </span>
                        </button>
                        <div v-if="isSelected(row)" :id="readerId(row)">
                            <slot name="reader" :row="row" />
                        </div>
                    </li>
                </template>
            </ul>
            <button
                v-if="group.earlier.length"
                type="button"
                data-testid="evidence-earlier-toggle"
                :aria-expanded="openEarlier.has(group.key) ? 'true' : 'false'"
                class="flex w-full items-center gap-1 border-t border-gray-800/70 px-3 py-1.5 text-left text-[10px] font-semibold uppercase tracking-wide text-gray-500 hover:text-cyan-300"
                @click="toggleEarlier(group.key)"
            >
                <component :is="openEarlier.has(group.key) ? ChevronDown : ChevronRight" :size="11" />
                {{ openEarlier.has(group.key) ? 'Hide earlier runs' : `Earlier runs (${group.earlier.length})` }}
            </button>
        </div>
    </section>
</template>
