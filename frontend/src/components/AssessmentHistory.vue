<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { History, RefreshCw } from '@lucide/vue'
import { getAssessmentHistory } from '../lib/api'
import type { AssessmentRevision } from '../lib/api'
import type { Instance } from '../types'
import { readTeamChangesRequests, stripTeamChangesRequests } from '../lib/assessmentChanges'

const props = defineProps<{
    instances: Instance[]
    /** Bumped by the parent after a save, a clear, or conflict resolution. */
    refreshKey?: number
}>()

/** Loading every finding of a very large vulnerability would be slow. */
const MAX_FINDINGS = 30

const ORIGIN_LABELS: Record<string, string> = {
    'individual-assessment': 'Saved',
    'mcp-assessment': 'Saved by an agent',
    'bulk-workflow': 'Bulk change',
    'assessment-deletion': 'Cleared',
    'assessment-changes-requested': 'Changes requested',
    'assessment-changes-resubmitted': 'Resubmitted for review',
    'assessment-changes-withdrawn': 'Request withdrawn',
    'export-discarded': 'Export discarded, previous value restored',
    'import': 'Changed in Dependency-Track',
    'conflict-resolution': 'Conflict resolved',
    'before-history': 'Before history was kept',
    'user': 'Saved',
}

interface HistoryEntry {
    key: string
    created_at: string
    author: string | null
    origin: string
    analysisState: string
    analysisDetails: string
    isSuppressed: boolean
    findings: string[]
}

const open = ref(false)
const loading = ref(false)
const error = ref('')
const entries = ref<HistoryEntry[]>([])
const loadedFindings = ref(0)
const expanded = ref<Set<string>>(new Set())

const eligible = computed(() => props.instances.filter(instance =>
    instance.project_uuid && instance.component_uuid && instance.vulnerability_uuid))
const truncated = computed(() => eligible.value.length > MAX_FINDINGS)

const findingLabel = (instance: Instance): string =>
    [instance.project_version, [instance.component_name, instance.component_version].filter(Boolean).join('@')]
        .filter(Boolean)
        .join(' · ')

const formatDate = (value: string): string => new Date(value).toLocaleString()

const load = async () => {
    loading.value = true
    error.value = ''
    try {
        const targets = eligible.value.slice(0, MAX_FINDINGS)
        const histories = await Promise.all(targets.map(async instance => ({
            label: findingLabel(instance),
            revisions: await getAssessmentHistory({
                project_uuid: instance.project_uuid,
                component_uuid: instance.component_uuid,
                vulnerability_uuid: instance.vulnerability_uuid as string,
            }),
        })))
        // One save usually writes the same value to every finding at the
        // same instant; show that as one entry.
        const merged = new Map<string, HistoryEntry>()
        for (const history of histories) {
            for (const revision of history.revisions as AssessmentRevision[]) {
                const key = [
                    revision.created_at,
                    revision.author || '',
                    revision.origin,
                    revision.analysisState,
                    revision.isSuppressed,
                    revision.analysisDetails,
                ].join('\u0000')
                const existing = merged.get(key)
                if (existing) {
                    existing.findings.push(history.label)
                } else {
                    merged.set(key, {
                        key,
                        created_at: revision.created_at,
                        author: revision.author,
                        origin: revision.origin,
                        analysisState: revision.analysisState,
                        analysisDetails: revision.analysisDetails,
                        isSuppressed: revision.isSuppressed,
                        findings: [history.label],
                    })
                }
            }
        }
        entries.value = Array.from(merged.values())
            .sort((left, right) => right.created_at.localeCompare(left.created_at))
        loadedFindings.value = targets.length
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Failed to load the history'
    } finally {
        loading.value = false
    }
}

const toggleOpen = () => {
    open.value = !open.value
    if (open.value) load()
}

const toggleEntry = (key: string) => {
    const next = new Set(expanded.value)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    expanded.value = next
}

watch(() => props.refreshKey, () => {
    if (open.value) load()
})
</script>

<template>
    <div data-testid="assessment-history">
        <div class="flex flex-wrap items-center gap-2">
            <button
                type="button"
                class="inline-flex items-center gap-2 rounded border border-gray-600 bg-gray-800 px-3 py-1.5 text-xs font-semibold text-gray-200 hover:bg-gray-700"
                :aria-expanded="open"
                data-testid="assessment-history-toggle"
                @click="toggleOpen"
            >
                <History :size="14" aria-hidden="true" />
                {{ open ? 'Hide history' : 'Show history' }}
            </button>
            <button
                v-if="open"
                type="button"
                class="inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1.5 text-xs text-gray-400 hover:bg-gray-800 disabled:opacity-50"
                :disabled="loading"
                aria-label="Reload history"
                @click="load"
            >
                <RefreshCw :size="12" :class="{ 'animate-spin': loading }" aria-hidden="true" />
            </button>
            <span v-if="open && truncated" class="text-[11px] text-amber-300" data-testid="assessment-history-truncated">
                Showing the first {{ loadedFindings }} of {{ eligible.length }} findings.
            </span>
        </div>

        <div v-if="open" class="mt-3">
            <p v-if="error" role="alert" class="rounded border border-red-800 bg-red-900/30 p-2 text-xs text-red-300">{{ error }}</p>
            <p v-else-if="loading && entries.length === 0" class="text-xs text-gray-500">Loading history…</p>
            <p v-else-if="entries.length === 0" class="text-xs text-gray-500" data-testid="assessment-history-empty">
                No assessment has been recorded in River for this vulnerability yet.
            </p>
            <ol v-else class="space-y-2">
                <li
                    v-for="entry in entries"
                    :key="entry.key"
                    class="rounded border border-gray-800 bg-gray-950/40 p-3"
                    data-testid="assessment-history-entry"
                >
                    <div class="flex flex-wrap items-baseline justify-between gap-2 text-xs">
                        <span class="font-semibold text-gray-100">
                            {{ ORIGIN_LABELS[entry.origin] || entry.origin }}
                            <span class="font-normal text-gray-400">
                                {{ entry.author ? `by ${entry.author}` : '' }}
                            </span>
                        </span>
                        <time class="text-gray-500" :datetime="entry.created_at">{{ formatDate(entry.created_at) }}</time>
                    </div>
                    <div class="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-gray-400">
                        <span class="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-gray-200">{{ entry.analysisState }}</span>
                        <span v-if="entry.isSuppressed" class="rounded bg-gray-800 px-1.5 py-0.5">suppressed</span>
                        <span :title="entry.findings.join('\n')">
                            {{ entry.findings.length === loadedFindings && loadedFindings > 1
                                ? `all ${loadedFindings} findings`
                                : entry.findings.length === 1 ? entry.findings[0] : `${entry.findings.length} findings` }}
                        </span>
                        <button
                            type="button"
                            class="ml-auto rounded border border-gray-700 px-2 py-0.5 text-gray-300 hover:bg-gray-800"
                            :aria-expanded="expanded.has(entry.key)"
                            data-testid="assessment-history-entry-toggle"
                            @click="toggleEntry(entry.key)"
                        >
                            {{ expanded.has(entry.key) ? 'Hide text' : 'Show text' }}
                        </button>
                    </div>
                    <div v-if="expanded.has(entry.key)" class="mt-2 space-y-2">
                        <p
                            v-for="request in readTeamChangesRequests(entry.analysisDetails)"
                            :key="request.team"
                            class="whitespace-pre-wrap break-words text-xs text-amber-200"
                        ><strong>{{ request.team }}</strong> · {{ request.reviewer }} · {{ request.rationale }}</p>
                        <pre
                            class="max-h-64 overflow-auto whitespace-pre-wrap rounded border border-gray-800 bg-gray-900 p-2 text-[11px] text-gray-300"
                        >{{ stripTeamChangesRequests(entry.analysisDetails) || '(No assessment text)' }}</pre>
                    </div>
                </li>
            </ol>
        </div>
    </div>
</template>
