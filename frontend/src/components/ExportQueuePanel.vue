<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { AlertTriangle, RefreshCw, Trash2, Upload } from '@lucide/vue'
import { discardExports, exportAssessments, getExportQueue } from '../lib/api'
import type { ExportQueue, ExportQueueItem } from '../lib/api'

const queue = ref<ExportQueue | null>(null)
const loading = ref(false)
const exporting = ref('')
const error = ref('')
const notice = ref('')
const expanded = ref<Set<string>>(new Set())

const errorMessage = (err: any, fallback: string): string =>
    err?.response?.data?.detail || err?.message || fallback

const exportable = computed(() => queue.value?.pending || [])

/** After this many failed attempts an export is not going to fix itself. */
const STUCK_ATTEMPTS = 10
const failing = computed(() =>
    (queue.value?.pending || []).filter(item => item.status === 'error'))

const waitingSince = (item: ExportQueueItem): string => {
    const queued = new Date(item.queued_at).getTime()
    if (Number.isNaN(queued)) return ''
    const hours = Math.floor((Date.now() - queued) / 3_600_000)
    if (hours < 1) return 'waiting less than an hour'
    if (hours < 48) return `waiting ${hours} h`
    return `waiting ${Math.floor(hours / 24)} days`
}

const failureHint = (item: ExportQueueItem): string => {
    if (!item.project_known) {
        return 'This project is no longer in Dependency-Track. The export cannot succeed; discard it.'
    }
    if (item.attempts >= STUCK_ATTEMPTS) {
        return `Failed ${item.attempts} times. Check the error; discard the export if it cannot succeed.`
    }
    return ''
}

const discard = async (items: ExportQueueItem[]) => {
    if (exporting.value || items.length === 0) return
    const what = items.length === 1
        ? `the export for ${items[0]!.vulnerability_id || 'this finding'}`
        : `${items.length} exports`
    if (!window.confirm(
        `Discard ${what}? The change will not be sent to Dependency-Track. `
        + 'Where the previous value is known, the assessment in DTVP goes back to it; '
        + 'the discarded version stays in the history.',
    )) return
    exporting.value = items.length === 1 ? `discard:${items[0]!.update_id}` : 'discard:all'
    error.value = ''
    notice.value = ''
    try {
        const result = await discardExports(items.map(item => item.update_id))
        notice.value = `${result.discarded} discarded.`
        await load(true)
    } catch (err: any) {
        error.value = errorMessage(err, 'The exports could not be discarded')
    } finally {
        exporting.value = ''
    }
}

const statusLabel = (item: ExportQueueItem): string => {
    if (item.status === 'error') {
        return item.attempts >= STUCK_ATTEMPTS || !item.project_known ? 'Stuck' : 'Failed, will retry'
    }
    return 'Waiting'
}

const findingLabel = (item: ExportQueueItem): string => {
    const project = [item.project_name, item.project_version].filter(Boolean).join(' ')
    const component = [item.component_name, item.component_version].filter(Boolean).join('@')
    return [project || item.project_uuid, component || item.component_uuid].join(' · ')
}

const formatDate = (value: string | null): string =>
    value ? new Date(value).toLocaleString() : ''

const toggle = (id: string) => {
    const next = new Set(expanded.value)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    expanded.value = next
}

const load = async (keepMessages = false) => {
    loading.value = true
    if (!keepMessages) {
        error.value = ''
        notice.value = ''
    }
    try {
        queue.value = await getExportQueue()
    } catch (err: any) {
        error.value = errorMessage(err, 'Failed to load the export queue')
    } finally {
        loading.value = false
    }
}

const runExport = async (item?: ExportQueueItem) => {
    if (exporting.value) return
    exporting.value = item ? item.update_id : 'all'
    error.value = ''
    notice.value = ''
    try {
        const result = await exportAssessments(item ? [item.update_id] : undefined)
        const parts = [`${result.exported} exported`]
        if (result.dropped > 0) parts.push(`${result.dropped} no longer in Dependency-Track`)
        const failed = result.failed
        if (failed.length > 0) parts.push(`${failed.length} failed`)
        notice.value = parts.join(', ') + '.'
        if (failed.length > 0 && failed[0]?.error) error.value = failed[0].error
        // Reload the queue but keep the outcome of this export on screen.
        await load(true)
    } catch (err: any) {
        error.value = errorMessage(err, 'The export failed')
    } finally {
        exporting.value = ''
    }
}

onMounted(() => load())
</script>

<template>
    <div class="bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-lg" data-testid="export-queue-panel">
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h3 class="text-xl font-bold text-gray-200 flex items-center gap-2">
                    <Upload :size="18" aria-hidden="true" />
                    Export to Dependency-Track
                </h3>
                <p v-if="queue" class="mt-1 text-sm text-gray-400" data-testid="export-mode">
                    <template v-if="queue.mode === 'manual'">
                        Manual export is on: assessments stay in DTVP until a reviewer exports them here.
                    </template>
                    <template v-else>
                        Assessments are exported automatically shortly after they are saved.
                        What is listed here is still waiting or failed.
                    </template>
                </p>
            </div>
            <div class="flex shrink-0 items-center gap-2">
                <button
                    type="button"
                    class="inline-flex items-center gap-2 rounded border border-gray-600 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-50"
                    :disabled="loading"
                    @click="load()"
                >
                    <RefreshCw :size="14" :class="{ 'animate-spin': loading }" aria-hidden="true" />
                    Refresh
                </button>
                <button
                    v-if="failing.length > 0"
                    type="button"
                    class="inline-flex items-center gap-2 rounded border border-red-800 px-3 py-1.5 text-xs font-bold text-red-200 hover:bg-red-950/60 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="exporting !== ''"
                    data-testid="export-discard-failing"
                    @click="discard(failing)"
                >
                    <Trash2 :size="14" aria-hidden="true" />
                    Discard failing ({{ failing.length }})
                </button>
                <button
                    type="button"
                    class="inline-flex items-center gap-2 rounded bg-blue-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="exportable.length === 0 || exporting !== ''"
                    data-testid="export-all"
                    @click="runExport()"
                >
                    <Upload :size="14" aria-hidden="true" />
                    {{ exporting === 'all' ? 'Exporting…' : `Export all (${exportable.length})` }}
                </button>
            </div>
        </div>

        <div v-if="notice" role="status" class="mb-4 p-3 bg-green-900/30 border border-green-800 text-green-300 rounded text-sm" data-testid="export-notice">
            {{ notice }}
        </div>
        <div v-if="error" role="alert" class="mb-4 p-3 bg-red-900/30 border border-red-800 text-red-400 rounded text-sm">
            {{ error }}
        </div>

        <p v-if="loading && !queue" class="text-sm text-gray-400">Loading the export queue…</p>
        <p v-else-if="queue && queue.pending.length === 0" class="text-sm text-gray-400" data-testid="export-empty">
            Nothing is waiting. Dependency-Track has every assessment made here.
        </p>

        <div v-else-if="queue" class="overflow-x-auto">
            <table class="w-full text-left text-sm text-gray-300">
                <thead class="text-xs uppercase text-gray-500">
                    <tr>
                        <th class="py-2 pr-4">Vulnerability</th>
                        <th class="py-2 pr-4">Finding</th>
                        <th class="py-2 pr-4">Change</th>
                        <th class="py-2 pr-4">By</th>
                        <th class="py-2 pr-4">Status</th>
                        <th class="py-2"><span class="sr-only">Actions</span></th>
                    </tr>
                </thead>
                <tbody>
                    <template v-for="item in queue.pending" :key="item.update_id">
                        <tr class="border-t border-gray-700 align-top" data-testid="export-row">
                            <td class="py-2 pr-4 font-medium text-gray-100">
                                {{ item.vulnerability_id || item.vulnerability_uuid }}
                            </td>
                            <td class="py-2 pr-4">
                                {{ findingLabel(item) }}
                                <span v-if="!item.project_known" class="block text-xs text-amber-300" data-testid="export-project-gone">
                                    {{ item.project_name ? 'Project deleted in Dependency-Track' : 'Unknown project, deleted in Dependency-Track' }}<template v-if="item.project_last_seen_at">, last seen {{ formatDate(item.project_last_seen_at) }}</template>
                                </span>
                            </td>
                            <td class="py-2 pr-4 whitespace-nowrap">
                                <span class="text-gray-500">{{ item.source?.analysisState ?? 'unknown' }}</span>
                                →
                                <span class="text-gray-100">{{ item.local.analysisState }}</span>
                            </td>
                            <td class="py-2 pr-4">
                                {{ item.author || 'unknown' }}
                                <span class="block text-xs text-gray-500">{{ formatDate(item.updated_at) }}</span>
                            </td>
                            <td class="py-2 pr-4">
                                <span
                                    :class="item.status === 'error' ? 'text-red-400' : 'text-gray-300'"
                                >{{ statusLabel(item) }}</span>
                                <span class="block text-xs text-gray-500">
                                    {{ waitingSince(item) }}<template v-if="item.attempts > 0"> · {{ item.attempts }} {{ item.attempts === 1 ? 'attempt' : 'attempts' }}</template>
                                </span>
                            </td>
                            <td class="py-2 text-right whitespace-nowrap">
                                <button
                                    type="button"
                                    class="mr-2 rounded border border-gray-600 px-2 py-1 text-xs text-gray-300 hover:bg-gray-700"
                                    :aria-expanded="expanded.has(item.update_id)"
                                    data-testid="export-toggle"
                                    @click="toggle(item.update_id)"
                                >
                                    {{ expanded.has(item.update_id) ? 'Hide text' : 'Show text' }}
                                </button>
                                <button
                                    type="button"
                                    class="mr-2 rounded border border-blue-700 px-2 py-1 text-xs text-blue-200 hover:bg-blue-900/40 disabled:opacity-50"
                                    :disabled="exporting !== ''"
                                    data-testid="export-one"
                                    @click="runExport(item)"
                                >
                                    {{ exporting === item.update_id ? 'Exporting…' : 'Export' }}
                                </button>
                                <button
                                    type="button"
                                    class="rounded border border-red-900 px-2 py-1 text-xs text-red-300 hover:bg-red-950/60 disabled:opacity-50"
                                    :disabled="exporting !== ''"
                                    :aria-label="`Discard the export for ${item.vulnerability_id || 'this finding'}`"
                                    data-testid="export-discard"
                                    @click="discard([item])"
                                >
                                    {{ exporting === `discard:${item.update_id}` ? 'Discarding…' : 'Discard' }}
                                </button>
                            </td>
                        </tr>
                        <tr v-if="item.last_error || failureHint(item)" class="border-t border-gray-800" data-testid="export-failure">
                            <td colspan="6" class="pb-2 text-xs">
                                <p v-if="failureHint(item)" class="flex items-center gap-1.5 text-amber-300">
                                    <AlertTriangle :size="12" aria-hidden="true" />
                                    {{ failureHint(item) }}
                                </p>
                                <p v-if="item.last_error" class="mt-1 whitespace-pre-wrap break-words font-mono text-[11px] text-red-300/90">{{ item.last_error }}</p>
                            </td>
                        </tr>
                        <tr v-if="expanded.has(item.update_id)" class="border-t border-gray-800" data-testid="export-detail">
                            <td colspan="6" class="pb-3">
                                <div class="grid gap-3 md:grid-cols-2">
                                    <div>
                                        <h5 class="mb-1 text-xs font-bold uppercase text-gray-500">Last known in Dependency-Track</h5>
                                        <pre class="max-h-48 overflow-auto whitespace-pre-wrap rounded border border-gray-700 bg-gray-900 p-2 text-xs text-gray-300">{{ item.source ? (item.source.analysisDetails || '(No details)') : 'Not known' }}</pre>
                                    </div>
                                    <div>
                                        <h5 class="mb-1 text-xs font-bold uppercase text-gray-500">Will be exported</h5>
                                        <pre class="max-h-48 overflow-auto whitespace-pre-wrap rounded border border-gray-700 bg-gray-900 p-2 text-xs text-gray-100">{{ item.local.analysisDetails || '(No details)' }}</pre>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </template>
                </tbody>
            </table>
        </div>
    </div>
</template>
