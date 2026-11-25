<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { Loader2, RefreshCw } from '@lucide/vue'
import {
    cancelSync,
    exportAssessments,
    getProjects,
    getSyncProgress,
    getSyncStatus,
    getSyncVersions,
    requestSourceAnalysis,
    resumeSync,
    requestSyncRead,
    type SyncProgress,
    type SyncQueueEntry,
    type SyncRequestTarget,
    type SyncSourceInfo,
} from '../lib/api'
import { useServerEvents } from '../lib/eventStream'

// Reviewers trigger work on the source by hand: read versions again now,
// ask the source to analyse them again, export the queued assessments now.
// The progress comes from the live events of the background sync.
const props = defineProps<{ projectName: string }>()

interface Version { uuid: string; version: string }
type State = 'requested' | 'queued' | 'syncing' | 'analysing' | 'done' | 'failed' | 'cancelled'

const open = ref(false)
const loading = ref(false)
const error = ref('')
const message = ref('')
const versions = ref<Version[]>([])
const source = ref<SyncSourceInfo | null>(null)
const states = ref<Record<string, State>>({})
const exporting = ref(false)
const requestErrors = ref<Record<string, string>>({})
const readAt = ref<Record<string, string>>({})
const root = ref<HTMLElement | null>(null)
// What the background sync does now, from ``source.sync_progress`` (and the
// last portfolio pass's outcome from ``source.portfolio_pass``).
const progress = ref<SyncProgress | null>(null)
const lastPass = ref<{ unchanged: number; changed: number } | null>(null)
const cancelling = ref(false)

const lastSuccess = ref<string | null>(null)
const queue = ref<{ total: number; items: SyncQueueEntry[] } | null>(null)
const sourceName = computed(() => source.value?.name || 'the source')
const formatTime = (value: string) => new Date(value).toLocaleString()
const canAnalyse = computed(() => Boolean(source.value?.can_request_analysis))
const ACTIVE: State[] = ['requested', 'queued', 'syncing', 'analysing']
const running = computed(() => Boolean(
    progress.value?.pass || progress.value?.running?.length || progress.value?.requested,
))
const busy = computed(() => running.value || Object.values(states.value).some(s => ACTIVE.includes(s)))

const PHASES: Record<string, string> = {
    preparing: 'preparing',
    findings: 'findings',
    vulns: 'vulnerability records',
    bom: 'BOM',
    commit: 'saving',
    events: 'saving',
}

// One line for the toolbar and the panel: what runs now.
const summary = computed(() => {
    const now = progress.value
    if (!now) return ''
    const parts: string[] = []
    if (now.pass) {
        const pages = now.pass.pages_total
            ? `page ${now.pass.pages_read}/${now.pass.pages_total}`
            : 'starting'
        parts.push(`Reading the portfolio (${now.pass.versions} versions): ${pages}`)
    }
    if (now.running.length) parts.push(`reading ${now.running.length} version(s)`)
    if (now.queued) parts.push(`${now.queued} waiting`)
    if (!parts.length && now.ranges) parts.push(`version ranges: ${now.ranges.checked}/${now.ranges.versions}`)
    return parts.join(' · ')
})

const shortSummary = computed(() => {
    const now = progress.value
    if (!now) return ''
    if (now.pass) return now.pass.pages_total ? `${now.pass.pages_read}/${now.pass.pages_total}` : '…'
    const pending = now.running.length + now.queued
    return pending ? String(pending) : ''
})

const STATE_LABELS: Record<State, string> = {
    requested: 'requested',
    queued: 'queued',
    syncing: 'reading',
    analysing: 'analysing',
    done: 'read',
    failed: 'failed',
    cancelled: 'cancelled',
}

const byVersionDescending = (left: Version, right: Version) =>
    right.version.localeCompare(left.version, undefined, { numeric: true, sensitivity: 'base' })

const load = async () => {
    loading.value = true
    error.value = ''
    try {
        const [projects, status, synced] = await Promise.all([
            getProjects(props.projectName),
            getSyncStatus(),
            getSyncVersions(props.projectName).catch(() => []),
        ])
        source.value = status.source
        lastSuccess.value = status.last_success_at
        queue.value = status.queue
        // A request's progress as the server keeps it (it outlives the page).
        const fromServer: Record<string, State> = {}
        const errors: Record<string, string> = {}
        for (const version of synced) {
            const request = version.request
            if (!request) continue
            fromServer[version.project_uuid] = request.state === 'running' ? 'syncing'
                : request.state === 'done' ? 'done'
                : request.state === 'failed' ? 'failed'
                : request.state === 'cancelled' ? 'cancelled'
                : 'requested'
            if (request.state === 'failed' && request.error) errors[version.project_uuid] = request.error
            if (request.state === 'done' && request.read_at) readAt.value[version.project_uuid] = request.read_at
        }
        states.value = { ...fromServer, ...states.value }
        requestErrors.value = errors
        versions.value = projects
            .filter(project => project.name === props.projectName && project.uuid)
            .map(project => ({ uuid: project.uuid, version: String(project.version || '') }))
            .sort(byVersionDescending)
    } catch {
        error.value = 'The versions could not be loaded.'
    } finally {
        loading.value = false
    }
}

const mark = (uuids: string[], state: State) => {
    states.value = { ...states.value, ...Object.fromEntries(uuids.map(uuid => [uuid, state])) }
}

const failure = (err: any, what: string) => {
    const status = err?.response?.status
    if (status === 403) return `Only reviewers can ${what}.`
    if (status === 501) return `${sourceName.value} cannot be asked for an analysis.`
    if (status === 503) return `${sourceName.value} is not reachable right now.`
    return `Could not ${what}.`
}

const read = async (target: SyncRequestTarget) => {
    message.value = ''
    try {
        const result = await requestSyncRead(target)
        mark(result.requested, 'requested')
        message.value = result.requested.length
            ? `Reading ${result.requested.length} version(s) from ${sourceName.value}.`
            : 'Already requested.'
    } catch (err) {
        message.value = failure(err, 'request a read')
    }
}

const analyse = async (target: SyncRequestTarget) => {
    message.value = ''
    try {
        const result = await requestSourceAnalysis(target)
        mark(result.requested, 'analysing')
        message.value = result.requested.length
            ? `${sourceName.value} analyses ${result.requested.length} version(s); they are read when it is done.`
            : 'An analysis is already running.'
    } catch (err) {
        message.value = failure(err, 'request an analysis')
    }
}

const exportNow = async () => {
    message.value = ''
    exporting.value = true
    try {
        await exportAssessments()
        message.value = `The queued assessments were exported to ${sourceName.value}.`
    } catch (err) {
        message.value = failure(err, 'export')
    } finally {
        exporting.value = false
    }
}

const cancel = async () => {
    message.value = ''
    cancelling.value = true
    try {
        const result = await cancelSync()
        mark([...result.requests, ...result.running].filter(known), 'cancelled')
        const parts = [
            result.pass ? 'pass' : '',
            result.running.length ? `${result.running.length} running` : '',
            result.waiting ? `${result.waiting} waiting` : '',
            result.requests.length ? `${result.requests.length} request(s)` : '',
        ].filter(Boolean)
        message.value = parts.length ? `Cancelled: ${parts.join(', ')}.` : 'Nothing was running.'
        await loadProgress()
    } catch (err) {
        message.value = failure(err, 'cancel')
    } finally {
        cancelling.value = false
    }
}

const resume = async () => {
    message.value = ''
    try {
        await resumeSync()
        message.value = 'Sync resumed.'
        await loadProgress()
    } catch (err) {
        message.value = failure(err, 'resume')
    }
}

const loadProgress = async () => {
    try {
        progress.value = await getSyncProgress()
    } catch {
        // The indicator stays empty; events fill it in.
    }
}

const known = (uuid: unknown): uuid is string =>
    typeof uuid === 'string' && versions.value.some(version => version.uuid === uuid)

useServerEvents('version.sync_state', event => {
    const { uuid, status } = event.data || {}
    if (!known(uuid)) return
    if (status === 'queued' || status === 'syncing' || status === 'analysing') mark([uuid], status)
})
useServerEvents('version.synced', event => {
    if (known(event.data?.uuid) && states.value[event.data.uuid]) mark([event.data.uuid], 'done')
})
useServerEvents('version.sync_failed', event => {
    if (known(event.data?.uuid) && states.value[event.data.uuid]) mark([event.data.uuid], 'failed')
})
// A cancel, a reconnect or a missed event: read the state again.
useServerEvents(['source.sync_cancelled', 'hello', 'resync'], () => { void loadProgress() })
const refreshQueue = async () => {
    try {
        const status = await getSyncStatus()
        queue.value = status.queue
        lastSuccess.value = status.last_success_at
    } catch {
        // The list stays as it was; the next change tries again.
    }
}
useServerEvents('source.sync_progress', event => {
    if (!event.data) return
    progress.value = event.data as SyncProgress
    // The queue's reasons come from the status: read it again when its size changed.
    if (open.value && queue.value && event.data.queued !== queue.value.total) void refreshQueue()
})
useServerEvents('source.portfolio_pass', event => {
    if (event.data?.phase === 'done') {
        lastPass.value = { unchanged: Number(event.data.unchanged || 0), changed: Number(event.data.changed || 0) }
    }
})
useServerEvents('version.sync_state', event => {
    const { uuid, status } = event.data || {}
    if (known(uuid) && status === 'cancelled') mark([uuid], 'cancelled')
})

const toggle = () => {
    open.value = !open.value
    if (open.value) void load()
}

const closeOnOutsideClick = (event: MouseEvent) => {
    if (open.value && root.value && !root.value.contains(event.target as Node)) open.value = false
}
const closeOnEscape = (event: KeyboardEvent) => {
    if (event.key === 'Escape') open.value = false
}

onMounted(() => {
    void loadProgress()
    document.addEventListener('mousedown', closeOnOutsideClick)
    document.addEventListener('keydown', closeOnEscape)
})
onBeforeUnmount(() => {
    document.removeEventListener('mousedown', closeOnOutsideClick)
    document.removeEventListener('keydown', closeOnEscape)
})
</script>

<template>
    <div ref="root" class="relative shrink-0">
        <button
            type="button"
            data-testid="source-sync-button"
            title="Read again, analyse again or export now"
            aria-haspopup="true"
            :aria-expanded="open"
            class="inline-flex h-10 items-center gap-2 rounded-xl border border-white/10 bg-slate-950/35 px-3 text-xs font-semibold uppercase tracking-wider text-slate-200 transition-colors hover:bg-slate-900/55 hover:text-white"
            @click="toggle"
        >
            <Loader2 v-if="busy" :size="14" class="animate-spin" />
            <RefreshCw v-else :size="14" />
            <span class="hidden sm:inline">Sync</span>
            <span
                v-if="shortSummary"
                data-testid="source-sync-indicator"
                class="rounded-full bg-white/10 px-1.5 py-0.5 font-mono text-[10px] normal-case tracking-normal"
                :title="summary"
            >{{ shortSummary }}</span>
        </button>
        <div
            v-if="open"
            data-testid="source-sync-panel"
            class="absolute right-0 z-40 mt-2 w-[26rem] max-w-[90vw] rounded-xl border border-white/10 bg-slate-950 p-3 text-left text-xs shadow-2xl"
        >
            <div class="font-semibold text-white">{{ sourceName }}</div>
            <div v-if="progress && progress.active !== undefined" data-testid="sync-activity" class="mt-0.5 text-[11px]" :class="progress.active ? 'text-emerald-300' : 'text-gray-400'">
                {{ progress.active ? 'Active' : 'Idle (no users): only exports and requests reach the source' }}
            </div>
            <div v-if="lastSuccess" data-testid="sync-last-success" class="mt-0.5 text-[11px] text-gray-400">
                Last successful sync: {{ formatTime(lastSuccess) }}
            </div>
            <p class="mt-1 text-[11px] leading-snug text-gray-400">
                River reads every version in the background. Read again now, ask
                {{ sourceName }} to analyse again, or export the queued assessments now.
            </p>
            <div v-if="summary || lastPass" data-testid="source-sync-progress" class="mt-3 rounded-lg border border-white/10 bg-white/[0.03] px-2 py-1.5" role="status" aria-live="polite">
                <div v-if="summary" class="flex items-center gap-2">
                    <span class="text-gray-200">{{ summary }}</span>
                    <button
                        v-if="running"
                        type="button"
                        data-testid="sync-cancel"
                        :disabled="cancelling"
                        class="ml-auto rounded-md border border-red-400/30 px-2 py-0.5 text-[10px] text-red-200 hover:bg-red-500/10 disabled:opacity-50"
                        @click="cancel"
                    >Cancel</button>
                </div>
                <ul v-if="progress?.running?.length" class="mt-1 space-y-0.5 text-[10px] text-gray-400" data-testid="source-sync-running">
                    <li v-for="item in progress.running" :key="item.uuid">
                        {{ item.product || item.uuid }} {{ item.version || '' }}: {{ PHASES[item.phase || ''] || item.phase || 'starting' }}<template v-if="item.seconds !== null"> · {{ Math.round(item.seconds) }} s</template>
                    </li>
                </ul>
                <div v-if="lastPass && !progress?.pass" class="mt-1 text-[10px] text-gray-400" data-testid="source-sync-last-pass">
                    Last portfolio check: {{ lastPass.unchanged + lastPass.changed }} versions, {{ lastPass.changed }} changed
                </div>
            </div>
            <div v-if="progress?.paused" data-testid="source-sync-paused" class="mt-3 flex items-center gap-2 rounded-lg border border-amber-400/30 bg-amber-500/10 px-2 py-1.5 text-amber-100" role="status">
                <span>Sync paused after cancel<template v-if="progress.paused.until"> until {{ new Date(progress.paused.until).toLocaleString() }}</template>; requests still run.</span>
                <button type="button" data-testid="sync-resume" class="ml-auto rounded-md border border-white/10 px-2 py-0.5 text-[10px] text-gray-100 hover:bg-white/10" @click="resume">Resume</button>
            </div>
            <div v-if="loading" class="mt-3 text-gray-400">Loading…</div>
            <div v-else-if="error" class="mt-3 text-red-300" role="alert">{{ error }}</div>
            <template v-else>
                <div class="mt-3 flex flex-wrap gap-2">
                    <button type="button" data-testid="sync-read-product" class="rounded-md border border-white/10 px-2 py-1 text-gray-100 hover:bg-white/10" @click="read({ product: projectName })">
                        Read all versions again
                    </button>
                    <button v-if="canAnalyse" type="button" data-testid="sync-analyse-product" class="rounded-md border border-white/10 px-2 py-1 text-gray-100 hover:bg-white/10" @click="analyse({ product: projectName })">
                        Ask {{ sourceName }} to analyse all again
                    </button>
                    <button type="button" data-testid="sync-export-now" :disabled="exporting" class="rounded-md border border-white/10 px-2 py-1 text-gray-100 hover:bg-white/10 disabled:opacity-50" @click="exportNow">
                        Export now
                    </button>
                </div>
                <ul class="mt-3 max-h-64 space-y-1 overflow-y-auto">
                    <li v-for="version in versions" :key="version.uuid" data-testid="sync-version" class="flex items-center gap-2 rounded-lg border border-white/5 px-2 py-1">
                        <span class="font-mono text-gray-200">{{ version.version || '(no version)' }}</span>
                        <span
                            v-if="states[version.uuid]"
                            :data-testid="`sync-state-${version.uuid}`"
                            class="text-amber-200"
                            :title="requestErrors[version.uuid] || (readAt[version.uuid] ? `Read ${new Date(readAt[version.uuid]!).toLocaleString()}` : undefined)"
                        >{{ STATE_LABELS[states[version.uuid]!] }}</span>
                        <span class="ml-auto flex gap-1">
                            <button type="button" :data-testid="`sync-read-${version.uuid}`" class="rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-200 hover:bg-white/10" @click="read({ project_uuid: version.uuid })">Read again</button>
                            <button v-if="canAnalyse" type="button" :data-testid="`sync-analyse-${version.uuid}`" class="rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-200 hover:bg-white/10" @click="analyse({ project_uuid: version.uuid })">Analyse again</button>
                        </span>
                    </li>
                </ul>
                <div v-if="queue && queue.total" data-testid="sync-queue" class="mt-3">
                    <div class="text-[11px] text-gray-400">Queued ({{ queue.total }})</div>
                    <ul class="mt-1 max-h-40 space-y-0.5 overflow-y-auto text-[11px]">
                        <li v-for="item in queue.items" :key="item.uuid" data-testid="sync-queued" class="text-gray-300">
                            <span class="font-mono text-gray-200">{{ item.version || item.uuid }}</span>
                            {{ item.product }}: <span class="text-gray-400">{{ item.reason || 'waiting' }}</span><span v-if="item.requested" class="text-amber-200"> (requested)</span>
                        </li>
                    </ul>
                    <p v-if="queue.total > queue.items.length" class="mt-0.5 text-[10px] text-gray-500">and {{ queue.total - queue.items.length }} more</p>
                </div>
                <p v-if="message" data-testid="sync-message" class="mt-2 text-[11px] text-gray-300" role="status">{{ message }}</p>
            </template>
        </div>
    </div>
</template>
