<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { Loader2, RefreshCw } from '@lucide/vue'
import {
    exportAssessments,
    getProjects,
    getSyncSource,
    getSyncVersions,
    requestSourceAnalysis,
    requestSyncRead,
    type SyncRequestTarget,
    type SyncSourceInfo,
} from '../lib/api'
import { useServerEvents } from '../lib/eventStream'

// Reviewers trigger work on the source by hand: read versions again now,
// ask the source to analyse them again, export the queued assessments now.
// The progress comes from the live events of the background sync.
const props = defineProps<{ projectName: string }>()

interface Version { uuid: string; version: string }
type State = 'requested' | 'queued' | 'syncing' | 'analysing' | 'done' | 'failed'

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

const sourceName = computed(() => source.value?.name || 'the source')
const canAnalyse = computed(() => Boolean(source.value?.can_request_analysis))
const busy = computed(() => Object.values(states.value).some(s => s !== 'done' && s !== 'failed'))

const STATE_LABELS: Record<State, string> = {
    requested: 'requested',
    queued: 'queued',
    syncing: 'reading',
    analysing: 'analysing',
    done: 'read',
    failed: 'failed',
}

const byVersionDescending = (left: Version, right: Version) =>
    right.version.localeCompare(left.version, undefined, { numeric: true, sensitivity: 'base' })

const load = async () => {
    loading.value = true
    error.value = ''
    try {
        const [projects, info, synced] = await Promise.all([
            getProjects(props.projectName),
            getSyncSource(),
            getSyncVersions(props.projectName).catch(() => []),
        ])
        source.value = info
        // A request's progress as the server keeps it (it outlives the page).
        const fromServer: Record<string, State> = {}
        const errors: Record<string, string> = {}
        for (const version of synced) {
            const request = version.request
            if (!request) continue
            fromServer[version.project_uuid] = request.state === 'running' ? 'syncing'
                : request.state === 'done' ? 'done'
                : request.state === 'failed' ? 'failed'
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
        </button>
        <div
            v-if="open"
            data-testid="source-sync-panel"
            class="absolute right-0 z-40 mt-2 w-[26rem] max-w-[90vw] rounded-xl border border-white/10 bg-slate-950 p-3 text-left text-xs shadow-2xl"
        >
            <div class="font-semibold text-white">{{ sourceName }}</div>
            <p class="mt-1 text-[11px] leading-snug text-gray-400">
                DTVP reads every version in the background. Read again now, ask
                {{ sourceName }} to analyse again, or export the queued assessments now.
            </p>
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
                <p v-if="message" data-testid="sync-message" class="mt-2 text-[11px] text-gray-300" role="status">{{ message }}</p>
            </template>
        </div>
    </div>
</template>
