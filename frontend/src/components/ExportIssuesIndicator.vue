<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { AlertTriangle } from '@lucide/vue'
import { getCacheStatus } from '../lib/api'
import { eventStream, useServerEvents } from '../lib/eventStream'

/**
 * Header warning for reviewers: assessments that are not reaching
 * Dependency-Track. Without it a failing export is only visible to whoever
 * opens the affected vulnerability or the Export tab.
 *
 * The numbers follow the `export.state` event; polling runs only while the
 * live-update stream is down. A load skipped while the tab was hidden runs
 * when it becomes visible, because no event repeats the current numbers.
 */
const emit = defineEmits<{ (e: 'open'): void }>()

const POLL_MS = 60_000
const failed = ref(0)
const oldest = ref<string | null>(null)
let timer: ReturnType<typeof setTimeout> | undefined
let mounted = false
// Counts export.state events, so a response requested before the latest
// event does not overwrite it.
let eventCount = 0
// A load was skipped while the tab was hidden.
let loadPending = false

const onVisibilityChange = () => {
    if (!document.hidden && mounted && loadPending) void load()
}

const total = computed(() => failed.value)
const label = computed(() => `${failed.value} failing`)
const title = computed(() => {
    const since = oldest.value ? ` The oldest change has been waiting since ${new Date(oldest.value).toLocaleString()}.` : ''
    return `Assessments not reaching Dependency-Track: ${label.value}.${since} Open the export queue.`
})

const load = async () => {
    if (document.hidden) {
        loadPending = true
        return
    }
    loadPending = false
    const seenEvents = eventCount
    try {
        const status = await getCacheStatus()
        if (seenEvents !== eventCount) return
        failed.value = status.failed_exports ?? 0
        oldest.value = status.oldest_pending_at ?? null
    } catch {
        // The header must not break when the backend is unreachable.
    }
}

const schedule = () => {
    if (timer) clearTimeout(timer)
    timer = undefined
    if (!mounted || eventStream.status.value === 'live') return
    timer = setTimeout(async () => {
        timer = undefined
        await load()
        schedule()
    }, POLL_MS)
}

useServerEvents('export.state', event => {
    eventCount += 1
    failed.value = Number(event.data?.failed ?? 0)
    oldest.value = event.data?.oldest_pending_at ?? null
})
useServerEvents(['hello', 'resync'], () => {
    void load()
})
watch(() => eventStream.status.value, schedule)

onMounted(async () => {
    mounted = true
    document.addEventListener('visibilitychange', onVisibilityChange)
    await load()
    schedule()
})
onUnmounted(() => {
    mounted = false
    document.removeEventListener('visibilitychange', onVisibilityChange)
    if (timer) clearTimeout(timer)
    timer = undefined
})
</script>

<template>
    <button
        v-if="total > 0"
        type="button"
        class="inline-flex items-center gap-1.5 rounded-full border border-amber-500/60 bg-amber-500/10 px-3 py-1.5 text-[10px] font-black uppercase tracking-widest text-amber-200 hover:bg-amber-500/20"
        :title="title"
        data-testid="export-issues-indicator"
        @click="emit('open')"
    >
        <AlertTriangle :size="13" aria-hidden="true" />
        Export: {{ label }}
    </button>
</template>
