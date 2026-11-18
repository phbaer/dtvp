<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { AlertTriangle } from '@lucide/vue'
import { getCacheStatus } from '../lib/api'

/**
 * Header warning for reviewers: assessments that are not reaching
 * Dependency-Track. Without it a failing export is only visible to whoever
 * opens the affected vulnerability or the Export tab.
 */
const emit = defineEmits<{ (e: 'open'): void }>()

const POLL_MS = 60_000
const failed = ref(0)
const oldest = ref<string | null>(null)
let timer: ReturnType<typeof setTimeout> | undefined

const total = computed(() => failed.value)
const label = computed(() => `${failed.value} failing`)
const title = computed(() => {
    const since = oldest.value ? ` The oldest change has been waiting since ${new Date(oldest.value).toLocaleString()}.` : ''
    return `Assessments not reaching Dependency-Track: ${label.value}.${since} Open the export queue.`
})

const poll = async () => {
    if (!document.hidden) {
        try {
            const status = await getCacheStatus()
            failed.value = status.failed_exports ?? 0
            oldest.value = status.oldest_pending_at ?? null
        } catch {
            // The header must not break when the backend is unreachable.
        }
    }
    timer = setTimeout(poll, POLL_MS)
}

onMounted(poll)
onUnmounted(() => {
    if (timer) clearTimeout(timer)
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
