<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref } from 'vue'
import { History, X } from '@lucide/vue'
import type { ProjectActivity } from '../lib/useProjectActivityHistory'

const props = defineProps<{
    entries: ProjectActivity[]
    persistent: boolean
    busy: boolean
    error: string
}>()
const emit = defineEmits<{
    (event: 'open', entry: ProjectActivity): void
    (event: 'clear'): void
}>()
const trigger = ref<HTMLButtonElement | null>(null)
const panel = ref<HTMLElement | null>(null)
const isOpen = ref(false)
const changesOnly = ref(false)
const visible = computed(() => props.entries.filter(entry => !changesOnly.value || entry.action === 'updated'))
const position = ref<Record<string, string>>({})
const place = () => {
    const bounds = trigger.value?.getBoundingClientRect()
    if (!bounds) return
    const width = Math.min(400, window.innerWidth - 16)
    const top = Math.min(bounds.bottom + 4, window.innerHeight - 100)
    position.value = {
        position: 'fixed', width: `${width}px`, top: `${Math.max(8, top)}px`,
        left: `${Math.max(8, Math.min(bounds.right - width, window.innerWidth - width - 8))}px`,
        maxHeight: `${Math.max(80, window.innerHeight - Math.max(8, top) - 8)}px`, zIndex: '11000',
    }
}
const close = (focus = false) => {
    isOpen.value = false
    if (focus) trigger.value?.focus()
}
const toggle = async () => {
    if (isOpen.value) { close(); return }
    isOpen.value = true
    await nextTick()
    place()
    panel.value?.focus()
}
const outside = (event: PointerEvent) => {
    const target = event.target as Node
    if (!trigger.value?.contains(target) && !panel.value?.contains(target)) close()
}
const escape = (event: KeyboardEvent) => {
    if (isOpen.value && event.key === 'Escape') {
        event.stopPropagation()
        close(true)
    }
}
const openEntry = (entry: ProjectActivity) => { close(); emit('open', entry) }
window.addEventListener('pointerdown', outside)
window.addEventListener('keydown', escape)
window.addEventListener('resize', place)
onBeforeUnmount(() => {
    window.removeEventListener('pointerdown', outside)
    window.removeEventListener('keydown', escape)
    window.removeEventListener('resize', place)
})
</script>

<template>
    <button
        ref="trigger" type="button" data-testid="project-activity-toggle"
        aria-label="Recent vulnerability activity" aria-haspopup="dialog" :aria-expanded="isOpen"
        :disabled="busy" title="Recently opened and changed vulnerabilities"
        class="inline-flex h-10 shrink-0 items-center gap-2 rounded-xl border border-white/10 bg-slate-950/35 px-3 text-xs font-semibold text-slate-200 hover:bg-slate-900/55 disabled:opacity-50"
        @click="toggle"
    >
        <History :size="14" aria-hidden="true" /><span class="hidden sm:inline">History</span>
    </button>
    <span v-if="error" role="alert" class="min-w-0 max-w-48 break-words text-xs text-red-300">{{ error }}</span>
    <Teleport to="body">
        <section
            v-if="isOpen" ref="panel" role="dialog" aria-label="Recent vulnerability activity" tabindex="-1"
            data-testid="project-activity-menu" :style="position"
            class="overflow-y-auto rounded-xl border border-gray-600 bg-gray-950 p-3 text-sm text-gray-200 shadow-2xl"
        >
            <div class="flex items-center justify-between gap-2">
                <h2 class="font-semibold">Recent vulnerability activity</h2>
                <button type="button" aria-label="Close activity history" class="rounded p-1 hover:bg-white/10" @click="close(true)"><X :size="16" /></button>
            </div>
            <p class="mt-1 text-xs text-gray-400">{{ persistent ? 'Last 50 activities for your account and this project in this browser.' : 'History is available until this page reloads; browser storage is unavailable.' }}</p>
            <div class="my-3 flex items-center justify-between gap-2 text-xs">
                <label class="flex items-center gap-2"><input v-model="changesOnly" type="checkbox">Changes only</label>
                <button type="button" :disabled="!entries.length" class="rounded px-2 py-1 text-gray-400 hover:bg-white/10 disabled:opacity-50" @click="emit('clear')">Clear history</button>
            </div>
            <ol v-if="visible.length" class="space-y-1">
                <li v-for="(entry, index) in visible" :key="`${entry.id}-${entry.at}-${entry.action}-${index}`">
                    <button type="button" class="w-full rounded border border-gray-800 px-3 py-2 text-left hover:bg-gray-800 focus-visible:outline focus-visible:outline-blue-400" @click="openEntry(entry)">
                        <span class="block break-all font-mono font-semibold text-blue-200">{{ entry.id }}</span>
                        <span v-if="entry.title" class="block truncate text-xs text-gray-400">{{ entry.title }}</span>
                        <span class="mt-1 flex flex-wrap justify-between gap-1 text-xs">
                            <span :class="entry.action === 'updated' ? 'text-emerald-300' : 'text-gray-400'">{{ entry.action === 'updated' ? 'Assessment updated' : 'Opened' }}</span>
                            <time :datetime="new Date(entry.at).toISOString()" class="text-gray-500">{{ new Date(entry.at).toLocaleString() }}</time>
                        </span>
                    </button>
                </li>
            </ol>
            <p v-else class="py-3 text-gray-400">{{ changesOnly ? 'No assessment changes recorded yet.' : 'No recent vulnerability activity.' }}</p>
        </section>
    </Teleport>
</template>
