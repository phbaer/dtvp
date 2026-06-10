<script setup lang="ts">
import { computed } from 'vue'
import { X } from 'lucide-vue-next'
import { useVulnModals } from '../lib/useVulnModals'

const { openModals, restoreModal, closeModal } = useVulnModals()

const minimizedModals = computed(() => {
    const result: Array<{ id: string; label: string; score: number }> = []
    for (const [id, entry] of openModals.value.entries()) {
        if (entry.minimized) {
            const score = entry.group.cvss ?? entry.group.cvss_score ?? 0
            result.push({ id, label: id, score })
        }
    }
    return result
})

const SEVERITY_TAB_CLASS: (score: number) => string = (score) => {
    if (score >= 9) return 'bg-violet-800 border-violet-600 hover:bg-violet-700'
    if (score >= 7) return 'bg-red-800 border-red-600 hover:bg-red-700'
    if (score >= 4) return 'bg-amber-800 border-amber-600 hover:bg-amber-700'
    if (score > 0) return 'bg-blue-800 border-blue-600 hover:bg-blue-700'
    return 'bg-gray-800 border-gray-600 hover:bg-gray-700'
}
</script>

<template>
    <Teleport to="body">
        <div
            v-if="minimizedModals.length > 0"
            class="fixed bottom-0 left-0 right-0 z-[10000] flex max-h-28 flex-wrap items-end gap-1 overflow-y-auto border-t border-white/10 bg-gray-950/85 px-2 pt-1.5 pointer-events-none backdrop-blur"
            style="padding-bottom: max(0.375rem, env(safe-area-inset-bottom));"
            data-testid="vuln-modal-taskbar"
        >
            <div
                v-for="modal in minimizedModals"
                :key="modal.id"
                class="pointer-events-auto flex min-w-0 flex-[1_1_9rem] items-center gap-1 border rounded-t px-2 py-1 cursor-pointer text-xs text-white font-mono max-w-[calc(50vw-0.75rem)] sm:max-w-[220px] transition-colors"
                :class="SEVERITY_TAB_CLASS(modal.score)"
                @click="restoreModal(modal.id)"
            >
                <span class="truncate grow">{{ modal.label }}</span>
                <button
                    class="shrink-0 p-0.5 rounded hover:bg-white/20 text-white/60 hover:text-white transition-colors"
                    title="Close"
                    @click.stop="closeModal(modal.id)"
                >
                    <X :size="10" />
                </button>
            </div>
        </div>
    </Teleport>
</template>
