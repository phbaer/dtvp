<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { GripHorizontal, Maximize2, Minimize2, X } from 'lucide-vue-next'

const expanded = ref(false)
const dialog = ref<HTMLElement | null>(null)
const expandButton = ref<HTMLButtonElement | null>(null)
let previousActiveElement: HTMLElement | null = null
let previousBodyOverflow = ''

const focusableSelector = [
    'button:not([disabled])',
    '[href]',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
].join(',')

const setExpanded = async (value: boolean) => {
    if (expanded.value === value) return
    if (value) {
        previousActiveElement = document.activeElement instanceof HTMLElement
            ? document.activeElement
            : expandButton.value
        previousBodyOverflow = document.body.style.overflow
        document.body.style.overflow = 'hidden'
    }
    expanded.value = value
    await nextTick()
    if (value) {
        dialog.value?.querySelector<HTMLElement>('[data-testid="close-llm-conversation-dialog"]')?.focus()
    } else {
        document.body.style.overflow = previousBodyOverflow
        const focusTarget = previousActiveElement?.isConnected ? previousActiveElement : expandButton.value
        focusTarget?.focus()
        previousActiveElement = null
    }
}

const handleKeydown = (event: KeyboardEvent) => {
    if (!expanded.value) return
    if (event.key === 'Escape') {
        event.preventDefault()
        void setExpanded(false)
        return
    }
    if (event.key !== 'Tab' || !dialog.value) return

    const focusable = [...dialog.value.querySelectorAll<HTMLElement>(focusableSelector)]
        .filter(element => !element.hasAttribute('disabled') && element.tabIndex !== -1)
    if (!focusable.length) {
        event.preventDefault()
        dialog.value.focus()
        return
    }
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
    }
}

onMounted(() => document.addEventListener('keydown', handleKeydown))
onBeforeUnmount(() => {
    document.removeEventListener('keydown', handleKeydown)
    if (expanded.value) document.body.style.overflow = previousBodyOverflow
})
</script>

<template>
    <Teleport to="body" :disabled="!expanded">
        <div
            :class="expanded
                ? 'fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-3 backdrop-blur-sm sm:p-6'
                : 'relative'"
            @mousedown.self="expanded && setExpanded(false)"
        >
            <section
                ref="dialog"
                :role="expanded ? 'dialog' : undefined"
                :aria-modal="expanded ? 'true' : undefined"
                :aria-label="expanded ? 'LLM conversation' : undefined"
                :tabindex="expanded ? -1 : undefined"
                class="flex min-h-0 flex-col overflow-hidden bg-gray-950"
                :class="expanded
                    ? 'h-[90vh] w-[96vw] max-w-7xl rounded-lg border border-gray-600 shadow-2xl shadow-black/70'
                    : 'border-t border-gray-700/50'"
                data-testid="llm-conversation-viewport"
            >
                <header class="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-gray-800 bg-gray-950/95 px-3 py-2.5">
                    <div class="min-w-0">
                        <div class="text-[11px] font-bold uppercase tracking-wider text-gray-300">
                            Conversation timeline
                        </div>
                        <div class="mt-0.5 text-[10px] text-gray-500">
                            Requests, tool activity, and model responses are separated by source.
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        <span v-if="!expanded" class="hidden items-center gap-1 text-[10px] text-gray-600 lg:flex">
                            <GripHorizontal :size="12" />
                            Drag the bottom-right corner to resize
                        </span>
                        <button
                            v-if="!expanded"
                            ref="expandButton"
                            type="button"
                            class="inline-flex items-center gap-1.5 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold text-gray-300 transition-colors hover:border-cyan-700 hover:text-cyan-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/60"
                            aria-haspopup="dialog"
                            :aria-expanded="expanded"
                            data-testid="open-llm-conversation-dialog"
                            @click="setExpanded(true)"
                        >
                            <Maximize2 :size="12" />
                            Open large view
                        </button>
                        <button
                            v-else
                            type="button"
                            class="inline-flex items-center gap-1.5 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold text-gray-300 transition-colors hover:border-gray-500 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/60"
                            data-testid="close-llm-conversation-dialog"
                            @click="setExpanded(false)"
                        >
                            <Minimize2 :size="12" />
                            Return inline
                            <X :size="12" class="ml-0.5 text-gray-500" />
                        </button>
                    </div>
                </header>

                <div
                    class="min-h-0 overflow-auto"
                    :class="expanded
                        ? 'flex-1 overscroll-contain p-4 sm:p-5'
                        : 'h-[32rem] min-h-72 max-h-[70vh] resize-y overscroll-auto p-3'"
                    data-testid="llm-conversation-scroll-region"
                >
                    <slot />
                </div>
            </section>
        </div>
    </Teleport>
</template>
