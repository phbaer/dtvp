<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { CheckCircle, ChevronDown, ClipboardCheck, Clock, FileText, Loader2, Zap } from '@lucide/vue'
import { codeAnalysisGetPrompts } from '../lib/api'

export type RunFormComponentStatus = 'active' | 'assessed' | 'completed' | ''

const props = defineProps<{
    components: string[]
    selected: string[]
    statusOf: (component: string) => RunFormComponentStatus
    guidance: string
    /** Guidance the next analyzer request will carry. */
    launchGuidance: string
    busy?: boolean
    submitting?: boolean
    canStart?: boolean
    startLabel: string
}>()

const emit = defineEmits<{
    (e: 'toggle-component', component: string): void
    (e: 'toggle-all'): void
    (e: 'update:guidance', value: string): void
    (e: 'start'): void
}>()

const root = ref<HTMLElement | null>(null)
const dropdownOpen = ref(false)
const promptsOpen = ref(false)
const promptsLoading = ref(false)
const promptsError = ref<string | null>(null)
const promptPayload = ref<Record<string, any> | null>(null)

const selectedSet = computed(() => new Set(props.selected))
const allSelected = computed(() => props.components.length > 0 && props.components.every(c => selectedSet.value.has(c)))
const selectionLabel = computed(() => {
    const total = props.components.length
    const count = props.selected.length
    if (total === 0) return 'No team-assigned targets'
    if (count === 0) return 'Select components…'
    if (count === total) return `All Components (${total})`
    if (count === 1) return props.selected[0]
    return `${count} of ${total} components`
})
const promptBundles = computed(() => {
    const bundles = promptPayload.value?.bundles
    return Array.isArray(bundles) ? bundles : []
})

const formatPromptValueLabel = (key: unknown) =>
    String(key || 'prompt').replace(/_/g, ' ')

const statusClass = (component: string) => ({
    active: 'text-yellow-300',
    assessed: 'text-purple-300',
    completed: 'text-green-300',
    '': 'text-gray-300',
}[props.statusOf(component)])

const togglePrompts = async () => {
    promptsOpen.value = !promptsOpen.value
    if (!promptsOpen.value || promptPayload.value || promptsLoading.value) return
    promptsLoading.value = true
    promptsError.value = null
    try {
        promptPayload.value = await codeAnalysisGetPrompts({ include_values: true, system_only: false })
    } catch (err: any) {
        promptsError.value = err?.response?.data?.detail || err?.message || 'Unable to load the request context.'
    } finally {
        promptsLoading.value = false
    }
}

const closeOnOutsideClick = (event: MouseEvent) => {
    if (dropdownOpen.value && root.value && !root.value.querySelector('[data-dropdown]')?.contains(event.target as Node)) {
        dropdownOpen.value = false
    }
}
onMounted(() => document.addEventListener('click', closeOnOutsideClick))
onBeforeUnmount(() => document.removeEventListener('click', closeOnOutsideClick))
</script>

<template>
    <section ref="root" data-testid="new-analysis-section" class="rounded border border-cyan-800/50 bg-gray-900/45">
        <div class="grid items-end gap-3 p-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
            <div class="relative" data-dropdown>
                <label for="code-analysis-components" class="mb-1 block text-[11px] font-semibold uppercase text-gray-500">Components</label>
                <button
                    id="code-analysis-components"
                    type="button"
                    :disabled="busy || components.length === 0"
                    class="flex w-full cursor-pointer items-center justify-between rounded border border-gray-700 bg-gray-950 p-2 text-left text-xs focus:border-cyan-500 disabled:opacity-50"
                    :aria-expanded="dropdownOpen ? 'true' : 'false'"
                    @click="dropdownOpen = !dropdownOpen"
                >
                    <span :class="selected.length === 0 ? 'text-gray-500' : 'text-gray-200'" class="truncate">{{ selectionLabel }}</span>
                    <ChevronDown :size="12" class="shrink-0 text-gray-500 transition-transform" :class="{ 'rotate-180': dropdownOpen }" />
                </button>
                <div v-if="dropdownOpen && !busy" class="absolute z-20 mt-1 max-h-48 w-full overflow-y-auto rounded border border-gray-700 bg-gray-900 shadow-lg">
                    <label v-if="components.length > 1" class="flex cursor-pointer items-center gap-2 border-b border-gray-700/50 px-2 py-1.5 text-xs hover:bg-gray-800">
                        <input type="checkbox" :checked="allSelected" class="accent-cyan-500" @change="emit('toggle-all')" />
                        <span class="font-semibold text-gray-300">All ({{ components.length }})</span>
                    </label>
                    <label v-for="c in components" :key="c" class="flex cursor-pointer items-center gap-2 px-2 py-1.5 text-xs hover:bg-gray-800">
                        <input type="checkbox" :checked="selectedSet.has(c)" class="accent-cyan-500" @change="emit('toggle-component', c)" />
                        <Clock v-if="statusOf(c) === 'active'" :size="11" class="shrink-0 text-yellow-400" title="Analysis queued or running" />
                        <ClipboardCheck v-else-if="statusOf(c) === 'assessed'" :size="11" class="shrink-0 text-purple-400" title="Team assessment exists" />
                        <CheckCircle v-else-if="statusOf(c) === 'completed'" :size="11" class="shrink-0 text-green-400" title="Code analysis completed" />
                        <span class="truncate font-mono" :class="statusClass(c)">{{ c }}</span>
                    </label>
                </div>
            </div>

            <div>
                <label for="code-analysis-guidance" class="mb-1 block text-[11px] font-semibold uppercase text-gray-500">Additional Guidance</label>
                <input
                    id="code-analysis-guidance"
                    :value="guidance"
                    :disabled="busy || components.length === 0"
                    placeholder="e.g. Focus on HTTP request handlers..."
                    class="w-full rounded border border-gray-700 bg-gray-950 p-2 text-xs focus:border-cyan-500 disabled:opacity-50"
                    @input="emit('update:guidance', ($event.target as HTMLInputElement).value)"
                />
            </div>

            <button
                type="button"
                data-testid="code-analysis-start"
                :disabled="!canStart"
                class="flex cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded px-4 py-2 text-xs font-bold transition-colors disabled:opacity-50"
                :class="submitting ? 'border border-cyan-700/40 bg-cyan-900/40 text-cyan-400' : 'bg-cyan-600 text-white hover:bg-cyan-700'"
                @click="emit('start')"
            >
                <Loader2 v-if="submitting" :size="14" class="animate-spin" />
                <Zap v-else :size="14" />
                {{ startLabel }}
            </button>
        </div>
        <section class="space-y-2 border-t border-gray-800/90 px-4 py-3">
            <button
                type="button"
                class="inline-flex cursor-pointer items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-gray-500 hover:text-cyan-300"
                @click="togglePrompts"
            >
                <Loader2 v-if="promptsLoading" :size="12" class="animate-spin" />
                <FileText v-else :size="12" />
                {{ promptsOpen ? 'Hide analyzer request context' : 'Analyzer request context' }}
            </button>
            <div v-if="promptsOpen" class="rounded border border-gray-700/50 bg-gray-950/60 p-2">
                <div v-if="promptsLoading" class="flex items-center gap-2 text-xs text-gray-500">
                    <Loader2 :size="12" class="animate-spin" /> Loading request context
                </div>
                <div v-else-if="promptsError" class="text-xs text-amber-300">{{ promptsError }}</div>
                <div v-else-if="promptBundles.length === 0 && !launchGuidance" class="text-xs text-gray-500">
                    No analyzer request context is available.
                </div>
                <div v-else class="max-h-72 space-y-2 overflow-auto">
                    <div v-for="bundle in promptBundles" :key="bundle.bundle" class="space-y-1">
                        <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">{{ bundle.bundle }} configured prompt values (fallback, not a captured run)</div>
                        <pre
                            v-for="(value, key) in (bundle.values || {})"
                            :key="String(key)"
                            class="whitespace-pre-wrap break-words rounded bg-gray-900 p-2 text-[10px] leading-relaxed text-gray-300"
                        >{{ formatPromptValueLabel(key) }}:
{{ value }}</pre>
                    </div>
                    <div v-if="launchGuidance" class="space-y-1">
                        <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">Guidance prepared for the next analyzer request</div>
                        <pre class="whitespace-pre-wrap break-words rounded bg-gray-900 p-2 text-[10px] leading-relaxed text-gray-300">{{ launchGuidance }}</pre>
                    </div>
                </div>
            </div>
        </section>
    </section>
</template>
