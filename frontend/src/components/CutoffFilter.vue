<script setup lang="ts">
// The cutoff (ADR 0015): a date, or a number of days before today, on the
// published or the first-attributed date.
import { computed, ref, useId } from 'vue'
import { CalendarClock, Info, X } from '@lucide/vue'
import { getCutoffPresetDays } from '../lib/cutoffPresets'
import {
    CUTOFF_BASIS_OPTIONS,
    CUTOFF_DISCLAIMER,
    CUTOFF_DOCS_URL,
    CUTOFF_NOTE,
    cutoffDate,
    isRelativeCutoff,
    normalizeCutoff,
    type CutoffBasis,
    type CutoffMode,
} from '../lib/cutoff'

const props = defineProps<{
    cutoff: string
    mode: CutoffMode
    basis?: CutoffBasis
    /** Vulnerabilities the cutoff keeps, with the other filters. */
    count?: number
    /** Listed vulnerabilities whose findings in scope have no first-seen date. */
    unknownCount?: number
}>()

const emit = defineEmits<{
    'update:cutoff': [value: string]
    'update:mode': [value: CutoffMode]
    'update:basis': [value: CutoffBasis]
}>()

const noteId = useId()
const helpId = useId()
const showHelp = ref(false)
const basisDetail = computed(() => CUTOFF_BASIS_OPTIONS.find(option => option.value === (props.basis || 'published'))?.detail || '')

const presets = getCutoffPresetDays()
const isActive = computed(() => !!normalizeCutoff(props.cutoff))
const dateValue = computed(() => cutoffDate(props.cutoff))
const relativeDays = computed(() => isRelativeCutoff(props.cutoff) ? Number(props.cutoff.slice(0, -1)) : null)

const onDate = (value: string) => emit('update:cutoff', normalizeCutoff(value))
const presetClass = (active: boolean) => [
    'px-2.5 py-0.5 rounded-full text-[10px] font-medium transition-all border focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400 active:scale-95',
    active ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/20' : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white',
]
</script>

<template>
    <div class="space-y-1.5" data-testid="cutoff-filter" :aria-describedby="noteId">
        <div class="flex items-center gap-1.5">
            <select
                :value="basis || 'published'"
                data-testid="cutoff-basis"
                aria-label="Cutoff basis"
                :title="basisDetail"
                class="h-8 min-w-0 flex-1 rounded-lg border border-white/10 bg-black/40 px-1.5 text-xs text-gray-200 focus:border-cyan-500/50 focus:outline-none"
                @change="emit('update:basis', ($event.target as HTMLSelectElement).value === 'attributed' ? 'attributed' : 'published')"
            >
                <option v-for="option in CUTOFF_BASIS_OPTIONS" :key="option.value" :value="option.value">{{ option.label }}</option>
            </select>
            <button
                type="button"
                data-testid="cutoff-help-toggle"
                class="inline-flex h-7 w-7 items-center justify-center rounded-full text-gray-400 hover:bg-white/10 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400"
                :aria-expanded="showHelp"
                :aria-controls="helpId"
                :title="`${CUTOFF_BASIS_OPTIONS.map(option => option.help).join(' ')} ${CUTOFF_NOTE}`"
                @click="showHelp = !showHelp"
            >
                <Info :size="13" />
                <span class="sr-only">Which date to use</span>
            </button>
        </div>
        <div
            v-if="showHelp"
            :id="helpId"
            role="note"
            data-testid="cutoff-help"
            class="space-y-1.5 rounded-lg border border-white/10 bg-white/3 p-2 text-[10px] leading-snug text-gray-300"
        >
            <p v-for="option in CUTOFF_BASIS_OPTIONS" :key="option.value" :data-testid="`cutoff-help-${option.value}`">
                <span class="font-semibold text-gray-100">{{ option.label }}.</span> {{ option.help }}
            </p>
            <p class="text-amber-200/90">{{ CUTOFF_NOTE }}</p>
            <p class="text-gray-500">{{ CUTOFF_DISCLAIMER }} <a :href="CUTOFF_DOCS_URL" target="_blank" rel="noopener" class="text-blue-300 hover:text-blue-200" data-testid="cutoff-help-docs">Learn more</a></p>
        </div>
        <div class="flex items-center gap-1.5">
            <select
                :value="mode"
                data-testid="cutoff-mode"
                aria-label="Cutoff mode"
                class="h-8 rounded-lg border border-white/10 bg-black/40 px-1.5 text-xs text-gray-200 focus:border-cyan-500/50 focus:outline-none"
                @change="emit('update:mode', ($event.target as HTMLSelectElement).value === 'after' ? 'after' : 'before')"
            >
                <option value="before">On or before</option>
                <option value="after">After</option>
            </select>
            <div class="relative min-w-0 flex-1">
                <CalendarClock :size="12" class="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                    type="date"
                    :value="dateValue"
                    data-testid="cutoff-date"
                    aria-label="Cutoff date"
                    class="h-8 w-full min-w-0 rounded-lg border border-white/10 bg-black/40 pl-6 pr-1 text-xs text-gray-200 [color-scheme:dark] focus:border-cyan-500/50 focus:outline-none"
                    :class="isActive ? 'border-cyan-500/30' : ''"
                    @change="onDate(($event.target as HTMLInputElement).value)"
                />
            </div>
        </div>
        <div class="flex flex-wrap items-center gap-1.5">
            <span class="text-[10px] text-gray-500">Rolling:</span>
            <button
                v-for="preset in presets"
                :key="preset"
                type="button"
                :data-testid="`cutoff-preset-${preset}d`"
                :aria-pressed="relativeDays === preset"
                :class="presetClass(relativeDays === preset)"
                :title="`${preset} days before today, moving with the date`"
                @click="emit('update:cutoff', `${preset}d`)"
            >{{ preset }} days ago</button>
            <span
                v-if="count != null && isActive"
                class="ml-auto rounded-md bg-black/20 px-1.5 py-0.5 text-[9px] text-white"
                data-testid="cutoff-count"
                title="Vulnerabilities the cutoff keeps with the other filters"
            >{{ count }}</span>
            <button
                v-if="isActive"
                type="button"
                data-testid="cutoff-clear"
                class="inline-flex h-7 w-7 items-center justify-center rounded-full text-gray-400 hover:bg-white/10 hover:text-white"
                title="Clear the cutoff"
                @click="emit('update:cutoff', '')"
            >
                <X :size="12" />
                <span class="sr-only">Clear the cutoff</span>
            </button>
        </div>
        <p v-if="relativeDays != null" class="text-[10px] text-gray-500">{{ relativeDays }} days before today, moving with the date.</p>
        <p
            v-if="isActive && unknownCount"
            class="text-[10px] text-amber-300/90"
            data-testid="cutoff-unknown"
        >{{ unknownCount }} listed without a {{ (basis || 'published') === 'attributed' ? 'first-attributed' : 'published' }} date</p>
        <p v-if="isActive" class="text-[10px] text-gray-500">{{ basisDetail }}.</p>
        <p :id="noteId" class="text-[10px] text-gray-500" :class="isActive && !showHelp ? '' : 'sr-only'" data-testid="cutoff-note">{{ CUTOFF_NOTE }}</p>
    </div>
</template>
