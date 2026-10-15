<script setup lang="ts">
import { computed, useId } from 'vue'
import type { ChartSegment } from '../lib/statisticsCharts'

const props = withDefaults(defineProps<{
    title: string
    segments: readonly ChartSegment[]
    updating?: boolean
    compact?: boolean
}>(), { updating: false, compact: false })

const titleId = useId()
const segments = computed(() => props.segments.map(segment => ({
    ...segment, value: Number.isFinite(segment.value) && segment.value > 0 ? segment.value : 0,
})))
const total = computed(() => segments.value.reduce((sum, segment) => sum + segment.value, 0))
const slices = computed(() => {
    let offset = 0
    return segments.value.filter(segment => segment.value > 0).map(segment => {
        const share = total.value ? segment.value / total.value * 100 : 0
        const slice = { ...segment, share, offset }
        offset += share
        return slice
    })
})
const percent = (value: number) => `${total.value ? (value / total.value * 100).toFixed(1) : '0.0'}%`
</script>

<template>
    <div :aria-busy="updating" class="space-y-3" data-testid="donut-chart">
        <p v-if="updating" role="status" class="text-xs text-gray-400">Updating chart…</p>
        <div v-else class="flex items-center gap-5" :class="compact ? 'flex-col' : 'flex-col sm:flex-row'">
            <svg viewBox="0 0 120 120" role="img" :aria-labelledby="titleId" class="shrink-0" :class="compact ? 'w-32' : 'w-40 sm:w-44'">
                <title :id="titleId">{{ title }}: {{ total }} vulnerabilities</title>
                <circle cx="60" cy="60" r="46" fill="none" stroke="#374151" stroke-width="18" />
                <circle v-for="slice in slices" :key="slice.label"
                    cx="60" cy="60" r="46" fill="none" :stroke="slice.color" stroke-width="18"
                    pathLength="100" :stroke-dasharray="`${slice.share} ${100 - slice.share}`"
                    :stroke-dashoffset="-slice.offset" transform="rotate(-90 60 60)"
                    data-testid="donut-slice">
                    <title>{{ slice.label }}: {{ slice.value }} ({{ percent(slice.value) }})</title>
                </circle>
                <text x="60" y="59" text-anchor="middle" fill="#f3f4f6" font-size="18" font-weight="700">{{ total }}</text>
                <text x="60" y="73" text-anchor="middle" fill="#9ca3af" font-size="8">VULNERABILITIES</text>
            </svg>
            <div class="w-full min-w-0 space-y-2 text-xs">
                <p v-if="!total" class="text-gray-400">No data for this chart.</p>
                <div v-for="segment in segments" :key="segment.label" class="flex items-center gap-2" data-testid="donut-legend-row">
                    <span class="h-2.5 w-2.5 shrink-0 rounded-sm" :style="{ backgroundColor: segment.color }" aria-hidden="true"></span>
                    <span class="min-w-0 flex-1 break-words text-gray-300">{{ segment.label }}</span>
                    <span class="tabular-nums text-gray-200">{{ segment.value }}</span>
                    <span class="w-12 text-right tabular-nums text-gray-400">{{ percent(segment.value) }}</span>
                </div>
            </div>
        </div>
    </div>
</template>
