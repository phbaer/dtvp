<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { CircleSlash } from '@lucide/vue'
import { getGoneFindings } from '../lib/api'
import { CARRY_OVER, REASONS } from '../lib/goneFindings'
import type { GoneFindingsOfVersion } from '../types'

// The full picture of findings Dependency-Track no longer reports, for all
// versions of a project: counts by reason and by what became of their
// assessments, and how many went per day.
const props = defineProps<{ projectName: string }>()

const versions = ref<GoneFindingsOfVersion[]>([])
const error = ref('')

const load = async () => {
    if (!props.projectName) return
    error.value = ''
    try {
        versions.value = (await getGoneFindings(props.projectName)).versions || []
    } catch {
        versions.value = []
        error.value = 'Gone findings could not be loaded.'
    }
}

const add = (into: Record<string, number>, from: Record<string, number> | undefined) => {
    for (const [key, value] of Object.entries(from || {})) into[key] = (into[key] || 0) + value
}

const totals = computed(() => {
    const byReason: Record<string, number> = {}
    const byCarryOver: Record<string, number> = {}
    let attention = 0
    let acknowledged = 0
    for (const version of versions.value) {
        add(byReason, version.summary?.by_reason)
        add(byCarryOver, version.summary?.by_carry_over)
        attention += version.summary?.needs_attention || 0
        acknowledged += version.summary?.acknowledged || 0
    }
    const total = Object.values(byReason).reduce((a, b) => a + b, 0)
    return { byReason, byCarryOver, attention, acknowledged, total }
})

const sorted = (counts: Record<string, number>) => Object.entries(counts).sort((a, b) => b[1] - a[1])

// Versions in which many findings went no longer matched at the last read.
const massVersions = computed(() =>
    versions.value
        .filter(version => version.summary?.mass_disappearance)
        .map(version => ({ version: version.version, mass: version.summary!.mass_disappearance! })),
)

// The last 30 days with something gone, oldest first.
const trend = computed(() => {
    const days: Record<string, Record<string, number>> = {}
    for (const version of versions.value) {
        for (const point of version.trend || []) {
            days[point.day] = days[point.day] || {}
            add(days[point.day], point.went)
        }
    }
    return Object.entries(days)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .slice(-30)
        .map(([day, went]) => ({ day, went, total: Object.values(went).reduce((a, b) => a + b, 0) }))
})
const trendMax = computed(() => Math.max(1, ...trend.value.map(point => point.total)))

const REASON_COLORS: Record<string, string> = {
    replaced: 'bg-sky-400',
    recreated: 'bg-teal-400',
    component_removed: 'bg-rose-400',
    no_longer_matched: 'bg-amber-400',
    undetermined: 'bg-slate-400',
    missing_at_export: 'bg-violet-400',
}

watch(() => props.projectName, () => void load())
onMounted(() => void load())
</script>

<template>
    <section
        v-if="error || totals.total > 0"
        data-testid="gone-findings-statistics"
        class="rounded-2xl border border-white/10 bg-slate-950/40 p-4"
    >
        <h3 class="flex items-center gap-2 text-sm font-semibold text-white">
            <CircleSlash :size="15" /> Gone findings
        </h3>
        <p v-if="error" class="mt-2 text-xs text-red-300" role="alert">{{ error }}</p>
        <template v-else>
            <p class="mt-1 text-xs text-gray-400" data-testid="gone-findings-statistics-total">
                {{ totals.total }} gone in all versions; {{ totals.attention }} need attention,
                {{ totals.acknowledged }} acknowledged.
            </p>
            <p
                v-for="entry in massVersions"
                :key="entry.version"
                data-testid="gone-findings-statistics-mass"
                class="mt-1 text-xs text-amber-200"
            >
                {{ entry.version || '(no version)' }}: {{ entry.mass.count }} findings went no longer matched at the last read
                ({{ Math.round(entry.mass.share * 100) }}% of the findings).
            </p>
            <div class="mt-3 grid gap-4 md:grid-cols-2">
                <div>
                    <div class="text-[11px] font-semibold uppercase tracking-wider text-gray-400">Why they went</div>
                    <ul class="mt-1 space-y-0.5 text-xs" data-testid="gone-findings-statistics-reasons">
                        <li v-for="[reason, count] in sorted(totals.byReason)" :key="reason" class="flex items-center gap-2">
                            <span class="h-2 w-2 rounded-full" :class="REASON_COLORS[reason] || 'bg-gray-400'"></span>
                            <span class="flex-1 text-gray-300">{{ REASONS[reason] || reason }}</span>
                            <span class="font-mono text-gray-200">{{ count }}</span>
                        </li>
                    </ul>
                </div>
                <div>
                    <div class="text-[11px] font-semibold uppercase tracking-wider text-gray-400">Their assessments</div>
                    <ul class="mt-1 space-y-0.5 text-xs" data-testid="gone-findings-statistics-carry-over">
                        <li v-for="[outcome, count] in sorted(totals.byCarryOver)" :key="outcome" class="flex items-center gap-2">
                            <span class="flex-1 text-gray-300">{{ CARRY_OVER[outcome] || outcome }}</span>
                            <span class="font-mono text-gray-200">{{ count }}</span>
                        </li>
                    </ul>
                </div>
            </div>
            <div v-if="trend.length" class="mt-4">
                <div class="text-[11px] font-semibold uppercase tracking-wider text-gray-400">Gone per day</div>
                <div class="mt-2 flex h-24 items-end gap-1" data-testid="gone-findings-statistics-trend">
                    <div
                        v-for="point in trend"
                        :key="point.day"
                        class="flex min-w-[6px] flex-1 flex-col-reverse overflow-hidden rounded-sm"
                        :style="{ height: `${Math.max(4, (point.total / trendMax) * 100)}%` }"
                        :title="`${point.day}: ${point.total} went (${sorted(point.went).map(([r, c]) => `${c} ${(REASONS[r] || r).toLowerCase()}`).join(', ')})`"
                    >
                        <div
                            v-for="[reason, count] in sorted(point.went)"
                            :key="reason"
                            :class="REASON_COLORS[reason] || 'bg-gray-400'"
                            :style="{ height: `${(count / point.total) * 100}%` }"
                        ></div>
                    </div>
                </div>
                <div class="mt-1 flex justify-between text-[10px] text-gray-500">
                    <span>{{ trend[0].day }}</span>
                    <span>{{ trend[trend.length - 1].day }}</span>
                </div>
                <p class="mt-1 text-[10px] text-gray-500">
                    Counted on the day each finding went; a finding that came back still counts there.
                </p>
            </div>
        </template>
    </section>
</template>
