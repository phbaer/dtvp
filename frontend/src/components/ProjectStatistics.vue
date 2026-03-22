<script setup lang="ts">
import { computed, ref, watchEffect } from 'vue'
import type { Statistics } from '../types'
import { ShieldAlert, CheckCircle2, Info } from 'lucide-vue-next'
import { sortVersions } from '../lib/version'

const props = defineProps<{
    stats: Statistics
    projectName?: string
}>()

const severityColors: Record<string, string> = {
    'CRITICAL': 'bg-red-600',
    'HIGH': 'bg-orange-500',
    'MEDIUM': 'bg-yellow-500',
    'LOW': 'bg-green-500',
    'INFO': 'bg-blue-500',
    'UNKNOWN': 'bg-gray-500'
}

const stateColors: Record<string, string> = {
    'EXPLOITABLE': 'bg-red-500',
    'IN_TRIAGE': 'bg-amber-400',
    'FALSE_POSITIVE': 'bg-gray-500',
    'NOT_AFFECTED': 'bg-green-600',
    'RESOLVED': 'bg-blue-500',
    'NOT_SET': 'bg-purple-500',
    'MIXED': 'bg-orange-400'
}

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
const severityPlotOrder = [...severityOrder].reverse() // draw bottom-to-top during stacking/rendering

const severitySvgColors: Record<string, string> = {
    CRITICAL: '#ef4444', // red-500
    HIGH: '#f97316', // orange-500
    MEDIUM: '#eab308', // yellow-400
    LOW: '#22c55e', // green-500
    INFO: '#3b82f6', // blue-500
    UNKNOWN: '#6b7280', // gray-500
}

const maxSeverityCount = computed(() => {
    return Math.max(...Object.values(props.stats.severity_counts), 1)
})

const maxStateCount = computed(() => {
    return Math.max(...Object.values(props.stats.state_counts), 1)
})

const selectedMajor = ref<string>('')

const majorKeys = computed(() => {
    return sortVersions(Object.keys(props.stats.major_version_details || {}), true)
})

watchEffect(() => {
    if (!selectedMajor.value) {
        selectedMajor.value = majorKeys.value[0] || ''
    }
})

const versionsForSelectedMajor = computed(() => {
    if (!selectedMajor.value) return []
    const versions = Object.keys(props.stats.major_version_details?.[selectedMajor.value] || {})
    return sortVersions(versions, true)
})

const severitySeries = computed(() => {
    return severityOrder.map((sev) => {
        const values = versionsForSelectedMajor.value.map((version) => {
            return versionSeverityCounts(version)[sev] || 0
        })
        return {
            key: sev,
            color: severitySvgColors[sev],
            values,
        }
    })
})

const stackedSeries = computed(() => {
    const sums = versionsForSelectedMajor.value.map(() => 0)
    return severityPlotOrder.map((sev) => {
        const series = severitySeries.value.find((s) => s.key === sev)
        if (!series) return { key: sev, color: severitySvgColors[sev], values: [] }

        const stackedValues = series.values.map((value, index) => {
            sums[index] = sums[index] + value
            return sums[index]
        })
        return {
            ...series,
            values: stackedValues,
        }
    })
})

const rawSeries = computed(() => severitySeries.value)
const chartSeries = computed(() => stackedSeries.value)

const maxLineValue = computed(() => {
    const allValues = [...chartSeries.value, ...rawSeries.value].flatMap((s) => s.values)
    if (!allValues.length) return 1
    return Math.max(...allValues, 1)
})

const yAxisTicks = computed(() => {
    const max = maxLineValue.value
    const steps = 5
    const step = Math.max(1, Math.ceil(max / steps))
    const ticks = []
    for (let i = 0; i <= steps; i++) {
        ticks.push(Math.min(i * step, max))
    }
    if (ticks[ticks.length - 1] !== max) {
        ticks[ticks.length - 1] = max
    }
    return Array.from(new Set(ticks))
})

function chartPoints(values: number[]): string {
    const n = values.length
    if (n === 0) return ''

    const { width, height } = chartDimensions.value
    const padding = 24
    const usableWidth = width - padding * 2
    const usableHeight = height - padding * 2
    const maxValue = maxLineValue.value

    if (n === 1) {
        const x = padding + usableWidth / 2
        const y = height - padding - (values[0] / maxValue) * usableHeight
        return `${x},${y}`
    }

    return values
        .map((value, i) => {
            const x = padding + (usableWidth * i) / (n - 1)
            const y = height - padding - (value / maxValue) * usableHeight
            return `${x},${y}`
        })
        .join(' ')
}

function areaPoints(values: number[]): string {
    if (values.length === 0) return ''

    const points = chartPoints(values)
    const { width, height } = chartDimensions.value
    const padding = 24
    const bottomY = height - padding

    if (!points) return ''

    const calc = values.map((_, i) => {
        const x = padding + ((width - padding * 2) * i) / (values.length - 1)
        const y = height - padding - (values[i] / maxLineValue.value) * (height - padding * 2)
        return `${x},${y}`
    })
    if (calc.length === 0) return ''

    const first = calc[0].split(',')[0]
    const last = calc[calc.length - 1].split(',')[0]

    return `${calc.join(' ')} ${last},${bottomY} ${first},${bottomY}`
}

const chartDimensions = computed(() => {
    const width = Math.max(versionsForSelectedMajor.value.length * 80, 360)
    const height = 240
    return { width, height }
})

function versionSeverityCounts(version: string): Record<string, number> {
    return props.stats.version_severity_counts?.[version] || {}
}

function stackedSeverityValue(seriesKey: string, index: number): number {
    const ss = stackedSeries.value.find((s) => s.key === seriesKey)
    if (!ss) return 0
    return ss.values[index] ?? 0
}

</script>

<template>
  <div class="space-y-8 animate-in fade-in duration-500">
    <!-- Overview Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="bg-gray-800/50 border border-gray-700/50 p-6 rounded-xl shadow-lg backdrop-blur-sm">
            <div class="text-gray-400 text-[10px] font-bold uppercase tracking-wider mb-2">Unique Vulns</div>
            <div class="text-4xl font-black text-white">{{ stats.total_unique }}</div>
        </div>
        <div class="bg-gray-800/50 border border-gray-700/50 p-6 rounded-xl shadow-lg backdrop-blur-sm">
            <div class="text-gray-400 text-[10px] font-bold uppercase tracking-wider mb-2">Total Findings</div>
            <div class="text-4xl font-black text-blue-400">{{ stats.total_findings }}</div>
        </div>
        <div class="bg-gray-800/50 border border-gray-700/50 p-6 rounded-xl shadow-lg backdrop-blur-sm">
            <div class="text-gray-400 text-[10px] font-bold uppercase tracking-wider mb-2">Projects Affected</div>
            <div class="text-4xl font-black text-purple-400">{{ stats.affected_projects_count }}</div>
        </div>
        <div class="bg-gray-800/50 border border-gray-700/50 p-6 rounded-xl shadow-lg backdrop-blur-sm">
            <div class="text-gray-400 text-[10px] font-bold uppercase tracking-wider mb-2">High+ Criticality</div>
            <div class="text-4xl font-black text-red-500">
                {{ (stats.severity_counts['CRITICAL'] || 0) + (stats.severity_counts['HIGH'] || 0) }}
            </div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <!-- Severity Distribution -->
        <div class="bg-gray-800/50 border border-gray-700/50 p-6 rounded-xl shadow-lg backdrop-blur-sm">
            <h3 class="text-lg font-black mb-6 flex items-center gap-2 uppercase tracking-tight">
                <ShieldAlert :size="18" class="text-red-500" />
                Severity Distribution
            </h3>
            <div class="space-y-5">
                <div v-for="sev in severityOrder" :key="sev" class="space-y-1.5">
                    <div class="flex justify-between text-xs font-bold">
                        <span class="text-gray-300">{{ sev }}</span>
                        <span class="text-gray-500">{{ stats.severity_counts[sev] || 0 }}</span>
                    </div>
                    <div class="w-full bg-gray-900/50 rounded-full h-2 overflow-hidden border border-gray-700/30">
                        <div 
                            :class="['h-full transition-all duration-1000 ease-out', severityColors[sev]]"
                            :style="{ width: `${((stats.severity_counts[sev] || 0) / maxSeverityCount) * 100}%` }"
                        ></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Analysis State Distribution -->
        <div class="bg-gray-800/50 border border-gray-700/50 p-6 rounded-xl shadow-lg backdrop-blur-sm">
            <h3 class="text-lg font-black mb-6 flex items-center gap-2 uppercase tracking-tight">
                <CheckCircle2 :size="18" class="text-green-500" />
                Analysis Progress
            </h3>
            <div class="space-y-5">
                <div v-for="(count, state) in stats.state_counts" :key="state" class="space-y-1.5">
                    <div class="flex justify-between text-xs font-bold">
                        <span class="text-gray-300">{{ state }}</span>
                        <span class="text-gray-500">{{ count }}</span>
                    </div>
                    <div class="w-full bg-gray-900/50 rounded-full h-2 overflow-hidden border border-gray-700/30">
                        <div 
                            :class="['h-full transition-all duration-1000 ease-out', stateColors[state] || 'bg-gray-500']"
                            :style="{ width: `${(count / maxStateCount) * 100}%` }"
                        ></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Per-Major / Version Graph -->
    <div v-if="majorKeys.length > 0" class="bg-gray-800/50 border border-gray-700/50 p-6 rounded-xl shadow-lg backdrop-blur-sm">
        <h3 class="text-lg font-black mb-4 flex items-center gap-2 uppercase tracking-tight">
            <Info :size="18" class="text-cyan-400" />
            Vulnerabilities by Version (Major grouping)
        </h3>

        <div class="mb-4 flex flex-wrap items-center gap-2">
            <span class="text-xs font-bold text-gray-400">Major:</span>
            <button
                v-for="major in majorKeys"
                :key="major"
                class="px-2 py-1 rounded-md text-xs font-semibold"
                :class="selectedMajor === major ? 'bg-blue-500 text-white' : 'bg-gray-700 text-gray-200 hover:bg-gray-600'"
                @click="selectedMajor = major"
            >
                v{{ major }}
            </button>
        </div>

        <div class="mb-3 text-sm font-bold text-gray-200">
            Stacked vulnerability totals by severity (per version) for v{{ selectedMajor }}
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-4 mb-4">
            <div class="overflow-x-auto border border-gray-700/40 rounded-lg bg-gray-900/10 p-2">
                <svg :width="chartDimensions.width" :height="chartDimensions.height">
                    <line :x1="24" :y1="chartDimensions.height - 24" :x2="chartDimensions.width - 24" :y2="chartDimensions.height - 24" stroke="#4b5563" stroke-width="1" />
                    <line :x1="24" :y1="24" :x2="24" :y2="chartDimensions.height - 24" stroke="#4b5563" stroke-width="1" />

                    <template v-for="tick in yAxisTicks" :key="`y-axis-${tick}`">
                        <line
                            :x1="24"
                            :y1="chartDimensions.height - 24 - (tick / maxLineValue) * (chartDimensions.height - 48)"
                            :x2="chartDimensions.width - 24"
                            :y2="chartDimensions.height - 24 - (tick / maxLineValue) * (chartDimensions.height - 48)"
                            stroke="#374151"
                            stroke-width="1"
                            stroke-dasharray="2 2"
                        />
                        <text
                            x="18"
                            :y="chartDimensions.height - 24 - (tick / maxLineValue) * (chartDimensions.height - 48) + 4"
                            text-anchor="end"
                            fill="#9ca3af"
                            font-size="10"
                        >
                            {{ tick }}
                        </text>
                    </template>

                    <template v-for="series in chartSeries" :key="series.key">
                        <polygon
                            :points="areaPoints(series.values)"
                            :fill="series.color"
                            fill-opacity="0.12"
                        />
                        <polyline
                            :points="chartPoints(series.values)"
                            fill="none"
                            :stroke="series.color"
                            stroke-width="2"
                            stroke-linejoin="round"
                        />
                    </template>

                    <template v-for="series in rawSeries" :key="series.key + '-raw'">
                        <template v-for="(value, i) in series.values" :key="series.key + '-raw-' + i">
                            <circle
                                :cx="versionsForSelectedMajor.length > 1 ? 24 + (chartDimensions.width - 48) * i / (versionsForSelectedMajor.length - 1) : chartDimensions.width / 2"
                                :cy="chartDimensions.height - 24 - (stackedSeverityValue(series.key, i) / maxLineValue) * (chartDimensions.height - 48)"
                                r="2.5"
                                :fill="series.color"
                                opacity="0.95"
                            >
                                <title>{{ series.key }} raw: {{ value }}\nstacked: {{ stackedSeverityValue(series.key, i) }}</title>
                            </circle>
                            <text
                                :x="versionsForSelectedMajor.length > 1 ? 24 + (chartDimensions.width - 48) * i / (versionsForSelectedMajor.length - 1) : chartDimensions.width / 2"
                                :y="chartDimensions.height - 24 - (stackedSeverityValue(series.key, i) / maxLineValue) * (chartDimensions.height - 48) - 8"
                                text-anchor="middle"
                                fill="#d1d5db"
                                font-size="8"
                            >
                                {{ value }}
                            </text>
                        </template>
                    </template>

                    <template v-for="(version, i) in versionsForSelectedMajor" :key="'label-' + version">
                        <text
                            :x="versionsForSelectedMajor.length > 1 ? 24 + (chartDimensions.width - 48) * i / (versionsForSelectedMajor.length - 1) : chartDimensions.width / 2"
                            :y="chartDimensions.height - 6"
                            text-anchor="middle"
                            fill="#d1d5db"
                            font-size="10"
                        >
                            {{ version }}
                        </text>
                    </template>
                </svg>
            </div>

            <div class="space-y-2 p-2 border border-gray-700/40 bg-gray-900/10 rounded-lg">
                <div class="text-xs font-bold text-gray-300 uppercase tracking-wide">Legend</div>
                <div v-for="sev in severityOrder" :key="sev" class="flex items-center gap-2 text-xs">
                    <span class="w-3 h-3 rounded" :style="{ backgroundColor: severitySvgColors[sev] }"></span>
                    <span class="text-gray-200">{{ sev }}</span>
                </div>
            </div>
        </div>

        <div class="mt-2 text-xs text-gray-400">
            Y-axis: vulnerability count; X-axis: version (sorted semver).
        </div>
    </div>

    <!-- Global Summary -->
    <div v-if="!projectName" class="bg-blue-600/5 border border-blue-500/20 p-6 rounded-xl flex items-start gap-4">
        <Info :size="24" class="text-blue-500 shrink-0 mt-1" />
        <div>
            <h4 class="font-black text-blue-400 mb-1 uppercase text-sm tracking-tight">Global Intelligence</h4>
            <p class="text-xs text-gray-400 leading-relaxed font-medium">
                This view shows unique vulnerabilities across your entire catalog. Vulnerabilities appearing in multiple projects or versions are de-duplicated using DTVP's canonical ID mapping.
            </p>
        </div>
    </div>
  </div>
</template>

<style scoped>
.fade-in {
    animation: fadeIn 0.5s ease-out;
}
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}
</style>
