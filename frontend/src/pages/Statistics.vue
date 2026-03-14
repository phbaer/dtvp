<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { getStatistics } from '../lib/api'
import type { Statistics } from '../types'
import { BarChart3, ShieldAlert, CheckCircle2, AlertTriangle, Info, ListFilter } from 'lucide-vue-next'

const route = useRoute()
const stats = ref<Statistics | null>(null)
const loading = ref(true)
const error = ref('')

const projectName = computed(() => route.query.name as string || '')
const cveFilter = computed(() => route.query.cve as string || '')

onMounted(async () => {
    try {
        stats.value = await getStatistics(projectName.value, cveFilter.value)
    } catch (err: any) {
        error.value = 'Failed to load statistics: ' + (err.message || err)
    } finally {
        loading.value = false
    }
})

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
    'IN_TRIAGE': 'bg-yellow-500',
    'FALSE_POSITIVE': 'bg-gray-500',
    'NOT_AFFECTED': 'bg-green-600',
    'RESOLVED': 'bg-blue-500',
    'NOT_SET': 'bg-purple-500',
    'MIXED': 'bg-orange-400'
}

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']

const maxSeverityCount = computed(() => {
    if (!stats.value) return 0
    return Math.max(...Object.values(stats.value.severity_counts), 1)
})

const maxStateCount = computed(() => {
    if (!stats.value) return 0
    return Math.max(...Object.values(stats.value.state_counts), 1)
})
</script>

<template>
  <div class="space-y-8">
    <div class="flex justify-between items-center">
        <div>
            <h2 class="text-3xl font-bold">Statistics</h2>
            <p v-if="projectName" class="text-gray-400 mt-1">Project: <span class="text-blue-400">{{ projectName }}</span></p>
            <p v-else class="text-gray-400 mt-1">Global view across all projects</p>
        </div>
        <div v-if="cveFilter" class="bg-gray-800 border border-gray-700 px-3 py-1 rounded text-sm flex items-center gap-2">
            <ListFilter :size="16" class="text-blue-400" />
            <span class="text-gray-300">Filtered by: <span class="font-mono text-blue-300">{{ cveFilter }}</span></span>
        </div>
    </div>

    <div v-if="loading" class="text-center py-20">
        <div class="animate-pulse flex flex-col items-center">
            <BarChart3 :size="48" class="text-blue-500 mb-4" />
            <div class="text-xl font-semibold">Calculating metrics...</div>
        </div>
    </div>

    <div v-else-if="error" class="bg-red-900/20 border border-red-900/50 p-6 rounded text-center text-red-400">
        {{ error }}
    </div>

    <div v-else-if="stats" class="space-y-8">
        <!-- Overview Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div class="bg-gray-800 border border-gray-700 p-6 rounded-lg shadow-lg">
                <div class="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">Unique Vulns</div>
                <div class="text-4xl font-bold text-white">{{ stats.total_unique }}</div>
            </div>
            <div class="bg-gray-800 border border-gray-700 p-6 rounded-lg shadow-lg">
                <div class="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">Total Findings</div>
                <div class="text-4xl font-bold text-blue-400">{{ stats.total_findings }}</div>
            </div>
            <div class="bg-gray-800 border border-gray-700 p-6 rounded-lg shadow-lg">
                <div class="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">Projects Affected</div>
                <div class="text-4xl font-bold text-purple-400">{{ stats.affected_projects_count }}</div>
            </div>
            <div class="bg-gray-800 border border-gray-700 p-6 rounded-lg shadow-lg">
                <div class="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">High+ Criticality</div>
                <div class="text-4xl font-bold text-red-500">
                    {{ (stats.severity_counts['CRITICAL'] || 0) + (stats.severity_counts['HIGH'] || 0) }}
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <!-- Severity Distribution -->
            <div class="bg-gray-800 border border-gray-700 p-6 rounded-lg shadow-lg">
                <h3 class="text-xl font-bold mb-6 flex items-center gap-2">
                    <ShieldAlert :size="20" class="text-red-500" />
                    Severity Distribution
                </h3>
                <div class="space-y-4">
                    <div v-for="sev in severityOrder" :key="sev" class="space-y-1">
                        <div class="flex justify-between text-sm">
                            <span class="font-medium">{{ sev }}</span>
                            <span class="text-gray-400">{{ stats.severity_counts[sev] || 0 }}</span>
                        </div>
                        <div class="w-full bg-gray-700 rounded-full h-3 overflow-hidden">
                            <div 
                                :class="['h-full transition-all duration-500', severityColors[sev]]"
                                :style="{ width: `${((stats.severity_counts[sev] || 0) / maxSeverityCount) * 100}%` }"
                            ></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Analysis State Distribution -->
            <div class="bg-gray-800 border border-gray-700 p-6 rounded-lg shadow-lg">
                <h3 class="text-xl font-bold mb-6 flex items-center gap-2">
                    <CheckCircle2 :size="20" class="text-green-500" />
                    Analysis Progress
                </h3>
                <div class="space-y-4">
                    <div v-for="(count, state) in stats.state_counts" :key="state" class="space-y-1">
                        <div class="flex justify-between text-sm">
                            <span class="font-medium text-gray-300">{{ state }}</span>
                            <span class="text-gray-400">{{ count }}</span>
                        </div>
                        <div class="w-full bg-gray-700 rounded-full h-3 overflow-hidden">
                            <div 
                                :class="['h-full transition-all duration-500', stateColors[state] || 'bg-gray-500']"
                                :style="{ width: `${(count / maxStateCount) * 100}%` }"
                            ></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Version Metrics (if project specific) -->
        <div v-if="projectName && Object.keys(stats.version_counts).length > 0" class="bg-gray-800 border border-gray-700 p-6 rounded-lg shadow-lg">
            <h3 class="text-xl font-bold mb-6 flex items-center gap-2">
                <AlertTriangle :size="20" class="text-yellow-500" />
                Vulnerabilities per Version
            </h3>
            <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                <div v-for="(count, ver) in stats.version_counts" :key="ver" class="bg-gray-700/50 p-4 rounded border border-gray-600">
                    <div class="text-xs text-gray-400 uppercase font-bold mb-1">v{{ ver }}</div>
                    <div class="text-2xl font-bold">{{ count }}</div>
                </div>
            </div>
        </div>

        <!-- Global Summary -->
        <div v-if="!projectName" class="bg-blue-900/10 border border-blue-900/30 p-6 rounded-lg flex items-start gap-4">
            <Info :size="24" class="text-blue-500 shrink-0 mt-1" />
            <div>
                <h4 class="font-bold text-blue-400 mb-1">Global Intelligence</h4>
                <p class="text-sm text-gray-400 leading-relaxed">
                    This view shows unique vulnerabilities across your entire catalog. Vulnerabilities appearing in multiple projects or versions are de-duplicated using DTVP's canonical ID mapping.
                </p>
            </div>
        </div>
    </div>
  </div>
</template>
