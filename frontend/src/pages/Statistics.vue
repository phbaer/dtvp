<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { getStatistics } from '../lib/api'
import type { Statistics } from '../types'
import { BarChart3, ListFilter } from 'lucide-vue-next'
import ProjectStatistics from '../components/ProjectStatistics.vue'

const route = useRoute()
const stats = ref<Statistics | null>(null)
const loading = ref(true)
const error = ref('')

const projectName = computed(() => route.query.name as string || '')
const idFilter = computed(() => (route.query.id || route.query.cve) as string || '')

onMounted(async () => {
    try {
        stats.value = await getStatistics(projectName.value, idFilter.value)
    } catch (err: any) {
        error.value = 'Failed to load statistics: ' + (err.message || err)
    } finally {
        loading.value = false
    }
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
        <div v-if="idFilter" class="bg-gray-800 border border-gray-700 px-3 py-1 rounded text-sm flex items-center gap-2">
            <ListFilter :size="16" class="text-blue-400" />
            <span class="text-gray-300">Filtered by: <span class="font-mono text-blue-300">{{ idFilter }}</span></span>
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
        <ProjectStatistics :stats="stats" :projectName="projectName" />
    </div>
  </div>
</template>
