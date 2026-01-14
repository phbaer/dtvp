<script setup lang="ts">
import { ref, computed } from 'vue'
import { getProjects } from '../lib/api'
import type { Project } from '../types'
import { Search } from 'lucide-vue-next'

const query = ref('')
const results = ref<Project[]>([])
const loading = ref(false)

const handleSearch = async () => {
    loading.value = true
    try {
        const data = await getProjects(query.value)
        results.value = data
    } catch (err) {
        console.error(err)
        alert('Failed to fetch projects')
    } finally {
        loading.value = false
    }
}

// Deduplicate names for display
const uniqueProjects = computed(() => {
    const names = new Set(results.value.map(p => p.name))
    return Array.from(names).map(name => results.value.find(p => p.name === name)!)
})
</script>

<template>
  <div class="mx-auto">
    <h2 class="text-3xl font-bold mb-6">Find a Project</h2>
    
    <form @submit.prevent="handleSearch" class="flex gap-2 mb-8">
      <input 
          type="text" 
          v-model="query"
          placeholder="Search project name..."
          class="flex-1 p-3 rounded bg-gray-800 border border-gray-700 focus:border-blue-500 focus:outline-none"
      />
      <button 
          type="submit" 
          :disabled="loading"
          class="bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded font-semibold disabled:opacity-50 flex items-center gap-2 cursor-pointer"
      >
          <Search :size="20" />
          Search
      </button>
    </form>

    <div class="grid gap-4">
      <router-link 
          v-for="p in uniqueProjects"
          :key="p.uuid" 
          :to="`/project/${p.name}`"
          class="block p-4 bg-gray-800 hover:bg-gray-750 border border-gray-700 rounded transition-colors group"
      >
          <div class="flex justify-between items-center">
              <span class="font-semibold text-lg group-hover:text-blue-400">{{ p.name }}</span>
              <span class="text-sm text-gray-500">View Vulnerabilities &rarr;</span>
          </div>
      </router-link>
      <div v-if="results.length === 0 && !loading" class="text-center text-gray-500">No projects found.</div>
    </div>
  </div>
</template>
