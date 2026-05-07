<script setup lang="ts">
import { computed, inject, onMounted, ref } from 'vue'
import { getProjects } from '../lib/api'
import { getRuntimeConfig } from '../lib/env'
import type { Project } from '../types'
import { Search } from 'lucide-vue-next'

const query = ref(getRuntimeConfig('DTVP_DEFAULT_PROJECT_FILTER', '')) // Kept for client-side filtering
const cveFilter = ref('') // Optional global CVE filter
const realRole = inject<any>('realRole', ref('ANALYST'))
const allProjects = ref<Project[]>([])
const loading = ref(false)

const fetchProjects = async () => {
    loading.value = true
    try {
        const data = await getProjects()
        allProjects.value = data
    } catch (err) {
        console.error(err)
        alert('Failed to fetch projects')
    } finally {
        loading.value = false
    }
}

onMounted(() => {
    void fetchProjects()
})

// Grouping logic
interface GroupedProject {
    name: string;
    versions: Project[];
}

interface ClassifierGroup {
    classifier: string;
    projects: GroupedProject[];
}

const groupedProjects = computed(() => {
    // 1. Filter by client-side query
    let filtered = allProjects.value
    if (query.value) {
        const q = query.value.toLowerCase()
        filtered = filtered.filter(p => p.name.toLowerCase().includes(q))
    }

    // 2. Group by Classifier -> Name -> Versions
    const groups: Record<string, Record<string, Project[]>> = {}

    for (const p of filtered) {
        const classifier = p.classifier || 'Unclassified' // Handle missing classifier
        if (!groups[classifier]) {
            groups[classifier] = {}
        }
        const group = groups[classifier]!;
        if (!group[p.name]) {
            group[p.name] = []
        }
        group[p.name]!.push(p)
    }

    // 3. Convert to array and Sort
    const result: ClassifierGroup[] = Object.keys(groups).sort().map(classifier => {
        const group = groups[classifier]!;
        const projectNames = Object.keys(group).sort()
        const projects: GroupedProject[] = projectNames.map(name => {
            const versions = group[name]!.sort((a, b) => {
                // Simple version sort for now, ideally semver but lexicographical is often good enough for basic display
                // or we can try to use a natural sort order if needed.
                return b.version.localeCompare(a.version, undefined, { numeric: true, sensitivity: 'base' })
            })
            return { name, versions }
        })
        return { classifier, projects }
    })

    return result
})
</script>

<template>
  <div class="w-full px-6 sm:px-8">
    <div class="flex flex-col gap-6 md:justify-between md:items-start mb-8">
        <h2 class="text-3xl font-bold pb-4 mt-4">Projects</h2>
        <div class="sticky top-20 z-30 pb-4 pt-4 sm:pt-6 -mx-6 sm:-mx-8 px-6 sm:px-8">
            <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-2">
                <div class="flex flex-col gap-2 w-full max-w-sm">
                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Project filter</label>
                    <div class="relative w-full">
                        <span class="absolute inset-y-0 left-0 flex items-center pl-3">
                            <Search :size="20" class="text-gray-500" />
                        </span>
                        <input 
                            type="text" 
                            v-model="query"
                            placeholder="Filter projects..."
                            class="bg-black/40 border border-white/10 rounded-xl px-3 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600 w-full pl-10"
                        />
                    </div>
                </div>
                <div class="flex flex-col gap-2 w-full max-w-sm">
                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">CVE filter</label>
                    <div class="relative w-full">
                        <span class="absolute inset-y-0 left-0 flex items-center pl-3">
                            <Search :size="20" class="text-gray-500" />
                        </span>
                        <input 
                            type="text" 
                            v-model="cveFilter"
                            placeholder="Global CVE filter..."
                            class="bg-black/40 border border-white/10 rounded-xl px-3 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600 w-full pl-10"
                        />
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div v-if="loading" class="text-center text-gray-500 py-8">Loading projects...</div>

    <div v-else class="space-y-8">
        <div v-for="group in groupedProjects" :key="group.classifier">
            <h3 class="text-xl font-semibold mb-4 text-gray-400 uppercase tracking-wider text-sm">{{ group.classifier }}</h3>
            
            <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                <div 
                    v-for="p in group.projects" 
                    :key="p.name"
                    class="bg-gray-800 border border-gray-700 rounded p-4 flex flex-col gap-2"
                >
                    <div class="flex items-start justify-between gap-3">
                        <router-link 
                            :to="{ path: `/project/${p.name}`, query: cveFilter ? { id: cveFilter } : {} }"
                            class="font-bold text-lg text-blue-400 hover:text-blue-300 hover:underline"
                        >
                            {{ p.name }}
                        </router-link>
                        <router-link
                            v-if="realRole === 'REVIEWER'"
                            :to="`/project/${p.name}/tmrescore`"
                            class="shrink-0 rounded-lg border border-blue-500/30 bg-blue-600/10 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-blue-200 transition-colors hover:bg-blue-600/20"
                        >
                            Threat Model
                        </router-link>
                    </div>
                    
                    <div class="flex flex-wrap gap-2 mt-2">
                        <span 
                            v-for="ver in p.versions"
                            :key="ver.uuid"
                            class="px-2 py-1 bg-gray-700 rounded text-sm text-gray-300 border border-gray-600"
                        >
                            v{{ ver.version }}
                        </span>
                    </div>
                </div>
            </div>
        </div>

        <div v-if="groupedProjects.length === 0 && !loading" class="text-center text-gray-500">
            No projects found matching your filter.
        </div>
    </div>
  </div>
</template>
