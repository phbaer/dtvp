<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { getProjects } from '../lib/api'
import type { Project } from '../types'
import { Search } from 'lucide-vue-next'

const query = ref('') // Kept for client-side filtering
const allProjects = ref<Project[]>([])
const loading = ref(false)

onMounted(async () => {
    loading.value = true
    try {
        // Fetch ALL projects (empty string as per existing API logic usually implies 'all' or we might need to adjust client logic if API requires empty string for wildcard)
        // Checking dt_client.py: if name is empty, it returns all versions if specific logic isn't restricting it. 
        // Actually dt_client.get_projects handles pagination to get ALL matching.
        const data = await getProjects('') 
        allProjects.value = data
    } catch (err) {
        console.error(err)
        alert('Failed to fetch projects')
    } finally {
        loading.value = false
    }
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
  <div class="mx-auto">
    <div class="flex justify-between items-center mb-6">
        <h2 class="text-3xl font-bold">Projects</h2>
        <div class="relative w-96">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3">
                <Search :size="20" class="text-gray-500" />
            </span>
            <input 
                type="text" 
                v-model="query"
                placeholder="Filter projects..."
                class="w-full pl-10 p-2 rounded bg-gray-800 border border-gray-700 focus:border-blue-500 focus:outline-none"
            />
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
                    <router-link 
                        :to="`/project/${p.name}`"
                        class="font-bold text-lg text-blue-400 hover:text-blue-300 hover:underline"
                    >
                        {{ p.name }}
                    </router-link>
                    
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
