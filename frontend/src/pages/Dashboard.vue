<script setup lang="ts">
import { computed, inject, ref, watch } from 'vue'
import { getProjectArchiveTaskDownloadUrl, getProjects, startProjectArchiveExport, waitForProjectArchiveTask } from '../lib/api'
import { getRuntimeConfig } from '../lib/env'
import type { Project, ProjectArchiveTask } from '../types'
import { Archive, Download, Loader2, Search } from 'lucide-vue-next'

const query = ref(getRuntimeConfig('DTVP_DEFAULT_PROJECT_FILTER', '')) // Kept for client-side filtering
const cveFilter = ref('') // Optional global CVE filter
const realRole = inject<any>('realRole', ref('ANALYST'))
const allProjects = ref<Project[]>([])
const loading = ref(false)
const exportingProject = ref('')
const exportMessage = ref('')
const exportError = ref('')
const exportTask = ref<ProjectArchiveTask | null>(null)

const exportProgress = computed(() => {
    const progress = exportTask.value?.progress ?? 0
    return Math.max(0, Math.min(100, progress))
})

const exportDownloadUrl = computed(() => {
    if (exportTask.value?.status !== 'completed') return ''
    return getProjectArchiveTaskDownloadUrl(exportTask.value.id)
})

const fetchProjects = async () => {
    loading.value = true
    try {
        // Fetch projects from backend (backend handles filtering by name if provided)
        const data = await getProjects(query.value || '')
        allProjects.value = data
    } catch (err) {
        console.error(err)
        alert('Failed to fetch projects')
    } finally {
        loading.value = false
    }
}

// Fetch projects when the component mounts and whenever the search query changes.
// This ensures that the default project filter (from runtime config) is applied immediately.
watch(query, () => {
    fetchProjects()
}, { immediate: true })

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

const exportProject = async (name: string) => {
    exportingProject.value = name
    exportTask.value = null
    exportMessage.value = `Queueing archive export for ${name}...`
    exportError.value = ''
    try {
        const { task_id } = await startProjectArchiveExport({ project_name: name, refresh: true })
        exportTask.value = {
            id: task_id,
            kind: 'export',
            status: 'pending',
            message: `Queued archive export for ${name}`,
            progress: 0,
        }
        const task = await waitForProjectArchiveTask(task_id, (status) => {
            exportTask.value = status
            exportMessage.value = status.message
        })
        exportTask.value = task
        exportMessage.value = `Archive ready for ${name}`
        window.location.href = getProjectArchiveTaskDownloadUrl(task.id)
    } catch (err: any) {
        exportError.value = err.message || 'Project archive export failed'
    } finally {
        exportingProject.value = ''
    }
}
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

    <div v-if="exportMessage || exportError" class="mb-4 rounded border px-4 py-3 text-sm"
        :class="exportError ? 'border-red-800 bg-red-900/30 text-red-300' : 'border-blue-800 bg-blue-900/20 text-blue-200'"
        role="status"
    >
        <div class="flex flex-wrap items-center justify-between gap-3">
            <span>{{ exportError || exportMessage }}</span>
            <span v-if="exportTask && !exportError" class="text-xs font-bold text-blue-200">{{ exportProgress }}%</span>
            <a
                v-if="exportDownloadUrl"
                :href="exportDownloadUrl"
                class="inline-flex items-center gap-1 rounded border border-green-500/30 bg-green-600/20 px-2 py-1 text-xs font-bold text-green-100 transition-colors hover:bg-green-600/30"
            >
                <Download :size="13" />
                Download
            </a>
        </div>
        <div v-if="exportTask && !exportError && exportTask.status !== 'completed'" class="mt-3 h-2 overflow-hidden rounded bg-black/30">
            <div class="h-full bg-blue-400 transition-all" :style="{ width: `${exportProgress}%` }"></div>
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
                        <button
                            v-if="realRole === 'REVIEWER'"
                            type="button"
                            :disabled="exportingProject === p.name"
                            class="inline-flex h-7 shrink-0 items-center justify-center rounded-lg border border-gray-600 bg-gray-900/70 px-2 text-gray-300 transition-colors hover:bg-gray-700 hover:text-white disabled:cursor-wait disabled:opacity-60"
                            title="Export project archive"
                            @click="exportProject(p.name)"
                        >
                            <Loader2 v-if="exportingProject === p.name" :size="14" class="animate-spin" />
                            <Archive v-else :size="14" />
                            <span class="sr-only">Export {{ p.name }}</span>
                        </button>
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
