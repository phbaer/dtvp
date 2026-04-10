<script setup lang="ts">
import { ref, computed } from 'vue'
import CustomSelect from './CustomSelect.vue'
import { Copy } from 'lucide-vue-next'

export interface FilterState {
    sortBy: string
    sortOrder: 'asc' | 'desc'
    dependencyFilter: 'ALL' | 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'
    idFilter: string
    tagFilter: string
    componentFilter: string
    versionFilterInput: string
    lifecycleFilters: string[]
    analysisFilters: string[]
}

export interface FilterOption {
    value: string
    label: string
    color: string
    description?: string
}

const props = defineProps<{
    filters: FilterState
    filterCounts: Record<string, number>
    availableVersions: string[]
    lifecycleOptions: FilterOption[]
    analysisOptions: FilterOption[]
    sortOptions: ReadonlyArray<{ value: string; label: string }>
    dependencyOptions: ReadonlyArray<{ value: string; label: string }>
    copiedUrl: boolean
}>()

const emit = defineEmits<{
    'update:filters': [filters: FilterState]
    'copy-filter-url': []
    'reset-filters': []
}>()

const versionSearch = ref('')
const versionSearchInput = ref<HTMLInputElement | null>(null)

const versionFilterList = computed(() => {
    return props.filters.versionFilterInput
        .split(',')
        .map(v => v.trim())
        .filter(v => v.length > 0)
})

const filteredVersionOptions = computed(() => {
    const query = versionSearch.value.trim().toLowerCase()
    return props.availableVersions.filter(ver => {
        if (query && !ver.toLowerCase().includes(query)) return false
        return true
    })
})

const updateFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    emit('update:filters', { ...props.filters, [key]: value })
}

const toggleVersion = (version: string) => {
    const list = versionFilterList.value
    const idx = list.findIndex(v => v.toLowerCase() === version.toLowerCase())
    let newInput: string
    if (idx >= 0) {
        const newList = [...list]
        newList.splice(idx, 1)
        newInput = newList.join(', ')
    } else {
        newInput = list.length ? `${list.join(', ')}, ${version}` : version
    }
    versionSearch.value = ''
    updateFilter('versionFilterInput', newInput)
}

const removeVersion = (version: string) => {
    const newList = versionFilterList.value.filter(v => v.toLowerCase() !== version.toLowerCase())
    updateFilter('versionFilterInput', newList.join(', '))
}

const toggleLifecycleFilter = (val: string) => {
    const current = [...props.filters.lifecycleFilters]
    const idx = current.indexOf(val)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(val)
    updateFilter('lifecycleFilters', current)
}

const toggleAnalysisFilter = (val: string) => {
    const current = [...props.filters.analysisFilters]
    const idx = current.indexOf(val)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(val)
    updateFilter('analysisFilters', current)
}
</script>

<template>
    <div class="sticky top-4 self-start w-full max-w-[360px] flex-shrink-0 shadow-xl bg-white/2 border border-white/5 rounded-2xl p-5 backdrop-blur-sm space-y-5 relative">
        <button
            @click="emit('copy-filter-url')"
            class="absolute top-3 right-3 text-gray-200 hover:text-white p-1 rounded-full border border-white/10 bg-white/5 hover:bg-white/15 transition-colors"
            title="Copy current filter URL"
        >
            <Copy :size="14" />
            <span class="sr-only">Copy filter URL</span>
        </button>
        <span v-if="copiedUrl" class="absolute top-3 right-12 text-[10px] text-green-300">Copied!</span>

        <!-- Sort & Scope -->
        <div class="space-y-2">
            <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Sort & Scope</label>
            <div class="grid grid-cols-[1fr_auto] gap-2">
                <div class="flex flex-col gap-1">
                    <label class="text-[9px] uppercase tracking-widest text-gray-400">Sort By</label>
                    <CustomSelect
                        :modelValue="filters.sortBy"
                        @update:modelValue="updateFilter('sortBy', $event)"
                        :options="[...sortOptions]"
                    />
                </div>
                <div class="flex flex-col gap-1">
                    <label class="text-[9px] uppercase tracking-widest text-gray-400">Order</label>
                    <button 
                        @click="updateFilter('sortOrder', filters.sortOrder === 'asc' ? 'desc' : 'asc')"
                        class="bg-black/40 border border-white/10 rounded-xl px-2 h-10 text-sm hover:bg-white/5 transition-colors font-medium text-blue-400 border-dashed"
                        :title="filters.sortOrder === 'asc' ? 'Ascending' : 'Descending'"
                    >
                        {{ filters.sortOrder === 'asc' ? 'ASC' : 'DESC' }}
                    </button>
                </div>
                <div class="col-span-2 flex flex-col gap-1">
                    <label class="text-[9px] uppercase tracking-widest text-gray-400">Dependency</label>
                    <CustomSelect
                        :modelValue="filters.dependencyFilter"
                        @update:modelValue="updateFilter('dependencyFilter', $event as FilterState['dependencyFilter'])"
                        :options="[...dependencyOptions]"
                    />
                </div>
            </div>
        </div>

        <!-- Search Filters -->
        <div class="space-y-2">
            <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Search Filters</label>
            <div class="grid grid-cols-2 gap-2">
                <div class="flex flex-col gap-1">
                    <label class="text-[9px] uppercase tracking-widest text-gray-400">Vulnerability ID</label>
                    <input 
                        :value="filters.idFilter"
                        @input="updateFilter('idFilter', ($event.target as HTMLInputElement).value)"
                        type="text" 
                        placeholder="CVE or ID..." 
                        class="bg-black/40 border border-white/10 rounded-xl px-3 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600 w-full"
                    />
                </div>
                <div class="flex flex-col gap-1">
                    <label class="text-[9px] uppercase tracking-widest text-gray-400">Team Identifier</label>
                    <input 
                        :value="filters.tagFilter"
                        @input="updateFilter('tagFilter', ($event.target as HTMLInputElement).value)"
                        type="text" 
                        placeholder="Team Identifier..." 
                        class="bg-black/40 border border-white/10 rounded-xl px-3 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600 w-full"
                    />
                </div>
                <div class="flex flex-col gap-1">
                    <label class="text-[9px] uppercase tracking-widest text-gray-400">Component Name</label>
                    <input 
                        :value="filters.componentFilter"
                        @input="updateFilter('componentFilter', ($event.target as HTMLInputElement).value)"
                        type="text" 
                        placeholder="Component..." 
                        class="bg-black/40 border border-white/10 rounded-xl px-3 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600 w-full"
                    />
                </div>
                <div class="flex flex-col gap-1 relative">
                    <label class="text-[9px] uppercase tracking-widest text-gray-400">Project Versions</label>
                    <CustomSelect modelValue="" :options="[]">
                        <template #trigger="{ open }">
                            <div class="relative" @focusin="open">
                                <div class="flex flex-wrap items-center gap-1 bg-black/40 border border-white/10 rounded-xl px-2 min-h-[2.5rem] cursor-text focus-within:border-blue-500/50 transition-all"
                                     @click="versionSearchInput?.focus()">
                                    <span v-for="ver in versionFilterList" :key="ver" class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-blue-500/20 text-blue-200 text-[11px] font-medium">
                                        {{ ver }}
                                        <button @click.stop="removeVersion(ver)" class="hover:text-white text-blue-300/70 leading-none">&times;</button>
                                    </span>
                                    <input
                                        ref="versionSearchInput"
                                        v-model="versionSearch"
                                        type="text"
                                        placeholder="Search versions..."
                                        class="flex-1 min-w-[5rem] bg-transparent border-none outline-none text-sm font-medium text-gray-200 placeholder:text-gray-600 h-8 px-1"
                                    />
                                </div>
                            </div>
                        </template>
                        <template #menu>
                            <div class="divide-y divide-white/5">
                                <button
                                    v-for="opt in filteredVersionOptions" :key="opt"
                                    @mousedown.prevent="toggleVersion(opt)"
                                    :class="[
                                        'w-full text-left px-3 py-1.5 text-sm transition-colors flex items-center justify-between',
                                        versionFilterList.some(v => v.toLowerCase() === opt.toLowerCase())
                                            ? 'bg-blue-500/15 text-blue-200'
                                            : 'text-gray-300 hover:bg-white/5'
                                    ]"
                                >
                                    {{ opt }}
                                    <span v-if="versionFilterList.some(v => v.toLowerCase() === opt.toLowerCase())" class="text-blue-400 text-xs">&#10003;</span>
                                </button>
                            </div>
                        </template>
                    </CustomSelect>
                </div>
            </div>
        </div>

        <!-- Lifecycle Status -->
        <div class="space-y-2">
            <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Lifecycle Status</label>
            <div class="flex flex-wrap gap-1.5 items-center">
                <button 
                    v-for="opt in lifecycleOptions" 
                    :key="opt.value"
                    @click="toggleLifecycleFilter(opt.value)"
                    :title="opt.description"
                    :class="[
                        'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                        filters.lifecycleFilters.includes(opt.value) 
                            ? `${opt.color} text-white border-transparent shadow-lg shadow-blue-900/40`
                            : 'bg-white/5 text-gray-500 border-white/5 hover:bg-white/10 hover:text-gray-300'
                    ]"
                >
                    {{ opt.label }}
                    <span 
                        class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20"
                        :class="filters.lifecycleFilters.includes(opt.value) ? 'text-white' : 'text-gray-500'"
                    >
                        {{ filterCounts[opt.value] || 0 }}
                    </span>
                </button>
            </div>
        </div>

        <!-- Analysis State -->
        <div class="space-y-2">
            <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Analysis State</label>
            <div class="flex flex-wrap gap-1.5 items-center">
                <button 
                    v-for="opt in analysisOptions" 
                    :key="opt.value"
                    @click="toggleAnalysisFilter(opt.value)"
                    :class="[
                        'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                        filters.analysisFilters.includes(opt.value) 
                            ? `${opt.color} text-white border-transparent shadow-lg shadow-gray-900/40`
                            : 'bg-white/5 text-gray-500 border-white/5 hover:bg-white/10 hover:text-gray-300'
                    ]"
                >
                    {{ opt.label }}
                    <span 
                        class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20"
                        :class="filters.analysisFilters.includes(opt.value) ? 'text-white' : 'text-gray-500'"
                    >
                        {{ filterCounts[opt.value] || 0 }}
                    </span>
                </button>
            </div>
        </div>

        <!-- Reset -->
        <button 
            @click="emit('reset-filters')"
            class="text-[10px] font-black text-blue-500 hover:text-blue-400 uppercase tracking-widest transition-colors"
        >
            Reset All Filters
        </button>
    </div>
</template>
