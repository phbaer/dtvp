<script setup lang="ts">
import { ref, computed } from 'vue'
import { LayoutList, Copy } from 'lucide-vue-next'
import CustomSelect from './CustomSelect.vue'
import type { CacheStatus } from '../types'

export interface TeamEntry {
    team: string
    open: number
    assessed: number
}

export interface DependencyCounts {
    direct: number
    transitive: number
    unknown: number
}

export interface FilterOption {
    value: string
    label: string
    color: string
    description?: string
}

export interface FilterState {
    sortBy: string
    sortOrder: 'asc' | 'desc'
    dependencyFilter: Array<'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'>
    tmrescoreFilter: Array<'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL'>
    idFilter: string
    tagFilter: string
    componentFilter: string
    versionFilterInput: string
    lifecycleFilters: string[]
    analysisFilters: string[]
    cvssVersionMismatchOnly: boolean
}

const props = defineProps<{
    filters: FilterState
    filterCounts: Record<string, number>
    availableVersions: string[]
    lifecycleOptions: FilterOption[]
    analysisOptions: FilterOption[]
    copiedUrl: boolean
    filteredCount: number
    dependencyCounts: DependencyCounts
    dependencyFilterCounts: DependencyCounts
    tmrescoreCounts: Record<string, number>
    analysisCounts: Record<string, number>
    teamTagList: TeamEntry[]
    cacheStatusState: 'cached' | 'partial' | 'unknown' | 'loading'
    cacheStatusLabel: string
    cacheStatusAge: string
    cacheStatusTooltip: string
    cacheStatusDetail: CacheStatus | null
    sortOptions: ReadonlyArray<{ value: string; label: string }>
    dependencyOptions: ReadonlyArray<{ value: string; label: string }>
    tmrescoreOptions: ReadonlyArray<{ value: string; label: string }>
    cvssVersionMismatchCount?: number
}>()

const emit = defineEmits<{
    'update:filters': [filters: FilterState]
    'copy-filter-url': []
}>()

const activeTab = ref<'scope-search' | 'statistics'>('scope-search')
const copiedStats = ref(false)

const versionFilterList = computed(() => {
    return props.filters.versionFilterInput
        .split(',')
        .map(v => v.trim())
        .filter(v => v.length > 0)
})

const filteredVersionOptions = computed(() => {
    const query = props.filters.versionFilterInput.trim().toLowerCase()
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
    updateFilter('versionFilterInput', newInput)
}

const toggleDependencyFilter = (value: 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN') => {
    const current = [...props.filters.dependencyFilter]
    const idx = current.indexOf(value)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(value)
    updateFilter('dependencyFilter', current as FilterState['dependencyFilter'])
}

const toggleTmrescoreFilter = (value: 'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL') => {
    const current = [...props.filters.tmrescoreFilter]
    const idx = current.indexOf(value)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(value)
    updateFilter('tmrescoreFilter', current as FilterState['tmrescoreFilter'])
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

const statsText = computed(() => {
    const lines = [
        `Findings: ${props.filteredCount}`,
        `Direct: ${props.dependencyCounts.direct}`,
        `Transitive: ${props.dependencyCounts.transitive}`,
        `Unknown: ${props.dependencyCounts.unknown}`
    ]

    if (props.teamTagList.length) {
        lines.push('Per Team:')
        props.teamTagList.forEach(entry => {
            lines.push(`  ${entry.team}: Open ${entry.open}, Assessed ${entry.assessed}`)
        })
    }

    return lines.join('\n')
})

const copyStatistics = async () => {
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(statsText.value)
        } else {
            const textarea = document.createElement('textarea')
            document.body.appendChild(textarea)
            textarea.value = statsText.value
            textarea.select()
            document.execCommand('copy')
            document.body.removeChild(textarea)
        }

        copiedStats.value = true
        setTimeout(() => {
            copiedStats.value = false
        }, 2000)
    } catch (e) {
        console.error('Failed to copy statistics', e)
    }
}

const handleCopy = () => {
    if (activeTab.value === 'scope-search') {
        emit('copy-filter-url')
    } else {
        copyStatistics()
    }
}
</script>

<template>
    <div class="w-full max-w-[440px] flex-shrink-0 space-y-3 z-40">
        <div class="shadow-xl bg-white/2 border border-white/5 rounded-2xl backdrop-blur-sm overflow-hidden">
            <div class="flex items-center gap-2 px-3 py-3">
                <button
                    type="button"
                    @click="activeTab = 'scope-search'"
                    :class="[
                        'flex-1 min-w-[11rem] h-10 px-4 text-sm font-semibold uppercase tracking-wider whitespace-nowrap transition-colors rounded-2xl',
                        activeTab === 'scope-search'
                            ? 'bg-slate-900/30 text-white border border-white/15 shadow-sm shadow-slate-900/20'
                            : 'bg-slate-900/5 text-slate-400 hover:bg-slate-900/10 hover:text-white border border-transparent'
                    ]"
                >
                    Scope & Search
                </button>
                <button
                    type="button"
                    @click="activeTab = 'statistics'"
                    :class="[
                        'flex-1 h-10 px-4 text-sm font-semibold uppercase tracking-wider transition-colors rounded-2xl',
                        activeTab === 'statistics'
                            ? 'bg-slate-900/30 text-white border border-white/15 shadow-sm shadow-slate-900/20'
                            : 'bg-slate-900/5 text-slate-400 hover:bg-slate-900/10 hover:text-white border border-transparent'
                    ]"
                >
                    Statistics
                </button>
                <button
                    type="button"
                    @click="handleCopy"
                    :title="activeTab === 'scope-search' ? 'Copy current filter URL' : 'Copy statistics'"
                    class="flex-none h-10 w-10 inline-flex items-center justify-center text-slate-200 hover:text-white rounded-full border border-white/10 bg-slate-900/10 hover:bg-slate-900/20 transition-colors"
                >
                    <Copy :size="14" />
                    <span class="sr-only">{{ activeTab === 'scope-search' ? 'Copy filter URL' : 'Copy statistics' }}</span>
                </button>
            </div>
            <div class="p-3.5 space-y-3 relative">
                <div v-if="activeTab === 'scope-search'" class="space-y-3">
                    <div class="space-y-3">
                        <div class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-4 backdrop-blur-sm">
                            <div class="space-y-2.5">
                                <div class="grid gap-2 sm:grid-cols-[1fr_auto]">
                                    <div class="flex flex-col gap-1">
                                        <label class="text-[10px] uppercase tracking-widest text-gray-400">Sort By</label>
                                        <CustomSelect
                                            :modelValue="props.filters.sortBy"
                                            @update:modelValue="(value) => updateFilter('sortBy', value)"
                                            :options="[...props.sortOptions]"
                                        />
                                    </div>
                                    <div class="flex flex-col gap-1">
                                        <label class="text-[10px] uppercase tracking-widest text-gray-400">Order</label>
                                        <button 
                                            @click="updateFilter('sortOrder', props.filters.sortOrder === 'asc' ? 'desc' : 'asc')"
                                            class="bg-black/40 border border-white/10 rounded-xl px-2 h-10 text-sm hover:bg-white/5 transition-colors font-medium text-blue-400 border-dashed"
                                            :title="props.filters.sortOrder === 'asc' ? 'Ascending' : 'Descending'"
                                        >
                                            {{ props.filters.sortOrder === 'asc' ? 'ASC' : 'DESC' }}
                                        </button>
                                    </div>
                                </div>

                                <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                    <div class="flex flex-col gap-1">
                                        <label class="text-[10px] uppercase tracking-widest text-gray-400">Vulnerability ID</label>
                                        <input
                                            type="text"
                                            :value="props.filters.idFilter"
                                            @input="(event) => updateFilter('idFilter', (event.target as HTMLInputElement).value)"
                                            placeholder="CVE or ID..."
                                            class="bg-black/40 border border-white/10 rounded-xl px-3 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600 w-full"
                                        />
                                    </div>
                                    <div class="flex flex-col gap-1">
                                        <label class="text-[10px] uppercase tracking-widest text-gray-400">Team Identifier</label>
                                        <input
                                            type="text"
                                            :value="props.filters.tagFilter"
                                            @input="(event) => updateFilter('tagFilter', (event.target as HTMLInputElement).value)"
                                            placeholder="Team Identifier..."
                                            class="bg-black/40 border border-white/10 rounded-xl px-3 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600 w-full"
                                        />
                                    </div>
                                    <div class="flex flex-col gap-1">
                                        <label class="text-[10px] uppercase tracking-widest text-gray-400">Component Name</label>
                                        <input
                                            type="text"
                                            :value="props.filters.componentFilter"
                                            @input="(event) => updateFilter('componentFilter', (event.target as HTMLInputElement).value)"
                                            placeholder="Component..."
                                            class="bg-black/40 border border-white/10 rounded-xl px-3 h-10 text-sm font-medium focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-gray-600 w-full"
                                        />
                                    </div>
                                    <div class="flex flex-col gap-1 relative">
                                        <label class="text-[10px] uppercase tracking-widest text-gray-400">Project Versions</label>
                                        <CustomSelect modelValue="" :options="[]">
                                            <template #trigger="{ open }">
                                                <div class="relative" @focusin="open">
                                                    <div class="flex flex-wrap items-center gap-1 bg-black/40 border border-white/10 rounded-xl px-2 min-h-[2.5rem] cursor-text focus-within:border-blue-500/50 transition-all">
                                                        <span v-for="ver in versionFilterList" :key="ver" class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-blue-500/20 text-blue-200 text-[11px] font-medium">
                                                            {{ ver }}
                                                            <button @click.stop="removeVersion(ver)" class="hover:text-white text-blue-300/70 leading-none">&times;</button>
                                                        </span>
                                                        <input
                                                            type="text"
                                                            :value="props.filters.versionFilterInput"
                                                            @input="(event) => updateFilter('versionFilterInput', (event.target as HTMLInputElement).value)"
                                                            placeholder="Search versions..."
                                                            class="flex-1 min-w-[5rem] bg-transparent border-none outline-none text-sm font-medium text-gray-200 placeholder:text-gray-600 h-8 px-1"
                                                        />
                                                    </div>
                                                </div>
                                            </template>
                                            <template #menu>
                                                <div class="divide-y divide-white/5">
                                                    <button
                                                        v-for="opt in filteredVersionOptions"
                                                        :key="opt"
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
                        </div>
                        <div class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-4 backdrop-blur-sm">
                            <div class="space-y-3">
                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Lifecycle Status</label>
                                    <div class="flex flex-wrap gap-1.5 items-center">
                                        <button
                                            v-for="opt in props.lifecycleOptions"
                                            :key="opt.value"
                                            @click="toggleLifecycleFilter(opt.value)"
                                            :title="opt.description"
                                            :class="[
                                                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                                                props.filters.lifecycleFilters.includes(opt.value)
                                                    ? `${opt.color} text-white border-transparent shadow-lg shadow-blue-900/40`
                                                    : 'bg-white/5 text-gray-500 border-white/5 hover:bg-white/10 hover:text-gray-300'
                                            ]"
                                        >
                                            {{ opt.label }}
                                            <span
                                                class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20"
                                                :class="props.filters.lifecycleFilters.includes(opt.value) ? 'text-white' : 'text-gray-500'"
                                            >
                                                {{ props.filterCounts[opt.value] || 0 }}
                                            </span>
                                        </button>
                                    </div>
                                </div>

                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Dependency</label>
                                    <div class="flex flex-wrap gap-2">
                                        <button
                                            v-for="opt in props.dependencyOptions"
                                            :key="opt.value"
                                            @click="toggleDependencyFilter(opt.value as 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN')"
                                            :class="[
                                                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                                                props.filters.dependencyFilter.includes(opt.value as 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN')
                                                    ? opt.value === 'DIRECT' ? 'bg-red-600/15 text-red-300 border-red-500/20' : opt.value === 'TRANSITIVE' ? 'bg-purple-600/10 text-purple-300 border-purple-600/20' : 'bg-slate-700/20 text-slate-300 border-slate-600/20'
                                                    : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
                                            ]"
                                        >
                                            {{ opt.label }}
                                            <span class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20" :class="props.filters.dependencyFilter.includes(opt.value as 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN') ? 'text-white' : 'text-gray-500'">
                                                {{ props.dependencyFilterCounts[opt.value === 'DIRECT' ? 'direct' : opt.value === 'TRANSITIVE' ? 'transitive' : 'unknown'] || 0 }}
                                            </span>
                                        </button>
                                    </div>
                                </div>

                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Threadmodel Proposal</label>
                                    <div class="flex flex-wrap gap-2">
                                        <button
                                            v-for="opt in props.tmrescoreOptions"
                                            :key="opt.value"
                                            @click="toggleTmrescoreFilter(opt.value as 'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL')"
                                            :class="[
                                                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                                                props.filters.tmrescoreFilter.includes(opt.value as 'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL')
                                                    ? opt.value === 'WITH_PROPOSAL' ? 'bg-blue-500 text-white border-blue-500' : 'bg-amber-500 text-white border-amber-500'
                                                    : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
                                            ]"
                                        >
                                            {{ opt.label }}
                                            <span class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20" :class="props.filters.tmrescoreFilter.includes(opt.value as 'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL') ? 'text-white' : 'text-gray-500'">
                                                {{ props.tmrescoreCounts[opt.value] || 0 }}
                                            </span>
                                        </button>
                                    </div>
                                </div>

                                <div v-if="props.cvssVersionMismatchCount != null" class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">CVSS Version</label>
                                    <div class="flex flex-wrap gap-2">
                                        <button
                                            @click="updateFilter('cvssVersionMismatchOnly', !props.filters.cvssVersionMismatchOnly)"
                                            :class="[
                                                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                                                props.filters.cvssVersionMismatchOnly
                                                    ? 'bg-orange-500/15 text-orange-300 border-orange-500/20'
                                                    : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
                                            ]"
                                        >
                                            Mismatch
                                            <span class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20" :class="props.filters.cvssVersionMismatchOnly ? 'text-white' : 'text-gray-500'">
                                                {{ props.cvssVersionMismatchCount }}
                                            </span>
                                        </button>
                                    </div>
                                </div>

                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Analysis State</label>
                                    <div class="flex flex-wrap gap-1.5 items-center">
                                        <button
                                            v-for="opt in props.analysisOptions"
                                            :key="opt.value"
                                            @click="toggleAnalysisFilter(opt.value)"
                                            :class="[
                                                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                                                props.filters.analysisFilters.includes(opt.value)
                                                    ? `${opt.color} text-white border-transparent shadow-lg shadow-blue-900/40`
                                                    : 'bg-white/5 text-gray-500 border-white/5 hover:bg-white/10 hover:text-gray-300'
                                            ]"
                                        >
                                            {{ opt.label }}
                                            <span
                                                class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20"
                                                :class="props.filters.analysisFilters.includes(opt.value) ? 'text-white' : 'text-gray-500'"
                                            >
                                                {{ props.analysisCounts[opt.value] || 0 }}
                                            </span>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div v-else class="space-y-3">
                    <div class="relative shadow-xl bg-white/2 border border-white/5 rounded-2xl p-4 backdrop-blur-sm">
                        <span v-if="copiedStats" class="absolute top-3 right-3 text-[10px] text-green-300">Copied!</span>
                        <div class="text-[10px] font-medium uppercase tracking-widest text-gray-500">Statistics</div>
                        <div class="flex items-center gap-2 px-3 py-1.5 my-2 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                            <LayoutList :size="12" class="text-blue-400" />
                            <span class="text-[10px] font-black text-blue-400 uppercase tracking-widest">{{ props.filteredCount }} Findings</span>
                        </div>
                        <div class="flex flex-col gap-1">
                            <div class="flex justify-between items-center px-2 py-0.5 rounded bg-green-500/10">
                                <span class="text-[10px] text-green-300">Direct</span>
                                <span class="text-[10px] font-bold text-green-200">{{ props.dependencyCounts.direct }}</span>
                            </div>
                            <div class="flex justify-between items-center px-2 py-0.5 rounded bg-purple-500/10">
                                <span class="text-[10px] text-purple-300">Transitive</span>
                                <span class="text-[10px] font-bold text-purple-200">{{ props.dependencyCounts.transitive }}</span>
                            </div>
                            <div class="flex justify-between items-center px-2 py-0.5 rounded bg-gray-500/10">
                                <span class="text-[10px] text-gray-400">Unknown</span>
                                <span class="text-[10px] font-bold text-gray-300">{{ props.dependencyCounts.unknown }}</span>
                            </div>
                        </div>
                    </div>

                    <div v-if="props.teamTagList.length > 0" class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-4 backdrop-blur-sm">
                        <div class="text-[10px] uppercase tracking-widest text-gray-500 mb-2">Per Team</div>
                        <div class="overflow-y-auto max-h-[20rem]">
                            <table class="min-w-full table-auto text-left text-[10px] text-gray-300 border-separate border-spacing-0">
                                <thead class="border-b border-white/10 sticky top-0 bg-white/5">
                                    <tr class="text-gray-400 uppercase text-[9px] tracking-widest">
                                        <th class="px-2 py-1">Team</th>
                                        <th class="px-2 py-1 text-right">Open</th>
                                        <th class="px-2 py-1 text-right">Assessed</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr
                                        v-for="entry in props.teamTagList"
                                        :key="entry.team"
                                        class="border-t border-white/5"
                                    >
                                        <td class="px-2 py-0.5 text-[10px] text-gray-200">{{ entry.team }}</td>
                                        <td class="px-2 py-0.5 text-right text-[10px] text-orange-200">{{ entry.open }}</td>
                                        <td class="px-2 py-0.5 text-right text-[10px] text-cyan-200">{{ entry.assessed }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div
                        class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-4 backdrop-blur-sm"
                        :title="props.cacheStatusTooltip"
                    >
                        <div class="text-[10px] font-medium uppercase tracking-widest text-gray-500 mb-2">Cache Status</div>
                        <div
                            class="flex items-center gap-3 px-3 py-1.5 rounded-lg border"
                            :class="[
                                props.cacheStatusState === 'cached' ? 'bg-emerald-500/10 border-emerald-300/20 text-emerald-200' :
                                props.cacheStatusState === 'partial' ? 'bg-amber-500/10 border-amber-300/20 text-amber-200' :
                                props.cacheStatusState === 'loading' ? 'bg-sky-500/10 border-sky-300/20 text-sky-200' :
                                'bg-gray-500/10 border-white/10 text-gray-300'
                            ]"
                        >
                            <span :class="[
                                'inline-flex h-2.5 w-2.5 rounded-full',
                                props.cacheStatusState === 'cached' ? 'bg-emerald-400' :
                                props.cacheStatusState === 'partial' ? 'bg-amber-400' :
                                props.cacheStatusState === 'loading' ? 'bg-sky-400' :
                                'bg-slate-400'
                            ]"></span>
                            <div class="flex flex-col gap-0.5 truncate">
                                <span class="text-[10px] font-black uppercase tracking-widest truncate">{{ props.cacheStatusLabel }}</span>
                                <span class="text-[10px] text-gray-400 truncate">{{ props.cacheStatusAge }}</span>
                            </div>
                        </div>
                        <div v-if="props.cacheStatusDetail" class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-[10px]">
                            <div class="flex justify-between">
                                <span class="text-gray-500">Projects</span>
                                <span class="text-gray-300 font-medium tabular-nums">{{ props.cacheStatusDetail.projects }}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-500">Active</span>
                                <span class="text-gray-300 font-medium tabular-nums">{{ props.cacheStatusDetail.active_projects }}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-500">Findings</span>
                                <span class="text-gray-300 font-medium tabular-nums">{{ props.cacheStatusDetail.cached_findings }}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-500">BOMs</span>
                                <span class="text-gray-300 font-medium tabular-nums">{{ props.cacheStatusDetail.cached_boms }}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-500">Analyses</span>
                                <span class="text-gray-300 font-medium tabular-nums">{{ props.cacheStatusDetail.cached_analyses }}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-500">Pending</span>
                                <span :class="['font-medium tabular-nums', props.cacheStatusDetail.pending_updates > 0 ? 'text-amber-300' : 'text-gray-300']">{{ props.cacheStatusDetail.pending_updates }}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
