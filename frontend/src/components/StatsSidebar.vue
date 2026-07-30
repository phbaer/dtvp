<script setup lang="ts">
import { ref, computed } from 'vue'
import { LayoutList, Copy } from 'lucide-vue-next'
import CustomSelect from './CustomSelect.vue'
import AttributionAgeFilter from './AttributionAgeFilter.vue'
import type { CacheStatus, InconsistencyReason } from '../types'
import type { TaskVulnGroupListCounts } from '../lib/api'
import type {
    AutomaticAssessmentOutcome,
    AutomaticAssessmentRescoreState,
} from '../lib/automaticAssessmentFilters'

export interface TeamEntry {
    team: string
    open: number
    assessed: number
    aliases?: string[]
}

interface TeamGroupTreeEntry extends TeamEntry {
    key: string
    kind: 'group' | 'team'
    depth: number
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
    automaticAssessmentFilter: Array<'WITH_AUTOMATIC_ASSESSMENT' | 'WITHOUT_AUTOMATIC_ASSESSMENT'>
    automaticAssessmentOutcomeFilter: AutomaticAssessmentOutcome[]
    automaticAssessmentRescoreFilter: AutomaticAssessmentRescoreState[]
    idFilter: string
    tagFilter: string
    componentFilter: string
    versionFilterInput: string
    lifecycleFilters: string[]
    inconsistencyReasonFilters?: InconsistencyReason[]
    analysisFilters: string[]
    cvssVersionMismatchOnly: boolean
    assigneeFilter: string
    attributionAgeDays: number | null
    attributionAgeMode: 'older' | 'younger'
}

const props = defineProps<{
    filters: FilterState
    availableVersions: string[]
    lifecycleOptions: FilterOption[]
    inconsistencyReasonOptions: ReadonlyArray<Omit<FilterOption, 'color'>>
    analysisOptions: FilterOption[]
    copiedUrl: boolean
    resultCounts: TaskVulnGroupListCounts
    countsUpdating: boolean
    teamOptions: string[]
    teamAliases: Readonly<Record<string, readonly string[]>>
    cacheStatusState: 'cached' | 'partial' | 'unknown' | 'loading'
    cacheStatusLabel: string
    cacheStatusAge: string
    cacheStatusTooltip: string
    cacheStatusDetail: CacheStatus | null
    sortOptions: ReadonlyArray<{ value: string; label: string }>
    dependencyOptions: ReadonlyArray<{ value: string; label: string }>
    tmrescoreOptions: ReadonlyArray<{ value: string; label: string }>
    automaticAssessmentOptions: ReadonlyArray<{ value: string; label: string }>
    automaticAssessmentOutcomeOptions: ReadonlyArray<{ value: string; label: string }>
    automaticAssessmentRescoreOptions: ReadonlyArray<{ value: string; label: string }>
}>()

const emit = defineEmits<{
    'update:filters': [filters: FilterState]
    'copy-filter-url': []
}>()

const activeTab = ref<'scope-search' | 'statistics'>('scope-search')
const copiedStats = ref(false)

const updateFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    emit('update:filters', { ...props.filters, [key]: value })
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

const toggleAutomaticAssessmentFilter = (value: 'WITH_AUTOMATIC_ASSESSMENT' | 'WITHOUT_AUTOMATIC_ASSESSMENT') => {
    const current = [...props.filters.automaticAssessmentFilter]
    const idx = current.indexOf(value)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(value)
    updateFilter('automaticAssessmentFilter', current as FilterState['automaticAssessmentFilter'])
}

const toggleAutomaticAssessmentOutcomeFilter = (value: AutomaticAssessmentOutcome) => {
    const current = [...props.filters.automaticAssessmentOutcomeFilter]
    const idx = current.indexOf(value)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(value)
    updateFilter('automaticAssessmentOutcomeFilter', current)
}

const toggleAutomaticAssessmentRescoreFilter = (value: AutomaticAssessmentRescoreState) => {
    const current = [...props.filters.automaticAssessmentRescoreFilter]
    const idx = current.indexOf(value)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(value)
    updateFilter('automaticAssessmentRescoreFilter', current)
}

const toggleLifecycleFilter = (val: string) => {
    const current = [...props.filters.lifecycleFilters]
    const idx = current.indexOf(val)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(val)
    if (val === 'INCONSISTENT' && idx >= 0) {
        emit('update:filters', {
            ...props.filters,
            lifecycleFilters: current,
            inconsistencyReasonFilters: [],
        })
        return
    }
    updateFilter('lifecycleFilters', current)
}

const toggleInconsistencyReasonFilter = (value: InconsistencyReason) => {
    const current = [...(props.filters.inconsistencyReasonFilters || [])]
    const idx = current.indexOf(value)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(value)
    const lifecycleFilters = current.length > 0
        ? Array.from(new Set([...props.filters.lifecycleFilters, 'INCONSISTENT']))
        : props.filters.lifecycleFilters
    emit('update:filters', {
        ...props.filters,
        lifecycleFilters,
        inconsistencyReasonFilters: current,
    })
}

const toggleAnalysisFilter = (val: string) => {
    const current = [...props.filters.analysisFilters]
    const idx = current.indexOf(val)
    if (idx >= 0) current.splice(idx, 1)
    else current.push(val)
    updateFilter('analysisFilters', current)
}

const countLabel = (count: number | undefined) => props.countsUpdating ? '…' : String(count || 0)

const teamFilterCountEntries = computed<TeamEntry[]>(() => props.teamOptions
    .map(team => ({
        team,
        open: props.resultCounts.team_tags?.[team]?.open || 0,
        assessed: props.resultCounts.team_tags?.[team]?.assessed || 0,
    })))

const teamAliasIndex = computed(() => {
    const canonicalByName = new Map<string, string>()
    const aliasesByCanonical = new Map<string, string[]>()
    Object.entries(props.teamAliases || {}).forEach(([canonical, aliases]) => {
        if (!canonicalByName.has(canonical.toLowerCase())) {
            canonicalByName.set(canonical.toLowerCase(), canonical)
        }
        aliasesByCanonical.set(canonical.toLowerCase(), [...aliases])
        aliases.forEach((alias) => {
            if (!canonicalByName.has(alias.toLowerCase())) {
                canonicalByName.set(alias.toLowerCase(), canonical)
            }
        })
    })
    return { canonicalByName, aliasesByCanonical }
})

const teamCountEntries = computed<TeamEntry[]>(() => {
    const source = props.resultCounts.canonical_team_tags
        || props.resultCounts.team_tags
        || {}
    const entries = new Map<string, TeamEntry>()
    Object.entries(source).forEach(([rawTeam, counts]) => {
        const canonical = teamAliasIndex.value.canonicalByName.get(rawTeam.toLowerCase())
            || rawTeam
        const key = canonical.toLowerCase()
        const entry = entries.get(key) || {
            team: canonical,
            open: 0,
            assessed: 0,
            aliases: teamAliasIndex.value.aliasesByCanonical.get(key) || [],
        }
        entry.open += Number(counts?.open || 0)
        entry.assessed += Number(counts?.assessed || 0)
        entries.set(key, entry)
    })
    return [...entries.values()]
})

const filteredTeamTagList = computed(() => teamCountEntries.value
    .filter(entry => entry.open + entry.assessed > 0)
    .sort((left, right) => left.team.localeCompare(
        right.team,
        undefined,
        { numeric: true, sensitivity: 'base' },
    )))

const compareNames = (left: string, right: string) => left.localeCompare(
    right,
    undefined,
    { numeric: true, sensitivity: 'base' },
)

const hasConfiguredTeamGroups = computed(() =>
    Object.keys(props.resultCounts.team_group_structure || {}).length > 0
)

const teamGroupTreeEntries = computed<TeamGroupTreeEntry[]>(() => {
    const groupCounts = props.resultCounts.team_groups || {}
    const structure = props.resultCounts.team_group_structure || {}
    const structureNames = Object.keys(structure)
    if (structureNames.length === 0) {
        return Object.entries(groupCounts)
            .map(([team, counts]) => ({
                key: `group:${team}`,
                kind: 'group' as const,
                depth: 0,
                team,
                open: Number(counts?.open || 0),
                assessed: Number(counts?.assessed || 0),
            }))
            .filter(entry => entry.open + entry.assessed > 0)
            .sort((left, right) => compareNames(left.team, right.team))
    }

    const groupNameByLower = new Map(
        structureNames.map(name => [name.toLowerCase(), name]),
    )
    const groupCountsByLower = new Map(
        Object.entries(groupCounts).map(([name, counts]) => [
            name.toLowerCase(),
            counts,
        ]),
    )
    const teamCountsByLower = new Map(
        teamCountEntries.value.map(entry => [entry.team.toLowerCase(), entry]),
    )
    const referencedGroups = new Set(
        Object.values(structure)
            .flatMap(definition => definition.groups || [])
            .map(name => name.toLowerCase()),
    )
    const groupedTeams = new Set(
        Object.values(structure)
            .flatMap(definition => definition.teams || [])
            .map(name => name.toLowerCase()),
    )
    const roots = structureNames
        .filter(name => !referencedGroups.has(name.toLowerCase()))
        .sort(compareNames)
    const entries: TeamGroupTreeEntry[] = []

    const appendGroup = (
        requestedName: string,
        depth: number,
        path: string,
        ancestors: Set<string>,
    ) => {
        const groupName = groupNameByLower.get(requestedName.toLowerCase())
        if (!groupName || ancestors.has(groupName.toLowerCase())) return
        const counts = groupCountsByLower.get(groupName.toLowerCase())
        entries.push({
            key: `${path}:group:${groupName}`,
            kind: 'group',
            depth,
            team: groupName,
            open: Number(counts?.open || 0),
            assessed: Number(counts?.assessed || 0),
        })

        const nextAncestors = new Set(ancestors)
        nextAncestors.add(groupName.toLowerCase())
        const definition = structure[groupName]
        const childGroups = [...(definition?.groups || [])].sort(compareNames)
        childGroups.forEach((child) => {
            appendGroup(
                child,
                depth + 1,
                `${path}:group:${groupName}`,
                nextAncestors,
            )
        })
        const directTeams = [...(definition?.teams || [])].sort(compareNames)
        directTeams.forEach((team) => {
            const countsForTeam = teamCountsByLower.get(team.toLowerCase())
            entries.push({
                key: `${path}:group:${groupName}:team:${team}`,
                kind: 'team',
                depth: depth + 1,
                team,
                open: Number(countsForTeam?.open || 0),
                assessed: Number(countsForTeam?.assessed || 0),
            })
        })
    }

    roots.forEach(root => appendGroup(root, 0, 'root', new Set()))
    teamCountEntries.value
        .filter(entry =>
            entry.open + entry.assessed > 0
            && !groupedTeams.has(entry.team.toLowerCase())
        )
        .sort((left, right) => compareNames(left.team, right.team))
        .forEach((entry) => {
            entries.push({
                key: `ungrouped:team:${entry.team}`,
                kind: 'team',
                depth: 0,
                team: entry.team,
                open: entry.open,
                assessed: entry.assessed,
            })
        })
    return entries
})

const teamFilterOptions = computed(() => [
    { value: '', label: 'All teams' },
    ...teamFilterCountEntries.value
        .filter(entry => entry.team.trim().length > 0)
        .slice()
        .sort((left, right) => left.team.localeCompare(
            right.team,
            undefined,
            { numeric: true, sensitivity: 'base' },
        ))
        .map(entry => ({
            value: entry.team,
            label: entry.team,
            suffix: props.countsUpdating
                ? 'Updating…'
                : `${entry.open + entry.assessed} vulnerabilities · ${entry.open} open · ${entry.assessed} assessed`,
        })),
])

const attributionRangeCount = computed(() =>
    props.filters.attributionAgeDays == null
        ? props.resultCounts.total
        : (props.resultCounts.attribution_age ?? props.resultCounts.total)
)

const statsText = computed(() => {
    if (props.countsUpdating) return 'Updating vulnerability counts…'
    const lines = [
        `Vulnerabilities: ${props.resultCounts.total}`,
        `Direct: ${props.resultCounts.dependency_relationship.direct}`,
        `Transitive: ${props.resultCounts.dependency_relationship.transitive}`,
        `Unknown: ${props.resultCounts.dependency_relationship.unknown}`
    ]

    if (teamGroupTreeEntries.value.length) {
        lines.push('Per Group:')
        teamGroupTreeEntries.value.forEach(entry => {
            const indent = '  '.repeat(entry.depth + 1)
            const type = entry.kind === 'group' ? 'Group' : 'Team'
            lines.push(`${indent}${entry.team} (${type}): Open ${entry.open}, Assessed ${entry.assessed}`)
        })
    }

    if (!hasConfiguredTeamGroups.value && filteredTeamTagList.value.length) {
        lines.push('Per Team:')
        filteredTeamTagList.value.forEach(entry => {
            const aliasText = entry.aliases?.length
                ? ` (aliases: ${entry.aliases.join(', ')})`
                : ''
            lines.push(`  ${entry.team}${aliasText}: Open ${entry.open}, Assessed ${entry.assessed}`)
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
    <div class="w-full min-w-0 flex-shrink-0 space-y-3" data-testid="stats-sidebar">
        <div class="shadow-xl bg-white/2 border border-white/5 rounded-2xl backdrop-blur-sm overflow-hidden">
            <div class="flex items-center gap-2 px-3 py-3">
                <button
                    type="button"
                    @click="activeTab = 'scope-search'"
                    :class="[
                        'flex-1 min-w-0 h-10 px-3 text-xs font-semibold uppercase tracking-wider whitespace-nowrap transition-colors rounded-2xl',
                        activeTab === 'scope-search'
                            ? 'bg-slate-900/30 text-white border border-white/15 shadow-sm shadow-slate-900/20'
                            : 'bg-slate-900/5 text-slate-400 hover:bg-slate-900/10 hover:text-white border border-transparent'
                    ]"
                >
                    Filters
                </button>
                <button
                    type="button"
                    @click="activeTab = 'statistics'"
                    :class="[
                        'flex-1 min-w-0 h-10 px-3 text-xs font-semibold uppercase tracking-wider transition-colors rounded-2xl',
                        activeTab === 'statistics'
                            ? 'bg-slate-900/30 text-white border border-white/15 shadow-sm shadow-slate-900/20'
                            : 'bg-slate-900/5 text-slate-400 hover:bg-slate-900/10 hover:text-white border border-transparent'
                    ]"
                >
                    Results
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
                        <div class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-3 backdrop-blur-sm">
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

                            </div>
                        </div>
                        <div class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-3 backdrop-blur-sm">
                            <div class="space-y-3">
                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Team</label>
                                    <CustomSelect
                                        data-testid="team-filter-select"
                                        :modelValue="props.filters.tagFilter"
                                        :options="teamFilterOptions"
                                        placeholder="All teams"
                                        searchable
                                        search-placeholder="Search teams..."
                                        @update:modelValue="(value) => updateFilter('tagFilter', value)"
                                    />
                                </div>

                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Attribution Age</label>
                                    <AttributionAgeFilter
                                        :days="props.filters.attributionAgeDays"
                                        :mode="props.filters.attributionAgeMode"
                                        :count="props.countsUpdating ? undefined : attributionRangeCount"
                                        @update:days="updateFilter('attributionAgeDays', $event)"
                                        @update:mode="updateFilter('attributionAgeMode', $event)"
                                    />
                                </div>

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
                                                {{ countLabel(props.resultCounts.lifecycle[opt.value]) }}
                                            </span>
                                        </button>
                                    </div>
                                </div>

                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Inconsistency Reason</label>
                                    <div class="flex flex-wrap gap-1.5 items-center">
                                        <button
                                            v-for="opt in props.inconsistencyReasonOptions"
                                            :key="opt.value"
                                            @click="toggleInconsistencyReasonFilter(opt.value as InconsistencyReason)"
                                            :title="opt.description"
                                            :class="[
                                                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                                                (props.filters.inconsistencyReasonFilters || []).includes(opt.value as InconsistencyReason)
                                                    ? 'bg-indigo-500/20 text-indigo-200 border-indigo-400/30'
                                                    : 'bg-white/5 text-gray-500 border-white/5 hover:bg-white/10 hover:text-gray-300'
                                            ]"
                                        >
                                            {{ opt.label }}
                                            <span class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20">
                                                {{ countLabel(props.resultCounts.inconsistency_reason?.[opt.value as InconsistencyReason]) }}
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
                                                {{ countLabel(props.resultCounts.dependency_relationship[opt.value === 'DIRECT' ? 'direct' : opt.value === 'TRANSITIVE' ? 'transitive' : 'unknown']) }}
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
                                                {{ countLabel(props.resultCounts.tmrescore?.[opt.value as 'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL']) }}
                                            </span>
                                        </button>
                                    </div>
                                </div>

                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Automatic Assessment</label>
                                    <div class="flex flex-wrap gap-2">
                                        <button
                                            v-for="opt in props.automaticAssessmentOptions"
                                            :key="opt.value"
                                            @click="toggleAutomaticAssessmentFilter(opt.value as 'WITH_AUTOMATIC_ASSESSMENT' | 'WITHOUT_AUTOMATIC_ASSESSMENT')"
                                            :class="[
                                                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                                                props.filters.automaticAssessmentFilter.includes(opt.value as 'WITH_AUTOMATIC_ASSESSMENT' | 'WITHOUT_AUTOMATIC_ASSESSMENT')
                                                    ? opt.value === 'WITH_AUTOMATIC_ASSESSMENT' ? 'bg-cyan-500 text-white border-cyan-500' : 'bg-slate-600/60 text-white border-slate-500'
                                                    : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
                                            ]"
                                        >
                                            {{ opt.label }}
                                            <span class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20" :class="props.filters.automaticAssessmentFilter.includes(opt.value as 'WITH_AUTOMATIC_ASSESSMENT' | 'WITHOUT_AUTOMATIC_ASSESSMENT') ? 'text-white' : 'text-gray-500'">
                                                {{ countLabel(props.resultCounts.automatic_assessment?.[opt.value as 'WITH_AUTOMATIC_ASSESSMENT' | 'WITHOUT_AUTOMATIC_ASSESSMENT']) }}
                                            </span>
                                        </button>
                                    </div>
                                </div>

                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Auto Analysis Outcome</label>
                                    <div class="flex flex-wrap gap-2" data-testid="automatic-assessment-outcome-filters">
                                        <button
                                            v-for="opt in props.automaticAssessmentOutcomeOptions"
                                            :key="opt.value"
                                            @click="toggleAutomaticAssessmentOutcomeFilter(opt.value as AutomaticAssessmentOutcome)"
                                            :class="[
                                                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                                                props.filters.automaticAssessmentOutcomeFilter.includes(opt.value as AutomaticAssessmentOutcome)
                                                    ? opt.value === 'AFFECTED' ? 'bg-red-600/80 text-white border-red-500'
                                                        : opt.value === 'PROBABLY_AFFECTED' ? 'bg-orange-500/80 text-white border-orange-400'
                                                            : opt.value === 'NOT_AFFECTED' ? 'bg-emerald-600/80 text-white border-emerald-500'
                                                                : 'bg-amber-600/70 text-white border-amber-500'
                                                    : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
                                            ]"
                                        >
                                            {{ opt.label }}
                                            <span class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20" :class="props.filters.automaticAssessmentOutcomeFilter.includes(opt.value as AutomaticAssessmentOutcome) ? 'text-white' : 'text-gray-500'">
                                                {{ countLabel(props.resultCounts.automatic_assessment_outcome?.[opt.value as AutomaticAssessmentOutcome]) }}
                                            </span>
                                        </button>
                                    </div>
                                </div>

                                <div class="space-y-0.5">
                                    <label class="text-[10px] font-medium text-gray-500 uppercase tracking-widest">Auto Analysis Rescore</label>
                                    <div class="flex flex-wrap gap-2" data-testid="automatic-assessment-rescore-filters">
                                        <button
                                            v-for="opt in props.automaticAssessmentRescoreOptions"
                                            :key="opt.value"
                                            @click="toggleAutomaticAssessmentRescoreFilter(opt.value as AutomaticAssessmentRescoreState)"
                                            :class="[
                                                'px-3 py-1 rounded-full text-[10px] font-medium uppercase tracking-tight transition-all border outline-none active:scale-95 flex items-center gap-1.5',
                                                props.filters.automaticAssessmentRescoreFilter.includes(opt.value as AutomaticAssessmentRescoreState)
                                                    ? 'bg-blue-600/80 text-white border-blue-500'
                                                    : 'bg-white/5 text-gray-400 border-white/10 hover:bg-white/10 hover:text-white'
                                            ]"
                                        >
                                            {{ opt.label }}
                                            <span class="px-1.5 py-0.5 rounded-md text-[9px] bg-black/20" :class="props.filters.automaticAssessmentRescoreFilter.includes(opt.value as AutomaticAssessmentRescoreState) ? 'text-white' : 'text-gray-500'">
                                                {{ countLabel(props.resultCounts.automatic_assessment_rescore?.[opt.value as AutomaticAssessmentRescoreState]) }}
                                            </span>
                                        </button>
                                    </div>
                                </div>

                                <div class="space-y-0.5">
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
                                                {{ countLabel(props.resultCounts.cvss_version_mismatch) }}
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
                                                {{ countLabel(props.resultCounts.analysis[opt.value]) }}
                                            </span>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div v-else class="space-y-3" data-testid="stats-sidebar-results">
                    <div class="relative shadow-xl bg-white/2 border border-white/5 rounded-2xl p-3 backdrop-blur-sm">
                        <span v-if="copiedStats" class="absolute top-3 right-3 text-[10px] text-green-300">Copied!</span>
                        <div class="text-[10px] font-medium uppercase tracking-widest text-gray-500">Statistics</div>
                        <div class="flex items-center gap-2 px-3 py-1.5 my-2 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                            <LayoutList :size="12" class="text-blue-400" />
                            <span class="text-[10px] font-black text-blue-400 uppercase tracking-widest">{{ props.countsUpdating ? 'Updating…' : `${props.resultCounts.total} Vulnerabilities` }}</span>
                        </div>
                        <div class="flex flex-col gap-1">
                            <div class="flex justify-between items-center px-2 py-0.5 rounded bg-green-500/10">
                                <span class="text-[10px] text-green-300">Direct</span>
                                <span class="text-[10px] font-bold text-green-200">{{ countLabel(props.resultCounts.dependency_relationship.direct) }}</span>
                            </div>
                            <div class="flex justify-between items-center px-2 py-0.5 rounded bg-purple-500/10">
                                <span class="text-[10px] text-purple-300">Transitive</span>
                                <span class="text-[10px] font-bold text-purple-200">{{ countLabel(props.resultCounts.dependency_relationship.transitive) }}</span>
                            </div>
                            <div class="flex justify-between items-center px-2 py-0.5 rounded bg-gray-500/10">
                                <span class="text-[10px] text-gray-400">Unknown</span>
                                <span class="text-[10px] font-bold text-gray-300">{{ countLabel(props.resultCounts.dependency_relationship.unknown) }}</span>
                            </div>
                        </div>
                    </div>

                    <div
                        v-if="teamGroupTreeEntries.length > 0"
                        class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-3 backdrop-blur-sm"
                        data-testid="per-group-statistics"
                    >
                        <div class="text-[10px] uppercase tracking-widest text-gray-500 mb-2">Per Group</div>
                        <div class="overflow-y-auto max-h-[20rem]">
                            <table class="min-w-full table-auto text-left text-[10px] text-gray-300 border-separate border-spacing-0">
                                <thead class="border-b border-white/10 sticky top-0 bg-white/5">
                                    <tr class="text-gray-400 uppercase text-[9px] tracking-widest">
                                        <th class="px-2 py-1">Group / member</th>
                                        <th class="px-2 py-1 text-right">Open</th>
                                        <th class="px-2 py-1 text-right">Assessed</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr
                                        v-for="entry in teamGroupTreeEntries"
                                        :key="entry.key"
                                        :class="[
                                            'border-t border-white/5',
                                            entry.kind === 'group' ? 'bg-white/[0.025]' : ''
                                        ]"
                                        data-testid="team-group-stat-row"
                                        :data-entry-kind="entry.kind"
                                        :data-entry-name="entry.team"
                                        :data-entry-depth="entry.depth"
                                    >
                                        <td
                                            class="py-1 pr-2 text-[10px] text-gray-200"
                                            :style="{ paddingLeft: `${8 + entry.depth * 14}px` }"
                                        >
                                            <div class="flex min-w-0 items-center gap-1.5">
                                                <span
                                                    :class="[
                                                        'h-1.5 w-1.5 shrink-0 rounded-full',
                                                        entry.kind === 'group' ? 'bg-violet-400' : 'bg-slate-500'
                                                    ]"
                                                ></span>
                                                <span :class="entry.kind === 'group' ? 'font-semibold text-violet-200' : 'text-gray-300'">
                                                    {{ entry.team }}
                                                </span>
                                                <span class="text-[8px] uppercase tracking-wider text-gray-600">
                                                    {{ entry.kind }}
                                                </span>
                                            </div>
                                        </td>
                                        <td class="px-2 py-0.5 text-right text-[10px] tabular-nums text-orange-200">{{ entry.open }}</td>
                                        <td class="px-2 py-0.5 text-right text-[10px] tabular-nums text-cyan-200">{{ entry.assessed }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div
                        v-if="!hasConfiguredTeamGroups && filteredTeamTagList.length > 0"
                        class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-3 backdrop-blur-sm"
                        data-testid="per-team-statistics"
                    >
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
                                        v-for="entry in filteredTeamTagList"
                                        :key="entry.team"
                                        class="border-t border-white/5"
                                    >
                                        <td class="px-2 py-1 text-[10px] text-gray-200">
                                            <div>{{ entry.team }}</div>
                                            <div
                                                v-if="entry.aliases?.length"
                                                class="mt-0.5 text-[9px] leading-tight text-gray-600"
                                                :data-testid="`team-aliases-${entry.team}`"
                                            >
                                                {{ entry.aliases.join(' · ') }}
                                            </div>
                                        </td>
                                        <td class="px-2 py-0.5 text-right text-[10px] text-orange-200">{{ entry.open }}</td>
                                        <td class="px-2 py-0.5 text-right text-[10px] text-cyan-200">{{ entry.assessed }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div
                        class="shadow-xl bg-white/2 border border-white/5 rounded-2xl p-3 backdrop-blur-sm"
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
