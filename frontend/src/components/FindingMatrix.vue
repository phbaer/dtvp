<script setup lang="ts">
import { computed, inject, ref, type Ref } from 'vue'
import { normalizeLegacyTags, wildcardTeams } from '../lib/dependency-team-selection'
import { ChevronDown, ChevronRight, AlertTriangle } from '@lucide/vue'
import { buildFindingMatrix, compareVariants, type MatrixVariant } from '../lib/findingMatrix'
import { parseVersionOverride } from '../lib/assessment-helpers'
import VulnGroupCardDependencies from './VulnGroupCardDependencies.vue'

const props = withDefaults(defineProps<{
    instances: any[]
    /** Reviewers may take one variant over for every finding. */
    canApply?: boolean
    /** False when the surrounding card already says that findings differ. */
    banner?: boolean
}>(), { banner: true })

const emit = defineEmits<{
    (e: 'apply-variant', details: string, state: string): void
}>()

const matrix = computed(() => buildFindingMatrix(props.instances))

// The team each component's findings belong to, as the findings carry it
// (resolved from the BOM), including the mapping's catch-all ``*``.
const teamMapping = inject<Ref<Record<string, string | string[]>>>('teamMapping', ref({}))
const rowTeams = (instances: any[]) => {
    const teams = new Map<string, string>()
    for (const instance of instances) {
        for (const team of normalizeLegacyTags(instance.tags, teamMapping.value || {})) {
            if (!teams.has(team.toLocaleLowerCase())) teams.set(team.toLocaleLowerCase(), team)
        }
    }
    const catchAll = wildcardTeams(teamMapping.value)
    return [...teams.values()].sort().map(team => ({ team, catchAll: catchAll.has(team.toLocaleLowerCase()) }))
}
const comparison = computed(() => compareVariants(matrix.value.variants))
const differingRows = computed(() => comparison.value.filter(row => row.differs))
const hasDifferences = computed(() => matrix.value.variants.length > 1)

const expandedRows = ref(new Set<string>())
const toggleRow = (key: string) => {
    const next = new Set(expandedRows.value)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    expandedRows.value = next
}

const showDifferences = ref(false)
const showAllFields = ref(false)
const comparisonRows = computed(() => (showAllFields.value ? comparison.value : differingRows.value))

const openDifferences = () => {
    showDifferences.value = true
}
defineExpose({ openDifferences })

const STATE_LABELS: Record<string, string> = {
    EXPLOITABLE: 'Exploitable',
    IN_TRIAGE: 'In triage',
    FALSE_POSITIVE: 'False positive',
    NOT_AFFECTED: 'Not affected',
    RESOLVED: 'Resolved',
    NOT_SET: 'Not set',
}
const stateLabel = (state: string) => STATE_LABELS[state] || state.replaceAll('_', ' ')
const stateClass = (state: string) => ({
    EXPLOITABLE: 'border-red-500/50 bg-red-500/15 text-red-200',
    IN_TRIAGE: 'border-amber-500/50 bg-amber-500/15 text-amber-200',
    FALSE_POSITIVE: 'border-teal-500/50 bg-teal-500/15 text-teal-200',
    NOT_AFFECTED: 'border-green-500/50 bg-green-500/15 text-green-200',
    RESOLVED: 'border-sky-500/50 bg-sky-500/15 text-sky-200',
}[state] || 'border-gray-600 bg-gray-800 text-gray-400')

const variantWhere = (variant: MatrixVariant) => {
    const versions = new Set(variant.instances.map(instance => String(instance.project_version || '(unknown)')))
    const components = new Set(variant.instances.map(instance => String(instance.component_name || '')))
    return `${components.size} component${components.size === 1 ? '' : 's'} · ${[...versions]
        .sort((left, right) => left.localeCompare(right, undefined, { numeric: true }))
        .join(', ')}`
}

const cellTitle = (rowName: string, version: string, cell: NonNullable<ReturnType<typeof cellOf>>) => [
    `${rowName}${cell.componentVersions.length ? `@${cell.componentVersions.join(', ')}` : ''} in ${version}`,
    stateLabel(cell.state),
    hasDifferences.value ? `Assessment ${cell.variantLabels.join(', ')}` : '',
    cell.isNew ? 'New finding' : '',
    cell.suppressed ? 'Suppressed' : '',
].filter(Boolean).join(' · ')

// The version override a version's findings carry (ADR 0010), read-only:
// one label is that override; more than one is ambiguous.
const versionScopes = computed(() => {
    const labels = new Map<string, Map<string, string>>()
    for (const instance of props.instances) {
        const version = String(instance.project_version || '(unknown)')
        const marker = parseVersionOverride(instance.analysis_details || instance.analysisDetails || '')
        if (!labels.has(version)) labels.set(version, new Map())
        if (marker) labels.get(version)!.set(marker.label.toLowerCase(), marker.label)
    }
    const scopes: Record<string, { label: string; ambiguous: boolean } | undefined> = {}
    for (const [version, found] of labels) {
        if (found.size === 1) scopes[version] = { label: [...found.values()][0]!, ambiguous: false }
        else if (found.size > 1) scopes[version] = { label: [...found.values()].join(', '), ambiguous: true }
    }
    return scopes
})

const cellOf = (row: (typeof matrix.value.rows)[number], version: string) => row.cells[version]
</script>

<template>
    <div class="space-y-3" data-testid="finding-matrix">
        <div
            v-if="hasDifferences && banner"
            data-testid="finding-differences-banner"
            class="flex flex-wrap items-center justify-between gap-3 rounded border border-indigo-500/40 bg-indigo-950/30 px-3 py-2 text-xs text-indigo-100"
            role="status"
        >
            <span class="flex items-center gap-2">
                <AlertTriangle :size="14" class="shrink-0 text-indigo-300" />
                <span>
                    <strong>{{ matrix.differingCount }} of {{ matrix.total }}</strong>
                    finding{{ matrix.total === 1 ? '' : 's' }} carry a different assessment than the rest
                    ({{ matrix.variants.length }} versions of the assessment: {{ matrix.variants.map(variant => variant.label).join(', ') }}).
                </span>
            </span>
            <button
                type="button"
                data-testid="finding-differences-toggle"
                class="inline-flex h-8 items-center gap-1.5 rounded border border-indigo-400/50 bg-indigo-900/40 px-3 text-xs font-bold text-indigo-100 transition-colors hover:bg-indigo-800/60"
                :aria-expanded="showDifferences ? 'true' : 'false'"
                @click="showDifferences = !showDifferences"
            >
                {{ showDifferences ? 'Hide differences' : 'Show differences' }}
            </button>
        </div>

        <div class="overflow-x-auto rounded border border-gray-700/70">
            <table class="w-full border-collapse text-left text-xs">
                <caption class="sr-only">Components by project versions with the assessment state of each finding</caption>
                <thead>
                    <tr class="bg-gray-900/70 text-[10px] uppercase tracking-wider text-gray-500">
                        <th scope="col" class="px-3 py-2 font-bold">
                            Component
                            <span class="ml-1 font-normal normal-case tracking-normal text-gray-600" data-testid="finding-matrix-summary">
                                {{ matrix.rows.length }} component{{ matrix.rows.length === 1 ? '' : 's' }} · {{ matrix.versions.length }} version{{ matrix.versions.length === 1 ? '' : 's' }}
                            </span>
                        </th>
                        <th
                            v-for="version in matrix.versions"
                            :key="version"
                            scope="col"
                            class="whitespace-nowrap px-2 py-2 text-center font-mono font-bold normal-case tracking-normal text-gray-300"
                            data-testid="context-project-version"
                        >
                            {{ version }}
                            <span
                                v-if="versionScopes[version]"
                                data-testid="matrix-version-scope"
                                class="mt-0.5 block font-sans text-[9px] font-semibold"
                                :class="versionScopes[version]!.ambiguous ? 'text-red-300' : 'text-sky-300'"
                                :title="versionScopes[version]!.ambiguous
                                    ? `Findings of this version carry different overrides: ${versionScopes[version]!.label}`
                                    : `This version has its own assessment: override ${versionScopes[version]!.label}`"
                            >{{ versionScopes[version]!.ambiguous ? 'two overrides' : `override: ${versionScopes[version]!.label}` }}</span>
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <template v-for="row in matrix.rows" :key="row.key">
                        <tr class="border-t border-gray-800" data-testid="finding-matrix-row">
                            <th scope="row" class="px-3 py-1.5 font-normal">
                                <button
                                    type="button"
                                    class="flex items-center gap-1.5 whitespace-nowrap text-left font-mono text-gray-200 hover:text-white"
                                    :aria-expanded="expandedRows.has(row.key) ? 'true' : 'false'"
                                    :title="expandedRows.has(row.key) ? 'Hide the dependency chains' : 'Show how this component enters the product'"
                                    data-testid="finding-matrix-row-toggle"
                                    @click="toggleRow(row.key)"
                                >
                                    <ChevronDown v-if="expandedRows.has(row.key)" :size="12" class="shrink-0 text-gray-500" />
                                    <ChevronRight v-else :size="12" class="shrink-0 text-gray-500" />
                                    <span>{{ row.name }}</span>
                                    <span v-if="row.version" class="text-gray-500">@{{ row.version }}</span>
                                </button>
                                <span class="mt-0.5 flex flex-wrap gap-1 pl-[18px]">
                                    <span
                                        v-for="entry in rowTeams(row.instances)"
                                        :key="entry.team"
                                        data-testid="finding-matrix-team"
                                        :data-catch-all="entry.catchAll ? 'true' : undefined"
                                        class="whitespace-nowrap rounded border px-1 py-px text-[9px] font-semibold"
                                        :class="entry.catchAll
                                            ? 'border-amber-700/50 bg-amber-950/30 text-amber-200'
                                            : 'border-blue-800/40 bg-blue-950/20 text-blue-300'"
                                        :title="entry.catchAll
                                            ? `No team mapping matches this component or its dependency chain; the catch-all '*' assigns ${entry.team}.`
                                            : `Team ${entry.team}`"
                                    >{{ entry.team }}<template v-if="entry.catchAll"> · catch-all</template></span>
                                </span>
                            </th>
                            <td
                                v-for="version in matrix.versions"
                                :key="version"
                                class="px-2 py-1.5 text-center"
                            >
                                <span
                                    v-if="cellOf(row, version)"
                                    data-testid="finding-matrix-cell"
                                    :data-differs="cellOf(row, version)!.differs ? 'true' : 'false'"
                                    class="inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-0.5 text-[10px] font-semibold"
                                    :class="[
                                        stateClass(cellOf(row, version)!.state),
                                        cellOf(row, version)!.differs ? 'ring-2 ring-indigo-400' : '',
                                    ]"
                                    :title="cellTitle(row.name, version, cellOf(row, version)!)"
                                >
                                    {{ stateLabel(cellOf(row, version)!.state) }}
                                    <span v-if="!row.version && cellOf(row, version)!.componentVersions.length" class="font-mono font-normal opacity-70">
                                        {{ cellOf(row, version)!.componentVersions.join(', ') }}
                                    </span>
                                    <span v-if="hasDifferences" class="rounded bg-black/30 px-1 font-mono">{{ cellOf(row, version)!.variantLabels.join('') }}</span>
                                    <span v-if="cellOf(row, version)!.isNew" class="rounded bg-emerald-500/20 px-1 text-emerald-200">new</span>
                                    <span v-if="cellOf(row, version)!.suppressed" class="rounded bg-gray-500/30 px-1 text-gray-200">suppressed</span>
                                </span>
                                <span v-else class="text-gray-700" title="Not found in this project version">–</span>
                            </td>
                        </tr>
                        <tr v-if="expandedRows.has(row.key)" class="border-t border-gray-800/60 bg-gray-950/40" data-testid="finding-matrix-chains">
                            <td :colspan="matrix.versions.length + 1" class="px-3 py-2">
                                <div class="max-w-full overflow-x-auto">
                                    <VulnGroupCardDependencies :instances="row.instances" :embedded="true" :showTitle="false" />
                                </div>
                            </td>
                        </tr>
                    </template>
                    <tr v-if="matrix.rows.length === 0">
                        <td :colspan="matrix.versions.length + 1" class="px-3 py-3 text-gray-500">No finding in the current scope.</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div
            v-if="hasDifferences && showDifferences"
            data-testid="finding-differences"
            class="rounded border border-indigo-500/30 bg-gray-950/40"
        >
            <div class="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 px-3 py-2">
                <h5 class="text-xs font-bold uppercase tracking-wider text-indigo-200">What differs</h5>
                <label class="flex items-center gap-1.5 text-[11px] text-gray-400">
                    <input v-model="showAllFields" type="checkbox" class="h-3.5 w-3.5 rounded" data-testid="finding-differences-all-fields" />
                    Show equal fields too
                </label>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full border-collapse text-left text-xs">
                    <thead>
                        <tr class="align-top">
                            <th scope="col" class="w-48 px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-gray-500">Field</th>
                            <th
                                v-for="variant in matrix.variants"
                                :key="variant.label"
                                scope="col"
                                class="px-3 py-2 font-normal"
                                data-testid="finding-variant"
                            >
                                <div class="flex flex-wrap items-center gap-2">
                                    <span class="rounded bg-indigo-500/25 px-1.5 py-0.5 font-mono font-bold text-indigo-100">{{ variant.label }}</span>
                                    <span class="font-semibold text-gray-200">
                                        {{ variant.instances.length }} finding{{ variant.instances.length === 1 ? '' : 's' }}
                                    </span>
                                    <button
                                        v-if="canApply"
                                        type="button"
                                        data-testid="finding-variant-apply"
                                        class="inline-flex h-7 items-center rounded border border-gray-600 bg-gray-800 px-2 text-[11px] font-bold text-gray-300 transition-colors hover:bg-gray-700 hover:text-white"
                                        title="Put this version into the Global assessment form. It applies to every finding once you save."
                                        @click="emit('apply-variant', variant.details, variant.state)"
                                    >
                                        Use for all findings
                                    </button>
                                </div>
                                <div class="mt-1 text-[11px] text-gray-500">{{ variantWhere(variant) }}</div>
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr
                            v-for="row in comparisonRows"
                            :key="row.key"
                            class="border-t border-gray-800 align-top"
                            data-testid="finding-difference-row"
                            :data-differs="row.differs ? 'true' : 'false'"
                        >
                            <th scope="row" class="px-3 py-2 font-semibold" :class="row.differs ? 'text-indigo-200' : 'text-gray-500'">
                                {{ row.label }}
                            </th>
                            <td
                                v-for="(value, index) in row.values"
                                :key="index"
                                class="whitespace-pre-wrap break-words px-3 py-2"
                                :class="row.differs ? 'bg-indigo-950/30 text-gray-100' : 'text-gray-400'"
                            >
                                <template v-if="value">{{ value }}</template>
                                <span v-else class="text-gray-600">(none)</span>
                            </td>
                        </tr>
                        <tr v-if="differingRows.length === 0 && !showAllFields">
                            <td :colspan="matrix.variants.length + 1" class="px-3 py-3 text-gray-400" data-testid="finding-differences-none">
                                The assessments differ only in parts that are not shown as fields here, such as the SSVC record or the order of the team assessments.
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</template>
