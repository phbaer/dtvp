<script setup lang="ts">
// What every team decided, on the Global assessment of a reviewer: one dense
// row per team, the rows that disagree first. "Open" switches to the team's
// tab, "Use as Global" fills the Global state and justification; nothing is
// saved here.
import { computed, ref } from 'vue'
import { Info } from '@lucide/vue'
import {
    stateLabel,
    statusLabel,
    visibleTeamOverviewRows,
    type TeamOverview,
    type TeamOverviewRow,
} from '../lib/teamOverview'
import type { GlobalDecision } from '../lib/assessment-helpers'

const props = defineProps<{
    overview: TeamOverview
    /** The worst team state, for "Use worst for Global"; '' for none. */
    worstState?: string
    /** The saved effective Global decision: set by a reviewer, or derived. */
    globalDecision?: GlobalDecision | null
}>()

const emit = defineEmits<{
    (e: 'open', team: string): void
    (e: 'use-as-global', row: TeamOverviewRow): void
    (e: 'use-worst'): void
    (e: 'show-former'): void
}>()

const showAll = ref(false)
const expanded = ref(new Set<string>())

const shownRows = computed(() => visibleTeamOverviewRows(props.overview.rows, showAll.value))
const hiddenCount = computed(() => props.overview.rows.length - shownRows.value.length)
const collapsible = computed(() => visibleTeamOverviewRows(props.overview.rows, false).length < props.overview.rows.length)

const toggleRationale = (team: string) => {
    const next = new Set(expanded.value)
    if (next.has(team)) next.delete(team)
    else next.add(team)
    expanded.value = next
}
const canExpand = (row: TeamOverviewRow) => row.rationale.length > row.rationaleFirstLine.length || row.rationaleFirstLine.length > 90

const stateClass = (state: string) => ({
    EXPLOITABLE: 'text-red-300',
    IN_TRIAGE: 'text-amber-300',
    NOT_AFFECTED: 'text-green-300',
    FALSE_POSITIVE: 'text-teal-300',
    RESOLVED: 'text-green-300',
} as Record<string, string>)[state] || 'text-gray-400'

const statusClass = (row: TeamOverviewRow) => ({
    approved: 'border-green-700/50 text-green-300',
    pending: 'border-amber-700/50 text-amber-200',
    submitted: 'border-blue-700/50 text-blue-200',
    missing: 'border-gray-700 text-gray-500',
})[row.status]

const decision = computed(() => (props.globalDecision && props.globalDecision.source !== 'none' ? props.globalDecision : null))
/** A reviewer's Global decision other than the worst team decision. */
const differsFromDerived = computed(() => !!decision.value
    && decision.value.source === 'manual'
    && !!decision.value.derived
    && decision.value.derived.state !== decision.value.state)
const DERIVED_HELP = 'No reviewer has set the Global decision, so it is the worst team assessment '
    + '(Exploitable, then In triage, False positive, Not affected, Resolved). '
    + 'It is what the findings export; approving records it as the Global assessment.'

const day = (timestamp?: number) => (timestamp ? new Date(timestamp).toLocaleDateString() : '')
const rowTitle = (row: TeamOverviewRow) => [
    row.disagreesWithGlobal ? 'Differs from the Global decision.' : row.disagrees ? 'Differs from the other teams.' : '',
    row.source === 'draft' ? 'Shows an unsaved edit of this team.' : '',
    row.source === 'automatic' ? 'No team assessment yet; the state is the analyzer proposal.' : '',
    row.required ? '' : 'Not required for this vulnerability any more.',
].filter(Boolean).join(' ')
</script>

<template>
    <div
        data-testid="team-assessment-overview"
        class="mt-2 rounded border border-gray-700/70 bg-gray-950/30 text-[11px]"
    >
        <div class="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-gray-700/60 px-2 py-1.5">
            <span
                class="inline-flex cursor-help items-center gap-1 font-semibold text-gray-300"
                title="Team assessments take precedence; an analyzer proposal is shown only for a missing team. Highlighted rows differ from the other teams or from the Global decision."
            >
                Teams
                <Info :size="11" aria-hidden="true" />
            </span>
            <span data-testid="team-overview-summary" class="min-w-0 flex-1 text-gray-400">{{ overview.summary }}</span>
            <span v-if="worstState" class="flex items-center gap-2">
                <span class="text-gray-500">Worst: <strong class="text-gray-200">{{ stateLabel(worstState) }}</strong></span>
                <button
                    type="button"
                    data-testid="use-effective-assessment-summary"
                    class="rounded bg-purple-700/70 px-2 py-0.5 text-[10px] font-bold text-white hover:bg-purple-600"
                    title="Fill the Global form with the worst team decision and a summary of all teams; nothing is saved."
                    @click="emit('use-worst')"
                >
                    Use worst for Global
                </button>
            </span>
        </div>

        <div
            v-if="decision"
            data-testid="team-overview-global"
            :data-source="decision.source"
            class="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-gray-700/60 px-2 py-1.5"
            :title="decision.source === 'derived' ? DERIVED_HELP : 'A reviewer set the Global decision; it takes precedence over the team assessments.'"
        >
            <span v-if="decision.source === 'derived'" class="text-gray-400">
                <span class="font-semibold text-gray-300">Global:</span> derived, worst of team assessments:
                <span :class="['font-semibold', stateClass(decision.state)]">{{ stateLabel(decision.state) }}</span>
                ({{ decision.teams.join(', ') }})
                <span class="text-gray-500">· no reviewer set it; approving records it</span>
            </span>
            <template v-else>
                <span class="text-gray-400">
                    <span class="font-semibold text-gray-300">Global:</span> set by reviewer:
                    <span :class="['font-semibold', stateClass(decision.state)]">{{ stateLabel(decision.state) }}</span>
                </span>
                <template v-if="differsFromDerived && decision.derived">
                    <span data-testid="team-overview-global-differs" class="text-amber-200">· differs from the worst team assessment ({{ stateLabel(decision.derived.state) }}, {{ decision.derived.teams.join(', ') }})</span>
                    <button
                        type="button"
                        data-testid="team-overview-use-worst"
                        class="rounded border border-purple-600/60 px-2 py-0.5 text-[10px] font-bold text-purple-200 hover:bg-purple-900/40"
                        title="Fill the Global form with the worst team decision; nothing is saved."
                        @click="emit('use-worst')"
                    >
                        Use worst
                    </button>
                </template>
            </template>
        </div>

        <ul class="divide-y divide-gray-800">
            <li
                v-for="row in shownRows"
                :key="row.team"
                data-testid="team-overview-row"
                :data-team="row.team"
                :data-status="row.status"
                :data-disagrees="row.disagrees ? 'true' : 'false'"
                :title="rowTitle(row) || undefined"
                :class="[
                    'border-l-2 px-2 py-1',
                    row.disagrees ? 'border-l-amber-500 bg-amber-950/25' : row.status === 'missing' ? 'border-l-gray-600' : 'border-l-transparent',
                ]"
            >
                <div class="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                    <span class="w-24 shrink-0 truncate font-semibold text-gray-200" :title="row.team">{{ row.team }}</span>
                    <span class="shrink-0" data-testid="team-overview-state">
                        <template v-if="row.state !== 'NOT_SET'">
                            <span :class="['font-semibold', stateClass(row.state)]">{{ stateLabel(row.state) }}</span>
                            <span v-if="row.justification !== 'NOT_SET'" class="text-gray-500"> · {{ stateLabel(row.justification) }}</span>
                            <span v-if="row.source === 'automatic'" class="text-cyan-300"> (analyzer)</span>
                            <span v-else-if="row.source === 'draft'" class="text-amber-300"> (unsaved)</span>
                        </template>
                        <span v-else class="italic text-gray-600">—</span>
                    </span>
                    <span
                        data-testid="team-overview-status"
                        :class="['shrink-0 rounded border px-1 text-[10px]', statusClass(row)]"
                    >{{ statusLabel(row.status) }}</span>
                    <span v-if="row.user || row.timestamp" class="shrink-0 text-gray-500">
                        {{ [row.user, day(row.timestamp)].filter(Boolean).join(', ') }}
                    </span>
                    <span
                        data-testid="team-overview-components"
                        class="shrink-0 cursor-help text-gray-500 underline decoration-dotted"
                        :title="row.components.length ? row.components.join(', ') : 'No mapped component'"
                    >{{ row.components.length }} {{ row.components.length === 1 ? 'component' : 'components' }}</span>
                    <span v-if="!row.required" class="shrink-0 italic text-gray-500">not required</span>
                    <span
                        v-if="row.rationaleFirstLine && !expanded.has(row.team)"
                        class="min-w-[8rem] flex-1 truncate text-gray-400"
                        data-testid="team-overview-rationale"
                    >{{ row.rationaleFirstLine }}</span>
                    <span v-else class="flex-1"></span>
                    <button
                        v-if="canExpand(row)"
                        type="button"
                        data-testid="team-overview-expand"
                        class="shrink-0 text-cyan-300 hover:text-cyan-200"
                        :aria-expanded="expanded.has(row.team) ? 'true' : 'false'"
                        @click="toggleRationale(row.team)"
                    >{{ expanded.has(row.team) ? 'Less' : 'More' }}</button>
                    <span class="flex shrink-0 items-center gap-1">
                        <button
                            type="button"
                            data-testid="team-overview-open"
                            class="rounded border border-gray-600 px-1.5 py-0.5 font-semibold text-gray-300 hover:bg-gray-700 disabled:cursor-not-allowed disabled:opacity-40"
                            :disabled="!row.required"
                            :title="row.required ? `Open the ${row.team} tab; the Global draft is kept.` : 'This team has no tab: the vulnerability does not require it.'"
                            @click="emit('open', row.team)"
                        >Open</button>
                        <button
                            type="button"
                            data-testid="team-overview-use"
                            class="rounded border border-purple-600/60 px-1.5 py-0.5 font-semibold text-purple-200 hover:bg-purple-900/40 disabled:cursor-not-allowed disabled:opacity-40"
                            :disabled="row.state === 'NOT_SET'"
                            title="Put this team's state and justification into the Global form; the text stays. Nothing is saved."
                            @click="emit('use-as-global', row)"
                        >Use as Global</button>
                    </span>
                </div>
                <p
                    v-if="expanded.has(row.team)"
                    data-testid="team-overview-rationale-full"
                    class="mt-1 whitespace-pre-wrap break-words border-l-2 border-gray-700 pl-2 text-gray-400"
                >{{ row.rationale }}</p>
            </li>
        </ul>

        <div
            v-if="collapsible || overview.formerCount"
            class="flex flex-wrap items-center gap-3 border-t border-gray-700/60 px-2 py-1"
        >
            <button
                v-if="collapsible"
                type="button"
                data-testid="team-overview-show-all"
                class="text-cyan-300 hover:text-cyan-200"
                @click="showAll = !showAll"
            >{{ showAll ? 'Show fewer' : `Show all ${overview.rows.length} teams (${hiddenCount} agreeing hidden)` }}</button>
            <button
                v-if="overview.formerCount"
                type="button"
                data-testid="team-overview-former"
                class="text-gray-500 underline decoration-dotted hover:text-gray-300"
                title="Former teams' assessments are kept as historical records; see Existing assessment evidence on the Context tab."
                @click="emit('show-former')"
            >{{ overview.formerCount }} former team {{ overview.formerCount === 1 ? 'assessment' : 'assessments' }}</button>
        </div>
    </div>
</template>
