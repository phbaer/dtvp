<script setup lang="ts">
// The team mapping editor (Settings → Team Mapping) over a draft organised
// by team (ADR 0012). An overview with the key numbers leads to one view at
// a time: the findings no team owns, the projects with their BOM trees, the
// teams, the checks, and the raw JSON. Changes stay in the draft until the
// save bar saves them; errors block saving, warnings do not.
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { onBeforeRouteLeave } from 'vue-router'
import { CircleQuestionMark, RefreshCw } from '@lucide/vue'
import {
    getTeamMappingReport,
    getTeamMappingTeams,
    previewTeamMapping,
    updateTeamMapping,
    uploadTeamMapping,
} from '../../lib/api'
import {
    documentFromTeams,
    isTeamFormat,
    selectorMappingFromTeams,
    teamConfigErrors,
    teamsFromDocument,
    type Team,
} from '../../lib/team-config'
import { parseTeamMappingKey } from '../../lib/team-mapping'
import {
    applyEdits,
    buildChecks,
    checkCounts,
    describeChange,
    diffTeams,
    plural,
    type CheckFix,
    type CheckTarget,
    type EditAction,
} from '../../lib/team-mapping-editing'
import {
    buildInventory,
    entryInsights,
    insightKey,
    type MappingPreview,
    type SuggestedEntry,
    type TeamMappingReportResponse,
} from '../../lib/team-mapping-insights'
import ChecksPanel from './ChecksPanel.vue'
import CoverageBrowser, { type AssignFeedback } from './CoverageBrowser.vue'
import TeamCards from './TeamCards.vue'

const emit = defineEmits<{ saved: []; 'dirty-change': [dirty: boolean] }>()

const teams = ref<Team[]>([])
const savedTeams = ref<Team[]>([])
const savedJson = ref('')
const format = ref<'teams' | 'selectors'>('teams')
const conversionWarnings = ref<string[]>([])
const loading = ref(true)
const loadError = ref('')
const message = ref('')
const error = ref('')
const saving = ref(false)

const reportResponse = ref<TeamMappingReportResponse | null>(null)
const reportError = ref('')
let pollTimer: ReturnType<typeof setTimeout> | null = null

const clone = (list: Team[]): Team[] => list.map(team => ({
    name: team.name,
    aliases: [...team.aliases],
    projects: [...team.projects],
    components: [...team.components],
}))

const teamDocument = computed(() => documentFromTeams(teams.value))
const documentJson = computed(() => JSON.stringify(teamDocument.value, null, 2))
const loaded = computed(() => !loading.value && !loadError.value)
/** The saved file is in the older format: saving writes it by team. */
const converting = computed(() => format.value === 'selectors')
/** The draft differs from the saved mapping. */
const edited = computed(() => loaded.value && documentJson.value !== savedJson.value)
/** Something to save: edits, or a file to write in the team format. */
const dirty = computed(() => edited.value || (loaded.value && converting.value))
const changes = computed(() => diffTeams(savedTeams.value, teams.value))
const mapping = computed(() => selectorMappingFromTeams(teams.value))
const report = computed(() => reportResponse.value?.report || null)
const inventory = computed(() => buildInventory(report.value))
const insights = computed(() => entryInsights(teams.value, inventory.value, mapping.value, Boolean(report.value)))
const errors = computed(() => teamConfigErrors(teamDocument.value))
const checks = computed(() => buildChecks({
    teams: teams.value,
    errors: errors.value,
    insights: insights.value,
    report: report.value,
    conversionWarnings: conversionWarnings.value,
}))
const counts = computed(() => checkCounts(checks.value))

// Only edits ask before leaving; a converted file is the same mapping.
watch(edited, value => emit('dirty-change', value), { immediate: true })

const loadTeams = async () => {
    loading.value = true
    loadError.value = ''
    try {
        const response = await getTeamMappingTeams()
        teams.value = teamsFromDocument(response.teams)
        savedTeams.value = clone(teams.value)
        savedJson.value = JSON.stringify(documentFromTeams(teams.value), null, 2)
        format.value = response.format
        conversionWarnings.value = response.warnings || []
    } catch (err: any) {
        loadError.value = err?.response?.data?.detail || err?.message || 'Unable to load the team mapping.'
    } finally {
        loading.value = false
    }
}

const stopPolling = () => {
    if (pollTimer) clearTimeout(pollTimer)
    pollTimer = null
}

const loadReport = async (refresh = false) => {
    stopPolling()
    reportError.value = ''
    try {
        reportResponse.value = await getTeamMappingReport(refresh)
        if (reportResponse.value.status === 'building') {
            pollTimer = setTimeout(() => loadReport(), 3000)
        }
    } catch (err: any) {
        reportError.value = err?.response?.data?.detail || err?.message || 'Unable to load the report.'
    }
}

// Leaving with unsaved changes asks first.
const beforeUnload = (event: BeforeUnloadEvent) => {
    if (!edited.value) return
    event.preventDefault()
    event.returnValue = ''
}
onMounted(() => {
    loadTeams()
    loadReport()
    window.addEventListener('beforeunload', beforeUnload)
})
onBeforeUnmount(() => {
    stopPolling()
    window.removeEventListener('beforeunload', beforeUnload)
    if (previewTimer) clearTimeout(previewTimer)
})
onBeforeRouteLeave(() => {
    if (!edited.value) return true
    return window.confirm(`Leave without saving? ${plural(changeCount.value, 'unsaved change')} to the team mapping will be lost.`)
})

// -- views ----------------------------------------------------------------------

type View = 'unowned' | 'projects' | 'teams' | 'checks' | 'json'
const view = ref<View>('unowned')
const views = computed<{ id: View; label: string; count?: string }[]>(() => [
    { id: 'unowned', label: 'Unowned', count: report.value ? String(report.value.unmapped_total) : undefined },
    { id: 'projects', label: 'Projects', count: report.value ? String(report.value.projects.length) : undefined },
    { id: 'teams', label: 'Teams', count: String(teams.value.filter(team => team.name.trim()).length) },
    {
        id: 'checks',
        label: 'Checks',
        count: counts.value.errors ? `${counts.value.errors} ${counts.value.errors === 1 ? 'error' : 'errors'}` : String(counts.value.warnings),
    },
    { id: 'json', label: 'Raw JSON' },
])
// With nothing unowned the projects view is the more useful start.
const stopDefaultView = watch(report, (value) => {
    if (!value) return
    if (value.unmapped_total === 0 && view.value === 'unowned') view.value = 'projects'
    stopDefaultView()
})
const tabRefs = ref<HTMLButtonElement[]>([])
const onTabKeydown = (event: KeyboardEvent, index: number) => {
    const count = views.value.length
    const next = event.key === 'ArrowRight' ? (index + 1) % count
        : event.key === 'ArrowLeft' ? (index - 1 + count) % count
            : event.key === 'Home' ? 0
                : event.key === 'End' ? count - 1 : -1
    if (next < 0) return
    event.preventDefault()
    view.value = views.value[next].id
    tabRefs.value[next]?.focus()
}

// -- selection and jumps -------------------------------------------------------

const selectedEntry = ref<{ team: string; key: string } | null>(null)
const focusTeam = ref<string | null>(null)
const focusProject = ref<string | null>(null)
const pickProject = ref<string | null>(null)

const highlight = computed(() => {
    const entry = selectedEntry.value
    if (!entry) return null
    const insight = insights.value.get(insightKey(entry.team, entry.key))
    return {
        key: entry.key,
        selector: parseTeamMappingKey(entry.key),
        projects: insight?.preview.projects || [],
    }
})

const signal = (target: typeof focusTeam, value: string) => {
    target.value = null
    queueMicrotask(() => { target.value = value })
}

const jump = (target: CheckTarget) => {
    if (target.team && target.entry) selectedEntry.value = { team: target.team, key: target.entry }
    if (target.team) {
        view.value = 'teams'
        signal(focusTeam, target.team)
    } else if (target.project) {
        view.value = 'projects'
        signal(focusProject, target.project)
    }
}

const selectEntry = (entry: { team: string; key: string } | null) => {
    selectedEntry.value = entry
    const first = entry ? insights.value.get(insightKey(entry.team, entry.key))?.preview.projects[0] : undefined
    if (first) {
        view.value = 'projects'
        signal(focusProject, first)
    }
}

// -- editing ------------------------------------------------------------------

const feedback = ref<AssignFeedback | null>(null)
let lastAssign: { team: string; created: boolean; actions: EditAction[] } | null = null

const assign = (teamName: string, entries: SuggestedEntry[]) => {
    const created = !teams.value.some(team => team.name.trim().toLowerCase() === teamName.toLowerCase())
    const actions: EditAction[] = entries
        .filter(entry => !teams.value.some(team => team.name.trim().toLowerCase() === teamName.toLowerCase()
            && (entry.kind === 'project' ? team.projects : team.components).includes(entry.value)))
        .map(entry => ({
            type: 'add',
            team: teamName,
            field: entry.kind === 'project' ? 'projects' : 'components',
            value: entry.value,
        }))
    teams.value = applyEdits(teams.value, actions)
    lastAssign = { team: teamName, created, actions }
    const names = entries.map(entry => entry.kind === 'project' ? `project ${entry.value}` : entry.value)
    feedback.value = {
        text: `${created ? `Created team ${teamName} and added` : 'Added'} ${names.join(', ')} to ${teamName}. Not saved yet; the tree shows the result.`,
        canUndo: actions.length > 0,
    }
    message.value = ''
}

const undoAssign = () => {
    if (!lastAssign) return
    const { team, created, actions } = lastAssign
    teams.value = applyEdits(teams.value, actions.map(action => ({ ...action, type: 'remove' })))
    if (created) {
        teams.value = teams.value.filter(item => !(item.name === team
            && !item.aliases.length && !item.projects.length && !item.components.length))
    }
    lastAssign = null
    feedback.value = { text: `Undone: nothing was added to ${team}.`, canUndo: false }
}

const FIELD_NOUN = { aliases: 'alias', projects: 'project', components: 'entry' } as const
const applyFix = (fix: CheckFix) => {
    teams.value = applyEdits(teams.value, fix.actions)
    const done = fix.actions.map(action => action.type === 'remove'
        ? `removed ${FIELD_NOUN[action.field]} ${action.value} from ${action.team}`
        : `added it to ${action.team}`)
    const text = done.join(', ')
    message.value = `${text.charAt(0).toUpperCase()}${text.slice(1)}. Not saved yet.`
}

const assignProject = (project: string) => {
    view.value = 'projects'
    signal(pickProject, project)
}

const addTeam = () => {
    teams.value = [...teams.value, { name: '', aliases: [], projects: [], components: [] }]
}
const removeTeam = (team: Team) => {
    teams.value = teams.value.filter(item => item !== team)
}

// -- the effect of the whole draft -----------------------------------------------

const draftPreview = ref<MappingPreview | null>(null)
const draftPreviewing = ref(false)
let previewTimer: ReturnType<typeof setTimeout> | null = null
let previewRequest = 0
watch([documentJson, dirty], () => {
    if (previewTimer) clearTimeout(previewTimer)
    const current = ++previewRequest
    draftPreview.value = null
    if (!edited.value || errors.value.length || !report.value) {
        draftPreviewing.value = false
        return
    }
    draftPreviewing.value = true
    previewTimer = setTimeout(async () => {
        try {
            const result = await previewTeamMapping(teamDocument.value)
            if (current === previewRequest) draftPreview.value = result
        } catch {
            // The bar then shows the changes without their effect.
        } finally {
            if (current === previewRequest) draftPreviewing.value = false
        }
    }, 600)
})

const catchAllTeam = computed(() => teams.value.find(team => team.components.includes('*'))?.name || null)
/** Unowned findings once the draft is saved (catch-all moves only). */
const unownedAfter = computed(() => {
    if (!report.value || !draftPreview.value) return null
    const team = catchAllTeam.value
    let total = report.value.totals.unmapped
    for (const move of draftPreview.value.moves) {
        const fromUnowned = !move.from || move.from === team
        const toUnowned = !move.to || move.to === team
        if (fromUnowned && !toUnowned) total -= move.findings
        if (!fromUnowned && toUnowned) total += move.findings
    }
    return total
})

// -- saving ---------------------------------------------------------------------

const changeCount = computed(() => changes.value.length + (converting.value ? 1 : 0))
const reviewOpen = ref(false)
const savedNotice = ref(false)
let savedTimer: ReturnType<typeof setTimeout> | null = null

const save = async () => {
    if (errors.value.length) return
    saving.value = true
    message.value = ''
    error.value = ''
    try {
        const result = await updateTeamMapping(teamDocument.value)
        if (result.status !== 'success') throw new Error(result.message)
        message.value = 'Team mapping saved. The report is being rebuilt.'
        reviewOpen.value = false
        feedback.value = null
        lastAssign = null
        await loadTeams()
        await loadReport()
        savedNotice.value = true
        if (savedTimer) clearTimeout(savedTimer)
        savedTimer = setTimeout(() => { savedNotice.value = false }, 5000)
        emit('saved')
    } catch (err: any) {
        error.value = err?.message || 'Failed to save the team mapping.'
    } finally {
        saving.value = false
    }
}

const discard = () => {
    if (!window.confirm(`Discard ${plural(changeCount.value, 'unsaved change')}?`)) return
    teams.value = clone(savedTeams.value)
    reviewOpen.value = false
    feedback.value = null
    lastAssign = null
    message.value = 'Changes discarded.'
}

// -- raw JSON -----------------------------------------------------------------

const rawJson = ref('')
const rawError = ref('')
watch(documentJson, (value) => {
    if (value !== rawJson.value) rawJson.value = value
}, { immediate: true })
const applyRaw = (text: string) => {
    rawJson.value = text
    try {
        const parsed = JSON.parse(text)
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            rawError.value = 'The team mapping must be a JSON object of teams.'
            return
        }
        if (Object.keys(parsed).length && !isTeamFormat(parsed)) {
            rawError.value = 'Give teams as objects ({"Core": {"components": [...]}}); a file of selector keys can be uploaded and is converted.'
            return
        }
        rawError.value = ''
        teams.value = teamsFromDocument(parsed)
    } catch (err: any) {
        rawError.value = err?.message || 'Invalid JSON'
    }
}

const fileInput = ref<HTMLInputElement | null>(null)
const uploading = ref(false)
const upload = async () => {
    const file = fileInput.value?.files?.[0]
    if (!file) return
    if (edited.value && !window.confirm('Uploading replaces the saved mapping and drops your unsaved changes. Upload?')) return
    uploading.value = true
    message.value = ''
    error.value = ''
    try {
        const result = await uploadTeamMapping(file)
        if (result.status !== 'success') throw new Error(result.message)
        message.value = 'Mapping file uploaded; it is stored organised by team.'
        if (fileInput.value) fileInput.value.value = ''
        await loadTeams()
        await loadReport()
        emit('saved')
    } catch (err: any) {
        error.value = err?.message || 'Upload failed.'
    } finally {
        uploading.value = false
    }
}

// -- status -----------------------------------------------------------------------

const formatTime = (value: string | null | undefined) => value
    ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    : ''
const builtAt = computed(() => formatTime(reportResponse.value?.built_at))
const coveragePercent = computed(() => {
    const totals = report.value?.totals
    if (!totals) return null
    return totals.findings ? Math.floor(((totals.findings - totals.unmapped) / totals.findings) * 100) : 100
})
const unownedProjects = computed(() => (report.value?.projects || []).filter(project => project.unmapped > 0).length)

const helpOpen = ref(false)
</script>

<template>
  <div data-testid="team-mapping-editor" class="space-y-4">
    <div class="flex flex-wrap items-start gap-x-4 gap-y-2">
      <div class="min-w-0 flex-1">
        <div class="flex items-center gap-2">
          <h3 class="text-xl font-bold text-gray-200">Team Mapping</h3>
          <button
            type="button"
            data-testid="team-mapping-help-toggle"
            class="rounded p-0.5 text-gray-300 hover:bg-gray-700 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
            :aria-expanded="helpOpen"
            aria-controls="team-mapping-help"
            aria-label="How entries match"
            title="How entries match"
            @click="helpOpen = !helpOpen"
          ><CircleQuestionMark :size="16" /></button>
        </div>
        <p class="mt-1 text-xs text-gray-300">
          Decide which team owns the findings of each project and component. Findings no entry owns are unowned: they fall to the catch-all team.
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-2 text-xs text-gray-300" data-testid="team-mapping-report-status" aria-live="polite">
        <template v-if="reportResponse?.status === 'building'">
          <RefreshCw :size="12" class="animate-spin" aria-hidden="true" />
          <span v-if="report">Report of {{ builtAt }} is out of date; rebuilding…</span>
          <span v-else>Building the report from the stored BOMs and findings…</span>
        </template>
        <template v-else-if="reportResponse?.status === 'failed'">
          <span class="text-red-300">The report failed: {{ reportResponse.error }}</span>
        </template>
        <template v-else-if="reportResponse?.status === 'ready'">
          <span>Report of {{ builtAt }}</span>
        </template>
        <span v-if="reportError" class="text-red-300">{{ reportError }}</span>
        <button type="button" class="rounded px-1 text-blue-300 hover:underline" @click="loadReport(true)">
          {{ reportResponse?.status === 'failed' || reportError ? 'Try again' : 'Rebuild' }}
        </button>
      </div>
    </div>

    <div
      v-if="helpOpen"
      id="team-mapping-help"
      data-testid="team-mapping-help"
      class="rounded border border-gray-600 bg-gray-900 p-3 text-xs text-gray-200"
      @keydown.esc="helpOpen = false"
    >
      <p class="mb-2">A team owns <strong>projects</strong> (Dependency-Track project names) and <strong>component entries</strong>. A finding belongs to the nearest component above it in the BOM that an entry matches; a component entry wins over a project; the team owning <code>*</code> gets the rest. Aliases are former team names.</p>
      <table>
        <tbody class="[&_td]:py-0.5 [&_td:first-child]:pr-4 [&_td:first-child]:font-mono [&_td:first-child]:text-blue-200">
          <tr><td>name</td><td>components with this name, or whose package URL names it</td></tr>
          <tr><td>group:name, group/name</td><td>name in a group</td></tr>
          <tr><td>purl::pkg:type/namespace/name</td><td>a package URL (without version)</td></tr>
          <tr><td>nogroup::name</td><td>name without a group</td></tr>
          <tr><td>cs::name</td><td>exact case</td></tr>
          <tr><td>project:&lt;project&gt;::name</td><td>any of the above, only in one project</td></tr>
          <tr><td>project::&lt;project&gt;</td><td>the project: its findings no component entry owns</td></tr>
          <tr><td>*</td><td>the catch-all</td></tr>
        </tbody>
      </table>
    </div>

    <div v-if="loading" class="rounded border border-gray-700 bg-gray-900/40 p-4 text-xs text-gray-300" data-testid="team-mapping-loading">
      Loading the team mapping…
    </div>
    <div v-else-if="loadError" class="flex flex-wrap items-center gap-3 rounded border border-red-800 bg-red-900/30 p-3 text-xs text-red-200" role="alert">
      <span>{{ loadError }} Nothing can be edited until it loads.</span>
      <button type="button" class="rounded border border-red-600 px-2 py-0.5 hover:bg-red-900" @click="loadTeams">Try again</button>
    </div>

    <template v-else>
      <div v-if="converting" class="rounded border border-blue-800 bg-blue-950/30 p-3 text-xs text-blue-100">
        The file is in the older format (selector → team). It is shown organised by team and written that way when you save.
      </div>
      <div v-if="error" role="alert" class="rounded border border-red-800 bg-red-900/30 p-3 text-xs text-red-200">{{ error }}</div>

      <!-- The overview: the key numbers, each leading to its view. -->
      <div class="grid grid-cols-2 gap-3 lg:grid-cols-4" data-testid="team-mapping-overview">
        <button
          type="button"
          class="rounded border border-gray-700 bg-gray-900/40 p-3 text-left hover:border-blue-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
          @click="view = 'unowned'"
        >
          <div class="text-[11px] font-semibold text-gray-300">Unowned findings</div>
          <div class="mt-0.5 flex items-baseline gap-2">
            <span class="text-2xl font-bold tabular-nums text-amber-300" data-testid="overview-unowned">{{ report ? report.totals.unmapped : '–' }}</span>
            <span v-if="unownedAfter !== null && unownedAfter !== report?.totals.unmapped" class="text-xs text-amber-100" data-testid="overview-unowned-after">
              → {{ unownedAfter }} after saving
            </span>
          </div>
          <div class="text-[11px] text-gray-300">{{ report ? `in ${plural(unownedProjects, 'project')}, on the catch-all` : 'the report is not built yet' }}</div>
        </button>
        <button
          type="button"
          class="rounded border border-gray-700 bg-gray-900/40 p-3 text-left hover:border-blue-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
          @click="view = 'projects'"
        >
          <div class="text-[11px] font-semibold text-gray-300">Owned by a team</div>
          <div class="mt-0.5 text-2xl font-bold tabular-nums text-emerald-300">{{ coveragePercent === null ? '–' : `${coveragePercent}%` }}</div>
          <div class="text-[11px] text-gray-300">
            {{ report ? `${report.totals.findings - report.totals.unmapped} of ${plural(report.totals.findings, 'finding')} in ${plural(report.totals.versions, 'version')}` : 'the report is not built yet' }}
          </div>
        </button>
        <button
          type="button"
          :class="['rounded border bg-gray-900/40 p-3 text-left hover:border-blue-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400', counts.errors ? 'border-red-600' : 'border-gray-700']"
          @click="view = 'checks'"
        >
          <div class="text-[11px] font-semibold text-gray-300">Errors</div>
          <div :class="['mt-0.5 text-2xl font-bold tabular-nums', counts.errors ? 'text-red-300' : 'text-gray-200']" data-testid="overview-errors">{{ counts.errors }}</div>
          <div class="text-[11px] text-gray-300">{{ counts.errors ? 'block saving' : 'nothing blocks saving' }}</div>
        </button>
        <button
          type="button"
          class="rounded border border-gray-700 bg-gray-900/40 p-3 text-left hover:border-blue-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
          @click="view = 'checks'"
        >
          <div class="text-[11px] font-semibold text-gray-300">Warnings</div>
          <div class="mt-0.5 text-2xl font-bold tabular-nums text-gray-200" data-testid="overview-warnings">{{ counts.warnings }}</div>
          <div class="truncate text-[11px] text-gray-300">
            {{ checks.filter(group => group.level === 'warning').map(group => group.title.toLowerCase()).slice(0, 2).join(', ') || 'none' }}
          </div>
        </button>
      </div>

      <!-- One view at a time. -->
      <div role="tablist" aria-label="Team mapping views" class="flex flex-wrap border-b border-gray-700">
        <button
          v-for="(item, index) in views"
          :id="`team-mapping-tab-${item.id}`"
          :key="item.id"
          ref="tabRefs"
          type="button"
          role="tab"
          :data-testid="`team-mapping-view-${item.id}`"
          :aria-selected="view === item.id"
          aria-controls="team-mapping-view"
          :tabindex="view === item.id ? 0 : -1"
          :class="[
            '-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-1.5 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400',
            view === item.id ? 'border-blue-500 text-blue-300' : 'border-transparent text-gray-300 hover:text-white',
          ]"
          @click="view = item.id"
          @keydown="onTabKeydown($event, index)"
        >
          {{ item.label }}
          <span
            v-if="item.count !== undefined"
            :class="['rounded px-1.5 text-[11px] tabular-nums', item.id === 'checks' && counts.errors ? 'bg-red-900/70 text-red-100' : 'bg-gray-700 text-gray-100']"
          >{{ item.count }}</span>
        </button>
      </div>

      <div id="team-mapping-view" role="tabpanel" :aria-labelledby="`team-mapping-tab-${view}`">
        <div v-if="message" data-testid="team-mapping-message" role="status" class="mb-3 rounded border border-emerald-800 bg-emerald-950/40 p-2 text-xs text-emerald-100">{{ message }}</div>

        <CoverageBrowser
          v-show="view === 'unowned' || view === 'projects'"
          :mode="view === 'projects' ? 'projects' : 'unowned'"
          :report="report"
          :teams="teams"
          :highlight="highlight"
          :focus-project="focusProject"
          :pick-project="pickProject"
          :draft="edited ? teamDocument : null"
          :feedback="feedback"
          @assign="assign"
          @undo="undoAssign"
          @dismiss-feedback="feedback = null"
        />

        <TeamCards
          v-if="view === 'teams'"
          :teams="teams"
          :report="report"
          :inventory="inventory"
          :mapping="mapping"
          :insights="insights"
          :selected-entry="selectedEntry"
          :focus-team="focusTeam"
          @select="selectEntry"
          @remove="removeTeam"
          @add="addTeam"
        />

        <ChecksPanel
          v-if="view === 'checks'"
          :groups="checks"
          @jump="jump"
          @fix="applyFix"
          @assign-project="assignProject"
        />

        <div v-if="view === 'json'" class="space-y-2">
          <p class="text-xs text-gray-300">The draft organised by team; edits here apply to the other views and are checked the same way.</p>
          <label for="team-mapping-json" class="sr-only">Team mapping JSON</label>
          <textarea
            id="team-mapping-json"
            :value="rawJson"
            data-testid="team-mapping-json"
            spellcheck="false"
            class="h-80 w-full rounded border border-gray-700 bg-gray-900 p-3 font-mono text-xs text-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
            @input="applyRaw(($event.target as HTMLTextAreaElement).value)"
          />
          <div v-if="rawError" role="alert" class="rounded border border-red-800 bg-red-900/30 p-2 text-xs text-red-200">{{ rawError }}</div>
          <div class="flex flex-wrap items-center gap-2 border-t border-gray-700 pt-3">
            <label for="team-mapping-upload" class="text-xs text-gray-300">Upload a mapping file</label>
            <input id="team-mapping-upload" ref="fileInput" type="file" accept=".json" class="text-xs text-gray-300" />
            <button type="button" :disabled="uploading" class="rounded bg-blue-600 px-3 py-1 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50" @click="upload">
              {{ uploading ? 'Uploading…' : 'Upload and save' }}
            </button>
            <span class="text-[11px] text-gray-300">Either format; it replaces the saved mapping and is stored organised by team.</span>
          </div>
        </div>
      </div>

      <!-- The save bar: what changed, its effect, and save or discard. -->
      <div
        v-if="dirty || saving || savedNotice"
        data-testid="team-mapping-save-bar"
        class="sticky bottom-[-2rem] z-30 -mx-6 -mb-6 rounded-b-lg border-t border-gray-600 bg-gray-900/95 px-6 py-3 shadow-[0_-8px_24px_rgba(0,0,0,0.4)] backdrop-blur"
      >
        <div v-if="reviewOpen && dirty" data-testid="team-mapping-review" class="mb-3 max-h-64 overflow-y-auto rounded border border-gray-700 bg-gray-950/60 p-3 text-xs">
          <h4 class="mb-1 font-semibold text-gray-100">Unsaved changes</h4>
          <ul class="list-disc space-y-0.5 pl-5 text-gray-200">
            <li v-if="converting">The file is written organised by team.</li>
            <li v-for="(change, index) in changes" :key="index">{{ describeChange(change) }}</li>
          </ul>
          <h4 class="mb-1 mt-3 font-semibold text-gray-100">Effect on findings, against the saved mapping</h4>
          <p v-if="errors.length" class="text-red-300">Fix the errors to see the effect.</p>
          <p v-else-if="!report" class="text-gray-300">The report is not built yet.</p>
          <p v-else-if="draftPreviewing" class="text-gray-300">Working out the effect…</p>
          <template v-else-if="draftPreview">
            <p class="text-gray-200">{{ plural(draftPreview.changed, 'finding') }} of {{ draftPreview.findings }} change owner.</p>
            <ul class="list-disc pl-5 text-gray-200">
              <li v-for="move in draftPreview.moves" :key="`${move.from}-${move.to}`">{{ move.from || 'no owner' }} → {{ move.to || 'no owner' }}: {{ move.findings }}</li>
            </ul>
          </template>
        </div>
        <div class="flex flex-wrap items-center gap-x-3 gap-y-2 text-xs" aria-live="polite">
          <template v-if="dirty">
            <span class="inline-flex items-center gap-1.5 font-semibold text-amber-100" data-testid="team-mapping-unsaved">
              <span class="h-2 w-2 rounded-full bg-amber-400" aria-hidden="true" />
              {{ edited ? plural(changeCount, 'unsaved change') : 'Saving writes the older file organised by team' }}
            </span>
            <span v-if="draftPreview" class="text-gray-200">· {{ plural(draftPreview.changed, 'finding') }} change owner</span>
            <span v-else-if="draftPreviewing" class="text-gray-300">· working out the effect…</span>
            <button
              v-if="counts.errors"
              type="button"
              class="text-red-200 underline-offset-2 hover:underline"
              @click="view = 'checks'"
            >{{ plural(counts.errors, 'error') }} {{ counts.errors === 1 ? 'blocks' : 'block' }} saving</button>
            <span class="ml-auto flex flex-wrap items-center gap-2">
              <button
                type="button"
                data-testid="team-mapping-review-toggle"
                class="rounded border border-gray-600 px-3 py-1 text-gray-100 hover:bg-gray-700"
                :aria-expanded="reviewOpen"
                @click="reviewOpen = !reviewOpen"
              >{{ reviewOpen ? 'Hide changes' : 'Review changes' }}</button>
              <button
                type="button"
                data-testid="team-mapping-discard"
                :disabled="saving"
                class="rounded border border-gray-600 px-3 py-1 text-gray-100 hover:bg-gray-700 disabled:opacity-50"
                @click="discard"
              >Discard</button>
              <button
                type="button"
                data-testid="team-mapping-save"
                :disabled="saving || errors.length > 0"
                class="rounded bg-green-700 px-4 py-1 font-bold text-white hover:bg-green-800 disabled:cursor-not-allowed disabled:opacity-50"
                @click="save"
              >{{ saving ? 'Saving…' : 'Save team mapping' }}</button>
            </span>
          </template>
          <span v-else class="font-semibold text-emerald-200" data-testid="team-mapping-saved">Saved. The report is being rebuilt.</span>
        </div>
      </div>
    </template>
  </div>
</template>
