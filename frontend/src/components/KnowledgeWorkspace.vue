<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api, ApiError, send } from '../api'
import { justifications, justificationLabel } from '../assessmentReasons'
import { knowledgeApi, type KnowledgeFinding, type KnowledgeProposal, type KnowledgeWorkspace, type KnowledgeScoreInput, type KnowledgeScorePreview } from '../knowledgeApi'
import type { Me } from '../types'
import SearchSelect from './SearchSelect.vue'
import KnowledgeComparison from './KnowledgeComparison.vue'
import KnowledgeRetained from './KnowledgeRetained.vue'
import KnowledgeLicenses from './KnowledgeLicenses.vue'
import KnowledgeAnalysisEvidence from './KnowledgeAnalysisEvidence.vue'
import KnowledgeSpecialists from './KnowledgeSpecialists.vue'
const props = defineProps<{ me: Me }>()
const project = ref(''), projectName = ref(''), version = ref(''), team = ref(''), lifecycle = ref(''), query = ref('')
const filterLabels: Record<string, string> = { source_severity: 'Source severity', contextual_severity: 'Published severity', applicability: 'Applicability', scoring_status: 'Scoring status', team_review: 'Team assessment', provider: 'Evidence provider', cvss_version: 'Source CVSS version', dependency: 'Dependency relationship', source_conflict: 'Source discrepancies', component: 'Component' }
const emptyFilters = () => Object.fromEntries(Object.keys(filterLabels).map(key => [key, '']))
const filters = ref(emptyFilters()), filterDraft = ref(emptyFilters())
const activeFilterCount = computed(() => Object.values(filters.value).filter(Boolean).length)
const severityBands = ['critical', 'high', 'medium', 'low', 'none', 'unknown']
const savedViews = ref<{ name: string; query: string }[]>([]), viewName = ref('')
const initialView = new URLSearchParams(location.search)
let restoring = false
const versions = ref<{ version: string; state: string }[]>([])
const versionMenu = ref(false), versionQuery = ref(''), versionNext = ref<number | null>(null), versionBusy = ref(false)
let versionSequence = 0, versionTimer: ReturnType<typeof setTimeout> | undefined
const workspace = ref<KnowledgeWorkspace | null>(null), selected = ref<KnowledgeFinding | null>(null)
const knownTeamLabels = ref<Record<string, string>>({})
let teamLabelProject = ''
const teamOptions = computed(() => {
  const labels = Object.fromEntries(props.me.workspaces.map(item => [item.id, item.name]))
  return Object.entries({ ...labels, ...knownTeamLabels.value }).map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name))
})
const offset = ref(0), previous = ref<number[]>([]), busy = ref(false), error = ref(''), notice = ref('')
const tab = ref<'evidence' | 'assessment' | 'review' | 'scoring'>('evidence')
const applicability = ref('under_investigation'), justification = ref(''), rationale = ref(''), conditions = ref('')
const scoreBase = ref(''), scoreVector = ref(''), scoreRationale = ref('')
const scorePreview = ref<{ input: KnowledgeScoreInput; result: KnowledgeScorePreview } | null>(null)
const sourceVectors = computed(() => [...new Set(selected.value?.source_ratings.map(item => item.vector).filter((value): value is string => Boolean(value)) || [])])
const workflowTabs = computed(() => can('rescore') ? ['evidence', 'assessment', 'review', 'scoring'] as const : ['evidence', 'assessment', 'review'] as const)
const assessmentId = ref(''), confirmed = ref(false), reviewRationale = ref('')
let pendingRequest: { signature: string; requestId: string } | null = null
let sequence = 0, timer: ReturnType<typeof setTimeout> | undefined
const scope = computed(() => `/projects/${encodeURIComponent(project.value)}/versions/${encodeURIComponent(version.value)}`)
const assessment = computed(() => selected.value?.coverage.assessment)
const label = (value: string) => value.replaceAll('_', ' ')
const teamName = (id?: string) => (id ? workspace.value?.team_labels?.[id] : undefined) || props.me.workspaces.find(item => item.id === id)?.name || id || 'Unassigned'
const can = (capability: string) => Boolean(selected.value?.capabilities.includes(capability))
const ratingSource = (rating: KnowledgeFinding['source_ratings'][number]) => (typeof rating.source === 'string' ? rating.source : rating.source?.name || rating.source?.url) || rating.observed_source || 'Unattributed source'
const sourceScore = (row: KnowledgeFinding) => row.source_ratings.filter(r => r.score != null).map(r => r.score!.toFixed(1)).join(' / ') || (typeof row.source_severity === 'string' ? label(row.source_severity) : 'Unknown')
const selectedIndex = computed(() => workspace.value?.items.findIndex(item => item.id === selected.value?.id) ?? -1)
function fail(err: unknown) { error.value = err instanceof ApiError && err.status === 409 ? 'The baseline or assessment changed. Refresh before retrying; your text is retained.' : err instanceof Error ? err.message : 'Request failed' }
function close() { selected.value = null; confirmed.value = false; scorePreview.value = null }
async function load(reset = true, keep = false) {
  const current = ++sequence
  if (!project.value || !version.value) { workspace.value = null; close(); return }
  busy.value = true; error.value = ''
  if (reset) { offset.value = 0; previous.value = [] }
  if (!keep) close()
  try {
    const params = new URLSearchParams({ offset: String(offset.value), limit: '30', q: query.value, team_id: team.value, lifecycle: lifecycle.value, ...Object.fromEntries(Object.entries(filters.value).filter(([, value]) => value !== '')) })
    if (!reset && workspace.value?.state) params.set('expected', workspace.value.state)
    const result = await knowledgeApi<KnowledgeWorkspace>(`${scope.value}/workspace?${params}`)
    if (current === sequence) { workspace.value = result; knownTeamLabels.value = { ...knownTeamLabels.value, ...result.team_labels }; syncViewUrl() }
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function chooseProject(option: { id: string; name?: string }, preferredVersion = '') {
  if (teamLabelProject !== option.id) { knownTeamLabels.value = {}; teamLabelProject = option.id; if (!restoring) team.value = '' }
  const current = ++sequence; ++versionSequence; projectName.value = option.name || option.id; versions.value = []; version.value = ''; versionQuery.value = ''; versionMenu.value = false; workspace.value = null; close()
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const result = await knowledgeApi<{ items: { version: string; state: string }[]; next_offset: number | null }>(`/projects/${encodeURIComponent(option.id)}/versions?limit=25`)
    if (current !== sequence) return
    versions.value = result.items; versionNext.value = result.next_offset; version.value = preferredVersion || result.items[0]?.version || ''; await load()
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function seedDemo() {
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const result = await knowledgeApi<{ project_id: string; project_name: string; version: string }>('/playground/knowledge/seed', send({}))
    project.value = result.project_id
    await chooseProject({ id: result.project_id, name: result.project_name })
    if (version.value !== result.version) { version.value = result.version; await load() }
    if (!error.value) notice.value = 'Synthetic workflow demo loaded. Existing interactive work is retained.'
  } catch (err) { fail(err) }
  finally { busy.value = false }
}
async function loadVersions(append = false) {
  const current = ++versionSequence; versionBusy.value = true
  try {
    const params = new URLSearchParams({ q: versionQuery.value, offset: String(append ? versionNext.value || 0 : 0), limit: '25' })
    const result = await knowledgeApi<{ items: { version: string; state: string }[]; next_offset: number | null }>(`/projects/${encodeURIComponent(project.value)}/versions?${params}`)
    if (current === versionSequence) { versions.value = append ? [...versions.value, ...result.items] : result.items; versionNext.value = result.next_offset }
  } catch (err) { if (current === versionSequence) fail(err) }
  finally { if (current === versionSequence) versionBusy.value = false }
}
function searchVersions() { clearTimeout(versionTimer); versionTimer = setTimeout(() => { void loadVersions() }, 200) }
function chooseVersion(value: string) { version.value = value; versionMenu.value = false; void load() }
async function open(row: KnowledgeFinding) {
  const current = ++sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    const detail = await knowledgeApi<KnowledgeFinding>(`${scope.value}/workspace/${encodeURIComponent(row.context_id)}/${encodeURIComponent(row.vulnerability_id)}?expected=${workspace.value!.state}`)
    if (current !== sequence) return
    selected.value = detail; tab.value = 'evidence'; confirmed.value = false; reviewRationale.value = ''; scorePreview.value = null
    scoreBase.value = detail.source_ratings.find(item => item.vector)?.vector || ''; scoreVector.value = scoreBase.value; scoreRationale.value = ''
    const record = detail.coverage.assessment
    assessmentId.value = record?.payload.assessment_id || crypto.randomUUID()
    applicability.value = record?.payload.state || 'under_investigation'; rationale.value = record?.payload.rationale || ''
    justification.value = record?.payload.justification || ''; conditions.value = record?.payload.conditions || ''
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function paginate(next: boolean) {
  if (next) { previous.value.push(offset.value); offset.value = workspace.value!.next_offset! }
  else offset.value = previous.value.pop() || 0
  await load(false)
}
async function mutate(kind: 'draft' | 'submit' | 'approve' | 'request_changes') {
  if (!selected.value || !workspace.value) return
  busy.value = true; error.value = ''; notice.value = ''; const row = selected.value
  try {
    const base = { expected_versions: { [version.value]: workspace.value.state }, targets: [{ version: version.value, context_id: row.context_id, vulnerability_id: row.vulnerability_id }] }
    const path = `/projects/${encodeURIComponent(project.value)}`
    const endpoint = kind === 'draft' || kind === 'submit' ? `${path}/assessments/${encodeURIComponent(assessmentId.value)}/${kind}` : `${path}/reviews`
    const body = kind === 'draft' || kind === 'submit'
      ? { ...base, expected_revision: assessment.value?.revision || null, state: applicability.value, justification: applicability.value === 'not_affected' ? justification.value || null : null, rationale: rationale.value, conditions: conditions.value, evidence: assessment.value?.payload.evidence || [] }
      : { ...base, assessment_id: assessment.value!.payload.assessment_id, assessment_revision: assessment.value!.revision, action: kind, rationale: reviewRationale.value }
    const signature = JSON.stringify({ endpoint, body })
    if (pendingRequest?.signature !== signature) pendingRequest = { signature, requestId: crypto.randomUUID() }
    await knowledgeApi(endpoint, send({ ...body, request_id: pendingRequest.requestId }))
    pendingRequest = null
    await load(true, true); if (error.value) return
    await open(row)
    if (!error.value) { notice.value = kind === 'draft' ? 'Draft saved.' : kind === 'submit' ? 'Assessment submitted for independent review.' : kind === 'approve' ? 'Assessment approved.' : 'Changes requested.'; tab.value = kind === 'draft' ? 'assessment' : 'review' }
  } catch (err) { fail(err) }
  finally { busy.value = false }
}
function useProposal(proposal: KnowledgeProposal) {
  if (!can('rescore') || !proposal.eligible || !proposal.score_input) return
  scoreBase.value = proposal.score_input.base_vector; scoreVector.value = proposal.score_input.vector
  scoreRationale.value = ''; tab.value = 'scoring'
  notice.value = 'Proposal loaded. Add your rationale and preview required reviews before publication.'
}
async function previewScore() {
  if (!selected.value || !workspace.value || !can('rescore')) return
  busy.value = true; error.value = ''; notice.value = ''; scorePreview.value = null
  try {
    const input: KnowledgeScoreInput = { request_id: crypto.randomUUID(), expected_versions: { [version.value]: selected.value.state || workspace.value.state }, targets: [{ version: version.value, context_id: selected.value.context_id, vulnerability_id: selected.value.vulnerability_id }], base_vector: scoreBase.value, vector: scoreVector.value, rationale: scoreRationale.value }
    const result = await knowledgeApi<KnowledgeScorePreview>(`/projects/${encodeURIComponent(project.value)}/scoring/preview`, send(input))
    scorePreview.value = { input, result }
  } catch (err) { fail(err) }
  finally { busy.value = false }
}
async function publishScore() {
  if (!scorePreview.value?.result.eligible || !selected.value || !can('rescore')) return
  busy.value = true; error.value = ''; notice.value = ''; const row = selected.value
  try {
    await knowledgeApi(`/projects/${encodeURIComponent(project.value)}/scoring/publish`, send({ ...scorePreview.value.input, preview: scorePreview.value.result.preview }))
    scorePreview.value = null
    await load(true, true); if (error.value) return
    await open(row)
    if (!error.value) { tab.value = 'scoring'; notice.value = 'Contextual score published.' }
  } catch (err) { fail(err) }
  finally { busy.value = false }
}
watch([scoreBase, scoreVector, scoreRationale], () => { scorePreview.value = null }, { flush: 'sync' })
function viewParams() {
  const params = new URLSearchParams()
  const values = { project: project.value, version: version.value, team: team.value, lifecycle: lifecycle.value, q: query.value, ...filters.value }
  for (const [key, value] of Object.entries(values)) if (value) params.set(`k_${key}`, value)
  return params
}
function syncViewUrl() {
  const params = new URLSearchParams(location.search)
  for (const key of [...params.keys()]) if (key.startsWith('k_')) params.delete(key)
  for (const [key, value] of viewParams()) params.set(key, value)
  params.set('page', 'Knowledge')
  history.replaceState(null, '', `${location.pathname}?${params}`)
}
async function applyFilters() { filters.value = { ...filterDraft.value }; await load() }
async function resetFilters() { filterDraft.value = emptyFilters(); filters.value = emptyFilters(); await load() }
function persistViews() { localStorage.setItem(`dtvp.knowledge.views:${props.me.id}`, JSON.stringify(savedViews.value)) }
function saveView() {
  const name = viewName.value.trim().slice(0, 100)
  if (!name) return
  savedViews.value = [...savedViews.value.filter(item => item.name !== name), { name, query: viewParams().toString() }].slice(-20)
  try { persistViews(); viewName.value = ''; notice.value = 'View saved in this browser for your user.' } catch { error.value = 'Browser storage is unavailable.' }
}
function removeView(name: string) { savedViews.value = savedViews.value.filter(item => item.name !== name); try { persistViews() } catch { error.value = 'Browser storage is unavailable.' } }
async function restoreView(value: string) {
  if (busy.value) return
  const params = new URLSearchParams(value), id = params.get('k_project') || ''
  restoring = true; busy.value = true; error.value = ''
  try {
    team.value = params.get('k_team') || ''; lifecycle.value = params.get('k_lifecycle') || ''; query.value = params.get('k_q') || ''
    filters.value = Object.fromEntries(Object.keys(filterLabels).map(key => [key, params.get(`k_${key}`) || ''])); filterDraft.value = { ...filters.value }
    if (id) { const result = await api<{ id: string; name: string }>(`/projects/${encodeURIComponent(id)}`); project.value = result.id; await chooseProject(result, params.get('k_version') || '') }
    else await load()
  } catch (err) { fail(err) }
  finally { restoring = false; busy.value = false }
}
async function copyView() {
  syncViewUrl()
  try { await navigator.clipboard.writeText(location.href); notice.value = 'View link copied.' } catch { error.value = 'Clipboard unavailable. Copy this page address instead.' }
}
watch([team, lifecycle], () => { if (!restoring) void load() })
watch(() => props.me.id, () => { knownTeamLabels.value = {}; team.value = ''; workspace.value = null; close(); void load() })
watch(query, () => { if (restoring) return; clearTimeout(timer); timer = setTimeout(() => { void load() }, 250) })
onMounted(() => {
  try { const stored: unknown = JSON.parse(localStorage.getItem(`dtvp.knowledge.views:${props.me.id}`) || '[]'); if (Array.isArray(stored)) savedViews.value = stored.filter(item => item && typeof item.name === 'string' && typeof item.query === 'string').slice(-20) } catch { /* Browser storage is optional. */ }
  if (initialView.has('k_project')) void restoreView(initialView.toString())
})
onBeforeUnmount(() => { ++sequence; ++versionSequence; clearTimeout(timer); clearTimeout(versionTimer) })
</script>
<template>
  <section class="knowledge-workspace" aria-label="Knowledge workspace">
    <header class="knowledge-heading"><div><h1>Contextual review</h1><p class="hint">Product version · consuming context · responsible team</p></div><div class="knowledge-actions"><button v-if="me.playground" :disabled="busy" @click="seedDemo">Load workflow demo</button><button :disabled="busy || !version" @click="load()">Refresh workspace</button></div></header>
    <form class="knowledge-filters" @submit.prevent="load()">
      <SearchSelect v-model="project" label="Knowledge product" :selected-label="projectName" endpoint="/catalog/projects" :disabled="busy" @select="chooseProject" />
      <div class="search-select" @keydown.esc="versionMenu = false"><span class="field-label" id="knowledge-version-label">Version</span><button type="button" :disabled="busy || !project" aria-labelledby="knowledge-version-label knowledge-version-value" :aria-expanded="versionMenu" aria-haspopup="listbox" @click="versionMenu = !versionMenu"><span id="knowledge-version-value">{{ version || 'Select…' }}</span><span aria-hidden="true">⌄</span></button><div v-if="versionMenu" class="select-menu"><input v-model="versionQuery" type="search" aria-label="Search versions" placeholder="Search versions" @input="searchVersions"><div role="listbox" aria-label="Version"><button v-for="item in versions" :key="item.version" type="button" role="option" :aria-selected="version === item.version" @click="chooseVersion(item.version)">{{ item.version }}</button></div><p v-if="versionBusy" role="status">Searching…</p><p v-else-if="!versions.length">No matching versions.</p><button v-if="versionNext != null" type="button" :disabled="versionBusy" @click="loadVersions(true)">More versions</button></div></div>
      <label>Responsible team<select v-model="team" :disabled="busy"><option value="">All accessible teams</option><option v-for="item in teamOptions" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
      <label>Review status<select v-model="lifecycle" :disabled="busy"><option value="">All statuses</option><option v-for="status in ['unassessed', 'draft', 'submitted', 'approved', 'reassessment_needed', 'historically_absent']" :key="status" :value="status">{{ label(status) }}</option></select></label>
      <label class="knowledge-search">Search<input v-model="query" :disabled="busy" type="search" placeholder="Vulnerability, component or description"></label>
    </form>
    <details class="knowledge-advanced"><summary>More filters<span v-if="activeFilterCount"> · {{ activeFilterCount }} applied</span></summary>
      <form @submit.prevent="applyFilters"><fieldset :disabled="busy"><div class="knowledge-filter-grid">
        <label>Source severity<select v-model="filterDraft.source_severity"><option value="">Any source severity</option><option v-for="band in severityBands" :key="band" :value="band">{{ label(band) }}</option></select></label>
        <label>Published severity<select v-model="filterDraft.contextual_severity"><option value="">Any published severity</option><option v-for="band in severityBands" :key="band" :value="band">{{ label(band) }}</option></select></label>
        <label>Context applicability<select v-model="filterDraft.applicability"><option value="">Any applicability</option><option v-for="value in ['affected', 'not_affected', 'fixed', 'under_investigation', 'unassessed', 'unknown']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Scoring status<select v-model="filterDraft.scoring_status"><option value="">Any scoring status</option><option v-for="value in ['published', 'outdated', 'not_published', 'unknown']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Team assessment<select v-model="filterDraft.team_review"><option value="">Any team assessment</option><option v-for="value in ['missing', 'recorded', 'current', 'draft', 'submitted', 'pending', 'approved', 'needs_revalidation', 'changes_requested']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Evidence provider<input v-model="filterDraft.provider" maxlength="200" placeholder="Exact attributed source"></label>
        <label>Source CVSS version<select v-model="filterDraft.cvss_version"><option value="">Any CVSS version</option><option v-for="value in ['2.0', '3.0', '3.1', '4.0', 'unknown']" :key="value" :value="value">{{ value }}</option></select></label>
        <label>Dependency relationship<select v-model="filterDraft.dependency"><option value="">Any relationship</option><option v-for="value in ['root', 'direct', 'transitive', 'unknown']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Source discrepancies<select v-model="filterDraft.source_conflict"><option value="">Any source discrepancies</option><option value="yes">Reported discrepancy</option><option value="no">No comparable discrepancy observed</option><option value="unknown">Unknown</option></select></label>
        <label>Component<input v-model="filterDraft.component" maxlength="500" placeholder="Name, namespace or package URL"></label>
      </div><div class="knowledge-actions"><button type="button" @click="resetFilters">Reset advanced filters</button><button class="primary">Apply filters</button></div></fieldset></form>
      <p class="hint">Filters and counts use the full server result. Unknown evidence stays unknown; outdated scores are excluded from published severity.</p>
    </details>
    <details class="knowledge-views"><summary>Saved views and sharing</summary><div class="knowledge-actions"><label>View name<input v-model="viewName" maxlength="100" placeholder="Save the applied scope"></label><button :disabled="busy || !project || !viewName.trim()" @click="saveView">Save view</button><button :disabled="busy || !project" @click="copyView">Copy view link</button></div><ul v-if="savedViews.length"><li v-for="view in savedViews" :key="view.name"><button :disabled="busy" @click="restoreView(view.query)">{{ view.name }}</button><button :disabled="busy" :aria-label="`Remove view ${view.name}`" @click="removeView(view.name)">×</button></li></ul></details>
    <KnowledgeComparison :project="project" />
    <p v-if="error" role="alert" class="message">{{ error }}</p><p v-if="notice" role="status" class="message">{{ notice }}</p><p v-if="busy" role="status">Loading…</p>
    <p v-if="project && !busy && !version && !versions.length" class="empty">No journal-backed versions. Import a baseline to start.</p><p v-else-if="!project" class="empty">Select a product to review its versioned knowledge.</p>
    <template v-if="workspace">
      <p v-if="workspace.baseline_status === 'withdrawn'" role="status" class="message">The current inventory was withdrawn. Historical assessments and release tags remain retained.</p>
      <div class="knowledge-statistics" aria-label="Filtered workspace statistics"><span><strong>{{ workspace.statistics.totals.context_findings }}</strong> context findings</span><span><strong>{{ workspace.statistics.totals.unique_vulnerabilities }}</strong> vulnerabilities</span><span><strong>{{ workspace.statistics.recorded }}</strong> recorded</span><span><strong>{{ workspace.statistics.submitted }}</strong> submitted</span><span><strong>{{ workspace.statistics.approved }}</strong> approved</span><details><summary>Breakdown</summary><dl><template v-for="(count, status) in workspace.statistics.by_status" :key="status"><dt>{{ label(String(status)) }}</dt><dd>{{ count }}</dd></template><template v-for="(count, id) in workspace.statistics.by_team" :key="id"><dt>{{ teamName(String(id)) }}</dt><dd>{{ typeof count === 'number' ? count : count.context_findings }} findings</dd></template><template v-for="(count, severity) in workspace.statistics.severity" :key="severity"><dt>{{ severity }}</dt><dd>{{ count }}</dd></template></dl></details></div>
      <KnowledgeRetained v-if="workspace.statistics.retained_absent_assessments" :project="project" :state="workspace.state" :team="team" />
      <KnowledgeLicenses :project="project" :version="version" :state="workspace.state" @changed="load(true, true)" />
      <div class="knowledge-columns" :class="{ 'has-detail': selected }">
        <section class="knowledge-queue" aria-label="Context finding queue"><div class="table-wrap"><table><thead><tr><th>Vulnerability / component</th><th>Team / status</th><th>Source</th><th>Published</th></tr></thead><tbody><tr v-for="row in workspace.items" :key="row.id" :class="{ selected: selected?.id === row.id }"><td><button class="text-link" :disabled="busy" @click="open(row)">{{ row.vulnerability_id }}</button><small>{{ row.component.name }} {{ row.component.version }}</small></td><td>{{ teamName(row.context.team_id) }}<small>{{ label(row.coverage.status) }}</small></td><td>{{ sourceScore(row) }}</td><td>{{ row.published_score?.score.toFixed(1) ?? '—' }}<small v-if="row.published_score?.current === false">Outdated</small></td></tr></tbody></table><p v-if="!workspace.items.length && !busy" class="empty">No context findings match this scope.</p></div><div class="knowledge-pagination"><button :disabled="busy || !previous.length" @click="paginate(false)">Previous page</button><span>{{ offset + (workspace.items.length ? 1 : 0) }}–{{ offset + workspace.items.length }}</span><button :disabled="busy || workspace.next_offset == null" @click="paginate(true)">Next page</button></div></section>
        <section v-if="selected" class="knowledge-detail" aria-label="Context finding detail">
          <header><div><h2>{{ selected.vulnerability_id }}</h2><p>{{ selected.component.name }} {{ selected.component.version }}</p></div><button aria-label="Close context finding" :disabled="busy" @click="close()">×</button></header><p class="hint">{{ teamName(selected.context.team_id) }} · {{ label(selected.coverage.status) }}</p>
          <div class="knowledge-score-pair"><span>Source <strong>{{ sourceScore(selected) }}</strong></span><span>Published <strong>{{ selected.published_score?.score.toFixed(1) ?? 'Not published' }}</strong><small v-if="selected.published_score?.current === false"> · Outdated</small></span></div>
          <KnowledgeAnalysisEvidence v-if="selected.code_analysis?.length" :items="selected.code_analysis" />
          <KnowledgeSpecialists :project="project" :state="workspace.state" :finding="selected" />
          <details v-if="selected.scoring_proposals?.length" class="knowledge-pane"><summary>External scoring proposals ({{ selected.scoring_proposals.length }})</summary><div class="table-wrap"><table aria-label="External scoring comparison"><thead><tr><th>Provider</th><th>Source Base</th><th>Proposed</th><th>Status</th><th v-if="can('rescore')">Action</th></tr></thead><tbody><tr v-for="proposal in selected.scoring_proposals" :key="proposal.id"><td>{{ proposal.source_label }}<small>{{ proposal.provider }}</small></td><td>{{ proposal.proposal?.base_score.toFixed(1) ?? 'Unknown' }}</td><td>{{ proposal.proposal?.score.toFixed(1) ?? 'Withheld' }}</td><td>{{ proposal.eligible ? 'Ready for coordinator preview' : proposal.ineligibility_reasons.map(label).join(' · ') }}<small>{{ proposal.current ? 'Current evidence' : 'Historical evidence' }}</small></td><td v-if="can('rescore')"><button :disabled="busy || !proposal.eligible" @click="useProposal(proposal)">Use proposal</button></td></tr></tbody></table></div><p class="hint">External proposals do not approve assessments or publish scores. Artifact consistency does not verify provider identity.</p><details><summary>Proposal vectors and provenance</summary><pre>{{ JSON.stringify(selected.scoring_proposals, null, 2) }}</pre></details></details>
          <details v-if="selected.curated_metadata" class="knowledge-pane"><summary>Curated component context · {{ label(selected.curated_metadata.status) }}</summary><p v-if="!selected.curated_metadata.applicable" class="warning">Historical annotations require reconciliation with this component/version before use.</p><dl><dt>Criticality / exposure</dt><dd>{{ label(selected.curated_metadata.payload.annotations.cybersecurity.criticality) }} · {{ label(selected.curated_metadata.payload.annotations.cybersecurity.exposure) }}</dd><dt>Deployment</dt><dd>{{ selected.curated_metadata.payload.annotations.deployment.environment || 'Unknown' }}</dd><dt>Usage</dt><dd>{{ selected.curated_metadata.payload.annotations.deployment.usage || 'Unknown' }}</dd><dt>Support</dt><dd>{{ label(selected.curated_metadata.payload.annotations.support.status) }}</dd><dt>Source</dt><dd>{{ selected.curated_metadata.payload.provenance.source }} · {{ selected.curated_metadata.payload.provenance.reference }}</dd></dl><p>{{ selected.curated_metadata.payload.rationale }}</p><details><summary>Mitigations, testing and supporting details</summary><pre>{{ JSON.stringify(selected.curated_metadata.payload.annotations, null, 2) }}</pre></details></details>
          <details v-if="selected.legacy_evidence?.length" class="knowledge-pane"><summary>Imported DT assessment history</summary><p class="hint">Historical team and author labels are source claims. These records do not establish current DTVP approval.</p><article v-for="claim in selected.legacy_evidence" :key="claim.id"><h3>{{ claim.source }} · {{ label(claim.status) }}</h3><p v-if="claim.conflicting" class="warning">Conflicting imported team conclusions require reconciliation.</p><div v-for="(record, index) in claim.current_records" :key="index"><strong>{{ record.team }} · {{ label(record.state || 'unknown') }}</strong><p>{{ record.rationale }}</p><p v-if="record.justification">{{ justificationLabel(record.justification) }}</p><small>Historical assessor: {{ record.assessor || 'Unknown' }} · reviewer: {{ record.reviewer || 'Unknown' }}</small></div><p v-if="!claim.current_records.length">{{ claim.raw_text || claim.raw_excerpt || 'No interpretable assessment text.' }}</p><ul v-if="claim.errors.length"><li v-for="issue in claim.errors" :key="issue">{{ issue }}</li></ul><details><summary>Complete imported history, comments and score claims</summary><pre>{{ JSON.stringify(claim, null, 2) }}</pre></details></article></details>
          <nav class="knowledge-tabs" aria-label="Assessment workflow"><button v-for="step in workflowTabs" :key="step" :aria-pressed="tab === step" @click="tab = step">{{ label(step) }}</button></nav>
          <div v-if="tab === 'evidence'" class="knowledge-pane"><p class="knowledge-description">{{ selected.description || 'No source description provided.' }}</p><dl><dt>Consuming root</dt><dd>{{ selected.context.root_ref || 'Unknown' }}</dd><dt>Ownership</dt><dd>{{ label(selected.context.status || 'unknown') }}</dd><dt>Package</dt><dd>{{ selected.component.purl || 'Unknown' }}</dd></dl><details><summary>Source ratings and vectors</summary><ul><li v-for="(rating, index) in selected.source_ratings" :key="index">{{ ratingSource(rating) }} · {{ rating.method || 'Unspecified method' }} · {{ rating.score ?? 'Unknown score' }}<code>{{ rating.vector }}</code></li></ul></details><details><summary>Dependency and ownership evidence</summary><pre>{{ JSON.stringify(selected.context, null, 2) }}</pre></details><details><summary>Imported source claims</summary><pre>{{ JSON.stringify(selected.sourcefacts || [], null, 2) }}</pre></details><details><summary>Additional evidence</summary><pre>{{ JSON.stringify(selected.evidence || [], null, 2) }}</pre></details><button v-if="can('assess')" class="primary" @click="tab = 'assessment'">Assess this context</button></div>
          <form v-if="tab === 'assessment'" class="knowledge-pane" @submit.prevent="mutate('submit')"><p v-if="selected.coverage.approved_assessment" class="hint">An approved assessment is retained. A new draft does not replace its approved pin.</p><fieldset :disabled="busy || !can('assess')"><label>Applicability<select v-model="applicability"><option v-for="state in ['under_investigation', 'affected', 'not_affected', 'fixed']" :key="state" :value="state">{{ label(state) }}</option></select></label><label v-if="applicability === 'not_affected'">Why not affected?<select v-model="justification" required><option value="" disabled>Select a reason</option><option v-for="(text, code) in justifications" :key="code" :value="code">{{ text }}</option></select></label><label>Reason and evidence<textarea v-model="rationale" rows="5" required placeholder="Explain this decision for the selected consuming context."></textarea></label><details><summary>Applicability conditions</summary><label>Conditions<textarea v-model="conditions" rows="3"></textarea></label></details></fieldset><p v-if="!can('assess')" class="hint">Assessment editing is unavailable for this context.</p><div v-else class="knowledge-actions"><button type="button" :disabled="busy" @click="mutate('draft')">Save draft</button><button class="primary" :disabled="busy || !rationale.trim() || (applicability === 'not_affected' && !justification)">Submit assessment</button></div></form>
          <div v-if="tab === 'review'" class="knowledge-pane"><template v-if="assessment"><h3>{{ label(assessment.payload.state) }}</h3><p v-if="assessment.payload.justification">{{ justificationLabel(assessment.payload.justification) }}</p><p class="knowledge-rationale">{{ assessment.payload.rationale }}</p><p v-if="assessment.payload.conditions" class="knowledge-rationale">Conditions: {{ assessment.payload.conditions }}</p><small>{{ label(assessment.stage) }} · Author {{ assessment.payload.author_id || 'Unknown' }}</small><details><summary>Assessment scope and evidence</summary><pre>{{ JSON.stringify({ targets: assessment.payload.targets, evidence: assessment.payload.evidence }, null, 2) }}</pre></details><template v-if="can('approve')"><label>Review rationale<textarea v-model="reviewRationale" rows="3" placeholder="Explain approval or requested changes."></textarea></label><label class="knowledge-confirm"><input v-model="confirmed" type="checkbox">I checked the evidence, applicability and context of this assessment.</label><div class="knowledge-actions"><button :disabled="busy || !confirmed || !reviewRationale.trim()" @click="mutate('request_changes')">Request changes</button><button class="primary" :disabled="busy || !confirmed || !reviewRationale.trim()" @click="mutate('approve')">Approve assessment</button></div></template><p v-else class="hint">Independent review actions are unavailable for this assessment.</p></template><p v-else>No assessment recorded for this context.</p><details v-if="selected.coverage.approved_assessment"><summary>Retained approved assessment</summary><p>{{ selected.coverage.approved_assessment.payload.rationale }}</p></details></div>
          <form v-if="tab === 'scoring' && can('rescore')" class="knowledge-pane" aria-label="Coordinator rescoring" @submit.prevent="previewScore">
            <p class="hint">Publication requires current independent reviews for every required context of this vulnerability.</p>
            <fieldset :disabled="busy">
              <label>Source Base vector<select v-model="scoreBase" :disabled="!sourceVectors.length" @change="scoreVector = scoreBase"><option v-if="!sourceVectors.length" value="">No source vector available</option><option v-for="vector in sourceVectors" :key="vector" :value="vector">{{ vector }}</option></select></label>
              <details><summary>Contextual vector</summary><p class="hint">Keep source Base metrics; adjust contextual metrics for this consuming context.</p><label>Proposed contextual vector<textarea v-model="scoreVector" rows="3" spellcheck="false"></textarea></label></details>
              <label>Scoring rationale<textarea v-model="scoreRationale" rows="3" required placeholder="Explain the contextual metrics and supporting evidence."></textarea></label>
            </fieldset>
            <p v-if="!sourceVectors.length" class="hint">A source Base vector is required before a contextual score can be proposed.</p>
            <section v-if="scorePreview" class="knowledge-score-preview" aria-label="Scoring preview">
              <div class="knowledge-score-pair"><span>Original <strong>{{ scorePreview.result.proposal.base_score.toFixed(1) }}</strong></span><span>Published <strong>{{ selected.published_score?.score.toFixed(1) ?? '—' }}</strong><small v-if="selected.published_score?.current === false"> · Outdated</small></span><span>Proposed <strong>{{ scorePreview.result.proposal.score.toFixed(1) }}</strong></span></div>
              <p v-if="scorePreview.result.eligible" role="status">Preview ready. Required reviews are current.</p>
              <template v-else><p role="status">Waiting for required team reviews or unresolved component ownership.</p><ul><li v-for="(block, index) in scorePreview.result.blocked" :key="index">{{ block.version }} · {{ block.vulnerability_id }}<ul v-if="block.missing?.length"><li v-for="missing in block.missing" :key="missing.context_id">{{ missing.context_id }} · {{ label(missing.status || 'review required') }}</li></ul><span v-if="block.unresolved_components?.length"> · {{ block.unresolved_components.length }} unresolved components</span></li></ul><details><summary>Review gate details</summary><pre>{{ JSON.stringify(scorePreview.result.blocked, null, 2) }}</pre></details></template>
            </section>
            <div class="knowledge-actions"><button :disabled="busy || !scoreBase || !scoreVector || !scoreRationale.trim()">Preview contextual score</button><button type="button" class="primary" :disabled="busy || !scorePreview?.result.eligible" @click="publishScore">Publish contextual score</button></div>
          </form>
          <footer class="knowledge-pagination"><button :disabled="busy || selectedIndex <= 0" @click="open(workspace.items[selectedIndex - 1]!)">Previous finding</button><button :disabled="busy || selectedIndex < 0 || selectedIndex >= workspace.items.length - 1" @click="open(workspace.items[selectedIndex + 1]!)">Next finding</button></footer>
        </section>
      </div><details class="knowledge-state"><summary>State reference</summary><code>{{ workspace.state }}</code></details>
    </template>
  </section>
</template>
<style scoped>
.knowledge-advanced,.knowledge-views { margin:12px 0; font-size:.85rem }.knowledge-filter-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:10px 14px; margin-top:12px }.knowledge-advanced fieldset { border:0; margin:0; padding:0; min-width:0 }.knowledge-views ul { list-style:none; padding:0; display:flex; gap:8px; flex-wrap:wrap }.knowledge-views li { display:flex; gap:4px }.knowledge-views .knowledge-actions { justify-content:flex-start }.knowledge-views label { margin:8px 0 0; min-width:160px }
.knowledge-heading,.knowledge-detail header,.knowledge-pagination,.knowledge-actions,.knowledge-score-pair,.knowledge-statistics { display:flex; align-items:center; gap:12px; flex-wrap:wrap }.knowledge-heading { justify-content:space-between; margin-bottom:16px }.knowledge-heading h1 { margin:0 }.knowledge-heading p { margin:4px 0 }.knowledge-filters { display:grid; grid-template-columns:minmax(160px,1.2fr) minmax(100px,.65fr) minmax(140px,1fr) minmax(140px,1fr) minmax(180px,1.5fr); gap:12px; align-items:end }.knowledge-filters label { margin:0 }.knowledge-statistics { margin:16px 0; font-size:.85rem; border-block:1px solid var(--line); padding:12px 0 }.knowledge-statistics details { margin-left:auto }.knowledge-statistics dl { position:absolute; z-index:2; background:var(--surface); padding:16px; border:1px solid var(--line); box-shadow:var(--shadow); right:24px; min-width:220px }.knowledge-columns { display:grid; gap:20px }.knowledge-columns.has-detail { grid-template-columns:minmax(380px,1fr) minmax(360px,1fr) }.knowledge-queue,.knowledge-detail { min-width:0 }.knowledge-queue small { display:block; color:var(--muted); margin-top:4px }.knowledge-queue .selected { background:var(--accent-soft) }.knowledge-queue th { font-size:.8rem; white-space:nowrap }.knowledge-queue td { font-size:.85rem; vertical-align:top }.knowledge-detail { background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:18px; align-self:start }.knowledge-detail header { justify-content:space-between; align-items:flex-start }.knowledge-detail h2 { margin:0; font-size:1.15rem }.knowledge-detail header p { margin:4px 0 }.knowledge-detail h3 { font-size:1rem }.knowledge-detail > .hint { margin:8px 0 }.knowledge-score-pair { font-size:.8rem; gap:22px; padding:10px 0 }.knowledge-tabs { display:flex; gap:6px; border-bottom:1px solid var(--line); padding-bottom:8px }.knowledge-tabs button { border:0; padding:5px 10px; text-transform:capitalize }.knowledge-tabs button[aria-pressed=true] { background:var(--accent-soft); color:var(--accent) }.knowledge-pane { padding-top:12px }.knowledge-pane fieldset { border:0; padding:0; margin:0; min-width:0 }.knowledge-pane details { margin:12px 0 }.knowledge-pane dl,.knowledge-statistics dl { display:grid; grid-template-columns:auto 1fr; gap:6px 12px; font-size:.8rem }.knowledge-pane dd,.knowledge-statistics dd { margin:0; overflow-wrap:anywhere }.knowledge-pane dt { color:var(--muted) }.knowledge-description { white-space:pre-wrap; overflow-wrap:anywhere; max-height:38vh; overflow:auto; line-height:1.6; font-size:.9rem; margin-top:0 }.knowledge-rationale { white-space:pre-wrap; overflow-wrap:anywhere; line-height:1.6 }.knowledge-pane pre { white-space:pre-wrap; overflow-wrap:anywhere; max-height:300px; overflow:auto; font-size:.75rem; background:var(--bg); padding:10px }.knowledge-pane code { display:block; overflow-wrap:anywhere; font-size:.75rem }.knowledge-confirm { display:flex; align-items:flex-start; gap:8px; font-size:.85rem }.knowledge-confirm input { width:auto; margin-top:3px }.knowledge-actions { justify-content:flex-end; margin-top:12px }.knowledge-pagination { justify-content:space-between; margin-top:12px; font-size:.8rem }.knowledge-state { margin-top:16px; font-size:.75rem; color:var(--muted) }.knowledge-state code { overflow-wrap:anywhere }
@media(max-width:1100px) { .knowledge-filters { grid-template-columns:repeat(2,minmax(0,1fr)) }.knowledge-search { grid-column:1/-1 }.knowledge-columns.has-detail { grid-template-columns:1fr } }@media(max-width:550px) { .knowledge-filters { grid-template-columns:1fr }.knowledge-statistics { gap:8px 16px }.knowledge-detail { padding:12px }.knowledge-queue th,.knowledge-queue td { padding:8px 5px } }
</style>
