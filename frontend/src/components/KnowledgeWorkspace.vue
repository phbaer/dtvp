<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
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
import KnowledgeSources from './KnowledgeSources.vue'
import KnowledgeComponentMetadata from './KnowledgeComponentMetadata.vue'
import KnowledgeComponents from './KnowledgeComponents.vue'
import KnowledgeIntake from './KnowledgeIntake.vue'
import KnowledgeInputQuality from './KnowledgeInputQuality.vue'
import KnowledgeAssembly from './KnowledgeAssembly.vue'
import KnowledgeCoverage from './KnowledgeCoverage.vue'
import KnowledgeDocuments from './KnowledgeDocuments.vue'
import KnowledgePortfolio from './KnowledgePortfolio.vue'
import KnowledgeAdvisories from './KnowledgeAdvisories.vue'
import KnowledgeReconciliation from './KnowledgeReconciliation.vue'
import KnowledgeOwnership from './KnowledgeOwnership.vue'
import KnowledgeBulkReview from './KnowledgeBulkReview.vue'
import KnowledgeCpePolicy from './KnowledgeCpePolicy.vue'
import KnowledgeAssessmentArchive from './KnowledgeAssessmentArchive.vue'
import KnowledgeEvidenceSources from './KnowledgeEvidenceSources.vue'
const props = defineProps<{ me: Me }>()
const intakeBusy = ref(false), assemblyLocked = ref(false), metadataLocked = ref(false), licenseLocked = ref(false), archiveLocked = ref(false), correspondenceLocked = ref(false)
const intakeLocked = computed(() => intakeBusy.value || assemblyLocked.value || metadataLocked.value || licenseLocked.value || archiveLocked.value || correspondenceLocked.value)
const bulkLocked = ref(false), bulkSelection = ref<Record<string, KnowledgeFinding>>({})
const bulkRows = computed(() => Object.values(bulkSelection.value))
function bulkEligible(row: KnowledgeFinding) {
  const record = row.coverage.assessment
  return Boolean(row.capabilities?.includes('approve') && record?.stage === 'submitted' && record.payload.author_id && record.payload.author_id !== props.me.id && !['unassessed', 'draft', 'reassessment_needed', 'historically_absent'].includes(row.coverage.status) && record.revision !== row.coverage.approved_assessment?.revision)
}
function toggleBulk(row: KnowledgeFinding) {
  if (bulkLocked.value || busy.value) return
  if (bulkSelection.value[row.id]) delete bulkSelection.value[row.id]
  else if (bulkEligible(row) && bulkRows.value.length < 100) bulkSelection.value[row.id] = JSON.parse(JSON.stringify(row)) as KnowledgeFinding
}
function bulkChanged(scope: { project: string; version: string }) { bulkSelection.value = {}; if (scope.project === project.value && scope.version === version.value) void load(true, true) }

const project = ref(''), projectName = ref(''), version = ref(''), team = ref(''), lifecycle = ref(''), query = ref('')
const filterLabels: Record<string, string> = { source_severity: 'Source severity', contextual_severity: 'Published severity', applicability: 'Applicability', scoring_status: 'Scoring status', team_review: 'Team assessment', provider: 'Evidence provider', cvss_version: 'Source CVSS version', dependency: 'Dependency relationship', source_conflict: 'Source discrepancies', component: 'Component', criticality: 'Cybersecurity criticality', exposure: 'Exposure', support_status: 'Support status', metadata_status: 'Annotation status' }
const emptyFilters = () => Object.fromEntries(Object.keys(filterLabels).map(key => [key, '']))
const filters = ref(emptyFilters()), filterDraft = ref(emptyFilters())
const activeFilterCount = computed(() => Object.values(filters.value).filter(Boolean).length)
const severityBands = ['critical', 'high', 'medium', 'low', 'none', 'unknown']
const savedViews = ref<{ name: string; query: string }[]>([]), viewName = ref('')
const initialView = new URLSearchParams(location.search)
const explicitAllTeams = ref(initialView.has('k_team') && !initialView.get('k_team'))
function defaultTeam() {
  const teams = props.me.workspaces.filter(item => item.capabilities.some(cap => cap === 'assess' || cap === 'approve'))
  return teams.length === 1 ? teams[0]!.id : ''
}

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
type BoundScorePreview = { input: KnowledgeScoreInput; result: KnowledgeScorePreview; generation: number; signature: string; project: string }
const scorePreview = ref<BoundScorePreview | null>(null)
type ScoreCapture = { generation: number; view: string; scope: string; project: string; version: string; row: KnowledgeFinding; body: KnowledgeScoreInput & { preview: string }; scrollX: number; scrollY: number }
const pendingScore = ref<ScoreCapture | null>(null)
let scoreSequence = 0
const sourceVectors = computed(() => [...new Set(selected.value?.source_ratings.map(item => item.vector).filter((value): value is string => Boolean(value)) || [])])
const workflowTabs = computed(() => can('rescore') ? ['evidence', 'assessment', 'review', 'scoring'] as const : ['evidence', 'assessment', 'review'] as const)
const assessmentScope = ref<{ expected_versions: Record<string, string>; targets: { version: string; context_id: string; vulnerability_id: string }[] } | null>(null)
const assessmentId = ref(''), confirmed = ref(false), reviewRationale = ref('')
type WorkflowKind = 'draft' | 'submit' | 'approve' | 'request_changes'
let actorGeneration = 0
type WorkflowRequest = { scope: string; generation: number; view: string; actor: string; endpoint: string; body: Record<string, unknown>; kind: WorkflowKind; next: boolean; project: string; version: string; row: KnowledgeFinding; following: string[]; scrollX: number; scrollY: number; queueX: number; queueY: number }
const pendingRequest = ref<WorkflowRequest | null>(null)
const queueElement = ref<HTMLElement | null>(null)
const workflowScope = () => JSON.stringify([project.value, version.value, team.value, lifecycle.value, query.value, filters.value, offset.value])
const workflowView = () => JSON.stringify([workflowScope(), selected.value?.id])
const scoreSignature = () => JSON.stringify([workflowView(), workspace.value?.state, selected.value?.state, scoreBase.value, scoreVector.value, scoreRationale.value])
let sequence = 0, timer: ReturnType<typeof setTimeout> | undefined
const scope = computed(() => `/projects/${encodeURIComponent(project.value)}/versions/${encodeURIComponent(version.value)}`)
const assessment = computed(() => selected.value?.coverage.assessment)
const revisesCurrent = computed(() => assessmentId.value === assessment.value?.payload.assessment_id)
const canEditAssessment = computed(() => can('assess') && (!assessment.value || !revisesCurrent.value || assessment.value.payload.author_id === props.me.id))
function startAssessment() {
  if (!can('assess') || busy.value || pendingRequest.value || pendingScore.value) return
  assessmentId.value = crypto.randomUUID(); assessmentScope.value = null
  notice.value = 'New assessment started. Existing decisions and approved history are retained; review the copied evidence before submitting.'
}

const label = (value: string) => value.replaceAll('_', ' ')
const teamName = (id?: string) => (id ? workspace.value?.team_labels?.[id] : undefined) || props.me.workspaces.find(item => item.id === id)?.name || id || 'Unassigned'
const can = (capability: string) => Boolean(selected.value?.capabilities.includes(capability))
const ratingSource = (rating: KnowledgeFinding['source_ratings'][number]) => (typeof rating.source === 'string' ? rating.source : rating.source?.name || rating.source?.url) || rating.observed_source || 'Unattributed source'
const sourceScore = (row: KnowledgeFinding) => row.source_ratings.filter(r => r.score != null).map(r => r.score!.toFixed(1)).join(' / ') || (typeof row.source_severity === 'string' ? label(row.source_severity) : 'Unknown')
const selectedIndex = computed(() => workspace.value?.items.findIndex(item => item.id === selected.value?.id) ?? -1)
function fail(err: unknown) { error.value = err instanceof ApiError && err.status === 409 ? 'The baseline or assessment changed. Refresh before retrying; your text is retained.' : err instanceof Error ? err.message : 'Request failed' }
function close() { if (metadataLocked.value) return; assessmentScope.value = null; selected.value = null; confirmed.value = false; scorePreview.value = null; ++scoreSequence }
async function load(reset = true, keep = false, refreshHead = false) {
  if (metadataLocked.value) return
  const current = ++sequence
  if (!project.value || !version.value) { workspace.value = null; close(); busy.value = false; return }
  busy.value = true; error.value = ''
  if (reset) { offset.value = 0; previous.value = [] }
  if (!keep) close()
  try {
    const params = new URLSearchParams({ offset: String(offset.value), limit: '30', q: query.value, ...(team.value ? { team_id: team.value } : {}), lifecycle: lifecycle.value, ...Object.fromEntries(Object.entries(filters.value).filter(([, value]) => value !== '')) })
    if (!reset && workspace.value?.state && !refreshHead) params.set('expected', workspace.value.state)
    const result = await knowledgeApi<KnowledgeWorkspace>(`${scope.value}/workspace?${params}`)
    if (current === sequence) { workspace.value = result; knownTeamLabels.value = { ...knownTeamLabels.value, ...result.team_labels }; syncViewUrl() }
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function chooseProject(option: { id: string; name?: string }, preferredVersion = '') {
  if (intakeLocked.value) return
  if (teamLabelProject !== option.id) { knownTeamLabels.value = {}; teamLabelProject = option.id; if (!restoring) team.value = explicitAllTeams.value ? '' : defaultTeam() }
  const current = ++sequence; ++versionSequence; projectName.value = option.name || option.id; versions.value = []; version.value = ''; versionQuery.value = ''; versionMenu.value = false; workspace.value = null; close()
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const result = await knowledgeApi<{ items: { version: string; state: string }[]; next_offset: number | null }>(`/projects/${encodeURIComponent(option.id)}/versions?limit=25`)
    if (current !== sequence) return
    versions.value = result.items; versionNext.value = result.next_offset; version.value = preferredVersion || result.items[0]?.version || ''; await load()
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function metadataChanged() {
  const row = selected.value
  await load(true, true)
  if (row && workspace.value) await open(row)
}
async function onCompositionImported(value: { version: string; part_id: string | null; kind?: 'assembly' }) {
  if (value.part_id) { notice.value = 'Source part imported; the assembled product remains unchanged.'; return }
  const generation = actorGeneration, selectedProject = project.value
  await chooseProject({ id: selectedProject, name: projectName.value }, value.version)
  if (generation === actorGeneration && project.value === selectedProject && version.value === value.version && workspace.value && !error.value && value.kind === 'assembly') notice.value = 'Product assembly published. Source observations remain distinct; current coverage is calculated by the backend.'
}
async function seedDemo(scenario: 'workflow' | 'specialists' = 'workflow') {
  if (intakeLocked.value) return
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const result = await knowledgeApi<{ project_id: string; project_name: string; version: string }>('/playground/knowledge/seed', send({ scenario }))
    project.value = result.project_id
    await chooseProject({ id: result.project_id, name: result.project_name })
    if (version.value !== result.version) { version.value = result.version; await load() }
    if (!error.value) notice.value = `Synthetic ${scenario === 'specialists' ? 'specialist' : 'workflow'} demo loaded. Existing interactive work is retained.`
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
function chooseVersion(value: string) { if (intakeLocked.value) return; version.value = value; versionMenu.value = false; void load() }
async function open(row: KnowledgeFinding) {
  if (metadataLocked.value) return
  ++scoreSequence; scorePreview.value = null
  const current = ++sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    const detail = await knowledgeApi<KnowledgeFinding>(`${scope.value}/workspace/${encodeURIComponent(row.context_id)}/${encodeURIComponent(row.vulnerability_id)}?expected=${workspace.value!.state}`)
    if (current !== sequence) return
    assessmentScope.value = null; selected.value = detail; tab.value = 'evidence'; confirmed.value = false; reviewRationale.value = ''; scorePreview.value = null
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
async function mutate(kind: WorkflowKind, next = false, retry = false) {
  if (busy.value || metadataLocked.value || pendingScore.value) return
  if (!retry) {
    if (pendingRequest.value || !selected.value || !workspace.value) return
    if ((kind === 'draft' || kind === 'submit') && !canEditAssessment.value) return
    if (kind === 'submit' && (!rationale.value.trim() || (assessmentScope.value && !conditions.value.trim()) || (applicability.value === 'not_affected' && !justification.value))) return
    if ((kind === 'approve' || kind === 'request_changes') && (!can('approve') || !assessment.value || !confirmed.value || !reviewRationale.value.trim())) return
    const row = selected.value
    const base = { expected_versions: { [version.value]: workspace.value.state }, targets: [{ version: version.value, context_id: row.context_id, vulnerability_id: row.vulnerability_id }] }
    const path = `/projects/${encodeURIComponent(project.value)}`
    const endpoint = kind === 'draft' || kind === 'submit' ? `${path}/assessments/${encodeURIComponent(assessmentId.value)}/${kind}` : `${path}/reviews`
    const body = kind === 'draft' || kind === 'submit'
      ? { ...(assessmentScope.value || base), expected_revision: revisesCurrent.value ? assessment.value?.revision || null : null, state: applicability.value, justification: applicability.value === 'not_affected' ? justification.value || null : null, rationale: rationale.value, conditions: conditions.value, evidence: assessment.value?.payload.evidence || [] }
      : { ...base, assessment_id: assessment.value!.payload.assessment_id, assessment_revision: assessment.value!.revision, action: kind, rationale: reviewRationale.value }
    pendingRequest.value = { scope: workflowScope(), generation: actorGeneration, view: workflowView(), actor: props.me.id, endpoint, body: JSON.parse(JSON.stringify({ ...body, request_id: crypto.randomUUID() })), kind, next, project: project.value, version: version.value, row: JSON.parse(JSON.stringify(row)), following: workspace.value.items.slice(selectedIndex.value + 1).map(item => item.id), scrollX: window.scrollX, scrollY: window.scrollY, queueX: queueElement.value?.scrollLeft || 0, queueY: queueElement.value?.scrollTop || 0 }
  }
  const request = pendingRequest.value
  if (!request) return
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const receipt = await knowledgeApi<{ committed?: boolean; projection?: string }>(request.endpoint, send(request.body))
    if (actorGeneration !== request.generation) return
    if (receipt.committed !== true || receipt.projection !== 'current') {
      notice.value = receipt.committed === true ? 'Committed; projection is pending. Keep this finding open and retry the exact request to refresh the projection.' : 'Publication is uncertain. The exact request is retained; no next finding was opened.'
      return
    }
    pendingRequest.value = null
    const message = request.kind === 'draft' ? 'Draft saved.' : request.kind === 'submit' ? 'Assessment submitted for independent review.' : request.kind === 'approve' ? 'Assessment approved.' : 'Changes requested.'
    if (workflowView() !== request.view) { notice.value = `${message} Recorded for ${request.project} / ${request.version}; current queue retained.`; return }
    await load(false, true, true); if (actorGeneration !== request.generation || workflowView() !== request.view || error.value) return
    const nextRow = request.next ? request.following.map(id => workspace.value!.items.find(item => item.id === id)).find((item): item is KnowledgeFinding => Boolean(item)) : undefined
    const sameRow = workspace.value!.items.find(item => item.id === request.row.id)
    if (nextRow || sameRow) await open((nextRow || sameRow)!)
    else close()
    if (actorGeneration !== request.generation || workflowScope() !== request.scope) return
    if (!error.value) { notice.value = `${message}${request.next && !nextRow ? ' No next finding remains on this page; queue position retained.' : ''}`; tab.value = nextRow ? 'evidence' : request.kind === 'draft' ? 'assessment' : 'review' }
    await nextTick(); if (actorGeneration !== request.generation || workflowScope() !== request.scope) return; window.scrollTo(request.scrollX, request.scrollY); queueElement.value?.scrollTo(request.queueX, request.queueY)
  } catch (err) { if (actorGeneration === request.generation) fail(err) }
  finally { if (actorGeneration === request.generation) busy.value = false }
}
function discardWorkflowRequest() {
  if (busy.value) return
  pendingRequest.value = null; error.value = ''; notice.value = 'Captured request discarded locally. Check current state before preparing another action; an earlier uncertain request may already have committed.'
}

function useProposal(proposal: KnowledgeProposal) {
  if (busy.value || metadataLocked.value || pendingRequest.value || pendingScore.value || !can('rescore') || !proposal.eligible || !proposal.score_input) return
  scoreBase.value = proposal.score_input.base_vector; scoreVector.value = proposal.score_input.vector
  scoreRationale.value = ''; tab.value = 'scoring'
  notice.value = 'Proposal loaded. Add your rationale and preview required reviews before publication.'
}
async function previewScore() {
  if (busy.value || metadataLocked.value || pendingRequest.value || pendingScore.value || !selected.value || !workspace.value || !can('rescore') || !scoreBase.value || !scoreVector.value || !scoreRationale.value.trim()) return
  const current = ++scoreSequence, generation = actorGeneration, signature = scoreSignature(), product = project.value
  busy.value = true; error.value = ''; notice.value = ''; scorePreview.value = null
  try {
    const input: KnowledgeScoreInput = { request_id: crypto.randomUUID(), expected_versions: { [version.value]: selected.value.state || workspace.value.state }, targets: [{ version: version.value, context_id: selected.value.context_id, vulnerability_id: selected.value.vulnerability_id }], base_vector: scoreBase.value, vector: scoreVector.value, rationale: scoreRationale.value }
    const result = await knowledgeApi<KnowledgeScorePreview>(`/projects/${encodeURIComponent(product)}/scoring/preview`, send(input))
    if (generation !== actorGeneration || current !== scoreSequence || signature !== scoreSignature()) return
    scorePreview.value = { input, result, generation, signature, project: product }
  } catch (err) { if (generation === actorGeneration && current === scoreSequence) fail(err) }
  finally { if (generation === actorGeneration && current === scoreSequence) busy.value = false }
}
async function publishScore(retry = false) {
  if (busy.value || metadataLocked.value || pendingRequest.value) return
  if (!retry) {
    const preview = scorePreview.value
    if (pendingScore.value || !preview?.result.eligible || !selected.value || !can('rescore') || preview.generation !== actorGeneration || preview.signature !== scoreSignature()) return
    pendingScore.value = { generation: actorGeneration, view: workflowView(), scope: workflowScope(), project: preview.project, version: version.value, row: JSON.parse(JSON.stringify(selected.value)), body: JSON.parse(JSON.stringify({ ...preview.input, preview: preview.result.preview })), scrollX: window.scrollX, scrollY: window.scrollY }
  }
  const capture = pendingScore.value
  if (!capture) return
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const result = await knowledgeApi<{ committed?: boolean; projection?: string }>(`/projects/${encodeURIComponent(capture.project)}/scoring/publish`, send(capture.body))
    if (capture.generation !== actorGeneration) return
    if (result.committed !== true || result.projection !== 'current') {
      notice.value = result.committed === true ? 'Score committed; projection is pending. Retry the exact captured publication to refresh it.' : 'Score publication is uncertain. Exact preview, source Base, rationale and request ID are retained.'
      return
    }
    pendingScore.value = null; scorePreview.value = null
    if (workflowView() !== capture.view) { notice.value = `Contextual score published for ${capture.project} / ${capture.version}; current queue retained.`; return }
    await load(false, true, true)
    if (capture.generation !== actorGeneration || workflowView() !== capture.view || error.value) return
    const row = workspace.value!.items.find(item => item.id === capture.row.id)
    if (row) await open(row)
    else close()
    if (capture.generation !== actorGeneration || workflowScope() !== capture.scope || error.value) return
    tab.value = can('rescore') ? 'scoring' : 'evidence'; notice.value = 'Contextual score published.'
    await nextTick()
    if (capture.generation === actorGeneration && workflowScope() === capture.scope) window.scrollTo(capture.scrollX, capture.scrollY)
  } catch (err) { if (capture.generation === actorGeneration) fail(err) }
  finally { if (capture.generation === actorGeneration) busy.value = false }
}
function discardScorePublication() {
  if (busy.value) return
  pendingScore.value = null; scorePreview.value = null; error.value = ''; notice.value = 'Captured score publication discarded locally. Check current state before another preview; this does not undo an earlier uncertain commit.'
}

watch(tab, () => { assessmentScope.value = null })
watch([scoreBase, scoreVector, scoreRationale], () => { ++scoreSequence; scorePreview.value = null }, { flush: 'sync' })
function viewParams() {
  const params = new URLSearchParams()
  const values = { project: project.value, version: version.value, team: team.value, lifecycle: lifecycle.value, q: query.value, ...filters.value }
  for (const [key, value] of Object.entries(values)) if (value || key === 'team') params.set(`k_${key}`, value)
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
  if (intakeLocked.value) return
  if (busy.value) return
  const params = new URLSearchParams(value), id = params.get('k_project') || ''
  restoring = true; busy.value = true; error.value = ''
  try {
    explicitAllTeams.value = params.has('k_team') && !params.get('k_team')
    team.value = params.has('k_team') ? params.get('k_team') || '' : defaultTeam(); lifecycle.value = params.get('k_lifecycle') || ''; query.value = params.get('k_q') || ''
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
watch(() => [project.value, version.value, workspace.value?.state, team.value, lifecycle.value, query.value, JSON.stringify(filters.value), props.me.id], () => { bulkSelection.value = {} })
watch([team, lifecycle], () => { if (!restoring && !busy.value) void load() })
watch(() => props.me.id, () => { ++actorGeneration; ++scoreSequence; pendingRequest.value = null; pendingScore.value = null; scorePreview.value = null; knownTeamLabels.value = {}; explicitAllTeams.value = false; team.value = defaultTeam(); workspace.value = null; close(); void load() }, { flush: 'sync' })
watch(query, () => { if (restoring) return; clearTimeout(timer); timer = setTimeout(() => { void load() }, 250) })
onMounted(() => {
  try { const stored: unknown = JSON.parse(localStorage.getItem(`dtvp.knowledge.views:${props.me.id}`) || '[]'); if (Array.isArray(stored)) savedViews.value = stored.filter(item => item && typeof item.name === 'string' && typeof item.query === 'string').slice(-20) } catch { /* Browser storage is optional. */ }
  if (initialView.has('k_project')) void restoreView(initialView.toString())
})
onBeforeUnmount(() => { ++actorGeneration; ++sequence; ++versionSequence; clearTimeout(timer); clearTimeout(versionTimer) })
</script>
<template>
  <section class="knowledge-workspace" aria-label="Knowledge workspace">
    <header class="knowledge-heading"><div><h1>Contextual review</h1><p class="hint">Product version · consuming context · responsible team</p></div><div class="knowledge-actions"><button v-if="me.playground" :disabled="busy || intakeLocked" @click="seedDemo()">Load workflow demo</button><button v-if="me.playground" :disabled="busy || intakeLocked" @click="seedDemo('specialists')">Load specialist demo</button><button :disabled="busy || !version" @click="load()">Refresh workspace</button></div></header>
    <form class="knowledge-filters" @submit.prevent="load()">
      <SearchSelect v-model="project" label="Knowledge product" :selected-label="projectName" endpoint="/catalog/projects" :disabled="busy || intakeLocked" @select="chooseProject" />
      <div class="search-select" @keydown.esc="versionMenu = false"><span class="field-label" id="knowledge-version-label">Version</span><button type="button" :disabled="busy || intakeLocked || !project" aria-labelledby="knowledge-version-label knowledge-version-value" :aria-expanded="versionMenu" aria-haspopup="listbox" @click="versionMenu = !versionMenu"><span id="knowledge-version-value">{{ version || 'Select…' }}</span><span aria-hidden="true">⌄</span></button><div v-if="versionMenu" class="select-menu"><input v-model="versionQuery" type="search" aria-label="Search versions" placeholder="Search versions" @input="searchVersions"><div role="listbox" aria-label="Version"><button v-for="item in versions" :key="item.version" type="button" role="option" :aria-selected="version === item.version" @click="chooseVersion(item.version)">{{ item.version }}</button></div><p v-if="versionBusy" role="status">Searching…</p><p v-else-if="!versions.length">No matching versions.</p><button v-if="versionNext != null" type="button" :disabled="versionBusy" @click="loadVersions(true)">More versions</button></div></div>
      <label>Responsible team<select v-model="team" :disabled="busy" @change="explicitAllTeams = !team"><option value="">All accessible teams</option><option v-for="item in teamOptions" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
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
        <label>Cybersecurity criticality<select v-model="filterDraft.criticality"><option value="">Any criticality</option><option v-for="value in ['unknown', 'low', 'moderate', 'high', 'critical']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Exposure<select v-model="filterDraft.exposure"><option value="">Any exposure</option><option v-for="value in ['unknown', 'not_exposed', 'internal', 'external']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Support status<select v-model="filterDraft.support_status"><option value="">Any support status</option><option v-for="value in ['unknown', 'supported', 'unsupported', 'internally_maintained']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Annotation status<select v-model="filterDraft.metadata_status"><option value="">Any annotation status</option><option v-for="value in ['missing', 'current', 'stale', 'out_of_scope', 'absent', 'unknown']" :key="value" :value="value">{{ label(value) }}</option></select></label>
      </div><div class="knowledge-actions"><button type="button" @click="resetFilters">Reset advanced filters</button><button class="primary">Apply filters</button></div></fieldset></form>
      <p class="hint">Filters and counts use the full server result. Unknown evidence stays unknown; outdated scores are excluded from published severity. Criticality, exposure and support use current authored annotations; missing or stale values stay unknown.</p>
    </details>
    <details class="knowledge-views"><summary>Saved views and sharing</summary><div class="knowledge-actions"><label>View name<input v-model="viewName" maxlength="100" placeholder="Save the applied scope"></label><button :disabled="busy || !project || !viewName.trim()" @click="saveView">Save view</button><button :disabled="busy || !project" @click="copyView">Copy view link</button></div><ul v-if="savedViews.length"><li v-for="view in savedViews" :key="view.name"><button :disabled="busy || intakeLocked" @click="restoreView(view.query)">{{ view.name }}</button><button :disabled="busy" :aria-label="`Remove view ${view.name}`" @click="removeView(view.name)">×</button></li></ul></details>
    <div class="knowledge-tools" role="group" aria-label="Product tools">
      <KnowledgeAssembly :key="`${me.id}:${project}`" :project="project" :version="version" :disabled="intakeBusy" @locked="assemblyLocked = $event" @assembled="onCompositionImported" />
      <KnowledgeIntake :key="`${me.id}:${project}`" :project="project" :version="version" :disabled="assemblyLocked" @locked="intakeBusy = $event" @imported="onCompositionImported" />
      <KnowledgeOwnership v-if="project" :key="`${me.id}:${project}`" :project="project" @changed="load(true, true)" />
      <KnowledgeAssessmentArchive v-if="project" :key="`${me.id}:${project}`" :project="project" :disabled="busy || intakeBusy || assemblyLocked || metadataLocked || licenseLocked" @locked="archiveLocked = $event" @changed="load(true, true)" />
      <KnowledgeCpePolicy v-if="project" :key="`${me.id}:${project}`" :project="project" />
      <KnowledgeEvidenceSources v-if="project" :key="`${me.id}:${project}`" :project="project" :state="workspace?.state || ''" @changed="load(true, true)" />
      <KnowledgeComparison :project="project" />
    </div>
    <section v-if="pendingScore" class="knowledge-pane" aria-label="Pending coordinator score publication"><p role="status">Captured contextual score for {{ pendingScore.project }} / {{ pendingScore.version }} / {{ pendingScore.row.vulnerability_id }}. Preview, expected source head, source Base, vector, rationale and request ID remain fixed.</p><button :disabled="busy || metadataLocked" @click="publishScore(true)">Retry exact score publication</button><button :disabled="busy" @click="discardScorePublication">Discard captured score publication</button><details><summary>Captured score input and preview</summary><pre>{{ JSON.stringify(pendingScore.body, null, 2) }}</pre></details></section>
    <section v-if="pendingRequest" class="knowledge-pane" aria-label="Pending assessment workflow request"><p role="status">Captured {{ label(pendingRequest.kind) }} for {{ pendingRequest.project }} / {{ pendingRequest.version }} / {{ pendingRequest.row.vulnerability_id }}. Exact source heads, evidence, target and request ID are retained.</p><button :disabled="busy || metadataLocked" @click="mutate(pendingRequest.kind, pendingRequest.next, true)">Retry exact assessment workflow request</button><button :disabled="busy" @click="discardWorkflowRequest">Discard captured workflow request</button><details><summary>Captured workflow input</summary><pre>{{ JSON.stringify(pendingRequest.body, null, 2) }}</pre></details></section>
    <KnowledgeBulkReview :key="me.id" :project="project" :version="version" :state="workspace?.state || ''" :rows="bulkRows" @locked="bulkLocked = $event" @reset="bulkSelection = {}" @changed="bulkChanged" />
    <p v-if="error" role="alert" class="message">{{ error }}</p><p v-if="notice" role="status" class="message">{{ notice }}</p><p v-if="busy" role="status">Loading…</p>
    <p v-if="project && !busy && !version && !versions.length" class="empty">No journal-backed versions. Import a baseline to start.</p><p v-else-if="!project" class="empty">Select a product to review its versioned knowledge.</p>
    <template v-if="workspace">
      <p v-if="workspace.baseline_status === 'withdrawn'" role="status" class="message">The current inventory was withdrawn. Historical assessments and release tags remain retained.</p>
      <div class="knowledge-statistics" aria-label="Filtered workspace statistics"><span><strong>{{ workspace.statistics.totals.context_findings }}</strong> context findings</span><span><strong>{{ workspace.statistics.totals.unique_vulnerabilities }}</strong> vulnerabilities</span><span><strong>{{ workspace.statistics.recorded }}</strong> recorded</span><span><strong>{{ workspace.statistics.submitted }}</strong> submitted</span><span><strong>{{ workspace.statistics.approved }}</strong> approved</span><details><summary>Breakdown</summary><dl><template v-for="(count, status) in workspace.statistics.by_status" :key="status"><dt>{{ label(String(status)) }}</dt><dd>{{ count }}</dd></template><template v-for="(count, id) in workspace.statistics.by_team" :key="id"><dt>{{ teamName(String(id)) }}</dt><dd>{{ typeof count === 'number' ? count : count.context_findings }} findings</dd></template><template v-for="(count, severity) in workspace.statistics.severity" :key="severity"><dt>{{ severity }}</dt><dd>{{ count }}</dd></template></dl></details></div>
      <div class="knowledge-tools" role="group" aria-label="Pinned state tools">
        <KnowledgeComponents :key="`${me.id}:${project}`" :project="project" :state="workspace.state" :disabled="busy || bulkLocked || !!pendingRequest || !!pendingScore" @locked="metadataLocked = $event" @changed="metadataChanged" />
        <KnowledgeRetained v-if="workspace.statistics.retained_absent_assessments" :project="project" :state="workspace.state" :team="team" />
        <KnowledgeLicenses :key="me.id" :project="project" :version="version" :state="workspace.state" @locked="licenseLocked = $event" @changed="load(true, true)" />
        <KnowledgePortfolio :project="project" :version="version" :state="workspace.state" :filters="filters" :q="query" :lifecycle="lifecycle" :team="team" />
        <KnowledgeDocuments :project="project" :version="version" :state="workspace.state" @changed="load(true, true)" />
        <div class="knowledge-composition-tools"><KnowledgeSources :project="project" :version="version" :state="workspace.state" /><KnowledgeInputQuality :key="`${me.id}:${project}`" :project="project" :state="workspace.state" /></div>
        <KnowledgeAdvisories :project="project" :state="workspace.state" />
        <KnowledgeReconciliation :key="`${me.id}:${project}`" :project="project" :version="version" :state="workspace.state" @locked="correspondenceLocked = $event" @changed="load(true, true)" />
      </div>
      <div class="knowledge-columns" :class="{ 'has-detail': selected }">
        <section class="knowledge-queue" aria-label="Context finding queue"><div ref="queueElement" class="table-wrap"><table><thead><tr><th v-if="workspace.items.some(row => row.capabilities?.includes('approve')) || bulkRows.length || bulkLocked">Review</th><th>Vulnerability / component</th><th>Team / status</th><th>Source</th><th>Published</th></tr></thead><tbody><tr v-for="row in workspace.items" :key="row.id" :class="{ selected: selected?.id === row.id }"><td v-if="workspace.items.some(item => item.capabilities?.includes('approve')) || bulkRows.length || bulkLocked"><input type="checkbox" :aria-label="`Select ${row.vulnerability_id} in ${row.context.root_ref} for bulk review`" :checked="!!bulkSelection[row.id]" :disabled="busy || bulkLocked || !bulkEligible(row) || (!bulkSelection[row.id] && bulkRows.length >= 100)" @change="toggleBulk(row)"></td><td><button class="text-link" :disabled="busy" @click="open(row)">{{ row.vulnerability_id }}</button><small>{{ row.component.name }} {{ row.component.version }}</small></td><td>{{ teamName(row.context.team_id) }}<small>{{ label(row.coverage.status) }}</small></td><td>{{ sourceScore(row) }}</td><td>{{ row.published_score?.score.toFixed(1) ?? '—' }}<small v-if="row.published_score?.current === false">Outdated</small></td></tr></tbody></table><p v-if="!workspace.items.length && !busy" class="empty">No context findings match this scope.</p></div><div class="knowledge-pagination"><button :disabled="busy || !previous.length" @click="paginate(false)">Previous page</button><span>{{ offset + (workspace.items.length ? 1 : 0) }}–{{ offset + workspace.items.length }}</span><button :disabled="busy || workspace.next_offset == null" @click="paginate(true)">Next page</button></div></section>
        <section v-if="selected" class="knowledge-detail" aria-label="Context finding detail">
          <header><div><h2>{{ selected.vulnerability_id }}</h2><p>{{ selected.component.name }} {{ selected.component.version }}</p></div><button aria-label="Close context finding" :disabled="busy" @click="close()">×</button></header><p class="hint">{{ teamName(selected.context.team_id) }} · {{ label(selected.coverage.status) }}</p>
          <div class="knowledge-score-pair"><span>Source <strong>{{ sourceScore(selected) }}</strong></span><span>Published <strong>{{ selected.published_score?.score.toFixed(1) ?? 'Not published' }}</strong><small v-if="selected.published_score?.current === false"> · Outdated</small></span></div>
          <KnowledgeAnalysisEvidence v-if="selected.code_analysis?.length" :items="selected.code_analysis" />
          <KnowledgeSpecialists :project="project" :state="workspace.state" :version="version" :finding="selected" />
          <details v-if="selected.scoring_proposals?.length" class="knowledge-pane"><summary>External scoring proposals ({{ selected.scoring_proposals.length }})</summary><div class="table-wrap"><table aria-label="External scoring comparison"><thead><tr><th>Provider</th><th>Source Base</th><th>Proposed</th><th>Status</th><th v-if="can('rescore')">Action</th></tr></thead><tbody><tr v-for="proposal in selected.scoring_proposals" :key="proposal.id"><td>{{ proposal.source_label }}<small>{{ proposal.provider }}</small></td><td>{{ proposal.proposal?.base_score.toFixed(1) ?? 'Unknown' }}</td><td>{{ proposal.proposal?.score.toFixed(1) ?? 'Withheld' }}</td><td>{{ proposal.eligible ? 'Ready for coordinator preview' : proposal.ineligibility_reasons.map(label).join(' · ') }}<small>{{ proposal.current ? 'Current evidence' : 'Historical evidence' }}</small></td><td v-if="can('rescore')"><button :disabled="busy || !!pendingScore || !!pendingRequest || !proposal.eligible" @click="useProposal(proposal)">Use proposal</button></td></tr></tbody></table></div><p class="hint">External proposals do not approve assessments or publish scores. Artifact consistency does not verify provider identity.</p><details><summary>Proposal vectors and provenance</summary><pre>{{ JSON.stringify(selected.scoring_proposals, null, 2) }}</pre></details></details>
          <details v-if="selected.curated_metadata" class="knowledge-pane"><summary>Curated component context · {{ label(selected.curated_metadata.status) }}</summary><p v-if="!selected.curated_metadata.applicable" class="warning">Historical annotations require reconciliation with this component/version before use.</p><dl><dt>Criticality / exposure</dt><dd>{{ label(selected.curated_metadata.payload.annotations.cybersecurity.criticality) }} · {{ label(selected.curated_metadata.payload.annotations.cybersecurity.exposure) }}</dd><dt>Deployment</dt><dd>{{ selected.curated_metadata.payload.annotations.deployment.environment || 'Unknown' }}</dd><dt>Usage</dt><dd>{{ selected.curated_metadata.payload.annotations.deployment.usage || 'Unknown' }}</dd><dt>Support</dt><dd>{{ label(selected.curated_metadata.payload.annotations.support.status) }}</dd><dt>Source</dt><dd>{{ selected.curated_metadata.payload.provenance.source }} · {{ selected.curated_metadata.payload.provenance.reference }}</dd></dl><p>{{ selected.curated_metadata.payload.rationale }}</p><details><summary>Mitigations, testing and supporting details</summary><pre>{{ JSON.stringify(selected.curated_metadata.payload.annotations, null, 2) }}</pre></details></details>
          <KnowledgeComponentMetadata :key="`${me.id}:${project}:${version}:${selected.context.component_ref}`" :project="project" :state="workspace.state" :version="version" :component-ref="String(selected.context.component_ref || '')" :context-id="selected.context_id" :disabled="busy || bulkLocked || !!pendingRequest || !!pendingScore" @locked="metadataLocked = $event" @changed="metadataChanged" @refresh="metadataChanged" />
          <details v-if="selected.legacy_evidence?.length" class="knowledge-pane"><summary>Imported DT assessment history</summary><p class="hint">Historical team and author labels are source claims. These records do not establish current DTVP approval.</p><article v-for="claim in selected.legacy_evidence" :key="claim.id"><h3>{{ claim.source }} · {{ label(claim.status) }}</h3><p v-if="claim.conflicting" class="warning">Conflicting imported team conclusions require reconciliation.</p><div v-for="(record, index) in claim.current_records" :key="index"><strong>{{ record.team }} · {{ label(record.state || 'unknown') }}</strong><p>{{ record.rationale }}</p><p v-if="record.justification">{{ justificationLabel(record.justification) }}</p><small>Historical assessor: {{ record.assessor || 'Unknown' }} · reviewer: {{ record.reviewer || 'Unknown' }}</small></div><p v-if="!claim.current_records.length">{{ claim.raw_text || claim.raw_excerpt || 'No interpretable assessment text.' }}</p><ul v-if="claim.errors.length"><li v-for="issue in claim.errors" :key="issue">{{ issue }}</li></ul><details><summary>Complete imported history, comments and score claims</summary><pre>{{ JSON.stringify(claim, null, 2) }}</pre></details></article></details>
          <nav class="knowledge-tabs" aria-label="Assessment workflow"><button v-for="step in workflowTabs" :key="step" :aria-pressed="tab === step" @click="tab = step">{{ label(step) }}</button></nav>
          <div v-if="tab === 'evidence'" class="knowledge-pane"><p class="knowledge-description">{{ selected.description || 'No source description provided.' }}</p><dl><dt>Consuming root</dt><dd>{{ selected.context.root_ref || 'Unknown' }}</dd><dt>Ownership</dt><dd>{{ label(selected.context.status || 'unknown') }}</dd><dt>Package</dt><dd>{{ selected.component.purl || 'Unknown' }}</dd></dl><details><summary>Source ratings and vectors</summary><ul><li v-for="(rating, index) in selected.source_ratings" :key="index">{{ ratingSource(rating) }} · {{ rating.method || 'Unspecified method' }} · {{ rating.score ?? 'Unknown score' }}<code>{{ rating.vector }}</code></li></ul></details><details><summary>Dependency and ownership evidence</summary><pre>{{ JSON.stringify(selected.context, null, 2) }}</pre></details><details><summary>Imported source claims</summary><pre>{{ JSON.stringify(selected.sourcefacts || [], null, 2) }}</pre></details><details><summary>Additional evidence</summary><pre>{{ JSON.stringify(selected.evidence || [], null, 2) }}</pre></details><button v-if="can('assess')" class="primary" @click="tab = 'assessment'">Assess this context</button></div>
          <form v-if="tab === 'assessment'" class="knowledge-pane" @submit.prevent="mutate('submit')"><p v-if="selected.coverage.approved_assessment" class="hint">An approved assessment is retained. A new draft does not replace its approved pin.</p><p v-if="assessment && revisesCurrent && !canEditAssessment && can('assess')" class="hint">This assessment belongs to another author. Start a separate assessment to record your decision.</p><button v-if="assessment && can('assess')" type="button" :disabled="busy || !!pendingRequest || !!pendingScore || !revisesCurrent" @click="startAssessment">Start new assessment</button><KnowledgeCoverage :project="project" :state="workspace!.state" :version="version" :finding="selected" :busy="busy || !!pendingRequest || !!pendingScore" @scope="assessmentScope = $event"/><fieldset :disabled="busy || !!pendingRequest || !!pendingScore || !canEditAssessment"><label>Applicability<select v-model="applicability"><option v-for="state in ['under_investigation', 'affected', 'not_affected', 'fixed']" :key="state" :value="state">{{ label(state) }}</option></select></label><label v-if="applicability === 'not_affected'">Why not affected?<select v-model="justification" required><option value="" disabled>Select a reason</option><option v-for="(text, code) in justifications" :key="code" :value="code">{{ text }}</option></select></label><label>Reason and evidence<textarea v-model="rationale" rows="5" required placeholder="Explain this decision for the selected consuming context."></textarea></label><details :open="Boolean(assessmentScope)"><summary>Applicability conditions</summary><label>Conditions<textarea v-model="conditions" rows="3" :required="Boolean(assessmentScope)"></textarea></label></details></fieldset><p v-if="!can('assess')" class="hint">Assessment editing is unavailable for this context.</p><div v-else class="knowledge-actions"><button type="button" :disabled="busy || !!pendingRequest || !!pendingScore || !canEditAssessment" @click="mutate('draft')">Save draft</button><button class="primary" :disabled="busy || !!pendingRequest || !!pendingScore || !canEditAssessment || !rationale.trim() || (assessmentScope && !conditions.trim()) || (applicability === 'not_affected' && !justification)">Submit assessment</button><button type="button" :disabled="busy || !!pendingRequest || !!pendingScore || !canEditAssessment || !rationale.trim() || (assessmentScope && !conditions.trim()) || (applicability === 'not_affected' && !justification)" @click="mutate('submit', true)">Submit and next</button></div></form>
          <div v-if="tab === 'review'" class="knowledge-pane"><template v-if="assessment"><h3>{{ label(assessment.payload.state) }}</h3><p v-if="assessment.payload.justification">{{ justificationLabel(assessment.payload.justification) }}</p><p class="knowledge-rationale">{{ assessment.payload.rationale }}</p><p v-if="assessment.payload.conditions" class="knowledge-rationale">Conditions: {{ assessment.payload.conditions }}</p><small>{{ label(assessment.stage) }} · Author {{ assessment.payload.author_id || 'Unknown' }}</small><details><summary>Assessment scope and evidence</summary><pre>{{ JSON.stringify({ targets: assessment.payload.targets, evidence: assessment.payload.evidence }, null, 2) }}</pre></details><template v-if="can('approve')"><label>Review rationale<textarea v-model="reviewRationale" :disabled="busy || !!pendingRequest || !!pendingScore" rows="3" placeholder="Explain approval or requested changes."></textarea></label><label class="knowledge-confirm"><input v-model="confirmed" type="checkbox" :disabled="busy || !!pendingRequest || !!pendingScore">I checked the evidence, applicability and context of this assessment.</label><div class="knowledge-actions"><button :disabled="busy || !!pendingRequest || !!pendingScore || !confirmed || !reviewRationale.trim()" @click="mutate('request_changes')">Request changes</button><button class="primary" :disabled="busy || !!pendingRequest || !!pendingScore || !confirmed || !reviewRationale.trim()" @click="mutate('approve')">Approve assessment</button><button :disabled="busy || !!pendingRequest || !!pendingScore || !confirmed || !reviewRationale.trim()" @click="mutate('approve', true)">Approve and next</button><button :disabled="busy || !!pendingRequest || !!pendingScore || !confirmed || !reviewRationale.trim()" @click="mutate('request_changes', true)">Request changes and next</button></div></template><p v-else class="hint">Independent review actions are unavailable for this assessment.</p></template><p v-else>No assessment recorded for this context.</p><details v-if="selected.coverage.approved_assessment"><summary>Retained approved assessment</summary><p>{{ selected.coverage.approved_assessment.payload.rationale }}</p></details></div>
          <form v-if="tab === 'scoring' && can('rescore')" class="knowledge-pane" aria-label="Coordinator rescoring" @submit.prevent="previewScore">
            <p class="hint">Publication requires current independent reviews for every required context of this vulnerability.</p>
            <fieldset :disabled="busy || !!pendingScore || !!pendingRequest">
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
            <div class="knowledge-actions"><button :disabled="busy || !!pendingScore || !!pendingRequest || !scoreBase || !scoreVector || !scoreRationale.trim()">Preview contextual score</button><button type="button" class="primary" :disabled="busy || !!pendingScore || !!pendingRequest || !scorePreview?.result.eligible" @click="publishScore()">Publish contextual score</button></div>
          </form>
          <footer class="knowledge-pagination"><button :disabled="busy || selectedIndex <= 0" @click="open(workspace.items[selectedIndex - 1]!)">Previous finding</button><button :disabled="busy || selectedIndex < 0 || selectedIndex >= workspace.items.length - 1" @click="open(workspace.items[selectedIndex + 1]!)">Next finding</button></footer>
        </section>
      </div><details class="knowledge-state"><summary>State reference</summary><code>{{ workspace.state }}</code></details>
    </template>
  </section>
</template>
<style scoped>
/* Existing panels stay mounted; only their direct disclosure roots join the toolbar. */
.knowledge-tools { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,210px),1fr)); align-items:start; gap:8px; margin:12px 0; min-width:0 }
.knowledge-tools:empty { display:none }
.knowledge-composition-tools { display:grid; gap:8px; min-width:0 }
.knowledge-composition-tools:has(> details[open]) { grid-column:1 / -1 }
.knowledge-composition-tools > :deep(details) { margin:0; min-width:0; background:var(--surface) }
.knowledge-workspace .knowledge-tools > :deep(details) { margin:0; min-width:0; padding:10px 12px; border:1px solid var(--line); border-radius:8px; background:var(--surface) }
.knowledge-workspace .knowledge-tools > :deep(details[open]) { grid-column:1 / -1 }
.knowledge-workspace .knowledge-tools > :deep(details > summary) { font-size:.82rem; line-height:1.4; overflow-wrap:anywhere; cursor:pointer }
@media(max-width:550px) { .knowledge-tools { grid-template-columns:minmax(0,1fr) } }

.knowledge-advanced,.knowledge-views { margin:12px 0; font-size:.85rem }.knowledge-filter-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:10px 14px; margin-top:12px }.knowledge-advanced fieldset { border:0; margin:0; padding:0; min-width:0 }.knowledge-views ul { list-style:none; padding:0; display:flex; gap:8px; flex-wrap:wrap }.knowledge-views li { display:flex; gap:4px }.knowledge-views .knowledge-actions { justify-content:flex-start }.knowledge-views label { margin:8px 0 0; min-width:160px }
.knowledge-heading,.knowledge-detail header,.knowledge-pagination,.knowledge-actions,.knowledge-score-pair,.knowledge-statistics { display:flex; align-items:center; gap:12px; flex-wrap:wrap }.knowledge-heading { justify-content:space-between; margin-bottom:16px }.knowledge-heading h1 { margin:0 }.knowledge-heading p { margin:4px 0 }.knowledge-filters { display:grid; grid-template-columns:minmax(160px,1.2fr) minmax(100px,.65fr) minmax(140px,1fr) minmax(140px,1fr) minmax(180px,1.5fr); gap:12px; align-items:end }.knowledge-filters label { margin:0 }.knowledge-statistics { margin:16px 0; font-size:.85rem; border-block:1px solid var(--line); padding:12px 0 }.knowledge-statistics details { margin-left:auto }.knowledge-statistics dl { position:absolute; z-index:2; background:var(--surface); padding:16px; border:1px solid var(--line); box-shadow:var(--shadow); right:24px; min-width:220px }.knowledge-columns { display:grid; gap:20px }.knowledge-columns.has-detail { grid-template-columns:minmax(380px,1fr) minmax(360px,1fr) }.knowledge-queue,.knowledge-detail { min-width:0 }.knowledge-queue small { display:block; color:var(--muted); margin-top:4px }.knowledge-queue .selected { background:var(--accent-soft) }.knowledge-queue th { font-size:.8rem; white-space:nowrap }.knowledge-queue td { font-size:.85rem; vertical-align:top }.knowledge-detail { background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:18px; align-self:start }.knowledge-detail header { justify-content:space-between; align-items:flex-start }.knowledge-detail h2 { margin:0; font-size:1.15rem }.knowledge-detail header p { margin:4px 0 }.knowledge-detail h3 { font-size:1rem }.knowledge-detail > .hint { margin:8px 0 }.knowledge-score-pair { font-size:.8rem; gap:22px; padding:10px 0 }.knowledge-tabs { display:flex; gap:6px; border-bottom:1px solid var(--line); padding-bottom:8px }.knowledge-tabs button { border:0; padding:5px 10px; text-transform:capitalize }.knowledge-tabs button[aria-pressed=true] { background:var(--accent-soft); color:var(--accent) }.knowledge-pane { padding-top:12px }.knowledge-pane fieldset { border:0; padding:0; margin:0; min-width:0 }.knowledge-pane details { margin:12px 0 }.knowledge-pane dl,.knowledge-statistics dl { display:grid; grid-template-columns:auto 1fr; gap:6px 12px; font-size:.8rem }.knowledge-pane dd,.knowledge-statistics dd { margin:0; overflow-wrap:anywhere }.knowledge-pane dt { color:var(--muted) }.knowledge-description { white-space:pre-wrap; overflow-wrap:anywhere; max-height:38vh; overflow:auto; line-height:1.6; font-size:.9rem; margin-top:0 }.knowledge-rationale { white-space:pre-wrap; overflow-wrap:anywhere; line-height:1.6 }.knowledge-pane pre { white-space:pre-wrap; overflow-wrap:anywhere; max-height:300px; overflow:auto; font-size:.75rem; background:var(--bg); padding:10px }.knowledge-pane code { display:block; overflow-wrap:anywhere; font-size:.75rem }.knowledge-confirm { display:flex; align-items:flex-start; gap:8px; font-size:.85rem }.knowledge-confirm input { width:auto; margin-top:3px }.knowledge-actions { justify-content:flex-end; margin-top:12px }.knowledge-pagination { justify-content:space-between; margin-top:12px; font-size:.8rem }.knowledge-state { margin-top:16px; font-size:.75rem; color:var(--muted) }.knowledge-state code { overflow-wrap:anywhere }
@media(max-width:1100px) { .knowledge-filters { grid-template-columns:repeat(2,minmax(0,1fr)) }.knowledge-search { grid-column:1/-1 }.knowledge-columns.has-detail { grid-template-columns:1fr } }@media(max-width:550px) { .knowledge-filters { grid-template-columns:1fr }.knowledge-statistics { gap:8px 16px }.knowledge-detail { padding:12px }.knowledge-queue th,.knowledge-queue td { padding:8px 5px } }
</style>
