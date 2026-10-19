<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { api, ApiError, send } from '../api'
import { justifications, justificationLabel } from '../assessmentReasons'
import { knowledgeApi, type SsvcSelection, type KnowledgeFinding, type KnowledgeProposal, type KnowledgeWorkspace, type KnowledgeScoreInput, type KnowledgeScorePreview } from '../knowledgeApi'
import type { Me } from '../types'
import SearchSelect from './SearchSelect.vue'
import KnowledgeDependencyTree from './KnowledgeDependencyTree.vue'
import KnowledgeDependencyPaths from './KnowledgeDependencyPaths.vue'
import SsvcAssessment from './SsvcAssessment.vue'
import KnowledgeScoringPolicy from './KnowledgeScoringPolicy.vue'
import CvssContextEditor from './CvssContextEditor.vue'
import CvssVectorComparison from './CvssVectorComparison.vue'
import { findingVectors } from '../lib/cvssComparison'
import KnowledgeCreateProduct from './KnowledgeCreateProduct.vue'
import KnowledgeComparison from './KnowledgeComparison.vue'
import KnowledgeRetained from './KnowledgeRetained.vue'
import KnowledgeLicenses from './KnowledgeLicenses.vue'
import KnowledgeContributions from './KnowledgeContributions.vue'
import KnowledgeCpeIdentification from './KnowledgeCpeIdentification.vue'
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
import KnowledgeOrganizationPortfolio from './KnowledgeOrganizationPortfolio.vue'
import KnowledgeAdvisories from './KnowledgeAdvisories.vue'
import KnowledgeReconciliation from './KnowledgeReconciliation.vue'
import KnowledgeOwnership from './KnowledgeOwnership.vue'
import KnowledgeBulkReview from './KnowledgeBulkReview.vue'
import KnowledgeCpePolicy from './KnowledgeCpePolicy.vue'
import KnowledgeAssessmentArchive from './KnowledgeAssessmentArchive.vue'
import KnowledgeEvidenceSources from './KnowledgeEvidenceSources.vue'
import KnowledgePipelineConfiguration from './KnowledgePipelineConfiguration.vue'
import KnowledgeSyncAutomation from './KnowledgeSyncAutomation.vue'
import KnowledgeObservations from './KnowledgeObservations.vue'
const props = defineProps<{ me: Me }>()
const emit = defineEmits<{ locked: [boolean] }>()
const compositionTools = ref<HTMLDetailsElement | null>(null), intelligenceTools = ref<HTMLDetailsElement | null>(null), reportTools = ref<HTMLDetailsElement | null>(null)
const productCreationLocked = ref(false)
const scoringPolicyLocked = ref(false)
const intakeBusy = ref(false), assemblyLocked = ref(false), metadataLocked = ref(false), licenseLocked = ref(false), archiveLocked = ref(false), correspondenceLocked = ref(false), analysisFollowUpLocked = ref(false), cpeLocked = ref(false), advisoryLocked = ref(false)
const pipelineConfigurationLocked = ref(false), syncAutomationLocked = ref(false), observationsLocked = ref(false)
const otherIntakeLocked = computed(() => intakeBusy.value || assemblyLocked.value || metadataLocked.value || licenseLocked.value || archiveLocked.value || correspondenceLocked.value || analysisFollowUpLocked.value || cpeLocked.value || advisoryLocked.value || scoringPolicyLocked.value)
const baseIntakeLocked = computed(() => productCreationLocked.value || otherIntakeLocked.value)
const intakeLocked = computed(() => baseIntakeLocked.value || pipelineConfigurationLocked.value || syncAutomationLocked.value || observationsLocked.value)
watch(() => productCreationLocked.value || intakeBusy.value || assemblyLocked.value || pipelineConfigurationLocked.value || observationsLocked.value || correspondenceLocked.value, value => { if (value && compositionTools.value) compositionTools.value.open = true }, { flush: 'post' })
watch(() => cpeLocked.value || advisoryLocked.value || syncAutomationLocked.value || scoringPolicyLocked.value, value => { if (value && intelligenceTools.value) intelligenceTools.value.open = true }, { flush: 'post' })
watch(() => metadataLocked.value || licenseLocked.value || archiveLocked.value, value => { if (value && reportTools.value) reportTools.value.open = true }, { flush: 'post' })
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

const projectCapabilities = ref<string[]>([])
const project = ref(''), projectName = ref(''), version = ref(''), team = ref(''), lifecycle = ref(''), query = ref('')
const filterLabels: Record<string, string> = { ssvc_status: 'SSVC status', ssvc_action: 'SSVC action', source_severity: 'Source severity', contextual_severity: 'Published severity', applicability: 'Applicability', scoring_status: 'Scoring status', team_review: 'Team assessment', provider: 'Evidence provider', agentyzer_evidence: 'Agentyzer evidence', vscorer_evidence: 'VScorer evidence', cvss_version: 'Source CVSS version', dependency: 'Dependency relationship', source_conflict: 'Source discrepancies', component: 'Component', criticality: 'Cybersecurity criticality', exposure: 'Exposure', support_status: 'Support status', metadata_status: 'Annotation status' }
const emptyFilters = () => Object.fromEntries(Object.keys(filterLabels).map(key => [key, '']))
const filters = ref(emptyFilters()), filterDraft = ref(emptyFilters())
const activeFilterCount = computed(() => Object.values(filters.value).filter(Boolean).length)
const receivedEvidenceFilters = ['agentyzer_evidence', 'vscorer_evidence'] as const
const receivedEvidenceOptions = [{ value: 'missing', label: 'No received evidence' }, { value: 'current', label: 'Has current evidence' }, { value: 'historical_only', label: 'Historical evidence only' }, { value: 'eligible', label: 'Has current eligible evidence' }]
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
const ssvc = ref<SsvcSelection | null>(null)
const scoreBase = ref(''), scoreVector = ref(''), scoreRationale = ref(''), scoreMode = ref<'manual' | 'applicability' | 'false_positive'>('manual')
type ScoreRequest = KnowledgeScoreInput & { expected_policy?: string | null; rule_basis?: 'applicability' | 'false_positive' }
type BoundScorePreview = { input: ScoreRequest; result: KnowledgeScorePreview; generation: number; signature: string; project: string }
const scorePreview = ref<BoundScorePreview | null>(null)
type ScoreCapture = { generation: number; view: string; scope: string; project: string; version: string; row: KnowledgeFinding; body: ScoreRequest & { preview: string }; scrollX: number; scrollY: number }
const pendingScore = ref<ScoreCapture | null>(null)
let scoreSequence = 0
const sourceVectors = computed(() => [...new Set((selected.value?.original_base_vectors || selected.value?.source_ratings || []).map(item => item.vector).filter((value): value is string => Boolean(value)) || [])])
const workflowTabs = computed(() => can('rescore') ? ['evidence', 'assessment', 'review', 'scoring'] as const : ['evidence', 'assessment', 'review'] as const)
const assessmentScope = ref<{ expected_versions: Record<string, string>; targets: { version: string; context_id: string; vulnerability_id: string }[] } | null>(null)
const assessmentEvidence = ref<unknown[]>([])
const citedInputs = computed(() => [...(selected.value?.contributions?.vulnerability_sources || []), ...(selected.value?.contributions?.vulnerability_analyses || [])])
const vectorEntries = computed(() => {
  if (!selected.value) return []
  const entries = findingVectors(selected.value)
  if (tab.value === 'scoring' && scorePreview.value) { const p = scorePreview.value.result.proposal; entries.push({ id: 'coordinator-preview', label: 'Coordinator preview', vector: p.vector, baseVector: p.base_vector, score: p.score, status: scorePreview.value.result.eligible ? 'Ready for explicit publication' : 'Blocked by required reviews' }) }
  return entries
})
const findingElement = ref<HTMLElement | null>(null)
const detailTask = ref<'workflow' | 'tools' | 'component' | 'technical'>('workflow')
const focused = computed(() => !!selected.value && detailTask.value === 'workflow' && tab.value !== 'evidence')
async function showDetailTask(task: typeof detailTask.value) {
  if (busy.value || metadataLocked.value || analysisFollowUpLocked.value) return
  detailTask.value = task
  await nextTick()
  findingElement.value?.querySelector<HTMLElement>(`[data-finding-task="${task}"] > h3`)?.focus()
}
watch(analysisFollowUpLocked, locked => { if (locked) detailTask.value = 'tools' })
watch(metadataLocked, locked => { if (locked) detailTask.value = 'component' })
const workflowTitle = (step: string) => ({ evidence: 'Overview', assessment: 'Assessment', review: 'Independent review', scoring: 'Coordinator scoring' })[step] || step
function isCited(id: string) { return assessmentEvidence.value.some(e => e && typeof e === 'object' && (e as Record<string, unknown>).proposal_id === id) }
function citeInput(id: string, checked: boolean) {
  if (!canEditAssessment.value || busy.value || pendingRequest.value || pendingScore.value) return
  if (checked && !isCited(id)) { const entry = citedInputs.value.find(e => e.id === id); if (!entry) return; if (assessmentEvidence.value.length >= 100) { error.value = 'Assessment evidence is limited to 100 citations.'; return }; assessmentEvidence.value.push({ proposal_id: id, label: entry.label || entry.provider, ...Object.fromEntries(['observation_id', 'artifact_sha256', 'report_sha256'].filter(key => entry.provenance[key]).map(key => [key, entry.provenance[key]])) }) }
  else if (!checked) assessmentEvidence.value = assessmentEvidence.value.filter(e => !e || typeof e !== 'object' || (e as Record<string, unknown>).proposal_id !== id)
}
const assessmentId = ref(''), confirmed = ref(false), reviewRationale = ref('')
type WorkflowKind = 'draft' | 'submit' | 'approve' | 'request_changes'
let actorGeneration = 0
type WorkflowRequest = { scope: string; generation: number; view: string; actor: string; endpoint: string; body: Record<string, unknown>; kind: WorkflowKind; next: boolean; project: string; version: string; row: KnowledgeFinding; following: string[]; scrollX: number; scrollY: number; queueX: number; queueY: number }
const pendingRequest = ref<WorkflowRequest | null>(null)
const queueElement = ref<HTMLElement | null>(null)
const workflowScope = () => JSON.stringify([project.value, version.value, team.value, lifecycle.value, query.value, filters.value, offset.value])
const workflowView = () => JSON.stringify([workflowScope(), selected.value?.id])
const scoreSignature = () => JSON.stringify([workflowView(), workspace.value?.state, selected.value?.state, scoreBase.value, scoreVector.value, scoreRationale.value, scoreMode.value])
let sequence = 0, timer: ReturnType<typeof setTimeout> | undefined
const scope = computed(() => `/projects/${encodeURIComponent(project.value)}/versions/${encodeURIComponent(version.value)}`)
const assessment = computed(() => selected.value?.coverage.assessment)
const revisesCurrent = computed(() => assessmentId.value === assessment.value?.payload.assessment_id)
const canEditAssessment = computed(() => can('assess') && (!assessment.value || !revisesCurrent.value || (assessment.value.stage === 'draft' && assessment.value.payload.author_id === props.me.id)))
type LocalDraft = { assessmentId: string; applicability: string; justification: string; rationale: string; conditions: string; ssvc: SsvcSelection | null; evidence: unknown[] }
const localDrafts = reactive(new Map<string, LocalDraft>())
const retainedDrafts = computed(() => [...localDrafts].filter(([key]) => key !== draftKey.value).map(([key, draft]) => ({ key, binding: JSON.parse(key) as string[], draft })))
const draftKey = ref(''), initialDraft = ref(''), restoredDraft = ref(false)
const draftValue = (): LocalDraft => ({ assessmentId: assessmentId.value, applicability: applicability.value, justification: justification.value, rationale: rationale.value, conditions: conditions.value, ssvc: ssvc.value, evidence: assessmentEvidence.value })
const draftChanged = computed(() => Boolean(draftKey.value && JSON.stringify(draftValue()) !== initialDraft.value))
function retainDraft() { if (draftKey.value && draftChanged.value && canEditAssessment.value) localDrafts.set(draftKey.value, JSON.parse(JSON.stringify(draftValue()))) }
function clearLocalDraft() { if (draftKey.value) localDrafts.delete(draftKey.value); initialDraft.value = JSON.stringify(draftValue()); restoredDraft.value = false }
function beforeLeave(event: BeforeUnloadEvent) { if (draftChanged.value || localDrafts.size || pendingRequest.value || pendingScore.value) { event.preventDefault(); event.returnValue = '' } }
function backToQueue() {
  if (metadataLocked.value || analysisFollowUpLocked.value) return
  const target = queueElement.value?.querySelector<HTMLButtonElement>('.review-queue-table .selected .text-link')
  close(); void nextTick(() => target?.focus())
}
function startAssessment() {
  if (!can('assess') || busy.value || pendingRequest.value || pendingScore.value) return
  assessmentId.value = crypto.randomUUID(); assessmentScope.value = null
  notice.value = 'New assessment started. Existing decisions and approved history are retained; review the copied evidence before submitting.'
}

const label = (value: string) => value.replaceAll('_', ' ')
const teamName = (id?: string) => (id ? workspace.value?.team_labels?.[id] : undefined) || props.me.workspaces.find(item => item.id === id)?.name || id || 'Unassigned'
const can = (capability: string) => Boolean(selected.value?.capabilities.includes(capability))
const ratingSource = (rating: KnowledgeFinding['source_ratings'][number]) => (typeof rating.source === 'string' ? rating.source : rating.source?.name || rating.source?.url) || rating.observed_source || 'Unattributed source'
const severity = (score: number | undefined | null) => score == null ? 'Unknown' : score === 0 ? 'None' : score < 4 ? 'Low' : score < 7 ? 'Medium' : score < 9 ? 'High' : 'Critical'
const sourceSeverity = (row: KnowledgeFinding) => typeof row.source_severity === 'string' ? label(row.source_severity) : severity(row.source_ratings.filter(r => r.score != null).reduce<number | undefined>((value, rating) => value == null ? rating.score! : Math.max(value, rating.score!), undefined))
const sourceScore = (row: KnowledgeFinding) => row.source_ratings.filter(r => r.score != null).map(r => r.score!.toFixed(1)).join(' / ') || (typeof row.source_severity === 'string' ? label(row.source_severity) : 'Unknown')
const selectedIndex = computed(() => workspace.value?.items.findIndex(item => item.id === selected.value?.id) ?? -1)
function fail(err: unknown) { error.value = err instanceof ApiError && err.status === 409 ? 'The baseline or assessment changed. Refresh before retrying; your text is retained.' : err instanceof Error ? err.message : 'Request failed' }
function close() { if (metadataLocked.value || analysisFollowUpLocked.value) return; retainDraft(); draftKey.value = ''; restoredDraft.value = false; assessmentScope.value = null; selected.value = null; confirmed.value = false; scorePreview.value = null; ++scoreSequence }
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
async function chooseProject(option: { id: string; name?: string; capabilities?: string[] }, preferredVersion = '') {
  if (intakeLocked.value) return
  if (teamLabelProject !== option.id) { knownTeamLabels.value = {}; teamLabelProject = option.id; if (!restoring) team.value = explicitAllTeams.value ? '' : defaultTeam() }
  projectCapabilities.value = option.capabilities || []
  const current = ++sequence; ++versionSequence; projectName.value = option.name || option.id; versions.value = []; version.value = ''; versionQuery.value = ''; versionMenu.value = false; workspace.value = null; close()
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const result = await knowledgeApi<{ items: { version: string; state: string }[]; next_offset: number | null }>(`/projects/${encodeURIComponent(option.id)}/versions?limit=25`)
    if (current !== sequence) return
    versions.value = result.items; versionNext.value = result.next_offset; version.value = preferredVersion || result.items[0]?.version || ''; await load()
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function onProductCreated(value: { id: string; name: string; workspace_id: string }) {
  productCreationLocked.value = false; project.value = value.id; await chooseProject(value)
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
  if (metadataLocked.value || analysisFollowUpLocked.value) return
  retainDraft()
  ++scoreSequence; scorePreview.value = null
  const current = ++sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    const detail = await knowledgeApi<KnowledgeFinding>(`${scope.value}/workspace/${encodeURIComponent(row.context_id)}/${encodeURIComponent(row.vulnerability_id)}?expected=${workspace.value!.state}`)
    if (current !== sequence) return
    assessmentScope.value = null; selected.value = detail; detailTask.value = 'workflow'; tab.value = 'evidence'; confirmed.value = false; reviewRationale.value = ''; scorePreview.value = null
    scoreBase.value = (detail.original_base_vectors || detail.source_ratings).find(item => item.vector)?.vector || ''; scoreVector.value = scoreBase.value; scoreRationale.value = ''
    const record = detail.coverage.assessment
    ssvc.value = record?.payload.ssvc ? JSON.parse(JSON.stringify(record.payload.ssvc.selection)) : null
    assessmentId.value = record?.payload.assessment_id || crypto.randomUUID()
    applicability.value = record?.payload.state || 'under_investigation'; rationale.value = record?.payload.rationale || ''
    justification.value = record?.payload.justification || ''; conditions.value = record?.payload.conditions || ''
    assessmentEvidence.value = JSON.parse(JSON.stringify(record?.payload.evidence || []))
    draftKey.value = JSON.stringify([props.me.id, project.value, version.value, detail.state || workspace.value?.state, detail.context_id, detail.vulnerability_id, record?.revision || null])
    initialDraft.value = JSON.stringify(draftValue()); restoredDraft.value = false
    const saved = localDrafts.get(draftKey.value)
    if (saved) { assessmentId.value = saved.assessmentId; applicability.value = saved.applicability; justification.value = saved.justification; rationale.value = saved.rationale; conditions.value = saved.conditions; ssvc.value = saved.ssvc; assessmentEvidence.value = saved.evidence; restoredDraft.value = true }
    await nextTick(); if (current === sequence) document.querySelector<HTMLElement>('.knowledge-detail h2')?.focus({ preventScroll: true })

  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function paginate(next: boolean) {
  if (analysisFollowUpLocked.value) return
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
      ? { ...(assessmentScope.value || base), expected_revision: revisesCurrent.value ? assessment.value?.revision || null : null, state: applicability.value, justification: applicability.value === 'not_affected' ? justification.value || null : null, rationale: rationale.value, conditions: conditions.value, ...(ssvc.value || assessment.value?.payload.ssvc ? { ssvc: ssvc.value } : {}), evidence: assessmentEvidence.value }
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
    if (workflowView() === request.view && (request.kind === 'draft' || request.kind === 'submit')) clearLocalDraft()
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
  scoreMode.value = 'manual'; scoreBase.value = proposal.score_input.base_vector; scoreVector.value = proposal.score_input.vector
  scoreRationale.value = ''; tab.value = 'scoring'
  notice.value = 'Proposal loaded. Add your rationale and preview required reviews before publication.'
}
async function previewScore() {
  if (busy.value || metadataLocked.value || pendingRequest.value || pendingScore.value || !selected.value || !workspace.value || !can('rescore') || !scoreBase.value || !scoreVector.value || !scoreRationale.value.trim()) return
  const current = ++scoreSequence, generation = actorGeneration, signature = scoreSignature(), product = project.value
  busy.value = true; error.value = ''; notice.value = ''; scorePreview.value = null
  try {
    const input: ScoreRequest = { request_id: crypto.randomUUID(), expected_versions: { [version.value]: selected.value.state || workspace.value.state }, targets: [{ version: version.value, context_id: selected.value.context_id, vulnerability_id: selected.value.vulnerability_id }], base_vector: scoreBase.value, vector: scoreVector.value, rationale: scoreRationale.value }
    if (scoreMode.value !== 'manual') {
      const policy = await knowledgeApi<{ state: string | null }>(`/projects/${encodeURIComponent(product)}/scoring-policy`)
      if (generation !== actorGeneration || current !== scoreSequence || signature !== scoreSignature()) return
      input.expected_policy = policy.state; input.rule_basis = scoreMode.value
    }
    const result = await knowledgeApi<KnowledgeScorePreview>(`/projects/${encodeURIComponent(product)}/scoring/${input.rule_basis ? 'rules/' : ''}preview`, send(input))
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
    const result = await knowledgeApi<{ committed?: boolean; projection?: string }>(`/projects/${encodeURIComponent(capture.project)}/scoring/${capture.body.rule_basis ? 'rules/' : ''}publish`, send(capture.body))
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

watch(tab, () => { assessmentScope.value = null; detailTask.value = 'workflow' })
watch(detailTask, task => { if (task !== 'workflow') assessmentScope.value = null })
watch([scoreBase, scoreVector, scoreRationale, scoreMode], () => { ++scoreSequence; scorePreview.value = null }, { flush: 'sync' })
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
  params.set('page', 'Review')
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
    if (id) { const result = await api<{ id: string; name: string; capabilities?: string[] }>(`/projects/${encodeURIComponent(id)}`); project.value = result.id; await chooseProject(result, params.get('k_version') || '') }
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
watch(() => props.me.id, () => { localDrafts.clear(); draftKey.value = ''; productCreationLocked.value = false; analysisFollowUpLocked.value = false; pipelineConfigurationLocked.value = false; syncAutomationLocked.value = false; ++actorGeneration; ++scoreSequence; pendingRequest.value = null; pendingScore.value = null; scorePreview.value = null; knownTeamLabels.value = {}; explicitAllTeams.value = false; team.value = defaultTeam(); workspace.value = null; close(); void load() }, { flush: 'sync' })
watch(query, () => { if (restoring) return; clearTimeout(timer); timer = setTimeout(() => { void load() }, 250) })
watch(() => Boolean(busy.value || intakeLocked.value || bulkLocked.value || pendingRequest.value || pendingScore.value), value => emit('locked', value), { immediate: true })
onMounted(() => {
  window.addEventListener('beforeunload', beforeLeave)
  try { const stored: unknown = JSON.parse(localStorage.getItem(`dtvp.knowledge.views:${props.me.id}`) || '[]'); if (Array.isArray(stored)) savedViews.value = stored.filter(item => item && typeof item.name === 'string' && typeof item.query === 'string').slice(-20) } catch { /* Browser storage is optional. */ }
  if (initialView.has('k_project')) void restoreView(initialView.toString())
})
onBeforeUnmount(() => { window.removeEventListener('beforeunload', beforeLeave); ++actorGeneration; ++sequence; ++versionSequence; clearTimeout(timer); clearTimeout(versionTimer); emit('locked', false) })
</script>
<template>
  <section class="knowledge-workspace" :class="{ 'finding-open': selected }" aria-label="Review workspace">
    <header class="knowledge-heading"><div><h1>Vulnerability review</h1><p class="hint">Product · version · responsible team</p></div><div class="knowledge-actions"><button :disabled="busy || metadataLocked || !version" @click="load()">Refresh workspace</button></div></header>


    <form class="knowledge-filters" @submit.prevent="load()">
      <SearchSelect v-model="project" label="Product scope" :selected-label="projectName" endpoint="/catalog/projects" :disabled="busy || intakeLocked" @select="chooseProject" />
      <div class="search-select" @keydown.esc="versionMenu = false"><span class="field-label" id="knowledge-version-label">Version</span><button type="button" :disabled="busy || intakeLocked || !project" aria-labelledby="knowledge-version-label knowledge-version-value" :aria-expanded="versionMenu" aria-haspopup="listbox" @click="versionMenu = !versionMenu"><span id="knowledge-version-value">{{ version || 'Select…' }}</span><span aria-hidden="true">⌄</span></button><div v-if="versionMenu" class="select-menu"><input v-model="versionQuery" type="search" aria-label="Search versions" placeholder="Search versions" @input="searchVersions"><div role="listbox" aria-label="Version"><button v-for="item in versions" :key="item.version" type="button" role="option" :aria-selected="version === item.version" @click="chooseVersion(item.version)">{{ item.version }}</button></div><p v-if="versionBusy" role="status">Searching…</p><p v-else-if="!versions.length">No matching versions.</p><button v-if="versionNext != null" type="button" :disabled="versionBusy" @click="loadVersions(true)">More versions</button></div></div>
      <label>Responsible team<select v-model="team" :disabled="busy" @change="explicitAllTeams = !team"><option value="">All accessible teams</option><option v-for="item in teamOptions" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
      <label>Review status<select v-model="lifecycle" :disabled="busy"><option value="">All statuses</option><option v-for="status in ['unassessed', 'draft', 'submitted', 'approved', 'reassessment_needed', 'historically_absent']" :key="status" :value="status">{{ label(status) }}</option></select></label>
      <label class="knowledge-search">Search<input v-model="query" :disabled="busy" type="search" placeholder="Vulnerability, component or description"></label>
    </form>
    <details class="knowledge-advanced"><summary>More filters<span v-if="activeFilterCount"> · {{ activeFilterCount }} applied</span></summary>
      <form @submit.prevent="applyFilters"><fieldset :disabled="busy"><div class="knowledge-filter-grid">
        <label>SSVC status<select v-model="filterDraft.ssvc_status"><option value="">Any SSVC status</option><option v-for="value in ['missing', 'draft', 'submitted', 'approved', 'pending', 'stale']" :key="value" :value="value">{{ label(value) }}</option></select></label><label>SSVC action<select v-model="filterDraft.ssvc_action"><option value="">Any SSVC action</option><option v-for="value in ['DEFER', 'SCHEDULED', 'OUT_OF_CYCLE', 'IMMEDIATE']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Source severity<select v-model="filterDraft.source_severity"><option value="">Any source severity</option><option v-for="band in severityBands" :key="band" :value="band">{{ label(band) }}</option></select></label>
        <label>Published severity<select v-model="filterDraft.contextual_severity"><option value="">Any published severity</option><option v-for="band in severityBands" :key="band" :value="band">{{ label(band) }}</option></select></label>
        <label>Context applicability<select v-model="filterDraft.applicability"><option value="">Any applicability</option><option v-for="value in ['affected', 'not_affected', 'fixed', 'under_investigation', 'unassessed', 'unknown']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Scoring status<select v-model="filterDraft.scoring_status"><option value="">Any scoring status</option><option v-for="value in ['published', 'outdated', 'not_published', 'unknown']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Team assessment<select v-model="filterDraft.team_review"><option value="">Any team assessment</option><option v-for="value in ['missing', 'recorded', 'current', 'draft', 'submitted', 'pending', 'approved', 'needs_revalidation', 'changes_requested']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Evidence provider<input v-model="filterDraft.provider" maxlength="200" placeholder="Exact attributed source"></label>
        <label v-for="key in receivedEvidenceFilters" :key="key">{{ filterLabels[key] }}<select v-model="filterDraft[key]"><option value="">Any received evidence</option><option v-for="option in receivedEvidenceOptions" :key="option.value" :value="option.value">{{ option.label }}</option></select></label>
        <label>Source CVSS version<select v-model="filterDraft.cvss_version"><option value="">Any CVSS version</option><option v-for="value in ['2.0', '3.0', '3.1', '4.0', 'unknown']" :key="value" :value="value">{{ value }}</option></select></label>
        <label>Dependency relationship<select v-model="filterDraft.dependency"><option value="">Any relationship</option><option v-for="value in ['root', 'direct', 'transitive', 'unknown']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Source discrepancies<select v-model="filterDraft.source_conflict"><option value="">Any source discrepancies</option><option value="yes">Reported discrepancy</option><option value="no">No comparable discrepancy observed</option><option value="unknown">Unknown</option></select></label>
        <label>Component<input v-model="filterDraft.component" maxlength="500" placeholder="Name, namespace or package URL"></label>
        <label>Cybersecurity criticality<select v-model="filterDraft.criticality"><option value="">Any criticality</option><option v-for="value in ['unknown', 'low', 'moderate', 'high', 'critical']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Exposure<select v-model="filterDraft.exposure"><option value="">Any exposure</option><option v-for="value in ['unknown', 'not_exposed', 'internal', 'external']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Support status<select v-model="filterDraft.support_status"><option value="">Any support status</option><option v-for="value in ['unknown', 'supported', 'unsupported', 'internally_maintained']" :key="value" :value="value">{{ label(value) }}</option></select></label>
        <label>Annotation status<select v-model="filterDraft.metadata_status"><option value="">Any annotation status</option><option v-for="value in ['missing', 'current', 'stale', 'out_of_scope', 'absent', 'unknown']" :key="value" :value="value">{{ label(value) }}</option></select></label>
      </div><div class="knowledge-actions"><button type="button" @click="resetFilters">Reset advanced filters</button><button class="primary">Apply filters</button></div></fieldset></form>
      <p class="hint">Filters and counts use the full server result. Unknown evidence stays unknown; outdated scores are excluded from published severity. Criticality, exposure and support use current authored annotations; missing or stale values stay unknown. Agentyzer and VScorer filters describe received evidence, not queued jobs or human approval. Current evidence may still be ineligible for application.</p>
    </details>


    <details v-if="retainedDrafts.length" class="knowledge-pane retained-drafts"><summary>Unsaved drafts from other contexts or earlier input states ({{ retainedDrafts.length }})</summary><p class="hint">These drafts have not been saved to DTVP. They are not applied automatically to a changed baseline or assessment revision. Inspect the original text and citations before explicitly authoring a current assessment.</p><article v-for="entry in retainedDrafts" :key="entry.key"><h3>{{ entry.binding[5] }} · {{ entry.binding[2] }}</h3><p class="hint">Context {{ entry.binding[4] }} · product {{ entry.binding[1] }}</p><details><summary>Original draft and input binding</summary><pre>{{ JSON.stringify({ source_state: entry.binding[3], assessment_revision: entry.binding[6], ...entry.draft }, null, 2) }}</pre></details><button :disabled="busy || !!pendingRequest || !!pendingScore" @click="localDrafts.delete(entry.key)">Discard this unsaved draft</button></article></details>
    <section v-if="pendingScore" class="knowledge-pane" aria-label="Pending coordinator score publication"><p role="status">Captured contextual score for {{ pendingScore.project }} / {{ pendingScore.version }} / {{ pendingScore.row.vulnerability_id }}. Preview, expected source head, source Base, vector, rationale and request ID remain fixed.</p><button :disabled="busy || metadataLocked" @click="publishScore(true)">Retry exact score publication</button><button :disabled="busy" @click="discardScorePublication">Discard captured score publication</button><details><summary>Captured score input and preview</summary><pre>{{ JSON.stringify(pendingScore.body, null, 2) }}</pre></details></section>
    <section v-if="pendingRequest" class="knowledge-pane" aria-label="Pending assessment workflow request"><p role="status">Captured {{ label(pendingRequest.kind) }} for {{ pendingRequest.project }} / {{ pendingRequest.version }} / {{ pendingRequest.row.vulnerability_id }}. Exact source heads, evidence, target and request ID are retained.</p><button :disabled="busy || metadataLocked" @click="mutate(pendingRequest.kind, pendingRequest.next, true)">Retry exact assessment workflow request</button><button :disabled="busy" @click="discardWorkflowRequest">Discard captured workflow request</button><details><summary>Captured workflow input</summary><pre>{{ JSON.stringify(pendingRequest.body, null, 2) }}</pre></details></section>
    <KnowledgeBulkReview :key="me.id" :project="project" :version="version" :state="workspace?.state || ''" :rows="bulkRows" @locked="bulkLocked = $event" @reset="bulkSelection = {}" @changed="bulkChanged" />
    <p v-if="error" role="alert" class="message">{{ error }}</p><p v-if="notice" role="status" class="message">{{ notice }}</p><p v-if="busy" role="status">Loading…</p>
    <p v-if="project && !busy && !version && !versions.length" class="empty">No journal-backed versions. Import a baseline to start.</p><p v-else-if="!project" class="empty">Select a product to review its versioned knowledge.</p>
    <template v-if="workspace">
      <p v-if="workspace.baseline_status === 'withdrawn'" role="status" class="message">The current inventory was withdrawn. Historical assessments and release tags remain retained.</p>
      <div class="knowledge-statistics" aria-label="Filtered workspace statistics"><span><strong>{{ workspace.statistics.totals.context_findings }}</strong> context findings</span><span><strong>{{ workspace.statistics.totals.unique_vulnerabilities }}</strong> vulnerabilities</span><span><strong>{{ workspace.statistics.recorded }}</strong> recorded</span><span><strong>{{ workspace.statistics.submitted }}</strong> submitted</span><span><strong>{{ workspace.statistics.approved }}</strong> approved</span><details><summary>Breakdown</summary><dl><template v-for="(count, status) in workspace.statistics.by_status" :key="status"><dt>{{ label(String(status)) }}</dt><dd>{{ count }}</dd></template><template v-for="(count, id) in workspace.statistics.by_team" :key="id"><dt>{{ teamName(String(id)) }}</dt><dd>{{ typeof count === 'number' ? count : count.context_findings }} findings</dd></template><template v-for="(count, severity) in workspace.statistics.severity" :key="severity"><dt>{{ severity }}</dt><dd>{{ count }}</dd></template></dl></details></div>

      <KnowledgeDependencyTree v-show="!selected" :key="`${me.id}:${project}`" :project="project" :state="workspace.state" />
      <div class="knowledge-columns" :class="{ 'has-detail': selected }">
        <section class="knowledge-queue" aria-label="Context finding queue"><div ref="queueElement" class="table-wrap"><ul v-if="selected" class="compact-queue" aria-label="Finding results"><li v-for="row in workspace.items" :key="row.id" :class="{ selected: selected.id === row.id }"><input v-if="workspace.items.some(item => item.capabilities?.includes('approve')) || bulkRows.length || bulkLocked" type="checkbox" :aria-label="`Select ${row.vulnerability_id} in ${row.context.root_ref} for bulk review`" :checked="!!bulkSelection[row.id]" :disabled="busy || bulkLocked || !bulkEligible(row) || (!bulkSelection[row.id] && bulkRows.length >= 100)" @change="toggleBulk(row)"><button class="text-link" :aria-current="selected.id === row.id ? 'true' : undefined" :disabled="busy" @click="open(row)">{{ row.vulnerability_id }}</button><small>{{ row.component.name }} {{ row.component.version }} · used by {{ row.context.root_ref || 'Unknown context' }}</small><small>{{ teamName(row.context.team_id) }} · {{ label(row.coverage.status) }}</small><small v-if="row.ssvc?.current || row.ssvc?.approved">SSVC: {{ (row.ssvc?.approved || row.ssvc?.current)?.outcome_label || 'Incomplete' }} · {{ label(row.ssvc.status) }}</small><div class="queue-ratings"><span>Source <strong>{{ sourceScore(row) }}</strong></span><span>Published <strong>{{ row.published_score?.score.toFixed(1) ?? '—' }}</strong><template v-if="row.published_score?.current === false"> · Outdated</template></span></div></li></ul><table v-show="!selected" class="review-queue-table"><colgroup><col v-if="workspace.items.some(row => row.capabilities?.includes('approve')) || bulkRows.length || bulkLocked" class="queue-check"><col class="queue-component"><col class="queue-team"><col class="queue-score"><col class="queue-score"></colgroup><thead><tr><th v-if="workspace.items.some(row => row.capabilities?.includes('approve')) || bulkRows.length || bulkLocked" aria-label="Select for bulk review" title="Select for bulk review">✓</th><th>Vulnerability / component</th><th>Team / status</th><th>Source</th><th>Published</th></tr></thead><tbody><tr v-for="row in workspace.items" :key="row.id" :class="{ selected: selected?.id === row.id }"><td v-if="workspace.items.some(item => item.capabilities?.includes('approve')) || bulkRows.length || bulkLocked"><input type="checkbox" :aria-label="`Select ${row.vulnerability_id} in ${row.context.root_ref} for bulk review`" :checked="!!bulkSelection[row.id]" :disabled="busy || bulkLocked || !bulkEligible(row) || (!bulkSelection[row.id] && bulkRows.length >= 100)" @change="toggleBulk(row)"></td><td><button class="text-link" :disabled="busy" @click="open(row)">{{ row.vulnerability_id }}</button><small>{{ row.component.name }} {{ row.component.version }}</small><small>Used by {{ row.context.root_ref || 'Unknown context' }}</small></td><td>{{ teamName(row.context.team_id) }}<small>{{ label(row.coverage.status) }}</small><small v-if="row.ssvc?.current || row.ssvc?.approved">SSVC: {{ (row.ssvc?.approved || row.ssvc?.current)?.outcome_label || 'Incomplete' }} · {{ label(row.ssvc.status) }}</small></td><td>{{ sourceScore(row) }}<small>{{ sourceSeverity(row) }}</small></td><td>{{ row.published_score?.score.toFixed(1) ?? '—' }}<small v-if="row.published_score">{{ severity(row.published_score.score) }}</small><small v-if="row.published_score?.current === false">Outdated</small></td></tr></tbody></table><p v-if="!workspace.items.length && !busy" class="empty">No context findings match this scope.</p></div><div class="knowledge-pagination"><button :disabled="busy || !previous.length" @click="paginate(false)">Previous page</button><span>{{ offset + (workspace.items.length ? 1 : 0) }}–{{ offset + workspace.items.length }}</span><button :disabled="busy || workspace.next_offset == null" @click="paginate(true)">Next page</button></div></section>
        <section v-if="selected" ref="findingElement" class="knowledge-detail" aria-label="Context finding detail">
          <button class="finding-back" :disabled="busy || metadataLocked || analysisFollowUpLocked" @click="backToQueue">← Back to results</button>
          <header class="finding-header"><div><h2 tabindex="-1">{{ selected.vulnerability_id }}</h2><p>{{ selected.component.name }} {{ selected.component.version }} · used by <strong>{{ selected.context.root_ref || 'Unknown context' }}</strong></p><p class="hint">{{ projectName }} · {{ version }} · {{ teamName(selected.context.team_id) }}</p></div><div class="finding-header-actions"><button v-if="can('assess')" class="primary" :disabled="busy || metadataLocked || analysisFollowUpLocked" @click="detailTask = 'workflow'; tab = 'assessment'">Assess this context</button><button v-else-if="can('approve')" class="primary" :disabled="busy || metadataLocked || analysisFollowUpLocked" @click="detailTask = 'workflow'; tab = 'review'">Review assessment</button><button v-else-if="can('rescore')" class="primary" :disabled="busy || metadataLocked || analysisFollowUpLocked" @click="detailTask = 'workflow'; tab = 'scoring'">Coordinate scoring</button><button aria-label="Close context finding" :disabled="busy || metadataLocked || analysisFollowUpLocked" @click="backToQueue">×</button></div></header>
          <div class="finding-status" aria-label="Finding status"><div class="source-status" :class="`severity-${sourceSeverity(selected).toLowerCase()}`"><span>Source severity</span><strong>{{ sourceScore(selected) }} · {{ sourceSeverity(selected) }}</strong><small>{{ [...new Set(selected.source_ratings.map(rating => [ratingSource(rating), rating.method].filter(Boolean).join(' · ')))].join(' / ') || 'No rating supplied' }}</small></div><div class="published-status"><span>Published contextual score</span><strong>{{ selected.published_score?.score.toFixed(1) ?? 'Not published' }}</strong><small>{{ selected.published_score ? selected.published_score.current === false ? 'Outdated · coordinator review required' : selected.published_score.current === true ? 'Current publication' : 'Currency unspecified' : 'Awaiting coordinator publication' }}</small></div><div class="assessment-status" :class="{ 'status-approved': selected.coverage.status === 'approved', 'status-attention': ['reassessment_needed', 'changes_requested'].includes(selected.coverage.status) }"><span>Team assessment</span><strong>{{ label(selected.coverage.status) }}</strong><small>{{ teamName(selected.context.team_id) }} · {{ assessment ? label(assessment.payload.state) : 'No decision recorded' }}</small></div></div>
          <nav class="knowledge-tabs" aria-label="Assessment workflow"><button v-for="step in workflowTabs" :key="step" :aria-pressed="detailTask === 'workflow' && tab === step" :disabled="busy || metadataLocked || analysisFollowUpLocked" @click="detailTask = 'workflow'; tab = step">{{ workflowTitle(step) }}</button></nav>
          <div v-show="detailTask === 'workflow' && tab === 'evidence'" class="knowledge-evidence-workspace"><div class="overview-grid"><div class="overview-context">
          <section class="knowledge-pane knowledge-overview" aria-label="Vulnerability overview"><h3>Description and context</h3><p class="knowledge-description" tabindex="0" aria-label="Vulnerability description">{{ selected.description || 'No source description provided.' }}</p><dl><dt>Consuming root</dt><dd>{{ selected.context.root_ref || 'Unknown' }}</dd><dt>Ownership</dt><dd>{{ label(selected.context.status || 'unknown') }}</dd><dt>Package</dt><dd>{{ selected.component.purl || 'Unknown' }}</dd></dl></section>
          <KnowledgeDependencyPaths :project="project" :state="workspace.state" :component-ref="String(selected.context.component_ref || (selected.component as { 'bom-ref'?: string })['bom-ref'] || '')" :root-ref="String(selected.context.root_ref || '')" />
          <section v-if="selected.curated_metadata" class="knowledge-pane usage-context"><h3>Usage context <small>{{ label(selected.curated_metadata.status) }}</small></h3><p v-if="!selected.curated_metadata.applicable" class="warning">Historical annotations require reconciliation with this component/version before use.</p><dl><dt>Criticality / exposure</dt><dd>{{ label(selected.curated_metadata.payload.annotations.cybersecurity.criticality) }} · {{ label(selected.curated_metadata.payload.annotations.cybersecurity.exposure) }}</dd><dt>Deployment</dt><dd>{{ selected.curated_metadata.payload.annotations.deployment.environment || 'Unknown' }}</dd><dt>Usage</dt><dd>{{ selected.curated_metadata.payload.annotations.deployment.usage || 'Unknown' }}</dd><dt>Support</dt><dd>{{ label(selected.curated_metadata.payload.annotations.support.status) }}</dd><dt>Mitigations</dt><dd>{{ selected.curated_metadata.payload.annotations.cybersecurity.mitigations.join(' · ') || 'Not recorded' }}</dd><dt>Testing evidence</dt><dd>{{ selected.curated_metadata.payload.annotations.cybersecurity.testing_evidence.join(' · ') || 'Not recorded' }}</dd><dt>Source</dt><dd>{{ selected.curated_metadata.payload.provenance.source }} · {{ selected.curated_metadata.payload.provenance.reference }}</dd></dl><p>{{ selected.curated_metadata.payload.rationale }}</p><details><summary>Mitigations, testing and supporting details</summary><pre>{{ JSON.stringify(selected.curated_metadata.payload.annotations, null, 2) }}</pre></details></section>
          <p v-if="!selected.curated_metadata" class="hint">Usage context unknown · no authored component annotations.</p></div><div class="overview-inputs"><p v-if="selected.source_conflict" class="warning">Sources disagree. Compare the attributed records before deciding.</p>
          <KnowledgeContributions :contributions="selected.contributions" :proposals="selected.scoring_proposals" :can-rescore="can('rescore')" :disabled="busy || !!pendingScore || !!pendingRequest" @proposal="useProposal" />

          </div></div></div>
          <div v-if="focused" class="assessment-task-layout">
          <section class="assessment-task-evidence knowledge-pane" aria-label="Evidence alongside assessment"><h3>Vulnerability and usage</h3><p class="knowledge-description" tabindex="0" aria-label="Vulnerability description">{{ selected.description || 'No source description provided.' }}</p><dl><dt>Consuming root</dt><dd>{{ selected.context.root_ref || 'Unknown' }}</dd><dt>Responsible team</dt><dd>{{ teamName(selected.context.team_id) }}</dd><dt>Version</dt><dd>{{ version }} · pinned input state</dd><dt>Criticality</dt><dd>{{ selected.curated_metadata?.applicable ? label(selected.curated_metadata.payload.annotations.cybersecurity.criticality) : 'Unknown · no current annotation' }}</dd><dt>Exposure</dt><dd>{{ selected.curated_metadata?.applicable ? label(selected.curated_metadata.payload.annotations.cybersecurity.exposure) : 'Unknown · no current annotation' }}</dd><dt>Deployment / usage</dt><dd>{{ selected.curated_metadata?.applicable ? [selected.curated_metadata.payload.annotations.deployment.environment, selected.curated_metadata.payload.annotations.deployment.usage].filter(Boolean).join(' · ') || 'Unknown' : 'Unknown' }}</dd><dt>Support</dt><dd>{{ selected.curated_metadata?.applicable ? label(selected.curated_metadata.payload.annotations.support.status) : 'Unknown' }}</dd><dt>Mitigations</dt><dd>{{ selected.curated_metadata?.applicable ? selected.curated_metadata.payload.annotations.cybersecurity.mitigations.join(' · ') || 'Not recorded' : 'Unknown' }}</dd><dt>Testing evidence</dt><dd>{{ selected.curated_metadata?.applicable ? selected.curated_metadata.payload.annotations.cybersecurity.testing_evidence.join(' · ') || 'Not recorded' : 'Unknown' }}</dd></dl>
          <KnowledgeDependencyPaths :project="project" :state="workspace.state" :component-ref="String(selected.context.component_ref || (selected.component as { 'bom-ref'?: string })['bom-ref'] || '')" :root-ref="String(selected.context.root_ref || '')" />
          <p v-if="selected.source_conflict" class="hint">Source discrepancies recorded. Compare the attributed advisory records before deciding.</p>
          <KnowledgeContributions :contributions="selected.contributions" :proposals="selected.scoring_proposals" :can-rescore="false" :disabled="true" />
          <details v-if="selected.evidence?.length"><summary>Additional supporting evidence</summary><pre>{{ JSON.stringify(selected.evidence, null, 2) }}</pre></details>
          <details v-if="assessment?.payload.evidence?.length"><summary>Recorded assessment citations</summary><pre>{{ JSON.stringify(assessment.payload.evidence, null, 2) }}</pre></details>
          </section><div class="assessment-task-decision">
          <form v-if="tab === 'assessment'" class="knowledge-pane assessment-editor" aria-label="Team assessment" @submit.prevent="mutate('submit')"><h3>Your assessment</h3><p class="hint">This consuming context only. Assessment does not require rescoring.</p><p v-if="draftChanged || restoredDraft" class="draft-indicator" role="status">Unsaved text and citations retained in this workspace session. Save draft before leaving the application.</p><p v-if="selected.coverage.approved_assessment" class="hint">An approved assessment is retained. A new draft does not replace its approved pin.</p><p v-if="assessment && revisesCurrent && !canEditAssessment && can('assess')" class="hint">This assessment is submitted or belongs to another author. Start a new assessment to propose a revision; the existing decision stays retained.</p><button v-if="assessment && can('assess')" type="button" :disabled="busy || !!pendingRequest || !!pendingScore || !revisesCurrent" @click="startAssessment">Start new assessment</button><p class="assessment-version">Version coverage: <strong>{{ version }}</strong><span v-if="assessmentScope"> · {{ assessmentScope.targets.length }} explicit targets selected</span></p><details v-if="assessmentScope"><summary>Selected version coverage and input states</summary><pre>{{ JSON.stringify(assessmentScope, null, 2) }}</pre><button type="button" :disabled="busy || !!pendingRequest || !!pendingScore" @click="assessmentScope = null">Limit assessment to current context</button></details><KnowledgeCoverage :project="project" :state="workspace!.state" :version="version" :finding="selected" :busy="busy || !!pendingRequest || !!pendingScore" @scope="assessmentScope = $event"/><fieldset :disabled="busy || !!pendingRequest || !!pendingScore || !canEditAssessment"><label>Applicability<select v-model="applicability"><option v-for="state in ['under_investigation', 'affected', 'not_affected', 'fixed']" :key="state" :value="state">{{ label(state) }}</option></select></label><label v-if="applicability === 'not_affected'">Why not affected?<select v-model="justification" required><option value="" disabled>Select a reason</option><option v-for="(text, code) in justifications" :key="code" :value="code">{{ text }}</option></select></label><label>Reason and evidence<textarea v-model="rationale" rows="5" required placeholder="Explain this decision for the selected consuming context."></textarea></label><fieldset v-if="citedInputs.length" class="assessment-citations"><legend>Evidence considered</legend><p class="hint">Citing a record does not adopt its proposed conclusion or score.</p><label v-for="input in citedInputs" :key="input.id" class="knowledge-confirm"><input type="checkbox" :checked="isCited(input.id)" @change="citeInput(input.id, ($event.target as HTMLInputElement).checked)">{{ input.label || input.provider }} · {{ label(input.status) }}</label></fieldset><details v-if="assessmentEvidence.length"><summary>Assessment evidence citations ({{ assessmentEvidence.length }})</summary><pre>{{ JSON.stringify(assessmentEvidence, null, 2) }}</pre></details><SsvcAssessment v-model="ssvc" :disabled="busy || !!pendingRequest || !!pendingScore || !canEditAssessment" /><details :open="Boolean(assessmentScope)"><summary>Applicability conditions</summary><label>Conditions<textarea v-model="conditions" rows="3" :required="Boolean(assessmentScope)"></textarea></label></details></fieldset><p v-if="!can('assess')" class="hint">Assessment editing is unavailable for this context.</p><div v-else class="knowledge-actions"><button type="button" :disabled="busy || !!pendingRequest || !!pendingScore || !canEditAssessment" @click="mutate('draft')">Save draft</button><button class="primary" :disabled="busy || !!pendingRequest || !!pendingScore || !canEditAssessment || !rationale.trim() || (assessmentScope && !conditions.trim()) || (applicability === 'not_affected' && !justification)">Submit assessment</button><button type="button" :disabled="busy || !!pendingRequest || !!pendingScore || !canEditAssessment || !rationale.trim() || (assessmentScope && !conditions.trim()) || (applicability === 'not_affected' && !justification)" @click="mutate('submit', true)">Submit and next</button></div><p class="hint">Next: independent team review. A security coordinator rescores only after all required contexts of this vulnerability are approved.</p></form>
          <div v-if="tab === 'review'" class="knowledge-pane" aria-label="Independent assessment review"><template v-if="assessment"><h3>{{ label(assessment.payload.state) }}</h3><p v-if="assessment.payload.justification">{{ justificationLabel(assessment.payload.justification) }}</p><p class="knowledge-rationale">{{ assessment.payload.rationale }}</p><p v-if="assessment.payload.conditions" class="knowledge-rationale">Conditions: {{ assessment.payload.conditions }}</p><details v-if="selected.ssvc?.current"><summary>SSVC · {{ selected.ssvc.current.outcome_label || 'Incomplete' }} · {{ label(selected.ssvc.status) }}</summary><p>{{ selected.ssvc.current.selection.rationale }}</p><pre>{{ JSON.stringify(selected.ssvc.current, null, 2) }}</pre></details><details v-if="selected.ssvc?.approved"><summary>Approved SSVC · {{ selected.ssvc.approved.outcome_label || 'Incomplete' }}</summary><p>{{ selected.ssvc.approved.selection.rationale }}</p><pre>{{ JSON.stringify(selected.ssvc.approved, null, 2) }}</pre></details><small>{{ label(assessment.stage) }} · Author {{ assessment.payload.author_id || 'Unknown' }}</small><details><summary>Assessment scope and evidence</summary><pre>{{ JSON.stringify({ targets: assessment.payload.targets, evidence: assessment.payload.evidence }, null, 2) }}</pre></details><template v-if="can('approve')"><label>Review rationale<textarea v-model="reviewRationale" :disabled="busy || !!pendingRequest || !!pendingScore" rows="3" placeholder="Explain approval or requested changes."></textarea></label><label class="knowledge-confirm"><input v-model="confirmed" type="checkbox" :disabled="busy || !!pendingRequest || !!pendingScore">I checked the evidence, applicability and context of this assessment.</label><div class="knowledge-actions"><button :disabled="busy || !!pendingRequest || !!pendingScore || !confirmed || !reviewRationale.trim()" @click="mutate('request_changes')">Request changes</button><button class="primary" :disabled="busy || !!pendingRequest || !!pendingScore || !confirmed || !reviewRationale.trim()" @click="mutate('approve')">Approve assessment</button><button :disabled="busy || !!pendingRequest || !!pendingScore || !confirmed || !reviewRationale.trim()" @click="mutate('approve', true)">Approve and next</button><button :disabled="busy || !!pendingRequest || !!pendingScore || !confirmed || !reviewRationale.trim()" @click="mutate('request_changes', true)">Request changes and next</button></div></template><p v-else class="hint">Independent review actions are unavailable for this assessment.</p></template><p v-else>No assessment recorded for this context.</p><details v-if="selected.coverage.approved_assessment"><summary>Retained approved assessment</summary><p>{{ selected.coverage.approved_assessment.payload.rationale }}</p></details></div>
          <form v-if="tab === 'scoring' && can('rescore')" class="knowledge-pane" aria-label="Coordinator rescoring" @submit.prevent="previewScore">
            <p class="hint">Publication requires current independent reviews for every required context of this vulnerability.</p>
            <fieldset :disabled="busy || !!pendingScore || !!pendingRequest">
              <label>Source Base vector<select v-model="scoreBase" :disabled="!sourceVectors.length" @change="scoreVector = scoreBase"><option v-if="!sourceVectors.length" value="">No source vector available</option><option v-for="vector in sourceVectors" :key="vector" :value="vector">{{ vector }}</option></select></label>
              <label>Proposal method<select v-model="scoreMode"><option value="manual">Verified contextual metrics</option><option value="applicability">Rules from approved applicability</option><option value="false_positive">Rules from approved false positive</option></select></label>
              <p v-if="scoreMode !== 'manual'" class="hint">The server derives applicability from approved team assessments and pins the current project rules. Preview shows the proposed result before publication.</p>
              <CvssContextEditor v-model="scoreVector" :base-vector="scoreBase" :disabled="busy || !!pendingScore || !!pendingRequest" />
              <label>Scoring rationale<textarea v-model="scoreRationale" rows="3" required placeholder="Explain the contextual metrics and supporting evidence."></textarea></label>
            </fieldset>
            <p v-if="!sourceVectors.length" class="hint">A source Base vector is required before a contextual score can be proposed.</p>
            <section v-if="scorePreview" class="knowledge-score-preview" aria-label="Scoring preview">
              <div class="knowledge-score-pair"><span>Original <strong>{{ scorePreview.result.proposal.base_score.toFixed(1) }}</strong></span><span>Published <strong>{{ selected.published_score?.score.toFixed(1) ?? '—' }}</strong><small v-if="selected.published_score?.current === false"> · Outdated</small></span><span>Proposed <strong>{{ scorePreview.result.proposal.score.toFixed(1) }}</strong></span></div>
              <p v-if="scorePreview.result.eligible" role="status">Preview ready. Required reviews are current.</p>
              <template v-else><p role="status">Waiting for required team reviews or unresolved component ownership.</p><ul><li v-for="(block, index) in scorePreview.result.blocked" :key="index">{{ block.version }} · {{ block.vulnerability_id }}<ul v-if="block.missing?.length"><li v-for="missing in block.missing" :key="missing.context_id">{{ missing.context_id }} · {{ label(missing.status || 'review required') }}</li></ul><span v-if="block.unresolved_components?.length"> · {{ block.unresolved_components.length }} unresolved components</span></li></ul><details><summary>Review gate details</summary><pre>{{ JSON.stringify(scorePreview.result.blocked, null, 2) }}</pre></details></template>
            </section>
            <details v-if="scorePreview && (scorePreview.result as any).provenance"><summary>Rule policy and approved assessment provenance</summary><pre>{{ JSON.stringify((scorePreview.result as any).provenance, null, 2) }}</pre></details>
            <div class="knowledge-actions"><button :disabled="busy || !!pendingScore || !!pendingRequest || !scoreBase || !scoreVector || !scoreRationale.trim()">Preview contextual score</button><button type="button" class="primary" :disabled="busy || !!pendingScore || !!pendingRequest || !scorePreview?.result.eligible" @click="publishScore()">Publish contextual score</button></div>
          </form>
          </div></div>
          <CvssVectorComparison v-show="detailTask === 'workflow'" :key="`${project}:${version}:${selected.id}`" :entries="vectorEntries" />
          <section v-show="detailTask === 'tools'" class="finding-task" data-finding-task="tools" aria-label="Analysis tools"><h3 tabindex="-1">Analysis tools</h3><p class="hint">Prepare inputs and manage analysis jobs. Their results appear under Vulnerability analyses.</p>
          <KnowledgeSpecialists :key="`${me.id}:${project}:${version}:${selected.context_id}:${selected.vulnerability_id}`" :project="project" :state="workspace.state" :version="version" :finding="selected" @locked="analysisFollowUpLocked = $event" />
          </section>
          <section v-show="detailTask === 'component'" class="finding-task" data-finding-task="component" aria-label="Component and CPE details"><h3 tabindex="-1">Component &amp; CPE details</h3><p class="hint">Component identity, candidate identifiers and authored annotations. Candidates require explicit acceptance.</p>
          <KnowledgeCpeIdentification :key="`${me.id}:${project}:${selected.context.component_ref}`" :project="project" :state="workspace.state" :component-ref="String(selected.context.component_ref || (selected.component as { 'bom-ref'?: string })['bom-ref'] || '')" :records="selected.contributions?.cpe" />
          <KnowledgeComponentMetadata :key="`${me.id}:${project}:${version}:${selected.context.component_ref}`" :project="project" :state="workspace.state" :version="version" :component-ref="String(selected.context.component_ref || '')" :context-id="selected.context_id" :disabled="busy || bulkLocked || !!pendingRequest || !!pendingScore" @locked="metadataLocked = $event" @changed="metadataChanged" @refresh="metadataChanged" />
          </section>
          <section v-show="detailTask === 'technical'" class="finding-task" data-finding-task="technical" aria-label="Technical provenance"><h3 tabindex="-1">Technical provenance &amp; imported history</h3>
          <details v-if="selected.legacy_evidence?.length" class="knowledge-pane"><summary>Imported DT assessment history</summary><p class="hint">Historical team and author labels are source claims. These records do not establish current DTVP approval.</p><article v-for="claim in selected.legacy_evidence" :key="claim.id"><h3>{{ claim.source }} · {{ label(claim.status) }}</h3><p v-if="claim.conflicting" class="warning">Conflicting imported team conclusions require reconciliation.</p><div v-for="(record, index) in claim.current_records" :key="index"><strong>{{ record.team }} · {{ label(record.state || 'unknown') }}</strong><p>{{ record.rationale }}</p><p v-if="record.justification">{{ justificationLabel(record.justification) }}</p><small>Historical assessor: {{ record.assessor || 'Unknown' }} · reviewer: {{ record.reviewer || 'Unknown' }}</small></div><p v-if="!claim.current_records.length">{{ claim.raw_text || claim.raw_excerpt || 'No interpretable assessment text.' }}</p><ul v-if="claim.errors.length"><li v-for="issue in claim.errors" :key="issue">{{ issue }}</li></ul><details><summary>Complete imported history, comments and score claims</summary><pre>{{ JSON.stringify(claim, null, 2) }}</pre></details></article></details>          <div class="knowledge-pane"><details><summary>Source ratings and vectors</summary><ul><li v-for="(rating, index) in selected.source_ratings" :key="index">{{ ratingSource(rating) }} · {{ rating.method || 'Unspecified method' }} · {{ rating.score ?? 'Unknown score' }}<code>{{ rating.vector }}</code></li></ul></details><details><summary>Dependency and ownership evidence</summary><pre>{{ JSON.stringify(selected.context, null, 2) }}</pre></details><details v-if="selected.supplemental_component_evidence?.length"><summary>Supplemental component evidence ({{ selected.supplemental_component_evidence.length }})</summary><pre>{{ JSON.stringify(selected.supplemental_component_evidence, null, 2) }}</pre></details><details><summary>Raw source and analysis records</summary><pre>{{ JSON.stringify({ sourcefacts: selected.sourcefacts || [], code_analysis: selected.code_analysis || [], scoring_proposals: selected.scoring_proposals || [] }, null, 2) }}</pre></details><details><summary>Additional evidence</summary><pre>{{ JSON.stringify(selected.evidence || [], null, 2) }}</pre></details></div>          </section>
          <nav class="record-utilities" aria-label="Finding details"><button :aria-pressed="detailTask === 'tools'" :disabled="busy || metadataLocked || analysisFollowUpLocked" @click="showDetailTask('tools')">Analysis tools</button><button :aria-pressed="detailTask === 'component'" :disabled="busy || metadataLocked || analysisFollowUpLocked" @click="showDetailTask('component')">Component &amp; CPE details</button><button :aria-pressed="detailTask === 'technical'" :disabled="busy || metadataLocked || analysisFollowUpLocked" @click="showDetailTask('technical')">Technical provenance</button></nav>
          <footer class="knowledge-pagination"><button :disabled="busy || selectedIndex <= 0" @click="open(workspace.items[selectedIndex - 1]!)">Previous finding</button><button :disabled="busy || selectedIndex < 0 || selectedIndex >= workspace.items.length - 1" @click="open(workspace.items[selectedIndex + 1]!)">Next finding</button></footer>
        </section>
      </div><details class="knowledge-state"><summary>State reference</summary><code>{{ workspace.state }}</code></details>
    </template>

    <div class="workspace-tool-menu" aria-label="Workspace tools">
      <details data-tool-group="composition" class="workspace-tool-group" ref="compositionTools"><summary>Sources & teams</summary><div class="knowledge-tools">
        <KnowledgeCreateProduct :key="me.id" :actor="me.id" :teams="me.workspaces" :disabled="busy || otherIntakeLocked || pipelineConfigurationLocked || syncAutomationLocked || observationsLocked || bulkLocked || !!pendingRequest || !!pendingScore" @locked="productCreationLocked = $event" @created="onProductCreated" />
        <KnowledgeAssembly :key="`${me.id}:${project}`" :project="project" :version="version" :disabled="productCreationLocked || intakeBusy || pipelineConfigurationLocked || syncAutomationLocked || observationsLocked" @locked="assemblyLocked = $event" @assembled="onCompositionImported" />
        <KnowledgeIntake :key="`${me.id}:${project}`" :project="project" :version="version" :disabled="productCreationLocked || assemblyLocked || pipelineConfigurationLocked || syncAutomationLocked || observationsLocked" @locked="intakeBusy = $event" @imported="onCompositionImported" />
        <template v-if="workspace"><KnowledgeReconciliation :key="`${me.id}:${project}`" :project="project" :version="version" :state="workspace.state" @locked="correspondenceLocked = $event" @changed="load(true, true)" /></template>
        <KnowledgeOwnership v-if="project" :key="`${me.id}:${project}`" :project="project" @changed="load(true, true)" />
        <KnowledgePipelineConfiguration class="knowledge-tool-group" v-if="project" :key="`${me.id}:${project}`" :project="project" :actor="me.id" :state="workspace?.state || ''" :disabled="busy || baseIntakeLocked || syncAutomationLocked || observationsLocked || bulkLocked || !!pendingRequest || !!pendingScore" @locked="pipelineConfigurationLocked = $event" @refresh="load(true, true)" />
        <KnowledgeObservations v-if="project && version && workspace?.state" :key="`${me.id}:${project}:${version}`" :project="project" :version="version" :state="workspace.state" :actor="me.id" :disabled="busy || baseIntakeLocked || pipelineConfigurationLocked || syncAutomationLocked || bulkLocked || !!pendingRequest || !!pendingScore" @locked="observationsLocked = $event" @refresh="load(true, true)" />
        <template v-if="workspace"><KnowledgeSources :project="project" :version="version" :state="workspace.state" /></template>
        <template v-if="workspace"><KnowledgeInputQuality :key="`${me.id}:${project}`" :project="project" :state="workspace.state" /></template>
      </div></details>
      <details v-if="project" data-tool-group="intelligence" class="workspace-tool-group" ref="intelligenceTools"><summary>Evidence & integrations</summary><div class="knowledge-tools">
        <KnowledgeScoringPolicy v-if="project" :editable="projectCapabilities.includes('manage')" :key="`${me.id}:${project}`" :project="project" :actor="me.id" :disabled="busy || productCreationLocked || intakeBusy || assemblyLocked || metadataLocked || licenseLocked || archiveLocked || correspondenceLocked || analysisFollowUpLocked || cpeLocked || advisoryLocked || pipelineConfigurationLocked || syncAutomationLocked || observationsLocked || bulkLocked || !!pendingScore || !!pendingRequest" @locked="scoringPolicyLocked = $event" />
        <KnowledgeCpePolicy v-if="project" :key="`${me.id}:${project}`" :project="project" @locked="cpeLocked = $event" />
        <KnowledgeEvidenceSources v-if="project" :key="`${me.id}:${project}`" :project="project" :state="workspace?.state || ''" @changed="load(true, true)" />
        <KnowledgeSyncAutomation class="knowledge-tool-group" v-if="project" :key="`${me.id}:${project}`" :project="project" :actor="me.id" :disabled="busy || baseIntakeLocked || pipelineConfigurationLocked || observationsLocked || bulkLocked || !!pendingRequest || !!pendingScore" @locked="syncAutomationLocked = $event" @refresh="load(true, true)" />
        <template v-if="workspace"><KnowledgeAdvisories :key="`${me.id}:${project}`" :project="project" :state="workspace.state" @locked="advisoryLocked = $event" /></template>
      </div></details>
      <details data-tool-group="reports" class="workspace-tool-group" ref="reportTools"><summary>Reports, licensing & history</summary>
    <details class="knowledge-views"><summary>Saved views and sharing</summary><div class="knowledge-actions"><label>View name<input v-model="viewName" maxlength="100" placeholder="Save the applied scope"></label><button :disabled="busy || !project || !viewName.trim()" @click="saveView">Save view</button><button :disabled="busy || !project" @click="copyView">Copy view link</button></div><ul v-if="savedViews.length"><li v-for="view in savedViews" :key="view.name"><button :disabled="busy || intakeLocked" @click="restoreView(view.query)">{{ view.name }}</button><button :disabled="busy" :aria-label="`Remove view ${view.name}`" @click="removeView(view.name)">×</button></li></ul></details>
<div class="knowledge-tools">
        <KnowledgeComparison :project="project" />
        <KnowledgeAssessmentArchive v-if="project" :key="`${me.id}:${project}`" :project="project" :disabled="busy || productCreationLocked || intakeBusy || assemblyLocked || metadataLocked || licenseLocked" @locked="archiveLocked = $event" @changed="load(true, true)" />
        <template v-if="workspace"><KnowledgeComponents :key="`${me.id}:${project}`" :project="project" :state="workspace.state" :disabled="busy || bulkLocked || !!pendingRequest || !!pendingScore" @locked="metadataLocked = $event" @changed="metadataChanged" /></template>
        <template v-if="workspace"><KnowledgeRetained v-if="workspace.statistics.retained_absent_assessments" :project="project" :state="workspace.state" :team="team" /></template>
        <template v-if="workspace"><KnowledgeLicenses :key="me.id" :project="project" :version="version" :state="workspace.state" @locked="licenseLocked = $event" @changed="load(true, true)" /></template>
        <template v-if="workspace"><KnowledgePortfolio :project="project" :version="version" :state="workspace.state" :filters="filters" :q="query" :lifecycle="lifecycle" :team="team" /></template>
        <template v-if="workspace"><KnowledgeDocuments :project="project" :version="version" :state="workspace.state" @changed="load(true, true)" /></template>
        <KnowledgeOrganizationPortfolio :key="me.id" :filters="filters" :q="query" :lifecycle="lifecycle" :team="team" />
      </div></details>
    </div>
  </section>
</template>
<style scoped>
/* Existing panels stay mounted; only their direct disclosure roots join the toolbar. */
.knowledge-tools { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,210px),1fr)); align-items:start; gap:8px; margin:12px 0; min-width:0 }
.knowledge-tools:empty { display:none }
.knowledge-tools > :deep(.knowledge-tool-group) { display:contents }
.knowledge-composition-tools { display:grid; gap:8px; min-width:0 }
.knowledge-composition-tools:has(> details[open]) { grid-column:1 / -1 }
.knowledge-composition-tools > :deep(details) { margin:0; min-width:0; background:var(--surface) }
.knowledge-workspace .knowledge-tools > :deep(details), .knowledge-workspace .knowledge-tools > :deep(.knowledge-tool-group > details) { margin:0; min-width:0; padding:8px 12px; border:1px solid var(--line); border-radius:8px; background:var(--surface) }
.knowledge-workspace .knowledge-tools > :deep(details[open]), .knowledge-workspace .knowledge-tools > :deep(.knowledge-tool-group > details[open]) { grid-column:1 / -1; padding:10px 12px }
.knowledge-workspace .knowledge-tools > :deep(details > summary), .knowledge-workspace .knowledge-tools > :deep(.knowledge-tool-group > details > summary) { font-size:.82rem; line-height:1.4; overflow-wrap:anywhere; cursor:pointer }
@media(max-width:550px) { .knowledge-tools { grid-template-columns:minmax(0,1fr) } }

.knowledge-advanced,.knowledge-views { margin:12px 0; font-size:.85rem }.knowledge-filter-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:10px 14px; margin-top:12px }.knowledge-advanced fieldset { border:0; margin:0; padding:0; min-width:0 }.knowledge-views ul { list-style:none; padding:0; display:flex; gap:8px; flex-wrap:wrap }.knowledge-views li { display:flex; gap:4px }.knowledge-views .knowledge-actions { justify-content:flex-start }.knowledge-views label { margin:8px 0 0; min-width:160px }
.knowledge-heading,.knowledge-detail header,.knowledge-pagination,.knowledge-actions,.knowledge-score-pair,.knowledge-statistics { display:flex; align-items:center; gap:12px; flex-wrap:wrap }.knowledge-heading { justify-content:space-between; margin-bottom:16px }.knowledge-heading h1 { margin:0 }.knowledge-heading p { margin:4px 0 }.knowledge-filters { display:grid; grid-template-columns:minmax(160px,1.2fr) minmax(100px,.65fr) minmax(140px,1fr) minmax(140px,1fr) minmax(180px,1.5fr); gap:12px; align-items:end }.knowledge-filters label { margin:0 }.knowledge-statistics { margin:16px 0; font-size:.85rem; border-block:1px solid var(--line); padding:12px 0 }.knowledge-statistics details { margin-left:auto }.knowledge-statistics dl { position:absolute; z-index:2; background:var(--surface); padding:16px; border:1px solid var(--line); box-shadow:var(--shadow); right:24px; min-width:220px }.knowledge-columns { display:grid; gap:20px }.knowledge-queue,.knowledge-detail { min-width:0 }.knowledge-queue small { display:block; color:var(--muted); margin-top:4px }.knowledge-queue .selected { background:var(--accent-soft) }.knowledge-queue th { font-size:.8rem; white-space:nowrap }.knowledge-queue td { font-size:.85rem; vertical-align:top }.knowledge-detail { background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:18px; align-self:start }.knowledge-detail header { justify-content:space-between; align-items:flex-start }.knowledge-detail h2 { margin:0; font-size:1.15rem }.knowledge-detail header p { margin:4px 0 }.knowledge-detail h3 { font-size:1rem }.knowledge-detail > .hint { margin:8px 0 }.knowledge-score-pair { font-size:.8rem; gap:22px; padding:10px 0 }.knowledge-tabs { display:flex; gap:6px; border-bottom:1px solid var(--line); padding-bottom:8px }.knowledge-tabs button { border:0; padding:5px 10px; text-transform:capitalize }.knowledge-tabs button[aria-pressed=true] { background:var(--accent-soft); color:var(--accent) }.knowledge-pane { padding-top:12px }.knowledge-pane fieldset { border:0; padding:0; margin:0; min-width:0 }.knowledge-pane details { margin:12px 0 }.knowledge-pane dl,.knowledge-statistics dl { display:grid; grid-template-columns:auto 1fr; gap:6px 12px; font-size:.8rem }.knowledge-pane dd,.knowledge-statistics dd { margin:0; overflow-wrap:anywhere }.knowledge-pane dt { color:var(--muted) }.knowledge-overview h3{font-size:.84rem;margin:0 0 5px}.knowledge-overview .knowledge-description{margin-bottom:8px;max-height:26vh}.knowledge-description { white-space:pre-wrap; overflow-wrap:anywhere; max-height:38vh; overflow:auto; line-height:1.6; font-size:.9rem; margin-top:0 }.knowledge-rationale { white-space:pre-wrap; overflow-wrap:anywhere; line-height:1.6 }.knowledge-pane pre { white-space:pre-wrap; overflow-wrap:anywhere; max-height:300px; overflow:auto; font-size:.75rem; background:var(--bg); padding:10px }.knowledge-pane code { display:block; overflow-wrap:anywhere; font-size:.75rem }.knowledge-confirm { display:flex; align-items:flex-start; gap:8px; font-size:.85rem }.knowledge-confirm input { width:auto; margin-top:3px }.knowledge-actions { justify-content:flex-end; margin-top:12px }.knowledge-pagination { justify-content:space-between; margin-top:12px; font-size:.8rem }.knowledge-state { margin-top:16px; font-size:.75rem; color:var(--muted) }.knowledge-state code { overflow-wrap:anywhere }
@media(max-width:1100px) { .knowledge-filters { grid-template-columns:repeat(2,minmax(0,1fr)) }.knowledge-search { grid-column:1/-1 }.knowledge-columns.has-detail { grid-template-columns:1fr } }@media(max-width:550px) { .knowledge-filters { grid-template-columns:1fr }.knowledge-statistics { gap:8px 16px }.knowledge-detail { padding:12px }.knowledge-queue th,.knowledge-queue td { padding:8px 5px } }


.finding-back{display:inline-flex;margin-bottom:10px}.assessment-task-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:20px;align-items:start}.assessment-task-layout>*{min-width:0}.assessment-task-evidence{border-right:1px solid var(--line);padding-right:20px}.assessment-task-evidence .knowledge-description{max-height:240px;font-size:.9rem}.assessment-task-evidence>h3,.assessment-editor>h3{font-size:1rem;margin:0 0 10px}.assessment-citations{margin:14px 0!important}.assessment-citations legend{font-size:.9rem;font-weight:600}.assessment-citations label{margin:7px 0;font-size:.85rem}.assessment-version,.draft-indicator{padding:8px;background:var(--accent-soft);border-radius:4px;font-size:.85rem}.assessment-editor .knowledge-actions{position:static;background:var(--surface);padding:10px 0;z-index:2;border-top:1px solid var(--line)}.knowledge-tabs{flex-wrap:wrap}.knowledge-tabs button{font-size:.9rem}.assessment-task-decision .knowledge-pane{padding-top:0}
@media(max-width:1100px){.finding-open .knowledge-queue{display:none}.finding-open .finding-back{display:inline-flex}.finding-open>.knowledge-filters,.finding-open>.knowledge-advanced{display:none}}
@container finding (max-width:820px){.assessment-task-layout{grid-template-columns:minmax(0,1fr)}.assessment-task-evidence{padding-right:0;border-right:0;padding-bottom:12px;border-bottom:1px solid var(--line)}}

.knowledge-workspace{min-width:0}.knowledge-heading{margin-bottom:10px;gap:8px;padding:0;min-height:0;background:none;border:0}.knowledge-heading h1{font-size:1.3rem}.knowledge-heading p{font-size:.78rem}.knowledge-filters{gap:8px;padding:10px;border:1px solid var(--line);background:var(--surface);border-radius:6px}.knowledge-statistics{margin:10px 0;padding:8px 0;gap:8px 18px}.knowledge-queue .table-wrap{margin-bottom:6px}.knowledge-queue td,.knowledge-queue th{padding:8px 10px}.knowledge-queue small{margin-top:2px}.knowledge-pagination{margin-top:6px}.workspace-tool-menu{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px;align-items:start}.workspace-tool-group{flex:1 1 210px;margin:0;border:1px solid var(--line);border-radius:6px;background:var(--surface);padding:8px 10px;min-width:0}.workspace-tool-group>summary{font-size:.8rem;margin:0}.workspace-tool-group[open]{flex-basis:100%}.workspace-tool-group[open]>summary{margin-bottom:10px}.knowledge-advanced{margin:8px 0}.knowledge-advanced summary{font-size:.8rem}.knowledge-advanced-grid{gap:8px}.knowledge-detail{padding:12px}.knowledge-detail header{min-height:0;padding:0;border:0;background:none}.knowledge-columns{gap:12px}@media(max-width:550px){.knowledge-filters{grid-template-columns:repeat(2,minmax(0,1fr))}.knowledge-search{grid-column:1/-1}.workspace-tool-menu{gap:6px}.workspace-tool-group{flex-basis:100%}}

/* Keep identifiers and comparison scores readable beside a wider reviewer workspace. */
.knowledge-columns.has-detail{grid-template-columns:minmax(290px,340px) minmax(0,1fr)}.review-queue-table{table-layout:fixed;width:100%}.queue-check{width:36px}.queue-team{width:112px}.queue-score{width:78px}.review-queue-table td{overflow-wrap:anywhere;word-break:normal}.review-queue-table th{white-space:normal;overflow-wrap:normal;word-break:normal}.review-queue-table .text-link{max-width:100%;white-space:normal;text-align:left;overflow-wrap:anywhere}.review-queue-table small{white-space:normal;overflow-wrap:anywhere}.review-queue-table td:nth-last-child(-n+2){font-variant-numeric:tabular-nums}.knowledge-detail{min-width:0}.knowledge-detail header>div{min-width:0;flex:1}.knowledge-detail header h2,.knowledge-detail header p{overflow-wrap:anywhere;white-space:normal}.knowledge-detail .knowledge-pane{min-width:0}@media(max-width:1100px){.knowledge-columns.has-detail{grid-template-columns:1fr}}@media(max-width:550px){.queue-team{width:85px}.queue-score{width:64px}.queue-check{width:28px}.review-queue-table th,.review-queue-table td{padding:7px 5px;font-size:.75rem}}


.knowledge-detail{container-type:inline-size;container-name:finding;padding:20px;overflow-wrap:anywhere}.finding-header{gap:12px;margin-bottom:16px}.finding-header h2{font-size:1.4rem}.finding-header-actions{display:flex;gap:8px;flex-wrap:wrap}.knowledge-detail header>.finding-header-actions{flex:0 1 auto}.finding-status{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:16px}.finding-status>div{border-left:3px solid var(--line);padding:4px 10px;min-width:0}.finding-status span{font-size:.8rem;color:var(--muted)}.finding-status strong{display:block;font-size:1rem;line-height:1.6;text-transform:capitalize}.finding-status small{font-size:.78rem}.finding-status .source-status{border-color:var(--source-accent)}.source-status.severity-critical strong{color:var(--danger)}.source-status.severity-high strong{color:var(--warning)}.finding-status .published-status{border-color:var(--accent)}.finding-status .status-approved{border-color:var(--positive)}.status-approved strong{color:var(--positive)}.finding-status .status-attention{border-color:var(--warning)}.status-attention strong{color:var(--warning)}.knowledge-tabs{padding-bottom:10px;margin-bottom:18px;gap:4px}.knowledge-tabs button{padding:7px 10px}.overview-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1fr);gap:24px}.overview-grid>*{min-width:0}.knowledge-overview{padding:0}.knowledge-overview h3,.usage-context h3{font-size:1rem;margin:0 0 10px}.knowledge-overview .knowledge-description{max-height:300px;font-size:1rem;line-height:1.65}.usage-context{padding-top:18px;border-top:1px solid var(--line);margin-top:18px}.usage-context h3 small{display:inline;font-weight:400}.usage-context dl{font-size:.9rem;line-height:1.5}.record-utilities{display:flex;flex-wrap:wrap;gap:8px;border-top:1px solid var(--line);padding-top:14px;margin-top:18px}.record-utilities button{color:var(--muted);font-size:.85rem}.record-utilities button[aria-pressed=true]{color:var(--accent);background:var(--accent-soft)}.finding-task{padding:4px 0 12px;min-width:0}.finding-task>h3{margin-top:0}.compact-queue{list-style:none;margin:0;padding:0}.compact-queue li{padding:12px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.compact-queue li:last-child{border:0}.compact-queue .text-link{text-align:left}.compact-queue input{float:right;width:auto;margin:3px}.compact-queue small{line-height:1.45;font-size:.85rem;margin:5px 0}.queue-ratings{display:flex;gap:12px;flex-wrap:wrap;font-size:.8rem;margin-top:8px;color:var(--muted)}.queue-ratings strong{color:var(--ink)}.knowledge-queue .knowledge-pagination{font-size:.8rem;gap:6px}.knowledge-queue .knowledge-pagination button{padding:5px 7px}.finding-task :deep(details){min-width:0}.finding-task :deep(input),.finding-task :deep(select){min-width:0;max-width:100%}
@container finding (max-width:820px){.overview-grid{grid-template-columns:minmax(0,1fr);gap:20px}.overview-inputs{border-top:1px solid var(--line);padding-top:12px}}
@container finding (max-width:500px){.finding-status{grid-template-columns:minmax(0,1fr);gap:10px}.finding-status>div{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);column-gap:8px}.finding-status small{grid-column:1/-1}.finding-status strong{font-size:.95rem}.knowledge-tabs button{font-size:.85rem}.assessment-task-evidence{padding-right:0}}
@media(max-width:550px){.knowledge-detail{padding:14px}.finding-header-actions{width:100%}.finding-header-actions .primary{flex:1}}
@media(min-width:1101px){.has-detail>.knowledge-queue{position:sticky;top:12px;align-self:start}.has-detail>.knowledge-queue .table-wrap{max-height:max(240px,calc(100dvh - 370px));overflow-y:auto;scrollbar-gutter:stable}}
</style>
