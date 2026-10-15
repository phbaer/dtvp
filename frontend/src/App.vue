<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { justificationLabel } from './assessmentReasons'
import { api, ApiError, send } from './api'
import SearchSelect from './components/SearchSelect.vue'
import KnowledgeWorkspace from './components/KnowledgeWorkspace.vue'
import ReviewWorkspace from './components/ReviewWorkspace.vue'
import StatisticsView from './components/StatisticsView.vue'
import RescorePolicyEditor from './components/RescorePolicyEditor.vue'
import type { AssessmentDraft, Component, Finding, Job, Me, Project, Release, RescoreRequest, Revision, Snapshot } from './types'

const me = ref<Me | null>(null)
const personas = ref<{ id: string; name: string }[]>([])
const page = ref(new URLSearchParams(location.search).get('page') || 'Review')
const projects = ref<Project[]>([])
const releases = ref<Release[]>([])
const projectId = ref('')
const releaseId = ref('')
const rows = ref<Finding[]>([])
const nextCursor = ref<string | null>(null)
const approvalSelection = ref<string[]>([])
type ApprovalItem = { finding_id: string; expected_version: number; decision_id: string }
const approvalPreview = ref<{ count: number; preview_digest: string; items: ApprovalItem[]; findings: Finding[] } | null>(null)
const canSelectApproval = (row: Finding) => row.capabilities.includes('approve') && row.review_lifecycle === 'ready' && Boolean(row.latest_decision) && row.latest_decision!.author_id !== me.value?.id
const hasApprovalAccess = computed(() => rows.value.some(row => row.capabilities.includes('approve')))
async function previewApprovals() {
  const findings = rows.value.filter(row => approvalSelection.value.includes(row.id))
  const items = findings.map(row => ({ finding_id: row.id, expected_version: row.state_version, decision_id: row.latest_decision!.id }))
  const result = await api<{ count: number; preview_digest: string }>('/approvals/preview', send({ items }))
  approvalPreview.value = { ...result, items, findings }
}
async function applyApprovals() {
  if (!approvalPreview.value) return
  await api('/approvals/apply', send({ items: approvalPreview.value.items, preview_digest: approvalPreview.value.preview_digest }))
  approvalPreview.value = null; approvalSelection.value = []; await loadFindings()
  notice.value = 'Selected decisions approved against their current evidence.'
}
const detail = ref<Finding | null>(null)
const components = ref<Component[]>([])
const componentCursor = ref<string | null>(null)
const revisions = ref<Revision[]>([])
const jobs = ref<Job[]>([])
const lifecycle = ref(new URLSearchParams(location.search).get('status') || '')
const url = new URLSearchParams(location.search)
const search = ref(url.get('q') || '')
const reviewProject = ref(url.get('project') || '')
const reviewProjectLabel = ref('')
const reviewTeam = ref(url.get('team') || '')
const reviewTeamLabel = ref('')
const ownerSearch = ref(url.get('owner') || '')
const ownerMatch = ref(url.get('owner_match') || 'contains')
const order = ref(url.get('sort') || 'identifier')
const productSearch = ref('')
const productTeam = ref('')
const catalog = ref<Project[]>([])
const catalogCursor = ref<string | null>(null)
const componentSearch = ref('')
const viewName = ref('')
const savedViews = ref<{ name: string; query: string }[]>([])
const queueAnchor = ref(-1)
const reviewIndex = computed(() => rows.value.findIndex(row => row.id === detail.value?.id))
function selectProject(option: { id: string }) {
  const project = option as Project
  if (!projects.value.some(p => p.id === project.id)) projects.value.push(project)
  void action(() => loadReleases())
}
async function loadCatalog(append = false) {
  const params = new URLSearchParams({ q: productSearch.value, workspace_id: productTeam.value })
  if (append && catalogCursor.value) params.set('cursor', catalogCursor.value)
  const result = await api<{ items: Project[]; next_cursor: string | null }>(`/catalog/projects?${params}`)
  catalog.value = append ? [...catalog.value, ...result.items] : result.items; catalogCursor.value = result.next_cursor
}
function filterParams() { return new URLSearchParams({ q: search.value, lifecycle: lifecycle.value, project_id: reviewProject.value, workspace_id: reviewTeam.value, owner: ownerSearch.value, owner_match: ownerMatch.value, sort: order.value }) }
function viewQuery() { return new URLSearchParams({ q: search.value, status: lifecycle.value, project: reviewProject.value, team: reviewTeam.value, owner: ownerSearch.value, owner_match: ownerMatch.value, sort: order.value }).toString() }
function updateUrl() { history.replaceState(null, '', `${location.pathname}?${viewQuery()}&page=${page.value}`) }
function resetReviewFilters() {
  search.value = ''; lifecycle.value = ''; reviewProject.value = ''; reviewProjectLabel.value = ''; reviewTeam.value = ''; reviewTeamLabel.value = ''; ownerSearch.value = ''; ownerMatch.value = 'contains'; order.value = 'identifier'
}
function applyView(query: string) {
  if (busy.value) return
  const params = new URLSearchParams(query)
  search.value = params.get('q') || ''; lifecycle.value = params.get('status') || ''; reviewProject.value = params.get('project') || ''; reviewProjectLabel.value = ''; reviewTeam.value = params.get('team') || ''; ownerSearch.value = params.get('owner') || ''; ownerMatch.value = params.get('owner_match') || 'contains'; order.value = params.get('sort') || 'identifier'
  void action(() => loadFindings())
}
function statisticsSlice(filters: Record<string, string>) {
  if (filters.project_id !== undefined) { reviewProject.value = filters.project_id; reviewProjectLabel.value = filters.project_name || '' }
  if (filters.workspace_id !== undefined) { reviewTeam.value = filters.workspace_id; reviewTeamLabel.value = filters.team_name || '' }
  if (filters.owner !== undefined) { ownerSearch.value = filters.owner; ownerMatch.value = filters.owner_match || 'contains' }
  if (filters.lifecycle !== undefined) lifecycle.value = filters.lifecycle
  page.value = 'Review'; void action(() => loadFindings())
}
async function copyView() { updateUrl(); await navigator.clipboard.writeText(location.href); notice.value = 'View link copied.' }
function saveView() {
  if (!viewName.value.trim() || !me.value) return
  savedViews.value = [...savedViews.value.filter(view => view.name !== viewName.value.trim()), { name: viewName.value.trim(), query: viewQuery() }].slice(-20)
  localStorage.setItem(`dtvp.views:${me.value.id}`, JSON.stringify(savedViews.value)); viewName.value = ''
}
function removeView(name: string) { savedViews.value = savedViews.value.filter(view => view.name !== name); localStorage.setItem(`dtvp.views:${me.value!.id}`, JSON.stringify(savedViews.value)) }
function restoreLocation() { const params = new URLSearchParams(location.search); page.value = ['Review', 'Knowledge', 'Statistics', 'Products', 'Activity', 'Access'].includes(params.get('page') || '') ? params.get('page')! : 'Review'; applyView(params.toString()) }
async function moveFinding(delta: number) {
  const target = reviewIndex.value >= 0 ? reviewIndex.value + delta : delta > 0 ? Math.min(queueAnchor.value, rows.value.length) : queueAnchor.value - 1
  if (target >= rows.value.length && nextCursor.value) await loadFindings(true)
  const row = rows.value[target]; if (row) await openFinding(row.id)
}
const draft = ref<AssessmentDraft>({ justification: null, state: 'under_investigation', rationale: '', rescoring: null })
const error = ref('')
const notice = ref('')
const busy = ref(false)
const power = ref(localStorage.getItem('dtvp.power') === 'true')
const theme = ref(localStorage.getItem('dtvp.theme') || 'system')
const latestSnapshot = ref<Snapshot | null>(null)
const newProjectName = ref('')
const newReleaseVersion = ref('')
const workspaceId = ref('')
const source = ref('file')
const provider = ref('osv')
const dtProjectId = ref('')
const analysisRepository = ref('')
const metadataEdit = ref<Component | null>(null)
const metadataText = ref('')
const metadataForm = ref<Record<string, string>>({})
const metadataFields: Record<string, string> = { owner: 'Responsible team', supplier: 'Supplier', repository: 'Repository', eol: 'End of support', license_clearance: 'License clearance', testing: 'Testing evidence', deployment_context: 'Deployment context' }
function editMetadata(component: Component) {
  rememberFocus()
  metadataEdit.value = component; metadataText.value = JSON.stringify(component.metadata, null, 2)
  metadataForm.value = Object.fromEntries(Object.keys(metadataFields).map(key => [key, typeof component.metadata[key] === 'string' ? component.metadata[key] : '']))
}
const tokenName = ref('Consumer')
const token = ref('')
const memberIssuer = ref('')
const memberSubject = ref('')
const memberName = ref('')
const memberRole = ref('analyst')
const shareWorkspace = ref('')
const sharedReadOnly = ref(true)
const workspaceName = ref('')
let poll: ReturnType<typeof setInterval> | undefined
let requestSequence = 0
let returnFocus: HTMLElement | null = null
let restorePending = false
const desktopMedia = window.matchMedia('(min-width: 1440px)')
const wideDesktop = ref(desktopMedia.matches)
const embeddedReview = computed(() => Boolean(detail.value && page.value === 'Review' && wideDesktop.value))
const showReviewFilters = ref(true)
let previousFilterVisibility = true
function desktopChanged(event: MediaQueryListEvent) { wideDesktop.value = event.matches }
watch(embeddedReview, embedded => {
  if (embedded) { previousFilterVisibility = showReviewFilters.value; showReviewFilters.value = false }
  else showReviewFilters.value = previousFilterVisibility
})
const modalOpen = computed(() => Boolean((detail.value && !embeddedReview.value) || metadataEdit.value))

function rememberFocus() {
  returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
}

function dialogKeys(event: KeyboardEvent) {
  if (!detail.value && !metadataEdit.value) return
  if (event.key === 'Escape') {
    event.preventDefault()
    if (!busy.value) { detail.value = null; metadataEdit.value = null }
  } else if (event.key === 'Tab' && modalOpen.value) {
    const controls = Array.from(document.querySelectorAll<HTMLElement>('[role="dialog"] button:not(:disabled), [role="dialog"] input:not(:disabled), [role="dialog"] select:not(:disabled), [role="dialog"] textarea:not(:disabled), [role="dialog"] a[href], [role="dialog"] summary')).filter(node => node.getClientRects().length)
    const first = controls[0], last = controls.at(-1)
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
  }
}

watch([modalOpen, busy], async ([open, pending], [wasOpen]) => {
  if (open !== wasOpen) {
    restorePending = !open
    document.body.style.overflow = open ? 'hidden' : ''
  }
  await nextTick()
  if (pending) return
  const dialog = document.querySelector<HTMLElement>('[role="dialog"]')
  if (open && !dialog?.contains(document.activeElement)) dialog?.querySelector<HTMLElement>('button:not(:disabled)')?.focus()
  else if (!open && restorePending) { if (returnFocus?.isConnected) returnFocus.focus(); restorePending = false }
})

const selectedProject = computed(() => projects.value.find(p => p.id === projectId.value))
const canWrite = computed(() => selectedProject.value?.capabilities.includes('write'))
const canManage = computed(() => selectedProject.value?.capabilities.includes('manage'))
const latestDecision = computed(() => detail.value?.latest_decision)
const canApprove = computed(() => detail.value?.capabilities.includes('approve') && detail.value.review_lifecycle === 'ready' && latestDecision.value?.author_id !== me.value?.id)
const access = computed(() => me.value?.org_admin || me.value?.workspaces.some(w => w.capabilities.includes('manage')))
const draftKey = computed(() => `dtvp.draft:${me.value?.id}:${detail.value?.id}:${detail.value?.review_workspace_id}`)
const names: Record<string, string> = { open: 'Needs analysis', ready: 'Ready for approval', approved: 'Approved', needs_revalidation: 'Evidence changed', changes_requested: 'Changes requested', legacy_assessed: 'Legacy assessment', legacy_pending: 'Legacy review pending', legacy_conflicting: 'Legacy conflict', legacy_documented: 'Legacy documentation' }
const label = (value: string) => names[value] || value.replaceAll('_', ' ')
const score = (value: number | null) => value === null ? 'Unknown' : value.toFixed(1)

async function action(callback: () => Promise<unknown>) {
  if (busy.value) return
  busy.value = true; error.value = ''; notice.value = ''
  try { await callback() }
  catch (err) {
    error.value = err instanceof Error ? err.message : 'Request failed'
    if (err instanceof ApiError && err.status === 401) me.value = null
  }
  finally { busy.value = false }
}

async function loadProjects() {
  projects.value = (await api<{ items: Project[] }>('/catalog/projects')).items
  await loadCatalog()
  if (reviewProject.value) reviewProjectLabel.value = (await api<Project>(`/projects/${reviewProject.value}`)).name
  if (!projects.value.some(p => p.id === projectId.value)) projectId.value = projects.value[0]?.id || ''
  workspaceId.value ||= me.value?.workspaces[0]?.id || ''
  await loadReleases()
}

async function loadReleases() {
  releases.value = projectId.value ? (await api<{ items: Release[] }>(`/catalog/projects/${projectId.value}/releases`)).items : []
  if (!releases.value.some(r => r.id === releaseId.value)) releaseId.value = releases.value[0]?.id || ''
  latestSnapshot.value = null
  await loadInventory()
}

async function loadInventory(append = false) {
  if (!releaseId.value) { components.value = []; revisions.value = []; return }
  const result = await api<{ items: Component[]; next_cursor: string | null }>(`/releases/${releaseId.value}/components?cursor=${append ? componentCursor.value || '' : ''}&q=${encodeURIComponent(componentSearch.value)}`)
  components.value = append ? [...components.value, ...result.items] : result.items
  componentCursor.value = result.next_cursor
  revisions.value = await api(`/releases/${releaseId.value}/revisions`)
}

async function loadFindings(append = false) {
  const sequence = ++requestSequence
  const params = filterParams()
  if (reviewProject.value && !reviewProjectLabel.value) {
    const project = await api<Project>(`/projects/${reviewProject.value}`)
    if (sequence !== requestSequence) return
    reviewProjectLabel.value = project.name
  }
  updateUrl()
  if (append && nextCursor.value) params.set('cursor', nextCursor.value)
  const result = await api<{ items: Finding[]; next_cursor: string | null }>(`/findings?${params}`)
  if (sequence !== requestSequence) return
  if (!append) { approvalSelection.value = []; approvalPreview.value = null }
  rows.value = append ? [...rows.value, ...result.items] : result.items
  nextCursor.value = result.next_cursor
}

async function openFinding(id: string, keepDraft = false, workspace = '') {
  if (!detail.value) rememberFocus()
  const position = rows.value.findIndex(row => row.id === id)
  if (position >= 0 || !keepDraft) queueAnchor.value = position
  detail.value = await api(`/findings/${id}${workspace || (keepDraft && detail.value?.review_workspace_id) ? `?workspace_id=${encodeURIComponent(workspace || detail.value!.review_workspace_id!)}` : ''}`)
  if (!keepDraft) {
    const saved = sessionStorage.getItem(draftKey.value)
    const prior = latestDecision.value?.details.rescoring
    const rescoring: RescoreRequest | null = prior ? { kind: prior.kind as RescoreRequest['kind'], base_vector: prior.base_vector, vector: prior.vector, evidence_id: prior.evidence_id, policy_digest: prior.policy_digest || '', preview_digest: '', rule_basis: prior.rule_basis || 'applicability', rationale: prior.rationale } : null
    const justification = latestDecision.value?.details.justification || detail.value!.imported_assessments?.[0]?.current_records[0]?.justification?.toLowerCase() || null
    draft.value = saved ? { justification: null, rescoring: null, ...JSON.parse(saved) } : { justification, rescoring, state: latestDecision.value?.state || detail.value!.imported_assessments?.[0]?.state || 'under_investigation', rationale: latestDecision.value?.rationale || detail.value!.imported_assessments?.[0]?.current_records.map(record => record.rationale).filter(Boolean).join('\n\n') || '' }
  }
}

async function login(persona: string) {
  await action(async () => {
    await api('/playground/login', send({ persona }))
    if (me.value) resetReviewFilters()
    me.value = await api('/me'); detail.value = null; token.value = ''; workspaceId.value = ''; provider.value = me.value!.playground ? 'demo' : 'osv'
    rows.value = []; projects.value = []; releases.value = []; components.value = []; revisions.value = []; jobs.value = []; approvalSelection.value = []; approvalPreview.value = null; latestSnapshot.value = null; metadataEdit.value = null
    await loadProjects(); await loadFindings()
  })
}

async function submit(advance = false) {
  if (!detail.value) return
  await action(async () => {
    await api(`/findings/${detail.value!.id}/decisions`, send({ state: draft.value.state, rationale: draft.value.rationale, justification: draft.value.justification, workspace_id: detail.value!.review_workspace_id, expected_version: detail.value!.state_version }))
    sessionStorage.removeItem(draftKey.value)
    await openFinding(detail.value!.id, true); await loadFindings()
    notice.value = 'Decision saved. A different reviewer can approve it.'
    if (advance) await moveFinding(1)
  })
}

async function approve(requestChanges = false, advance = false) {
  await action(async () => {
    await api(`/findings/${detail.value!.id}/approvals`, send({ expected_version: detail.value!.state_version, decision_id: latestDecision.value!.id, action: requestChanges ? 'request_changes' : 'approve' }))
    await openFinding(detail.value!.id, true); await loadFindings()
    notice.value = requestChanges ? 'Changes requested.' : 'Decision approved against the current evidence.'
    if (advance) await moveFinding(1)
  })
}

async function upload(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file || !releaseId.value) return
  await action(async () => {
    const form = new FormData(); form.set('file', file); form.set('source', source.value)
    await api(`/releases/${releaseId.value}/uploads`, { method: 'POST', body: form })
    await loadInventory(); await loadFindings(); notice.value = 'SBOM imported. Existing decisions and metadata retained.'
    input.value = ''
  })
}

async function snapshot() {
  await action(async () => { latestSnapshot.value = await api('/snapshots', send({ release_id: releaseId.value })) })
}

async function queue(kind: string) {
  await action(async () => {
    await api('/jobs', send({ kind, release_id: releaseId.value, ...(kind === 'import-dt' ? { external_project_id: dtProjectId.value } : { provider: provider.value }) }))
    jobs.value = await api('/jobs'); notice.value = 'Job queued. Progress is available in Activity.'
  })
}

async function replay(scenario: string) {
  await action(async () => {
    await api(`/playground/replay/${scenario}`, send({})); await loadInventory(); await loadFindings()
    if (detail.value) await openFinding(detail.value.id, true)
    notice.value = 'Pipeline event replayed.'
  })
}

watch(() => me.value?.id, id => { try { savedViews.value = id ? JSON.parse(localStorage.getItem(`dtvp.views:${id}`) || '[]') : [] } catch { savedViews.value = [] } })
watch(approvalSelection, () => { approvalPreview.value = null }, { deep: true })
watch(draft, value => { if (detail.value && me.value) sessionStorage.setItem(draftKey.value, JSON.stringify(value)) }, { deep: true })
watch(power, value => localStorage.setItem('dtvp.power', String(value)))
watch(theme, value => { localStorage.setItem('dtvp.theme', value); document.documentElement.dataset.theme = value }, { immediate: true })
watch(page, value => { if (value !== 'Review') detail.value = null; updateUrl(); if (value === 'Products') void action(() => loadCatalog()); if (value === 'Activity') void action(async () => { jobs.value = await api('/jobs') }) })

onMounted(async () => {
  desktopMedia.addEventListener('change', desktopChanged)
  document.addEventListener('keydown', dialogKeys)
  window.addEventListener('popstate', restoreLocation)
  try { personas.value = await api('/playground/personas') } catch { /* Production has OIDC. */ }
  await action(async () => {
    try { me.value = await api('/me') } catch (err) { if (err instanceof ApiError && err.status === 401) return; throw err }
    provider.value = me.value!.playground ? 'demo' : 'osv'
    await loadProjects(); await loadFindings()
  })
  poll = setInterval(() => { if (me.value && page.value === 'Activity' && !busy.value) void api<Job[]>('/jobs').then(value => jobs.value = value).catch(() => {}) }, 3000)
})
onUnmounted(() => { desktopMedia.removeEventListener('change', desktopChanged); clearInterval(poll); document.removeEventListener('keydown', dialogKeys); window.removeEventListener('popstate', restoreLocation); document.body.style.overflow = '' })
</script>

<template>
  <div class="app-shell">
    <header :inert="modalOpen">
      <a class="brand" href="/">DTVP <span>Security review</span></a>
      <nav v-if="me" aria-label="Main navigation">
        <button v-for="item in ['Review', 'Knowledge', 'Statistics', 'Products', 'Activity', ...(access ? ['Access'] : [])]" :key="item" :class="{ current: page === item }" :disabled="busy" @click="page = item">{{ item }}</button>
      </nav>
      <div class="preferences">
        <label>Theme <select v-model="theme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
        <button v-if="me" :disabled="busy" @click="action(async () => { await api('/auth/logout', send({})); me = null; detail = null; token = '' })">Sign out</button>
      </div>
    </header>
    <div v-if="me?.playground" class="playground-bar" :inert="modalOpen">
      <span><strong>Playground</strong> · Synthetic data · External services disabled by default</span>
      <label>Persona <select :value="personas.find(p => p.name === me?.name)?.id" :disabled="busy" @change="login(($event.target as HTMLSelectElement).value)"><option v-for="p in personas" :key="p.id" :value="p.id">{{ p.name }}</option></select></label>
      <details><summary>Replay events</summary><div class="menu"><button :disabled="busy" @click="replay('release-change')">Changed evidence</button><button :disabled="busy" @click="replay('conflict')">Conflicting source</button><button :disabled="busy" @click="replay('partial')">Partial scan</button><button v-if="me.org_admin" :disabled="busy" @click="action(async () => { await api('/playground/scale', send({})); await loadProjects(); await loadFindings(); notice = 'Loaded 100 synthetic projects with 20 findings each.' })">Load large inventory</button><button v-if="me.org_admin" :disabled="busy" @click="action(async () => { await api('/playground/reset', send({})); me = null; detail = null; token = ''; resetReviewFilters(); updateUrl() })">Reset playground</button></div></details>
    </div>
    <div v-if="error" class="message error" role="alert" :inert="modalOpen">{{ error }} <button @click="error = ''" aria-label="Dismiss error">×</button></div>
    <div v-if="notice" class="message success" role="status" :inert="modalOpen">{{ notice }}</div>

    <main v-if="!me" class="login" :inert="modalOpen">
      <p class="eyebrow">DevSecOps coordination</p><h1>Clear evidence.<br>Confident decisions.</h1>
      <p>Review security findings across releases, preserve decisions, and share consistent inventory with your tools.</p>
      <template v-if="personas.length"><h2>Explore the playground</h2><button v-for="p in personas" :key="p.id" :disabled="busy" @click="login(p.id)">{{ p.name }}</button></template>
      <a v-else class="button primary" href="/auth/login">Sign in with SSO</a>
    </main>
    <main v-else :inert="modalOpen" :class="{ 'review-main': page === 'Review' }">
      <KnowledgeWorkspace v-if="page === 'Knowledge'" :key="me.id" :me="me" />
      <template v-if="page === 'Review'">
        <div class="page-title"><div><p class="eyebrow">{{ me.name }}</p><h1>Review workspace</h1><p>What needs your attention, across your accessible teams and releases.</p></div><label class="toggle"><input v-model="power" type="checkbox"> Technical details</label></div>
        <form class="review-searchbar" @submit.prevent="action(() => loadFindings())">
          <label class="search">Search <input v-model="search" placeholder="Vulnerability or component"></label>
          <button type="submit" :disabled="busy">Search</button>
          <button type="button" :aria-expanded="showReviewFilters" aria-controls="review-filters" @click="showReviewFilters = !showReviewFilters">Filters</button>
          <button type="button" :disabled="busy" @click="action(() => loadFindings())">Refresh</button>
        </form>
        <div class="review-layout" :class="{ 'with-filters': showReviewFilters, 'with-detail': embeddedReview }">
        <aside v-show="showReviewFilters" id="review-filters" class="review-filter-rail" aria-label="Review filters"><h2>Filters</h2>
        <form class="filters" @submit.prevent="action(() => loadFindings())">
          <SearchSelect v-model="reviewProject" label="Review product" :selected-label="reviewProjectLabel" endpoint="/catalog/projects" allow-clear :disabled="busy" @select="option => { reviewProjectLabel = option.name || ''; action(() => loadFindings()) }" @update:model-value="value => { if (!value) action(() => loadFindings()) }" />
          <label>Team <select v-model="reviewTeam" @change="action(() => loadFindings())"><option value="">All accessible teams</option><option v-if="reviewTeam && !me.workspaces.some(w => w.id === reviewTeam)" :value="reviewTeam">{{ reviewTeamLabel || "Shared project owning team" }}</option><option v-for="w in me.workspaces" :key="w.id" :value="w.id">{{ w.name }}</option></select></label>
          <label>Status <select v-model="lifecycle" @change="action(() => loadFindings())"><option value="">All statuses</option><option v-for="(name, key) in names" :key="key" :value="key">{{ name }}</option></select></label>
          <label>Sort <select v-model="order" @change="action(() => loadFindings())"><option value="identifier">Vulnerability</option><option value="original_score">Original severity · highest first</option><option value="effective_score">Effective severity · highest first</option><option value="project">Product</option><option value="component">Component</option></select></label>
          <button type="submit" :disabled="busy">Apply</button>
        </form>
        <details class="view-controls"><summary>More filters and saved views</summary><div class="filters"><label>Component owner <input v-model="ownerSearch" placeholder="Responsible team"></label><label>Owner match <select v-model="ownerMatch"><option value="contains">Contains</option><option value="exact">Exact owner</option></select></label><button :disabled="busy" @click="action(() => loadFindings())">Apply filters</button><button :disabled="busy" @click="applyView('')">Reset filters</button><button :disabled="busy" @click="action(copyView)">Copy view link</button><label>View name <input v-model="viewName" maxlength="100"></label><button :disabled="!viewName.trim()" @click="saveView">Save view</button></div><div class="saved-views"><span v-for="view in savedViews" :key="view.name"><button :disabled="busy" @click="applyView(view.query)">{{ view.name }}</button><button :aria-label="`Remove view ${view.name}`" @click="removeView(view.name)">×</button></span></div></details>
        </aside>
        <section class="review-results" aria-label="Findings list">
        <div v-if="hasApprovalAccess" class="bulk-toolbar"><button :disabled="busy" @click="approvalSelection = rows.filter(canSelectApproval).slice(0, 100).map(row => row.id)">Select loaded ready findings</button><span>{{ approvalSelection.length }} selected · maximum 100</span><button :disabled="busy || !approvalSelection.length" @click="action(previewApprovals)">Preview approvals</button><button v-if="approvalSelection.length" :disabled="busy" @click="approvalSelection = []">Clear selection</button></div>
        <section v-if="approvalPreview" class="panel" aria-labelledby="approval-preview-title"><h2 id="approval-preview-title">Approval preview · {{ approvalPreview.count }} decisions</h2><p class="hint">Review the scope and rationale below. Changed evidence or decisions will block the whole selection.</p><article v-for="finding in approvalPreview.findings" :key="finding.id" class="decision-record"><h3>{{ finding.identifier }} · {{ finding.project }} / {{ finding.release }}</h3><p>{{ finding.component }} {{ finding.component_version }} · {{ label(finding.latest_decision!.state) }}</p><p v-if="finding.latest_decision!.state === 'not_affected'" class="justification">{{ justificationLabel(finding.latest_decision!.details.justification) }}</p><p>{{ finding.latest_decision!.rationale }}</p><p v-if="finding.proposed_rescoring">Contextual score proposal: CVSS {{ finding.proposed_rescoring.version }} · {{ finding.proposed_rescoring.base_score }} → {{ finding.proposed_rescoring.score }}. {{ finding.proposed_rescoring.rationale }}</p><button class="text-link" :disabled="busy" @click="action(() => openFinding(finding.id))">Review finding evidence</button></article><button class="primary" :disabled="busy" @click="action(applyApprovals)">Approve reviewed selection</button><button :disabled="busy" @click="approvalPreview = null">Close preview</button></section>
        <div class="table-wrap"><table><thead><tr><th v-if="hasApprovalAccess">Select</th><th>Finding</th><th>Product / release</th><th>Component / owner</th><th>Original score</th><th>Next step</th></tr></thead><tbody>
          <tr v-for="row in rows" :key="row.id" :class="{ selected: detail?.id === row.id, critical: (row.original_score || 0) >= 9, high: (row.original_score || 0) >= 7 }"><td v-if="hasApprovalAccess"><input v-if="canSelectApproval(row)" v-model="approvalSelection" type="checkbox" :value="row.id" :aria-label="`Select ${row.identifier} in ${row.project} ${row.release}`" :disabled="busy || (!approvalSelection.includes(row.id) && approvalSelection.length >= 100)"><span v-else aria-label="Not eligible for approval">—</span></td><td class="finding-identity"><button class="text-link" :disabled="busy" :aria-current="detail?.id === row.id ? 'true' : undefined" @click="action(() => openFinding(row.id))">{{ row.identifier }}</button><small v-if="row.conflicting_scores" class="warning">Conflicting source scores</small><small v-if="row.stale_evidence" class="warning">Evidence needs refreshing</small></td><td class="finding-product">{{ row.project }}<small>{{ row.release }}</small></td><td class="finding-component">{{ row.component }} <small>{{ row.component_version }} · {{ row.owner }}</small></td><td class="finding-severity"><span class="score" :class="{ high: (row.original_score || 0) >= 7 }">{{ score(row.original_score) }}</span><small v-if="row.adopted_rescoring">Approved contextual: {{ score(row.effective_score) }}</small></td><td class="finding-state"><span class="badge" :class="row.lifecycle">{{ label(row.lifecycle) }}</span></td></tr>
        </tbody></table><p v-if="!rows.length" class="empty">{{ nextCursor ? "No matches in this batch. Continue to the next batch." : "No findings in this view. Reset filters or check Products for inventory and matching coverage." }}</p><button v-if="!rows.length && !nextCursor" :disabled="busy" @click="applyView('')">Show all accessible findings</button></div>
        <button v-if="nextCursor" :disabled="busy" @click="action(() => loadFindings(true))">Load more</button>
        </section>
        <div id="review-detail-host" v-show="embeddedReview" class="review-detail-host"></div>
        </div>
      </template>

      <StatisticsView v-if="page === 'Statistics'" :key="me.id" :scope-busy="busy" :query="filterParams().toString()" :scope="`Scope: ${reviewProjectLabel || 'all accessible projects'}${reviewTeam ? ' · ' + (reviewTeamLabel || me.workspaces.find(w => w.id === reviewTeam)?.name || 'selected owning team') : ''}${lifecycle ? ' · ' + label(lifecycle) : ''}${search ? ' · Search: ' + search : ''}${ownerSearch ? ' · Owner: ' + ownerSearch : ''}`" @review="statisticsSlice" @reset="applyView('')" />
      <template v-if="page === 'Products'">
        <div class="page-title"><div><p class="eyebrow">DTVP-owned inventory</p><h1>Products and releases</h1><p>Import sources, curate metadata, and freeze consistent consumer inputs.</p></div></div>
        <details class="panel"><summary>Browse products</summary><form class="filters" @submit.prevent="action(() => loadCatalog())"><label class="search">Search products <input v-model="productSearch" placeholder="Product name"></label><label>Product team <select v-model="productTeam" @change="action(() => loadCatalog())"><option value="">All accessible teams</option><option v-for="w in me.workspaces" :key="w.id" :value="w.id">{{ w.name }}</option></select></label><button :disabled="busy">Search products</button></form><div class="table-wrap"><table><thead><tr><th>Product</th><th>Team</th><th>Releases</th><th>Active findings</th></tr></thead><tbody><tr v-for="product in catalog" :key="product.id"><td><button class="text-link" :disabled="busy" @click="projectId = product.id; selectProject(product)">{{ product.name }}</button></td><td>{{ product.workspace }}</td><td>{{ product.release_count }}</td><td>{{ product.finding_count }}</td></tr></tbody></table><p v-if="!catalog.length" class="empty">No matching products.</p></div><button v-if="catalogCursor" :disabled="busy" @click="action(() => loadCatalog(true))">More products</button></details>
        <div class="filters"><SearchSelect v-model="projectId" label="Product" :selected-label="selectedProject?.name" endpoint="/catalog/projects" :disabled="busy" @select="selectProject" /><SearchSelect v-model="releaseId" label="Release" :selected-label="releases.find(r => r.id === releaseId)?.version" :endpoint="projectId ? `/catalog/projects/${projectId}/releases` : ''" :disabled="busy" @select="option => { if (!releases.some(r => r.id === option.id)) releases.push(option as Release); action(() => loadInventory()) }" /></div>
        <details class="panel"><summary>Add product or release</summary><div class="form-row"><label>Team <select v-model="workspaceId"><option v-for="w in me.workspaces.filter(w => w.capabilities.includes('write'))" :key="w.id" :value="w.id">{{ w.name }}</option></select></label><label>Product name <input v-model="newProjectName"></label><button :disabled="busy || !newProjectName" @click="action(async () => { const p = await api<Project>('/projects', send({ workspace_id: workspaceId, name: newProjectName })); projectId = p.id; newProjectName = ''; await loadProjects() })">Create product</button></div><div v-if="canWrite" class="form-row"><label>Release version <input v-model="newReleaseVersion"></label><button :disabled="busy || !newReleaseVersion" @click="action(async () => { const r = await api<Release>(`/projects/${projectId}/releases`, send({ version: newReleaseVersion })); releaseId = r.id; newReleaseVersion = ''; await loadReleases() })">Create release</button></div></details>
        <div v-if="releaseId" class="columns">
          <section class="panel"><h2>Source inputs</h2><p v-if="!revisions.length">No SBOM imported yet.</p><ul class="source-list"><li v-for="r in revisions.slice(0, 5)" :key="r.id"><strong>{{ r.source }}</strong><span class="badge">{{ r.completeness }}</span><small>{{ new Date(r.occurred_at).toLocaleString() }}</small></li></ul>
            <div v-if="canWrite" class="form-row"><label>Source <select v-model="source"><option value="file">File</option><option value="cybeats">CyBeats export</option><option value="pipeline">Pipeline report</option><option value="dependency-track">DT export</option></select></label><label class="button">Import SBOM <input class="file-input" type="file" accept=".json,.xml" :disabled="busy" @change="upload"></label></div>
            <p class="hint">CycloneDX 1.5/1.6 or SPDX 2.3. A plain SBOM does not establish vulnerability coverage.</p>
            <details v-if="canWrite"><summary>Matching and advisory services</summary><div class="form-row"><label>Provider <select v-model="provider"><option v-if="me.playground" value="demo">Offline demo matcher</option><option v-if="me.playground" value="demo-failure">Simulated source failure</option><option value="osv">OSV package matching</option><option value="nvd">NVD advisories</option><option value="circl">CIRCL advisories</option></select></label><button :disabled="busy" @click="queue(['osv', 'demo', 'demo-failure'].includes(provider) ? 'match' : 'enrich')">Run selected provider</button></div><p class="hint">Deployment must enable the provider. Matching sends package coordinates; advisory lookup sends vulnerability IDs.</p><label>Dependency-Track project UUID <input v-model="dtProjectId"></label><button v-if="canManage" :disabled="busy || !dtProjectId" @click="action(async () => { await api(`/projects/${projectId}/connectors/dependency-track`, { method: 'PUT', body: JSON.stringify({ external_project_id: dtProjectId }) }); notice = 'DT project binding saved.' })">Bind DT project</button><button :disabled="busy || !dtProjectId" @click="queue('import-dt')">Import from configured DT source</button><p class="hint">An administrator binds this product to its source project before import.</p></details>
          </section>
          <section class="panel"><h2>Consumer snapshot</h2><p>Freeze this release's inventory, findings, metadata and decisions for Generator or VScorer.</p><button class="primary" :disabled="busy || !selectedProject?.capabilities.includes('snapshot') || !revisions.length" @click="snapshot">Create snapshot</button>
            <div v-if="latestSnapshot" class="snapshot-links"><p role="status">Snapshot ready. Inventory: {{ latestSnapshot.coverage.inventory }}. Matching: {{ latestSnapshot.coverage.matching }}.</p><p v-if="latestSnapshot.coverage.unresolved_findings.length || latestSnapshot.coverage.excluded_components.length" class="warning">Some findings or components could not be included in the VScorer inputs. Check coverage before analysis.</p><a :href="`/api/v2/snapshots/${latestSnapshot.id}/bundle`">Generator bundle</a><a :href="`/api/v2/snapshots/${latestSnapshot.id}/sbom`">CycloneDX SBOM</a><a :href="`/api/v2/snapshots/${latestSnapshot.id}/exports/vscorer/worklist`">VScorer vulnerability list</a><a :href="`/api/v2/snapshots/${latestSnapshot.id}`">Coverage and manifest</a></div>
            <a v-if="me.vscorer_url" :href="me.vscorer_url" target="_blank" rel="noopener">Open VScorer</a>
          </section>
        </div>
        <RescorePolicyEditor v-if="canManage && projectId" :key="projectId" :project-id="projectId" :disabled="busy" />
        <details v-if="canManage" class="panel"><summary>Agentyzer repository integration</summary><p class="hint">Bind this product to a logical repository name in the separate Agentyzer service's repos.yaml. Deployment controls the endpoint and credentials.</p><label>Agentyzer repository name <input v-model="analysisRepository" maxlength="200"></label><button :disabled="busy || !analysisRepository.trim()" @click="action(async () => { await api(`/projects/${projectId}/connectors/agentyzer`, { method: 'PUT', body: JSON.stringify({ component_name: analysisRepository }) }); notice = 'Agentyzer repository binding saved.' })">Bind Agentyzer repository</button></details>
        <section v-if="releaseId" class="panel"><h2>Components</h2><form class="filters" @submit.prevent="action(() => loadInventory())"><label class="search">Search components <input v-model="componentSearch" placeholder="Name, version or PURL"></label><button :disabled="busy">Search components</button></form><div class="table-wrap"><table><thead><tr><th>Component</th><th>Version</th><th>Owner</th><th>Support / EOL</th><th></th></tr></thead><tbody><tr v-for="c in components" :key="c.id"><td>{{ c.name }}</td><td>{{ c.version }}</td><td>{{ c.metadata.owner || 'Unassigned' }}</td><td>{{ c.metadata.eol || 'Unknown' }}</td><td><button v-if="canWrite" :disabled="busy" @click="editMetadata(c)">Edit metadata</button></td></tr></tbody></table></div><button v-if="componentCursor" :disabled="busy" @click="action(() => loadInventory(true))">More components</button></section>
      </template>

      <template v-if="page === 'Activity'">
        <div class="page-title"><div><p class="eyebrow">Durable operations</p><h1>Activity</h1><p>Imports, matching and enrichment keep their progress across restarts.</p></div></div>
        <section class="panel"><p v-if="!jobs.length" class="empty">No background operations yet.</p><article v-for="job in jobs" :key="job.id" class="job"><div><h2>{{ label(job.kind) }}</h2><span class="badge">{{ job.status }}</span><p v-if="job.error" class="warning">{{ job.error }}</p><details v-if="Object.keys(job.result).length"><summary>Results and coverage</summary><pre>{{ JSON.stringify(job.result, null, 2) }}</pre></details></div><div><button v-if="job.finding_id" :disabled="busy" @click="action(() => openFinding(job.finding_id!))">Open finding</button><button v-if="job.kind !== 'analyse' && ['failed', 'cancelled'].includes(job.status)" :disabled="busy" @click="action(async () => { await api(`/jobs/${job.id}/retry`, send({})); jobs = await api('/jobs') })">Retry</button><button v-if="['queued', 'running'].includes(job.status)" :disabled="busy" @click="action(async () => { await api(`/jobs/${job.id}/cancel`, send({})); jobs = await api('/jobs') })">Cancel</button></div></article></section>
      </template>

      <template v-if="page === 'Access'">
        <div class="page-title"><div><p class="eyebrow">Explicit team access</p><h1>Access and integrations</h1><p>Ownership describes responsibility. Team memberships and sharing control access.</p></div></div>
        <label>Team <select v-model="workspaceId"><option v-for="w in me.workspaces.filter(w => w.capabilities.includes('manage'))" :key="w.id" :value="w.id">{{ w.name }}</option></select></label>
        <div class="columns"><section class="panel"><h2>Member mapping</h2><label>OIDC issuer <input v-model="memberIssuer"></label><label>Subject <input v-model="memberSubject"></label><label>Display name <input v-model="memberName"></label><label>Role <select v-model="memberRole"><option v-for="role in ['viewer', 'analyst', 'reviewer', 'coordinator', 'admin']" :key="role">{{ role }}</option></select></label><p class="hint">Administrator permission does not grant approval. Map the verified issuer and subject from your identity provider.</p><button :disabled="busy || !memberIssuer || !memberSubject || !memberName" @click="action(async () => { await api(`/workspaces/${workspaceId}/members`, { method: 'PUT', body: JSON.stringify({ issuer: memberIssuer, subject: memberSubject, name: memberName, roles: [memberRole] }) }); notice = 'Membership saved.' })">Save membership</button></section>
          <section class="panel"><h2>Consumer credential</h2><label>Name <input v-model="tokenName"></label><p class="hint">Create a 24-hour read-only credential for this team. It remains constrained by your current membership.</p><button :disabled="busy || !tokenName" @click="action(async () => { const result = await api<{ token: string }>('/credentials', send({ workspace_id: workspaceId, name: tokenName, capabilities: ['read'], projects: [], hours: 24 })); token = result.token })">Issue read credential</button><label v-if="token">Copy now; shown only once <textarea readonly :value="token"></textarea></label><a href="/openapi.json" target="_blank" rel="noopener">API schema</a></section>
        </div>
        <section v-if="me.workspaces.some(w => w.capabilities.includes('manage'))" class="panel"><h2>Project sharing</h2><SearchSelect v-model="projectId" label="Shared product" :selected-label="selectedProject?.name" endpoint="/catalog/projects" :disabled="busy" @select="selectProject" /><p v-if="!canManage" class="hint">Select a product you manage to change sharing.</p><label>Share with team <select v-model="shareWorkspace"><option v-for="w in me.workspaces.filter(w => w.id !== selectedProject?.workspace_id)" :key="w.id" :value="w.id">{{ w.name }}</option></select></label><label class="toggle"><input v-model="sharedReadOnly" type="checkbox"> Read only</label><button :disabled="busy || !shareWorkspace || !canManage" @click="action(async () => { await api(`/projects/${projectId}/sharing`, { method: 'PUT', body: JSON.stringify({ workspace_id: shareWorkspace, capabilities: sharedReadOnly ? ['read'] : ['read', 'assess', 'approve', 'rescore', 'snapshot', 'evidence'] }) }); notice = 'Sharing updated.' })">Save sharing</button></section>
        <section v-if="me.org_admin" class="panel"><h2>Add team workspace</h2><label>Team name <input v-model="workspaceName"></label><button :disabled="busy || !workspaceName" @click="action(async () => { await api('/workspaces', send({ name: workspaceName })); me = await api('/me'); workspaceName = '' })">Create workspace</button></section>
      </template>
    </main>

    <Teleport v-if="detail" to="#review-detail-host" :disabled="!embeddedReview"><ReviewWorkspace :embedded="embeddedReview" :key="detail.id" :finding="detail" :draft="draft" :me="me!" :busy="busy" :error="error" :notice="notice" :power="power" :can-approve="Boolean(canApprove)" :index="reviewIndex" :loaded="rows.length" :previous="reviewIndex >= 0 ? reviewIndex > 0 : queueAnchor > 0" :next="!(reviewIndex < 0 && queueAnchor < 0) && (reviewIndex >= 0 ? reviewIndex < rows.length - 1 || Boolean(nextCursor) : queueAnchor < rows.length || Boolean(nextCursor))" @close="detail = null" @move="delta => action(() => moveFinding(delta))" @refresh="action(() => openFinding(detail!.id, true))" @team="workspace => action(() => openFinding(detail!.id, false, workspace))" @update:draft="value => draft = value" @submit="submit" @approve="approve" /></Teleport>
    <div v-if="metadataEdit" class="overlay"><section class="inspector" role="dialog" aria-modal="true" aria-labelledby="metadata-title"><div class="inspector-header"><h2 id="metadata-title">Metadata · {{ metadataEdit.name }}</h2><button aria-label="Close metadata" :disabled="busy" @click="metadataEdit = null">×</button></div><div class="inspector-content"><p>Curated information survives source reimports. Changes reopen affected approvals for review.</p><label v-for="(name, key) in metadataFields" :key="key">{{ name }}<input v-model="metadataForm[key]"></label><details><summary>Additional properties</summary><label>Extension data (JSON)<textarea v-model="metadataText" rows="8"></textarea></label></details><p v-if="error" role="alert">{{ error }}</p><button class="primary" :disabled="busy" @click="action(async () => { await api(`/components/${metadataEdit!.id}/metadata`, { method: 'PUT', body: JSON.stringify({ expected_version: metadataEdit!.metadata_version, metadata: { ...JSON.parse(metadataText), ...metadataForm } }) }); metadataEdit = null; await loadInventory(); notice = 'Metadata saved.' })">Save metadata</button></div></section></div>
  </div>
</template>
