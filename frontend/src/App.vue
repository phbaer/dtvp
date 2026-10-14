<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { api, ApiError, send } from './api'
import type { Component, Finding, Job, Me, Project, Release, Revision, Snapshot } from './types'

const me = ref<Me | null>(null)
const personas = ref<{ id: string; name: string }[]>([])
const page = ref('Review')
const projects = ref<Project[]>([])
const releases = ref<Release[]>([])
const projectId = ref('')
const releaseId = ref('')
const rows = ref<Finding[]>([])
const nextCursor = ref<string | null>(null)
const detail = ref<Finding | null>(null)
const components = ref<Component[]>([])
const componentCursor = ref<string | null>(null)
const revisions = ref<Revision[]>([])
const jobs = ref<Job[]>([])
const lifecycle = ref('')
const search = ref('')
const draft = ref({ state: 'under_investigation', rationale: '' })
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
const modalOpen = computed(() => Boolean(detail.value || metadataEdit.value))

function rememberFocus() {
  returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
}

function dialogKeys(event: KeyboardEvent) {
  if (!modalOpen.value) return
  if (event.key === 'Escape') {
    event.preventDefault()
    if (!busy.value) { detail.value = null; metadataEdit.value = null }
  } else if (event.key === 'Tab') {
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
const latestDecision = computed(() => detail.value?.decisions[0])
const canApprove = computed(() => detail.value?.capabilities.includes('approve') && detail.value.lifecycle === 'ready' && latestDecision.value?.author_id !== me.value?.id)
const access = computed(() => me.value?.org_admin || me.value?.workspaces.some(w => w.capabilities.includes('manage')))
const draftKey = computed(() => `dtvp.draft:${me.value?.id}:${detail.value?.id}`)
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
  projects.value = await api('/projects')
  if (!projects.value.some(p => p.id === projectId.value)) projectId.value = projects.value[0]?.id || ''
  workspaceId.value ||= me.value?.workspaces[0]?.id || ''
  await loadReleases()
}

async function loadReleases() {
  releases.value = projectId.value ? await api(`/projects/${projectId.value}/releases`) : []
  if (!releases.value.some(r => r.id === releaseId.value)) releaseId.value = releases.value[0]?.id || ''
  latestSnapshot.value = null
  await loadInventory()
}

async function loadInventory(append = false) {
  if (!releaseId.value) { components.value = []; revisions.value = []; return }
  const result = await api<{ items: Component[]; next_cursor: string | null }>(`/releases/${releaseId.value}/components?cursor=${append ? componentCursor.value || '' : ''}`)
  components.value = append ? [...components.value, ...result.items] : result.items
  componentCursor.value = result.next_cursor
  revisions.value = await api(`/releases/${releaseId.value}/revisions`)
}

async function loadFindings(append = false) {
  const sequence = ++requestSequence
  const params = new URLSearchParams({ q: search.value, lifecycle: lifecycle.value })
  if (append && nextCursor.value) params.set('cursor', nextCursor.value)
  const result = await api<{ items: Finding[]; next_cursor: string | null }>(`/findings?${params}`)
  if (sequence !== requestSequence) return
  rows.value = append ? [...rows.value, ...result.items] : result.items
  nextCursor.value = result.next_cursor
}

async function openFinding(id: string, keepDraft = false) {
  if (!detail.value) rememberFocus()
  detail.value = await api(`/findings/${id}`)
  if (!keepDraft) {
    const saved = sessionStorage.getItem(draftKey.value)
    draft.value = saved ? JSON.parse(saved) : { state: latestDecision.value?.state || detail.value!.imported_assessments?.[0]?.state || 'under_investigation', rationale: latestDecision.value?.rationale || detail.value!.imported_assessments?.[0]?.current_records.map(record => record.rationale).filter(Boolean).join('\n\n') || '' }
  }
}

async function login(persona: string) {
  await action(async () => {
    await api('/playground/login', send({ persona }))
    me.value = await api('/me'); detail.value = null; token.value = ''; workspaceId.value = ''; provider.value = me.value!.playground ? 'demo' : 'osv'
    await loadProjects(); await loadFindings()
  })
}

async function submit() {
  if (!detail.value) return
  await action(async () => {
    await api(`/findings/${detail.value!.id}/decisions`, send({ ...draft.value, expected_version: detail.value!.state_version }))
    sessionStorage.removeItem(draftKey.value)
    await openFinding(detail.value!.id, true); await loadFindings()
    notice.value = 'Decision saved. A different reviewer can approve it.'
  })
}

async function approve(requestChanges = false) {
  await action(async () => {
    await api(`/findings/${detail.value!.id}/approvals`, send({ expected_version: detail.value!.state_version, decision_id: latestDecision.value!.id, action: requestChanges ? 'request_changes' : 'approve' }))
    await openFinding(detail.value!.id, true); await loadFindings()
    notice.value = requestChanges ? 'Changes requested.' : 'Decision approved against the current evidence.'
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

watch(draft, value => { if (detail.value && me.value) sessionStorage.setItem(draftKey.value, JSON.stringify(value)) }, { deep: true })
watch(power, value => localStorage.setItem('dtvp.power', String(value)))
watch(theme, value => { localStorage.setItem('dtvp.theme', value); document.documentElement.dataset.theme = value }, { immediate: true })
watch(page, value => { if (value === 'Activity') void action(async () => { jobs.value = await api('/jobs') }) })

onMounted(async () => {
  document.addEventListener('keydown', dialogKeys)
  try { personas.value = await api('/playground/personas') } catch { /* Production has OIDC. */ }
  await action(async () => {
    try { me.value = await api('/me') } catch (err) { if (err instanceof ApiError && err.status === 401) return; throw err }
    provider.value = me.value!.playground ? 'demo' : 'osv'
    await loadProjects(); await loadFindings()
  })
  poll = setInterval(() => { if (me.value && page.value === 'Activity' && !busy.value) void api<Job[]>('/jobs').then(value => jobs.value = value).catch(() => {}) }, 3000)
})
onUnmounted(() => { clearInterval(poll); document.removeEventListener('keydown', dialogKeys); document.body.style.overflow = '' })
</script>

<template>
  <div class="app-shell">
    <header :inert="modalOpen">
      <a class="brand" href="/">DTVP <span>Security review</span></a>
      <nav v-if="me" aria-label="Main navigation">
        <button v-for="item in ['Review', 'Products', 'Activity', ...(access ? ['Access'] : [])]" :key="item" :class="{ current: page === item }" :disabled="busy" @click="page = item">{{ item }}</button>
      </nav>
      <div class="preferences">
        <label>Theme <select v-model="theme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
        <button v-if="me" :disabled="busy" @click="action(async () => { await api('/auth/logout', send({})); me = null; detail = null; token = '' })">Sign out</button>
      </div>
    </header>
    <div v-if="me?.playground" class="playground-bar" :inert="modalOpen">
      <span><strong>Playground</strong> · Synthetic data · External services disabled by default</span>
      <label>Persona <select :value="personas.find(p => p.name === me?.name)?.id" :disabled="busy" @change="login(($event.target as HTMLSelectElement).value)"><option v-for="p in personas" :key="p.id" :value="p.id">{{ p.name }}</option></select></label>
      <details><summary>Replay events</summary><div class="menu"><button :disabled="busy" @click="replay('release-change')">Changed evidence</button><button :disabled="busy" @click="replay('conflict')">Conflicting source</button><button :disabled="busy" @click="replay('partial')">Partial scan</button><button v-if="me.org_admin" :disabled="busy" @click="action(async () => { await api('/playground/reset', send({})); me = null; detail = null; token = '' })">Reset playground</button></div></details>
    </div>
    <div v-if="error" class="message error" role="alert" :inert="modalOpen">{{ error }} <button @click="error = ''" aria-label="Dismiss error">×</button></div>
    <div v-if="notice" class="message success" role="status" :inert="modalOpen">{{ notice }}</div>

    <main v-if="!me" class="login" :inert="modalOpen">
      <p class="eyebrow">DevSecOps coordination</p><h1>Clear evidence.<br>Confident decisions.</h1>
      <p>Review security findings across releases, preserve decisions, and share consistent inventory with your tools.</p>
      <template v-if="personas.length"><h2>Explore the playground</h2><button v-for="p in personas" :key="p.id" :disabled="busy" @click="login(p.id)">{{ p.name }}</button></template>
      <a v-else class="button primary" href="/auth/login">Sign in with SSO</a>
    </main>
    <main v-else :inert="modalOpen">
      <template v-if="page === 'Review'">
        <div class="page-title"><div><p class="eyebrow">{{ me.name }}</p><h1>Review workspace</h1><p>What needs your attention, across your accessible teams and releases.</p></div><label class="toggle"><input v-model="power" type="checkbox"> Technical details</label></div>
        <form class="filters" @submit.prevent="action(() => loadFindings())">
          <label class="search">Search <input v-model="search" placeholder="Vulnerability or component"></label>
          <label>Status <select v-model="lifecycle" @change="action(() => loadFindings())"><option value="">All statuses</option><option v-for="(name, key) in names" :key="key" :value="key">{{ name }}</option></select></label>
          <button type="submit" :disabled="busy">Search</button><button type="button" :disabled="busy" @click="action(() => loadFindings())">Refresh</button>
        </form>
        <div class="table-wrap"><table><thead><tr><th>Finding</th><th>Product / release</th><th>Component / owner</th><th>Original score</th><th>Next step</th></tr></thead><tbody>
          <tr v-for="row in rows" :key="row.id"><td><button class="text-link" :disabled="busy" @click="action(() => openFinding(row.id))">{{ row.identifier }}</button><small v-if="row.conflicting_scores" class="warning">Conflicting source scores</small><small v-if="row.stale_evidence" class="warning">Evidence needs refreshing</small></td><td>{{ row.project }}<small>{{ row.release }}</small></td><td>{{ row.component }} <small>{{ row.component_version }} · {{ row.owner }}</small></td><td><span class="score" :class="{ high: (row.original_score || 0) >= 7 }">{{ score(row.original_score) }}</span></td><td><span class="badge" :class="row.lifecycle">{{ label(row.lifecycle) }}</span></td></tr>
        </tbody></table><p v-if="!rows.length" class="empty">No findings in this view. Check Products for inventory and matching coverage.</p></div>
        <button v-if="nextCursor" :disabled="busy" @click="action(() => loadFindings(true))">Load more</button>
      </template>

      <template v-if="page === 'Products'">
        <div class="page-title"><div><p class="eyebrow">DTVP-owned inventory</p><h1>Products and releases</h1><p>Import sources, curate metadata, and freeze consistent consumer inputs.</p></div></div>
        <div class="filters"><label>Product <select v-model="projectId" :disabled="busy" @change="action(() => loadReleases())"><option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option></select></label><label>Release <select v-model="releaseId" :disabled="busy" @change="action(() => loadInventory())"><option v-for="r in releases" :key="r.id" :value="r.id">{{ r.version }}</option></select></label></div>
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
        <section v-if="releaseId" class="panel"><h2>Components</h2><div class="table-wrap"><table><thead><tr><th>Component</th><th>Version</th><th>Owner</th><th>Support / EOL</th><th></th></tr></thead><tbody><tr v-for="c in components" :key="c.id"><td>{{ c.name }}</td><td>{{ c.version }}</td><td>{{ c.metadata.owner || 'Unassigned' }}</td><td>{{ c.metadata.eol || 'Unknown' }}</td><td><button v-if="canWrite" :disabled="busy" @click="editMetadata(c)">Edit metadata</button></td></tr></tbody></table></div><button v-if="componentCursor" :disabled="busy" @click="action(() => loadInventory(true))">More components</button></section>
      </template>

      <template v-if="page === 'Activity'">
        <div class="page-title"><div><p class="eyebrow">Durable operations</p><h1>Activity</h1><p>Imports, matching and enrichment keep their progress across restarts.</p></div></div>
        <section class="panel"><p v-if="!jobs.length" class="empty">No background operations yet.</p><article v-for="job in jobs" :key="job.id" class="job"><div><h2>{{ label(job.kind) }}</h2><span class="badge">{{ job.status }}</span><p v-if="job.error" class="warning">{{ job.error }}</p><details v-if="Object.keys(job.result).length"><summary>Results and coverage</summary><pre>{{ JSON.stringify(job.result, null, 2) }}</pre></details></div><div><button v-if="['failed', 'cancelled'].includes(job.status)" :disabled="busy" @click="action(async () => { await api(`/jobs/${job.id}/retry`, send({})); jobs = await api('/jobs') })">Retry</button><button v-if="['queued', 'running'].includes(job.status)" :disabled="busy" @click="action(async () => { await api(`/jobs/${job.id}/cancel`, send({})); jobs = await api('/jobs') })">Cancel</button></div></article></section>
      </template>

      <template v-if="page === 'Access'">
        <div class="page-title"><div><p class="eyebrow">Explicit team access</p><h1>Access and integrations</h1><p>Ownership describes responsibility. Team memberships and sharing control access.</p></div></div>
        <label>Team <select v-model="workspaceId"><option v-for="w in me.workspaces.filter(w => w.capabilities.includes('manage'))" :key="w.id" :value="w.id">{{ w.name }}</option></select></label>
        <div class="columns"><section class="panel"><h2>Member mapping</h2><label>OIDC issuer <input v-model="memberIssuer"></label><label>Subject <input v-model="memberSubject"></label><label>Display name <input v-model="memberName"></label><label>Role <select v-model="memberRole"><option v-for="role in ['viewer', 'analyst', 'reviewer', 'admin']" :key="role">{{ role }}</option></select></label><p class="hint">Administrator permission does not grant approval. Map the verified issuer and subject from your identity provider.</p><button :disabled="busy || !memberIssuer || !memberSubject || !memberName" @click="action(async () => { await api(`/workspaces/${workspaceId}/members`, { method: 'PUT', body: JSON.stringify({ issuer: memberIssuer, subject: memberSubject, name: memberName, roles: [memberRole] }) }); notice = 'Membership saved.' })">Save membership</button></section>
          <section class="panel"><h2>Consumer credential</h2><label>Name <input v-model="tokenName"></label><p class="hint">Create a 24-hour read-only credential for this team. It remains constrained by your current membership.</p><button :disabled="busy || !tokenName" @click="action(async () => { const result = await api<{ token: string }>('/credentials', send({ workspace_id: workspaceId, name: tokenName, capabilities: ['read'], projects: [], hours: 24 })); token = result.token })">Issue read credential</button><label v-if="token">Copy now; shown only once <textarea readonly :value="token"></textarea></label><a href="/openapi.json" target="_blank" rel="noopener">API schema</a></section>
        </div>
        <section v-if="canManage" class="panel"><h2>Project sharing</h2><label>Product <select v-model="projectId"><option v-for="p in projects.filter(p => p.capabilities.includes('manage'))" :key="p.id" :value="p.id">{{ p.name }}</option></select></label><label>Share with team <select v-model="shareWorkspace"><option v-for="w in me.workspaces.filter(w => w.id !== selectedProject?.workspace_id)" :key="w.id" :value="w.id">{{ w.name }}</option></select></label><label class="toggle"><input v-model="sharedReadOnly" type="checkbox"> Read only</label><button :disabled="busy || !shareWorkspace" @click="action(async () => { await api(`/projects/${projectId}/sharing`, { method: 'PUT', body: JSON.stringify({ workspace_id: shareWorkspace, capabilities: sharedReadOnly ? ['read'] : ['read', 'assess', 'snapshot', 'evidence'] }) }); notice = 'Sharing updated.' })">Save sharing</button></section>
        <section v-if="me.org_admin" class="panel"><h2>Add team workspace</h2><label>Team name <input v-model="workspaceName"></label><button :disabled="busy || !workspaceName" @click="action(async () => { await api('/workspaces', send({ name: workspaceName })); me = await api('/me'); workspaceName = '' })">Create workspace</button></section>
      </template>
    </main>

    <div v-if="detail" class="overlay" @click.self="!busy && (detail = null)"><section class="inspector" role="dialog" aria-modal="true" aria-labelledby="finding-title">
      <div class="inspector-header"><div><p class="eyebrow">{{ detail.project }} · {{ detail.release }}</p><h1 id="finding-title">{{ detail.identifier }}</h1><p>{{ detail.component }} {{ detail.component_version }} · {{ detail.owner }}</p></div><button aria-label="Close finding" :disabled="busy" @click="detail = null">×</button></div>
      <div class="inspector-content"><div class="summary-line"><span class="score high">{{ score(detail.original_score) }}</span><span>Original severity</span><span class="badge" :class="detail.lifecycle">{{ label(detail.lifecycle) }}</span></div>
        <p v-if="error" class="message error" role="alert">{{ error }}</p><p v-if="notice" class="message success" role="status">{{ notice }}</p>
        <p v-if="detail.lifecycle === 'needs_revalidation'" class="warning">Evidence changed since the last decision. Review the changes and submit a new assessment.</p><p v-if="detail.conflicting_scores" class="warning">Sources disagree on the original score. Resolve the difference before exporting to VScorer.</p><p v-if="detail.stale_evidence" class="warning">Source evidence is older than 30 days. Check whether it still applies.</p>
        <section v-for="(imported, index) in detail.imported_assessments" :key="index" class="decision-record"><h2>Imported DT assessment</h2><p class="hint">{{ imported.source }} · {{ imported.format === 'plain-dt' ? 'Legacy documentation without DTVP metadata' : 'Previous DTVP documentation' }}. Imported review history remains separate from DTVP approval.</p><p v-if="imported.pending_review || imported.conflicting" class="warning">{{ imported.conflicting ? 'Imported team decisions conflict.' : 'Source assessment is pending review.' }}</p><p v-if="imported.suppressed" class="warning">Suppressed in the source. Retained for review.</p><article v-for="(record, position) in imported.current_records" :key="position"><strong>{{ record.team }} · {{ record.state ? label(record.state) : 'Applicability not recorded' }}</strong><p>{{ record.rationale || 'No rationale recorded.' }}</p><small>{{ record.assessor ? `Source assessor: ${record.assessor}` : 'Assessor not recorded' }}{{ record.reviewer ? ` · Source reviewer: ${record.reviewer}` : '' }}</small><p v-if="record.rescored_score !== null" class="hint">Legacy contextual score: {{ record.rescored_score }}. Original Base severity remains unchanged.</p><p v-if="record.ssvc_priority" class="hint">Imported SSVC priority: {{ record.ssvc_priority }}</p></article></section><h2>What needs review</h2><p>{{ detail.description || 'No advisory description supplied. Review the available source evidence.' }}</p>
        <p class="hint">{{ detail.observations.length }} source observations · {{ detail.evidence.length }} additional evidence records. A lower contextual score does not prove the component is unaffected.</p>
        <section v-for="record in detail.evidence.filter(e => e.kind === 'contextual-assessment')" :key="String(record.id)" class="decision-record"><h2>{{ record.source === 'vscorer' ? 'VScorer contextual assessment' : 'Contextual assessment' }}</h2><p v-if="typeof record.environmental_score === 'number'">Proposed Environmental score: <strong>{{ record.environmental_score.toFixed(1) }}</strong>. Original Base severity remains unchanged.</p><p v-if="typeof record.rationale === 'string'">{{ record.rationale }}</p><p class="hint">Imported evidence informs your decision; it does not approve it.</p></section><section v-if="latestDecision" class="decision-record"><h2>Latest assessment</h2><strong>{{ label(latestDecision.state) }}</strong><p>{{ latestDecision.rationale }}</p><p class="hint">{{ detail.approval ? 'Reviewed and approved' : 'Awaiting review' }} · {{ new Date(latestDecision.created_at).toLocaleString() }}</p></section>
        <form v-if="detail.capabilities.includes('assess')" @submit.prevent="submit"><h2>Your assessment</h2><label>Applicability <select v-model="draft.state"><option value="under_investigation">Under investigation</option><option value="affected">Affected</option><option value="not_affected">Not affected</option><option value="fixed">Fixed</option></select></label><label>Reason and evidence <textarea v-model="draft.rationale" rows="5" maxlength="6000" placeholder="Explain the scope, relevant evidence, and proposed action."></textarea></label><p class="hint">Drafts are retained in this browser session. Saving submits a new revision for independent review.</p><button class="primary" :disabled="busy || !draft.rationale.trim()">Submit assessment</button></form>
        <div v-if="canApprove" class="approval-actions"><button class="primary" :disabled="busy" @click="approve()">Approve decision</button><button :disabled="busy" @click="approve(true)">Request changes</button></div><p v-else-if="detail.lifecycle === 'ready' && latestDecision?.author_id === me?.id" class="hint">A different reviewer must approve your assessment.</p>
        <button :disabled="busy" @click="action(() => openFinding(detail!.id, true))">Refresh evidence</button>
        <details :open="power"><summary>Technical evidence and history</summary><h3>Package coordinate</h3><code>{{ detail.purl || 'No PURL supplied' }}</code><h3>Source observations</h3><pre>{{ JSON.stringify(detail.observations, null, 2) }}</pre><h3>Contextual evidence</h3><pre>{{ JSON.stringify(detail.evidence, null, 2) }}</pre><h3>Decision history</h3><pre>{{ JSON.stringify(detail.decisions, null, 2) }}</pre></details>
      </div>
    </section></div>
    <div v-if="metadataEdit" class="overlay"><section class="inspector" role="dialog" aria-modal="true" aria-labelledby="metadata-title"><div class="inspector-header"><h2 id="metadata-title">Metadata · {{ metadataEdit.name }}</h2><button aria-label="Close metadata" :disabled="busy" @click="metadataEdit = null">×</button></div><div class="inspector-content"><p>Curated information survives source reimports. Changes reopen affected approvals for review.</p><label v-for="(name, key) in metadataFields" :key="key">{{ name }}<input v-model="metadataForm[key]"></label><details><summary>Additional properties</summary><label>Extension data (JSON)<textarea v-model="metadataText" rows="8"></textarea></label></details><p v-if="error" role="alert">{{ error }}</p><button class="primary" :disabled="busy" @click="action(async () => { await api(`/components/${metadataEdit!.id}/metadata`, { method: 'PUT', body: JSON.stringify({ expected_version: metadataEdit!.metadata_version, metadata: { ...JSON.parse(metadataText), ...metadataForm } }) }); metadataEdit = null; await loadInventory(); notice = 'Metadata saved.' })">Save metadata</button></div></section></div>
  </div>
</template>
