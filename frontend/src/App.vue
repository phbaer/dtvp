<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, onUnmounted, ref, watch } from 'vue'
import { api, ApiError, send } from './api'
import SearchSelect from './components/SearchSelect.vue'
import type { Me, Project, Job } from './types'
const Review = defineAsyncComponent(() => import('./components/KnowledgeWorkspace.vue'))
const me = ref<Me | null>(null), busy = ref(false), locked = ref(false), error = ref(''), notice = ref('')
const personas = ref<{ id: string; name: string }[]>([]), jobs = ref<Job[]>([])
const page = ref<'Review' | 'Activity' | 'Access'>(new URLSearchParams(location.search).get('page') === 'Activity' ? 'Activity' : new URLSearchParams(location.search).get('page') === 'Access' ? 'Access' : 'Review')
const canAdminister = computed(() => me.value?.org_admin || me.value?.workspaces.some(team => team.capabilities.includes('manage')))
const pages = computed(() => canAdminister.value ? ['Review', 'Activity', 'Access'] as const : ['Review', 'Activity'] as const)
const theme = ref(localStorage.getItem('dtvp.theme') || 'system')
const workspaceId = ref(''), memberIssuer = ref(''), memberSubject = ref(''), memberName = ref(''), memberRole = ref('viewer'), tokenName = ref(''), token = ref(''), workspaceName = ref(''), shareWorkspace = ref(''), sharedReadOnly = ref(true)
const projectId = ref(''), selectedProject = ref<Project | null>(null)
const canManage = computed(() => selectedProject.value?.capabilities.includes('manage'))
const label = (value: string) => value.replaceAll('-', ' ').replaceAll('_', ' ')
let generation = 0
async function action(work: () => Promise<void>) {
  if (busy.value) return
  const current = generation; busy.value = true; error.value = ''; notice.value = ''
  try { await work() } catch (err) { if (current === generation) error.value = err instanceof Error ? err.message : 'Request failed' }
  finally { if (current === generation) busy.value = false }
}
async function loadJobs() { const current = generation; const result = await api<Job[]>('/jobs'); if (current === generation) jobs.value = result }
async function session() {
  me.value = await api<Me>('/me')
  workspaceId.value = me.value.workspaces.find(team => team.capabilities.includes('manage'))?.id || ''
  if (me.value.playground) { try { personas.value = await api('/playground/personas') } catch { personas.value = [] } }
  else personas.value = []
  if (page.value === 'Access' && !canAdminister.value) page.value = 'Review'
  if (page.value === 'Activity') await loadJobs()
}
async function login(persona: string) {
  // Personas replace the session; old native views/requests are discarded by actor key.
  await action(async () => { await api('/playground/login', send({ persona })); token.value = ''; memberIssuer.value = ''; memberSubject.value = ''; memberName.value = ''; tokenName.value = ''; workspaceName.value = ''; shareWorkspace.value = ''; selectedProject.value = null; projectId.value = ''; jobs.value = []; locked.value = false; await session(); busy.value = false })
}
async function logout() { await action(async () => { await api('/auth/logout', send({})); me.value = null; personas.value = []; token.value = ''; jobs.value = []; locked.value = false; busy.value = false }) }
function selectProject(value: { id: string; name?: string }) { selectedProject.value = value as Project }
function navigate(value: 'Review' | 'Activity' | 'Access') { if (!locked.value && !busy.value) page.value = value }
function locationChanged() { if (locked.value) return; const value = new URLSearchParams(location.search).get('page'); page.value = value === 'Activity' ? 'Activity' : value === 'Access' && canAdminister.value ? 'Access' : 'Review' }
watch(page, value => { const params = new URLSearchParams(location.search); params.set('page', value); history.replaceState(null, '', `${location.pathname}?${params}`); token.value = ''; if (me.value && value === 'Activity') void action(loadJobs) })
watch(theme, value => { const selected = ['light', 'dark', 'system'].includes(value) ? value : 'system'; localStorage.setItem('dtvp.theme', selected); document.documentElement.dataset.theme = selected }, { immediate: true })
onMounted(async () => { window.addEventListener('popstate', locationChanged); try { personas.value = await api('/playground/personas') } catch { personas.value = [] }; await action(async () => { try { await session() } catch (err) { if (err instanceof ApiError && err.status === 401) return; throw err } }); const params = new URLSearchParams(location.search); params.set('page', page.value); history.replaceState(null, '', `${location.pathname}?${params}`) })
onUnmounted(() => { ++generation; window.removeEventListener('popstate', locationChanged) })
</script>
<template>
  <div class="app-shell">
    <header class="app-header"><a class="brand" href="/">DTVP <span>Security review</span></a><nav v-if="me" aria-label="Main navigation"><button v-for="item in pages" :key="item" :class="{ current: page === item }" :disabled="busy || locked" @click="navigate(item)">{{ item }}</button></nav><div class="preferences"><label>Theme<select v-model="theme" aria-label="Theme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label><button v-if="me" :disabled="busy" @click="logout">Sign out</button></div></header>
    <div v-if="me?.playground" class="playground-bar"><span>Synthetic playground</span><label v-if="personas.length">Persona<select :value="personas.find(person => person.name === me?.name)?.id" :disabled="busy" @change="login(($event.target as HTMLSelectElement).value)"><option v-for="person in personas" :key="person.id" :value="person.id">{{ person.name }}</option></select></label></div>
    <p v-if="error" role="alert" class="message error">{{ error }}</p><p v-if="notice" role="status" class="message success">{{ notice }}</p>
    <main v-if="!me" class="login"><h1>Security review</h1><p>Sign in to review product composition and security evidence.</p><a class="button primary" href="/auth/login">Sign in</a><label v-if="personas.length">Playground persona<select aria-label="Playground persona" @change="login(($event.target as HTMLSelectElement).value)"><option value="" selected disabled>Choose a synthetic persona</option><option v-for="person in personas" :key="person.id" :value="person.id">{{ person.name }}</option></select></label></main>
    <main v-else><Review v-if="page === 'Review'" :key="me.id" :me="me" @locked="locked = $event" />
      <section v-if="page === 'Activity'" aria-label="Operational activity"><div class="page-title"><h1>Activity</h1><button :disabled="busy" @click="action(loadJobs)">Refresh activity</button></div><p v-if="!jobs.length" class="empty">No background operations.</p><article v-for="job in jobs" :key="job.id" class="job"><div><h2>{{ label(job.kind) }}</h2><span class="badge">{{ label(job.status) }}</span><small v-if="job.project_id">{{ job.project_id }}<template v-if="job.version"> · {{ job.version }}</template></small><p v-if="job.error" class="warning">{{ job.error }}</p><details v-if="Object.keys(job.result || {}).length"><summary>Results</summary><pre>{{ JSON.stringify(job.result, null, 2) }}</pre></details></div></article></section>
      <template v-if="page === 'Access'">
        <div class="page-title"><div><p class="eyebrow">Explicit team access</p><h1>Access and integrations</h1><p>Ownership describes responsibility. Team memberships and sharing control access.</p></div></div>
        <label>Team <select v-model="workspaceId"><option v-for="w in me.workspaces.filter(w => w.capabilities.includes('manage'))" :key="w.id" :value="w.id">{{ w.name }}</option></select></label>
        <div class="columns"><section class="panel"><h2>Member mapping</h2><label>OIDC issuer <input v-model="memberIssuer"></label><label>Subject <input v-model="memberSubject"></label><label>Display name <input v-model="memberName"></label><label>Role <select v-model="memberRole"><option v-for="role in ['viewer', 'analyst', 'reviewer', 'coordinator', 'license_analyst', 'license_reviewer', 'documentary_analyst', 'documentary_reviewer', 'admin']" :key="role">{{ role }}</option></select></label><p class="hint">Administrator permission does not grant approval. Map the verified issuer and subject from your identity provider.</p><button :disabled="busy || !memberIssuer || !memberSubject || !memberName" @click="action(async () => { await api(`/workspaces/${workspaceId}/members`, { method: 'PUT', body: JSON.stringify({ issuer: memberIssuer, subject: memberSubject, name: memberName, roles: [memberRole] }) }); notice = 'Membership saved.' })">Save membership</button></section>
          <section class="panel"><h2>Consumer credential</h2><label>Name <input v-model="tokenName"></label><p class="hint">Create a 24-hour read-only credential for this team. It remains constrained by your current membership.</p><button :disabled="busy || !tokenName" @click="action(async () => { const result = await api<{ token: string }>('/credentials', send({ workspace_id: workspaceId, name: tokenName, capabilities: ['read'], projects: [], hours: 24 })); token = result.token })">Issue read credential</button><label v-if="token">Copy now; shown only once <textarea readonly :value="token"></textarea></label><a href="/openapi.json" target="_blank" rel="noopener">API schema</a></section>
        </div>
        <section v-if="me.workspaces.some(w => w.capabilities.includes('manage'))" class="panel"><h2>Project sharing</h2><SearchSelect v-model="projectId" label="Shared product" :selected-label="selectedProject?.name" endpoint="/catalog/projects" :disabled="busy" @select="selectProject" /><p v-if="!canManage" class="hint">Select a product you manage to change sharing.</p><label>Share with team <select v-model="shareWorkspace"><option v-for="w in me.workspaces.filter(w => w.id !== selectedProject?.workspace_id)" :key="w.id" :value="w.id">{{ w.name }}</option></select></label><label class="toggle"><input v-model="sharedReadOnly" type="checkbox"> Read only</label><button :disabled="busy || !shareWorkspace || !canManage" @click="action(async () => { await api(`/projects/${projectId}/sharing`, { method: 'PUT', body: JSON.stringify({ workspace_id: shareWorkspace, capabilities: sharedReadOnly ? ['read'] : ['read', 'assess', 'approve', 'rescore', 'snapshot', 'evidence', 'license_assess', 'license_approve', 'documentary_assess', 'documentary_approve'] }) }); notice = 'Sharing updated.' })">Save sharing</button></section>
        <section v-if="me.org_admin" class="panel"><h2>Add team workspace</h2><label>Team name <input v-model="workspaceName"></label><button :disabled="busy || !workspaceName" @click="action(async () => { await api('/workspaces', send({ name: workspaceName })); me = await api('/me'); workspaceName = '' })">Create workspace</button></section>
      </template>
    </main>
  </div>
</template>
