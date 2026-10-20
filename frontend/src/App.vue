<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, onUnmounted, ref, watch } from 'vue'
import { api, ApiError, send } from './api'
import type { Me, Project, Job } from './types'
import { pageFromLocation, type AppPage } from './lib/navigation'
const Review = defineAsyncComponent(() => import('./components/KnowledgeWorkspace.vue'))
const me = ref<Me | null>(null), busy = ref(false), locked = ref(false), error = ref(''), notice = ref('')
const personas = ref<{ id: string; name: string }[]>([]), jobs = ref<Job[]>([])
const jobProjectNames = ref<Record<string, string>>({})
const page = ref<AppPage>(pageFromLocation(location.search))
const menuOpen = ref(false), menuButton = ref<HTMLButtonElement>()
const adminTab = ref<'access' | 'maintenance'>('access')
const canAdminister = computed(() => me.value?.org_admin || me.value?.workspaces.some(team => team.capabilities.includes('manage')))
const pages = computed<AppPage[]>(() => canAdminister.value ? ['My work', 'Products', 'Activity', 'Administration'] : ['My work', 'Products', 'Activity'])
const workspaceView = ref<'products' | 'my-work' | 'maintenance'>(page.value === 'My work' ? 'my-work' : 'products')
// Hidden global destinations must not retarget the retained workspace or its scope.
watch([page, adminTab], ([destination, tab]) => {
  if (destination === 'Products') workspaceView.value = 'products'
  else if (destination === 'My work') workspaceView.value = 'my-work'
  else if (destination === 'Administration' && tab === 'maintenance') workspaceView.value = 'maintenance'
}, { immediate: true })
const workspaceVisible = computed(() => page.value === 'Products' || page.value === 'My work' || (page.value === 'Administration' && adminTab.value === 'maintenance'))
const theme = ref(localStorage.getItem('dtvp.theme') || 'system')
const workspaceId = ref(''), memberIssuer = ref(''), memberSubject = ref(''), memberName = ref(''), memberRole = ref('viewer'), tokenName = ref(''), token = ref(''), workspaceName = ref('')
const label = (value: string) => value.replaceAll('-', ' ').replaceAll('_', ' ')
let generation = 0
async function action(work: () => Promise<void>) {
  if (busy.value) return
  const current = generation; busy.value = true; error.value = ''; notice.value = ''
  try { await work() } catch (err) { if (current === generation) error.value = err instanceof Error ? err.message : 'Request failed' }
  finally { if (current === generation) busy.value = false }
}
async function loadJobs() {
  const current = generation; const result = await api<Job[]>('/jobs')
  if (current !== generation) return
  jobs.value = result
  const projectIds = [...new Set(result.flatMap(job => job.project_id ? [job.project_id] : []))]
  const names = await Promise.allSettled(projectIds.map(async id => { const project = await api<Project>(`/projects/${encodeURIComponent(id)}`); return { id, name: project.name } }))
  if (current !== generation) return
  jobProjectNames.value = Object.fromEntries(names.flatMap(item => item.status === 'fulfilled' && item.value.name ? [[item.value.id, item.value.name]] : []))
}
async function session() {
  me.value = await api<Me>('/me')
  workspaceId.value = me.value.workspaces.find(team => team.capabilities.includes('manage'))?.id || ''
  if (me.value.playground) { try { personas.value = await api('/playground/personas') } catch { personas.value = [] } }
  else personas.value = []
  if (page.value === 'Administration' && !canAdminister.value) page.value = 'Products'
  if (page.value === 'Activity') await loadJobs()
}
async function login(persona: string) {
  // Personas replace the session; old native views/requests are discarded by actor key.
  await action(async () => { await api('/playground/login', send({ persona })); token.value = ''; memberIssuer.value = ''; memberSubject.value = ''; memberName.value = ''; tokenName.value = ''; workspaceName.value = ''; jobs.value = []; jobProjectNames.value = {}; locked.value = false; await session(); busy.value = false })
}
async function logout() { await action(async () => { await api('/auth/logout', send({})); me.value = null; personas.value = []; token.value = ''; jobs.value = []; jobProjectNames.value = {}; locked.value = false; busy.value = false }) }
function navigate(value: AppPage) { if (!locked.value && !busy.value) { page.value = value; menuOpen.value = false } }
function closeMenu() { menuOpen.value = false; menuButton.value?.focus() }
function writeLocation() { const params = new URLSearchParams(location.search); params.set('page', page.value); history.replaceState(null, '', `${location.pathname}?${params}${location.hash}`) }
function locationChanged() { if (locked.value || busy.value) { writeLocation(); return }; const value = pageFromLocation(location.search); page.value = value === 'Administration' && !canAdminister.value ? 'Products' : value }
watch(page, value => { writeLocation(); token.value = ''; if (me.value && value === 'Activity') void action(loadJobs) })
watch(theme, value => { const selected = ['light', 'dark', 'system'].includes(value) ? value : 'system'; localStorage.setItem('dtvp.theme', selected); document.documentElement.dataset.theme = selected }, { immediate: true })
onMounted(async () => { window.addEventListener('popstate', locationChanged); try { personas.value = await api('/playground/personas') } catch { personas.value = [] }; await action(async () => { try { await session() } catch (err) { if (err instanceof ApiError && err.status === 401) return; throw err } }); const params = new URLSearchParams(location.search); params.set('page', page.value); history.replaceState(null, '', `${location.pathname}?${params}`) })
onUnmounted(() => { ++generation; window.removeEventListener('popstate', locationChanged) })
</script>
<template>
  <div class="app-shell">
    <a class="skip-link" href="#app-main">Skip to content</a>
    <aside v-if="me" class="app-sidebar" @keydown.esc="closeMenu">
      <a class="brand" href="?page=Products" @click.prevent="navigate('Products')">DTVP <span>Security review</span></a>
      <button ref="menuButton" class="mobile-menu-toggle" aria-controls="application-navigation" :aria-expanded="menuOpen" @click="menuOpen = !menuOpen">{{ menuOpen ? 'Close menu' : 'Menu' }}</button>
      <nav id="application-navigation" aria-label="Main navigation" :class="{ expanded: menuOpen }"><button v-for="item in pages" :key="item" :class="{ current: page === item }" :aria-current="page === item ? 'page' : undefined" :disabled="busy || locked" @click="navigate(item)">{{ item }}</button></nav>
      <p class="sidebar-caption">One shared workspace.<br>Actions follow permissions.</p>
    </aside>
    <div class="app-body" :class="{ authenticated: me }">
    <header class="app-header"><span v-if="me" class="app-location">{{ page }}</span><a v-else class="brand" href="/">DTVP</a><div class="preferences"><span v-if="me?.playground" class="playground-indicator">Synthetic playground</span><label v-if="me?.playground && personas.length">Persona<select :value="personas.find(person => person.name === me?.name)?.id" :disabled="busy" @change="login(($event.target as HTMLSelectElement).value)"><option v-for="person in personas" :key="person.id" :value="person.id">{{ person.name }}</option></select></label><label>Theme<select v-model="theme" aria-label="Theme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label><button v-if="me" :disabled="busy" @click="logout">Sign out</button></div></header>
    <p v-if="error" role="alert" class="message error">{{ error }}</p><p v-if="notice" role="status" class="message success">{{ notice }}</p>
    <main v-if="!me" id="app-main" tabindex="-1" class="login"><h1>Security review</h1><p>Sign in to review product composition and security evidence.</p><a class="button primary" href="/auth/login">Sign in</a><label v-if="personas.length">Playground persona<select aria-label="Playground persona" @change="login(($event.target as HTMLSelectElement).value)"><option value="" selected disabled>Choose a synthetic persona</option><option v-for="person in personas" :key="person.id" :value="person.id">{{ person.name }}</option></select></label></main>
    <main v-else id="app-main" tabindex="-1">
      <div v-if="page === 'Administration'" class="administration-heading"><div class="page-title"><div><p class="eyebrow">Organization and product configuration</p><h1>Administration</h1></div></div><nav aria-label="Administration"><button :class="{current: adminTab === 'access'}" :aria-current="adminTab === 'access' ? 'page' : undefined" :disabled="busy || locked" @click="adminTab = 'access'">Access and integrations</button><button :class="{current: adminTab === 'maintenance'}" :aria-current="adminTab === 'maintenance' ? 'page' : undefined" :disabled="busy || locked" @click="adminTab = 'maintenance'">Product maintenance</button></nav></div>
      <Review v-show="workspaceVisible" :key="me.id" :me="me" :view="workspaceView" @locked="locked = $event" />
      <section v-if="page === 'Activity'" aria-label="Operational activity"><div class="page-title"><h1>Activity</h1><button :disabled="busy" @click="action(loadJobs)">Refresh activity</button></div><p v-if="!jobs.length" class="empty">No background operations.</p><article v-for="job in jobs" :key="job.id" class="job"><div><h2>{{ label(job.kind) }}</h2><span class="badge">{{ label(job.status) }}</span><small v-if="job.project_id">{{ jobProjectNames[job.project_id] || `Product ID: ${job.project_id}` }}<template v-if="job.version"> · {{ job.version }}</template></small><p v-if="job.error" class="warning">{{ job.error }}</p><details v-if="Object.keys(job.result || {}).length"><summary>Results</summary><pre>{{ JSON.stringify(job.result, null, 2) }}</pre></details></div></article></section>
      <template v-if="page === 'Administration' && adminTab === 'access'">
        <div class="page-title"><div><p class="eyebrow">Explicit team access</p><h2>Access and integrations</h2><p>Ownership describes responsibility. Team memberships and sharing control access.</p></div></div>
        <label>Team <select v-model="workspaceId"><option v-for="w in me.workspaces.filter(w => w.capabilities.includes('manage'))" :key="w.id" :value="w.id">{{ w.name }}</option></select></label>
        <div class="columns"><section class="panel"><h2>Member mapping</h2><label>OIDC issuer <input v-model="memberIssuer"></label><label>Subject <input v-model="memberSubject"></label><label>Display name <input v-model="memberName"></label><label>Role <select v-model="memberRole"><option v-for="role in ['viewer', 'analyst', 'reviewer', 'coordinator', 'license_analyst', 'license_reviewer', 'documentary_analyst', 'documentary_reviewer', 'admin']" :key="role">{{ role }}</option></select></label><p class="hint">Administrator permission does not grant approval. Map the verified issuer and subject from your identity provider.</p><button :disabled="busy || !memberIssuer || !memberSubject || !memberName" @click="action(async () => { await api(`/workspaces/${workspaceId}/members`, { method: 'PUT', body: JSON.stringify({ issuer: memberIssuer, subject: memberSubject, name: memberName, roles: [memberRole] }) }); notice = 'Membership saved.' })">Save membership</button></section>
          <section class="panel"><h2>Consumer credential</h2><label>Name <input v-model="tokenName"></label><p class="hint">Create a 24-hour read-only credential for this team. It remains constrained by your current membership.</p><button :disabled="busy || !tokenName" @click="action(async () => { const result = await api<{ token: string }>('/credentials', send({ workspace_id: workspaceId, name: tokenName, capabilities: ['read'], projects: [], hours: 24 })); token = result.token })">Issue read credential</button><label v-if="token">Copy now; shown only once <textarea readonly :value="token"></textarea></label><a href="/openapi.json" target="_blank" rel="noopener">API schema</a></section>
        </div>

        <section v-if="me.org_admin" class="panel"><h2>Add team workspace</h2><label>Team name <input v-model="workspaceName"></label><button :disabled="busy || !workspaceName" @click="action(async () => { await api('/workspaces', send({ name: workspaceName })); me = await api('/me'); workspaceName = '' })">Create workspace</button></section>
      </template>
    </main>
    </div>
  </div>
</template>

<style scoped>
.app-shell { min-height:100vh; }
.app-sidebar { position:fixed; inset:0 auto 0 0; width:190px; padding:24px 14px; background:var(--surface); border-right:1px solid var(--line); display:flex; flex-direction:column; gap:26px; z-index:8; }
.app-sidebar .brand { padding:0 10px; font-size:1.5rem; }
.app-sidebar .brand span { display:block; margin:5px 0 0; font-size:.78rem; letter-spacing:0; }
.app-sidebar nav { display:flex; flex-direction:column; gap:5px; width:100%; }
.app-sidebar nav button { justify-content:flex-start; padding:10px 12px; border-radius:5px; }
.app-sidebar nav button.current { background:var(--accent-soft); color:var(--accent); font-weight:650; }
.sidebar-caption { margin:auto 10px 0; color:var(--muted); font-size:.78rem; }
.app-body.authenticated { margin-left:190px; min-width:0; }
.app-header { min-height:52px; padding:8px 24px; gap:12px; }
.app-location { color:var(--muted); font-size:.85rem; }
.preferences { flex-wrap:wrap; justify-content:flex-end; gap:12px; }
.preferences select { max-width:185px; }
.playground-indicator { color:var(--muted); font-size:.75rem; }
.administration-heading { margin-bottom:20px; }
.administration-heading .page-title { margin-bottom:10px; }
.administration-heading nav { flex-wrap:wrap; }
.mobile-menu-toggle { display:none; }
.skip-link { position:fixed; left:12px; top:-80px; z-index:30; padding:10px; background:var(--surface); }
.skip-link:focus { top:10px; }
@media(max-width:900px) {
 .app-sidebar { position:sticky; top:0; width:100%; padding:10px 14px; display:flex; flex-direction:row; align-items:center; flex-wrap:wrap; gap:10px; border-right:0; border-bottom:1px solid var(--line); }
 .app-sidebar .brand { font-size:1.15rem; padding:0; }
 .app-sidebar .brand span,.sidebar-caption { display:none; }
 .mobile-menu-toggle { display:inline-flex; margin-left:auto; }
 .app-sidebar nav { display:none; flex-basis:100%; order:3; }
 .app-sidebar nav.expanded { display:flex; }
 .app-body.authenticated { margin-left:0; }
 .app-header { padding:8px 12px; }
 .app-location,.playground-indicator { display:none; }
 .preferences { gap:8px; margin-left:0; width:100%; }
 .preferences label { font-size:.8rem; }
 .preferences select { max-width:145px; }
}
</style>
