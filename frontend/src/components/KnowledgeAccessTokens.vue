<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api, send } from '../api'
import SearchSelect from './SearchSelect.vue'
type Token = { id: string; name: string; workspace_id: string; projects: string[]; capabilities: string[]; expires_at: string; revoked: boolean }
const props = defineProps<{ workspace: string; disabled?: boolean }>()
const emit = defineEmits<{ busy: [value: boolean] }>()
const name = ref(''), days = ref(365), profile = ref('ci'), scope = ref('all'), picker = ref('')
const projects = ref<{ id: string; name: string }[]>([]), tokens = ref<Token[]>([])
const busy = ref(false), error = ref(''), secret = ref(''), issued = ref<{ id: string; expires_at: string; workspace: string } | null>(null)
const attempted = ref(false), confirmRevoke = ref('')
const capabilities = computed(() => profile.value === 'consumer' ? ['read'] : profile.value === 'evidence' ? ['read', 'write', 'evidence'] : ['read', 'write'])
const visible = computed(() => tokens.value.filter(token => token.workspace_id === props.workspace))
let sequence = 0
watch(busy, value => emit('busy', value), { flush: 'sync' })
async function load() {
  if (busy.value) return
  const current = ++sequence; busy.value = true; error.value = ''
  try { const result = await api<Token[]>('/credentials'); if (!Array.isArray(result)) throw new Error('Token list unavailable'); if (current === sequence) tokens.value = result }
  catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Tokens unavailable' }
  finally { if (current === sequence) busy.value = false }
}
function addProject(project: { id: string; name?: string }) { if (!projects.value.some(item => item.id === project.id) && projects.value.length < 100) projects.value.push({ id: project.id, name: project.name || project.id }); picker.value = '' }
async function create() {
  if (busy.value || props.disabled || attempted.value || !props.workspace || !name.value.trim() || !Number.isInteger(days.value) || days.value < 1 || days.value > 3650 || (scope.value === 'selected' && !projects.value.length)) return
  const current = ++sequence, workspace = props.workspace; busy.value = true; error.value = ''; attempted.value = true
  try {
    const result = await api<{ id: string; token: string; expires_at: string }>('/credentials', send({ workspace_id: workspace, name: name.value.trim(), capabilities: capabilities.value, projects: scope.value === 'selected' ? projects.value.map(project => project.id) : [], hours: days.value * 24 }))
    if (current !== sequence) return
    secret.value = result.token; issued.value = { id: result.id, expires_at: result.expires_at, workspace }
    const listed = await api<Token[]>('/credentials'); if (!Array.isArray(listed)) throw new Error('Token list unavailable'); if (current === sequence) tokens.value = listed
  } catch (err) { if (current === sequence) error.value = secret.value ? 'Token created; list refresh failed. Copy the secret now.' : `${err instanceof Error ? err.message : 'Creation not confirmed'}. Inspect the token list before creating another; this request is not retried automatically.` }
  finally { if (current === sequence) busy.value = false }
}
function reset() { if (!busy.value) { attempted.value = false; secret.value = ''; issued.value = null; error.value = ''; name.value = '' } }
async function revoke(id: string) {
  if (busy.value || props.disabled || confirmRevoke.value !== id) return
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    await api(`/credentials/${encodeURIComponent(id)}`, { method: 'DELETE' })
    if (current !== sequence) return
    if (issued.value?.id === id) secret.value = ''
    confirmRevoke.value = ''; const listed = await api<Token[]>('/credentials'); if (!Array.isArray(listed)) throw new Error('Token list unavailable'); if (current === sequence) tokens.value = listed
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Revocation not confirmed; refresh the list' }
  finally { if (current === sequence) busy.value = false }
}
watch(() => props.workspace, () => { ++sequence; busy.value = false; reset(); projects.value = []; confirmRevoke.value = ''; void load() }, { immediate: true })
onBeforeUnmount(() => { ++sequence; emit('busy', false) })
</script>
<template>
  <section class="panel access-tokens" aria-label="CI and consumer access tokens">
    <h2>CI and consumer access tokens</h2>
    <p class="hint">Tokens remain limited by the issuing account's current team permissions. Create a replacement before revoking an old token to rotate CI secrets.</p>
    <p v-if="error" role="alert" class="warning">{{ error }}</p>
    <form @submit.prevent="create"><fieldset :disabled="disabled || busy || attempted || !workspace">
      <label>Token name<input v-model="name" required maxlength="200" placeholder="Nightly SBOM pipeline"></label>
      <div class="form-row"><label>Token profile<select v-model="profile"><option value="ci">CI SBOM import · read, write</option><option value="evidence">CI import and evidence · read, write, evidence</option><option value="consumer">Read-only consumer</option></select></label><label>Lifetime (days)<input v-model.number="days" type="number" min="1" max="3650" step="1" required></label></div>
      <label>Product scope<select v-model="scope"><option value="all">All accessible products for this team, including future products</option><option value="selected">Selected existing products</option></select></label>
      <template v-if="scope === 'selected'"><SearchSelect v-model="picker" label="Add token product" endpoint="/catalog/projects" @select="addProject" /><ul><li v-for="project in projects" :key="project.id">{{ project.name }} <button type="button" @click="projects = projects.filter(item => item.id !== project.id)">Remove {{ project.name }}</button></li></ul><p class="hint">A product-restricted token cannot create new products.</p></template>
      <button :disabled="!name.trim() || (scope === 'selected' && !projects.length)">Issue access token</button>
    </fieldset></form>
    <div v-if="secret && issued" role="status"><label>Copy now; shown only once<textarea readonly :value="secret" spellcheck="false" autocomplete="off"></textarea></label><p>Expires {{ new Date(issued.expires_at).toLocaleString() }} · Token ID {{ issued.id }}</p></div>
    <button v-if="attempted" :disabled="disabled || busy" @click="reset">Start another token request</button>
    <div class="token-heading"><h3>Your tokens for this team</h3><button :disabled="disabled || busy" @click="load">Refresh tokens</button></div>
    <p v-if="busy" role="status">Working…</p>
    <div v-if="visible.length" class="table-wrap"><table><thead><tr><th>Name</th><th>Permissions / products</th><th>Expiry / status</th><th>Action</th></tr></thead><tbody><tr v-for="token in visible" :key="token.id"><td>{{ token.name }}<small>{{ token.id }}</small></td><td>{{ token.capabilities.join(', ') }}<small>{{ token.projects.length ? `${token.projects.length} selected products` : 'All accessible team products' }}</small></td><td>{{ new Date(token.expires_at).toLocaleString() }}<small>{{ token.revoked ? 'Revoked' : Date.parse(token.expires_at) <= Date.now() ? 'Expired' : 'Active' }}</small></td><td><template v-if="confirmRevoke === token.id"><button :disabled="disabled || busy" @click="revoke(token.id)">Confirm revoke {{ token.name }}</button><button :disabled="disabled || busy" @click="confirmRevoke = ''">Cancel</button></template><button v-else :disabled="disabled || busy || token.revoked" @click="confirmRevoke = token.id">Revoke {{ token.name }}</button></td></tr></tbody></table></div>
    <p v-else-if="!busy" class="hint">No tokens issued by your account for this team.</p>
    <a href="/openapi.json" target="_blank" rel="noopener">API schema</a>
  </section>
</template>
<style scoped>
fieldset{border:0;padding:0;min-width:0}label{max-width:560px}.form-row{gap:12px}.form-row label{min-width:0}.token-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:20px}.token-heading h3{margin:0}td{overflow-wrap:anywhere}small{white-space:normal}.access-tokens{min-width:0}button{margin-block:3px}textarea{font-family:monospace}
</style>
