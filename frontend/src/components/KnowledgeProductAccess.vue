<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api } from '../api'
import type { Me } from '../types'
type Access = { owner: { id: string; name: string }; grants: { workspace_id: string; workspace_name: string; capabilities: string[] }[]; capabilities: string[] }
type Capture = { project: string; body: { workspace_id: string; capabilities: string[] }; team: string; attempted: boolean }
const props = defineProps<{ me: Me; project: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [value: boolean] }>()
const access = ref<Access | null>(null), busy = ref(false), error = ref(''), notice = ref('')
const workspace = ref(''), mode = ref('read'), captured = ref<Capture | null>(null)
const canManage = computed(() => access.value?.capabilities.includes('manage'))
const choices = computed(() => props.me.workspaces.filter(team => team.id !== access.value?.owner.id))
const locked = computed(() => busy.value || captured.value !== null)
const collaborative = ['read', 'assess', 'approve', 'rescore', 'snapshot', 'evidence', 'license_assess', 'license_approve', 'documentary_assess', 'documentary_approve']
let generation = 0
watch(locked, value => emit('locked', value), { immediate: true })
async function load() {
  if (busy.value || captured.value || !props.project) return
  const current = ++generation, project = props.project; busy.value = true; error.value = ''; access.value = null
  try {
    const result = await api<Access>(`/projects/${encodeURIComponent(project)}/sharing`)
    if (current !== generation) return
    if (!result?.owner?.id || typeof result.owner.name !== 'string' || !Array.isArray(result.grants) || !Array.isArray(result.capabilities)) throw new Error('Product access response unavailable')
    access.value = result
  }
  catch (err) { if (current === generation) error.value = err instanceof Error ? err.message : 'Product access unavailable' }
  finally { if (current === generation) busy.value = false }
}
function review() {
  if (busy.value || props.disabled || !canManage.value || !choices.value.some(team => team.id === workspace.value)) return
  const team = choices.value.find(team => team.id === workspace.value)!
  captured.value = { project: props.project, team: team.name, body: { workspace_id: team.id, capabilities: mode.value === 'remove' ? [] : mode.value === 'read' ? ['read'] : [...collaborative] }, attempted: false }
  error.value = ''; notice.value = ''
}
async function apply() {
  const capture = captured.value
  if (!capture || busy.value || props.disabled) return
  const current = generation; capture.attempted = true; busy.value = true; error.value = ''
  try {
    await api(`/projects/${encodeURIComponent(capture.project)}/sharing`, { method: 'PUT', body: JSON.stringify(capture.body) })
    if (current !== generation) return
    captured.value = null; notice.value = 'Product sharing updated.'
  } catch (err) { if (current === generation) error.value = err instanceof Error ? err.message : 'Sharing update unavailable' }
  finally { if (current === generation) busy.value = false }
  if (current === generation && !captured.value) await load()
}
function cancel() { if (!busy.value) { const attempted = captured.value?.attempted; captured.value = null; error.value = ''; if (attempted) void load() } }
watch(() => [props.project, props.me.id], () => { ++generation; busy.value = false; captured.value = null; access.value = null; workspace.value = ''; mode.value = 'read'; notice.value = ''; void load() }, { immediate: true })
onBeforeUnmount(() => { ++generation; emit('locked', false) })
</script>
<template>
  <section class="panel" aria-label="Product access and sharing">
    <h2>Product access and sharing</h2><p class="hint">Team memberships and explicit grants control access. Component ownership describes responsibility.</p>
    <p v-if="busy" role="status">{{ captured ? 'Updating product sharing…' : 'Loading product access…' }}</p>
    <p v-if="error" role="alert" class="warning">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <template v-if="access"><p>Owner workspace: <strong>{{ access.owner.name }}</strong></p>
      <div v-if="access.grants.length" class="table-wrap"><table><thead><tr><th>Shared team workspace</th><th>Granted capabilities</th></tr></thead><tbody><tr v-for="grant in access.grants" :key="grant.workspace_id"><td>{{ grant.workspace_name }}</td><td>{{ grant.capabilities.length ? grant.capabilities.join(', ') : 'No granted access' }}</td></tr></tbody></table></div>
      <p v-else>No explicit sharing grants.</p>
      <p v-if="!canManage" class="hint">You can inspect sharing. Product management permission is required to change it.</p>
      <div v-else-if="!captured"><label>Share with team<select v-model="workspace" :disabled="disabled || busy"><option value="">Choose a team workspace</option><option v-for="team in choices" :key="team.id" :value="team.id">{{ team.name }}</option></select></label><label>Access grant<select v-model="mode" :disabled="disabled || busy"><option value="read">Read only</option><option value="collaborate">Review collaboration</option><option value="remove">Remove granted access</option></select></label><p class="hint">Collaboration grants {{ collaborative.join(', ') }}. Each action also requires the recipient's current membership capability.</p><p v-if="!choices.length" class="hint">No other team workspaces are available in your current memberships.</p><button :disabled="disabled || busy || !workspace" @click="review">Review sharing update</button></div>
    </template>
    <section v-if="captured" aria-label="Confirm sharing update" class="decision-record"><h3>Review sharing update</h3><p>Team: <strong>{{ captured.team }}</strong></p><p>Replace this team's explicit grant with: <strong>{{ captured.body.capabilities.join(', ') || 'No granted access' }}</strong>.</p><p v-if="captured.attempted" class="hint">The previous request may have completed. Retry sends the same captured product, team and capabilities. Stopping retries does not undo a completed update.</p><button :disabled="disabled || busy" @click="apply">{{ captured.attempted ? 'Retry captured sharing update' : 'Confirm sharing update' }}</button> <button :disabled="busy" @click="cancel">{{ captured.attempted ? 'Stop retrying' : 'Cancel sharing update' }}</button></section>
    <button :disabled="disabled || busy || !!captured" @click="load">Refresh product access</button>
  </section>
</template>
<style scoped>
label { max-width:420px; } td { overflow-wrap:anywhere; } .decision-record { padding:12px; } button { margin-block:4px; }
</style>
