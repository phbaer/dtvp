<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
const props = defineProps<{ project: string; actor: string; kind: 'pipeline' | 'synchronization'; disabled?: boolean }>()
const emit = defineEmits<{ locked: [boolean]; refresh: []; loaded: [Record<string, unknown>] }>()
const busy = ref(false), loaded = ref(false), canConfigure = ref(false), error = ref(''), notice = ref(''), text = ref(''), initial = ref(''), reason = ref(''), confirmed = ref(false)
const current = ref<Record<string, unknown> | null>(null)
const captured = ref<{ endpoint: string; body: Record<string, unknown> } | null>(null)
let generation = 0
const title = computed(() => props.kind === 'pipeline' ? 'Pipeline source roles and threat-model mappings' : 'Automatic synchronization relationships')
const dirty = computed(() => loaded.value && (text.value !== initial.value || !!reason.value))
const locked = computed(() => busy.value || !!captured.value || dirty.value)
const blocked = computed(() => busy.value || props.disabled)
watch(locked, value => emit('locked', value), { immediate: true })
const endpoint = () => `/projects/${encodeURIComponent(props.project)}/${props.kind === 'pipeline' ? 'pipeline-config' : 'synchronization-policy'}`
function reset() { ++generation; busy.value = false; loaded.value = false; canConfigure.value = false; current.value = null; captured.value = null; confirmed.value = false; error.value = ''; notice.value = ''; reason.value = ''; text.value = ''; initial.value = '' }
watch(() => [props.project, props.actor, props.kind], reset)
async function load() {
  if (blocked.value || captured.value || dirty.value) return
  const sequence = ++generation; busy.value = true; error.value = ''
  try {
    const value = await knowledgeApi<Record<string, unknown>>(endpoint())
    if (sequence !== generation) return
    current.value = value; loaded.value = true; canConfigure.value = Array.isArray(value.capabilities) && value.capabilities.includes('configure')
    initial.value = text.value = JSON.stringify(props.kind === 'pipeline' ? value.configuration : { relationships: value.relationships }, null, 2)
    emit('loaded', value)
  } catch (err) { if (sequence === generation) error.value = err instanceof Error ? err.message : 'Configuration unavailable' }
  finally { if (sequence === generation) busy.value = false }
}
function toggle(event: Event) { if ((event.target as HTMLDetailsElement).open && !loaded.value) void load() }
function capture() {
  if (blocked.value || !canConfigure.value || !current.value || captured.value) return
  error.value = ''; notice.value = ''
  try {
    if (text.value.length > 2 * 1024 * 1024) throw new Error('Configuration exceeds 2 MiB.')
    const value: unknown = JSON.parse(text.value)
    if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('Configuration requires a JSON object.')
    if (props.kind === 'pipeline' && !reason.value.trim()) throw new Error('Explain the configuration replacement.')
    const body: Record<string, unknown> = { ...value, request_id: crypto.randomUUID(), expected_policy: props.kind === 'pipeline' ? current.value.configuration_state : current.value.state }
    if (props.kind === 'pipeline') { body.expected_versions = current.value.expected_versions; body.reason = reason.value.trim() }
    captured.value = { endpoint: endpoint(), body }; confirmed.value = false
  } catch (err) { error.value = err instanceof Error ? err.message : 'Invalid configuration JSON' }
}
function discard() { if (busy.value) return; captured.value = null; confirmed.value = false; text.value = initial.value; reason.value = ''; error.value = ''; notice.value = '' }
async function publish() {
  if (blocked.value || !captured.value || !confirmed.value || !canConfigure.value) return
  const sequence = ++generation; busy.value = true; error.value = ''
  try {
    const receipt = await knowledgeApi<{ committed: boolean }>(captured.value.endpoint, { method: 'PUT', body: JSON.stringify(captured.value.body) })
    if (sequence !== generation) return
    if (receipt.committed !== true) throw new Error('Publication uncertain; retry the identical captured request.')
    captured.value = null; confirmed.value = false; reason.value = ''; initial.value = text.value; loaded.value = false
    notice.value = 'Configuration committed. No assessment or approval was applied.'; emit('refresh')
  } catch (err) { if (sequence === generation) error.value = `${err instanceof Error ? err.message : 'Publication unavailable'}. Captured request retained; retry identically or discard explicitly.` }
  finally { if (sequence === generation) busy.value = false }
  if (!captured.value && !loaded.value) await load()
}
onBeforeUnmount(() => { ++generation; emit('locked', false) })
</script>
<template>
  <details class="knowledge-configuration" @toggle="toggle">
    <summary>{{ title }}</summary>
    <section :aria-label="title">
      <p class="hint">{{ kind === 'pipeline' ? 'CI/user declarations bind source roles and model entities. DTVP validates consistency; model authenticity is not inferred.' : 'Prepare proposals on explicit version relationships. Target inventory and independent approvals remain unchanged.' }}</p>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
      <button :disabled="blocked || !!captured || dirty" @click="load">Refresh configuration</button>
      <p v-if="current" class="hint">Policy: <code>{{ current.configuration_state || current.state || 'not configured' }}</code></p>
      <template v-if="loaded && canConfigure">
        <label>{{ kind === 'pipeline' ? 'Pipeline configuration JSON' : 'Synchronization relationships JSON' }}<textarea v-model="text" :disabled="blocked || !!captured" rows="10" spellcheck="false" /></label>
        <label v-if="kind === 'pipeline'">Configuration replacement reason<input v-model="reason" :disabled="blocked || !!captured" maxlength="2000"></label>
        <button :disabled="blocked || !!captured" @click="capture">Review configuration replacement</button>
      </template>
      <pre v-else-if="loaded">{{ initial }}</pre>
      <section v-if="captured" aria-label="Captured configuration replacement">
        <p>Exact request and policy pins retained. Server validates the replacement when published.</p><pre>{{ JSON.stringify(captured.body, null, 2) }}</pre>
        <label><input v-model="confirmed" type="checkbox" :disabled="blocked">I reviewed this configuration replacement</label>
        <button :disabled="blocked || !confirmed" @click="publish">Publish captured configuration</button>
      </section>
      <button v-if="captured || dirty" :disabled="busy" @click="discard">Discard configuration changes</button>
      <p v-for="item in (current?.limitations as string[] || [])" :key="item" class="hint">{{ item }}</p>
    </section>
  </details>
</template>
<style scoped>
.knowledge-configuration{margin-block:1rem}.knowledge-configuration label{display:grid;gap:.35rem;margin-block:.65rem}.knowledge-configuration label:has([type=checkbox]){display:flex;align-items:center}.knowledge-configuration textarea{width:100%;box-sizing:border-box;font-family:monospace;resize:vertical}.knowledge-configuration pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:24rem;overflow:auto}.knowledge-configuration code{overflow-wrap:anywhere}.knowledge-configuration button{margin:.4rem .5rem .4rem 0}.hint{font-size:.875rem;opacity:.8}summary{cursor:pointer}
</style>
