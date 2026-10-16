<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError, send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeCpeSources from './KnowledgeCpeSources.vue'
type Configuration = { algorithm_version: string; catalog: unknown[]; rules: Record<string, unknown>; offline_sources?: Record<string, { source: string; revision: string; occurred_at: string; artifact_sha256: string; records: number; losses: Record<string, number> }> }
type Editor = { policy_state: string | null; configuration: Configuration; capabilities: string[]; limitations: string[] }
type Input = { request_id: string; expected: string | null; catalog: unknown[]; rules: Record<string, unknown> }
type Preview = { committed: false; policy_state: string | null; preview_digest: string; configuration: Configuration; changes: Record<string, number>; limitations: string[] }
const props = defineProps<{ project: string }>()
const emit = defineEmits<{ locked: [boolean] }>()
const sourceLocked = ref(false)
const opened = ref(false), busy = ref(false), loaded = ref<Editor | null>(null), error = ref(''), notice = ref('')
const catalog = ref('[]'), rules = ref('{}'), editing = ref(false), expected = ref<string | null>(null)
const frozen = ref<Input | null>(null), preview = ref<Preview | null>(null), attempted = ref(false), confirmed = ref(false)
let sequence = 0
watch(() => sourceLocked.value || busy.value || editing.value, value => emit('locked', value))
const canConfigure = computed(() => loaded.value?.capabilities.includes('configure') === true)
const stale = computed(() => Boolean(frozen.value && loaded.value && frozen.value.expected !== loaded.value.policy_state))
const path = () => `/projects/${encodeURIComponent(props.project)}/cpe`
async function load() {
  if (busy.value) return
  const current = ++sequence; busy.value = true; error.value = ''
  try { const result = await knowledgeApi<Editor>(`${path()}/editor`); if (current === sequence) loaded.value = result }
  catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'CPE policy unavailable' }
  finally { if (current === sequence) busy.value = false }
}
function toggle(event: Event) { opened.value = (event.target as HTMLDetailsElement).open; if (opened.value && !loaded.value) void load() }
function start() {
  if (busy.value || sourceLocked.value || !loaded.value || !canConfigure.value) return
  catalog.value = JSON.stringify(loaded.value.configuration.catalog, null, 2); rules.value = JSON.stringify(loaded.value.configuration.rules, null, 2)
  expected.value = loaded.value.policy_state; frozen.value = null; preview.value = null; attempted.value = false; confirmed.value = false; editing.value = true; error.value = ''; notice.value = ''
}
async function inspect() {
  if (busy.value || !canConfigure.value) return
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    if (!frozen.value) {
      if (new Blob([catalog.value, rules.value]).size > 8 * 1024 * 1024) throw new Error('Policy editor supports at most 8 MiB. Use the API for larger supported inputs.')
      const entries = JSON.parse(catalog.value), mappings = JSON.parse(rules.value)
      if (!Array.isArray(entries) || !mappings || typeof mappings !== 'object' || Array.isArray(mappings)) throw new Error('Catalog must be a JSON array and rules a JSON object.')
      frozen.value = { request_id: crypto.randomUUID(), expected: expected.value, catalog: entries, rules: mappings }
    }
    const result = await knowledgeApi<Preview>(`${path()}/preview`, send(frozen.value))
    if (current !== sequence) return
    if (result.policy_state !== frozen.value.expected || result.committed !== false) throw new Error('Preview does not match the captured policy state.')
    preview.value = result; confirmed.value = false
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Policy preview unavailable' }
  finally { if (current === sequence) busy.value = false }
}
async function publish() {
  if (busy.value || !frozen.value || !preview.value || !confirmed.value || !canConfigure.value || (stale.value && !attempted.value)) return
  const current = ++sequence; busy.value = true; error.value = ''; attempted.value = true
  try {
    const receipt = await knowledgeApi<{ committed: boolean; projection?: string }>(path(), { method: 'PUT', body: JSON.stringify(frozen.value) })
    if (current !== sequence) return
    if (receipt.committed !== true) throw new Error('Policy publication uncertain; retry the identical request.')
    notice.value = 'CPE discovery policy committed. No component identity, vulnerability assessment or approval was adopted. Refresh candidate discovery explicitly to use this policy.'
    frozen.value = null; preview.value = null; editing.value = false; attempted.value = false; confirmed.value = false
  } catch (err) { if (current === sequence) error.value = err instanceof ApiError && err.status === 409 ? 'The captured policy or request conflicts. Inputs and request ID are retained; explicitly discard them and load current policy before preparing a replacement.' : 'Policy publication failed or may be uncertain. Retry the identical captured request; refreshing the policy does not repin it.' }
  finally { if (current === sequence) busy.value = false }
  if (!error.value) await load()
}
function cancelEditing() { if (busy.value) return; frozen.value = null; preview.value = null; editing.value = false; attempted.value = false; confirmed.value = false; error.value = '' }
function editCaptured() { if (busy.value) return; frozen.value = null; preview.value = null; attempted.value = false; confirmed.value = false; error.value = '' }
onBeforeUnmount(() => { ++sequence; emit('locked', false) })
</script>
<template>
  <details class="knowledge-cpe-policy" aria-label="CPE discovery policy" @toggle="toggle">
    <summary>CPE discovery policy and reviewed mappings</summary>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <p class="hint">Offline supplied identities and attributed rules. Discovery candidates do not establish vulnerability applicability or approved component identities.</p>
    <button :disabled="busy || sourceLocked" @click="load">Refresh current CPE policy</button>
    <template v-if="loaded">
      <p>{{ loaded.configuration.catalog.length }} catalog entries · {{ Object.keys(loaded.configuration.rules).length }} mapping rules</p>
      <details><summary>Current policy, attribution and limits</summary><code>{{ loaded.policy_state || 'No configured policy' }}</code><ul><li v-for="limit in loaded.limitations" :key="limit">{{ limit }}</li></ul><pre>{{ JSON.stringify(loaded.configuration, null, 2) }}</pre></details>
      <button v-if="canConfigure" :disabled="busy || sourceLocked" @click="start">{{ editing ? 'Discard edits and start from loaded policy' : 'Prepare complete policy replacement' }}</button>
      <form v-if="editing && canConfigure" aria-label="Replace CPE discovery policy" @submit.prevent="inspect">
        <p class="hint">This replaces the whole catalog and rule set. Preserve required entries and source attribution; omitted entries are removed from the current policy, with history retained.</p>
        <fieldset :disabled="busy || !!frozen"><label>Supplied CPE catalog JSON<textarea v-model="catalog" rows="6" spellcheck="false" /></label><label>Reviewed mapping rules JSON<textarea v-model="rules" rows="6" spellcheck="false" /></label></fieldset>
        <button v-if="!preview" :disabled="busy">{{ frozen ? 'Retry exact policy preview' : 'Preview complete policy replacement' }}</button>
      </form>
      <section v-if="preview && frozen" aria-label="CPE policy replacement preview">
        <p v-if="stale" role="status">The loaded policy changed. This request still uses its original policy state.</p>
        <dl><template v-for="(count, name) in preview.changes" :key="name"><dt>{{ name.replaceAll('_', ' ') }}</dt><dd>{{ count }}</dd></template></dl>
        <p v-for="limit in preview.limitations" :key="limit" class="hint">{{ limit }}</p>
        <details><summary>Normalized policy and exact request</summary><code>{{ preview.preview_digest }}</code><pre>{{ JSON.stringify({ normalized: preview.configuration, request: frozen }, null, 2) }}</pre></details>
        <label><input v-model="confirmed" type="checkbox" :disabled="busy || attempted"> I checked the complete replacement, including removals and source attribution.</label>
        <button :disabled="busy || !confirmed || (stale && !attempted) || !canConfigure" @click="publish">{{ attempted ? 'Retry identical CPE policy publication' : 'Publish previewed CPE policy' }}</button>
      </section>
      <button v-if="frozen" :disabled="busy" @click="editCaptured">Discard captured request and edit original inputs</button>
      <button v-if="editing" :disabled="busy" @click="cancelEditing">Discard CPE policy edits</button>
      <KnowledgeCpeSources :project="project" :policy="loaded.policy_state" :sources="loaded.configuration.offline_sources" :can-configure="canConfigure" :disabled="busy || editing" @locked="sourceLocked = $event" @refresh="load" />
    </template>
    <p v-if="busy" role="status">CPE policy request in progress…</p>
  </details>
</template>
<style scoped>
.knowledge-cpe-policy{margin:12px 0;border:1px solid var(--line);border-radius:8px;padding:12px;min-width:0}.knowledge-cpe-policy summary{cursor:pointer}.knowledge-cpe-policy label{display:block;margin:10px 0}.knowledge-cpe-policy fieldset{border:0;padding:0;min-width:0}.knowledge-cpe-policy textarea{width:100%;max-width:100%;box-sizing:border-box;font-family:monospace;font-size:.8rem}.knowledge-cpe-policy pre,.knowledge-cpe-policy code{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.75rem}.knowledge-cpe-policy pre{max-height:250px;overflow:auto}.knowledge-cpe-policy button{margin:6px 8px 6px 0}.knowledge-cpe-policy input[type=checkbox]{width:auto}.hint{color:var(--muted);font-size:.8rem}.knowledge-cpe-policy dl{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px;max-width:400px}.knowledge-cpe-policy dd{margin:0}
</style>
