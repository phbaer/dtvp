<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeDependencyNeighbors from './KnowledgeDependencyNeighbors.vue'
type Annotations = { cybersecurity: { criticality: string; exposure: string; mitigations: string[]; testing_evidence: string[] }; deployment: { environment: string; usage: string; configuration: string }; support: { status: string; supplier: string; support_until: string | null; end_of_life: string | null; references: string[] }; notes: string; properties: Record<string, string> }
type RecordData = { revision: string; status: string; applicable: boolean; payload: { annotations: Annotations; provenance: { source: string; reference: string; observed_at?: string | null }; rationale: string; actor_id: string; created_at: string } }
type Neighbor = { ref: string; name: string; version: string; resolved: boolean }
type ContextData = { state: string; head: string; version: string; component_ref: string; component: Record<string, unknown>; metadata: RecordData | null; defaults: Annotations; capabilities: string[]; blocked_reasons: string[]; limitations: string[]; topology: { dependency_graph: string; consuming_root: string | null; incoming: Neighbor[]; outgoing: Neighbor[]; incoming_total: number; outgoing_total: number; neighbor_limit: number; limitations: string[] } }
const props = defineProps<{ project: string; state: string; version: string; componentRef: string; contextId?: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [value: boolean]; changed: []; refresh: [] }>()
const data = ref<ContextData | null>(null), busy = ref(false), error = ref(''), notice = ref(''), expanded = ref(false), editing = ref(false)
const modal = ref<HTMLDialogElement | null>(null), annotations = ref<Annotations | null>(null), source = ref(''), reference = ref(''), observed = ref(''), rationale = ref(''), acknowledged = ref(false), advanced = ref('')
const captured = ref<{ project: string; version: string; body: Record<string, unknown> } | null>(null)
let sequence = 0
const endpoint = () => `/projects/${encodeURIComponent(props.project)}`
const failure = (value: unknown) => value instanceof Error ? value.message : 'Component context request failed'
const stale = computed(() => data.value?.metadata && !data.value.metadata.applicable)
async function load() {
  if (busy.value || captured.value || !props.componentRef) return
  const current = ++sequence
  busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<ContextData>(`${endpoint()}/states/${props.state}/component-context?${new URLSearchParams({ component_ref: props.componentRef, ...(props.contextId ? { context_id: props.contextId } : {}) })}`)
    if (current === sequence) data.value = result
  } catch (value) { if (current === sequence) error.value = failure(value) }
  finally { if (current === sequence) busy.value = false }
}
function toggle(event: Event) { expanded.value = (event.currentTarget as HTMLDetailsElement).open; if (expanded.value && !data.value) void load() }
async function edit() {
  if (busy.value || props.disabled || !data.value?.capabilities.includes('curate')) return
  const record = data.value.metadata
  annotations.value = JSON.parse(JSON.stringify(record?.payload.annotations || data.value.defaults))
  source.value = record?.payload.provenance.source || ''; reference.value = record?.payload.provenance.reference || ''; observed.value = record?.payload.provenance.observed_at || ''
  rationale.value = ''; acknowledged.value = false; advanced.value = JSON.stringify(annotations.value, null, 2); editing.value = true; error.value = ''; notice.value = ''; emit('locked', true)
  await nextTick(); modal.value?.showModal()
}
function applyAdvanced() {
  try {
    const value = JSON.parse(advanced.value)
    if (!value || typeof value !== 'object' || Array.isArray(value) || !['cybersecurity', 'deployment', 'support'].every(key => value[key] && typeof value[key] === 'object' && !Array.isArray(value[key]))) throw new Error('Keep the typed cybersecurity, deployment and support objects. The server validates all annotation fields.')
    annotations.value = value; error.value = ''
  } catch (value) { error.value = failure(value) }
}
function reviewCapture() {
  if (busy.value || captured.value || !data.value?.capabilities.includes('curate') || !annotations.value || !acknowledged.value || !rationale.value.trim() || !source.value.trim()) return
  const draft = JSON.parse(JSON.stringify(annotations.value))
  draft.support.support_until ||= null; draft.support.end_of_life ||= null
  captured.value = { project: props.project, version: data.value.version, body: { request_id: crypto.randomUUID(), expected: data.value.state, expected_revision: data.value.metadata?.revision || null, component_ref: data.value.component_ref, annotations: draft, provenance: { source: source.value, reference: reference.value, observed_at: observed.value || null }, rationale: rationale.value } }
}
async function publish() {
  const capture = captured.value
  if (busy.value || !capture) return
  const current = ++sequence
  busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<{ committed: boolean | null; projection?: string }>(`/projects/${encodeURIComponent(capture.project)}/versions/${encodeURIComponent(capture.version)}/metadata`, { method: 'PUT', body: JSON.stringify(capture.body) })
    if (current !== sequence) return
    if (result.committed !== true) throw new Error('Publication is uncertain; retry the identical captured annotations.')
    captured.value = null; editing.value = false; modal.value?.close(); emit('locked', false); notice.value = 'Component annotations recorded. Imported facts and historical decisions are retained; affected assessments may need review.'; data.value = null; emit('changed')
  } catch (value) { if (current === sequence) error.value = `${failure(value)}. Exact annotations, expected state/revision and request ID are retained. Retry unchanged or explicitly discard and refresh; no head was repinned.` }
  finally { if (current === sequence) busy.value = false }
}
function discard() { if (busy.value) return; captured.value = null; editing.value = false; modal.value?.close(); emit('locked', false); error.value = ''; annotations.value = null }
function discardAndRefresh() { if (busy.value) return; discard(); emit('refresh') }
function cancel(event: Event) { event.preventDefault(); if (!captured.value && !busy.value) discard() }
watch(() => [props.project, props.state, props.componentRef, props.contextId], () => { if (captured.value || editing.value) return; ++sequence; busy.value = false; data.value = null; error.value = ''; if (expanded.value) void load() })
onBeforeUnmount(() => { ++sequence; modal.value?.close(); emit('locked', false) })
</script>
<template>
  <details class="component-context" @toggle="toggle"><summary>Component context, dependencies and annotations</summary>
    <p v-if="busy && !editing" role="status">Loading pinned component context…</p><p v-if="error && !editing" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <template v-if="data"><p class="hint">Authored context applies to this component occurrence in {{ data.version }}. It does not establish vulnerability applicability, license clearance or architectural approval.</p>
      <dl><dt>Criticality / exposure</dt><dd>{{ data.metadata?.applicable ? data.metadata.payload.annotations.cybersecurity.criticality + ' / ' + data.metadata.payload.annotations.cybersecurity.exposure : 'Unknown (no current annotations)' }}</dd><dt>Runtime / usage</dt><dd>{{ data.metadata?.applicable ? data.metadata.payload.annotations.deployment.usage || 'Unknown' : 'Unknown' }}</dd><dt>Deployment</dt><dd>{{ data.metadata?.applicable ? data.metadata.payload.annotations.deployment.environment || 'Unknown' : 'Unknown' }}</dd></dl>
      <p v-if="stale" class="warning">Retained annotations are {{ data.metadata!.status }} and do not currently apply. Review their provenance and each field before explicitly replacing them.</p>
      <details v-if="data.metadata"><summary>Authored annotation provenance and retained values</summary><p>{{ data.metadata.payload.provenance.source }} · {{ data.metadata.payload.provenance.reference || 'No reference' }} · {{ data.metadata.payload.provenance.observed_at || 'Observation time unknown' }}</p><p>{{ data.metadata.payload.rationale }}</p><p>Recorded by {{ data.metadata.payload.actor_id }} · {{ data.metadata.payload.created_at }}</p><pre>{{ JSON.stringify(data.metadata, null, 2) }}</pre></details>
      <details><summary>Declared dependency neighborhood · {{ data.topology.dependency_graph }}</summary><p>Consuming root: {{ data.topology.consuming_root || 'Not selected' }}</p><p>Used by: {{ data.topology.incoming_total }} declared edges · Depends on: {{ data.topology.outgoing_total }} declared edges.</p><KnowledgeDependencyNeighbors :project="project" :state="data.state" :component-ref="data.component_ref" :incoming="data.topology.incoming" :outgoing="data.topology.outgoing" :incoming-total="data.topology.incoming_total" :outgoing-total="data.topology.outgoing_total" :disabled="disabled || busy || editing" /><ul><li v-for="limitation in data.topology.limitations" :key="limitation">{{ limitation }}</li></ul></details>
      <details><summary>Imported component facts</summary><pre>{{ JSON.stringify(data.component, null, 2) }}</pre></details>
      <button v-if="data.capabilities.includes('curate')" :disabled="busy || disabled" @click="edit">Edit component annotations</button><p v-else class="hint">Read only: {{ data.blocked_reasons.map(reason => reason.replaceAll('_', ' ')).join('; ') }}.</p>
    </template>
    <dialog ref="modal" aria-labelledby="component-metadata-title" @cancel="cancel"><section v-if="editing && annotations" class="component-editor"><header><h3 id="component-metadata-title">Component annotations</h3><button type="button" :disabled="busy || !!captured" aria-label="Close component annotation editor" @click="discard">×</button></header><p>{{ componentRef }} · {{ version }}</p><p class="hint">Changes affect review evidence throughout this component's consuming trees. Imported source data and human decisions remain retained.</p><p v-if="stale" class="warning">Previous annotations do not currently apply. Saving explicitly records reviewed replacement values for this occurrence/version.</p><p v-if="error" role="alert">{{ error }}</p>
      <form v-if="!captured" aria-label="Edit component annotations" @submit.prevent="reviewCapture"><fieldset :disabled="busy"><div class="component-fields"><label>Cybersecurity criticality<select v-model="annotations.cybersecurity.criticality"><option v-for="value in ['unknown', 'low', 'moderate', 'high', 'critical']" :key="value" :value="value">{{ value }}</option></select></label><label>Exposure<select v-model="annotations.cybersecurity.exposure"><option v-for="value in ['unknown', 'not_exposed', 'internal', 'external']" :key="value" :value="value">{{ value.replaceAll('_', ' ') }}</option></select></label></div><label>Runtime usage<textarea v-model="annotations.deployment.usage" rows="2" maxlength="6000" /></label><label>Deployment environment<input v-model="annotations.deployment.environment" maxlength="6000"></label><details><summary>Configuration, support and additional evidence</summary><label>Configuration<textarea v-model="annotations.deployment.configuration" rows="2" maxlength="6000" /></label><label>Support status<select v-model="annotations.support.status"><option v-for="value in ['unknown', 'supported', 'unsupported', 'internally_maintained']" :key="value" :value="value">{{ value.replaceAll('_', ' ') }}</option></select></label><label>Supplier<input v-model="annotations.support.supplier" maxlength="1000"></label><div class="component-fields"><label>Supported until<input v-model="annotations.support.support_until" type="date"></label><label>End of life<input v-model="annotations.support.end_of_life" type="date"></label></div><label>Notes<textarea v-model="annotations.notes" rows="3" maxlength="12000" /></label><details><summary>Advanced typed annotation JSON</summary><p class="hint">Mitigations, testing evidence, support references and custom properties are retained exactly. Apply JSON explicitly to change these fields. The server validates this schema.</p><button type="button" @click="advanced = JSON.stringify(annotations, null, 2)">Copy current fields to JSON editor</button><label>Annotation JSON<textarea v-model="advanced" rows="10" spellcheck="false" /></label><button type="button" @click="applyAdvanced">Apply annotation JSON to form</button></details></details>
      <div class="component-fields"><label>Provenance source<input v-model="source" required maxlength="200"></label><label>Evidence reference<input v-model="reference" maxlength="3000"></label></div><label>Evidence observed at (timezone required)<input v-model="observed" placeholder="Optional ISO 8601 timestamp"></label><label>Reason for annotation change<textarea v-model="rationale" required maxlength="6000" rows="3" /></label><label class="component-confirm"><input v-model="acknowledged" type="checkbox" required> I reviewed the values and provenance for this exact component/version.</label><button class="primary" :disabled="!acknowledged || !rationale.trim() || !source.trim()">Review captured annotations</button></fieldset></form>
      <section v-else aria-label="Captured component annotations"><p>Exact values, source state, metadata revision and request ID are frozen across retries.</p><details><summary>Captured annotation request</summary><pre>{{ JSON.stringify(captured.body, null, 2) }}</pre></details><button class="primary" :disabled="busy" @click="publish">Save captured annotations</button></section><button :disabled="busy" @click="discard">{{ captured ? 'Discard captured annotations' : 'Cancel annotation edit' }}</button><button v-if="captured && error" :disabled="busy" @click="discardAndRefresh">Discard and refresh workspace</button>
    </section></dialog>
  </details>
</template>
<style scoped>
.component-context{margin-block:1rem}.component-context summary{cursor:pointer;font-weight:600}.component-context dl{display:grid;grid-template-columns:auto 1fr;gap:.3rem .8rem}.component-context dd{margin:0;overflow-wrap:anywhere}.component-context pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:20rem;overflow:auto;font-size:.8rem}.component-context dialog{width:min(760px,calc(100vw - 2rem));max-height:90vh;padding:0;border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--text);box-shadow:var(--shadow);box-sizing:border-box}.component-context dialog::backdrop{background:#0008}.component-editor{padding:1.2rem;overflow:auto;max-height:calc(90vh - 2px);box-sizing:border-box}.component-editor header{display:flex;justify-content:space-between;align-items:start}.component-editor h3{margin:0}.component-editor fieldset{padding:0;border:0;min-width:0;display:grid;gap:.7rem}.component-fields,.component-neighbors{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem}.component-editor label{display:grid;gap:.3rem;min-width:0}.component-editor input,.component-editor select,.component-editor textarea{box-sizing:border-box;max-width:100%}.component-editor .component-confirm{display:flex;align-items:start}.component-confirm input{width:auto}.component-editor button{margin-block:.3rem}.component-editor p{overflow-wrap:anywhere}@media(max-width:550px){.component-fields,.component-neighbors{grid-template-columns:1fr}.component-editor{padding:.8rem}}
</style>
