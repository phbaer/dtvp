<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError, send } from '../api'
import { knowledgeApi } from '../knowledgeApi'

type Payload = { concluded_expression: string; disposition: string; obligations: string[]; conditions: string; evidence: object[]; distribution: string; modification: string; linking: string; rationale: string; provenance: { source: string; reference?: string }; actor_id?: string }
type Assessment = { revision: string; stage: string; payload: Payload }
type Row = { component_ref: string; component: { name?: string; group?: string; version?: string; purl?: string }; source: object; evidence: { status: string; facts: { source_field: string; value: unknown }[]; limitations: string[] }; license_review: { status: string; assessment?: Assessment | null; approved_assessment?: Assessment | null; approved: boolean; pending?: boolean; review?: object | null } }
type Worklist = { items: Row[]; total: number; next_offset: number | null; capabilities: string[]; statistics: { components: number; by_evidence_status: Record<string, number> } }
const props = defineProps<{ project: string; version: string; state: string }>()
const emit = defineEmits<{ changed: [] }>()
const expanded = ref(false), busy = ref(false), error = ref(''), notice = ref(''), result = ref<Worklist | null>(null)
const selectedRef = ref(''), offset = ref(0), previous = ref<number[]>([]), reviewRationale = ref(''), dirty = ref(false)
const empty = () => ({ concluded_expression: '', disposition: 'unresolved', obligations: '', conditions: '', evidence: '[]', distribution: '', modification: '', linking: '', rationale: '', source: '', reference: '' })
const form = ref(empty())
let sequence = 0, pending: { signature: string; requestId: string } | null = null
const selected = computed(() => result.value?.items.find(row => row.component_ref === selectedRef.value))
const can = (capability: string) => Boolean(result.value?.capabilities?.includes(capability))
const human = (text: string) => text.replaceAll('_', ' ')
const valueText = (value: unknown) => typeof value === 'string' ? value : JSON.stringify(value, null, 2)
function open(row: Row) {
  selectedRef.value = row.component_ref; dirty.value = false; error.value = ''; notice.value = ''; reviewRationale.value = ''; pending = null
  const payload = row.license_review?.assessment?.payload
  form.value = payload ? { ...empty(), ...payload, obligations: payload.obligations.join('\n'), evidence: JSON.stringify(payload.evidence, null, 2), source: payload.provenance.source, reference: payload.provenance.reference || '' } : empty()
}
async function load(nextOffset = 0) {
  if (!props.project || !props.state) return false
  const request = ++sequence; busy.value = true; error.value = ''
  try {
    const query = new URLSearchParams({ offset: String(nextOffset), limit: '20' })
    const data = await knowledgeApi<Worklist>(`/projects/${encodeURIComponent(props.project)}/states/${encodeURIComponent(props.state)}/license-worklist?${query}`)
    if (request !== sequence) return false
    result.value = data; offset.value = nextOffset
    return true
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'License evidence unavailable'; return false }
  finally { if (request === sequence) busy.value = false }
}
function toggle(event: Event) { expanded.value = (event.currentTarget as HTMLDetailsElement).open; if (expanded.value && !result.value && !busy.value) void load() }
async function paginate(forward: boolean) {
  const next = forward ? result.value?.next_offset : previous.value.at(-1)
  if (next == null) return
  const prior = offset.value
  if (await load(next)) { selectedRef.value = ''; dirty.value = false; if (forward) previous.value.push(prior); else previous.value.pop() }
}
async function mutate(action: 'draft' | 'submit' | 'approve' | 'request_changes') {
  const row = selected.value
  if (!row || busy.value) return
  const request = ++sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    const reviewing = action === 'approve' || action === 'request_changes'
    let body: object
    if (reviewing) body = { expected: props.state, component_ref: row.component_ref, revision: row.license_review.assessment!.revision, action, rationale: reviewRationale.value }
    else {
      const evidence: unknown = JSON.parse(form.value.evidence)
      if (!Array.isArray(evidence) || evidence.some(item => item === null || typeof item !== 'object' || Array.isArray(item))) throw new Error('Evidence must be a JSON array of attributed objects')
      body = { expected: props.state, expected_revision: row.license_review?.assessment?.revision || null, component_ref: row.component_ref,
        concluded_expression: form.value.concluded_expression, disposition: form.value.disposition, obligations: form.value.obligations.split('\n').map(value => value.trim()).filter(Boolean),
        conditions: form.value.conditions, evidence, distribution: form.value.distribution, modification: form.value.modification, linking: form.value.linking,
        rationale: form.value.rationale, provenance: { source: form.value.source, reference: form.value.reference } }
    }
    const endpoint = `/projects/${encodeURIComponent(props.project)}/versions/${encodeURIComponent(props.version)}/licenses/${reviewing ? 'reviews' : action}`
    const signature = JSON.stringify({ endpoint, body })
    if (pending?.signature !== signature) pending = { signature, requestId: crypto.randomUUID() }
    await knowledgeApi(endpoint, send({ ...body, request_id: pending.requestId }))
    if (request !== sequence) return
    pending = null; dirty.value = false; notice.value = action === 'approve' ? 'License disposition approved for this exact revision.' : action === 'request_changes' ? 'Changes requested.' : action === 'submit' ? 'Submitted for independent license review.' : 'License draft saved.'
    emit('changed')
  } catch (err) {
    if (request === sequence) error.value = err instanceof ApiError && err.status === 409 ? 'The source or disposition changed. Refresh the baseline before retrying; your input is retained.' : err instanceof Error ? err.message : 'License request failed'
  } finally { if (request === sequence) busy.value = false }
}
watch(() => [props.project, props.version, props.state], (current, prior) => {
  ++sequence; busy.value = false; error.value = ''; result.value = null; offset.value = 0; previous.value = []
  if (current[0] !== prior[0] || current[1] !== prior[1]) { selectedRef.value = ''; form.value = empty(); dirty.value = false; pending = null; notice.value = '' }
  if (expanded.value) void load()
})
onBeforeUnmount(() => { ++sequence })
</script>

<template>
  <details class="knowledge-licenses" @toggle="toggle">
    <summary>License evidence and review</summary>
    <section aria-label="License evidence and review" :aria-busy="busy">
      <p class="hint">Source evidence and human dispositions are separate. No automatic license compatibility or permission to distribute is inferred.</p>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p><p v-if="busy" role="status">Loading license evidence…</p>
      <template v-if="result">
        <p aria-label="License component total">{{ result.total }} components in this pinned state</p>
        <div class="license-list"><button v-for="row in result.items" :key="row.component_ref" :aria-pressed="selectedRef === row.component_ref" :disabled="busy" @click="open(row)"><strong>{{ row.component.name || row.component_ref }}</strong><span>{{ row.component.version }} · Source {{ human(row.evidence.status) }} · {{ human(row.license_review?.status || 'unassessed') }}</span></button></div>
        <nav aria-label="License evidence pages"><button :disabled="busy || !previous.length" @click="paginate(false)">Previous license components</button><button :disabled="busy || result.next_offset === null" @click="paginate(true)">Next license components</button></nav>
        <article v-if="selected" aria-label="License component detail">
          <h3>{{ selected.component.name || selected.component_ref }}</h3><p class="hint">{{ selected.component.purl || selected.component_ref }}</p>
          <h4>Imported license evidence</h4><p v-if="!selected.evidence.facts.length">No license terms were reported. Explicit human evidence is required to support a conclusion.</p>
          <dl v-for="(fact, index) in selected.evidence.facts" :key="index"><dt>{{ fact.source_field }}</dt><dd>{{ valueText(fact.value) }}</dd></dl>
          <details><summary>Source attribution and original facts</summary><pre>{{ JSON.stringify({ source: selected.source, evidence: selected.evidence }, null, 2) }}</pre></details>
          <p><strong>Human disposition: {{ human(selected.license_review.status) }}</strong><template v-if="selected.license_review.pending"> · A pending edit retains the previous approved revision.</template></p>
          <details v-if="selected.license_review.approved_assessment"><summary>Approved expression and usage assumptions</summary><pre>{{ JSON.stringify(selected.license_review.approved_assessment.payload, null, 2) }}</pre></details>
          <form v-if="can('license_assess')" @submit.prevent="mutate('submit')" @input="dirty = true">
            <h4>Human conclusion and usage</h4><label>Concluded license expression<input v-model="form.concluded_expression" required maxlength="6000"></label>
            <label>Disposition<select v-model="form.disposition"><option value="unresolved">Unresolved</option><option value="allowed">Allowed</option><option value="restricted">Restricted</option><option value="prohibited">Prohibited</option></select></label>
            <div class="assumptions"><label>Distribution assumptions<textarea v-model="form.distribution" required maxlength="6000" /></label><label>Modification assumptions<textarea v-model="form.modification" required maxlength="6000" /></label><label>Linking assumptions<textarea v-model="form.linking" required maxlength="6000" /></label></div>
            <label>Decision rationale<textarea v-model="form.rationale" required maxlength="6000" /></label>
            <label>Evidence source<input v-model="form.source" required maxlength="200"></label>
            <details><summary>Obligations, conditions and evidence</summary><label>Obligations (one per line)<textarea v-model="form.obligations" /></label><label>Conditions<textarea v-model="form.conditions" maxlength="6000" /></label><label>Evidence references (JSON)<textarea v-model="form.evidence" spellcheck="false" /></label><label>Provenance reference<input v-model="form.reference" maxlength="3000"></label></details>
            <div class="actions"><button type="button" :disabled="busy" @click="mutate('draft')">Save license draft</button><button type="submit" :disabled="busy">Submit license disposition</button></div>
          </form>
          <details v-else-if="selected.license_review.assessment"><summary>Recorded human conclusion and usage</summary><pre>{{ JSON.stringify(selected.license_review.assessment.payload, null, 2) }}</pre></details>
          <form v-if="can('license_approve') && selected.license_review.assessment?.stage === 'submitted'" @submit.prevent="mutate('approve')"><h4>Independent license review</h4><p class="hint">Review this exact submitted revision and its usage assumptions. The author cannot approve their own decision.</p><label>License review rationale<textarea v-model="reviewRationale" required maxlength="6000" /></label><div class="actions"><button type="submit" :disabled="busy">Approve license disposition</button><button type="button" :disabled="busy || !reviewRationale.trim()" @click="mutate('request_changes')">Request license changes</button></div></form>
          <button v-if="error" type="button" :disabled="busy" @click="emit('changed')">Refresh license baseline, retain input</button>
        </article>
      </template>
      <button v-if="error && !result" :disabled="busy" @click="load()">Retry license evidence</button>
    </section>
  </details>
</template>

<style scoped>
.knowledge-licenses { margin-block: .75rem; padding: .8rem; border: 1px solid var(--border, #64748b55); border-radius: .65rem; min-width: 0; }
summary { cursor: pointer; font-weight: 600; } section { padding-top: .5rem; min-width: 0; } .hint, .license-list span { opacity: .8; font-size: .85rem; }
.license-list { display: grid; gap: .3rem; } .license-list button { display: flex; flex-wrap: wrap; justify-content: space-between; gap: .4rem; text-align: left; } .license-list button[aria-pressed=true] { outline: 2px solid var(--accent, #2563eb); }
article { margin-top: 1rem; border-top: 1px solid var(--border, #64748b55); overflow-wrap: anywhere; } label { display: grid; gap: .25rem; margin-block: .6rem; } input, textarea, select { box-sizing: border-box; width: 100%; min-width: 0; padding: .5rem; font: inherit; } textarea { min-height: 4rem; resize: vertical; } .assumptions { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: .6rem; }
.actions, nav { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .7rem; } pre, dd { white-space: pre-wrap; overflow-wrap: anywhere; margin-left: 0; max-height: 25rem; overflow: auto; } h4 { margin-bottom: .4rem; }
</style>
