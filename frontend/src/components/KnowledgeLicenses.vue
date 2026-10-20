<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { API_PREFIX } from '../apiContract'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError, send } from '../api'
import { knowledgeApi } from '../knowledgeApi'

type Payload = { concluded_expression: string; disposition: string; obligations: string[]; conditions: string; evidence: object[]; distribution: string; modification: string; linking: string; rationale: string; provenance: { source: string; reference?: string }; actor_id?: string }
type Assessment = { revision: string; stage: string; payload: Payload }
type LicenseEvidence = { status: string; facts: { source_field: string; value: unknown }[]; limitations: string[] }
type SupplementalEvidence = { status: string; claims: { source: string; part_id: string | null; state: string; ref: string; source_format: string; artifact_sha?: string | null; evidence: LicenseEvidence }[]; reported_values: { category: string; values: string[] }[]; source_claims_differ: boolean; limitations: string[] }
type Row = { inventory_role?: 'authority' | 'adopted_observation'; supplemental_evidence?: SupplementalEvidence; component_ref: string; component: { name?: string; group?: string; version?: string; purl?: string }; source: object; evidence: LicenseEvidence; license_review: { status: string; assessment?: Assessment | null; approved_assessment?: Assessment | null; approved: boolean; pending?: boolean; review?: object | null } }
type Worklist = { items: Row[]; total: number; next_offset: number | null; capabilities: string[]; statistics: { components: number; by_evidence_status: Record<string, number> } }
const props = defineProps<{ project: string; version: string; state: string }>()
const emit = defineEmits<{ changed: []; locked: [value: boolean] }>()
const capabilities = ref<string[]>([])
const expanded = ref(false), busy = ref(false), error = ref(''), notice = ref(''), result = ref<Worklist | null>(null)
const selectedRef = ref(''), offset = ref(0), previous = ref<number[]>([]), reviewRationale = ref(''), dirty = ref(false)
const empty = () => ({ concluded_expression: '', disposition: 'unresolved', obligations: '', conditions: '', evidence: '[]', distribution: '', modification: '', linking: '', rationale: '', source: '', reference: '' })
const form = ref(empty())
type Capture = { endpoint: string; body: Record<string, unknown>; action: string }
const pending = ref<Capture | null>(null), selected = ref<Row | null>(null)
type Scope = { project: string; version: string; state: string }
const listScope = ref<Scope | null>(null), selectedScope = ref<Scope | null>(null)
const scopeChanged = computed(() => !!selectedScope.value && (selectedScope.value.project !== props.project || selectedScope.value.version !== props.version || selectedScope.value.state !== props.state))
const filterEmpty = () => ({ q: '', evidence_status: '', review_status: '', approved_disposition: '' })
const filterDraft = ref(filterEmpty()), appliedFilters = ref(filterEmpty())
const locked = computed(() => dirty.value || !!reviewRationale.value || !!pending.value || busy.value)
watch(locked, value => emit('locked', value), { flush: 'sync' })
let sequence = 0, alive = true

const can = (capability: string) => capabilities.value.includes(capability)
const human = (text: string) => text.replaceAll('_', ' ')
const valueText = (value: unknown) => typeof value === 'string' ? value : JSON.stringify(value, null, 2)
function claimText(value: unknown): string {
  if (typeof value === 'string') return value.length > 300 ? value.slice(0, 300) + '…' : value
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const item = value as Record<string, unknown>, license = item.license as Record<string, unknown> | undefined
    if (typeof item.expression === 'string' && item.expression.trim()) return claimText(item.expression)
    if (license && typeof license === 'object') {
      const name = typeof license.id === 'string' && license.id.trim() ? license.id : license.name
      if (typeof name === 'string' && name.trim()) return claimText(name)
    }
  }
  const text = valueText(value) || 'No displayable claim'
  return text.length > 300 ? text.slice(0, 300) + '…' : text
}
function originalArtifact(artifact: unknown) {
  const scope = selectedScope.value
  if (!scope || typeof artifact !== 'string' || !/^[a-f0-9]{64}$/.test(artifact) || !/^[a-f0-9]{64}$/.test(scope.state)) return undefined
  return `${API_PREFIX}/projects/${encodeURIComponent(scope.project)}/states/${encodeURIComponent(scope.state)}/artifacts/${artifact}`
}
function open(row: Row) {
  if (locked.value || !listScope.value) return
  selectedScope.value = { ...listScope.value }
  selected.value = JSON.parse(JSON.stringify(row)); selectedRef.value = row.component_ref; dirty.value = false; error.value = ''; notice.value = ''; reviewRationale.value = ''
  const payload = row.license_review?.assessment?.payload
  form.value = payload ? { ...empty(), ...payload, obligations: payload.obligations.join('\n'), evidence: JSON.stringify(payload.evidence, null, 2), source: payload.provenance.source, reference: payload.provenance.reference || '' } : empty()
}
async function load(nextOffset = 0) {
  if (!props.project || !props.state) return false
  const request = ++sequence, scope = { project: props.project, version: props.version, state: props.state }; busy.value = true; error.value = ''
  try {
    const query = new URLSearchParams({ offset: String(nextOffset), limit: '20', ...appliedFilters.value })
    const data = await knowledgeApi<Worklist>(`/projects/${encodeURIComponent(scope.project)}/states/${encodeURIComponent(scope.state)}/license-worklist?${query}`)
    if (request !== sequence) return false
    result.value = data; listScope.value = scope; capabilities.value = data.capabilities || []; offset.value = nextOffset
    return true
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'License evidence unavailable'; return false }
  finally { if (request === sequence) busy.value = false }
}
function toggle(open: boolean) { expanded.value = open; if (expanded.value && !result.value && !busy.value) void load() }
async function paginate(forward: boolean) {
  if (locked.value) return
  const next = forward ? result.value?.next_offset : previous.value.at(-1)
  if (next == null) return
  const prior = offset.value
  if (await load(next)) { selectedRef.value = ''; selected.value = null; if (forward) previous.value.push(prior); else previous.value.pop() }
}
function discard() {
  if (busy.value) return
  const reload = scopeChanged.value
  pending.value = null; dirty.value = false; reviewRationale.value = ''; selected.value = null; selectedRef.value = ''; form.value = empty(); selectedScope.value = null; error.value = ''; notice.value = ''
  if (reload && expanded.value) void load()
}
async function applyFilters() {
  if (locked.value) return
  const prior = appliedFilters.value
  appliedFilters.value = { ...filterDraft.value }
  if (await load()) { previous.value = []; selected.value = null; selectedRef.value = '' }
  else appliedFilters.value = prior
}
async function mutate(action: 'draft' | 'submit' | 'approve' | 'request_changes', retry = false) {
  const row = selected.value, scope = selectedScope.value
  if (!scope || !row || busy.value || (pending.value && !retry && pending.value.action !== action)) return
  busy.value = true; error.value = ''; notice.value = ''
  try {
    if (!pending.value) {
      const reviewing = action === 'approve' || action === 'request_changes'
      let body: Record<string, unknown>
      if (reviewing) body = { expected: scope.state, component_ref: row.component_ref, revision: row.license_review.assessment!.revision, action, rationale: reviewRationale.value }
      else {
        const evidence: unknown = JSON.parse(form.value.evidence)
        if (!Array.isArray(evidence) || evidence.some(item => item === null || typeof item !== 'object' || Array.isArray(item))) throw new Error('Evidence must be a JSON array of attributed objects')
        body = { expected: scope.state, expected_revision: row.license_review?.assessment?.revision || null, component_ref: row.component_ref,
          concluded_expression: form.value.concluded_expression, disposition: form.value.disposition, obligations: form.value.obligations.split('\n').map(value => value.trim()).filter(Boolean),
          conditions: form.value.conditions, evidence, distribution: form.value.distribution, modification: form.value.modification, linking: form.value.linking,
          rationale: form.value.rationale, provenance: { source: form.value.source, reference: form.value.reference }, request_id: crypto.randomUUID() }
      }
      body.request_id ||= crypto.randomUUID()
      pending.value = { endpoint: `/projects/${encodeURIComponent(scope.project)}/versions/${encodeURIComponent(scope.version)}/licenses/${reviewing ? 'reviews' : action}`, body: JSON.parse(JSON.stringify(body)), action }
    }
    const capture = pending.value
    const response = await knowledgeApi<{ committed?: boolean; projection?: string }>(capture.endpoint, send(capture.body))
    if (!alive || pending.value !== capture) return
    if (response.committed !== true || response.projection !== 'current') { error.value = 'Publication is not confirmed with a current projection. Retry the exact captured request.'; return }
    pending.value = null; dirty.value = false; reviewRationale.value = ''; selected.value = null; selectedRef.value = ''
    notice.value = capture.action === 'approve' ? 'License disposition approved for this exact revision.' : capture.action === 'request_changes' ? 'Changes requested.' : capture.action === 'submit' ? 'Submitted for independent license review.' : 'License draft saved.'
    emit('changed')
  } catch (err) {
    if (alive) error.value = err instanceof ApiError && err.status === 409 ? 'The source or disposition changed; your input is retained. Retry the exact request or discard it explicitly.' : err instanceof Error ? err.message : 'License request failed'
  } finally { if (alive) busy.value = false }
}
watch(() => [props.project, props.version, props.state], () => {
  if (dirty.value || reviewRationale.value || pending.value) return
  ++sequence; result.value = null; offset.value = 0; previous.value = []; selected.value = null; selectedScope.value = null; selectedRef.value = ''; form.value = empty()
  if (expanded.value) void load()
})
onBeforeUnmount(() => { alive = false; ++sequence; emit('locked', false) })
</script>

<template>
  <TaskSurface class="knowledge-licenses" @active="toggle" title="License evidence and review">
    <section aria-label="License evidence and review" :aria-busy="busy">
      <p class="hint">Source evidence and human dispositions are separate. No automatic license compatibility or permission to distribute is inferred.</p>
      <p v-if="scopeChanged" role="status">The workspace moved to another state. This retained input stays bound to its original source.</p><p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p><p v-if="busy" role="status">Loading license evidence…</p>
      <form class="license-filters" @submit.prevent="applyFilters">
        <label>Search license evidence<input v-model="filterDraft.q" type="search" maxlength="500" :disabled="locked"></label>
        <label>Authoritative license evidence status<select v-model="filterDraft.evidence_status" :disabled="locked"><option value="">All evidence</option><option v-for="value in ['reported', 'explicit_none', 'unknown', 'not_reported', 'malformed']" :key="value" :value="value">{{ human(value) }}</option></select></label>
        <label>License review status<select v-model="filterDraft.review_status" :disabled="locked"><option value="">All reviews</option><option v-for="value in ['unassessed', 'draft', 'submitted', 'approved', 'pending', 'changes_requested', 'stale', 'out_of_scope', 'absent']" :key="value" :value="value">{{ human(value) }}</option></select></label>
        <label>Approved license disposition<select v-model="filterDraft.approved_disposition" :disabled="locked"><option value="">All dispositions</option><option v-for="value in ['allowed', 'restricted', 'prohibited', 'unresolved', 'missing']" :key="value" :value="value">{{ human(value) }}</option></select></label>
        <button :disabled="locked" type="submit">Apply license filters</button>
      </form>
      <section v-if="locked && selected" aria-label="Retained license input"><p role="status">Input retained for {{ selectedScope?.project }} / {{ selectedScope?.version }} / {{ selected.component.name || selected.component_ref }} at {{ selectedScope?.state }}. Discard explicitly before changing component or filters.</p><button v-if="pending" :disabled="busy" @click="mutate(pending.action as 'draft', true)">Retry exact license request</button><button :disabled="busy" @click="discard">Discard license input</button></section>
      <template v-if="result">
        <p aria-label="License component total">{{ result.total }} components in this pinned state</p>
        <div class="license-list"><button v-for="row in result.items" :key="row.component_ref" :aria-pressed="selectedRef === row.component_ref" :disabled="locked" @click="open(row)"><strong>{{ row.component.name || row.component_ref }}</strong><span>{{ row.component.version }} · Authority {{ human(row.evidence.status) }} · {{ human(row.license_review?.status || 'unassessed') }}</span></button></div>
        <nav aria-label="License evidence pages"><button :disabled="locked || !previous.length" @click="paginate(false)">Previous license components</button><button :disabled="locked || result.next_offset === null" @click="paginate(true)">Next license components</button></nav>
      </template>
        <article v-if="selected" aria-label="License component detail">
          <h3>{{ selected.component.name || selected.component_ref }}</h3><p class="hint">{{ selected.component.purl || selected.component_ref }}</p>
          <h4>Authoritative license evidence</h4><p v-if="selected.inventory_role === 'adopted_observation'" class="hint">Added from a selected observation; no authoritative license claim for this occurrence.</p><p v-else-if="!selected.evidence.facts.length">No license terms were reported. Explicit human evidence is required to support a conclusion.</p>
          <dl v-for="(fact, index) in selected.evidence.facts" :key="index"><dt>{{ fact.source_field }}</dt><dd>{{ valueText(fact.value) }}</dd></dl>
          <details><summary>Source attribution and original facts</summary><pre>{{ JSON.stringify({ source: selected.source, evidence: selected.evidence }, null, 2) }}</pre></details>
          <details v-if="selected.supplemental_evidence && (selected.supplemental_evidence.claims.length || selected.supplemental_evidence.status !== 'not_reported')" class="supplemental-license-evidence">
            <summary>Additional source license evidence · {{ selected.supplemental_evidence.claims.length }} {{ selected.supplemental_evidence.claims.length === 1 ? 'claim' : 'claims' }}<template v-if="selected.supplemental_evidence.source_claims_differ"> · source claims differ</template></summary>
            <p class="hint">Authority evidence remains above. These imported claims do not conclude license compatibility or grant permission to distribute.</p>
            <p v-if="selected.supplemental_evidence.source_claims_differ" class="source-difference">Source claims differ. This describes reported statements, not a legal compatibility decision.</p>
            <p>Additional evidence: {{ human(selected.supplemental_evidence.status) }}</p>
            <dl v-for="item in selected.supplemental_evidence.reported_values" :key="item.category" class="reported-license-values"><dt>{{ human(item.category) }}</dt><dd><span v-for="(value, index) in item.values" :key="index" class="license-value">{{ value }}</span></dd></dl>
            <details v-for="(claim, index) in selected.supplemental_evidence.claims" :key="`${claim.state}:${claim.ref}:${index}`" class="supplemental-license-claim">
              <summary>{{ claim.source }} · {{ claim.part_id || 'whole product' }} · {{ human(claim.evidence.status) }}</summary>
              <dl v-for="(fact, factIndex) in claim.evidence.facts" :key="factIndex"><dt>{{ fact.source_field }}</dt><dd>{{ claimText(fact.value) }}</dd></dl>
              <p v-if="!claim.evidence.facts.length" class="hint">No interpretable license facts available from this source.</p>
              <ul v-if="claim.evidence.limitations.length"><li v-for="(limitation, limitIndex) in claim.evidence.limitations" :key="limitIndex">{{ limitation }}</li></ul>
              <a v-if="originalArtifact(claim.artifact_sha)" :href="originalArtifact(claim.artifact_sha)" target="_blank" rel="noopener noreferrer">Open original SBOM</a>
              <details><summary>Source pins and original claim</summary>
                <dl class="claim-pins"><dt>Parser format</dt><dd>{{ claim.source_format }}</dd><dt>Source state</dt><dd><code>{{ claim.state }}</code></dd><dt>Source component</dt><dd>{{ claim.ref }}</dd><dt>Original artifact</dt><dd><code>{{ claim.artifact_sha || 'Unavailable' }}</code></dd></dl>
                <pre>{{ JSON.stringify(claim.evidence.facts, null, 2) }}</pre>
              </details>
            </details>
            <ul v-if="selected.supplemental_evidence.limitations.length" class="hint"><li v-for="(limitation, index) in selected.supplemental_evidence.limitations" :key="index">{{ limitation }}</li></ul>
          </details>
          <p><strong>Human disposition: {{ human(selected.license_review.status) }}</strong><template v-if="selected.license_review.pending"> · A pending edit retains the previous approved revision.</template></p>
          <details v-if="selected.license_review.approved_assessment"><summary>Approved expression and usage assumptions</summary><pre>{{ JSON.stringify(selected.license_review.approved_assessment.payload, null, 2) }}</pre></details>
          <form v-if="can('license_assess')" @submit.prevent="mutate('submit')" @input="dirty = true">
            <fieldset :disabled="busy || !!pending"><h4>Human conclusion and usage</h4><label>Concluded license expression<input v-model="form.concluded_expression" required maxlength="6000"></label>
            <label>Disposition<select v-model="form.disposition"><option value="unresolved">Unresolved</option><option value="allowed">Allowed</option><option value="restricted">Restricted</option><option value="prohibited">Prohibited</option></select></label>
            <div class="assumptions"><label>Distribution assumptions<textarea v-model="form.distribution" required maxlength="6000" /></label><label>Modification assumptions<textarea v-model="form.modification" required maxlength="6000" /></label><label>Linking assumptions<textarea v-model="form.linking" required maxlength="6000" /></label></div>
            <label>Decision rationale<textarea v-model="form.rationale" required maxlength="6000" /></label>
            <label>Evidence source<input v-model="form.source" required maxlength="200"></label>
            <details><summary>Obligations, conditions and evidence</summary><label>Obligations (one per line)<textarea v-model="form.obligations" /></label><label>Conditions<textarea v-model="form.conditions" maxlength="6000" /></label><label>Evidence references (JSON)<textarea v-model="form.evidence" spellcheck="false" /></label><label>Provenance reference<input v-model="form.reference" maxlength="3000"></label></details>
            <div class="actions"><button type="button" :disabled="busy" @click="mutate('draft')">Save license draft</button><button type="submit" :disabled="busy">Submit license disposition</button></div>
            </fieldset>
          </form>
          <details v-else-if="selected.license_review.assessment"><summary>Recorded human conclusion and usage</summary><pre>{{ JSON.stringify(selected.license_review.assessment.payload, null, 2) }}</pre></details>
          <form v-if="can('license_approve') && selected.license_review.assessment?.stage === 'submitted'" @submit.prevent="mutate('approve')" @input="dirty = true"><fieldset :disabled="busy || !!pending"><h4>Independent license review</h4><p class="hint">Review this exact submitted revision and its usage assumptions. The author cannot approve their own decision.</p><label>License review rationale<textarea v-model="reviewRationale" required maxlength="6000" /></label><div class="actions"><button type="submit" :disabled="busy">Approve license disposition</button><button type="button" :disabled="busy || !reviewRationale.trim()" @click="mutate('request_changes')">Request license changes</button></div></fieldset></form>
          <button v-if="error" type="button" :disabled="busy" @click="emit('changed')">Refresh license baseline, retain input</button>
        </article>
      <button v-if="error && !result" :disabled="busy" @click="load()">Retry license evidence</button>
    </section>
  </TaskSurface>
</template>

<style scoped>
.knowledge-licenses { margin-block: .75rem; padding: .8rem; border: 1px solid var(--border, #64748b55); border-radius: .65rem; min-width: 0; }
summary { cursor: pointer; font-weight: 600; } section { padding-top: .5rem; min-width: 0; } .hint, .license-list span { opacity: .8; font-size: .85rem; }
.license-list { display: grid; gap: .3rem; } .license-list button { display: flex; flex-wrap: wrap; justify-content: space-between; gap: .4rem; text-align: left; } .license-list button[aria-pressed=true] { outline: 2px solid var(--accent, #2563eb); }
.license-filters { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .5rem; align-items: end; } fieldset { border: 0; padding: 0; min-width: 0; } article { margin-top: 1rem; border-top: 1px solid var(--border, #64748b55); overflow-wrap: anywhere; } label { display: grid; gap: .25rem; margin-block: .6rem; } input, textarea, select { box-sizing: border-box; width: 100%; min-width: 0; padding: .5rem; font: inherit; } textarea { min-height: 4rem; resize: vertical; } .assumptions { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: .6rem; }
.supplemental-license-evidence { margin-block:.8rem; padding:.7rem; border:1px solid var(--border, #64748b55); border-radius:.5rem; min-width:0; }
.supplemental-license-claim { margin-block:.6rem; padding-block:.4rem; border-top:1px solid var(--border, #64748b55); min-width:0; }
.reported-license-values { margin-block:.5rem; }.license-value { display:inline-block; margin-right:.7rem; overflow-wrap:anywhere; }.claim-pins { display:grid;grid-template-columns:minmax(6rem,auto) minmax(0,1fr);gap:.3rem .6rem; }.claim-pins dd { margin:0; }.source-difference { font-size:.875rem; }
.actions, nav { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .7rem; } pre, dd { white-space: pre-wrap; overflow-wrap: anywhere; margin-left: 0; max-height: 25rem; overflow: auto; } h4 { margin-bottom: .4rem; }
</style>
