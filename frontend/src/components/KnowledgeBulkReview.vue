<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import { ApiError, send } from '../api'
import { knowledgeApi, type KnowledgeFinding } from '../knowledgeApi'
type Candidate = { target: { version: string; context_id: string; vulnerability_id: string }; assessment_id: string; assessment_revision: string }
type PlanRow = Candidate & { item_id: string; ready: boolean; reason: string; detail?: string }
type Plan = { preview_digest: string; items: PlanRow[]; total: number; next_offset: number | null; statistics: { total: number; ready: number; excluded: number; by_reason: Record<string, number> } }
type Capture = { project: string; version: string; state: string; body: { request_id: string; expected_versions: Record<string, string>; items: Candidate[]; action: string; rationale: string }; rows: KnowledgeFinding[]; plan?: Plan; selected: string[]; apply?: Record<string, unknown> }
const props = defineProps<{ project: string; version: string; state: string; rows: KnowledgeFinding[] }>()
const emit = defineEmits<{ locked: [value: boolean]; changed: [scope: { project: string; version: string }]; reset: [] }>()
const busy = ref(false), error = ref(''), notice = ref(''), action = ref('approve'), rationale = ref(''), confirmed = ref(false), capture = ref<Capture | null>(null)
let sequence = 0
const human = (value: string) => value.replaceAll('_', ' ')
const moved = computed(() => Boolean(capture.value && (capture.value.project !== props.project || capture.value.version !== props.version || capture.value.state !== props.state)))
function source(row: PlanRow) { return capture.value?.rows.find(item => item.context_id === row.target.context_id && item.vulnerability_id === row.target.vulnerability_id) }
function selectAll() { if (capture.value?.plan && !capture.value.apply) capture.value.selected = capture.value.plan.items.filter(item => item.ready).map(item => item.item_id) }
async function preview() {
  if (busy.value) return
  const current = ++sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    if (!capture.value) {
      if (!props.rows.length || props.rows.length > 100 || !rationale.value.trim()) throw new Error('Select 1 to 100 exact findings and enter a review rationale.')
      const items = props.rows.map(row => {
        const record = row.coverage.assessment
        if (!record) throw new Error('Every candidate needs an explicit assessment revision.')
        return { target: { version: props.version, context_id: row.context_id, vulnerability_id: row.vulnerability_id }, assessment_id: record.payload.assessment_id, assessment_revision: record.revision }
      })
      capture.value = { project: props.project, version: props.version, state: props.state, body: { request_id: crypto.randomUUID(), expected_versions: { [props.version]: props.state }, items, action: action.value, rationale: rationale.value }, rows: JSON.parse(JSON.stringify(props.rows)) as KnowledgeFinding[], selected: [] }
      emit('locked', true)
    }
    const selected = capture.value
    const plan = await knowledgeApi<Plan>(`/projects/${encodeURIComponent(selected.project)}/reviews/bulk/preview?offset=0&limit=100`, send(selected.body))
    if (current === sequence) { selected.plan = plan; selected.selected = []; confirmed.value = false }
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Bulk preview unavailable' }
  finally { if (current === sequence) busy.value = false }
}
async function apply() {
  const selected = capture.value
  if (busy.value || !selected?.plan || !selected.selected.length || !confirmed.value) return
  const current = ++sequence; busy.value = true; error.value = ''
  if (!selected.apply) selected.apply = { ...selected.body, preview_digest: selected.plan.preview_digest, selected: [...selected.selected] }
  try {
    const receipt = await knowledgeApi<{ committed: boolean; projection?: string }>(`/projects/${encodeURIComponent(selected.project)}/reviews/bulk/apply`, send(selected.apply))
    if (current !== sequence) return
    if (receipt.committed !== true) throw new Error('Publication uncertain; retry the exact captured batch.')
    notice.value = `${selected.selected.length} exact review targets committed for ${selected.project} / ${selected.version}.${receipt.projection === 'pending' ? ' Projection pending.' : ''}`
    capture.value = null; confirmed.value = false; rationale.value = ''; emit('locked', false); emit('changed', { project: selected.project, version: selected.version }); emit('reset')
  } catch (err) {
    if (current === sequence) error.value = err instanceof ApiError && err.status === 409 ? 'The pinned batch conflicts. Captured inputs remain fixed; check any earlier uncertain outcome before discarding this batch and refreshing the queue.' : 'Review publication failed or may be uncertain. Exact heads, targets, rationale and request ID are retained. Retry this identical batch.'
  } finally { if (current === sequence) busy.value = false }
}
function reset() { if (busy.value) return; ++sequence; capture.value = null; confirmed.value = false; error.value = ''; notice.value = ''; emit('locked', false); emit('reset') }
onBeforeUnmount(() => { ++sequence; emit('locked', false) })
</script>
<template>
  <section v-if="rows.length || capture || notice" class="knowledge-bulk-review" aria-label="Explicit bulk review">
    <h3>Review selected assessments</h3><p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <form v-if="!capture && rows.length" @submit.prevent="preview"><p>{{ rows.length }} explicit context targets selected. Each vulnerability and consuming context remains a separate review.</p><fieldset :disabled="busy"><label>Bulk review action<select v-model="action"><option value="approve">Approve selected assessments</option><option value="request_changes">Request changes to selected assessments</option></select></label><label>Bulk review rationale<textarea v-model="rationale" required maxlength="6000" rows="3" /></label><button :disabled="!rationale.trim()">Preview exact review targets</button><button type="button" @click="reset">Clear queue selection</button></fieldset></form>
    <template v-if="capture"><p><strong>Captured scope: {{ capture.project }} / {{ capture.version }}</strong> · {{ human(capture.body.action) }}</p><p v-if="moved" role="status">The current queue has changed. This captured batch retains its original project, version and state.</p><p class="hint">All selected targets are committed together or none are changed. No additional targets from shared assessment scopes are included.</p><template v-if="capture.plan"><p aria-label="Bulk review preview counts">{{ capture.plan.statistics.total }} candidates · {{ capture.plan.statistics.ready }} ready · {{ capture.plan.statistics.excluded }} excluded</p><div class="bulk-actions"><button :disabled="busy || !!capture.apply" @click="selectAll">Select all server-ready targets</button><span>{{ capture.selected.length }} explicitly selected for final review</span></div><div class="bulk-targets"><article v-for="row in capture.plan.items" :key="row.item_id"><label><input v-model="capture.selected" type="checkbox" :value="row.item_id" :disabled="busy || !row.ready || !!capture.apply"> {{ row.target.vulnerability_id }} · {{ source(row)?.component.name || row.target.context_id }}</label><small>{{ row.target.version }} · {{ source(row)?.context.root_ref }} · {{ human(row.reason) }}</small><p v-if="row.detail" class="hint">{{ row.detail }}</p><details><summary>Assessment rationale, evidence and scores</summary><p>{{ source(row)?.coverage.assessment?.payload.rationale }}</p><p v-if="source(row)?.coverage.assessment?.payload.justification">Reason: {{ human(source(row)!.coverage.assessment!.payload.justification!) }}</p><p>Source severity: {{ source(row)?.source_severity || 'unknown' }} · Published: <span v-if="source(row)?.published_score?.current === true">{{ source(row)?.published_score?.score }}</span><span v-else>Unknown<template v-if="source(row)?.published_score?.current === false"> (outdated publication)</template></span></p><p>{{ source(row)?.description }}</p><pre>{{ JSON.stringify({ context: source(row)?.context, assessment: { assessment_id: row.assessment_id, revision: row.assessment_revision, state: source(row)?.coverage.assessment?.payload.state, conditions: source(row)?.coverage.assessment?.payload.conditions, evidence: source(row)?.coverage.assessment?.payload.evidence, author_id: source(row)?.coverage.assessment?.payload.author_id }, original_ratings: source(row)?.source_ratings }, null, 2) }}</pre></details></article></div><label class="bulk-confirm"><input v-model="confirmed" type="checkbox" :disabled="busy || !!capture.apply"> I reviewed the evidence, applicability and consuming context for every explicitly selected target.</label><button class="primary" :disabled="busy || !confirmed || !capture.selected.length" @click="apply">{{ capture.apply ? 'Retry exact captured review' : `${capture.body.action === 'approve' ? 'Approve' : 'Request changes for'} ${capture.selected.length} selected targets` }}</button></template><button v-else :disabled="busy" @click="preview">Retry exact preview</button><button :disabled="busy" @click="reset">Discard captured batch and clear selection</button><details><summary>Immutable request and source head</summary><pre>{{ JSON.stringify(capture.apply || capture.body, null, 2) }}</pre><code>{{ capture.state }}</code></details></template>
    <p v-if="busy" role="status">Review request in progress…</p>
  </section>
</template>
<style scoped>
.knowledge-bulk-review { margin:16px 0; border:1px solid var(--line); border-radius:8px; padding:16px; min-width:0 }.knowledge-bulk-review h3 { margin-top:0;font-size:1rem }.knowledge-bulk-review fieldset { border:0;padding:0;min-width:0 }.knowledge-bulk-review label { display:block;margin:10px 0 }.knowledge-bulk-review input[type=checkbox] { width:auto }.bulk-targets { max-height:420px;overflow:auto }.bulk-targets article { padding:10px 0;border-bottom:1px solid var(--line) }.bulk-targets small,.hint { color:var(--muted);font-size:.8rem }.bulk-actions { display:flex;gap:12px;flex-wrap:wrap;align-items:center }.knowledge-bulk-review pre,.knowledge-bulk-review code { white-space:pre-wrap;overflow-wrap:anywhere;font-size:.75rem }.knowledge-bulk-review pre { max-height:240px;overflow:auto }.knowledge-bulk-review button { margin:6px 8px 6px 0 }.bulk-confirm { font-size:.85rem }
</style>
