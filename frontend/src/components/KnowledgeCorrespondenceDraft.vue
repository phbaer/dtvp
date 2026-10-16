<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
type Assertion = { revision: string; in_version_scope: boolean; payload: { reconciliation_id: string; stage: string; rationale: string } }
type Candidate = { context_id: string; vulnerability_id: string; approved_assessment: { revision: string; payload: { assessment_id?: string; state: string; rationale: string; conditions?: string; author_id?: string; evidence?: unknown[] } }; component?: { name?: string; version?: string }; root_ref?: string }
type Catalog = { items: Candidate[]; total: number; next_offset: number | null; current_policy: string | null; candidates_digest: string }
type Context = { id: string; component_ref: string; root_ref: string | null; component: { name?: string; version?: string } | null }
type Input = { source: string; target: string; source_context_id: string; target_context_id: string; vulnerability_id: string; source_assessment_revision: string; assertions: Record<string, string>; expected_policy: string | null }
type Preview = { preview_digest: string; draft_allowed: boolean; source_version: string; target_version: string; source_assessment: Candidate['approved_assessment']; requires_new_target_review: boolean; limitations: string[] }
type Capture = { endpoint: string; body: Input & { request_id: string; preview_digest: string; assessment_id: string; conditions: string; reason: string } }
const props = defineProps<{ project: string; version: string; state: string; source: string; disabled?: boolean }>()
const emit = defineEmits<{ changed: []; locked: [boolean] }>()
const busy = ref(false), error = ref(''), notice = ref(''), sourcePin = ref(''), targetPin = ref(''), q = ref(''), contextQuery = ref('')
const appliedQ = ref(''), appliedContextQuery = ref('')
const catalog = ref<Catalog | null>(null), contexts = ref<Context[]>([]), contextNext = ref<number | null>(null), selected = ref<Candidate | null>(null), targetContext = ref('')
const assertionRows = ref<Assertion[]>([]), assertionNext = ref<number | null>(null)
const assertions = ref<Record<string, string>>({}), preview = ref<{ input: Input; result: Preview } | null>(null), captured = ref<Capture | null>(null)
const assessmentId = ref(crypto.randomUUID() as string), conditions = ref(''), reason = ref(''), confirmed = ref(false)
const hasBuffer = computed(() => !!selected.value || !!preview.value || !!captured.value || !!conditions.value || !!reason.value || Object.keys(assertions.value).length > 0)
const locked = computed(() => busy.value || hasBuffer.value)
const stale = computed(() => !!targetPin.value && targetPin.value !== props.state)
const frozen = computed(() => busy.value || !!captured.value || !!props.disabled)
let sequence = 0, alive = true
watch(locked, value => emit('locked', value), { flush: 'sync' })
const root = () => `/projects/${encodeURIComponent(props.project)}`
const key = (row: Candidate) => `${row.context_id}:${row.vulnerability_id}`
function invalidate() { preview.value = null; confirmed.value = false }
function choose(row: Candidate) { if (frozen.value) return; selected.value = JSON.parse(JSON.stringify(row)); invalidate() }
function toggleAssertion(row: Assertion) {
  if (frozen.value) return
  const id = row.payload.reconciliation_id
  if (assertions.value[id]) delete assertions.value[id]; else assertions.value[id] = row.revision
  invalidate()
}
async function loadCandidates(offset = 0) {
  if (frozen.value || !props.source || (offset === 0 && hasBuffer.value)) return
  const token = ++sequence, pin = offset ? sourcePin.value : props.source, target = offset ? targetPin.value : props.state
  busy.value = true; error.value = ''
  try {
    const query = new URLSearchParams({ q: offset ? appliedQ.value : q.value, offset: String(offset), limit: '20' })
    const data = await knowledgeApi<Catalog>(`${root()}/states/${pin}/correspondence-draft-candidates?${query}`)
    if (token !== sequence) return
    if (offset && (data.candidates_digest !== catalog.value?.candidates_digest || data.current_policy !== catalog.value?.current_policy)) throw new Error('Source candidates or policy changed. Discard and select fresh pins.')
    catalog.value = data; if (!offset) appliedQ.value = q.value; sourcePin.value = pin; targetPin.value = target
  } catch (err) { if (token === sequence) error.value = err instanceof Error ? err.message : 'Approved source evidence unavailable' }
  finally { if (token === sequence) busy.value = false }
}
async function loadContexts(offset = 0) {
  if (frozen.value || !targetPin.value) return
  const token = ++sequence; busy.value = true; error.value = ''
  try {
    const query = new URLSearchParams({ kind: 'context', q: offset ? appliedContextQuery.value : contextQuery.value, offset: String(offset), limit: '20' })
    const data = await knowledgeApi<{ items: Context[]; next_offset: number | null }>(`${root()}/states/${targetPin.value}/reconciliation-candidates?${query}`)
    if (token !== sequence) return
    contexts.value = data.items; contextNext.value = data.next_offset; if (!offset) appliedContextQuery.value = contextQuery.value
  } catch (err) { if (token === sequence) error.value = err instanceof Error ? err.message : 'Target contexts unavailable' }
  finally { if (token === sequence) busy.value = false }
}
async function loadAssertions(offset = 0) {
  if (frozen.value || !targetPin.value) return
  const token = ++sequence; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<{ items: Assertion[]; next_offset: number | null }>(`${root()}/states/${targetPin.value}/reconciliations?offset=${offset}&limit=20`)
    if (token === sequence) { assertionRows.value = data.items; assertionNext.value = data.next_offset }
  } catch (err) { if (token === sequence) error.value = err instanceof Error ? err.message : 'Recorded assertions unavailable' }
  finally { if (token === sequence) busy.value = false }
}
async function inspect() {
  if (frozen.value || stale.value || !selected.value || !catalog.value || !targetContext.value || !Object.keys(assertions.value).length) return
  const token = ++sequence; busy.value = true; error.value = ''; preview.value = null; confirmed.value = false
  const row = selected.value
  const input: Input = { source: sourcePin.value, target: targetPin.value, source_context_id: row.context_id, target_context_id: targetContext.value, vulnerability_id: row.vulnerability_id, source_assessment_revision: row.approved_assessment.revision, assertions: { ...assertions.value }, expected_policy: catalog.value.current_policy }
  try {
    const data = await knowledgeApi<Preview>(`${root()}/correspondence-drafts/preview`, send(input))
    if (token === sequence) preview.value = { input, result: data }
  } catch (err) { if (token === sequence) error.value = err instanceof Error ? err.message : 'Linked draft preview failed' }
  finally { if (token === sequence) busy.value = false }
}
async function publish() {
  if (busy.value || props.disabled) return
  if (!captured.value) {
    if (stale.value || !preview.value?.result.draft_allowed || !conditions.value.trim() || !reason.value.trim() || !assessmentId.value.trim() || !confirmed.value) return
    captured.value = { endpoint: `${root()}/correspondence-drafts`, body: JSON.parse(JSON.stringify({ ...preview.value.input, request_id: crypto.randomUUID(), preview_digest: preview.value.result.preview_digest, assessment_id: assessmentId.value, conditions: conditions.value, reason: reason.value })) }
  }
  const request = captured.value, token = ++sequence; busy.value = true; error.value = ''
  try {
    const response = await knowledgeApi<{ committed?: boolean; projection?: string }>(request.endpoint, send(request.body))
    if (!alive || token !== sequence) return
    if (response.committed !== true || response.projection !== 'current') throw new Error('Publication or projection is not confirmed current.')
    reset(); notice.value = 'New target draft created with linked historical evidence. Independent target review is still required.'; emit('changed')
  } catch (err) { if (token === sequence) error.value = `${err instanceof Error ? err.message : 'Draft publication failed'} Retry the identical captured request or discard explicitly; no pins are replaced.` }
  finally { if (token === sequence) busy.value = false }
}
function reset() { captured.value = null; selected.value = null; preview.value = null; assertions.value = {}; catalog.value = null; assertionRows.value = []; assertionNext.value = null; contexts.value = []; contextNext.value = null; sourcePin.value = ''; targetPin.value = ''; targetContext.value = ''; assessmentId.value = crypto.randomUUID(); conditions.value = ''; reason.value = ''; confirmed.value = false; error.value = ''; notice.value = '' }
function discard() { if (busy.value) return; ++sequence; reset() }
watch(() => [props.source, props.state], (current, prior) => { if (!hasBuffer.value && !busy.value) { const message = current[0] === prior[0] ? notice.value : ''; ++sequence; reset(); notice.value = message } })
onBeforeUnmount(() => { alive = false; ++sequence; emit('locked', false) })
</script>
<template>
  <details class="linked-draft"><summary>Reuse approved assessment through correspondence</summary>
    <section aria-label="Linked target assessment draft">
      <p class="hint">Select independently approved historical evidence and explicit component/context assertions. Create one new target draft; approval, scores and identity are never transferred.</p>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p><p v-if="stale" role="status">The target advanced. Retained pins stay fixed; discard to start from the new baseline.</p>
      <form @submit.prevent="loadCandidates()"><label>Search approved source assessments<input v-model="q" type="search" maxlength="500" :disabled="frozen || hasBuffer"></label><button :disabled="frozen || hasBuffer || !source">Find approved source evidence</button></form>
      <p v-if="catalog">{{ catalog.total }} approved source contexts at {{ sourcePin.slice(0, 12) }} · target {{ version }} {{ targetPin.slice(0, 12) }}</p>
      <label v-for="row in catalog?.items" :key="key(row)" class="choice"><input type="radio" name="correspondence-approved-source" :checked="!!selected && key(selected) === key(row)" :disabled="frozen" @change="choose(row)"><span>{{ row.vulnerability_id }} · {{ row.component?.name || row.context_id }} {{ row.component?.version }} · {{ row.root_ref || row.context_id }}</span></label>
      <button v-if="catalog?.next_offset != null" type="button" :disabled="frozen" @click="loadCandidates(catalog.next_offset)">More approved source assessments</button>
      <template v-if="selected">
        <p aria-label="Selected approved source evidence">Selected {{ selected.vulnerability_id }} · context {{ selected.context_id }} · revision {{ selected.approved_assessment.revision }}.</p>
        <form @submit.prevent="loadContexts()"><label>Search linked target contexts<input v-model="contextQuery" maxlength="200" :disabled="frozen"></label><button :disabled="frozen">Find linked target contexts</button></form>
        <label>Linked target context<select v-model="targetContext" :disabled="frozen" @change="invalidate"><option value="">Select explicitly</option><option v-if="targetContext && !contexts.some(row => row.id === targetContext)" :value="targetContext">Selected context {{ targetContext }}</option><option v-for="row in contexts" :key="row.id" :value="row.id">{{ row.component?.name || row.component_ref }} · via {{ row.root_ref || 'unknown root' }} · {{ row.id.slice(0, 12) }}</option></select></label>
        <button v-if="contextNext != null" type="button" :disabled="frozen" @click="loadContexts(contextNext)">More linked target contexts</button>
        <h4>Use recorded correspondence assertions</h4><button type="button" :disabled="frozen" @click="loadAssertions()">Load recorded target assertions</button>
        <div class="assertions"><label v-for="row in assertionRows.filter(item => item.in_version_scope && item.payload.stage === 'active')" :key="row.revision" class="choice"><input type="checkbox" :checked="!!assertions[row.payload.reconciliation_id]" :disabled="frozen" @change="toggleAssertion(row)"><span>{{ row.payload.reconciliation_id }} · {{ row.payload.rationale }}</span></label></div>
        <button v-if="assertionNext != null" type="button" :disabled="frozen" @click="loadAssertions(assertionNext)">More recorded target assertions</button>
        <p v-if="Object.keys(assertions).length" class="hint">Selected assertions: {{ Object.keys(assertions).join(', ') }}. Component and consuming-context relations are both required; the server checks their exact revisions.</p>
        <button type="button" :disabled="frozen || stale || !targetContext || !Object.keys(assertions).length" @click="inspect">Preview linked target draft</button>
      </template>
      <template v-if="preview">
        <article aria-label="Linked draft preview"><h4>{{ preview.result.source_version }} → {{ preview.result.target_version }} · {{ selected?.vulnerability_id }}</h4><p><strong>Source conclusion: {{ preview.result.source_assessment.payload.state.replaceAll('_', ' ') }}</strong></p><p>{{ preview.result.source_assessment.payload.rationale }}</p><details><summary>Source evidence and exact draft pins</summary><pre>{{ JSON.stringify({ source: preview.result.source_assessment, pins: preview.input }, null, 2) }}</pre></details><p v-for="item in preview.result.limitations" :key="item" class="hint">{{ item }}</p><p v-if="!preview.result.draft_allowed" role="status">Current permissions do not allow creating this target draft.</p></article>
        <form @submit.prevent="publish"><fieldset :disabled="frozen"><label>New target assessment ID<input v-model="assessmentId" @input="confirmed = false" maxlength="189" required></label><label>Target applicability conditions<textarea v-model="conditions" @input="confirmed = false" required maxlength="6000" /></label><label>Reason for adopting this evidence<textarea v-model="reason" @input="confirmed = false" required maxlength="6000" /></label><label class="choice"><input v-model="confirmed" type="checkbox"><span>I checked the source evidence, correspondence and target conditions. This creates an unsubmitted draft requiring new target review.</span></label></fieldset><button :disabled="busy || disabled || (!captured && (stale || !preview.result.draft_allowed || !conditions.trim() || !reason.trim() || !assessmentId.trim() || !confirmed))">{{ captured ? 'Retry exact linked draft request' : 'Create new linked target draft' }}</button></form>
      </template>
      <details v-if="captured"><summary>Captured linked draft request</summary><pre>{{ JSON.stringify(captured.body, null, 2) }}</pre></details>
      <button v-if="hasBuffer || catalog" type="button" :disabled="busy" @click="discard">Discard linked draft input</button><p v-if="busy" role="status">Loading linked draft workflow…</p>
    </section>
  </details>
</template>
<style scoped>
.linked-draft{margin-block:.7rem;border-top:1px solid var(--line);padding-top:.6rem;min-width:0}.linked-draft summary{cursor:pointer}.linked-draft label{display:grid;gap:.3rem;margin-block:.6rem}.linked-draft input,.linked-draft select,.linked-draft textarea{width:100%;box-sizing:border-box;min-width:0}.linked-draft .choice{display:flex;align-items:flex-start;gap:.4rem}.linked-draft input[type=radio],.linked-draft input[type=checkbox]{width:auto}.linked-draft fieldset{border:0;padding:0;min-width:0}.linked-draft textarea{min-height:4rem}.linked-draft pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:20rem;overflow:auto}.hint{font-size:.85rem;color:var(--muted)}
</style>
