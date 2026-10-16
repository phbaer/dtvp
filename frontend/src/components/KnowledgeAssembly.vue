<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Part = { part_id: string; state: string | null; required: boolean; role: 'delivery'; availability?: string }
type Row = Part & { action: 'keep' | 'missing' | 'remove' }
type Target = { state: string | null; predecessor: string | null; previous_kind: string; parts: Part[]; coherence: unknown; capabilities: string[]; limitations: string[]; cross_part_relationships?: unknown[] }
type Preview = { preview_digest: string; readiness: string; missing_required_parts: string[]; selected_part_count: number; counts: Record<string, number>; selection: Part[]; changes: unknown; limitations: string[]; relationship_diagnostics?: unknown }
type Frozen = { project: string; version: string; input: Record<string, unknown>; preview?: Preview }
const props = defineProps<{ project: string; version: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [value: boolean]; assembled: [value: { version: string; part_id: null; kind: 'assembly' }] }>()
const busy = ref(false), error = ref(''), notice = ref(''), version = ref(''), predecessor = ref('')
const target = ref<Target | null>(null), rows = ref<Row[]>([]), choices = ref<{ part_id: string; state: string; source?: string }[]>([])
const query = ref(''), next = ref<number | null>(null), missing = ref(''), versionOptions = ref<string[]>([])
const removal = ref(''), withdrawal = ref(''), policy = ref(''), coherence = ref('unverified'), build = ref(''), rationale = ref(''), frozen = ref<Frozen | null>(null)
const relationships = ref('[]'), relationshipReason = ref('')
const relationshipExample = JSON.stringify([{ relationship_id: 'application-runtime', kind: 'DEPENDS_ON', from: { part_id: 'application', state: 'EXACT_SELECTED_STATE_SHA256', ref: 'ORIGINAL_COMPONENT_REF' }, to: { part_id: 'runtime', state: 'EXACT_SELECTED_STATE_SHA256', ref: 'ORIGINAL_ROOT_REF' }, rationale: 'Reason for this explicit occurrence relationship' }], null, 2)
let sequence = 0
const base = () => `/projects/${encodeURIComponent(props.project)}`
const failure = (value: unknown) => value instanceof Error ? value.message : 'Assembly request failed'
const selectedCount = computed(() => rows.value.filter(item => item.action !== 'remove').length)
const removed = computed(() => rows.value.filter(item => item.action === 'remove' && target.value?.parts.some(old => old.part_id === item.part_id)))
const withdrawn = computed(() => rows.value.filter(item => item.action === 'missing' && target.value?.parts.some(old => old.part_id === item.part_id && old.state)))
const changedPolicy = computed(() => rows.value.some(item => item.action !== 'remove' && target.value?.parts.some(old => old.part_id === item.part_id && old.required !== item.required)))
function invalidate() { sequence++; target.value = null; rows.value = []; choices.value = []; relationships.value = '[]'; relationshipReason.value = ''; error.value = ''; notice.value = '' }
async function search(offset = 0) {
  if (!version.value.trim()) return
  const current = sequence
  try {
    const result = await knowledgeApi<{ items: typeof choices.value; next_offset: number | null }>(`${base()}/assembly-parts?${new URLSearchParams({ version: version.value.trim(), q: query.value, limit: '20', offset: String(offset) })}`)
    if (current !== sequence) return
    choices.value = offset ? [...choices.value, ...result.items] : result.items; next.value = result.next_offset
  } catch (value) { if (current === sequence) error.value = failure(value) }
}
async function versions() {
  if (!props.project) { versionOptions.value = []; return }
  const current = sequence
  try { const value = await knowledgeApi<{ items: { version: string }[] }>(`${base()}/versions?${new URLSearchParams({ q: version.value, limit: '20' })}`); if (current === sequence) versionOptions.value = value.items.map(item => item.version) } catch { /* Inspect remains authoritative. */ }
}
async function inspect() {
  if (busy.value || frozen.value || props.disabled || !version.value.trim()) return
  const current = ++sequence
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const parameters = new URLSearchParams({ version: version.value.trim() }); if (predecessor.value.trim()) parameters.set('predecessor', predecessor.value.trim())
    const value = await knowledgeApi<Target>(`${base()}/assembly-target?${parameters}`)
    if (current !== sequence) return
    target.value = value; rows.value = value.parts.map(part => ({ ...part, action: 'keep' })); relationships.value = JSON.stringify(value.cross_part_relationships || [], null, 2); relationshipReason.value = ''; coherence.value = 'unverified'; build.value = ''; rationale.value = ''; removal.value = ''; withdrawal.value = ''; policy.value = ''; await search()
  } catch (value) { if (current === sequence) error.value = failure(value) }
  finally { if (current === sequence) busy.value = false }
}
function add(part: Part) { if (!rows.value.some(row => row.part_id === part.part_id)) rows.value.push({ ...part, action: 'keep' }) }
function addMissing() { if (missing.value.trim()) { add({ part_id: missing.value.trim(), state: null, required: true, role: 'delivery' }); missing.value = '' } }
function chooseHead(row: Row) { const choice = choices.value.find(item => item.part_id === row.part_id); if (choice) { row.state = choice.state; row.action = 'keep' } }
async function preview() {
  if (busy.value || props.disabled || !target.value?.capabilities.includes('assemble')) return
  const current = sequence
  error.value = ''; busy.value = true; emit('locked', true)
  try {
    const declarations = frozen.value ? null : JSON.parse(relationships.value)
    if (!frozen.value && (!Array.isArray(declarations) || declarations.length > 2000)) throw new Error('Cross-part relationships require a JSON array of at most 2000 declarations.')
    if (!frozen.value) frozen.value = { project: props.project, version: version.value.trim(), input: {
      request_id: crypto.randomUUID(), expected: target.value.state, predecessor: target.value.predecessor,
      parts: rows.value.filter(row => row.action !== 'remove').map(row => ({ part_id: row.part_id, state: row.action === 'missing' ? null : row.state, required: row.required, role: row.role })),
      removed_parts: removed.value.map(row => row.part_id), removal_reason: removal.value,
      withdrawn_parts: withdrawn.value.map(row => row.part_id), withdrawal_reason: withdrawal.value, policy_change_reason: policy.value,
      coherence: { status: coherence.value, build_id: coherence.value === 'producer_declared' ? build.value : null, rationale: coherence.value === 'producer_declared' ? rationale.value : '' },
      ...(declarations.length ? { cross_part_relationships: declarations } : {}),
      ...(relationshipReason.value.trim() ? { relationship_change_reason: relationshipReason.value.trim() } : {}),
    } }
    const capture = frozen.value
    const result = await knowledgeApi<Preview>(`/projects/${encodeURIComponent(capture.project)}/versions/${encodeURIComponent(capture.version)}/assembly-preview`, { method: 'POST', body: JSON.stringify(capture.input) })
    if (current === sequence) capture.preview = result
  } catch (value) { if (current === sequence) error.value = `${failure(value)}. ${frozen.value ? 'Selection and request ID retained; retry or explicitly start a new plan.' : 'Correct the input before previewing.'}` }
  finally { if (current === sequence) { busy.value = false; if (!frozen.value) emit('locked', false) } }
}
async function apply() {
  const capture = frozen.value
  if (busy.value || !capture?.preview) return
  const current = sequence
  busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<{ committed: boolean | null; projection?: string }>(`/projects/${encodeURIComponent(capture.project)}/versions/${encodeURIComponent(capture.version)}/assembly-apply`, { method: 'POST', body: JSON.stringify({ assembly: capture.input, preview_digest: capture.preview.preview_digest }) })
    if (current !== sequence) return
    if (result.committed !== true) throw new Error('Publication is uncertain; retry the identical captured assembly.')
    frozen.value = null; target.value = null; emit('locked', false); notice.value = 'Product assembly published. Source observations remain distinct; current coverage is calculated by the backend.'; emit('assembled', { version: capture.version, part_id: null, kind: 'assembly' })
  } catch (value) { if (current === sequence) error.value = `${failure(value)}. Exact selection, preview and request ID retained for retry; no source pin was advanced.` }
  finally { if (current === sequence) busy.value = false }
}
function reset() { if (busy.value) return; frozen.value = null; emit('locked', false); invalidate() }
watch(() => [props.project, props.version], () => { if (!frozen.value) { invalidate(); version.value = props.version; void versions() } }, { immediate: true })
onBeforeUnmount(() => { sequence++; emit('locked', false) })
</script>
<template>
  <details v-if="project" class="knowledge-assembly"><summary>Assemble product version</summary>
    <section aria-label="Product assembly editor">
      <p class="hint">Select immutable delivery parts. No components are merged and no cross-part dependency edges are invented. Importing a part alone never changes the assembled product.</p>
      <fieldset :disabled="busy || !!frozen || disabled"><form class="assembly-line" @submit.prevent="inspect">
        <label>Assembly version (existing or new)<input v-model="version" list="assembly-versions" required maxlength="200" @input="invalidate(); versions()"></label><datalist id="assembly-versions"><option v-for="item in versionOptions" :key="item" :value="item" /></datalist>
        <details><summary>Branch predecessor</summary><label>Committed product state for a new version<input v-model="predecessor" maxlength="64" @input="invalidate"></label><p class="hint">Source parts must be imported for the target version; a predecessor does not substitute another version's inputs.</p></details><button>Inspect assembly target</button>
      </form></fieldset>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
      <template v-if="target && !frozen">
        <p>Baseline: {{ target.previous_kind.replaceAll('_', ' ') }} · {{ target.state ? target.state.slice(0, 12) : 'new product version' }}</p>
        <p v-if="!target.capabilities.includes('assemble')">Your permissions allow viewing this target only.</p>
        <form v-else aria-label="Prepare product assembly" @submit.prevent="preview"><fieldset :disabled="busy || disabled">
          <div class="assembly-line"><label>Find delivery parts<input v-model="query" type="search" @input="search()"></label><button type="button" @click="search()">Search delivery parts</button></div>
          <ul class="assembly-choices"><li v-for="part in choices" :key="part.part_id"><span>{{ part.part_id }} · {{ part.state.slice(0, 12) }}</span><button type="button" :disabled="rows.some(row => row.part_id === part.part_id) || selectedCount >= 200" @click="add({ ...part, required: true, role: 'delivery' })">Add {{ part.part_id }}</button></li></ul><button v-if="next !== null" type="button" @click="search(next)">More delivery parts</button>
          <div class="assembly-line"><label>Declare missing part ID<input v-model="missing" maxlength="200"></label><button type="button" :disabled="!missing.trim() || selectedCount >= 200" @click="addMissing">Add missing declaration</button></div>
          <p v-if="!rows.length" class="hint">No parts selected. Choose delivery parts or explicitly declare missing inputs.</p>
          <div class="assembly-rows"><article v-for="row in rows" :key="row.part_id"><strong>{{ row.part_id }}</strong><span>{{ row.state ? `Pinned ${row.state.slice(0, 12)}` : 'Missing input' }}</span><label><input v-model="row.required" type="checkbox"> Required {{ row.part_id }}</label><label>Selection for {{ row.part_id }}<select v-model="row.action"><option value="keep">Keep selected pin</option><option value="missing">Declare missing input</option><option value="remove">Remove declaration</option></select></label><button v-if="choices.some(part => part.part_id === row.part_id && part.state !== row.state)" type="button" @click="chooseHead(row)">Use inspected head for {{ row.part_id }}</button><details><summary>Exact source pin</summary><label>SHA for {{ row.part_id }}<input v-model="row.state" maxlength="64"></label></details></article></div>
          <label v-if="removed.length">Removal reason<textarea v-model="removal" required maxlength="2000" /></label><label v-if="withdrawn.length">Withdrawal reason<textarea v-model="withdrawal" required maxlength="2000" /></label><label v-if="changedPolicy">Requirement change reason<textarea v-model="policy" required maxlength="2000" /></label>
          <details><summary>Explicit cross-part relationships</summary><p class="hint">Keep existing declarations unless explicitly changing them. Both endpoints require the exact selected part ID, revision SHA and original component/root reference. No names or package identities are matched. DEPENDS_ON adds a dependency path; CONTAINS records containment only. Source roots remain distinct. Changing a selected pin requires explicitly reviewing its relationship pins.</p><label>Cross-part relationships JSON<textarea v-model="relationships" rows="7" spellcheck="false" /></label><label>Relationship change reason<textarea v-model="relationshipReason" maxlength="2000" rows="2" placeholder="Required when changing or removing an existing relationship" /></label><details><summary>Relationship input example</summary><p class="hint">Replace every placeholder with an exact selected input. The backend validates every reference.</p><pre>{{ relationshipExample }}</pre></details></details>
          <details><summary>Build coherence declaration</summary><p class="hint">Default: unverified. Choosing parts does not prove they came from the same build. A producer declaration remains an attributed claim.</p><label>Coherence<select v-model="coherence"><option value="unverified">Unverified</option><option value="producer_declared">Producer declared</option></select></label><template v-if="coherence === 'producer_declared'"><label>Build identity<input v-model="build" required maxlength="200"></label><label>Coherence rationale<textarea v-model="rationale" required maxlength="2000" /></label></template><details v-if="target.coherence"><summary>Previous declaration (not reused)</summary><pre>{{ JSON.stringify(target.coherence, null, 2) }}</pre></details></details>
          <button class="primary" :disabled="!rows.some(row => row.action !== 'remove')">Preview exact assembly</button>
        </fieldset></form>
      </template>
      <section v-if="frozen" aria-label="Frozen assembly selection"><p>Selection and request ID are frozen. Source head changes never replace these pins.</p><template v-if="frozen.preview"><p><strong>{{ frozen.preview.readiness.replaceAll('_', ' ') }}</strong> · {{ frozen.preview.selected_part_count }} selected inputs · discovery coverage not verified</p><p v-if="frozen.preview.missing_required_parts.length">Missing required parts: {{ frozen.preview.missing_required_parts.join(', ') }}</p><dl><template v-for="(value, key) in frozen.preview.counts" :key="key"><dt>{{ String(key).replaceAll('_', ' ') }}</dt><dd>{{ value }}</dd></template></dl><ul><li v-for="limitation in frozen.preview.limitations" :key="limitation">{{ limitation }}</li></ul><details><summary>Exact selection and structural changes</summary><pre>{{ JSON.stringify({ input: frozen.input, changes: frozen.preview.changes, relationship_diagnostics: frozen.preview.relationship_diagnostics }, null, 2) }}</pre></details><button class="primary" :disabled="busy" @click="apply">Publish selected assembly</button></template><button v-else :disabled="busy" @click="preview">Retry exact preview</button><button :disabled="busy" @click="reset">Discard plan and inspect again</button></section>
    </section>
  </details>
</template>
<style scoped>
.knowledge-assembly{margin-block:1rem;border:1px solid var(--border);border-radius:8px;padding:.7rem}.knowledge-assembly summary{cursor:pointer;font-weight:600}.knowledge-assembly section{min-width:0;padding-block:.5rem}.knowledge-assembly fieldset{border:0;padding:0;margin:0;min-width:0}.assembly-line{display:flex;gap:.7rem;align-items:end;flex-wrap:wrap;margin-block:.7rem}.assembly-line label{flex:1;min-width:160px}.assembly-choices,.assembly-rows{max-height:26rem;overflow:auto;list-style:none;padding:0}.assembly-choices li,.assembly-rows article{display:flex;gap:.7rem;flex-wrap:wrap;align-items:center;padding:.6rem;border-bottom:1px solid var(--border)}.assembly-rows article>label{min-width:120px}.knowledge-assembly pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:18rem;overflow:auto}.knowledge-assembly input,.knowledge-assembly select,.knowledge-assembly textarea{max-width:100%;box-sizing:border-box}.knowledge-assembly dl{display:grid;grid-template-columns:auto 1fr;gap:.3rem 1rem}.knowledge-assembly dd{margin:0}.knowledge-assembly button{margin:.2rem}
</style>
