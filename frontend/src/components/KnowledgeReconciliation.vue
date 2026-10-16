<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError, send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
type Kind = 'component' | 'context'
type Pair = { kind: Kind; source_id: string; target_id: string }
type Facts = { name?: string; version?: string; purl?: string; [key: string]: unknown }
type Occurrence = { id: string; kind: Kind; component_ref: string; root_ref: string | null; component: Facts | null; root: Facts | null; team_id: string | null; ownership_status: string | null }
type Catalog = { items: Occurrence[]; total: number; next_offset: number | null }
type Pane = { q: string; data: Catalog | null; offset: number; previous: number[]; selected: string }
type Reference = { kind: string; name: string; version: string; state: string }
type History = { state: string; version: string; reason: string; created_at: string }
type Preview = { source: string; target: string; preview_digest: string; eligible: boolean; items: (Pair & { classification: string; reasons: string[]; source_facts: unknown; target_facts: unknown })[]; limitations: string[] }
type Payload = { reconciliation_id: string; source: string; target: string; stage: string; rationale: string; evidence: object[]; preview: Preview; actor_id: string; retraction_reason?: string }
type Record = { revision: string; payload: Payload; in_version_scope: boolean }
const props = defineProps<{ project: string; version: string; state: string }>()
const emit = defineEmits<{ changed: [] }>()
const expanded = ref(false), busy = ref(false), error = ref(''), notice = ref(''), source = ref(''), target = ref(props.state), advancedSource = ref(''), stale = ref(false)
const references = ref<Reference[]>([]), refsNext = ref<number | null>(null), history = ref<History[]>([]), historyNext = ref<number | null>(null), historyOffset = ref(0), historyPrevious = ref<number[]>([]), historyVersion = ref('')
const emptyPane = (): Pane => ({ q: '', data: null, offset: 0, previous: [], selected: '' })
const panes = ref({ source: emptyPane(), target: emptyPane() }), kind = ref<Kind>('component'), pairs = ref<Pair[]>([]), preview = ref<Preview | null>(null)
const registry = ref<{ items: Record[]; total: number; next_offset: number | null; capabilities: string[] } | null>(null), registryOffset = ref(0), registryPrevious = ref<number[]>([])
const id = ref(crypto.randomUUID() as string), revision = ref<string | null>(null), rationale = ref(''), evidence = ref('[]'), retractReason = ref(''), retractId = ref('')
const pending = ref<{ action: 'confirm' | 'retract'; recordId: string; endpoint: string; input: object; requestId: string } | null>(null)
let sequence = 0
const root = () => `/projects/${encodeURIComponent(props.project)}`
const writable = computed(() => registry.value?.capabilities.includes('write'))
const human = (value: string) => value.replaceAll('_', ' ')
const title = (row: Occurrence) => `${row.component?.name || row.component_ref} ${row.component?.version || ''}${row.kind === 'context' ? ` · via ${row.root?.name || row.root_ref}` : ''}`
function fail(value: unknown) { error.value = value instanceof Error ? value.message : 'Correspondence request failed' }
function clearPreview() { preview.value = null; pending.value = null }
function chooseSource(state: string) { source.value = state; pairs.value = []; panes.value = { source: emptyPane(), target: emptyPane() }; clearPreview(); error.value = '' }
async function read<T>(path: string): Promise<T | null> {
  if (busy.value) return null
  const current = sequence; busy.value = true; error.value = ''
  try { const data = await knowledgeApi<T>(path); return current === sequence ? data : null }
  catch (err) { if (current === sequence) fail(err); return null }
  finally { if (current === sequence) busy.value = false }
}
async function loadRefs(append = false) {
  const data = await read<{ items: Reference[]; next_offset: number | null }>(`${root()}/refs?offset=${append ? refsNext.value || 0 : 0}&limit=50`)
  if (data) { references.value = append ? [...references.value, ...data.items] : data.items; refsNext.value = data.next_offset }
}
async function loadRegistry(page = 0) {
  const selectedTarget = target.value
  const data = await read<NonNullable<typeof registry.value>>(`${root()}/states/${encodeURIComponent(selectedTarget)}/reconciliations?offset=${page}&limit=20`)
  if (data && selectedTarget === target.value) { registry.value = data; registryOffset.value = page; return true }; return false
}
async function toggle(event: Event) { expanded.value = (event.currentTarget as HTMLDetailsElement).open; if (expanded.value && !registry.value) { await loadRegistry(); await loadRefs() } }
async function loadHistory(page = 0) {
  const params = new URLSearchParams({ offset: String(page), limit: '20' }); if (historyVersion.value.trim()) params.set('version', historyVersion.value.trim())
  const data = await read<{ items: History[]; next_offset: number | null }>(`${root()}/history?${params}`)
  if (data) { history.value = data.items; historyNext.value = data.next_offset; historyOffset.value = page; return true }; return false
}
async function historyPage(next: boolean) {
  const page = next ? historyNext.value : historyPrevious.value.at(-1); if (page == null) return
  const old = historyOffset.value; if (await loadHistory(page)) { if (next) historyPrevious.value.push(old); else historyPrevious.value.pop() }
}
async function loadCatalog(side: 'source' | 'target', page = 0) {
  const state = side === 'source' ? source.value : target.value; if (!state) return false
  const pane = panes.value[side]
  const params = new URLSearchParams({ kind: kind.value, q: pane.q, offset: String(page), limit: '20' })
  const data = await read<Catalog>(`${root()}/states/${encodeURIComponent(state)}/reconciliation-candidates?${params}`)
  if (data) { pane.data = data; pane.offset = page; pane.selected = ''; return true }; return false
}
async function catalogPage(side: 'source' | 'target', next: boolean) {
  const pane = panes.value[side], page = next ? pane.data?.next_offset : pane.previous.at(-1); if (page == null) return
  const old = pane.offset; if (await loadCatalog(side, page)) { if (next) pane.previous.push(old); else pane.previous.pop() }
}
function add() {
  if (pending.value || pairs.value.length >= 100) return
  const pair = { kind: kind.value, source_id: panes.value.source.selected, target_id: panes.value.target.selected }
  if (!pair.source_id || !pair.target_id) return
  if (pairs.value.some(item => item.kind === pair.kind && (item.source_id === pair.source_id || item.target_id === pair.target_id))) { error.value = 'Each source and target occurrence can appear only once within its relation kind.'; return }
  pairs.value.push(pair); clearPreview(); panes.value.source.selected = ''; panes.value.target.selected = ''; error.value = ''
}
async function inspect() {
  if (!pairs.value.length || !source.value || busy.value || pending.value) return
  const current = sequence; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Preview>(`${root()}/reconciliation/preview`, send({ source: source.value, target: target.value, pairs: pairs.value }))
    if (current === sequence) preview.value = data
  } catch (err) { if (current === sequence) { fail(err); if (err instanceof ApiError && err.status === 409) stale.value = true } }
  finally { if (current === sequence) busy.value = false }
}
function edit(row: Record) {
  chooseSource(row.payload.source); target.value = props.state; stale.value = false; id.value = row.payload.reconciliation_id; revision.value = row.revision; rationale.value = row.payload.rationale; evidence.value = JSON.stringify(row.payload.evidence, null, 2); pairs.value = row.payload.preview.items.map(({ kind, source_id, target_id }) => ({ kind, source_id, target_id }))
}
function fresh() { const targetChanged = target.value !== props.state; if (targetChanged) registry.value = null; pending.value = null; preview.value = null; target.value = props.state; stale.value = false; revision.value = null; id.value = crypto.randomUUID(); rationale.value = ''; evidence.value = '[]'; pairs.value = []; panes.value = { source: emptyPane(), target: emptyPane() }; retractReason.value = ''; retractId.value = ''; error.value = ''; notice.value = ''; if (targetChanged && expanded.value && !busy.value) void loadRegistry() }
async function mutate(action: 'confirm' | 'retract', row?: Record) {
  if (busy.value || !writable.value || (pending.value && (pending.value.action !== action || (action === 'retract' && pending.value.recordId !== row?.payload.reconciliation_id)))) return
  const current = sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    if (!pending.value) {
      let input: object, recordId: string
      if (action === 'confirm') {
        if (!preview.value?.eligible || !rationale.value.trim()) return
        const refs: unknown = JSON.parse(evidence.value)
        if (!Array.isArray(refs) || refs.some(item => !item || typeof item !== 'object' || Array.isArray(item))) throw new Error('Evidence references must be a JSON array of objects.')
        input = { expected: target.value, expected_revision: revision.value, source: preview.value.source, preview_digest: preview.value.preview_digest, pairs: pairs.value, rationale: rationale.value, evidence: refs }; recordId = id.value
      } else {
        if (!row || !row.in_version_scope || row.payload.stage !== 'active' || !retractReason.value.trim()) return
        input = { expected: target.value, expected_revision: row.revision, reason: retractReason.value }; recordId = row.payload.reconciliation_id
      }
      pending.value = { action, recordId, endpoint: `${root()}/versions/${encodeURIComponent(props.version)}/reconciliations/${encodeURIComponent(recordId)}/${action}`, input, requestId: crypto.randomUUID() }
    }
    await knowledgeApi(pending.value.endpoint, send({ ...pending.value.input, request_id: pending.value.requestId }))
    if (current !== sequence) return
    fresh(); notice.value = action === 'confirm' ? 'Attributed correspondence recorded. No identities, decisions or approvals were transferred.' : 'Correspondence retracted; prior assertions remain in history.'; emit('changed'); busy.value = false; await loadRegistry()
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function registryPage(next: boolean) {
  const page = next ? registry.value?.next_offset : registryPrevious.value.at(-1); if (page == null) return
  const old = registryOffset.value; if (await loadRegistry(page)) { if (next) registryPrevious.value.push(old); else registryPrevious.value.pop() }
}
function applyAdvanced() { if (/^[a-f0-9]{64}$/.test(advancedSource.value)) chooseSource(advancedSource.value); else error.value = 'Use a complete lowercase SHA-256 product state.' }
watch(kind, () => { panes.value = { source: emptyPane(), target: emptyPane() } })
watch(() => props.state, () => { if (pending.value || preview.value || pairs.value.length) stale.value = true; else { ++sequence; busy.value = false; registry.value = null; target.value = props.state; if (expanded.value) void loadRegistry() } })
watch(() => [props.project, props.version], () => { ++sequence; busy.value = false; fresh(); source.value = ''; references.value = []; history.value = []; registry.value = null; refsNext.value = null; historyNext.value = null; historyPrevious.value = []; registryPrevious.value = []; if (expanded.value) void loadRegistry().then(() => loadRefs()) })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <details class="knowledge-reconciliation" @toggle="toggle"><summary>Occurrence correspondence across imports</summary>
    <section aria-label="Occurrence correspondence">
      <p class="hint">Record an attributed component or consuming-context correspondence after a producer changes references. These are separate relations, never verified identity or automatic transfer of assessments, ownership, evidence, metadata or approvals.</p>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p><p v-if="stale" class="hint">The workspace target advanced. The current request retains its original pins; start a new assertion to select the new baseline.</p>
      <div class="actions"><button type="button" :disabled="busy" @click="loadRegistry(registryOffset)">Refresh correspondence registry</button><button type="button" :disabled="busy" @click="fresh">New correspondence assertion</button></div>
      <label>Source branch or tag<select :value="source" :disabled="busy || Boolean(pending)" @change="chooseSource(($event.target as HTMLSelectElement).value)"><option value="">Select a pinned source</option><option v-if="source && !references.some(item => item.state === source)" :value="source">Historical state · {{ source.slice(0, 12) }}</option><option v-for="item in references" :key="item.kind + item.name" :value="item.state">{{ item.kind }} · {{ item.name }} · {{ item.state.slice(0, 12) }}</option></select></label><button v-if="refsNext != null" type="button" :disabled="busy" @click="loadRefs(true)">More source references</button>
      <details><summary>Historical source states</summary><form @submit.prevent="historyPrevious = []; loadHistory()"><label>History version filter<input v-model="historyVersion" maxlength="200" :disabled="busy"></label><button :disabled="busy">Search source history</button></form><ul><li v-for="item in history" :key="item.state"><button type="button" :disabled="busy || Boolean(pending)" @click="chooseSource(item.state)">{{ item.version }} · {{ item.reason }} · {{ item.state.slice(0, 12) }}</button></li></ul><div class="actions"><button type="button" :disabled="busy || !historyPrevious.length" @click="historyPage(false)">Previous source history</button><button type="button" :disabled="busy || historyNext == null" @click="historyPage(true)">Next source history</button></div></details>
      <details><summary>Advanced source state identifier</summary><label>Historical source SHA-256<input v-model="advancedSource" :disabled="busy || Boolean(pending)"></label><button type="button" :disabled="busy || Boolean(pending)" @click="applyAdvanced">Use exact historical source</button></details>
      <details><summary>Selected state pins</summary><p>Source <code>{{ source || 'Not selected' }}</code></p><p>Target {{ version }} <code>{{ target }}</code></p><p>Assertion {{ id }} · previous revision {{ revision || 'None (new assertion)' }}</p></details>
      <label>Relation kind<select v-model="kind" :disabled="busy || Boolean(pending)"><option value="component">Component occurrence</option><option value="context">Consuming context</option></select></label>
      <div class="selectors"><section v-for="side in (['source', 'target'] as const)" :key="side" :aria-label="`${side} occurrence selector`"><form @submit.prevent="panes[side].previous = []; loadCatalog(side)"><label>{{ side === 'source' ? 'Source occurrence search' : 'Target occurrence search' }}<input v-model="panes[side].q" :disabled="busy || Boolean(pending)" maxlength="200"></label><button :disabled="busy || Boolean(pending) || (side === 'source' && !source)">{{ side === 'source' ? 'Search source occurrences' : 'Search target occurrences' }}</button></form><p v-if="panes[side].data">{{ panes[side].data!.total }} matching {{ kind }} occurrences</p><label v-for="item in panes[side].data?.items" :key="item.id" class="choice"><input v-model="panes[side].selected" type="radio" :name="`correspondence-${side}`" :value="item.id" :disabled="busy || Boolean(pending)"><span>{{ title(item) }}<small>{{ item.id }}</small></span></label><div class="actions"><button type="button" :disabled="busy || Boolean(pending) || !panes[side].previous.length" @click="catalogPage(side, false)">Previous {{ side }} occurrences</button><button type="button" :disabled="busy || Boolean(pending) || panes[side].data?.next_offset == null" @click="catalogPage(side, true)">Next {{ side }} occurrences</button></div></section></div>
      <button type="button" :disabled="busy || Boolean(pending) || !panes.source.selected || !panes.target.selected || pairs.length >= 100" @click="add">Add explicit correspondence pair</button>
      <p>{{ pairs.length }}/100 explicitly selected pairs</p><ul class="pairs"><li v-for="(pair, index) in pairs" :key="pair.kind + pair.source_id"><strong>{{ pair.kind }}</strong> {{ pair.source_id }} → {{ pair.target_id }} <button type="button" :disabled="busy || Boolean(pending)" @click="pairs.splice(index, 1); clearPreview()">Remove pair {{ index + 1 }}</button></li></ul>
      <button type="button" :disabled="busy || Boolean(pending) || !pairs.length" @click="inspect">Preview correspondence</button>
      <div v-if="preview" aria-label="Correspondence preview"><p>{{ preview.eligible ? 'Eligible attributed assertion; identity is not verified.' : 'Blocked: conflicting or missing occurrences.' }}</p><details v-for="(item, index) in preview.items" :key="index"><summary>{{ item.kind }} · {{ human(item.classification) }}</summary><p v-for="reason in item.reasons" :key="reason">{{ human(reason) }}</p><pre>{{ JSON.stringify({ source: item.source_facts, target: item.target_facts }, null, 2) }}</pre></details><p v-for="text in preview.limitations" :key="text" class="hint">{{ text }}</p></div>
      <form v-if="writable" aria-label="Record correspondence" @submit.prevent="mutate('confirm')"><label>Correspondence rationale<textarea v-model="rationale" required maxlength="6000" :disabled="busy || Boolean(pending)" /></label><details><summary>Attributed evidence references</summary><label>Correspondence evidence (JSON array)<textarea v-model="evidence" spellcheck="false" :disabled="busy || Boolean(pending)" /></label></details><button :disabled="busy || pending?.action === 'retract' || (!pending && (!preview?.eligible || !rationale.trim() || stale))">{{ pending ? 'Resend identical correspondence request' : 'Record attributed correspondence' }}</button></form>
      <p v-if="registry">{{ registry.total }} retained assertions in this pinned target state</p><article v-for="row in registry?.items" :key="row.revision"><strong>{{ row.payload.reconciliation_id }} · {{ human(row.payload.stage) }}</strong><p>{{ row.payload.rationale }}</p><p v-if="!row.in_version_scope" class="hint">Historical assertion from another version; no current coverage is inferred.</p><details><summary>Recorded correspondence pins and evidence</summary><pre>{{ JSON.stringify(row, null, 2) }}</pre></details><template v-if="writable && row.in_version_scope"><button type="button" :disabled="busy || Boolean(pending)" @click="edit(row)">Supersede assertion {{ row.payload.reconciliation_id }}</button><button v-if="row.payload.stage === 'active'" type="button" :disabled="busy || Boolean(pending)" @click="retractId = row.payload.reconciliation_id; retractReason = ''">Consider retraction {{ row.payload.reconciliation_id }}</button><form v-if="row.payload.stage === 'active' && retractId === row.payload.reconciliation_id" @submit.prevent="mutate('retract', row)"><label>Retraction reason<textarea v-model="retractReason" required maxlength="6000" :disabled="busy || Boolean(pending)" /></label><button :disabled="busy || (pending && (pending.action !== 'retract' || pending.recordId !== row.payload.reconciliation_id)) || (!pending && !retractReason.trim())">{{ pending ? 'Resend identical retraction request' : 'Retract assertion' }}</button></form></template></article>
      <nav class="actions" aria-label="Correspondence registry pages"><button type="button" :disabled="busy || !registryPrevious.length" @click="registryPage(false)">Previous correspondence assertions</button><button type="button" :disabled="busy || registry?.next_offset == null" @click="registryPage(true)">Next correspondence assertions</button></nav>
    </section>
  </details>
</template>
<style scoped>
.knowledge-reconciliation { margin-block: .75rem; padding: .8rem; border: 1px solid var(--line); border-radius: .65rem; min-width: 0; } summary { cursor: pointer; font-weight: 600; } section, article, form, li { min-width: 0; overflow-wrap: anywhere; }.hint, small { font-size: .85rem; color: var(--muted); }.actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-block: .6rem; } label { display: grid; gap: .3rem; margin-block: .6rem; } input, select, textarea { width: 100%; min-width: 0; box-sizing: border-box; } textarea { min-height: 4rem; }.selectors { display: grid; grid-template-columns: repeat(auto-fit,minmax(min(250px,100%),1fr)); gap: 1rem; }.choice { display: flex; align-items: flex-start; }.choice input { width: auto; margin-top: .2rem; }.choice small { display: block; font-size: .7rem; }article { border-top: 1px solid var(--line); padding-block: .8rem; }pre { overflow-wrap: anywhere; white-space: pre-wrap; max-height: 18rem; overflow: auto; font-size: .75rem; }code { font-size: .75rem; overflow-wrap: anywhere; }.pairs { padding-left: 1.2rem; }
</style>
