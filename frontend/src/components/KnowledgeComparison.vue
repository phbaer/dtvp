<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import { send } from '../api'

type Reference = { kind: 'branch' | 'tag'; name: string; state: string; version: string; created_at: string }
type Revision = { state: string; version: string; created_at: string; reason: string; actor_id: string; parents: string[] }
type Choice = { id: string; state: string; label: string }
type Change = { category: string; key: string | string[]; change: string; classifications: string[]; before: Record<string, unknown> | null; after: Record<string, unknown> | null }
type Comparison = { before: string; after: string; before_version: string; after_version: string; items: Change[]; total: number; next_offset: number | null; summary: { by_category: Record<string, number>; by_classification: Record<string, number> }; retention: { before: { retained_assessments: number; retained_absent_assessments: number }; after: { retained_assessments: number; retained_absent_assessments: number } }; limitations: string[] }
type SyncPreview = { preview_digest: string; mode: string; total: number; next_offset: number | null; items: { id: string; category: string; vulnerability_id?: string; reasons: string[]; requires_new_target_review: boolean; [key: string]: unknown }[]; limitations: string[] }
const synchronization = ref<SyncPreview | null>(null), syncBusy = ref(false), syncOffset = ref(0), syncPrevious = ref<number[]>([])
let syncSequence = 0
const props = defineProps<{ project: string }>()
const expanded = ref(false), references = ref<Reference[]>([]), referencesNext = ref<number | null>(null)
const before = ref(''), after = ref(''), beforeHistory = ref<Choice | null>(null), afterHistory = ref<Choice | null>(null)
const history = ref<Revision[]>([]), historyNext = ref<number | null>(null), historyVersion = ref(''), historyLoaded = ref(false)
const result = ref<Comparison | null>(null), offset = ref(0), previous = ref<number[]>([])
const refsBusy = ref(false), historyBusy = ref(false), compareBusy = ref(false), error = ref('')
let projectSequence = 0, comparisonSequence = 0, historySequence = 0
const human = (value: string) => value.replaceAll('_', ' ')
const referenceChoices = computed<Choice[]>(() => references.value.map(item => ({ id: `${item.kind}:${item.name}:${item.state}`, state: item.state, label: `${item.kind === 'tag' ? 'Tag' : 'Version'} · ${item.name}` })))
const choices = computed(() => [...referenceChoices.value, ...[beforeHistory.value, afterHistory.value].filter((value): value is Choice => Boolean(value)).filter((value, index, all) => all.findIndex(other => other.id === value.id) === index)])
const beforeState = computed(() => choices.value.find(item => item.id === before.value)?.state || '')
const afterState = computed(() => choices.value.find(item => item.id === after.value)?.state || '')
const endpoint = () => `/projects/${encodeURIComponent(props.project)}`
function failure(err: unknown) { error.value = err instanceof Error ? err.message : 'Comparison request failed' }
function changed() { ++syncSequence; synchronization.value = null; syncOffset.value = 0; syncPrevious.value = []; syncBusy.value = false; ++comparisonSequence; result.value = null; offset.value = 0; previous.value = []; compareBusy.value = false; error.value = '' }
async function loadReferences(append = false) {
  if (!props.project || refsBusy.value) return
  const scope = projectSequence
  refsBusy.value = true; error.value = ''
  try {
    const query = new URLSearchParams({ offset: String(append ? referencesNext.value || 0 : 0), limit: '50' })
    const data = await knowledgeApi<{ items: Reference[]; next_offset: number | null }>(`${endpoint()}/refs?${query}`)
    if (scope !== projectSequence) return
    references.value = append ? [...references.value, ...data.items] : data.items; referencesNext.value = data.next_offset
    if (!before.value) before.value = referenceChoices.value[0]?.id || ''
    if (!after.value) after.value = referenceChoices.value[1]?.id || referenceChoices.value[0]?.id || ''
  } catch (err) { if (scope === projectSequence) failure(err) }
  finally { if (scope === projectSequence) refsBusy.value = false }
}
function toggle(event: Event) {
  expanded.value = (event.currentTarget as HTMLDetailsElement).open
  if (expanded.value && references.value.length === 0) void loadReferences()
}
async function loadHistory(append = false) {
  if (!props.project) return
  const scope = projectSequence, request = ++historySequence
  historyBusy.value = true; error.value = ''
  try {
    const query = new URLSearchParams({ offset: String(append ? historyNext.value || 0 : 0), limit: '20' })
    if (historyVersion.value.trim()) query.set('version', historyVersion.value.trim())
    const data = await knowledgeApi<{ items: Revision[]; next_offset: number | null }>(`${endpoint()}/history?${query}`)
    if (scope !== projectSequence || request !== historySequence) return
    history.value = data.items; historyNext.value = data.next_offset; historyLoaded.value = true
  } catch (err) { if (scope === projectSequence && request === historySequence) failure(err) }
  finally { if (scope === projectSequence && request === historySequence) historyBusy.value = false }
}
function toggleHistory(event: Event) {
  if ((event.currentTarget as HTMLDetailsElement).open && !historyLoaded.value) void loadHistory()
}
function chooseHistorical(revision: Revision, side: 'before' | 'after') {
  const choice = { id: `history:${revision.state}`, state: revision.state, label: `${revision.version} · ${revision.reason} · ${revision.state.slice(0, 10)}` }
  if (side === 'before') { beforeHistory.value = choice; before.value = choice.id }
  else { afterHistory.value = choice; after.value = choice.id }
  changed()
}
async function compare(reset = true) {
  if (!beforeState.value || !afterState.value) return
  const scope = projectSequence, request = ++comparisonSequence
  if (reset) { offset.value = 0; previous.value = []; result.value = null }
  compareBusy.value = true; error.value = ''
  try {
    const query = new URLSearchParams({ before: beforeState.value, after: afterState.value, offset: String(offset.value), limit: '25' })
    const data = await knowledgeApi<Comparison>(`${endpoint()}/compare/details?${query}`)
    if (scope === projectSequence && request === comparisonSequence) result.value = data
  } catch (err) { if (scope === projectSequence && request === comparisonSequence) failure(err) }
  finally { if (scope === projectSequence && request === comparisonSequence) compareBusy.value = false }
}
async function previewSynchronization(nextOffset = 0) {
  if (!beforeState.value || !afterState.value) return
  const scope = projectSequence, request = ++syncSequence
  syncBusy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<SyncPreview>(`${endpoint()}/synchronization/preview?offset=${nextOffset}&limit=20`, send({ source: beforeState.value, target: afterState.value }))
    if (scope === projectSequence && request === syncSequence) { synchronization.value = data; syncOffset.value = nextOffset }
  } catch (err) { if (scope === projectSequence && request === syncSequence) failure(err) }
  finally { if (scope === projectSequence && request === syncSequence) syncBusy.value = false }
}
async function syncPage(forward: boolean) {
  if (!synchronization.value || syncBusy.value) return
  const old = syncOffset.value
  await previewSynchronization(forward ? synchronization.value.next_offset! : syncPrevious.value.at(-1) || 0)
  if (syncOffset.value !== old) { if (forward) syncPrevious.value.push(old); else syncPrevious.value.pop() }
}
async function paginate(forward: boolean) {
  if (!result.value) return
  if (forward) { previous.value.push(offset.value); offset.value = result.value.next_offset! }
  else offset.value = previous.value.pop() || 0
  await compare(false)
}
function title(change: Change) {
  const item = change.after || change.before
  if (change.category === 'context_finding') return `${item?.vulnerability_id || 'Finding'} · ${item?.component_ref || ''}`
  return String(item?.name || (Array.isArray(change.key) ? change.key.join(' → ') : change.key))
}
watch(() => props.project, () => {
  ++projectSequence; ++historySequence; changed(); references.value = []; referencesNext.value = null
  before.value = ''; after.value = ''; beforeHistory.value = null; afterHistory.value = null
  history.value = []; historyNext.value = null; historyLoaded.value = false; historyVersion.value = ''
  refsBusy.value = false; historyBusy.value = false
  if (expanded.value) void loadReferences()
})
onBeforeUnmount(() => { ++syncSequence; ++projectSequence; ++comparisonSequence; ++historySequence })
</script>

<template>
  <details v-if="project" class="knowledge-comparison" @toggle="toggle">
    <summary>Compare versions and history</summary>
    <section aria-label="Historical state comparison" :aria-busy="compareBusy">
      <div class="comparison-controls">
        <label>Before state<select v-model="before" :disabled="refsBusy || compareBusy" @change="changed"><option value="" disabled>Select a state</option><option v-for="choice in choices" :key="choice.id" :value="choice.id">{{ choice.label }}</option></select></label>
        <span class="comparison-arrow" aria-hidden="true">→</span>
        <label>After state<select v-model="after" :disabled="refsBusy || compareBusy" @change="changed"><option value="" disabled>Select a state</option><option v-for="choice in choices" :key="choice.id" :value="choice.id">{{ choice.label }}</option></select></label>
        <button :disabled="refsBusy || compareBusy || !beforeState || !afterState" @click="compare()">{{ compareBusy ? 'Comparing…' : 'Compare states' }}</button>
      </div>
      <div v-if="refsBusy || referencesNext !== null" class="comparison-reference-tools"><small v-if="refsBusy" role="status">Loading version references…</small><button v-if="referencesNext !== null" :disabled="refsBusy" @click="loadReferences(true)">More version references</button></div>
      <p v-if="!refsBusy && references.length === 0" class="hint">No accepted version or release references available.</p>
      <p v-if="error" role="alert">{{ error }}</p>
      <details class="comparison-history" @toggle="toggleHistory">
        <summary>Choose an earlier import or review state</summary>
        <form class="comparison-history-search" @submit.prevent="loadHistory()"><label>History version (optional)<input v-model="historyVersion" placeholder="All versions" /></label><button :disabled="historyBusy">Find history</button></form>
        <p v-if="historyBusy" role="status">Loading history…</p>
        <p v-else-if="historyLoaded && history.length === 0" class="hint">No matching historical states.</p>
        <ul class="comparison-history-list"><li v-for="revision in history" :key="revision.state"><span><strong>{{ revision.version }}</strong> · {{ revision.reason }}<small>{{ revision.created_at }} · {{ revision.state.slice(0, 12) }}</small></span><button @click="chooseHistorical(revision, 'before')" :aria-label="`Use ${revision.version} ${revision.reason} as before`">Before</button><button @click="chooseHistorical(revision, 'after')" :aria-label="`Use ${revision.version} ${revision.reason} as after`">After</button></li></ul>
        <div class="comparison-page"><button v-if="historyNext !== null" :disabled="historyBusy" @click="loadHistory(true)">Next history page</button><button v-if="historyLoaded && history.length > 0" :disabled="historyBusy" @click="loadHistory()">Newest history</button></div>
      </details>
      <details class="comparison-scope"><summary>Assessment reuse between selected states</summary><p class="hint">Before is the source; After is the target. This preview compares content without confirming a software merge or changing inventory, assessments or approvals.</p><button :disabled="syncBusy || refsBusy || !beforeState || !afterState" @click="syncPrevious = []; previewSynchronization()">Preview assessment reuse</button><p v-if="syncBusy" role="status">Preparing reuse preview…</p><section v-if="synchronization" aria-label="Assessment reuse preview"><strong>{{ synchronization.total }} candidates · {{ human(synchronization.mode) }}</strong><details v-for="row in synchronization.items" :key="row.id" class="comparison-row"><summary>{{ row.vulnerability_id || 'Unknown scope' }} · {{ human(row.category) }}</summary><p>{{ row.reasons.map(human).join(' · ') }}</p><p v-if="row.requires_new_target_review" class="hint">New target coverage requires independent review.</p><pre>{{ JSON.stringify(row, null, 2) }}</pre></details><nav class="comparison-page" aria-label="Assessment reuse pages"><button :disabled="syncBusy || !syncPrevious.length" @click="syncPage(false)">Previous candidates</button><button :disabled="syncBusy || synchronization.next_offset === null" @click="syncPage(true)">Next candidates</button></nav><details><summary>Reuse limitations and preview pin</summary><code>{{ synchronization.preview_digest }}</code><ul><li v-for="limit in synchronization.limitations" :key="limit">{{ limit }}</li></ul></details></section></details>
      <template v-if="result">
        <div class="comparison-summary" aria-label="Comparison totals"><strong>{{ result.total }} changes</strong><span v-for="(count, category) in result.summary.by_category" :key="category">{{ human(String(category)) }}: {{ count }}</span></div>
        <p v-if="result.total === 0" role="status">No differences between these pinned states.</p>
        <p class="hint comparison-limitation">Exact source-local references; changed references appear as additions/removals. Removed findings do not prove remediation.</p>
        <div class="comparison-rows" aria-label="Historical changes">
          <details v-for="(change, index) in result.items" :key="`${change.category}:${JSON.stringify(change.key)}:${index}`" class="comparison-row">
            <summary><span class="comparison-change">{{ human(change.change) }}</span><strong>{{ title(change) }}</strong><small>{{ human(change.category) }} · {{ change.classifications.map(human).join(', ') }}</small></summary>
            <div class="comparison-values"><div><h4>Before</h4><pre>{{ change.before === null ? 'Absent in this state' : JSON.stringify(change.before, null, 2) }}</pre></div><div><h4>After</h4><pre>{{ change.after === null ? 'Absent in this state' : JSON.stringify(change.after, null, 2) }}</pre></div></div>
          </details>
        </div>
        <nav class="comparison-page" aria-label="Comparison pages"><button :disabled="previous.length === 0 || compareBusy" @click="paginate(false)">Previous changes</button><button :disabled="result.next_offset === null || compareBusy" @click="paginate(true)">Next changes</button></nav>
        <details class="comparison-scope"><summary>Pinned states, classifications and retained assessments</summary><p class="comparison-pins">Before: {{ result.before_version }} · <code>{{ result.before }}</code><br />After: {{ result.after_version }} · <code>{{ result.after }}</code></p><p>Retained assessments: {{ result.retention.before.retained_assessments }} before → {{ result.retention.after.retained_assessments }} after. Absent targets: {{ result.retention.before.retained_absent_assessments }} before → {{ result.retention.after.retained_absent_assessments }} after.</p><p>Server classifications may overlap: <span v-for="(count, kind) in result.summary.by_classification" :key="kind">{{ human(String(kind)) }} {{ count }}; </span></p><ul><li v-for="limitation in result.limitations" :key="limitation">{{ limitation }}</li></ul></details>
      </template>
    </section>
  </details>
</template>

<style scoped>
.knowledge-comparison { margin-block: .75rem; border: 1px solid var(--border, #64748b55); border-radius: .65rem; padding: .7rem .9rem; }
.knowledge-comparison > summary { cursor: pointer; font-weight: 600; }
.knowledge-comparison section { padding-top: .75rem; min-width: 0; }
.comparison-controls { display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr) auto; gap: .65rem; align-items: end; }
.comparison-controls label, .comparison-history-search label { display: grid; gap: .25rem; min-width: 0; }
.comparison-controls select { width: 100%; min-width: 0; }
.comparison-arrow { padding-block: .6rem; }
.comparison-reference-tools, .comparison-page, .comparison-history-search { display: flex; flex-wrap: wrap; align-items: end; gap: .6rem; margin-block: .6rem; }
.comparison-history { margin-block: .7rem; }
.comparison-history-search input { min-width: 0; }
.comparison-history-list { list-style: none; padding: 0; }
.comparison-history-list li { display: flex; align-items: center; gap: .5rem; padding-block: .45rem; border-bottom: 1px solid var(--border, #64748b33); }
.comparison-history-list li > span { flex: 1; min-width: 0; overflow-wrap: anywhere; }
.comparison-history-list small { display: block; opacity: .7; }
.comparison-summary { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: baseline; }
.comparison-summary span, .comparison-limitation { font-size: .85rem; }
.comparison-rows { margin-block: .6rem; }
.comparison-row { border-bottom: 1px solid var(--border, #64748b33); padding-block: .55rem; }
.comparison-row > summary { cursor: pointer; overflow-wrap: anywhere; }
.comparison-row strong { margin-inline: .6rem; font-weight: 500; }
.comparison-row small { opacity: .7; }
.comparison-change { font-size: .8rem; text-transform: capitalize; }
.comparison-values { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: .8rem; }
.comparison-values h4 { margin: .7rem 0 .3rem; }
.comparison-values pre { max-height: 20rem; overflow: auto; font-size: .8rem; white-space: pre-wrap; overflow-wrap: anywhere; }
.comparison-scope { font-size: .85rem; margin-top: .6rem; }
.comparison-pins { overflow-wrap: anywhere; }
@media (max-width: 650px) { .comparison-controls { grid-template-columns: minmax(0, 1fr); } .comparison-arrow { display: none; } .comparison-values { grid-template-columns: minmax(0, 1fr); } .comparison-row small { display: block; margin-top: .25rem; } }
</style>
