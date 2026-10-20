<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
type Pins = { inventory_state: string; evidence_state: string | null }
type Row = { id: string; source: string; publisher: string; document_id: string; vulnerability_id: string; component_refs: string[]; status: string; before: unknown[]; after: unknown[]; inactive_selected_records: unknown[] }
type Report = { inventory_state: string; inventory_version: string; evidence_state: string | null; report_digest: string; currentness: { captured_evidence_head: string | null; selected_is_current: boolean }; statistics: { baseline_identifiers: number; claim_groups: number; by_status: Record<string, number>; excluded_document_formats: { before: Record<string, number>; after: Record<string, number> }; nonbaseline_statements: { before: number; after: number } }; items: Row[]; total: number; next_offset: number | null; limitations: string[] }
const props = defineProps<{ project: string; state: string }>()
const busy = ref(false), error = ref(''), inputs = ref<{ inventory: string; evidence: string | null } | null>(null), mode = ref(''), historical = ref('')
const report = ref<Report | null>(null), applied = ref<Pins | null>(null), offset = ref(0), previous = ref<number[]>([])
const valid = computed(() => !!inputs.value && /^[a-f0-9]{64}$/.test(inputs.value.inventory) && (mode.value === 'none' || mode.value === 'captured' || (mode.value === 'historical' && /^[a-f0-9]{64}$/.test(historical.value))))
const moved = computed(() => !!report.value && props.state !== report.value.inventory_state)
const human = (text: string) => text.replaceAll('_', ' ')
const providers = computed(() => {
  const counts = new Map<string, Record<string, number>>()
  for (const row of report.value?.items || []) { const key = `${row.source} · ${row.publisher || 'publisher unknown'}`; const tally = counts.get(key) || {}; tally[row.status] = (tally[row.status] || 0) + 1; counts.set(key, tally) }
  return [...counts.entries()]
})
let sequence = 0
const root = () => `/projects/${encodeURIComponent(props.project)}`
async function capture() {
  if (busy.value || !props.project || !props.state) return
  const token = ++sequence, state = props.state; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<{ evidence_state: string | null }>(`${root()}/evidence`)
    if (token !== sequence) return
    inputs.value = { inventory: state, evidence: data.evidence_state }; mode.value = ''; historical.value = ''
  } catch (err) { if (token === sequence) error.value = err instanceof Error ? err.message : 'Evidence reference unavailable' }
  finally { if (token === sequence) busy.value = false }
}
async function compare(page = 0, fresh = true) {
  if (busy.value || (fresh && !valid.value) || (!fresh && (!applied.value || !report.value))) return false
  const pins: Pins = fresh ? { inventory_state: inputs.value!.inventory, evidence_state: mode.value === 'none' ? null : mode.value === 'historical' ? historical.value : inputs.value!.evidence } : { ...applied.value! }
  const token = ++sequence, digest = !fresh ? report.value!.report_digest : null; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Report>(`${root()}/compare/intelligence?offset=${page}&limit=20`, send({ ...pins, ...(digest ? { expected_digest: digest } : {}) }))
    if (token !== sequence) return false
    if (digest && data.report_digest !== digest) throw new Error('Comparison digest changed. Previous results and pins remain; compare explicitly to replace them.')
    report.value = data; applied.value = pins; offset.value = page; if (fresh) previous.value = []; return true
  } catch (err) { if (token === sequence) error.value = err instanceof Error ? err.message : 'Intelligence comparison unavailable'; return false }
  finally { if (token === sequence) busy.value = false }
}
async function paginate(forward: boolean) {
  const page = forward ? report.value?.next_offset : previous.value.at(-1); if (page == null || busy.value) return
  const before = offset.value
  if (await compare(page, false)) { if (forward) previous.value.push(before); else previous.value.pop() }
}
watch(() => props.project, () => { ++sequence; busy.value = false; inputs.value = null; report.value = null; applied.value = null; previous.value = []; mode.value = ''; historical.value = ''; error.value = '' })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <TaskSurface class="intelligence-comparison" title="Compare retained inventory with advisory evidence">
    <section aria-label="Pinned advisory intelligence comparison" :aria-busy="busy">
      <p class="hint">Read-only comparison for vulnerability IDs already reported by this inventory. Source ratings and human approvals remain unchanged; provider differences do not establish independent corroboration or remediation.</p>
      <p v-if="error" role="alert">{{ error }}</p>
      <button type="button" :disabled="busy" @click="capture">Capture intelligence comparison inputs</button>
      <form v-if="inputs" @submit.prevent="compare()">
        <p class="hint">Inventory input <code>{{ inputs.inventory }}</code></p>
        <details><summary>Choose retained inventory state</summary><label>Retained inventory SHA-256<input v-model="inputs.inventory" maxlength="64" pattern="[a-f0-9]{64}" :disabled="busy" spellcheck="false"></label><button type="button" :disabled="busy" @click="inputs.inventory = state">Use workspace inventory state</button><p class="hint">Select an exact committed product state from version history. Comparing never restores or changes that state; displayed report pages keep their original pins.</p></details>
        <label>Advisory evidence snapshot<select v-model="mode" :disabled="busy"><option value="">Select explicitly</option><option value="captured">Captured current reference · {{ inputs.evidence?.slice(0, 12) || 'no evidence' }}</option><option value="none">No advisory evidence</option><option value="historical">Exact retained evidence state</option></select></label>
        <label v-if="mode === 'historical'">Retained advisory evidence SHA-256<input v-model="historical" maxlength="64" :disabled="busy" spellcheck="false"></label>
        <button :disabled="busy || !valid">Compare pinned advisory evidence</button>
      </form>
      <template v-if="report">
        <p v-if="moved" role="status">The workspace inventory changed. This report retains its original inventory pin; capture new inputs explicitly to compare another state.</p>
        <p v-if="!report.currentness.selected_is_current" role="status">The selected evidence differs from the current reference at comparison capture. Paging keeps the retained selection.</p>
        <p aria-label="Displayed intelligence comparison pins">Showing inventory {{ report.inventory_state.slice(0, 12) }} · evidence {{ report.evidence_state?.slice(0, 12) || 'none (explicit selection)' }}.</p>
        <p v-if="report.currentness.selected_is_current" class="hint">The evidence reference matched at comparison capture.</p>
        <p aria-label="Intelligence comparison totals">{{ report.total }} claim groups · {{ report.statistics.baseline_identifiers }} baseline identifiers · inventory {{ report.inventory_version }}</p>
        <dl class="statistics"><template v-for="(count, status) in report.statistics.by_status" :key="status"><dt>{{ human(String(status)) }}</dt><dd>{{ count }}</dd></template></dl>
        <details v-if="providers.length"><summary>Provider differences on this page</summary><p v-for="[provider, counts] in providers" :key="provider">{{ provider }} · {{ Object.entries(counts).map(([status, count]) => `${human(status)}: ${count}`).join(' · ') }}</p></details>
        <article v-for="row in report.items" :key="row.id"><strong>{{ row.vulnerability_id }} · {{ human(row.status) }}</strong><p>{{ row.source }} · publisher {{ row.publisher || 'unknown' }} · {{ row.document_id }}</p><p class="hint">{{ row.component_refs.join(', ') }}</p><details><summary>Before, selected evidence and inactive records</summary><pre>{{ JSON.stringify({ before: row.before, after: row.after, inactive_selected_records: row.inactive_selected_records }, null, 2) }}</pre></details></article>
        <p v-if="!report.items.length">No claim groups were reported for these pinned inputs; vulnerability and remediation coverage remain unestablished.</p>
        <nav aria-label="Intelligence comparison pages"><button type="button" :disabled="busy || !previous.length" @click="paginate(false)">Previous intelligence comparison page</button><button type="button" :disabled="busy || report.next_offset == null" @click="paginate(true)">Next intelligence comparison page</button></nav>
        <details><summary>Comparison pins, exclusions and limits</summary><pre>{{ JSON.stringify({ inventory_state: report.inventory_state, evidence_state: report.evidence_state, report_digest: report.report_digest, currentness: report.currentness, excluded_document_formats: report.statistics.excluded_document_formats, nonbaseline_statements: report.statistics.nonbaseline_statements }, null, 2) }}</pre><p v-for="item in report.limitations" :key="item" class="hint">{{ item }}</p></details>
      </template>
      <p v-if="busy" role="status">Loading pinned intelligence comparison…</p>
    </section>
  </TaskSurface>
</template>
<style scoped>
.intelligence-comparison{margin-block:.7rem;padding-top:.6rem;border-top:1px solid var(--line);min-width:0}.intelligence-comparison summary{cursor:pointer}.intelligence-comparison label{display:grid;gap:.3rem;margin-block:.6rem}.intelligence-comparison input,.intelligence-comparison select{width:100%;min-width:0;box-sizing:border-box}.intelligence-comparison article{border-top:1px solid var(--line);padding-block:.6rem;overflow-wrap:anywhere}.intelligence-comparison nav{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.6rem}.intelligence-comparison pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:20rem;overflow:auto}.intelligence-comparison code{overflow-wrap:anywhere}.statistics{display:flex;flex-wrap:wrap;gap:.3rem}.statistics dd{margin:0 .6rem 0 0}.hint{font-size:.85rem;color:var(--muted)}
</style>
