<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Source = { id: string; part_id: string | null; state: string | null; availability: string; required?: boolean; collection: Record<string, unknown>; dependency_graph: string; coverage_verification: string; source: Record<string, unknown> }
type Issue = { id: string; code: string; component_ref: string | null; source_id: string | null; roles: string[]; details: Record<string, unknown> }
type Report = { format: string; state: string; project_id: string; version: string; baseline_status: string; report_digest: string; sources: Source[]; statistics: { occurrences: number; by_role: Record<string, number>; inventory_components: Record<string, number>; by_source: Record<string, { occurrences: number; inventory_components: number; license_evidence: Record<string, number>; by_code: Record<string, number> }>; unique_dependency_edges: number; unresolved_dependency_refs: number; issues: number; by_code: Record<string, number> }; selection: { q: string; code: string }; items: Issue[]; total: number; next_offset: number | null; limitations: string[] }
const props = defineProps<{ project: string; state: string }>()
const expanded = ref(false), busy = ref(false), error = ref(''), report = ref<Report | null>(null)
const query = ref(''), code = ref(''), offset = ref(0), previous = ref<number[]>([])
let sequence = 0, pinnedDigest = ''
const label = (value: string) => value.replaceAll('_', ' ')
async function load(selectedOffset = 0, reset = false) {
  if (busy.value || !props.project || !props.state) return false
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    const params = new URLSearchParams({ q: query.value, code: code.value, offset: String(selectedOffset), limit: '20' })
    const result = await knowledgeApi<Report>(`/projects/${encodeURIComponent(props.project)}/states/${props.state}/input-quality?${params}`)
    if (current !== sequence) return false
    if (result.state !== props.state || result.project_id !== props.project || result.format !== 'dtvp.input-quality/1') throw new Error('Input report scope does not match the selected inventory.')
    if (!reset && pinnedDigest && result.report_digest !== pinnedDigest) throw new Error('The derived report changed. Retained results were not replaced; explicitly reload the pinned report before continuing.')
    pinnedDigest = result.report_digest; report.value = result; offset.value = selectedOffset
    if (reset) previous.value = []
    return true
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Input report unavailable'; return false }
  finally { if (current === sequence) busy.value = false }
}
function toggle(event: Event) { expanded.value = (event.currentTarget as HTMLDetailsElement).open; if (expanded.value && !report.value) void load() }
async function filter() { if (await load(0)) previous.value = [] }
async function page(forward: boolean) {
  if (busy.value) return
  const currentOffset = offset.value, target = forward ? report.value?.next_offset : previous.value.at(-1)
  if (target == null || !report.value) return
  const generation = sequence + 1
  // Pages continue the applied server selection, not unsubmitted filter edits.
  const draft = { q: query.value, code: code.value }; query.value = report.value.selection.q; code.value = report.value.selection.code
  if (await load(target)) { if (forward) previous.value.push(currentOffset); else previous.value.pop() }
  if (sequence === generation) { query.value = draft.q; code.value = draft.code }
}
watch(() => [props.project, props.state], () => { ++sequence; busy.value = false; report.value = null; error.value = ''; pinnedDigest = ''; offset.value = 0; previous.value = []; query.value = ''; code.value = ''; if (expanded.value) void load() })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <details class="knowledge-input-quality" aria-label="Composition input observations" @toggle="toggle">
    <summary>Composition input observations</summary>
    <p class="hint">Read-only observations of the selected imported model. Producer coverage is not verified; missing inventory cannot be discovered from these counts. No quality score, license conclusion or automatic release gate is applied.</p>
    <p v-if="!state">Select a product inventory to inspect its input evidence.</p>
    <button :disabled="busy || !state" @click="load(0, true)">Reload pinned input report</button>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="busy" role="status">Reading pinned composition inputs…</p>
    <template v-if="report">
      <p><strong>{{ report.version }} · {{ label(report.baseline_status) }}</strong> · {{ report.statistics.occurrences }} source-local occurrences · {{ report.statistics.issues }} observations in the full model</p>
      <dl aria-label="Full input counts"><template v-for="(count, role) in report.statistics.by_role" :key="role"><dt>{{ label(role) }}</dt><dd>{{ count }}</dd></template><dt>Declared unique dependency edges</dt><dd>{{ report.statistics.unique_dependency_edges }}</dd><dt>Unresolved dependency references</dt><dd>{{ report.statistics.unresolved_dependency_refs }}</dd></dl>
      <details><summary>Source and constituent coverage claims</summary><article v-for="source in report.sources" :key="source.id"><strong>{{ source.id }} · {{ label(source.availability) }}<template v-if="source.required"> · required</template></strong><p class="hint">Producer-declared; {{ label(source.coverage_verification) }}. Dependency graph: {{ label(source.dependency_graph) }}.</p><dl><dt>Package coverage</dt><dd>{{ label(String(source.collection.package_coverage || 'unknown')) }}</dd><dt>Dependency coverage</dt><dd>{{ label(String(source.collection.dependency_coverage || 'unknown')) }}</dd><dt>License coverage</dt><dd>{{ label(String(source.collection.license_coverage || 'unknown')) }}</dd><template v-if="report.statistics.by_source[source.id]"><dt>Inventory components</dt><dd>{{ report.statistics.by_source[source.id]!.inventory_components }}</dd><dt>All source-local occurrences</dt><dd>{{ report.statistics.by_source[source.id]!.occurrences }}</dd></template></dl><details><summary>Exact source pins, scope and license evidence counts</summary><pre>{{ JSON.stringify({ state: source.state, source: source.source, collection: source.collection, statistics: report.statistics.by_source[source.id] }, null, 2) }}</pre></details></article><p v-if="!report.sources.length">No retained source declarations in this inventory.</p></details>
      <form aria-label="Filter input observations" @submit.prevent="filter"><fieldset :disabled="busy"><label>Observation class<select v-model="code"><option value="">All observation classes</option><option v-for="(count, kind) in report.statistics.by_code" :key="kind" :value="kind">{{ kind }} ({{ count }})</option></select></label><label>Search input observations<input v-model="query" maxlength="200" type="search" placeholder="Component reference, source or detail"></label><button>Apply input observation filters</button></fieldset></form>
      <p>{{ report.total }} matching observations · showing {{ offset + (report.items.length ? 1 : 0) }}–{{ offset + report.items.length }}. Full-model counts above stay unfiltered.</p>
      <p v-if="report.selection.q || report.selection.code" class="hint">Applied selection: {{ report.selection.code || 'all classes' }} · {{ report.selection.q || 'all text' }}</p>
      <ul class="input-observations"><li v-for="item in report.items" :key="item.id"><code>{{ item.code }}</code><span>{{ item.component_ref || 'Source or inventory observation' }}</span><small>{{ item.source_id || 'Source attribution unresolved' }}<template v-if="item.roles.length"> · {{ item.roles.map(label).join(', ') }}</template></small><details><summary>Observation details</summary><pre>{{ JSON.stringify(item.details, null, 2) }}</pre></details></li></ul><p v-if="!report.items.length">No observations match this selection. This does not verify input correctness or product completeness.</p>
      <nav aria-label="Input observation pages"><button :disabled="busy || !previous.length" @click="page(false)">Previous input observations</button><button :disabled="busy || report.next_offset == null" @click="page(true)">Next input observations</button></nav>
      <details><summary>Input report pins and limitations</summary><dl><dt>Inventory state</dt><dd><code>{{ report.state }}</code></dd><dt>Full report digest</dt><dd><code>{{ report.report_digest }}</code></dd></dl><ul><li v-for="limit in report.limitations" :key="limit">{{ limit }}</li></ul></details>
    </template>
  </details>
</template>
<style scoped>
.knowledge-input-quality{margin-block:.75rem;padding:.7rem .9rem;border:1px solid var(--line);border-radius:.65rem;min-width:0}.knowledge-input-quality summary{cursor:pointer;overflow-wrap:anywhere}.knowledge-input-quality p,.knowledge-input-quality li{overflow-wrap:anywhere}.knowledge-input-quality dl{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.3rem .8rem}.knowledge-input-quality dd{margin:0;overflow-wrap:anywhere}.knowledge-input-quality fieldset{display:flex;gap:.7rem;align-items:end;flex-wrap:wrap;border:0;padding:0;margin:1rem 0;min-width:0}.knowledge-input-quality label{display:grid;gap:.3rem;flex:1;min-width:160px}.knowledge-input-quality input,.knowledge-input-quality select{box-sizing:border-box;max-width:100%;min-width:0;width:100%}.knowledge-input-quality pre,.knowledge-input-quality code{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.75rem}.knowledge-input-quality pre{max-height:230px;overflow:auto}.knowledge-input-quality article{padding:.7rem 0;border-bottom:1px solid var(--line)}.knowledge-input-quality nav{display:flex;gap:.7rem;flex-wrap:wrap}.input-observations{list-style:none;margin:0;padding:0;max-height:400px;overflow:auto}.input-observations li{padding:.7rem 0;border-bottom:1px solid var(--line)}.input-observations code,.input-observations span,.input-observations small{display:block}.hint,.input-observations small{color:var(--muted);font-size:.8rem}@media(max-width:550px){.knowledge-input-quality dl{grid-template-columns:minmax(0,1fr)}.knowledge-input-quality label{min-width:0;flex-basis:100%}}
</style>
