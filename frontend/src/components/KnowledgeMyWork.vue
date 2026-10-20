<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError } from '../api'
import { knowledgeApi } from '../knowledgeApi'

type Counts = { context_findings: number; unique_vulnerabilities: number; by_status: Record<string, number>; required_context_review_workload: { required_targets: number; approved_targets: number; remaining_targets: number; not_assessable_targets: number } }
type Product = { project_id: string; name: string; statistics: Counts; by_version: Record<string, Counts> }
type Workload = { heads: Record<string, Record<string, string>>; heads_digest: string; statistics: Counts; by_team: Record<string, Counts>; team_labels: Record<string, string>; team_counts_overlap: boolean; project_count: number; version_count: number; total: number; items: Product[]; next_offset: number | null }
const props = defineProps<{ active: boolean; workScope: string; q?: string; lifecycle?: string; filters?: Record<string, string> }>()
const emit = defineEmits<{ open: [value: { project: { id: string; name: string }; version: string }] }>()
const result = ref<Workload | null>(null), busy = ref(false), error = ref(''), stale = ref(false)
const appliedQuery = ref(''), appliedLabel = ref(''), offset = ref(0), previous = ref<number[]>([])
let sequence = 0
const human = (value: string) => value.replaceAll('_', ' ')
const scopeName = (scope: string) => ({ my_teams: 'My teams', all: 'All teams', unassigned: 'Unassigned ownership', conflicts: 'Ownership conflicts' } as Record<string, string>)[scope] || scope
const selection = computed(() => {
  const query = new URLSearchParams({ work_scope: props.workScope, q: props.q || '', lifecycle: props.lifecycle || '' })
  for (const [key, value] of Object.entries(props.filters || {}).sort(([a], [b]) => a.localeCompare(b))) if (value) query.set(key, value)
  return query.toString()
})
function describe(query: URLSearchParams) {
  return [scopeName(query.get('work_scope') || 'all'), ...[...query.entries()].filter(([key, value]) => key !== 'work_scope' && value).map(([key, value]) => `${human(key)}: ${human(value)}`)].join(' · ')
}
async function load(page = 0, fresh = true) {
  if (!props.active || (!fresh && (stale.value || !result.value))) return false
  const token = ++sequence, query = new URLSearchParams(fresh ? selection.value : appliedQuery.value)
  const capturedQuery = query.toString(), capturedLabel = describe(query)
  query.set('offset', String(page)); query.set('limit', '20')
  if (!fresh && result.value) query.set('expected_heads', result.value.heads_digest)
  busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Workload>(`/portfolio?${query}`)
    if (token !== sequence || !props.active) return false
    result.value = data; appliedQuery.value = capturedQuery; appliedLabel.value = capturedLabel; offset.value = page; stale.value = false
    if (fresh) previous.value = []
    return true
  } catch (err) {
    if (token !== sequence) return false
    stale.value = err instanceof ApiError && err.status === 409
    error.value = stale.value ? 'Product or version states changed. Displayed workload retains its captured scope and states. Refresh workload to continue.' : err instanceof Error ? err.message : 'Workload unavailable'
    return false
  } finally { if (token === sequence) busy.value = false }
}
async function paginate(forward: boolean) {
  if (busy.value || stale.value) return
  const page = forward ? result.value?.next_offset : previous.value.at(-1)
  if (page == null) return
  const prior = offset.value
  if (await load(page, false)) { if (forward) previous.value.push(prior); else previous.value.pop() }
}
watch(() => [props.active, selection.value] as const, ([active, query]) => {
  ++sequence; busy.value = false
  if (!active) return
  if (!result.value || query !== appliedQuery.value) void load()
}, { immediate: true })
onBeforeUnmount(() => { ++sequence })
</script>

<template>
  <section v-show="active" class="my-work" aria-label="My work across products" :aria-busy="busy">
    <header><div><h2>Work across products</h2><p>Assessment cases in your selected responsibility scope.</p></div><button type="button" :disabled="busy" @click="load()">Refresh workload</button></header>
    <p v-if="busy" role="status">Loading workload…</p>
    <p v-if="error" role="alert">{{ error }}</p>
    <template v-if="result">
      <p class="scope" aria-label="Displayed workload scope">{{ stale ? 'Previous captured scope' : 'Displayed scope' }}: {{ appliedLabel }}</p>
      <dl class="totals" aria-label="My work totals">
        <div><dt>Assessment cases</dt><dd>{{ result.statistics.context_findings }}</dd></div>
        <div><dt>Unique vulnerabilities</dt><dd>{{ result.statistics.unique_vulnerabilities }}</dd></div>
        <div><dt>Approved review targets</dt><dd>{{ result.statistics.required_context_review_workload.approved_targets }} / {{ result.statistics.required_context_review_workload.required_targets }}</dd></div>
        <div><dt>Remaining review targets</dt><dd>{{ result.statistics.required_context_review_workload.remaining_targets }}</dd></div>
      </dl>
      <p class="hint">Each product version and consuming context is a separate case. One vulnerability can create several cases. Counts cover the complete selected scope before product paging.</p>
      <p v-if="!result.statistics.context_findings" role="status">No assessment cases in this scope. My teams uses current analyst and reviewer memberships; no applicable membership gives an empty workload.</p>
      <div class="product-work" aria-label="Product and version workload">
        <article v-for="product in result.items" :key="product.project_id">
          <h3>{{ product.name }}</h3>
          <p>{{ product.statistics.context_findings }} cases · {{ product.statistics.required_context_review_workload.remaining_targets }} remaining review targets</p>
          <ul :aria-label="`${product.name} versions`">
            <li v-for="(counts, version) in product.by_version" :key="version"><div><strong>{{ version }}</strong><span>{{ counts.context_findings }} cases · {{ counts.required_context_review_workload.approved_targets }} / {{ counts.required_context_review_workload.required_targets }} approved · {{ counts.required_context_review_workload.remaining_targets }} remaining</span></div><button type="button" :aria-label="`Open ${product.name} ${version} cases`" @click="emit('open', { project: { id: product.project_id, name: product.name }, version: String(version) })">Open cases</button></li>
          </ul>
        </article>
      </div>
      <nav aria-label="My work product pages"><button type="button" :disabled="busy || stale || !previous.length" @click="paginate(false)">Previous products</button><span>{{ result.total }} products in captured scope</span><button type="button" :disabled="busy || stale || result.next_offset == null" @click="paginate(true)">Next products</button></nav>
      <details v-if="Object.keys(result.by_team).length"><summary>Workload by responsible team</summary><ul class="teams"><li v-for="(counts, team) in result.by_team" :key="team">{{ result.team_labels[team] || team }}: {{ counts.context_findings }} cases · {{ counts.required_context_review_workload.remaining_targets }} remaining</li></ul><p class="hint">Team counts can overlap when ownership is disputed; do not add them together.</p></details>
      <details><summary>Captured states and scope</summary><pre>{{ JSON.stringify({ query: appliedQuery, heads_digest: result.heads_digest, heads: result.heads }, null, 2) }}</pre><p class="hint">Input coverage can be incomplete. Zero findings do not establish absence of vulnerabilities. Review approval does not publish a contextual score.</p></details>
    </template>
  </section>
</template>

<style scoped>
.my-work{border-block:1px solid var(--line);padding-block:1rem;margin-block:1rem;min-width:0}.my-work header{min-height:0;padding:0;background:none;border:0;display:flex;justify-content:space-between;align-items:start;gap:1rem}.my-work h2,.my-work h3{margin:0 0 .4rem}.my-work p{line-height:1.5}.my-work header p{margin:.3rem 0;color:var(--muted)}.scope,.hint{color:var(--muted);font-size:.875rem}.totals{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1rem}.totals dt{color:var(--muted);font-size:.875rem}.totals dd{font-size:1.5rem;font-weight:600;margin:.3rem 0}.product-work{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(340px,100%),1fr));gap:1rem}.product-work article{background:var(--surface);border:1px solid var(--line);border-radius:.5rem;padding:1rem;min-width:0;overflow-wrap:anywhere}.product-work article>p{color:var(--muted);font-size:.875rem}.product-work ul{list-style:none;padding:0;margin:0}.product-work li{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding-block:.75rem;border-top:1px solid var(--line)}.product-work li span{display:block;font-size:.875rem;line-height:1.5;margin-top:.25rem}.product-work button{flex-shrink:0}nav{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;margin-block:1rem}nav span{font-size:.875rem;color:var(--muted)}details{margin-top:.75rem}summary{cursor:pointer}.teams{padding-left:1.2rem;line-height:1.6}pre{font-size:.75rem;max-height:15rem;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}@media(max-width:650px){.totals{grid-template-columns:repeat(2,minmax(0,1fr))}.my-work header{flex-wrap:wrap}.product-work li{align-items:start;flex-wrap:wrap}.product-work li button{min-height:2.5rem}}
</style>
