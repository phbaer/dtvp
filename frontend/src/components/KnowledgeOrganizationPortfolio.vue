<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError } from '../api'
import { knowledgeApi } from '../knowledgeApi'
import SearchSelect from './SearchSelect.vue'
type Counts = { context_findings: number; unique_vulnerabilities: number; unique_latest_logical_assessments: number; unique_approved_logical_assessments: number; reviewed_covered_targets: number; pending_revision_targets: number; by_status: Record<string, number>; source_severity: Record<string, number>; current_published_severity: Record<string, number>; scoring_status: Record<string, number>; required_context_review_workload: { required_targets: number; approved_targets: number; remaining_targets: number; unresolved_targets: number; not_assessable_targets: number } }
type Project = { project_id: string; name: string; heads: Record<string, string>; statistics: Counts; by_version: Record<string, Counts>; state_evidence: Record<string, unknown> }
type Portfolio = { heads: Record<string, Record<string, string>>; heads_digest: string; statistics: Counts; by_team: Record<string, Counts>; team_labels: Record<string, string>; team_counts_overlap: boolean; project_count: number; version_count: number; items: Project[]; total: number; next_offset: number | null; limitations: string[] }
const props = defineProps<{ filters?: Record<string, string>; q?: string; lifecycle?: string; team?: string; workScope?: string }>()
const expanded = ref(false), busy = ref(false), error = ref(''), stale = ref(false), result = ref<Portfolio | null>(null)
const mode = ref('all'), projects = ref<{ id: string; name: string }[]>([]), picker = ref(''), selectedTeam = ref(props.team || ''), labels = ref<Record<string, string>>({})
const appliedScope = ref('')
const applied = ref<string | null>(null), previous = ref<number[]>([]), offset = ref(0)
let sequence = 0
const human = (value: string) => value.replaceAll('_', ' ')
const bands = (counts: Record<string, number>) => Object.entries(counts).map(([band, count]) => `${human(band)} ${count}`).join(' · ') || 'No reported targets'
const workScopeLabel = computed(() => (({ my_teams: 'My teams', unassigned: 'Unassigned', conflicts: 'Ownership conflicts' } as Record<string, string>)[props.workScope || ''] || 'All responsible teams'))
const filterDescription = computed(() => [props.q ? `Search: ${props.q}` : '', props.lifecycle ? `Workflow: ${human(props.lifecycle)}` : '', ...Object.entries(props.filters || {}).filter(([, value]) => value).map(([key, value]) => `${human(key)}: ${human(value)}`)].filter(Boolean).join(' · '))
function addProject(item: { id: string; name?: string }) { if (!projects.value.some(row => row.id === item.id) && projects.value.length < 100) projects.value.push({ id: item.id, name: item.name || item.id }); picker.value = '' }
function draftQuery() {
  const query = new URLSearchParams({ q: props.q || '', lifecycle: props.lifecycle || '' })
  if (props.workScope) query.set('work_scope', props.workScope)
  if (selectedTeam.value) query.set('team_id', selectedTeam.value)
  for (const [key, value] of Object.entries(props.filters || {})) if (value) query.set(key, value)
  if (mode.value === 'selected') for (const project of projects.value) query.append('project', project.id)
  return query
}
async function load(page = 0, fresh = true) {
  if (busy.value || (fresh && mode.value === 'selected' && !projects.value.length) || (!fresh && (!applied.value || !result.value))) return false
  const token = ++sequence, query = fresh ? draftQuery() : new URLSearchParams(applied.value!)
  const selection = query.toString()
  const scope = [query.has('project') ? `Products: ${projects.value.map(item => item.name).join(', ')}` : 'All accessible products at capture', [(({ my_teams: 'My teams', unassigned: 'Unassigned', conflicts: 'Ownership conflicts' } as Record<string, string>)[query.get('work_scope') || ''] || 'All responsible teams'), query.get('team_id') ? `Team: ${labels.value[query.get('team_id')!] || query.get('team_id')}` : ''].filter(Boolean).join(' · '), ...[...query.entries()].filter(([key, value]) => value && key !== 'project' && key !== 'team_id' && key !== 'work_scope').map(([key, value]) => `${human(key)}: ${human(value)}`)].join(' · ')
  query.set('offset', String(page)); query.set('limit', '20')
  if (!fresh && result.value) query.set('expected_heads', result.value.heads_digest)
  busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Portfolio>(`/portfolio?${query}`)
    if (token !== sequence) return false
    result.value = data; applied.value = selection; labels.value = { ...labels.value, ...data.team_labels }; offset.value = page; stale.value = false
    if (fresh) { previous.value = []; appliedScope.value = scope }
    return true
  } catch (err) {
    if (token === sequence) { stale.value = err instanceof ApiError && err.status === 409; error.value = stale.value ? 'Product or version heads changed. Previous statistics and pins remain; refresh the full selection explicitly.' : err instanceof Error ? err.message : 'Product portfolio unavailable' }
    return false
  } finally { if (token === sequence) busy.value = false }
}
function toggle(event: Event) { expanded.value = (event.currentTarget as HTMLDetailsElement).open; if (expanded.value && !result.value && !busy.value) void load() }
async function paginate(forward: boolean) {
  const page = forward ? result.value?.next_offset : previous.value.at(-1); if (page == null || busy.value) return
  const prior = offset.value; if (await load(page, false)) { if (forward) previous.value.push(prior); else previous.value.pop() }
}
watch(() => props.team, () => { selectedTeam.value = props.team || '' })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <details class="organization-portfolio" @toggle="toggle"><summary>Statistics across products</summary>
    <section aria-label="Statistics across products" :aria-busy="busy">
      <form class="portfolio-controls" @submit.prevent="load()">
        <label>Portfolio products<select v-model="mode" :disabled="busy"><option value="all">All accessible products (maximum 100)</option><option value="selected">Explicit product selection</option></select></label>
        <SearchSelect v-if="mode === 'selected'" v-model="picker" label="Add portfolio product" selected-label="Search products…" endpoint="/catalog/projects" :disabled="busy || projects.length >= 100" @select="addProject" />
        <label>Cross-product team<select v-model="selectedTeam" :disabled="busy"><option value="">{{ workScopeLabel }}</option><option v-for="(name, id) in labels" :key="id" :value="id">{{ name }}</option><option v-if="selectedTeam && !labels[selectedTeam]" :value="selectedTeam">{{ selectedTeam }}</option></select></label>
        <button :disabled="busy || (mode === 'selected' && !projects.length)">{{ result ? 'Refresh cross-product statistics' : 'Load cross-product statistics' }}</button>
      </form>
      <ul v-if="mode === 'selected'" aria-label="Explicit portfolio products"><li v-for="project in projects" :key="project.id">{{ project.name }} <button type="button" :disabled="busy" :aria-label="`Remove portfolio product ${project.name}`" @click="projects = projects.filter(item => item.id !== project.id)">Remove</button></li></ul>
      <p class="hint">Next load: {{ workScopeLabel }} · {{ filterDescription || 'All findings under the selected team and products.' }} Workspace finding filters apply when loading or refreshing; draft selection edits do not change displayed pages.</p>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="busy" role="status">Loading cross-product statistics…</p>
      <template v-if="result">
        <p v-if="stale" role="status">Previous captured selection retained.</p>
        <p>{{ result.project_count }} selected products · {{ result.version_count }} current product versions · complete counts before product paging.</p>
        <p aria-label="Displayed cross-product scope">Displayed scope: {{ appliedScope }}</p>
        <dl class="totals" aria-label="Cross-product portfolio totals"><div><dt>Context findings</dt><dd>{{ result.statistics.context_findings }}</dd></div><div><dt>Unique vulnerabilities</dt><dd>{{ result.statistics.unique_vulnerabilities }}</dd></div><div><dt>Latest logical assessments</dt><dd>{{ result.statistics.unique_latest_logical_assessments }}</dd></div><div><dt>Approved logical assessments</dt><dd>{{ result.statistics.unique_approved_logical_assessments }}</dd></div></dl>
        <p aria-label="Cross-product review workload">{{ result.statistics.required_context_review_workload.approved_targets }} / {{ result.statistics.required_context_review_workload.required_targets }} required targets approved · {{ result.statistics.required_context_review_workload.remaining_targets }} remaining · {{ result.statistics.required_context_review_workload.not_assessable_targets }} not assessable · {{ result.statistics.pending_revision_targets }} pending revisions.</p>
        <p><strong>Source severity:</strong> {{ bands(result.statistics.source_severity) }}<br><strong>Current published severity:</strong> {{ bands(result.statistics.current_published_severity) }}</p><p class="hint">Missing or outdated published scores retain unknown contextual severity. Publication state: {{ bands(result.statistics.scoring_status) }}.</p>
        <div class="workload-grid">
          <div class="portfolio-table"><table aria-label="Review workload across products"><thead><tr><th>Product</th><th>Findings</th><th>Approved / required</th><th>Remaining</th></tr></thead><tbody><tr v-for="project in result.items" :key="project.project_id"><th>{{ project.name }}</th><td>{{ project.statistics.context_findings }}</td><td>{{ project.statistics.required_context_review_workload.approved_targets }} / {{ project.statistics.required_context_review_workload.required_targets }}<progress :value="project.statistics.required_context_review_workload.approved_targets" :max="Math.max(1, project.statistics.required_context_review_workload.required_targets)" :aria-label="`Approved review targets for ${project.name}`" /></td><td>{{ project.statistics.required_context_review_workload.remaining_targets }}</td></tr></tbody></table></div>
          <div class="portfolio-table"><table aria-label="Cross-product review workload by team"><thead><tr><th>Team</th><th>Findings</th><th>Approved / required</th><th>Remaining</th></tr></thead><tbody><tr v-for="(counts, team) in result.by_team" :key="team"><th>{{ result.team_labels[team] || team }}</th><td>{{ counts.context_findings }}</td><td>{{ counts.required_context_review_workload.approved_targets }} / {{ counts.required_context_review_workload.required_targets }}</td><td>{{ counts.required_context_review_workload.remaining_targets }}</td></tr></tbody></table><p class="hint">Team counts can overlap when ownership is disputed; they are not additive.</p></div>
        </div>
        <nav aria-label="Cross-product statistics pages"><button type="button" :disabled="busy || !previous.length" @click="paginate(false)">Previous portfolio products</button><button type="button" :disabled="busy || result.next_offset == null" @click="paginate(true)">Next portfolio products</button></nav>
        <details><summary>Workflow states, input coverage and pinned selection</summary><p>Workflow: {{ bands(result.statistics.by_status) }}.</p><p class="hint">Input coverage is unfiltered for each pinned state. Zero findings do not establish complete software or vulnerability coverage.</p><details v-for="project in result.items" :key="project.project_id"><summary>{{ project.name }} · per-version counts and input coverage</summary><pre>{{ JSON.stringify({ by_version: project.by_version, state_evidence: project.state_evidence }, null, 2) }}</pre></details><pre>{{ JSON.stringify({ applied_query: applied, heads_digest: result.heads_digest, heads: result.heads }, null, 2) }}</pre><p v-for="text in result.limitations" :key="text" class="hint">{{ text }}</p></details>
      </template>
    </section>
  </details>
</template>
<style scoped>
.organization-portfolio{margin-block:.8rem;padding:.7rem 0;border-block:1px solid var(--line);min-width:0}.organization-portfolio summary{cursor:pointer;font-weight:600}.portfolio-controls{display:flex;align-items:end;flex-wrap:wrap;gap:.6rem;margin-block:.6rem}.portfolio-controls label,.portfolio-controls .search-select{min-width:min(180px,100%);flex:1}.portfolio-controls label{display:grid;gap:.3rem}.portfolio-controls select{width:100%;min-width:0}.totals{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.7rem}.totals dd{margin:.3rem 0;font-size:1.3rem;font-weight:600}.totals dt,.hint{font-size:.8rem;color:var(--muted)}.workload-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(350px,100%),1fr));gap:1rem}.portfolio-table{max-width:100%;overflow:auto}.portfolio-table table{width:100%;font-size:.85rem;text-align:left}.portfolio-table th,.portfolio-table td{vertical-align:top;padding:.4rem}.portfolio-table progress{display:block;width:100%;max-width:100px;margin-top:.25rem;height:.4rem}nav{display:flex;gap:.5rem;flex-wrap:wrap;margin-block:.6rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:20rem;overflow:auto;font-size:.75rem}li{overflow-wrap:anywhere}@media(max-width:650px){.totals{grid-template-columns:repeat(2,minmax(0,1fr))}.portfolio-controls{align-items:stretch}}
</style>
