<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError } from '../api'
import { knowledgeApi } from '../knowledgeApi'

type Counts = { context_findings: number; unique_vulnerabilities: number; unique_latest_logical_assessments: number; unique_approved_logical_assessments: number; reviewed_covered_targets: number; pending_revision_targets: number; by_status: Record<string, number>; source_severity: Record<string, number>; current_published_severity: Record<string, number>; scoring_status: Record<string, number>; required_context_review_workload: { required_targets: number; approved_targets: number; remaining_targets: number; unresolved_targets: number; not_assessable_targets: number } }
type Portfolio = { heads: Record<string, string>; heads_digest: string; statistics: Counts; by_version: Record<string, Counts>; by_team: Record<string, Counts>; team_labels: Record<string, string>; team_counts_overlap: boolean; state_evidence: Record<string, { baseline_status: string; collection_coverage: Record<string, string>; coverage_verification: string; uncontextualized_source_findings: number }>; limitations: string[] }
const props = defineProps<{ project: string; version: string; state: string; filters?: Record<string, string>; q?: string; lifecycle?: string; team?: string; workScope?: string }>()
const expanded = ref(false), busy = ref(false), error = ref(''), stale = ref(false), result = ref<Portfolio | null>(null)
const mode = ref('all'), selected = ref<string[]>([]), selectedTeam = ref(props.team || '')
const versions = ref<{ version: string; state: string }[]>([]), nextOffset = ref<number | null>(0), versionsBusy = ref(false), catalogError = ref('')
const labels = ref<Record<string, string>>({})
let sequence = 0, catalogSequence = 0
const workScopeLabel = computed(() => (({ my_teams: 'My teams', unassigned: 'Unassigned', conflicts: 'Ownership conflicts' } as Record<string, string>)[props.workScope || ''] || 'All responsible teams'))
const filterDescription = computed(() => [props.q ? `Search: ${props.q}` : '', props.lifecycle ? `Workflow: ${props.lifecycle}` : '', ...Object.entries(props.filters || {}).filter(([, value]) => value).map(([key, value]) => `${key.replaceAll('_', ' ')}: ${value}`)].filter(Boolean).join(' · '))
const human = (value: string) => value.replaceAll('_', ' ')
const bands = (counts: Record<string, number | string>) => Object.entries(counts).map(([band, count]) => `${human(band)} ${count}`).join(' · ') || 'No reported targets'
function invalidate() { ++sequence; busy.value = false; error.value = ''; stale.value = false; result.value = null }
async function load(checkHeads = false) {
  if (!props.project || (mode.value === 'selected' && !selected.value.length)) return
  const request = ++sequence; busy.value = true; error.value = ''
  const query = new URLSearchParams({ q: props.q || '', lifecycle: props.lifecycle || '' })
  if (props.workScope) query.set('work_scope', props.workScope)
  for (const [key, value] of Object.entries(props.filters || {})) if (value) query.set(key, value)
  if (selectedTeam.value) query.set('team_id', selectedTeam.value)
  if (mode.value === 'selected') for (const version of selected.value) query.append('version', version)
  if (checkHeads && result.value) query.set('expected_heads', result.value.heads_digest)
  try {
    const data = await knowledgeApi<Portfolio>(`/projects/${encodeURIComponent(props.project)}/portfolio?${query}`)
    if (request !== sequence) return
    result.value = data; labels.value = { ...labels.value, ...data.team_labels }; stale.value = false
  } catch (err) {
    if (request !== sequence) return
    stale.value = err instanceof ApiError && err.status === 409
    error.value = stale.value ? 'Version heads changed. These statistics retain their previous pins; refresh explicitly to load the current heads.' : err instanceof Error ? err.message : 'Portfolio unavailable'
  } finally { if (request === sequence) busy.value = false }
}
async function loadVersions() {
  if (!props.project || versionsBusy.value || nextOffset.value === null) return
  const request = ++catalogSequence; versionsBusy.value = true; catalogError.value = ''
  try {
    const page = await knowledgeApi<{ items: { version: string; state: string }[]; next_offset: number | null }>(`/projects/${encodeURIComponent(props.project)}/versions?offset=${nextOffset.value}&limit=50`)
    if (request !== catalogSequence) return
    versions.value = [...versions.value, ...page.items]; nextOffset.value = page.next_offset
  } catch (err) { if (request === catalogSequence) catalogError.value = err instanceof Error ? err.message : 'Versions unavailable' }
  finally { if (request === catalogSequence) versionsBusy.value = false }
}
function toggle(open: boolean) {
  expanded.value = open
  if (expanded.value) { if (!result.value && !busy.value) void load(); if (!versions.value.length && !versionsBusy.value) void loadVersions() }
}
watch([mode, selected, selectedTeam], invalidate, { deep: true })
watch(() => [props.project, props.version, props.state, props.q, props.lifecycle, JSON.stringify(props.filters || {}), props.team, props.workScope], (current, previous) => {
  invalidate()
  if (current[0] !== previous[0]) { ++catalogSequence; versionsBusy.value = false; versions.value = []; nextOffset.value = 0; labels.value = {}; selected.value = []; mode.value = 'all' }
  if (current[0] !== previous[0] || current[6] !== previous[6]) selectedTeam.value = props.team || ''
  void nextTick(() => { if (expanded.value) { void load(); if (!versions.value.length) void loadVersions() } })
})
onBeforeUnmount(() => { ++sequence; ++catalogSequence })
</script>

<template>
  <TaskSurface class="knowledge-portfolio" @active="toggle" title="Project statistics across versions">
    <section aria-label="Project statistics across versions" :aria-busy="busy">
      <form class="portfolio-controls" @submit.prevent="load()">
        <label>Portfolio versions<select v-model="mode"><option value="all">All current versions</option><option value="selected">Selected versions</option></select></label>
        <label v-if="mode === 'selected'">Selected portfolio versions<select v-model="selected" multiple size="4"><option v-for="item in versions" :key="item.version" :value="item.version">{{ item.version }}</option></select></label>
        <button v-if="mode === 'selected' && nextOffset !== null" type="button" :disabled="versionsBusy" @click="loadVersions">More portfolio versions</button>
        <label>Portfolio team<select v-model="selectedTeam"><option value="">{{ workScopeLabel }}</option><option v-for="(label, id) in labels" :key="id" :value="id">{{ label }}</option><option v-if="selectedTeam && !labels[selectedTeam]" :value="selectedTeam">{{ selectedTeam }}</option></select></label>
        <button type="submit" :disabled="busy || (mode === 'selected' && !selected.length)">{{ result ? 'Refresh statistics' : 'Load statistics' }}</button>
        <button v-if="result" type="button" :disabled="busy" @click="load(true)">Check selected heads</button>
      </form>
      <p class="hint">{{ workScopeLabel }} · {{ filterDescription || 'All findings in the selected versions.' }} Team and workflow filters describe the displayed review workload.</p>
      <p v-if="catalogError" role="alert">{{ catalogError }}</p><p v-if="error" role="alert">{{ error }}</p><p v-if="busy" role="status">Loading project statistics…</p>
      <template v-if="result">
        <p v-if="stale" class="hint">Previous snapshot — current heads have changed.</p>
        <dl class="portfolio-totals" aria-label="Portfolio totals">
          <div><dt>Context findings</dt><dd>{{ result.statistics.context_findings }}</dd></div>
          <div><dt>Unique vulnerabilities</dt><dd>{{ result.statistics.unique_vulnerabilities }}</dd></div>
          <div><dt>Latest logical assessments</dt><dd>{{ result.statistics.unique_latest_logical_assessments }}</dd></div>
          <div><dt>Approved logical assessments</dt><dd>{{ result.statistics.unique_approved_logical_assessments }}</dd></div>
        </dl>
        <p class="hint">A shared assessment can cover several targets. Each version and consuming context still needs its own reviewed coverage.</p>
        <div class="portfolio-table"><table aria-label="Review workload by version"><thead><tr><th>Version</th><th>Context findings</th><th>Approved targets</th><th>Remaining</th><th>Not assessable</th></tr></thead><tbody><tr v-for="(counts, version) in result.by_version" :key="version"><th>{{ version }}</th><td>{{ counts.context_findings }}</td><td>{{ counts.required_context_review_workload.approved_targets }} / {{ counts.required_context_review_workload.required_targets }}</td><td>{{ counts.required_context_review_workload.remaining_targets }}</td><td>{{ counts.required_context_review_workload.not_assessable_targets }}</td></tr></tbody></table></div>
        <p><strong>Source severity:</strong> {{ bands(result.statistics.source_severity) }}<br><strong>Current published severity:</strong> {{ bands(result.statistics.current_published_severity) }}</p>
        <p class="hint">Outdated or absent publications count as unknown contextual severity. Publications: {{ bands(result.statistics.scoring_status) }}.</p>
        <details><summary>Teams and workflow states</summary><div class="portfolio-table"><table aria-label="Review workload by team"><thead><tr><th>Team</th><th>Context findings</th><th>Approved targets</th><th>Workflow</th></tr></thead><tbody><tr v-for="(counts, team) in result.by_team" :key="team"><th>{{ result.team_labels[team] || team }}</th><td>{{ counts.context_findings }}</td><td>{{ counts.reviewed_covered_targets }}</td><td>{{ bands(counts.by_status) }}</td></tr></tbody></table></div><p class="hint">Team counts overlap when ownership is disputed. Pending revisions: {{ result.statistics.pending_revision_targets }} targets.</p></details>
        <details><summary>Input coverage and pinned heads</summary><p class="hint">Coverage below describes the entire state before finding filters. Zero findings do not establish complete input coverage or absence of vulnerabilities.</p><dl v-for="(facts, version) in result.state_evidence" :key="version"><dt>{{ version }} · {{ facts.baseline_status }}</dt><dd>Declared coverage: {{ bands(facts.collection_coverage) }} · {{ human(facts.coverage_verification) }} · Uncontextualized source findings: {{ facts.uncontextualized_source_findings }}</dd><dd><code>{{ result.heads[version] }}</code></dd></dl><p>Selection digest: <code>{{ result.heads_digest }}</code></p><p v-for="limit in result.limitations" :key="limit" class="hint">{{ limit }}</p></details>
      </template>
    </section>
  </TaskSurface>
</template>

<style scoped>
.knowledge-portfolio { margin:16px 0; border-block:1px solid var(--line); padding:12px 0 }.knowledge-portfolio > summary { cursor:pointer; font-weight:600 }.portfolio-controls { display:flex; gap:12px; align-items:end; flex-wrap:wrap; margin-top:16px }.portfolio-controls label { min-width:160px; margin:0 }.portfolio-controls select[multiple] { min-width:180px }.portfolio-totals { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:16px; margin:16px 0 }.portfolio-totals dt { color:var(--muted); font-size:.8rem }.portfolio-totals dd { margin:4px 0; font-size:1.35rem; font-weight:600 }.portfolio-table { max-width:100%; overflow:auto }.portfolio-table table { width:100%; font-size:.85rem }.portfolio-table th,.portfolio-table td { text-align:left; vertical-align:top }.knowledge-portfolio .hint { font-size:.8rem; line-height:1.5 }.knowledge-portfolio details { margin:12px 0 }.knowledge-portfolio code { overflow-wrap:anywhere; font-size:.75rem }.knowledge-portfolio dd { margin-left:0; overflow-wrap:anywhere }@media(max-width:650px) { .portfolio-totals { grid-template-columns:repeat(2,minmax(0,1fr)) }.portfolio-controls { align-items:stretch }.portfolio-controls label { flex:1 } }
</style>
