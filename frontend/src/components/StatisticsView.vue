<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api } from '../api'

type Group = { id?: string; name: string; total: number; states: Record<string, number> }
type Project = Group & { workspace: string; workspace_id: string }
type Statistics = { as_of: string; totals: Record<string, number>; workflow: Record<string, number>; applicability: Record<string, number>; base_severity: Record<string, number>; effective_severity: Record<string, number>; unique_states: Record<string, number>; unique_base_severity: Record<string, number>; teams: Group[]; owners: Group[]; project_page: { items: Project[]; next_cursor: number | null } }
const props = defineProps<{ query: string; scope: string; scopeBusy: boolean }>()
const emit = defineEmits<{ review: [filters: Record<string, string>]; reset: [] }>()
const data = ref<Statistics | null>(null), error = ref(''), busy = ref(false)
const projects = ref<Project[]>([]), cursor = ref<number | null>(null)
const names: Record<string, string> = { open: 'Needs analysis', ready: 'Ready for approval', approved: 'Approved', needs_revalidation: 'Evidence changed', changes_requested: 'Changes requested', legacy_assessed: 'Legacy assessment', legacy_pending: 'Legacy pending', legacy_conflicting: 'Legacy conflict', legacy_documented: 'Legacy documentation', unassessed: 'Unassessed', affected: 'Affected', not_affected: 'Not affected', fixed: 'Fixed', under_investigation: 'Under investigation' }
const label = (key: string) => names[key] || key.replaceAll('_', ' ').replace('legacy:', 'Legacy: ')
const workflow = computed(() => Object.entries(data.value?.workflow || {}).sort((a, b) => b[1] - a[1]))
const max = computed(() => Math.max(1, ...workflow.value.map(entry => entry[1])))
const primaryStates = ['open', 'ready', 'approved', 'needs_revalidation']
const severities = ['critical', 'high', 'medium', 'low', 'none', 'unknown']
let sequence = 0
async function load(append = false) {
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    const params = new URLSearchParams(props.query)
    if (append && cursor.value !== null) params.set('project_cursor', String(cursor.value))
    const result = await api<Statistics>(`/statistics?${params}`)
    if (current !== sequence) return
    data.value = result; projects.value = append ? [...projects.value, ...result.project_page.items] : result.project_page.items; cursor.value = result.project_page.next_cursor
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Statistics unavailable' }
  finally { if (current === sequence) busy.value = false }
}
watch(() => props.query, () => { void load() }, { immediate: true })
onBeforeUnmount(() => { sequence++ })
</script>
<template>
  <div class="statistics-view">
    <div class="page-title"><div><p class="eyebrow">Full authorized inventory</p><h1>Statistics</h1><p>{{ scope }}</p></div><div class="approval-actions"><button :disabled="busy" @click="load()">Refresh statistics</button><button :disabled="busy || scopeBusy" @click="emit('reset')">Reset scope</button></div></div>
    <p v-if="error" class="warning" role="alert">{{ error }}</p><p v-if="busy" role="status" class="hint">Calculating counts across the full scope…</p>
    <template v-if="data">
      <div class="stat-cards"><article><span>Component / release findings</span><strong>{{ data.totals.findings.toLocaleString() }}</strong></article><article><span>Unique vulnerability IDs</span><strong>{{ data.totals.unique_vulnerabilities.toLocaleString() }}</strong></article><article><span>Projects with findings</span><strong>{{ data.totals.projects_with_findings.toLocaleString() }}</strong><small>{{ data.totals.projects }} projects in scope</small></article><article><span>Evidence changed</span><strong>{{ data.totals.needs_revalidation.toLocaleString() }}</strong></article></div>
      <div class="columns"><section class="panel"><h2>Review progress</h2><p class="hint">Counts include every matching active finding, across all pages. Select a state to review it.</p><button v-for="[state, count] in workflow" :key="state" class="stat-bar" :disabled="busy" @click="emit('review', { lifecycle: state })"><span>{{ label(state) }}</span><span class="bar-track"><span :style="{ width: `${count / max * 100}%` }"></span></span><strong>{{ count.toLocaleString() }}</strong></button><p v-if="!workflow.length" class="empty">No active findings in this scope.</p></section><section class="panel"><h2>Applicability</h2><p class="hint">Submitted decisions and reviewed decisions remain distinct in Review progress. Changed evidence invalidates current applicability.</p><dl class="stat-list"><template v-for="(count, state) in data.applicability" :key="state"><dt>{{ label(String(state)) }}</dt><dd>{{ count.toLocaleString() }}</dd></template></dl><details><summary>Unique vulnerability consistency</summary><p class="hint">One ID can have several occurrences. Incomplete means some remain unassessed; inconsistent means their applicability differs.</p><dl class="stat-list"><template v-for="(count, state) in data.unique_states" :key="state"><dt>{{ label(String(state)) }}</dt><dd>{{ count }}</dd></template></dl></details></section></div>
      <section class="panel"><h2>Owning teams</h2><p class="hint">Project-owning workspaces. Sharing grants access without counting the same finding twice.</p><div class="table-wrap"><table><thead><tr><th>Team</th><th>Total</th><th v-for="state in primaryStates" :key="state">{{ label(state) }}</th><th>Other states</th></tr></thead><tbody><tr v-for="team in data.teams" :key="team.id"><td><button class="text-link" @click="emit('review', { workspace_id: team.id!, team_name: team.name })">{{ team.name }}</button></td><td>{{ team.total.toLocaleString() }}</td><td v-for="state in primaryStates" :key="state"><button class="count-link" :disabled="!team.states[state] || busy" @click="emit('review', { workspace_id: team.id!, team_name: team.name, lifecycle: state })">{{ team.states[state] || 0 }}</button></td><td>{{ team.total - primaryStates.reduce((sum, state) => sum + (team.states[state] || 0), 0) }}</td></tr></tbody></table></div></section>
      <div class="columns"><section class="panel"><h2>Severity distribution</h2><p class="hint">Contextual scores affect this view only after current independent approval.</p><table><thead><tr><th>Severity</th><th>Original Base</th><th>Effective</th></tr></thead><tbody><tr v-for="severity in severities" :key="severity"><td class="capitalize">{{ severity }}</td><td>{{ data.base_severity[severity] || 0 }}</td><td>{{ data.effective_severity[severity] || 0 }}</td></tr></tbody></table></section><section class="panel"><h2>Coverage requiring attention</h2><dl class="stat-list"><dt>Conflicting original scores</dt><dd>{{ data.totals.conflicting_scores }}</dd><dt>Stale source evidence</dt><dd>{{ data.totals.stale_evidence }}</dd><dt>Approved contextual scores</dt><dd>{{ data.totals.adopted_rescoring }}</dd></dl><details><summary>Component owners</summary><p class="hint">Curated responsibility metadata. These labels do not grant permissions.</p><table><thead><tr><th>Owner</th><th>Findings</th></tr></thead><tbody><tr v-for="owner in data.owners" :key="owner.name"><td><button class="text-link" @click="emit('review', { owner: owner.name, owner_match: 'exact' })">{{ owner.name }}</button></td><td>{{ owner.total }}</td></tr></tbody></table></details></section></div>
      <section class="panel"><h2>Projects</h2><div class="table-wrap"><table><thead><tr><th>Project</th><th>Owning team</th><th>Total</th><th v-for="state in primaryStates" :key="state">{{ label(state) }}</th></tr></thead><tbody><tr v-for="project in projects" :key="project.id"><td><button class="text-link" @click="emit('review', { project_id: project.id!, project_name: project.name })">{{ project.name }}</button></td><td>{{ project.workspace }}</td><td>{{ project.total }}</td><td v-for="state in primaryStates" :key="state">{{ project.states[state] || 0 }}</td></tr></tbody></table></div><button v-if="cursor !== null" :disabled="busy" @click="load(true)">More project statistics</button></section>
      <p class="hint">Snapshot of current data · {{ new Date(data.as_of).toLocaleString() }}. Original scores and occurrence counts are preserved.</p>
    </template>
  </div>
</template>
