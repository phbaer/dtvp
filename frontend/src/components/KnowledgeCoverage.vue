<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi, type KnowledgeAssessment, type KnowledgeFinding } from '../knowledgeApi'
const props = defineProps<{ project: string; state: string; version: string; finding: KnowledgeFinding; busy?: boolean }>()
type Target = { version: string; context_id: string; vulnerability_id: string }
type Row = Target & { id: string; state: string; component: { name?: string; version?: string } | null; context: { root_ref?: string } | null; capabilities: string[]; assessment_candidate: boolean; classification: string; reasons: string[]; coverage: { status: string; assessment?: KnowledgeAssessment | null; approved_assessment?: KnowledgeAssessment | null }; comparison: { same_context_references: boolean; lineage_compatible: boolean } }
type VersionSelection = { lower: string | null; upper: string | null; include: string[]; exclude: string[] }
type SelectionReport = { semantics: string; captured_versions: number; selected_versions: string[]; versions: { version: string; status: string }[] }
type Preview = { version_selection?: SelectionReport; preview_digest: string; source: { coverage: Row['coverage'] }; heads: Record<string, string>; items: Row[]; total: number; next_offset: number | null }
const emit = defineEmits<{ scope: [value: { expected_versions: Record<string, string>; targets: Target[] } | null] }>()
const result = ref<Preview | null>(null), chosen = ref<Record<string, Row>>({}), loading = ref(false), error = ref(''), offset = ref(0)
const previous = ref<number[]>([])
const rangeEnabled = ref(false), lower = ref(''), upper = ref(''), includes = ref(''), excludes = ref('')
const appliedSelector = ref<VersionSelection | null>(null)
const lines = (value: string) => value.split('\n').map(item => item.trim()).filter(Boolean)
let sequence = 0
const source = computed<Target>(() => ({ version: props.version, context_id: props.finding.context_id, vulnerability_id: props.finding.vulnerability_id }))
const label = (text: string) => text.replaceAll('_', ' ')
function isSource(row: Row) { return row.version === props.version && row.context_id === props.finding.context_id }
function blocked(row: Row): string {
  if (isSource(row)) return 'Current context stays in scope.'
  if (!row.assessment_candidate || !row.comparison.lineage_compatible) return 'Identity, presence or responsibility is unresolved.'
  if (!row.comparison.same_context_references) return 'Different consuming root: assess separately.'
  if (!row.capabilities.includes('assess') || !props.finding.capabilities.includes('assess')) return 'Assessment permission unavailable.'
  const original = props.finding.coverage.assessment
  if ([row.coverage.assessment, row.coverage.approved_assessment].some(record => record && (!original || record.revision !== original.revision || record.payload.assessment_id !== original.payload.assessment_id))) return 'Independent target decision: assess separately.'
  return ''
}
function publish() {
  const rows = Object.values(chosen.value)
  emit('scope', rows.length ? { expected_versions: { [props.version]: props.state, ...Object.fromEntries(rows.map(row => [row.version, row.state])) }, targets: [source.value, ...rows.map(({ version, context_id, vulnerability_id }) => ({ version, context_id, vulnerability_id }))] } : null)
}
function toggle(row: Row) {
  if (blocked(row) || loading.value || props.busy) return
  if (chosen.value[row.id]) delete chosen.value[row.id]
  else chosen.value[row.id] = row
  publish()
}
async function load(page = 0, refresh = false) {
  const current = ++sequence; loading.value = true; error.value = ''
  try {
    const selector = refresh ? (rangeEnabled.value ? { lower: lower.value || null, upper: upper.value || null, include: lines(includes.value), exclude: lines(excludes.value) } : null) : appliedSelector.value
    const data = await knowledgeApi<Preview>(`/projects/${encodeURIComponent(props.project)}/coverage/candidates?offset=${page}&limit=20`, send({ source: props.state, context_id: props.finding.context_id, vulnerability_id: props.finding.vulnerability_id, ...(selector ? { version_selection: selector } : {}), ...(!refresh && result.value ? { expected_preview: result.value.preview_digest } : {}) }))
    if (current !== sequence) return
    if (refresh) { appliedSelector.value = selector; chosen.value = {}; previous.value = []; publish() }
    result.value = data; offset.value = page
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Candidate preview failed. Your selection is retained.' }
  finally { if (current === sequence) loading.value = false }
}
async function next() { if (result.value?.next_offset != null) { const old = offset.value; await load(result.value.next_offset); if (!error.value) previous.value.push(old) } }
async function back() { const page = previous.value.at(-1); if (page != null) { await load(page); if (!error.value) previous.value.pop() } }
watch(() => [props.project, props.state, props.version, props.finding.context_id, props.finding.vulnerability_id], () => { ++sequence; result.value = null; chosen.value = {}; previous.value = []; appliedSelector.value = null; rangeEnabled.value = false; lower.value = ''; upper.value = ''; includes.value = ''; excludes.value = ''; loading.value = false; error.value = ''; publish() })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <details class="coverage-panel" aria-label="Cross-version assessment scope">
    <summary>Coverage across product versions <span v-if="Object.keys(chosen).length">· {{ Object.keys(chosen).length }} additional</span></summary>
    <p class="hint">Current scope: {{ version }} · {{ finding.context.root_ref }} · {{ finding.vulnerability_id }}. Other versions require explicit selection and independent review; new branches gain no automatic coverage.</p>
    <details class="version-selection"><summary>Limit additional versions</summary>
      <label><input v-model="rangeEnabled" type="checkbox" :disabled="loading || busy"> Use numeric release range and explicit version names</label>
      <fieldset v-if="rangeEnabled" :disabled="loading || busy"><label>From version (inclusive)<input v-model="lower" placeholder="6.15.6" maxlength="200"></label><label>Through version (inclusive)<input v-model="upper" placeholder="7.2.0" maxlength="200"></label><label>Include versions (one per line)<textarea v-model="includes" rows="2" /></label><label>Exclude versions (one per line)<textarea v-model="excludes" rows="2" /></label></fieldset>
      <p class="hint">Only strict major.minor.patch labels are ordered. Other labels require explicit inclusion. Filters narrow additional candidates; the current assessment context stays in scope. Refresh explicitly to apply edits; no candidates are selected automatically.</p>
    </details>
    <div class="knowledge-actions"><button type="button" :disabled="loading || busy" @click="load(0, true)">{{ result ? 'Refresh coverage candidates' : 'Find coverage candidates' }}</button><small v-if="result">{{ result.total }} candidate contexts · pinned current version heads</small></div>
    <details v-if="result?.version_selection" aria-label="Captured version selection"><summary>Captured version selection · {{ result.version_selection.selected_versions.length }} of {{ result.version_selection.captured_versions }} branches</summary><p class="hint">{{ result.version_selection.semantics }}</p><ul><li v-for="entry in result.version_selection.versions" :key="entry.version">{{ entry.version }} · {{ label(entry.status) }}</li></ul></details>
    <p v-if="error" role="alert">{{ error }} Selection retained. Refreshing candidates clears additional scope.</p>
    <p v-if="Object.keys(chosen).length" role="status">One shared assessment for {{ Object.keys(chosen).length + 1 }} explicit targets. Supporting conditions are required before submission. Package version/material differences need explicit applicability review.</p>
    <ul v-if="result" class="coverage-list">
      <li v-for="row in result.items" :key="row.id">
        <label><input type="checkbox" :aria-label="`Include ${row.version} ${row.context?.root_ref || 'absent context'}`" :checked="isSource(row) || Boolean(chosen[row.id])" :disabled="isSource(row) || Boolean(blocked(row)) || loading || busy" @change="toggle(row)"><strong>{{ row.version }}</strong> · {{ row.component?.name || 'Absent component' }} {{ row.component?.version }} · {{ row.context?.root_ref || 'Absent context' }}</label>
        <small>{{ label(row.classification) }} · {{ label(row.coverage.status) }}</small>
        <p v-if="row.classification === 'material_changed'" class="hint">Material/package version changed: confirm this conclusion and its conditions apply.</p>
        <p v-if="blocked(row)" class="hint">{{ blocked(row) }}</p>
      </li>
    </ul>
    <div v-if="result" class="knowledge-actions"><button type="button" :disabled="loading || busy || !previous.length" @click="back">Previous candidate page</button><button type="button" :disabled="loading || busy || result.next_offset == null" @click="next">Next candidate page</button></div>
    <small class="hint">Source-local references only. Matching inputs do not establish applicability, identity verification or approval.</small>
  </details>
</template>
<style scoped>
.coverage-panel { margin-block: .8rem; min-width: 0; }
.coverage-panel summary { cursor: pointer; }
.version-selection fieldset{border:0;padding:0;display:grid;gap:.5rem;grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}.version-selection label{display:block}.version-selection input:not([type=checkbox]),.version-selection textarea{width:100%;box-sizing:border-box}.version-selection input[type=checkbox]{width:auto}
.coverage-list { list-style: none; padding: 0; display: grid; gap: .65rem; }
.coverage-list li { border-bottom: 1px solid var(--border, #8885); padding-bottom: .5rem; overflow-wrap: anywhere; }
.coverage-list label { display: flex; gap: .4rem; flex-wrap: wrap; align-items: center; }
.coverage-list input { width: auto; }
.coverage-list p { margin: .2rem 0; }
</style>
