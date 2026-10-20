<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError, send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
type Rule = { selector: string; team_id: string; aliases: string[]; versions: string[] | null }
type Fields = { mode: 'component' | 'purl' | 'fallback'; name: string; namespace_mode: 'exact' | 'known_empty' | 'absent_or_unknown'; namespace: string; purl: string; case_sensitive: boolean }
type Selector = { raw: string; fields: Fields; representable: boolean }
type Editor = { policy_state: string | null; policy: { rules: Rule[]; context_roots: Record<string, string[]> }; versions: Record<string, string>; selectors: Selector[]; capabilities: string[]; available_teams: { id: string; name: string }[] }
type Preview = { preview_digest: string; versions: Record<string, { before: { contexts: number }; after: { contexts: number; by_status: Record<string, number> }; changed_contexts: number; added_contexts: number; removed_contexts: number }>; limitations: string[] }
const props = defineProps<{ project: string }>(), emit = defineEmits<{ changed: [] }>()
const opened = ref(false), busy = ref(false), error = ref(''), notice = ref(''), data = ref<Editor | null>(null), query = ref('')
const rules = ref<Rule[]>([]), selectors = ref<Selector[]>([]), selected = ref<number | null>(null), selectorChanged = ref(false)
const empty = (): Fields => ({ mode: 'component', name: '', namespace_mode: 'absent_or_unknown', namespace: '', purl: '', case_sensitive: false })
const fields = ref(empty()), team = ref(''), aliases = ref(''), scope = ref('all'), versions = ref<string[]>([])
const prepared = ref<{ body: Record<string, unknown>; preview: Preview } | null>(null)
let sequence = 0
function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T }
const path = () => `/projects/${encodeURIComponent(props.project)}/ownership`
const canManage = computed(() => data.value?.capabilities.includes('manage'))
const visible = computed(() => rules.value.map((rule, index) => ({ rule, index })).filter(({ rule }) => `${rule.selector} ${name(rule.team_id)} ${rule.aliases.join(' ')}`.toLocaleLowerCase().includes(query.value.toLocaleLowerCase())))
const versionOptions = computed(() => [...new Set([...Object.keys(data.value?.versions || {}), ...versions.value])].sort())
const editableSelector = computed(() => selected.value === -1 || selectorChanged.value || selected.value !== null && selectors.value[selected.value]?.representable)
function name(id: string) { return data.value?.available_teams.find(item => item.id === id)?.name || id }
function closeRule() { selected.value = null; fields.value = empty(); selectorChanged.value = false }
function edit(index: number) {
  selected.value = index; selectorChanged.value = index < 0; prepared.value = null; error.value = ''
  const rule = rules.value[index]
  fields.value = rule ? { ...selectors.value[index]!.fields } : empty()
  team.value = rule?.team_id || ''; aliases.value = rule?.aliases.join('\n') || ''; scope.value = rule?.versions ? 'selected' : 'all'; versions.value = [...(rule?.versions || [])]
}
async function load(keepDraft = false) {
  const request = ++sequence; busy.value = true; error.value = ''
  try {
    const current = await knowledgeApi<Editor>(`${path()}/editor`)
    if (request !== sequence) return
    data.value = current
    if (!keepDraft) { rules.value = clone(current.policy.rules); selectors.value = clone(current.selectors); closeRule() }
    prepared.value = null
    if (keepDraft) notice.value = 'Current policy pins refreshed. Your draft is retained; review the complete preview again before applying.'
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'Ownership editor unavailable' }
  finally { if (request === sequence) busy.value = false }
}
async function saveRule() {
  if (busy.value || selected.value === null || !team.value || scope.value === 'selected' && !versions.value.length) return
  const request = ++sequence; busy.value = true; error.value = ''
  try {
    const index = selected.value
    const selector = selectorChanged.value ? await knowledgeApi<Selector>(`${path()}/selectors/encode`, send(fields.value)) : selectors.value[index]!
    if (request !== sequence) return
    const previous = rules.value[index]
    const values = previous && aliases.value === previous.aliases.join('\n') ? [...previous.aliases] : aliases.value.split('\n').map(value => value.trim()).filter(Boolean)
    const rule: Rule = { selector: selector.raw, team_id: team.value, aliases: values, versions: scope.value === 'all' ? null : [...versions.value] }
    if (index < 0) { rules.value.push(rule); selectors.value.push(selector) } else { rules.value[index] = rule; selectors.value[index] = selector }
    prepared.value = null; closeRule()
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'Selector could not be represented' }
  finally { if (request === sequence) busy.value = false }
}
function remove(index: number) { rules.value.splice(index, 1); selectors.value.splice(index, 1); prepared.value = null; closeRule() }
async function preview() {
  if (!data.value || busy.value || selected.value !== null) return
  const request = ++sequence; busy.value = true; error.value = ''; notice.value = ''
  const body = { request_id: crypto.randomUUID(), expected_policy: data.value.policy_state, expected_versions: { ...data.value.versions }, rules: clone(rules.value), context_roots: clone(data.value.policy.context_roots) }
  try {
    const result = await knowledgeApi<Preview>(`${path()}/editor/preview`, send(body))
    if (request === sequence) prepared.value = { body, preview: result }
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'Ownership preview failed' }
  finally { if (request === sequence) busy.value = false }
}
async function apply() {
  if (!prepared.value || busy.value) return
  const request = ++sequence; busy.value = true; error.value = ''
  try {
    const receipt = await knowledgeApi<{ committed: boolean; projection?: string }>(`${path()}/editor/apply`, send({ ...prepared.value.body, preview_digest: prepared.value.preview.preview_digest }))
    if (request !== sequence) return
    if (!receipt.committed) throw new Error('Publication uncertain. Retry this exact prepared policy.')
    prepared.value = null; notice.value = receipt.projection === 'pending' ? 'Ownership committed; projection pending.' : 'Ownership updated across the pinned versions. Historical assessments remain retained.'
    emit('changed'); await load()
  } catch (err) { if (request === sequence) error.value = err instanceof ApiError && err.status === 409 ? 'Policy or version heads changed. Your draft is retained. Reload current pins explicitly, then review a new preview.' : err instanceof ApiError && err.status === 503 ? 'Publication may be uncertain. Retry this exact prepared policy and request ID.' : err instanceof Error ? err.message : 'Ownership update failed' }
  finally { if (request === sequence) busy.value = false }
}
function toggle(open: boolean) { opened.value = open; if (opened.value && !data.value && !busy.value) void load() }
watch(() => fields.value.mode, value => { if (value === 'fallback') fields.value.case_sensitive = false })
watch(() => props.project, () => { ++sequence; data.value = null; query.value = ''; rules.value = []; selectors.value = []; prepared.value = null; busy.value = false; notice.value = ''; error.value = ''; closeRule(); if (opened.value) void load() })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <TaskSurface class="knowledge-ownership" @active="toggle" title="Component ownership"><section aria-label="Component ownership editor" :aria-busy="busy">
    <p class="hint">Teams own matched components and their dependencies recursively. An explicit child owner takes responsibility for that subtree. Ownership never grants access or additional approval.</p>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p><p v-if="busy" role="status">Loading ownership…</p>
    <template v-if="data">
      <div class="ownership-toolbar"><label>Find ownership rules<input v-model="query" type="search" placeholder="Component, namespace or team"></label><button v-if="canManage" :disabled="busy || !!prepared" @click="edit(-1)">Add ownership rule</button></div>
      <p>{{ rules.length }} rules · {{ Object.keys(data.versions).length }} current versions <span v-if="!canManage">· Read only</span></p>
      <div class="ownership-list"><article v-for="{rule,index} in visible" :key="index"><div><strong>{{ name(rule.team_id) }}</strong> · <code>{{ rule.selector }}</code><small>{{ rule.versions ? `Versions: ${rule.versions.join(', ')}` : 'All product versions' }}<span v-if="rule.aliases.length"> · Labels: {{ rule.aliases.join(', ') }}</span></small></div><button v-if="canManage" :disabled="busy || !!prepared" @click="edit(index)">Edit rule {{ index + 1 }}</button><button v-if="canManage" :disabled="busy || !!prepared" @click="remove(index)">Remove rule {{ index + 1 }}</button></article></div>
      <form v-if="canManage && selected !== null" aria-label="Ownership rule editor" @submit.prevent="saveRule"><fieldset :disabled="busy">
        <p v-if="!editableSelector" class="hint">This selector uses legacy syntax. It will remain byte-for-byte unchanged unless you explicitly replace it.</p><button v-if="!editableSelector" type="button" @click="selectorChanged = true; fields = empty()">Replace legacy selector explicitly</button>
        <fieldset :disabled="!editableSelector" @input="selectorChanged = true" @change="selectorChanged = true"><label>Match by<select v-model="fields.mode"><option value="component">Component name and namespace</option><option value="purl">Package URL</option><option value="fallback">Fallback for otherwise unowned components</option></select></label>
          <template v-if="fields.mode === 'component'"><label>Component name<input v-model="fields.name" required maxlength="200"></label><label>Namespace matching<select v-model="fields.namespace_mode"><option value="absent_or_unknown">Unknown or known-empty namespace (v1 bare name)</option><option value="known_empty">Known-empty namespace only</option><option value="exact">Exact namespace</option></select></label><label v-if="fields.namespace_mode === 'exact'">Namespace<input v-model="fields.namespace" required maxlength="200"></label></template>
          <label v-if="fields.mode === 'purl'">Package URL<input v-model="fields.purl" required maxlength="200" placeholder="pkg:maven/org.example/library"></label><label v-if="fields.mode !== 'fallback'"><input v-model="fields.case_sensitive" type="checkbox"> Case-sensitive matching</label>
        </fieldset>
        <label>Primary responsible team<select v-model="team" required><option value="" disabled>Select responsible team</option><option v-for="item in data.available_teams" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
        <label>Product-version scope<select v-model="scope"><option value="all">All product versions (default)</option><option value="selected">Only selected versions</option></select></label><label v-if="scope === 'selected'">Scoped versions<select v-model="versions" multiple required><option v-for="version in versionOptions" :key="version" :value="version">{{ version }}</option></select></label>
        <details><summary>Descriptive aliases</summary><label>Alias labels (one per line)<textarea v-model="aliases" /></label><p class="hint">Aliases are descriptive labels, not extra owners, required reviewers or permissions.</p></details>
        <button>Keep rule in draft</button><button type="button" @click="closeRule">Cancel rule edit</button>
      </fieldset></form>
      <details><summary>Preserved consuming roots and raw policy</summary><pre>{{ JSON.stringify({ rules, context_roots: data.policy.context_roots }, null, 2) }}</pre><p class="hint">Existing consuming-root selections and untouched selectors are retained. This editor does not replace those selections.</p></details>
      <div v-if="canManage" class="ownership-toolbar"><button v-if="!prepared" :disabled="busy || selected !== null" @click="preview">Preview complete ownership policy</button><button :disabled="busy" @click="load(true)">Reload current pins, keep draft</button></div>
      <section v-if="prepared" aria-label="Prepared ownership policy"><h3>Review changes across all current versions</h3><div class="ownership-table"><table><thead><tr><th>Version</th><th>Contexts before / after</th><th>Changed</th><th>Added / removed</th></tr></thead><tbody><tr v-for="(row, version) in prepared.preview.versions" :key="version"><th>{{ version }}</th><td>{{ row.before.contexts }} / {{ row.after.contexts }}</td><td>{{ row.changed_contexts }}</td><td>{{ row.added_contexts }} / {{ row.removed_contexts }}</td></tr></tbody></table></div><p v-for="limit in prepared.preview.limitations" :key="limit" class="hint">{{ limit }}</p><details><summary>Exact prepared policy and pins</summary><pre>{{ JSON.stringify(prepared.body, null, 2) }}</pre><code>{{ prepared.preview.preview_digest }}</code></details><button :disabled="busy" @click="apply">Apply reviewed ownership policy</button></section>
    </template>
  </section></TaskSurface>
</template>
<style scoped>
.knowledge-ownership { margin:12px 0; padding:12px 0; border-block:1px solid var(--line); min-width:0 }summary { cursor:pointer }.ownership-toolbar { display:flex; gap:12px; align-items:end; flex-wrap:wrap; margin:12px 0 }.ownership-toolbar label { flex:1; min-width:180px; margin:0 }.ownership-list { max-height:320px; overflow:auto }.ownership-list article { display:flex; gap:8px; align-items:center; border-bottom:1px solid var(--line); padding:10px 0 }.ownership-list article > div { flex:1; min-width:0 }.ownership-list small { display:block; color:var(--muted); margin-top:4px }.ownership-list code { overflow-wrap:anywhere }fieldset { border:0; padding:0; min-width:0 }form { padding:16px 0 }label { display:block; margin:10px 0 }input[type=checkbox] { width:auto }pre,code { white-space:pre-wrap; overflow-wrap:anywhere; font-size:.75rem }pre { max-height:300px; overflow:auto }.hint { font-size:.8rem; line-height:1.5 }.ownership-table { overflow:auto; max-width:100% }button { margin-right:6px }@media(max-width:600px) { .ownership-list article { flex-wrap:wrap }.ownership-list article > div { flex-basis:100% } }
</style>
