<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Row = { component_ref: string; parent_ref: string | null; depth: number; component: { name?: string; version?: string; group?: string; purl?: string; type?: string }; child_count: number; vulnerability_count: number; cycle: boolean; shared: boolean; missing: boolean; path: string[] }
type Tree = { state: string; version: string; items: Row[]; total: number; next_offset: number | null; offset?: number; root_ref?: string | null; truncated?: boolean; row_limit?: number; component_count?: number; dependency_graph?: string | null; max_depth: number; depth_limited: boolean; limitations: string[] }
const props = defineProps<{ project: string; state: string }>()
const opened = ref(false), busy = ref(false), error = ref(''), data = ref<Tree | null>(null)
const depthDraft = ref('3'), root = ref(''), offset = ref(0), previous = ref<number[]>([]), collapsed = ref<Set<string>>(new Set())
let sequence = 0
const key = (row: Row) => JSON.stringify(row.path)
const terminal = (row: Row) => row.cycle || row.shared
const visible = computed(() => data.value?.items.filter(row => !row.path.slice(0, -1).some((_, index) => collapsed.value.has(JSON.stringify(row.path.slice(0, index + 1))))) || [])
const expandable = (row: Row) => !terminal(row) && data.value?.items.some(item => item.path.length > row.path.length && row.path.every((value, index) => item.path[index] === value))
async function load(target = { offset: 0, root: root.value, depth: Number(depthDraft.value) }) {
  if (!props.project || !props.state || !Number.isInteger(target.depth) || target.depth < 0 || target.depth > 20) return false
  const request = ++sequence, pin = props.state, project = props.project
  busy.value = true; error.value = ''
  try {
    const params = new URLSearchParams({ offset: String(target.offset), limit: '100', max_depth: String(target.depth) })
    if (target.root) params.set('root_ref', target.root)
    const result = await knowledgeApi<Tree>(`/projects/${encodeURIComponent(project)}/states/${encodeURIComponent(pin)}/dependency-tree?${params}`)
    if (request !== sequence) return false
    if (result.state !== pin || result.max_depth !== target.depth || ('root_ref' in result && (result.root_ref || '') !== target.root) || ('offset' in result && result.offset !== target.offset)) throw new Error('Dependency tree response changed its requested state, scope or depth; previous page retained.')
    if (root.value !== target.root || data.value?.max_depth !== target.depth) previous.value = []
    data.value = result; root.value = target.root; offset.value = target.offset; collapsed.value = new Set()
    return true
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'Dependency tree unavailable'; return false }
  finally { if (request === sequence) busy.value = false }
}
function toggle(event: Event) { opened.value = (event.currentTarget as HTMLDetailsElement).open; if (opened.value && !data.value && !busy.value) void load() }
function collapse(row: Row) { const next = new Set(collapsed.value), id = key(row); if (next.has(id)) next.delete(id); else next.add(id); collapsed.value = next }
async function paginate(forward: boolean) {
  const target = forward ? data.value?.next_offset : previous.value.at(-1)
  if (target == null || !data.value) return
  const current = offset.value
  if (await load({ offset: target, root: root.value, depth: data.value.max_depth })) { if (forward) previous.value.push(current); else previous.value.pop() }
}
async function browse(componentRef: string) { if (await load({ offset: 0, root: componentRef, depth: data.value?.max_depth ?? 3 })) previous.value = [] }
async function applyDepth() { if (await load()) previous.value = [] }
watch(() => [props.project, props.state], () => { ++sequence; busy.value = false; error.value = ''; data.value = null; root.value = ''; previous.value = []; offset.value = 0; collapsed.value = new Set(); if (opened.value) void load() })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <details class="dependency-tree" aria-label="Dependency tree" @toggle="toggle"><summary>Dependency tree</summary>
    <section aria-label="Pinned dependency tree"><p class="hint">Imported dependencies for this pinned product version, independent of queue filters. Vulnerability counts are unique imported IDs linked to each component, not descendant totals or approved applicability.</p><form class="tree-toolbar" @submit.prevent="applyDepth"><label>Dependency depth<select v-model="depthDraft" :disabled="busy"><option v-for="value in 21" :key="value" :value="String(value - 1)">{{ value - 1 }}</option></select></label><button :disabled="busy">Apply depth</button><button type="button" :disabled="busy || !data" @click="load({ offset, root, depth: data?.max_depth ?? 3 })">Refresh tree page</button><button v-if="root" type="button" :disabled="busy" @click="browse('')">View product roots</button></form>
      <p v-if="busy" role="status">Loading dependency tree…</p><p v-if="error" role="alert">{{ error }}</p>
      <template v-if="data"><p class="tree-summary">{{ data.version }} · {{ data.total }} traversal entries at depth {{ data.max_depth }}<template v-if="root"> · Subtree <code>{{ root }}</code></template></p><p v-if="data.dependency_graph !== undefined && data.dependency_graph !== 'reported'" role="status" class="tree-cap">Dependency graph declaration: {{ data.dependency_graph || 'unknown' }}. Components shown as isolated roots do not prove they have no dependencies; source graph coverage was not reported.</p><p v-if="data.truncated" role="status" class="tree-cap">Traversal capped at {{ data.row_limit ?? 10000 }} entries; counts and pages cover this bounded capture. Browse a smaller subtree or reduce depth for more focused coverage.</p><p v-if="data.depth_limited" class="hint">Deeper dependencies are omitted at this depth. Browse a subtree or apply a larger depth to inspect them.</p>
        <div class="tree-scroll"><table aria-label="Dependency hierarchy"><thead><tr><th>Component</th><th>Dependencies</th><th>Vulnerabilities</th><th>Traversal</th></tr></thead><tbody><tr v-for="row in visible" :key="key(row)"><td><div class="tree-node" :style="{ paddingInlineStart: `${Math.min(row.depth, 8) * 12}px` }"><button v-if="expandable(row)" class="tree-expand" type="button" :aria-label="`${collapsed.has(key(row)) ? 'Expand' : 'Collapse'} ${row.component.name || row.component_ref}`" :aria-expanded="!collapsed.has(key(row))" @click="collapse(row)">{{ collapsed.has(key(row)) ? '▸' : '▾' }}</button><span v-else class="tree-spacer"></span><div><strong>{{ row.component.group ? `${row.component.group}/` : '' }}{{ row.component.name || row.component_ref }}</strong><span v-if="row.component.version" class="tree-version"> {{ row.component.version }}</span><small v-if="row.parent_ref" class="tree-path" :title="row.path.join(' → ')">Depth {{ row.depth }} · Parent {{ row.parent_ref }}</small><details class="tree-identifiers"><summary>Identifiers and path</summary><code>{{ row.component_ref }}</code><code v-if="row.component.purl">{{ row.component.purl }}</code><p>{{ row.path.join(' → ') }}</p><span v-if="row.component.type">{{ row.component.type }}</span></details></div></div></td><td>{{ row.child_count }}<button v-if="row.child_count" type="button" class="tree-browse" :disabled="busy" :aria-label="`Browse subtree ${row.component.name || row.component_ref}`" @click="browse(row.component_ref)">Browse subtree</button></td><td>{{ row.vulnerability_count }}</td><td><span v-if="row.cycle" class="badge">Cycle</span><span v-if="row.shared" class="badge">Shared</span><span v-if="row.missing" class="badge">Missing reference</span><span v-if="!terminal(row) && row.child_count && !expandable(row)" class="hint">Children outside this page/depth</span></td></tr></tbody></table><p v-if="!data.items.length" class="empty">No dependency entries in this state.</p></div>
        <div class="tree-pagination"><button :disabled="busy || !previous.length" @click="paginate(false)">Previous tree page</button><span>{{ offset + (data.items.length ? 1 : 0) }}–{{ offset + data.items.length }} of {{ data.total }} entries · {{ visible.length }} visible</span><button :disabled="busy || data.next_offset === null" @click="paginate(true)">Next tree page</button></div><details><summary>Coverage and traversal limits</summary><ul><li v-for="limitation in data.limitations" :key="limitation">{{ limitation }}</li></ul><p>Cycle and shared rows end the current traversal path. Missing references have no imported component metadata; any displayed dependency edges remain source declarations. Traversal counts describe imported evidence, not completeness of the deployed software.</p><code>{{ data.state }}</code></details>
      </template>
    </section>
  </details>
</template>
<style scoped>
.dependency-tree{border:1px solid var(--line);border-radius:6px;padding:8px 10px;margin:10px 0;background:var(--surface);min-width:0}.dependency-tree>summary{font-size:.82rem}.tree-toolbar{display:flex;gap:8px;align-items:end;flex-wrap:wrap}.tree-toolbar label{margin:0;min-width:120px;font-size:.8rem}.tree-version{margin-inline-start:4px;color:var(--muted)}.tree-summary{font-size:.8rem;color:var(--muted);overflow-wrap:anywhere}.tree-scroll{max-height:58vh;overflow:auto;border:1px solid var(--line);border-radius:5px}.tree-scroll table{font-size:.8rem;min-width:530px}.tree-scroll th{position:sticky;top:0;z-index:1}.tree-node{display:flex;align-items:start;gap:4px;min-width:0}.tree-node>div{min-width:100px;overflow-wrap:anywhere}.tree-expand,.tree-spacer{width:22px;min-width:22px}.tree-expand{padding:1px 4px}.tree-spacer{display:inline-block}.tree-path{font-size:.7rem;margin:2px 0;color:var(--muted)}.tree-identifiers{margin:4px 0 0;font-size:.7rem}.tree-identifiers code{display:block;overflow-wrap:anywhere}.tree-browse{display:block;font-size:.7rem;padding:2px 5px;margin-top:4px}.tree-pagination{display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px;font-size:.75rem}.tree-scroll td{vertical-align:top}.badge{font-size:.68rem;padding:2px 4px;margin:1px}.hint{font-size:.75rem}.dependency-tree code{overflow-wrap:anywhere}.tree-cap{padding:8px;background:var(--warning-bg);color:var(--warning);font-size:.8rem}@media(max-width:600px){.tree-toolbar button{font-size:.75rem}.tree-pagination{justify-content:start}.tree-scroll{max-height:52vh}}
</style>
