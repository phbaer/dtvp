<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeDependencyPaths from './KnowledgeDependencyPaths.vue'
type Row = { component_ref: string; parent_ref: string | null; depth: number; component: { name?: string; version?: string; group?: string; purl?: string; type?: string }; child_count: number; vulnerability_count: number; cycle: boolean; shared: boolean; missing: boolean; path: string[] }
type Tree = { state: string; version: string; items: Row[]; total: number; next_offset: number | null; offset?: number; root_ref?: string | null; truncated?: boolean; row_limit?: number; component_count?: number; dependency_graph?: string | null; max_depth: number; depth_limited: boolean; limitations: string[] }
const props = defineProps<{ project: string; state: string }>()
const opened = ref(false), busy = ref(false), error = ref(''), data = ref<Tree | null>(null)
const depthDraft = ref('3'), root = ref(''), offset = ref(0), previous = ref<number[]>([]), collapsed = ref<Set<string>>(new Set())
const focused = ref(''), pathOnly = ref(false), selected = ref<Row | null>(null), trail = ref<string[]>([])
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
    data.value = result; root.value = target.root; offset.value = target.offset; collapsed.value = new Set(result.items.filter(row => row.child_count > 0).map(key)); selected.value = null
    return true
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'Dependency tree unavailable'; return false }
  finally { if (request === sequence) busy.value = false }
}
function toggle(event: Event) { if (event.target !== event.currentTarget) return; opened.value = (event.currentTarget as HTMLDetailsElement).open; if (opened.value && !data.value && !busy.value) void load() }
function collapse(row: Row) { const next = new Set(collapsed.value), id = key(row); if (next.has(id)) next.delete(id); else next.add(id); collapsed.value = next }
async function paginate(forward: boolean) {
  const target = forward ? data.value?.next_offset : previous.value.at(-1)
  if (target == null || !data.value) return
  const current = offset.value
  if (await load({ offset: target, root: root.value, depth: data.value.max_depth })) { if (forward) previous.value.push(current); else previous.value.pop() }
}
async function browse(componentRef: string, back = false) {
  const origin = root.value
  if (await load({ offset: 0, root: componentRef, depth: data.value?.max_depth ?? 3 })) {
    previous.value = []; focused.value = ''; pathOnly.value = false
    if (!componentRef) trail.value = []
    else if (back) trail.value.pop()
    else trail.value.push(origin)
  }
}
function collapseAll() { selected.value = null; collapsed.value = new Set(data.value?.items.filter(row => row.child_count > 0).map(key)) }

async function applyDepth() { if (await load()) previous.value = [] }
watch(() => [props.project, props.state], () => { ++sequence; busy.value = false; error.value = ''; data.value = null; focused.value = ''; pathOnly.value = false; selected.value = null; trail.value = []; root.value = ''; previous.value = []; offset.value = 0; collapsed.value = new Set(); if (opened.value) void load() })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <details class="dependency-tree" aria-label="Dependency tree" @toggle="toggle">
    <summary>Dependency tree</summary>
    <section aria-label="Pinned dependency tree">
      <div class="tree-toolbar">
        <button v-if="trail.length" type="button" :disabled="busy" @click="browse(trail.at(-1)!, true)">Back</button>
        <button v-if="root" type="button" :disabled="busy" @click="browse('')">View product roots</button>
        <span v-if="data" class="tree-summary">{{ data.version }} · {{ data.total }} traversal entries at depth {{ data.max_depth }}<template v-if="root"> · {{ root }}</template></span>
        <button v-if="data && !pathOnly" type="button" :disabled="busy" @click="collapseAll">Collapse all</button>
        <details class="tree-options"><summary>Options</summary><form @submit.prevent="applyDepth"><label>Dependency depth<select v-model="depthDraft" :disabled="busy"><option v-for="value in 21" :key="value" :value="String(value - 1)">{{ value - 1 }}</option></select></label><button :disabled="busy">Apply depth</button><button type="button" :disabled="busy || !data" @click="load({ offset, root, depth: data?.max_depth ?? 3 })">Refresh tree page</button></form></details>
      </div>
      <p v-if="busy" role="status">Loading dependency tree…</p><p v-if="error" role="alert">{{ error }}</p>
      <template v-if="data">
        <p v-if="data.dependency_graph !== undefined && data.dependency_graph !== 'reported'" role="status" class="tree-cap">Dependency graph declaration: {{ data.dependency_graph || 'unknown' }}. Components shown as isolated roots do not prove they have no dependencies; source graph coverage was not reported.</p>
        <p v-if="data.truncated" role="status" class="tree-cap">Traversal capped at {{ data.row_limit ?? 10000 }} entries; browse a smaller subtree for more focused coverage.</p>
        <KnowledgeDependencyPaths v-if="focused" :project="project" :state="state" :component-ref="focused" expanded />
        <button v-if="focused" type="button" class="tree-back" @click="pathOnly = !pathOnly">{{ pathOnly ? 'Back to dependency tree' : 'Path only' }}</button>
        <div v-show="!pathOnly" class="tree-scroll">
          <table aria-label="Dependency hierarchy"><colgroup><col><col class="count-column"><col class="count-column"></colgroup>
            <thead><tr><th>Component</th><th title="Direct declared dependencies">Deps</th><th title="Unique imported vulnerability identifiers on this component">Vulns</th></tr></thead>
            <tbody><tr v-for="row in visible" :key="key(row)" :class="{ 'selected-node': selected && key(selected) === key(row) }">
              <td><div class="tree-node" :style="{ paddingInlineStart: `${Math.min(row.depth, 20) * 14}px` }">
                <button v-if="expandable(row)" class="tree-expand" type="button" :aria-label="`${collapsed.has(key(row)) ? 'Expand' : 'Collapse'} ${row.component.name || row.component_ref}`" :aria-expanded="!collapsed.has(key(row))" @click="collapse(row)">{{ collapsed.has(key(row)) ? '▸' : '▾' }}</button><span v-else class="tree-spacer"></span>
                <button type="button" class="tree-name" :aria-label="`Select ${row.component.name || row.component_ref}`" :title="[row.component.name, row.component.version, row.component_ref, row.component.purl].filter(Boolean).join('\n')" @click="selected = row"><strong>{{ row.component.group ? `${row.component.group}/` : '' }}{{ row.component.name || row.component_ref }}</strong><span v-if="row.component.version" class="tree-version"> {{ row.component.version }}</span></button>
                <span v-if="row.cycle" class="badge">Cycle</span><span v-if="row.shared" class="badge">Shared</span><span v-if="row.missing" class="badge">Missing reference</span>
              </div><small v-if="row.parent_ref && !data.items.some(item => item.component_ref === row.parent_ref)" class="tree-parent">Parent {{ row.parent_ref }} · preceding page</small></td>
              <td>{{ row.child_count }}</td><td>{{ row.vulnerability_count }}</td>
            </tr></tbody>
          </table><p v-if="!data.items.length" class="empty">No dependency entries in this state.</p>
        </div>
        <p v-if="!selected && !pathOnly && data.items.length" class="tree-hint">Select a component for paths, subtree browsing and identifiers.</p>
        <div v-if="selected && !pathOnly" class="tree-selection" aria-label="Selected dependency">
          <span>{{ selected.component.name || selected.component_ref }} {{ selected.component.version }}</span>
          <button type="button" :aria-label="`Show paths to ${selected.component.name || selected.component_ref}`" @click="focused = selected.component_ref; pathOnly = true">Show paths</button>
          <button v-if="selected.child_count" type="button" :disabled="busy" :aria-label="`Browse subtree ${selected.component.name || selected.component_ref}`" @click="browse(selected.component_ref)">Browse subtree</button>
          <details><summary>Identifiers and path</summary><code>{{ selected.component_ref }}</code><code v-if="selected.component.purl">{{ selected.component.purl }}</code><p>{{ selected.path.join(' → ') }}</p><span v-if="selected.component.type">{{ selected.component.type }}</span></details>
        </div>
        <div v-show="!pathOnly" class="tree-pagination"><button :disabled="busy || !previous.length" @click="paginate(false)">Previous tree page</button><span>{{ offset + (data.items.length ? 1 : 0) }}–{{ offset + data.items.length }} of {{ data.total }} · {{ visible.length }} visible</span><button :disabled="busy || data.next_offset === null" @click="paginate(true)">Next tree page</button></div>
        <details class="tree-coverage"><summary>Coverage and traversal limits</summary><p>Imported dependencies are independent of queue filters. Vulnerability counts are unique imported IDs on each component, not descendant totals or approved applicability.</p><p v-if="data.depth_limited">Deeper dependencies are omitted. Select a component and browse its subtree, or increase depth in Options.</p><ul><li v-for="limitation in data.limitations" :key="limitation">{{ limitation }}</li></ul><p>Cycle and shared rows end their traversal path. Missing references have no imported component metadata. Traversal counts do not establish completeness of deployed software.</p><code>{{ data.state }}</code></details>
      </template>
    </section>
  </details>
</template>
<style scoped>
.dependency-tree{border:1px solid var(--line);border-radius:5px;padding:6px 9px;margin:8px 0;background:var(--surface);min-width:0}.dependency-tree>summary{font-size:.78rem;margin:0}.dependency-tree[open]>summary{margin-bottom:6px}.tree-toolbar{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:6px;font-size:.72rem}.tree-toolbar button,.tree-selection button,.tree-pagination button,.tree-back{padding:3px 7px;font-size:.72rem}.tree-hint{font-size:.7rem;color:var(--muted);margin:5px 0}.tree-summary{flex:1;color:var(--muted);overflow-wrap:anywhere}.tree-options{margin:0}.tree-options>summary{margin:0;font-size:.72rem}.tree-options form{display:flex;align-items:end;gap:6px;flex-wrap:wrap;margin-top:6px}.tree-options label{margin:0;font-size:.72rem}.tree-options select{padding:3px;font-size:.72rem}.tree-scroll{max-height:38vh;overflow:auto;border:1px solid var(--line);border-radius:4px}.tree-scroll table{table-layout:fixed;font-size:.76rem}.count-column{width:52px}.tree-scroll th{position:sticky;top:0;z-index:1;font-size:.68rem}.tree-scroll td,.tree-scroll th{padding:3px 7px}.tree-scroll td:not(:first-child),.tree-scroll th:not(:first-child){text-align:right}.tree-node{display:flex;align-items:center;gap:4px;min-width:0;min-height:23px}.tree-name{padding:0;border:0;background:none;text-align:start;color:var(--ink);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.76rem}.tree-name strong{font-weight:500}.tree-name:hover{text-decoration:underline}.tree-version{color:var(--muted);font-size:.7rem}.tree-expand,.tree-spacer{width:20px;min-width:20px;display:inline-block}.tree-expand{border:0;background:none;padding:1px 3px;font-size:.78rem;color:var(--accent)}.selected-node{background:var(--accent-soft)}.tree-parent{margin:2px 0;font-size:.68rem;overflow-wrap:anywhere}.tree-selection{display:flex;align-items:center;flex-wrap:wrap;gap:6px;padding:6px 0;font-size:.73rem}.tree-selection>span{overflow-wrap:anywhere}.tree-selection details{margin:0;font-size:.7rem;min-width:0}.tree-selection summary{margin:0}.tree-selection code{display:block;overflow-wrap:anywhere}.tree-selection p{overflow-wrap:anywhere}.tree-pagination{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:5px;margin-top:6px;font-size:.7rem}.tree-coverage{margin:6px 0 0;font-size:.7rem}.tree-coverage>summary{margin:0}.tree-coverage p{font-size:.72rem}.badge{font-size:.62rem;padding:1px 3px;margin:0;max-width:90px;white-space:normal}.tree-cap{margin:6px 0;padding:5px 7px;background:var(--warning-bg);color:var(--warning);font-size:.72rem}.dependency-tree code{overflow-wrap:anywhere}.tree-back{margin:3px 0 6px}@media(max-width:600px){.count-column{width:42px}.tree-scroll td,.tree-scroll th{padding:3px 4px}.tree-node{gap:2px}.tree-name{font-size:.72rem}.tree-scroll{max-height:34vh}}
</style>
