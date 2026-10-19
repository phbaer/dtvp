<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeDependencyPaths from './KnowledgeDependencyPaths.vue'
type Row = { component_ref: string; parent_ref: string | null; depth: number; component: { name?: string; version?: string; group?: string; purl?: string; type?: string }; child_count: number; vulnerability_count: number; cycle: boolean; shared: boolean; missing: boolean; path: string[] }
type Page = { state: string; version: string; root_ref: string | null; parent_ref: string | null; ancestor_path: string[]; items: Row[]; offset: number; total: number; next_offset: number | null; component_count: number; dependency_graph: string; limitations: string[] }
type Branch = { items: Row[]; total: number; next: number | null; busy: boolean; error: string }
type Entry = { key: string; row: Row } | { key: string; branch: Branch; parent: Row | null }
const props = defineProps<{ project: string; state: string }>()
const opened = ref(false), busy = ref(false), error = ref(''), data = ref<Page | null>(null)
const root = ref(''), expanded = ref(new Set<string>()), branches = ref(new Map<string, Branch>())
const focused = ref(''), pathOnly = ref(false), selected = ref<Row | null>(null), trail = ref<string[]>([])
const ROOT = '@roots', MAX_LOADED = 10000
let sequence = 0, generation = 0
const key = (row: Row) => JSON.stringify(row.path)
const expandable = (row: Row) => !row.cycle && row.child_count > 0 && row.depth < 100
const loaded = computed(() => [...branches.value.values()].reduce((sum, branch) => sum + branch.items.length, 0))
const visible = computed(() => {
  const entries: Entry[] = []
  function visit(id: string, parent: Row | null) {
    const branch = branches.value.get(id)
    if (!branch) return
    for (const row of branch.items) {
      entries.push({ key: key(row), row })
      if (expanded.value.has(key(row))) visit(key(row), row)
    }
    if (branch.busy || branch.error || branch.next !== null) entries.push({ key: `more:${id}`, branch, parent })
  }
  visit(ROOT, null)
  return entries
})
async function fetchPage(parent: Row | null, offset: number, scope: string, limit = 100) {
  const params = new URLSearchParams({ offset: String(offset), limit: String(limit) })
  if (scope) params.set('root_ref', scope)
  if (parent) {
    params.set('parent_ref', parent.component_ref)
    for (const ref of parent.path) params.append('path', ref)
  }
  const pin = props.state
  const result = await knowledgeApi<Page>(`/projects/${encodeURIComponent(props.project)}/states/${encodeURIComponent(pin)}/dependency-children?${params}`)
  if (result.state !== pin || (result.root_ref || '') !== scope || result.parent_ref !== (parent?.component_ref || null) || result.offset !== offset || JSON.stringify(result.ancestor_path) !== JSON.stringify(parent?.path || [])) throw new Error('Dependency response changed its requested state or branch; previous rows retained.')
  return result
}
function pageBranch(result: Page): Branch { return { items: result.items, total: result.total, next: result.next_offset, busy: false, error: '' } }
async function load(scope = root.value) {
  if (!props.project || !props.state) return false
  const request = ++sequence
  busy.value = true; error.value = ''
  try {
    const result = await fetchPage(null, 0, scope)
    if (request !== sequence) return false
    ++generation
    data.value = result; root.value = scope; branches.value = new Map([[ROOT, pageBranch(result)]])
    expanded.value = new Set(); selected.value = null; focused.value = ''; pathOnly.value = false
    return true
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'Dependency tree unavailable'; return false }
  finally { if (request === sequence) busy.value = false }
}
async function loadChildren(parent: Row | null) {
  if (busy.value) return
  const id = parent ? key(parent) : ROOT
  if (!branches.value.has(id)) branches.value.set(id, { items: [], total: parent?.child_count || 0, next: 0, busy: false, error: '' })
  const branch = branches.value.get(id)!
  if (branch.busy || branch.next === null) return
  const limit = Math.min(100, MAX_LOADED - loaded.value)
  if (limit <= 0) { branch.error = 'Loaded entry limit reached. Browse a smaller subtree or refresh to release loaded branches.'; return }
  const current = generation
  branch.busy = true; branch.error = ''
  try {
    const result = await fetchPage(parent, branch.next, root.value, limit)
    if (current !== generation) return
    // Concurrent sibling requests may have consumed the remaining display budget.
    if (loaded.value + result.items.length > MAX_LOADED) throw new Error('Loaded entry limit reached. Browse a smaller subtree or refresh.')
    branch.items.push(...result.items); branch.total = result.total; branch.next = result.next_offset
  } catch (err) { if (current === generation) branch.error = err instanceof Error ? err.message : 'Dependencies unavailable' }
  finally { if (current === generation) branch.busy = false }
}
function toggle(event: Event) { if (event.target !== event.currentTarget) return; opened.value = (event.currentTarget as HTMLDetailsElement).open; if (opened.value && !data.value && !busy.value) void load() }
function collapse(row: Row) {
  const next = new Set(expanded.value), id = key(row)
  if (next.has(id)) next.delete(id)
  else { next.add(id); if (!branches.value.has(id)) void loadChildren(row) }
  expanded.value = next
}
async function browse(componentRef: string, back = false) {
  const origin = root.value
  if (await load(componentRef)) {
    if (!componentRef) trail.value = []
    else if (back) trail.value.pop()
    else trail.value.push(origin)
  }
}
function collapseAll() { selected.value = null; expanded.value = new Set() }
watch(() => [props.project, props.state], () => { ++sequence; ++generation; busy.value = false; error.value = ''; data.value = null; branches.value = new Map(); expanded.value = new Set(); focused.value = ''; pathOnly.value = false; selected.value = null; trail.value = []; root.value = ''; if (opened.value) void load() })
onBeforeUnmount(() => { ++sequence; ++generation })
</script>
<template>
  <details class="dependency-tree" aria-label="Dependency tree" @toggle="toggle">
    <summary>Dependency tree</summary>
    <section aria-label="Pinned dependency tree">
      <div class="tree-toolbar">
        <button v-if="trail.length" type="button" :disabled="busy" @click="browse(trail.at(-1)!, true)">Back</button>
        <button v-if="root" type="button" :disabled="busy" @click="browse('')">View product roots</button>
        <span v-if="data" class="tree-summary">{{ data.version }} · {{ data.component_count }} components · {{ loaded }} loaded<template v-if="root"> · {{ root }}</template></span>
        <button v-if="data && !pathOnly" type="button" :disabled="busy" @click="collapseAll">Collapse all</button>
        <button type="button" :disabled="busy" @click="load()">Refresh tree</button>
      </div>
      <p v-if="busy" role="status">Loading dependency tree…</p><p v-if="error" role="alert">{{ error }}</p>
      <template v-if="data">
        <p v-if="data.dependency_graph !== undefined && data.dependency_graph !== 'reported'" role="status" class="tree-cap">Dependency graph declaration: {{ data.dependency_graph || 'unknown' }}. Components shown as isolated roots do not prove they have no dependencies; source graph coverage was not reported.</p>

        <KnowledgeDependencyPaths v-if="focused" :project="project" :state="state" :component-ref="focused" expanded />
        <button v-if="focused" type="button" class="tree-back" @click="pathOnly = !pathOnly">{{ pathOnly ? 'Back to dependency tree' : 'Path only' }}</button>
        <div v-show="!pathOnly" class="tree-scroll">
          <table aria-label="Dependency hierarchy"><colgroup><col><col class="count-column"><col class="count-column"></colgroup>
            <thead><tr><th>Component</th><th title="Direct declared dependencies">Deps</th><th title="Unique imported vulnerability identifiers on this component">Vulns</th></tr></thead>
            <tbody><template v-for="entry in visible" :key="entry.key"><tr v-if="'row' in entry" :class="{ 'selected-node': selected && key(selected) === key(entry.row) }">
              <td><div class="tree-node" :style="{ paddingInlineStart: `${Math.min(entry.row.depth, 20) * 14}px` }">
                <button v-if="expandable(entry.row)" class="tree-expand" type="button" :disabled="busy" :aria-label="`${!expanded.has(key(entry.row)) ? 'Expand' : 'Collapse'} ${entry.row.component.name || entry.row.component_ref}`" :aria-expanded="expanded.has(key(entry.row))" @click="collapse(entry.row)">{{ !expanded.has(key(entry.row)) ? '▸' : '▾' }}</button><span v-else class="tree-spacer"></span>
                <button type="button" class="tree-name" :aria-label="`Select ${entry.row.component.name || entry.row.component_ref}`" :title="[entry.row.component.name, entry.row.component.version, entry.row.component_ref, entry.row.component.purl].filter(Boolean).join('\n')" @click="selected = entry.row"><strong>{{ entry.row.component.group ? `${entry.row.component.group}/` : '' }}{{ entry.row.component.name || entry.row.component_ref }}</strong><span v-if="entry.row.component.version" class="tree-version"> {{ entry.row.component.version }}</span></button>
                <span v-if="entry.row.cycle" class="badge">Cycle</span><span v-if="entry.row.shared" class="badge">Shared</span><span v-if="entry.row.missing" class="badge">Missing reference</span><span v-if="entry.row.child_count && entry.row.depth >= 100" class="badge">Depth limit</span>
              </div></td>
              <td>{{ entry.row.child_count }}</td><td>{{ entry.row.vulnerability_count }}</td>
            </tr><tr v-else class="branch-more"><td colspan="3" :style="{ paddingInlineStart: `${Math.min((entry.parent?.depth ?? -1) + 1, 20) * 14 + 30}px` }"><span v-if="entry.branch.busy" role="status">Loading dependencies…</span><template v-else><p v-if="entry.branch.error" role="alert">{{ entry.branch.error }}</p><button type="button" :disabled="busy || loaded >= MAX_LOADED" @click="loadChildren(entry.parent)">{{ entry.branch.error ? 'Retry' : entry.parent ? 'Load more children' : 'Load more roots' }}<template v-if="entry.parent"> of {{ entry.parent.component.name || entry.parent.component_ref }}</template> · {{ entry.branch.items.length }} of {{ entry.branch.total }}</button></template></td></tr></template></tbody>
          </table><p v-if="!branches.get(ROOT)?.items.length" class="empty">No dependency entries in this state.</p>
        </div>
        <p v-if="!selected && !pathOnly && loaded" class="tree-hint">Select a component for paths, subtree browsing and identifiers.</p>
        <div v-if="selected && !pathOnly" class="tree-selection" aria-label="Selected dependency">
          <span>{{ selected.component.name || selected.component_ref }} {{ selected.component.version }}</span>
          <button type="button" :aria-label="`Show paths to ${selected.component.name || selected.component_ref}`" @click="focused = selected.component_ref; pathOnly = true">Show paths</button>
          <button v-if="selected.child_count" type="button" :disabled="busy" :aria-label="`Browse subtree ${selected.component.name || selected.component_ref}`" @click="browse(selected.component_ref)">Browse subtree</button>
          <details><summary>Identifiers and path</summary><code>{{ selected.component_ref }}</code><code v-if="selected.component.purl">{{ selected.component.purl }}</code><p>{{ selected.path.join(' → ') }}</p><span v-if="selected.component.type">{{ selected.component.type }}</span></details>
        </div>

        <details class="tree-coverage"><summary>Coverage and traversal limits</summary><p>Imported dependencies are independent of queue filters. Vulnerability counts are unique imported IDs on each component, not descendant totals or approved applicability.</p><p>Children load on expansion. Load more siblings within their branch; existing branches stay in place. The browser retains at most 10,000 loaded entries and 100 dependency levels; browse a subtree to focus further.</p><ul><li v-for="limitation in data.limitations" :key="limitation">{{ limitation }}</li></ul><p>Cycle rows end their traversal path. Shared components can be expanded separately in each usage path. Missing references have no imported component metadata. Traversal counts do not establish completeness of deployed software.</p><code>{{ data.state }}</code></details>
      </template>
    </section>
  </details>
</template>
<style scoped>
.dependency-tree{border:1px solid var(--line);border-radius:5px;padding:6px 9px;margin:8px 0;background:var(--surface);min-width:0}.dependency-tree>summary{font-size:.78rem;margin:0}.dependency-tree[open]>summary{margin-bottom:6px}.tree-toolbar{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:6px;font-size:.72rem}.tree-toolbar button,.tree-selection button,.branch-more button,.tree-back{padding:3px 7px;font-size:.72rem}.branch-more td{background:var(--bg)}.branch-more button{border:0;background:none;color:var(--accent);font-size:.7rem;padding:2px}.branch-more p{margin:3px 0;font-size:.7rem}.tree-hint{font-size:.7rem;color:var(--muted);margin:5px 0}.tree-summary{flex:1;color:var(--muted);overflow-wrap:anywhere}.tree-scroll{max-height:38vh;overflow:auto;border:1px solid var(--line);border-radius:4px}.tree-scroll table{table-layout:fixed;font-size:.76rem}.count-column{width:52px}.tree-scroll th{position:sticky;top:0;z-index:1;font-size:.68rem}.tree-scroll td,.tree-scroll th{padding:3px 7px}.tree-scroll td:not(:first-child),.tree-scroll th:not(:first-child){text-align:right}.tree-node{display:flex;align-items:center;gap:4px;min-width:0;min-height:23px}.tree-name{padding:0;border:0;background:none;text-align:start;color:var(--ink);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.76rem}.tree-name strong{font-weight:500}.tree-name:hover{text-decoration:underline}.tree-version{color:var(--muted);font-size:.7rem}.tree-expand,.tree-spacer{width:20px;min-width:20px;display:inline-block}.tree-expand{border:0;background:none;padding:1px 3px;font-size:.78rem;color:var(--accent)}.selected-node{background:var(--accent-soft)}.tree-selection{display:flex;align-items:center;flex-wrap:wrap;gap:6px;padding:6px 0;font-size:.73rem}.tree-selection>span{overflow-wrap:anywhere}.tree-selection details{margin:0;font-size:.7rem;min-width:0}.tree-selection summary{margin:0}.tree-selection code{display:block;overflow-wrap:anywhere}.tree-selection p{overflow-wrap:anywhere}.tree-coverage{margin:6px 0 0;font-size:.7rem}.tree-coverage>summary{margin:0}.tree-coverage p{font-size:.72rem}.badge{font-size:.62rem;padding:1px 3px;margin:0;max-width:90px;white-space:normal}.tree-cap{margin:6px 0;padding:5px 7px;background:var(--warning-bg);color:var(--warning);font-size:.72rem}.dependency-tree code{overflow-wrap:anywhere}.tree-back{margin:3px 0 6px}@media(max-width:600px){.count-column{width:42px}.tree-scroll td,.tree-scroll th{padding:3px 4px}.tree-node{gap:2px}.tree-name{font-size:.72rem}.tree-scroll{max-height:34vh}}
</style>
