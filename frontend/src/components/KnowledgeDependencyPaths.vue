<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Node = { component_ref: string; component: { name?: string; group?: string; version?: string; purl?: string }; missing: boolean }
type Paths = { state: string; component_ref: string; root_ref: string | null; paths: Node[][]; truncated: boolean; dependency_graph: string; limitations: string[] }
const props = defineProps<{ project: string; state: string; componentRef: string; rootRef?: string; expanded?: boolean }>()
const data = ref<Paths | null>(null), busy = ref(false), error = ref(''), selected = ref('0')
const opened = ref(props.expanded || false)
const path = computed(() => data.value?.paths[Number(selected.value)] || [])
let sequence = 0
async function load() {
  const request = ++sequence, pin = props.state, component = props.componentRef, root = props.rootRef || ''
  data.value = null; error.value = ''; selected.value = '0'; busy.value = false
  if (!props.project || !pin || !component) return
  busy.value = true
  try {
    const params = new URLSearchParams({ component_ref: component, limit: '20' })
    if (root) params.set('root_ref', root)
    const result = await knowledgeApi<Paths>(`/projects/${encodeURIComponent(props.project)}/states/${encodeURIComponent(pin)}/dependency-paths?${params}`)
    if (request !== sequence) return
    if (result.state !== pin || result.component_ref !== component || (result.root_ref || '') !== root) throw new Error('Dependency path response changed its requested state or component.')
    data.value = result
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'Dependency paths unavailable' }
  finally { if (request === sequence) busy.value = false }
}
function toggle(event: Event) {
  if (event.target !== event.currentTarget) return
  opened.value = (event.currentTarget as HTMLDetailsElement).open
  if (opened.value && !data.value && !busy.value) void load()
}
watch(() => [props.project, props.state, props.componentRef, props.rootRef], () => {
  ++sequence; data.value = null; error.value = ''; busy.value = false; opened.value = props.expanded || false
  if (opened.value) void load()
}, { immediate: true })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <details class="dependency-location" :open="opened" @toggle="toggle"><summary>Location in dependency tree</summary>
  <section aria-label="Location in dependency tree">
    <header v-if="data && data.paths.length > 1"><label>Path<select v-model="selected" aria-label="Dependency path"><option v-for="(item, index) in data.paths" :key="index" :value="String(index)">{{ index + 1 }} of {{ data.paths.length }} · {{ item.length - 1 }} edges</option></select></label></header>
    <p v-if="busy" role="status">Loading dependency path…</p>
    <p v-if="error" role="alert">{{ error }} <button type="button" @click="load">Retry path</button></p>
    <template v-if="data">
      <ol v-if="path.length" aria-label="Dependency path components"><li v-for="(node, index) in path" :key="`${index}:${node.component_ref}`" :class="{ target: index === path.length - 1 }"><span v-if="index" aria-hidden="true" class="connector">›</span><span :title="[node.component_ref, node.component.purl].filter(Boolean).join('\n')">{{ node.component.group ? `${node.component.group}/` : '' }}{{ node.component.name || node.component_ref }}<small v-if="node.component.version"> {{ node.component.version }}</small><small v-if="node.missing"> · Missing reference</small></span></li></ol>
      <p v-else-if="data.truncated">No path found within the search limits.</p>
      <p v-else>No declared path from {{ rootRef ? 'this consuming root' : 'a product root' }} to this component.</p>
      <p v-if="data.truncated" class="warning" role="status">Path search or display limit reached; additional paths may exist.</p>
      <details><summary>Shortest declared paths · source coverage</summary><p v-if="data.dependency_graph !== 'reported'">Dependency graph coverage: {{ data.dependency_graph || 'unknown' }}.</p><p v-for="item in data.limitations" :key="item">{{ item }}</p><code>{{ data.state }}</code></details>
    </template>
  </section>
  </details>
</template>
<style scoped>
.dependency-location{min-width:0;margin:8px 0;padding:6px 9px;border:1px solid var(--line);border-radius:5px;background:var(--surface);font-size:.78rem}.dependency-location>summary{font-size:.75rem}.dependency-location[open]>summary{margin-bottom:6px}.dependency-location header{min-height:0;padding:0;margin:0;border:0;background:none;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}.dependency-location header strong{font-size:.78rem}.dependency-location label{display:flex;align-items:center;gap:6px;margin:0;font-size:.72rem}.dependency-location select{width:auto;padding:3px 5px;font-size:.72rem}.dependency-location ol{display:flex;flex-wrap:wrap;align-items:center;gap:5px 8px;list-style:none;margin:9px 0 2px;padding:0;max-height:240px;overflow:auto}.dependency-location li{display:flex;align-items:baseline;gap:8px;min-width:0;overflow-wrap:anywhere}.dependency-location li>span:last-child{min-width:0}.connector{color:var(--muted);font-size:1rem}.target>span:last-child{font-weight:650}.dependency-location small{display:inline;margin:0;font-size:.72rem;color:var(--muted);font-weight:400}.dependency-location summary{margin:0}.dependency-location details{margin:7px 0 0;font-size:.7rem;color:var(--muted)}.dependency-location details p{margin:5px 0}.dependency-location code{overflow-wrap:anywhere}.dependency-location p{font-size:.75rem;margin:7px 0}
</style>
