<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeComponentMetadata from './KnowledgeComponentMetadata.vue'
type Row = { component_ref: string; component: { name?: string; group?: string; version?: string; purl?: string }; context_count: number; team_ids: string[]; ownership_statuses: string[]; delegated_contexts: number; incoming_declared: number; outgoing_declared: number }
type Context = { id: string; root_ref: string; team_id: string | null; status: string; delegated: boolean; assignment: string; dependency_graph: string }
type Page = { state: string; head: string; version: string; items: Row[]; next_offset: number | null; statistics: { component_occurrences: number; consuming_contexts: number; all_component_occurrences: number }; teams: { id: string; name: string }[]; limitations: string[] }
const props = defineProps<{ project: string; state: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [value: boolean]; changed: [] }>()
const expanded = ref(false), busy = ref(false), contextBusy = ref(false), locked = ref(false), error = ref(''), data = ref<Page | null>(null)
const selectedState = ref(props.state), pinnedState = ref(props.state), applied = ref({ q: '', team: '', ownership: '' }), query = ref(''), team = ref(''), ownership = ref(''), offset = ref(0), previous = ref<number[]>([])
const selected = ref<Row | null>(null), contexts = ref<Context[]>([]), contextId = ref(''), contextNext = ref<number | null>(null), contextTotal = ref<number | null>(null)
let sequence = 0, contextSequence = 0
const endpoint = () => `/projects/${encodeURIComponent(props.project)}/states/${pinnedState.value}`
const readonly = computed(() => data.value && data.value.state !== data.value.head)
const teamName = (id: string) => data.value?.teams.find(value => value.id === id)?.name || id
const human = (value: string) => value.replaceAll('_', ' ')
const message = (value: unknown) => value instanceof Error ? value.message : 'Component inventory request failed'
async function load(target = 0) {
  if (props.disabled || locked.value || busy.value || !/^[a-f0-9]{64}$/.test(pinnedState.value)) return
  const current = ++sequence; ++contextSequence; busy.value = true; error.value = ''; data.value = null; selected.value = null; contexts.value = []; contextTotal.value = null; contextBusy.value = false
  try {
    const params = new URLSearchParams({ q: applied.value.q, offset: String(target), limit: '25' })
    if (applied.value.team) params.set('team_id', applied.value.team)
    if (applied.value.ownership) params.set('ownership', applied.value.ownership)
    const result = await knowledgeApi<Page>(`${endpoint()}/components?${params}`)
    if (current !== sequence) return
    data.value = result; offset.value = target
  } catch (value) { if (current === sequence) error.value = message(value) }
  finally { if (current === sequence) busy.value = false }
}
async function page(forward: boolean) {
  const target = forward ? data.value?.next_offset : previous.value.at(-1)
  if (target === undefined || target === null || locked.value || busy.value || props.disabled) return
  const old = offset.value; await load(target)
  if (offset.value === target) { if (forward) previous.value.push(old); else previous.value.pop() }
}
function applyFilters() { if (!props.disabled && !locked.value && !busy.value) { applied.value = { q: query.value, team: team.value, ownership: ownership.value }; previous.value = []; void load() } }
function loadPinned() { if (props.disabled || locked.value || busy.value || !/^[a-f0-9]{64}$/.test(selectedState.value)) return; pinnedState.value = selectedState.value; applyFilters() }
async function choose(row: Row, append = false) {
  if (props.disabled || locked.value || busy.value || contextBusy.value) return
  const current = ++contextSequence, scope = sequence
  if (!append) { selected.value = row; contexts.value = []; contextId.value = ''; contextNext.value = null; contextTotal.value = null }
  contextBusy.value = true; error.value = ''
  try {
    const params = new URLSearchParams({ component_ref: row.component_ref, offset: String(append ? contextNext.value || 0 : 0), limit: '50' })
    const result = await knowledgeApi<{ items: Context[]; total: number; next_offset: number | null }>(`/projects/${encodeURIComponent(props.project)}/states/${data.value!.state}/components/contexts?${params}`)
    if (current !== contextSequence || scope !== sequence) return
    contexts.value = append ? [...contexts.value, ...result.items] : result.items; contextNext.value = result.next_offset; contextTotal.value = result.total
  } catch (value) { if (current === contextSequence && scope === sequence) error.value = message(value) }
  finally { if (current === contextSequence && scope === sequence) contextBusy.value = false }
}
function setLocked(value: boolean) { locked.value = value; emit('locked', value) }
function changed() { emit('changed') }
function useCurrent() { if (props.disabled || locked.value || busy.value) return; selectedState.value = props.state; pinnedState.value = props.state; applyFilters() }
function toggle(event: Event) { expanded.value = (event.currentTarget as HTMLDetailsElement).open; if (expanded.value && !data.value) void load() }
watch(() => [props.project, props.state], () => { if (locked.value) return; ++sequence; ++contextSequence; busy.value = false; contextBusy.value = false; data.value = null; selected.value = null; contexts.value = []; selectedState.value = props.state; pinnedState.value = props.state; previous.value = []; offset.value = 0; error.value = ''; if (expanded.value) void load() })
onBeforeUnmount(() => { ++sequence; ++contextSequence })
</script>
<template>
  <details class="component-inventory" @toggle="toggle"><summary>Component inventory</summary>
    <p class="hint">All imported component occurrences, including packages without vulnerability observations. No finding does not mean cleared.</p>
    <form aria-label="Search component inventory" @submit.prevent="applyFilters"><fieldset :disabled="busy || locked || disabled"><div class="inventory-filters"><label>Find component<input v-model="query" type="search" maxlength="500" placeholder="Name, namespace, version, PURL or reference"></label><label>Component team<select v-model="team"><option value="">All component teams</option><option v-for="item in data?.teams || []" :key="item.id" :value="item.id">{{ item.name }}</option></select></label><label>Ownership evidence<select v-model="ownership"><option value="">All ownership states</option><option v-for="value in ['resolved', 'delegated', 'unassigned', 'conflict', 'topology_unknown', 'no_context']" :key="value" :value="value">{{ human(value) }}</option></select></label></div><button>Search components</button></fieldset></form>
    <details><summary>Pinned inventory state</summary><label>Inventory state SHA<input v-model="selectedState" maxlength="64" pattern="[a-f0-9]{64}" :disabled="busy || locked || disabled"></label><button :disabled="busy || locked || disabled" @click="loadPinned">Load pinned inventory state</button><button :disabled="busy || locked || disabled" @click="useCurrent">Use workspace state</button><p class="hint">Paste a committed product state from version history to browse an earlier inventory. Loading never changes a source or branch.</p></details>
    <p v-if="busy" role="status">Loading component inventory…</p><p v-if="error" role="alert">{{ error }}</p>
    <template v-if="data"><p role="status">{{ data.statistics.component_occurrences }} component occurrences · {{ data.statistics.consuming_contexts }} consuming contexts · {{ data.statistics.all_component_occurrences }} occurrences before filters.</p><p>{{ data.version }} · <code>{{ data.state }}</code><span v-if="readonly"> · Historical inventory, read only</span></p>
      <div class="inventory-table"><table><thead><tr><th>Component occurrence</th><th>Ownership / contexts</th><th>Declared edges</th></tr></thead><tbody><tr v-for="row in data.items" :key="row.component_ref"><td><button :disabled="busy || locked || contextBusy || disabled" @click="choose(row)">{{ row.component.name || row.component_ref }}<span v-if="row.component.version"> @ {{ row.component.version }}</span></button><small v-if="row.component.group">{{ row.component.group }}</small><small>{{ row.component.purl || row.component_ref }}</small></td><td>{{ row.team_ids.map(teamName).join(', ') || 'No resolved team' }}<small>{{ row.ownership_statuses.map(human).join(', ') }} · {{ row.context_count }} contexts<span v-if="row.delegated_contexts"> · {{ row.delegated_contexts }} delegated</span></small></td><td>{{ row.incoming_declared }} incoming / {{ row.outgoing_declared }} outgoing<small>Observed edges only</small></td></tr></tbody></table></div><p v-if="!data.items.length">No components match this pinned inventory scope.</p>
      <nav aria-label="Component inventory pages"><button :disabled="busy || locked || !previous.length" @click="page(false)">Previous components</button><button :disabled="busy || locked || data.next_offset === null" @click="page(true)">Next components</button></nav>
      <section v-if="selected" aria-label="Selected inventory component"><h3>{{ selected.component.name || selected.component_ref }}</h3><p>{{ selected.component_ref }} · {{ contextTotal ?? selected.context_count }} consuming contexts</p><label>Consuming component context<select v-model="contextId" :disabled="contextBusy || locked"><option value="">Component occurrence (no consuming context selected)</option><option v-for="context in contexts" :key="context.id" :value="context.id">{{ context.root_ref }} · {{ context.team_id ? teamName(context.team_id) : human(context.status) }}{{ context.delegated ? ' · delegated' : '' }}</option></select></label><button v-if="contextNext !== null" :disabled="contextBusy || locked" @click="choose(selected, true)">More consuming contexts</button><p v-if="contextTotal === 0 && !contextBusy" class="hint">No resolved consuming contexts are recorded; this does not establish non-use.</p>
        <KnowledgeComponentMetadata :key="`${data.state}:${selected.component_ref}:${contextId}`" :project="project" :state="data.state" :version="data.version" :component-ref="selected.component_ref" :context-id="contextId || undefined" :disabled="disabled" @locked="setLocked" @changed="changed" @refresh="changed" />
      </section><details><summary>Inventory coverage limits</summary><ul><li v-for="value in data.limitations" :key="value">{{ value }}</li></ul></details>
    </template>
  </details>
</template>
<style scoped>
.component-inventory summary{cursor:pointer;font-weight:600}.component-inventory fieldset{border:0;padding:0;min-width:0}.inventory-filters{display:grid;grid-template-columns:2fr 1fr 1fr;gap:.7rem}.component-inventory label{display:grid;gap:.3rem}.component-inventory input,.component-inventory select{max-width:100%;box-sizing:border-box}.component-inventory button{margin-block:.3rem}.inventory-table{overflow:auto}.inventory-table table{width:100%;border-collapse:collapse}.inventory-table th,.inventory-table td{text-align:left;vertical-align:top;padding:.5rem;border-bottom:1px solid var(--line)}.inventory-table small{display:block;overflow-wrap:anywhere}.component-inventory code{overflow-wrap:anywhere}.component-inventory section{border-top:1px solid var(--line);margin-top:.8rem;padding-top:.6rem}.component-inventory nav{display:flex;gap:.5rem}@media(max-width:650px){.inventory-filters{grid-template-columns:1fr}}
</style>
