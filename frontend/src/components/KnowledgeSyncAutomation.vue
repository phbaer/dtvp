<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeConfigurationEditor from './KnowledgeConfigurationEditor.vue'
type Job = { id: string; kind: string; status: string; stale: boolean; inputs: { source: string; target: string; relationship: { relationship_id: string } }; capabilities: string[]; error: string; result: Record<string, unknown> }
type Page = { items: Job[]; next_offset: number | null }
type Proposal = { job_id: string; source: string; target: string; stale: boolean; preview_digest: string; total: number; next_offset: number | null; items: { id: string; vulnerability_id?: string; category: string; reasons: string[] }[] }
const props = defineProps<{ project: string; actor: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [boolean]; refresh: [] }>()
const configurationLocked = ref(false), busy = ref(false), loaded = ref(false), error = ref(''), page = ref<Page | null>(null), selected = ref<Job | null>(null), proposal = ref<Proposal | null>(null)
const pending = ref<{ endpoint: string; action: string; id: string } | null>(null)
let generation = 0
const locked = computed(() => configurationLocked.value || busy.value || !!pending.value)
watch(locked, value => emit('locked', value), { immediate: true })
const blocked = computed(() => busy.value || configurationLocked.value || props.disabled)
const path = () => `/projects/${encodeURIComponent(props.project)}/synchronization-jobs`
function reset() { ++generation; busy.value = false; loaded.value = false; page.value = null; selected.value = null; proposal.value = null; pending.value = null; error.value = ''; configurationLocked.value = false }
watch(() => [props.project, props.actor], reset)
async function load(offset = 0) {
  if (blocked.value || pending.value) return
  const current = ++generation; busy.value = true; error.value = ''
  try {
    const value = await knowledgeApi<Page>(`${path()}?offset=${offset}&limit=20`)
    if (current !== generation) return
    if (!Array.isArray(value.items) || value.items.some(row => row.kind !== 'propose-sync-native')) throw new Error('Unexpected synchronization job response.')
    page.value = value; loaded.value = true
  } catch (err) { if (current === generation) error.value = err instanceof Error ? err.message : 'Jobs unavailable' }
  finally { if (current === generation) busy.value = false }
}
function toggle(event: Event) { if ((event.target as HTMLDetailsElement).open && !loaded.value) void load() }
async function inspect(job: Job, offset = 0) {
  if (blocked.value || pending.value) return
  const current = ++generation; busy.value = true; error.value = ''
  if (selected.value?.id !== job.id) proposal.value = null
  selected.value = job
  try {
    const value = await knowledgeApi<Proposal>(`${path()}/${encodeURIComponent(job.id)}/proposal?offset=${offset}&limit=20`)
    if (current !== generation) return
    if (value.job_id !== job.id || value.source !== job.inputs.source || value.target !== job.inputs.target || (offset && value.preview_digest !== proposal.value?.preview_digest)) throw new Error('Proposal response changed its captured job or state pins.')
    proposal.value = value
  } catch (err) { if (current === generation) error.value = err instanceof Error ? err.message : 'Proposal unavailable' }
  finally { if (current === generation) busy.value = false }
}
async function action(job: Job, name: string) {
  if (blocked.value || !job.capabilities.includes(name) || (pending.value && (pending.value.id !== job.id || pending.value.action !== name))) return
  if (!pending.value) pending.value = { endpoint: `${path()}/${encodeURIComponent(job.id)}/${name}`, action: name, id: job.id }
  const captured = pending.value, current = ++generation; busy.value = true; error.value = ''
  try {
    const value = await knowledgeApi<Job>(captured.endpoint, { method: 'POST' })
    if (current !== generation) return
    if (value.id !== captured.id || value.kind !== 'propose-sync-native' || value.inputs.source !== job.inputs.source || value.inputs.target !== job.inputs.target) throw new Error('Action response does not match the captured job.')
    pending.value = null; selected.value = value; proposal.value = null
    if (page.value) page.value.items = page.value.items.map(row => row.id === value.id ? value : row)
  } catch (err) { if (current === generation) error.value = `${err instanceof Error ? err.message : 'Action uncertain'}. Captured action retained; retry identically or discard explicitly.` }
  finally { if (current === generation) busy.value = false }
}
function discard() { if (!busy.value) { pending.value = null; error.value = '' } }
onBeforeUnmount(() => { ++generation; emit('locked', false) })
</script>
<template>
  <section aria-label="Automatic synchronization">
    <KnowledgeConfigurationEditor :project="project" :actor="actor" kind="synchronization" :disabled="busy || !!pending || disabled" @locked="configurationLocked = $event" @refresh="emit('refresh')" />
    <details @toggle="toggle"><summary>Automatic synchronization proposals</summary>
      <p class="hint">Read-only proposals retain exact inputs. New target coverage always needs explicit adoption and independent review.</p>
      <p v-if="error" role="alert">{{ error }}</p>
      <button :disabled="blocked || !!pending" @click="load()">Refresh synchronization jobs</button>
      <p v-if="loaded && !page?.items.length">No automatic proposals captured yet.</p>
      <ul><li v-for="job in page?.items || []" :key="job.id">
        <span>{{ job.inputs.relationship.relationship_id }} · {{ job.status }} · {{ job.stale ? 'stale inputs' : 'current inputs' }}</span>
        <button v-if="job.status === 'succeeded'" :disabled="blocked || !!pending" @click="inspect(job)">Inspect proposal {{ job.id }}</button>
        <button v-for="name in job.capabilities" :key="name" :disabled="blocked || (!!pending && (pending.id !== job.id || pending.action !== name))" @click="action(job, name)">{{ pending?.id === job.id && pending.action === name ? 'Retry captured action' : name }} {{ job.id }}</button>
        <p v-if="job.error">{{ job.error }}</p>
      </li></ul>
      <button v-if="page?.next_offset !== null && page?.next_offset !== undefined" :disabled="blocked || !!pending" @click="load(page.next_offset)">Next synchronization jobs</button>
      <button v-if="pending" :disabled="busy" @click="discard">Discard captured synchronization action</button>
      <section v-if="proposal && selected" aria-label="Frozen automatic proposal">
        <p>{{ proposal.total }} items · {{ proposal.stale ? 'stale inputs' : 'current inputs' }}</p>
        <details><summary>Exact proposal pins</summary><p>Source: <code>{{ proposal.source }}</code></p><p>Target: <code>{{ proposal.target }}</code></p><p>Digest: <code>{{ proposal.preview_digest }}</code></p></details>
        <ul><li v-for="item in proposal.items" :key="item.id">{{ item.vulnerability_id || 'Unknown scope' }} · {{ item.category }}<p>{{ item.reasons.join('; ') }}</p></li></ul>
        <button v-if="proposal.next_offset !== null" :disabled="blocked || !!pending" @click="inspect(selected, proposal.next_offset)">Next automatic proposal items</button>
      </section>
    </details>
  </section>
</template>
<style scoped>
section{min-width:0}summary{cursor:pointer}button{margin:.4rem .5rem .4rem 0}li{margin-block:.65rem}code{overflow-wrap:anywhere}.hint{font-size:.875rem;opacity:.8}
</style>
