<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi } from '../knowledgeApi'

type Binding = { project_id: string | null; configured: boolean; capabilities: string[] }
type SourceJob = { id: string; status: string; version: string; expected: string; external_project_id: string; build_number: number; attempts: number; created_at: string; error: string; result: Record<string, unknown>; capabilities: string[] }
type JobPage = { items: SourceJob[]; next_offset: number | null }
const props = defineProps<{ project: string; version: string; state: string }>()
const expanded = ref(false), busy = ref(false), loaded = ref(false), binding = ref<Binding | null>(null)
const bindingError = ref(''), listError = ref(''), importError = ref(''), notice = ref('')
const externalProject = ref(''), bindingDirty = ref(false), buildNumber = ref(''), observedAt = ref(''), recorded = ref(false)
const items = ref<SourceJob[]>([]), recent = ref<SourceJob | null>(null), offset = ref(0), nextOffset = ref<number | null>(null), previous = ref<number[]>([])
let sequence = 0, pending: { signature: string; requestId: string } | null = null
const endpoint = () => `/projects/${encodeURIComponent(props.project)}`
const versionEndpoint = () => `${endpoint()}/versions/${encodeURIComponent(props.version)}`
const visibleJobs = computed(() => recent.value && !items.value.some(item => item.id === recent.value!.id) ? [{ job: recent.value, recent: true }, ...items.value.map(job => ({ job, recent: false }))] : items.value.map(job => ({ job, recent: false })))
const label = (value: string) => value.replaceAll('_', ' ')
const message = (value: unknown) => value instanceof Error ? value.message : 'Source request failed'
const can = (action: string) => Boolean(binding.value?.capabilities.includes(action))
async function load(selectedOffset = offset.value, refreshBinding = true) {
  if (busy.value) return false
  const current = sequence
  busy.value = true; bindingError.value = ''; listError.value = ''
  try {
    const [configuration, jobs] = await Promise.allSettled([
      refreshBinding ? knowledgeApi<Binding>(`${versionEndpoint()}/connectors/dependency-track`) : Promise.resolve(binding.value),
      knowledgeApi<JobPage>(`${versionEndpoint()}/source-jobs?${new URLSearchParams({ offset: String(selectedOffset), limit: '20' })}`),
    ])
    if (current !== sequence) return false
    if (configuration.status === 'fulfilled' && configuration.value) { binding.value = configuration.value; if (!bindingDirty.value) externalProject.value = configuration.value.project_id || '' }
    else if (configuration.status === 'rejected') bindingError.value = message(configuration.reason)
    if (jobs.status === 'fulfilled') { items.value = jobs.value.items; nextOffset.value = jobs.value.next_offset; offset.value = selectedOffset; loaded.value = true; return true }
    listError.value = message(jobs.reason)
    return false
  } finally { if (current === sequence) busy.value = false }
}
function toggle(open: boolean) { expanded.value = open; if (expanded.value && !loaded.value) void load() }
async function page(forward: boolean) {
  const target = forward ? nextOffset.value : previous.value.at(-1), old = offset.value
  if (target === null || target === undefined) return
  if (await load(target, false)) { if (forward) previous.value.push(old); else previous.value.pop() }
}
async function bind() {
  if (busy.value || !binding.value || !can('bind')) return
  const current = sequence
  busy.value = true; bindingError.value = ''; notice.value = ''
  try {
    const result = await knowledgeApi<{ project_id: string }>(`${versionEndpoint()}/connectors/dependency-track`, { ...send({ external_project_id: externalProject.value.trim(), expected_external_project_id: binding.value.project_id }), method: 'PUT' })
    if (current !== sequence) return
    binding.value = { ...binding.value, ...result }; externalProject.value = result.project_id; bindingDirty.value = false
    notice.value = 'DT project binding saved in DTVP. No source data was imported.'
  } catch (error) { if (current === sequence) bindingError.value = message(error) }
  finally { if (current === sequence) busy.value = false }
}
async function enqueue() {
  if (busy.value || recorded.value || !binding.value?.configured || !binding.value.project_id || !can('import')) return
  const current = sequence
  busy.value = true; importError.value = ''; notice.value = ''
  try {
    const number = Number(buildNumber.value), time = observedAt.value.trim()
    if (!/^\d+$/.test(buildNumber.value) || !Number.isSafeInteger(number)) throw new Error('Build number must be a nonnegative integer within the browser safe integer range.')
    if (!/(?:Z|[+-]\d{2}:\d{2})$/i.test(time) || !Number.isFinite(Date.parse(time))) throw new Error('Observed time requires an ISO 8601 timestamp with an explicit timezone.')
    const body = { expected: props.state, build_number: number, occurred_at: time }, signature = JSON.stringify({ external_project_id: binding.value.project_id, ...body })
    if (pending?.signature !== signature) pending = { signature, requestId: crypto.randomUUID() }
    const result = await knowledgeApi<SourceJob>(`${versionEndpoint()}/imports/dependency-track/jobs`, send({ ...body, request_id: pending.requestId }))
    if (current !== sequence) return
    recent.value = result; recorded.value = true
    notice.value = 'DT import request recorded. Refresh job status to follow collection and publication; refresh the workspace explicitly after success.'
  } catch (error) { if (current === sequence) importError.value = message(error) }
  finally { if (current === sequence) busy.value = false }
}
async function inspect(job: SourceJob, action?: 'retry' | 'cancel') {
  if (busy.value) return
  const current = sequence
  busy.value = true; listError.value = ''
  try {
    const result = await knowledgeApi<SourceJob>(`${endpoint()}/source-jobs/${encodeURIComponent(job.id)}${action ? '/' + action : ''}`, action ? send({}) : {})
    if (current !== sequence) return
    if (recent.value?.id === result.id) recent.value = result
    items.value = items.value.map(item => item.id === result.id ? result : item)
  } catch (error) { if (current === sequence) listError.value = message(error) }
  finally { if (current === sequence) busy.value = false }
}
function newRequest() { recorded.value = false; pending = null; importError.value = ''; notice.value = '' }
watch(() => [props.project, props.version, props.state], () => {
  ++sequence; binding.value = null; items.value = []; recent.value = null; loaded.value = false; busy.value = false
  bindingError.value = ''; listError.value = ''; importError.value = ''; notice.value = ''; externalProject.value = ''; bindingDirty.value = false; buildNumber.value = ''; observedAt.value = ''; recorded.value = false; pending = null; offset.value = 0; nextOffset.value = null; previous.value = []
  if (expanded.value) void load()
})
onBeforeUnmount(() => { ++sequence })
</script>

<template>
  <TaskSurface class="knowledge-sources" @active="toggle" title="Dependency-Track source imports">
    <section aria-label="Dependency-Track source imports">
      <p class="hint">Import into the selected existing version: {{ version }}. Its accepted source authority cannot be switched here. New versions and assembly parts use CLI/API intake; a source change requires a separate explicit authority policy. DTVP reads DT without automatic writeback.</p>
      <button :disabled="busy" @click="load()">{{ busy ? 'Working…' : 'Refresh source configuration and jobs' }}</button>
      <p v-if="bindingError" role="alert">{{ bindingError }}</p><p v-if="listError" role="alert">{{ listError }}</p><p v-if="notice" role="status">{{ notice }}</p>
      <template v-if="binding">
        <dl><dt>DT project binding</dt><dd><code>{{ binding.project_id || 'Not bound' }}</code></dd><dt>Deployment connection</dt><dd>{{ binding.configured ? 'Configured' : 'Not configured' }}</dd><dt>Expected input state</dt><dd><code>{{ state }}</code></dd></dl>
        <p v-if="!binding.configured" class="hint">The deployment DT URL and read-only API key must be configured before collection. Their values are not exposed here.</p>
        <details v-if="can('bind')"><summary>Edit version-specific DT binding</summary><form aria-label="DT project binding" @submit.prevent="bind"><label>External DT project UUID<input v-model="externalProject" required maxlength="36" pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" :disabled="busy" @input="bindingDirty = true" /></label><p class="hint">Saving a binding does not change an existing baseline's source authority or import data.</p><button :disabled="busy || !externalProject.trim()">Save DT binding</button></form></details>
        <form v-if="can('import')" aria-label="Request DT source import" @submit.prevent="enqueue">
          <label>Source build number<input v-model="buildNumber" inputmode="numeric" required pattern="[0-9]+" :disabled="busy || recorded" /></label>
          <label>Observed at (ISO 8601 with timezone)<input v-model="observedAt" required maxlength="100" placeholder="2026-10-15T12:00:00Z" :disabled="busy || recorded" /></label>
          <p v-if="importError" role="alert">{{ importError }}</p>
          <button v-if="!recorded" :disabled="busy || !binding.configured || !binding.project_id || !buildNumber || !observedAt.trim()">Queue DT import</button><button v-else type="button" @click="newRequest">New DT import request</button>
        </form>
      </template>
      <p class="hint">Captured DT responses are retained. Collection uses separate reads and does not guarantee one consistent remote snapshot. Retrying uses retained captures when available.</p>
      <p v-if="loaded && !visibleJobs.length">No DT import jobs for this product version.</p>
      <article v-for="entry in visibleJobs" :key="entry.job.id" :aria-label="`DT import job ${entry.job.id}`"><small v-if="entry.recent">Requested import</small><strong>{{ label(entry.job.status) }} · build {{ entry.job.build_number }}</strong><small>{{ entry.job.created_at }} · {{ entry.job.attempts }} attempts</small><p v-if="entry.job.error">{{ entry.job.error }}</p><p v-if="entry.job.result.capture_sha256">Captured responses retained; no remote snapshot consistency is established.</p><div class="source-actions"><button :disabled="busy" @click="inspect(entry.job)">Refresh import status</button><button v-if="entry.job.capabilities.includes('retry')" :disabled="busy" @click="inspect(entry.job, 'retry')">Retry DT import</button><button v-if="entry.job.capabilities.includes('cancel')" :disabled="busy" @click="inspect(entry.job, 'cancel')">Cancel DTVP import job</button></div><details><summary>Source job pins and capture receipts</summary><dl><dt>External project</dt><dd><code>{{ entry.job.external_project_id }}</code></dd><dt>Expected state</dt><dd><code>{{ entry.job.expected }}</code></dd><dt>Job</dt><dd><code>{{ entry.job.id }}</code></dd></dl><pre>{{ JSON.stringify(entry.job.result, null, 2) }}</pre></details></article>
      <nav v-if="loaded" class="source-actions" aria-label="DT import job pages"><button :disabled="busy || !previous.length" @click="page(false)">Previous source jobs</button><button :disabled="busy || nextOffset === null" @click="page(true)">Next source jobs</button></nav>
    </section>
  </TaskSurface>
</template>

<style scoped>
.knowledge-sources { margin-block: .75rem; padding: .7rem .9rem; border: 1px solid var(--border, #64748b55); border-radius: .65rem; min-width: 0; }
summary { cursor: pointer; overflow-wrap: anywhere; }
section { padding-top: .6rem; }
form { display: grid; gap: .5rem; max-width: 44rem; margin-block: .7rem; }
label { display: grid; gap: .25rem; min-width: 0; }
input { box-sizing: border-box; width: 100%; min-width: 0; }
dl { display: grid; grid-template-columns: minmax(6rem, 1fr) minmax(0, 2fr); gap: .35rem; }
dd { margin: 0; overflow-wrap: anywhere; }
code, pre { font-size: .8rem; white-space: pre-wrap; overflow-wrap: anywhere; }
pre { max-height: 20rem; overflow: auto; }
article { padding-block: .7rem; border-top: 1px solid var(--border, #64748b33); }
strong, small { display: block; }
small { opacity: .75; }
.source-actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-block: .5rem; }
@media (max-width: 650px) { dl { grid-template-columns: minmax(0, 1fr); } }
</style>
