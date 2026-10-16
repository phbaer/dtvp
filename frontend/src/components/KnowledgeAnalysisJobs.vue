<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeAnalysisFollowUp from './KnowledgeAnalysisFollowUp.vue'

type AnalysisJob = { id: string; status: string; version: string; context_id: string; vulnerability_id: string; state: string; attempts: number; error: string; result: Record<string, unknown>; created_at: string; requires_explicit_reconciliation: boolean; capabilities: string[] }
type JobPage = { items: AnalysisJob[]; next_offset: number | null; capabilities: string[] }
const props = defineProps<{ project: string; state: string; version: string; contextId: string; vulnerabilityId: string; sourceReady: boolean }>()
const emit = defineEmits<{ locked: [boolean] }>()
const followUp = ref<InstanceType<typeof KnowledgeAnalysisFollowUp>>(), followUpLocked = ref(false)
const items = ref<AnalysisJob[]>([]), recent = ref<AnalysisJob | null>(null), capabilities = ref<string[]>([])
const loaded = ref(false), listBusy = ref(false), createBusy = ref(false), actionBusy = ref(''), guidance = ref(''), error = ref(''), createError = ref(''), notice = ref(''), requestRecorded = ref(false)
const reconcileRemote = ref<Record<string, string>>({}), reconcileConfirmed = ref<Record<string, boolean>>({}), reconcileCaptured = ref<Record<string, { request_id: string; remote_id: string }>>({})
const offset = ref(0), nextOffset = ref<number | null>(null), previous = ref<number[]>([])
let sequence = 0, listSequence = 0
let attempt: { signature: string; requestId: string } | null = null
const endpoint = () => `/projects/${encodeURIComponent(props.project)}`
const collection = () => `${endpoint()}/versions/${encodeURIComponent(props.version)}/analysis-jobs`
const visibleJobs = computed(() => recent.value && !items.value.some(item => item.id === recent.value!.id) ? [{ job: recent.value, recent: true }, ...items.value.map(job => ({ job, recent: false }))] : items.value.map(job => ({ job, recent: false })))
const label = (value: string) => value.replaceAll('_', ' ')
const message = (value: unknown) => value instanceof Error ? value.message : 'Analysis job request failed'
function reset() { reconcileRemote.value = {}; reconcileConfirmed.value = {}; reconcileCaptured.value = {}; ++sequence; ++listSequence; items.value = []; recent.value = null; capabilities.value = []; loaded.value = false; listBusy.value = false; createBusy.value = false; actionBusy.value = ''; guidance.value = ''; error.value = ''; createError.value = ''; notice.value = ''; requestRecorded.value = false; offset.value = 0; nextOffset.value = null; previous.value = []; attempt = null }
async function loadJobs(selectedOffset = offset.value) {
  if (createBusy.value || actionBusy.value) return false
  const scope = sequence, request = ++listSequence
  listBusy.value = true; error.value = ''
  try {
    const query = new URLSearchParams({ context_id: props.contextId, vulnerability_id: props.vulnerabilityId, offset: String(selectedOffset), limit: '20' })
    const result = await knowledgeApi<JobPage>(`${collection()}?${query}`)
    if (scope !== sequence || request !== listSequence) return false
    items.value = result.items; capabilities.value = result.capabilities; nextOffset.value = result.next_offset; offset.value = selectedOffset; loaded.value = true
    return true
  } catch (failure) { if (scope === sequence && request === listSequence) error.value = message(failure); return false }
  finally { if (scope === sequence && request === listSequence) listBusy.value = false }
}
async function page(forward: boolean) {
  if (listBusy.value) return
  const old = offset.value, target = forward ? nextOffset.value : previous.value.at(-1)
  if (target === null || target === undefined) return
  if (await loadJobs(target)) { if (forward) previous.value.push(old); else previous.value.pop() }
}
function update(job: AnalysisJob) { if (recent.value?.id === job.id) recent.value = job; items.value = items.value.map(item => item.id === job.id ? job : item) }
async function inspect(job: AnalysisJob, action?: 'retry' | 'cancel') {
  if (actionBusy.value || listBusy.value || createBusy.value) return
  const scope = sequence
  actionBusy.value = job.id; error.value = ''
  try {
    const result = await knowledgeApi<AnalysisJob>(`${endpoint()}/analysis-jobs/${encodeURIComponent(job.id)}${action ? '/' + action : ''}`, action ? send({}) : {})
    if (scope === sequence) update(result)
  } catch (failure) { if (scope === sequence) error.value = message(failure) }
  finally { if (scope === sequence) actionBusy.value = '' }
}
async function reconcile(job: AnalysisJob) {
  if (actionBusy.value || listBusy.value || createBusy.value || !job.capabilities.includes('reconcile')) return
  if (!reconcileCaptured.value[job.id]) {
    const remote = reconcileRemote.value[job.id]?.trim() || ''
    if (!reconcileConfirmed.value[job.id] || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,199}$/.test(remote)) return
    reconcileCaptured.value[job.id] = { request_id: crypto.randomUUID(), remote_id: remote }
  }
  const captured = reconcileCaptured.value[job.id]!, scope = sequence
  actionBusy.value = job.id; error.value = ''
  try {
    const result = await knowledgeApi<AnalysisJob>(`${endpoint()}/analysis-jobs/${encodeURIComponent(job.id)}/reconcile`, send(captured))
    if (scope !== sequence) return
    if (result.requires_explicit_reconciliation || !result.result.reconciliation_observation_sha256) throw new Error('No authenticated completed-job binding was accepted.')
    update(result); delete reconcileCaptured.value[job.id]
    notice.value = 'Completed remote job bound to the exact issued input. Its retained report is queued for evidence import; no analysis POST, assessment or approval was created.'
  } catch (failure) { if (scope === sequence) error.value = `${message(failure)} Exact remote ID and request ID are retained for safe verification retry.` }
  finally { if (scope === sequence) actionBusy.value = '' }
}
function discardReconcile(id: string) { if (actionBusy.value) return; delete reconcileCaptured.value[id]; reconcileConfirmed.value[id] = false; error.value = '' }
async function enqueue() {
  if (createBusy.value || listBusy.value || actionBusy.value || requestRecorded.value || !props.sourceReady || !capabilities.value.includes('submit')) return
  const body = { expected: props.state, context_id: props.contextId, vulnerability_id: props.vulnerabilityId, user_guidance: guidance.value.trim() }, signature = JSON.stringify(body)
  if (!attempt || attempt.signature !== signature) attempt = { signature, requestId: crypto.randomUUID() }
  const scope = sequence
  createBusy.value = true; createError.value = ''; notice.value = ''
  try {
    const result = await knowledgeApi<AnalysisJob>(collection(), send({ ...body, request_id: attempt.requestId }))
    if (scope !== sequence) return
    recent.value = result; requestRecorded.value = true
    notice.value = 'Analysis request recorded. Refresh job status to follow processing. No assessment or approval was created.'
  } catch (failure) { if (scope === sequence) createError.value = message(failure) }
  finally { if (scope === sequence) createBusy.value = false }
}
function newRequest() { requestRecorded.value = false; attempt = null; createError.value = ''; notice.value = '' }
watch(() => [props.project, props.state, props.version, props.contextId, props.vulnerabilityId], reset)
onBeforeUnmount(() => { ++sequence; ++listSequence; emit('locked', false) })
</script>

<template>
  <details class="analysis-jobs">
    <summary>Agentyzer analysis jobs</summary>
    <KnowledgeAnalysisFollowUp ref="followUp" :project="project" :state="state" :version="version" :disabled="createBusy || listBusy || !!actionBusy" @locked="followUpLocked = $event; emit('locked', $event)" @recorded="recent = $event as AnalysisJob" />
    <fieldset class="analysis-job-controls" :disabled="followUpLocked">
    <p class="hint">Jobs use this product version, consuming context and vulnerability. Status refreshes are read-only; work is queued only by an explicit request.</p>
    <button :disabled="listBusy || createBusy || Boolean(actionBusy)" @click="loadJobs()">{{ listBusy ? 'Loading jobs…' : loaded ? 'Refresh jobs' : 'Load analysis jobs' }}</button>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <form v-if="loaded && capabilities.includes('submit')" aria-label="Request Agentyzer analysis" @submit.prevent="enqueue">
      <p v-if="!sourceReady" class="hint">Prepare qualified Agentyzer source inputs above before requesting a new analysis.</p>
      <label>Analysis guidance (optional)<textarea v-model="guidance" maxlength="6000" rows="3" :disabled="createBusy || requestRecorded" /></label>
      <p v-if="createError" role="alert">{{ createError }}</p>
      <button v-if="!requestRecorded" :disabled="createBusy || listBusy || Boolean(actionBusy) || !sourceReady">{{ createBusy ? 'Recording request…' : 'Queue Agentyzer analysis' }}</button>
      <button v-else type="button" @click="newRequest">New analysis request</button>
    </form>
    <p v-if="loaded && !visibleJobs.length">No analysis jobs in this context and vulnerability scope.</p>
    <article v-for="entry in visibleJobs" :key="entry.job.id" :aria-label="`Analysis job ${entry.job.id}`">
      <small v-if="entry.recent">Requested job</small>
      <strong>{{ label(entry.job.status) }}</strong><small>{{ entry.job.created_at }} · {{ entry.job.attempts }} attempts</small>
      <p v-if="entry.job.requires_explicit_reconciliation" class="job-reconciliation">Submission outcome is unknown. This job needs explicit reconciliation; refreshing status does not resubmit it.</p>
      <form v-if="entry.job.capabilities.includes('reconcile')" :aria-label="`Reconcile analysis job ${entry.job.id}`" @submit.prevent="reconcile(entry.job)">
        <p class="hint">Explicit recovery uses the configured private authenticated endpoint. Only a completed job with the exact repository, executed commit and issued DTVP input binding can be attached. Missing proof stays unknown; no analysis is resubmitted.</p>
        <label>Completed remote job ID<input v-model="reconcileRemote[entry.job.id]" required maxlength="200" pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,199}" :readonly="!!reconcileCaptured[entry.job.id]" :disabled="Boolean(actionBusy) || listBusy || createBusy"></label>
        <label class="job-confirm"><input v-model="reconcileConfirmed[entry.job.id]" type="checkbox" required :disabled="Boolean(actionBusy) || !!reconcileCaptured[entry.job.id]"> I explicitly selected this completed remote job for the recorded request.</label>
        <button :disabled="Boolean(actionBusy) || listBusy || createBusy || (!reconcileCaptured[entry.job.id] && !reconcileConfirmed[entry.job.id])">{{ reconcileCaptured[entry.job.id] ? 'Retry exact remote verification' : 'Verify and reconcile completed job' }}</button><button v-if="reconcileCaptured[entry.job.id]" type="button" :disabled="Boolean(actionBusy)" @click="discardReconcile(entry.job.id)">Discard captured reconciliation</button>
      </form>
      <button v-if="entry.job.capabilities.includes('follow_up')" type="button" :disabled="Boolean(actionBusy) || listBusy || createBusy" @click="followUp?.start(entry.job)">Ask a bound follow-up</button>
      <p v-if="entry.job.error">{{ entry.job.error }}</p>
      <div class="job-actions"><button :disabled="Boolean(actionBusy) || listBusy || createBusy" @click="inspect(entry.job)">Refresh job status</button><button v-if="entry.job.capabilities.includes('retry') && !entry.job.requires_explicit_reconciliation" :disabled="Boolean(actionBusy) || listBusy || createBusy" @click="inspect(entry.job, 'retry')">Retry known job</button><button v-if="entry.job.capabilities.includes('cancel')" :disabled="Boolean(actionBusy) || listBusy || createBusy" @click="inspect(entry.job, 'cancel')">Cancel DTVP job</button></div>
      <p v-if="entry.job.capabilities.includes('cancel')" class="hint">Cancellation stops local processing; it does not confirm cancellation at Agentyzer.</p>
      <details><summary>Job input and result pins</summary><dl><dt>Job</dt><dd><code>{{ entry.job.id }}</code></dd><dt>Input state</dt><dd><code>{{ entry.job.state }}</code></dd><dt>Product version</dt><dd>{{ entry.job.version }}</dd><dt>Context</dt><dd><code>{{ entry.job.context_id }}</code></dd><dt>Vulnerability</dt><dd>{{ entry.job.vulnerability_id }}</dd></dl><pre>{{ JSON.stringify(entry.job.result, null, 2) }}</pre></details>
    </article>
    <nav v-if="loaded" class="job-actions" aria-label="Analysis job pages"><button :disabled="listBusy || createBusy || Boolean(actionBusy) || !previous.length" @click="page(false)">Previous jobs</button><button :disabled="listBusy || createBusy || Boolean(actionBusy) || nextOffset === null" @click="page(true)">Next jobs</button></nav>
    </fieldset>
  </details>
</template>

<style scoped>
.analysis-job-controls { border: 0; padding: 0; min-width: 0; }
.analysis-jobs { margin-top: .8rem; min-width: 0; }
summary { cursor: pointer; overflow-wrap: anywhere; }
form { margin-block: .75rem; }
label { display: grid; gap: .3rem; }
input,textarea { box-sizing: border-box; width: 100%; min-width: 0; resize: vertical; }
.job-confirm { display:flex; align-items:start; gap:.4rem; margin-block:.6rem }.job-confirm input { width:auto }
article { border-top: 1px solid var(--border, #64748b33); padding-block: .65rem; }
strong, small { display: block; overflow-wrap: anywhere; }
small { opacity: .75; }
.job-actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-block: .5rem; }
dl { display: grid; grid-template-columns: minmax(5rem, 1fr) minmax(0, 2fr); gap: .3rem; }
dd { margin: 0; overflow-wrap: anywhere; }
code, pre { font-size: .8rem; white-space: pre-wrap; overflow-wrap: anywhere; }
pre { max-height: 20rem; overflow: auto; }
@media (max-width: 650px) { dl { grid-template-columns: minmax(0, 1fr); } }
</style>
