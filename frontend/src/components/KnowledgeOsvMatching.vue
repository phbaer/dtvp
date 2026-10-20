<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { API_PREFIX } from '../apiContract'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import { send } from '../api'
type Plan = { expected_versions: Record<string, string>; expected_evidence: string | null; enabled: boolean; next_revision: number; purls: string[]; total: number; next_offset: number | null; coverage: { eligible_purls: number; eligible_occurrences: number; unsupported_occurrences: Record<string, number>; unqueried_coverage: string }; selection_digest: string; capabilities: string[]; limitations: string[] }
type Job = { id: string; kind: string; status: string; purls: string[]; expected_versions: Record<string, string>; expected_evidence: string | null; revision: number; attempts: number; error: string; result: Record<string, unknown>; capabilities: string[] }
type Input = { request_id: string; expected_versions: Record<string, string>; expected_evidence: string | null; purls: string[]; revision: number }
type Capture = { endpoint: string; body: Input }
const emit = defineEmits<{ locked: [boolean] }>()
const props = defineProps<{ project: string; state: string; disabled?: boolean }>()
const opened = ref(false), busy = ref(false), error = ref(''), notice = ref(''), plan = ref<Plan | null>(null), selected = ref<string[]>([]), pending = ref<Capture | null>(null), recorded = ref(false)
const planOffset = ref(0), planPrevious = ref<number[]>([]), jobs = ref<Job[]>([]), recent = ref<Job | null>(null), jobsLoaded = ref(false), jobOffset = ref(0), jobNext = ref<number | null>(null), jobPrevious = ref<number[]>([])
const action = ref<{ endpoint: string; job: string; kind: string; scope: string } | null>(null)
let generation = 0
const root = () => `/projects/${encodeURIComponent(props.project)}`
const human = (value: string) => value.replaceAll('_', ' ')
const canQuery = computed(() => Boolean(plan.value?.enabled && plan.value.capabilities.includes('query')))
const stale = computed(() => Boolean(plan.value && !Object.values(plan.value.expected_versions).includes(props.state)))
const locked = computed(() => busy.value || Boolean(pending.value && !recorded.value) || Boolean(action.value))
watch(locked, value => emit('locked', value), { immediate: true, flush: 'sync' })
const jobScope = (job: Job) => JSON.stringify([job.kind, [...job.purls].sort(), Object.entries(job.expected_versions).sort(), job.expected_evidence, job.revision])
const shownJobs = computed(() => recent.value && !jobs.value.some(job => job.id === recent.value!.id) ? [recent.value, ...jobs.value] : jobs.value)
const message = (value: unknown) => value instanceof Error ? value.message : 'OSV matching request failed'
async function loadPlan(offset = 0, refresh = false) {
  if (busy.value || props.disabled || pending.value && refresh) return false
  const current = generation; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Plan>(`${root()}/osv-matching?offset=${offset}&limit=20`)
    if (current !== generation) return false
    if (!refresh && plan.value && data.selection_digest !== plan.value.selection_digest) throw new Error('OSV package plan changed. Prior selection and pins remain; refresh explicitly before preparing a new request.')
    if (refresh) { selected.value = []; planPrevious.value = [] }
    plan.value = data; planOffset.value = offset; return true
  } catch (value) { if (current === generation) error.value = message(value); return false }
  finally { if (current === generation) busy.value = false }
}
async function loadJobs(offset = jobOffset.value) {
  if (busy.value || props.disabled) return false
  const current = generation; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<{ items: Job[]; next_offset: number | null }>(`${root()}/osv-jobs?offset=${offset}&limit=20`)
    if (current !== generation) return false
    jobs.value = data.items; jobOffset.value = offset; jobNext.value = data.next_offset; jobsLoaded.value = true; return true
  } catch (value) { if (current === generation) error.value = message(value); return false }
  finally { if (current === generation) busy.value = false }
}
async function toggle(open: boolean) { opened.value = open; if (opened.value && !plan.value) { await loadPlan(); const prior = error.value; if (!jobsLoaded.value) await loadJobs(0); if (prior) error.value = prior } }
async function planPage(next: boolean) { const offset = next ? plan.value?.next_offset : planPrevious.value.at(-1); if (offset == null) return; const before = planOffset.value; if (await loadPlan(offset)) { if (next) planPrevious.value.push(before); else planPrevious.value.pop() } }
async function jobPage(next: boolean) { const offset = next ? jobNext.value : jobPrevious.value.at(-1); if (offset == null) return; const before = jobOffset.value; if (await loadJobs(offset)) { if (next) jobPrevious.value.push(before); else jobPrevious.value.pop() } }
function choose(purl: string) { if (pending.value || busy.value || props.disabled || !canQuery.value) return; if (selected.value.includes(purl)) selected.value = selected.value.filter(value => value !== purl); else if (selected.value.length < 20) selected.value.push(purl) }
function discard() { if (busy.value) return; ++generation; pending.value = null; recorded.value = false; action.value = null; selected.value = []; error.value = ''; notice.value = 'Capture discarded locally. This does not cancel an OSV job that may already have been recorded.' }
async function enqueue() {
  if (busy.value || props.disabled || action.value || recorded.value || !plan.value || (!pending.value && (!canQuery.value || !selected.value.length || stale.value))) return
  const current = generation; busy.value = true; error.value = ''; notice.value = ''
  try {
    if (!pending.value && (!Number.isSafeInteger(plan.value.next_revision) || plan.value.next_revision < 0)) throw new Error('OSV provider revision exceeds the supported safe integer range.')
    if (!pending.value) pending.value = { endpoint: `${root()}/osv-jobs`, body: { request_id: crypto.randomUUID(), expected_versions: { ...plan.value.expected_versions }, expected_evidence: plan.value.expected_evidence, revision: plan.value.next_revision, purls: [...selected.value].sort() } }
    const capture = pending.value
    const job = await knowledgeApi<Job>(capture.endpoint, send(capture.body))
    if (current !== generation) return
    if (!job.id || job.kind !== 'match-osv-native' || JSON.stringify([...job.purls].sort()) !== JSON.stringify(capture.body.purls) || JSON.stringify(Object.entries(job.expected_versions).sort()) !== JSON.stringify(Object.entries(capture.body.expected_versions).sort()) || job.expected_evidence !== capture.body.expected_evidence || job.revision !== capture.body.revision) throw new Error('Recorded job differs from the captured matching request.')
    recent.value = job; recorded.value = true; notice.value = 'OSV job recorded. Provider observations require separate human analysis; no assessment or approval was created.'
  } catch (value) { if (current === generation) error.value = `${message(value)} Exact package selection, heads, evidence, revision and request ID are retained.` }
  finally { if (current === generation) busy.value = false }
}
async function inspect(job: Job) {
  if (busy.value || props.disabled) return
  const current = generation; busy.value = true; error.value = ''
  try {
    const value = await knowledgeApi<Job>(`${root()}/osv-jobs/${encodeURIComponent(job.id)}`)
    if (current !== generation) return
    if (value.id !== job.id || value.kind !== 'match-osv-native' || jobScope(value) !== jobScope(job)) throw new Error('OSV status response differs from the requested job or its frozen scope.')
    jobs.value = jobs.value.map(row => row.id === value.id ? value : row); if (recent.value?.id === value.id) recent.value = value
  } catch (value) { if (current === generation) error.value = message(value) }
  finally { if (current === generation) busy.value = false }
}
async function mutate(job?: Job, kind?: string) {
  if (busy.value || props.disabled || pending.value && !recorded.value) return
  const current = generation; busy.value = true; error.value = ''
  try {
    if (!action.value) { if (!job || !kind || !job.capabilities.includes(kind)) return; action.value = { endpoint: `${root()}/osv-jobs/${encodeURIComponent(job.id)}/${kind}`, job: job.id, kind, scope: jobScope(job) } }
    const value = await knowledgeApi<Job>(action.value.endpoint, send({}))
    if (current !== generation) return
    if (value.id !== action.value.job || value.kind !== 'match-osv-native' || jobScope(value) !== action.value.scope) throw new Error('Job action response differs from the captured job.')
    jobs.value = jobs.value.map(row => row.id === value.id ? value : row); if (recent.value?.id === value.id) recent.value = value; action.value = null
  } catch (value) { if (current === generation) error.value = `${message(value)} Captured job action is retained; refresh status or retry it explicitly.` }
  finally { if (current === generation) busy.value = false }
}
function artifactLinks(job: Job) { return [...new Set([...(Array.isArray(job.result.raw_artifact_shas) ? job.result.raw_artifact_shas : []), job.result.progress_sha256, job.result.capture_sha256].filter((value): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)))] }
const download = (job: Job, sha: string) => `${API_PREFIX}${root()}/osv-jobs/${encodeURIComponent(job.id)}/artifacts/${sha}`
watch(() => props.state, () => { ++generation; busy.value = false; error.value = '' })
watch(() => props.project, () => { ++generation; busy.value = false; plan.value = null; pending.value = null; recorded.value = false; selected.value = []; jobs.value = []; recent.value = null; jobsLoaded.value = false; action.value = null; planPrevious.value = []; jobPrevious.value = []; planOffset.value = 0; jobOffset.value = 0; jobNext.value = null; error.value = ''; notice.value = ''; if (opened.value) void loadPlan() })
onBeforeUnmount(() => { ++generation; emit('locked', false) })
</script>
<template>
  <TaskSurface class="osv-matching" @active="toggle" title="External OSV package matching"><section aria-label="OSV package matching">
    <h3>Discover vulnerabilities</h3>
    <p class="hint">Explicit package/version queries to OSV. Results are provider claims, not applicability assessments or approvals. A no-match response does not prove absence or remediation.</p>
    <div><button :disabled="busy || disabled || !!pending" @click="loadPlan(0, true)">Refresh OSV package plan</button><button :disabled="busy || disabled" @click="loadJobs()">Refresh OSV jobs</button></div><p v-if="busy" role="status">Working…</p><p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <template v-if="plan"><p>{{ plan.enabled ? 'OSV provider enabled' : 'OSV provider disabled' }} · {{ plan.total }} eligible package versions · {{ selected.length }}/20 explicitly selected</p><p v-if="stale" role="status">Workspace state changed. Prior package selection and captured requests keep their pins. Refresh explicitly for a new operation.</p><p class="hint">Unsupported and unselected coverage remains unknown. A complete lookup covers only the explicitly queried coordinates.</p><fieldset :disabled="busy || disabled || !canQuery || !!pending"><label v-for="purl in plan.purls" :key="purl"><input type="checkbox" :checked="selected.includes(purl)" :disabled="!selected.includes(purl) && selected.length >= 20" @change="choose(purl)">{{ purl }}</label></fieldset><p v-if="selected.length" aria-label="Explicitly selected OSV packages">Selected: {{ selected.join(' · ') }}</p><nav><button :disabled="busy || disabled || !planPrevious.length" @click="planPage(false)">Previous OSV packages</button><button :disabled="busy || disabled || plan.next_offset === null" @click="planPage(true)">Next OSV packages</button></nav>
      <details><summary>OSV coverage limits and source pins</summary><p>{{ plan.coverage.eligible_occurrences }} eligible occurrences · {{ Math.max(0, plan.coverage.eligible_purls - selected.length) }} eligible package versions not selected in this plan</p><p v-for="(count, key) in plan.coverage.unsupported_occurrences" :key="key">{{ human(key) }}: {{ count }} · coverage unknown</p><pre>{{ JSON.stringify({ expected_versions: plan.expected_versions, expected_evidence: plan.expected_evidence, selection_digest: plan.selection_digest, next_revision: plan.next_revision }, null, 2) }}</pre><ul><li v-for="limit in plan.limitations" :key="limit">{{ limit }}</li></ul></details>
      <button v-if="!recorded && (canQuery || pending)" :disabled="busy || disabled || !!action || (!pending && (!selected.length || stale))" @click="enqueue">{{ pending ? 'Resend identical OSV request' : 'Queue selected OSV queries' }}</button><button v-if="pending" :disabled="busy || disabled" @click="discard">{{ recorded ? 'Prepare another OSV request' : 'Discard OSV request capture' }}</button><details v-if="pending"><summary>Frozen OSV matching request</summary><pre>{{ JSON.stringify(pending.body, null, 2) }}</pre></details>
    </template>
    <p v-if="jobsLoaded && !shownJobs.length">No recorded OSV jobs for this product.</p><section v-if="action" aria-label="Captured OSV job action"><p>{{ action.kind }} · job {{ action.job }} · unchanged across retries</p><button :disabled="busy || disabled" @click="mutate()">Resend captured OSV job action</button><button :disabled="busy || disabled" @click="action = null">Discard captured OSV job action</button></section>
    <article v-for="job in shownJobs" :key="job.id" :aria-label="`OSV job ${job.id}`"><strong>OSV · {{ human(job.status) }}</strong><p>{{ job.purls.join(' · ') }} · {{ job.attempts }} attempts</p><p v-if="job.error">{{ job.error }}</p><p v-if="job.result.completed_queries !== undefined">Completed query captures: {{ job.result.completed_queries }}/{{ job.result.selected_queries }}. Unqueried coverage remains unknown.</p><button :disabled="busy || disabled" @click="inspect(job)">Refresh OSV job status</button><button v-if="job.capabilities.includes('retry')" :disabled="busy || disabled || !!action || (!!pending && !recorded)" @click="mutate(job, 'retry')">Retry OSV job</button><button v-if="job.capabilities.includes('cancel')" :disabled="busy || disabled || !!action || (!!pending && !recorded)" @click="mutate(job, 'cancel')">Cancel OSV job</button><details><summary>OSV job pins, capture and source bytes</summary><pre>{{ JSON.stringify(job, null, 2) }}</pre><p v-for="sha in artifactLinks(job)" :key="sha"><a :href="download(job, sha)" download>Download captured OSV artifact {{ sha }}</a></p></details></article><nav v-if="jobsLoaded"><button :disabled="busy || disabled || !jobPrevious.length" @click="jobPage(false)">Previous OSV jobs</button><button :disabled="busy || disabled || jobNext === null" @click="jobPage(true)">Next OSV jobs</button></nav>
  </section></TaskSurface>
</template>
<style scoped>
.osv-matching { border-top:1px solid var(--line); margin-top:1rem; padding-top:.8rem; min-width:0 } section,article,fieldset { min-width:0; overflow-wrap:anywhere } fieldset { border:0; padding:0 } label { display:flex; align-items:flex-start; gap:.4rem; margin-block:.5rem } input[type=checkbox] { width:auto; margin-top:.2rem } button { margin:.3rem .5rem .3rem 0 } summary { cursor:pointer } pre { white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word; max-height:18rem; overflow:auto } article { border-top:1px solid var(--line); padding-block:.5rem }.hint { font-size:.85rem; color:var(--muted) }
</style>
