<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeOsvMatching from './KnowledgeOsvMatching.vue'
import KnowledgeIntelligenceComparison from './KnowledgeIntelligenceComparison.vue'
type Provider = { id: string; publisher: string; enabled: boolean; next_revision: number; identifier_formats?: string[] }
type Plan = { expected_versions: Record<string, string>; expected_evidence: string | null; providers: Provider[]; identifiers: string[]; total: number; unsupported_total?: number; selected_provider?: string | null; next_offset: number | null; capabilities: string[]; limitations: string[] }
type Job = { id: string; status: string; provider: string; identifiers: string[]; expected_versions: Record<string, string>; expected_evidence: string | null; revision: number; attempts: number; error: string; result: Record<string, unknown>; capabilities: string[] }
type Page = { items: Job[]; next_offset: number | null }
type Input = { request_id: string; provider: string; identifiers: string[]; expected_versions: Record<string, string>; expected_evidence: string | null; revision: number }
const emit = defineEmits<{ locked: [boolean] }>()
const childLocked = ref(false)
const props = defineProps<{ project: string; state: string }>()
const expanded = ref(false), busy = ref(false), plan = ref<Plan | null>(null), provider = ref(''), query = ref(''), identifiers = ref<string[]>([])
const error = ref(''), notice = ref(''), stale = ref(false), recorded = ref(false), pending = ref<Input | null>(null)
const offset = ref(0), previous = ref<number[]>([]), jobs = ref<Job[]>([]), recent = ref<Job | null>(null), jobOffset = ref(0), jobNext = ref<number | null>(null), jobPrevious = ref<number[]>([]), jobsLoaded = ref(false)
const ownLocked = computed(() => busy.value || Boolean(pending.value && !recorded.value))
watch(() => ownLocked.value || childLocked.value, value => emit('locked', value), { immediate: true, flush: 'sync' })
let sequence = 0
const root = () => `/projects/${encodeURIComponent(props.project)}`
const selectedProvider = computed(() => plan.value?.providers.find(item => item.id === provider.value))
const can = computed(() => plan.value?.capabilities.includes('refresh'))
const shownJobs = computed(() => recent.value && !jobs.value.some(item => item.id === recent.value!.id) ? [recent.value, ...jobs.value] : jobs.value)
const human = (value: string) => value.replaceAll('_', ' ')
const pin = (value: Plan) => JSON.stringify([Object.entries(value.expected_versions).sort(), value.expected_evidence, value.providers])
function fail(value: unknown) { error.value = value instanceof Error ? value.message : 'Advisory request failed' }
async function loadPlan(page = 0, refresh = false) {
  if (busy.value) return false
  const current = sequence; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Plan>(`${root()}/advisory-refresh?${new URLSearchParams({ q: query.value, offset: String(page), limit: '20', ...(provider.value ? { provider: provider.value } : {}) })}`)
    if (current !== sequence) return false
    if (!refresh && plan.value && pin(data) !== pin(plan.value)) throw new Error('Advisory plan changed. Refresh the plan explicitly; existing selection and pending request are retained.')
    if (refresh) { if (!pending.value) { identifiers.value = []; provider.value = '' }; previous.value = []; stale.value = false }
    plan.value = data; offset.value = page; return true
  } catch (err) { if (current === sequence) fail(err); return false }
  finally { if (current === sequence) busy.value = false }
}
async function loadJobs(page = jobOffset.value) {
  if (busy.value) return false
  const current = sequence; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Page>(`${root()}/advisory-jobs?offset=${page}&limit=20`)
    if (current !== sequence) return false
    jobs.value = data.items; jobNext.value = data.next_offset; jobOffset.value = page; jobsLoaded.value = true; return true
  } catch (err) { if (current === sequence) fail(err); return false }
  finally { if (current === sequence) busy.value = false }
}
async function toggle(event: Event) { expanded.value = (event.currentTarget as HTMLDetailsElement).open; if (expanded.value && !plan.value) { await loadPlan(); const planError = error.value; if (!jobsLoaded.value) await loadJobs(0); if (planError) error.value = planError } }
async function pageIdentifiers(next: boolean) {
  const page = next ? plan.value?.next_offset : previous.value.at(-1); if (page == null) return
  const old = offset.value; if (await loadPlan(page)) { if (next) previous.value.push(old); else previous.value.pop() }
}
async function pageJobs(next: boolean) {
  const page = next ? jobNext.value : jobPrevious.value.at(-1); if (page == null) return
  const old = jobOffset.value; if (await loadJobs(page)) { if (next) jobPrevious.value.push(old); else jobPrevious.value.pop() }
}
function select(identifier: string) {
  if (pending.value || busy.value) return
  if (identifiers.value.includes(identifier)) identifiers.value = identifiers.value.filter(item => item !== identifier)
  else if (identifiers.value.length < 20) identifiers.value.push(identifier)
}
async function enqueue() {
  if (busy.value || recorded.value || !can.value) return
  if (!pending.value) {
    if (!plan.value || !selectedProvider.value?.enabled || !identifiers.value.length || stale.value) return
    pending.value = { request_id: crypto.randomUUID(), provider: provider.value, identifiers: [...identifiers.value].sort(), expected_versions: { ...plan.value.expected_versions }, expected_evidence: plan.value.expected_evidence, revision: selectedProvider.value.next_revision }
  }
  const current = sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    const result = await knowledgeApi<Job>(`${root()}/advisory-jobs`, send(pending.value))
    if (current !== sequence) return
    recent.value = result; recorded.value = true; notice.value = 'Advisory refresh job recorded. Refresh status explicitly; publication never approves assessments or proves remediation.'
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function inspect(job: Job, action?: 'retry' | 'cancel') {
  if (busy.value) return
  const current = sequence; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<Job>(`${root()}/advisory-jobs/${encodeURIComponent(job.id)}${action ? '/' + action : ''}`, action ? send({}) : {})
    if (current !== sequence) return
    if (recent.value?.id === result.id) recent.value = result
    jobs.value = jobs.value.map(item => item.id === result.id ? result : item)
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
function newRequest() { pending.value = null; recorded.value = false; identifiers.value = []; provider.value = ''; error.value = ''; notice.value = ''; stale.value = true }
watch(provider, value => {
  if (!value || pending.value || !plan.value) return
  identifiers.value = []; previous.value = []
  void loadPlan(0)
})
watch(() => props.state, () => { stale.value = true })
watch(() => props.project, () => {
  ++sequence; busy.value = false; plan.value = null; pending.value = null; recorded.value = false; stale.value = false; identifiers.value = []; provider.value = ''; query.value = ''; jobs.value = []; recent.value = null; jobsLoaded.value = false; previous.value = []; jobPrevious.value = []; offset.value = 0; jobOffset.value = 0; error.value = ''; notice.value = ''
  if (expanded.value) void loadPlan().then(() => loadJobs(0))
})
onBeforeUnmount(() => { ++sequence; emit('locked', false) })
</script>
<template>
  <details class="knowledge-advisories" @toggle="toggle">
    <summary>Advisory intelligence refresh</summary>
    <section aria-label="Advisory intelligence refresh"><fieldset class="advisory-controls" :disabled="childLocked">
      <KnowledgeIntelligenceComparison :project="project" :state="state" />
      <p class="hint">Enrich exact vulnerability IDs already reported by product baselines. No package matching, new vulnerability discovery or assessment approval is implied.</p>
      <p class="hint">Provider and advisory publisher differ: mirrors are not independent corroboration. A provider not-found response never proves remediation. Cancel stops DTVP work; an in-flight remote lookup may finish.</p>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
      <p v-if="stale" class="hint">The workspace or request changed. Refresh the plan explicitly before starting a new request; pending requests keep their original pins.</p>
      <div class="actions"><button type="button" :disabled="busy" @click="loadPlan(0, true)">Refresh advisory plan</button><button type="button" :disabled="busy" @click="loadJobs()">Refresh advisory jobs</button></div>
      <template v-if="plan">
        <details><summary>Provider availability and plan pins</summary><p v-for="item in plan.providers" :key="item.id">{{ item.id }} · publisher {{ item.publisher }} · {{ item.enabled ? 'Configured' : 'Disabled' }} · next revision {{ item.next_revision }}</p><pre>{{ JSON.stringify({ expected_versions: plan.expected_versions, expected_evidence: plan.expected_evidence }, null, 2) }}</pre><p v-for="text in plan.limitations" :key="text" class="hint">{{ text }}</p></details>
        <form @submit.prevent="loadPlan(0)"><label>Search baseline vulnerability IDs<input v-model="query" maxlength="200" :disabled="busy"></label><button :disabled="busy">Search advisory identifiers</button></form>
        <p>{{ plan.total }} matching baseline IDs · {{ identifiers.length }}/20 explicitly selected</p><p v-if="provider && plan.unsupported_total" class="hint">{{ plan.unsupported_total }} baseline IDs unsupported by {{ provider }}; these have not been looked up.</p>
        <div class="identifiers"><label v-for="identifier in plan.identifiers" :key="identifier"><input type="checkbox" :checked="identifiers.includes(identifier)" :disabled="busy || !can || Boolean(pending) || (!identifiers.includes(identifier) && identifiers.length >= 20)" @change="select(identifier)">{{ identifier }}</label></div>
        <nav class="actions" aria-label="Advisory identifier pages"><button type="button" :disabled="busy || !previous.length" @click="pageIdentifiers(false)">Previous advisory identifiers</button><button type="button" :disabled="busy || plan.next_offset == null" @click="pageIdentifiers(true)">Next advisory identifiers</button></nav>
        <form v-if="can" aria-label="Queue advisory refresh" @submit.prevent="enqueue"><label>Advisory provider<select v-model="provider" :disabled="busy || Boolean(pending)"><option value="" disabled>Select a provider</option><option v-for="item in plan.providers" :key="item.id" :value="item.id" :disabled="!item.enabled">{{ item.id }} · {{ item.publisher }}{{ item.enabled ? '' : ' (disabled)' }}</option></select></label><p v-if="selectedProvider">Explicit provider catalog revision {{ selectedProvider.next_revision }}. <template v-if="selectedProvider.identifier_formats">Supported exact IDs: {{ selectedProvider.identifier_formats.join(', ') }}.</template></p><p v-if="pending" class="hint">Request pinned to provider {{ pending.provider }}, revision {{ pending.revision }} and {{ pending.identifiers.length }} IDs. Refreshing the plan does not change this request.</p><details v-if="pending"><summary>Frozen pending advisory request</summary><pre>{{ JSON.stringify(pending, null, 2) }}</pre></details><button v-if="!recorded" :disabled="busy || (!pending && (!selectedProvider?.enabled || !identifiers.length || stale))">{{ pending ? 'Resend identical advisory request' : 'Queue advisory refresh' }}</button><button v-if="pending" type="button" :disabled="busy" @click="newRequest">Start new advisory request</button></form>
      </template>
      <p v-if="jobsLoaded && !shownJobs.length">No advisory jobs for this product.</p>
      <article v-for="job in shownJobs" :key="job.id" :aria-label="`Advisory job ${job.id}`"><strong>{{ job.provider }} · {{ human(job.status) }}</strong><p>{{ job.identifiers.join(', ') }} · {{ job.attempts }} attempts</p><p v-if="job.error">{{ job.error }}</p><div class="actions"><button type="button" :disabled="busy" @click="inspect(job)">Refresh advisory status</button><button v-if="job.capabilities.includes('retry')" type="button" :disabled="busy" @click="inspect(job, 'retry')">Retry advisory job</button><button v-if="job.capabilities.includes('cancel')" type="button" :disabled="busy" @click="inspect(job, 'cancel')">Cancel DTVP advisory job</button></div><details><summary>Advisory job pins and capture result</summary><pre>{{ JSON.stringify({ provider: job.provider, identifiers: job.identifiers, revision: job.revision, expected_versions: job.expected_versions, expected_evidence: job.expected_evidence, result: job.result }, null, 2) }}</pre></details></article>
      <nav v-if="jobsLoaded" class="actions" aria-label="Advisory job pages"><button type="button" :disabled="busy || !jobPrevious.length" @click="pageJobs(false)">Previous advisory jobs</button><button type="button" :disabled="busy || jobNext == null" @click="pageJobs(true)">Next advisory jobs</button></nav>
      </fieldset><KnowledgeOsvMatching :project="project" :state="state" :disabled="ownLocked" @locked="childLocked = $event" />
    </section>
  </details>
</template>
<style scoped>
.knowledge-advisories { margin-block: .75rem; padding: .8rem; border: 1px solid var(--line); border-radius: .65rem; min-width: 0; } .advisory-controls { min-width:0; margin:0; padding:0; border:0 } summary { cursor: pointer; font-weight: 600; } section, article, form { min-width: 0; overflow-wrap: anywhere; }.hint { font-size: .85rem; color: var(--muted); }.actions { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin-block: .6rem; } label { display: grid; gap: .3rem; margin-block: .6rem; } input, select { width: 100%; min-width: 0; box-sizing: border-box; }.identifiers { display: flex; flex-wrap: wrap; gap: .3rem 1rem; }.identifiers label { display: flex; align-items: center; }.identifiers input { width: auto; } article { border-top: 1px solid var(--line); padding-block: .7rem; } pre { overflow-wrap: anywhere; white-space: pre-wrap; max-height: 18rem; overflow: auto; font-size: .75rem; }
</style>
