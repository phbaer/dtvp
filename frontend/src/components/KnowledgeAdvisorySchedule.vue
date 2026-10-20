<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Provider = { id: string; publisher: string; enabled: boolean }
type Schedule = { provider: string; versions: string[]; interval_seconds: number; batch_size: number }
type Policy = { state: string | null; providers: Schedule[]; capabilities: string[]; limitations: string[]; provider_minimum_seconds: Record<string, number> }
type Row = Omit<Schedule, 'versions'> & { versions: string }
type Input = { request_id: string; expected_policy: string | null; providers: Schedule[] }
const props = defineProps<{ project: string; providers: Provider[]; disabled?: boolean; active?: boolean }>()
const emit = defineEmits<{ locked: [boolean] }>()
const policy = ref<Policy | null>(null), rows = ref<Row[]>([]), initial = ref('[]'), busy = ref(false), error = ref(''), notice = ref(''), provider = ref('')
const pending = ref<{ endpoint: string; input: Input } | null>(null), confirmed = ref(false), attempted = ref(false), committed = ref(false)
const dirty = computed(() => JSON.stringify(rows.value) !== initial.value)
const can = computed(() => policy.value?.capabilities.includes('configure') === true)
const blocked = computed(() => busy.value || props.disabled === true)
const locked = computed(() => !committed.value && (busy.value || dirty.value || !!pending.value))
const available = computed(() => props.providers.filter(item => item.enabled && !rows.value.some(row => row.provider === item.id)))
const stale = computed(() => !!pending.value && pending.value.input.expected_policy !== policy.value?.state)
let sequence = 0
watch(locked, value => emit('locked', value), { immediate: true, flush: 'sync' })
const path = () => `/projects/${encodeURIComponent(props.project)}/advisory-schedule`
function adopt(value: Policy) { rows.value = value.providers.map(row => ({ ...row, versions: row.versions.join('\n') })); initial.value = JSON.stringify(rows.value); provider.value = '' }
async function load() {
  if (busy.value) return
  const current = ++sequence; busy.value = true; error.value = ''
  try { const result = await knowledgeApi<Policy>(path()); if (current !== sequence) return; policy.value = result; if (!pending.value && !dirty.value) adopt(result) }
  catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Schedule unavailable' }
  finally { if (current === sequence) busy.value = false }
}
function toggle(open: boolean) { if (open && !policy.value) void load() }
function add() { if (blocked.value || !can.value || pending.value || !available.value.some(item => item.id === provider.value)) return; rows.value.push({ provider: provider.value, versions: '', interval_seconds: 86400, batch_size: 20 }); provider.value = '' }
function review() {
  if (blocked.value || !can.value || pending.value || !policy.value) return
  pending.value = { endpoint: path(), input: { request_id: crypto.randomUUID(), expected_policy: policy.value.state, providers: rows.value.map(row => ({ provider: row.provider, versions: row.versions.split(/\r?\n/).map(value => value.trim()).filter(Boolean), interval_seconds: Number(row.interval_seconds), batch_size: Number(row.batch_size) })) } }; confirmed.value = false; attempted.value = false; error.value = ''; notice.value = ''
}
function discard() { if (busy.value) return; pending.value = null; attempted.value = false; committed.value = false; confirmed.value = false; error.value = ''; notice.value = ''; if (policy.value) adopt(policy.value) }
async function publish() {
  if (blocked.value || !can.value || !pending.value || !confirmed.value || (stale.value && !attempted.value)) return
  const capture = pending.value, current = ++sequence; busy.value = true; attempted.value = true; error.value = ''
  try {
    const result = await knowledgeApi<{ committed: boolean; projection?: string }>(capture.endpoint, { method: 'PUT', body: JSON.stringify(capture.input) })
    if (current !== sequence) return
    if (result.committed !== true) throw new Error('Schedule publication uncertain; resend the identical request.')
    committed.value = true
    if (result.projection !== 'current') { notice.value = 'Schedule committed; projection pending. Refresh its identical receipt.'; return }
    busy.value = false; discard(); await load(); notice.value = 'Advisory schedule saved. No assessments or approvals were adopted.'
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Publication failed; captured schedule retained.' }
  finally { if (current === sequence) busy.value = false }
}
onBeforeUnmount(() => { ++sequence; emit('locked', false) })
</script>
<template>
  <TaskSurface :active="active" class="advisory-schedule" aria-label="Automatic advisory refresh schedule" @active="toggle" title="Optional automatic refresh schedule">
    <p class="hint">Only known IDs from selected versions. Batches rotate; each interval does not guarantee every ID. Empty configuration stops new scheduling.</p>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <button :disabled="busy" @click="load">Refresh schedule configuration</button>
    <template v-if="policy"><p>{{ policy.providers.length }} configured providers</p>
      <form v-if="can" aria-label="Configure automatic advisory refresh" @submit.prevent="review"><fieldset :disabled="blocked || !!pending">
        <section v-for="(row, index) in rows" :key="row.provider" :aria-label="`Scheduled provider ${row.provider}`"><strong>{{ row.provider }} · {{ providers.find(item => item.id === row.provider)?.publisher || 'Attributed provider' }}</strong>
          <label>Versions (one per line)<textarea v-model="row.versions" rows="2" maxlength="4200" required /></label>
          <label>Refresh interval (seconds)<input v-model.number="row.interval_seconds" type="number" min="3600" max="2592000" step="1" required></label>
          <label>Maximum IDs per batch<input v-model.number="row.batch_size" type="number" min="1" max="20" step="1" required></label>
          <button type="button" @click="rows.splice(index, 1)">Remove {{ row.provider }} from schedule</button>
        </section>
        <div v-if="available.length"><label>Schedule provider<select v-model="provider"><option value="" disabled>Select an enabled provider</option><option v-for="item in available" :key="item.id" :value="item.id">{{ item.id }} · {{ item.publisher }}</option></select></label><button type="button" :disabled="!provider" @click="add">Add scheduled provider</button></div>
        <button>Review schedule changes</button>
      </fieldset></form>
      <ul v-else><li v-for="row in policy.providers" :key="row.provider">{{ row.provider }} · {{ row.versions.join(', ') }} · every {{ row.interval_seconds }} seconds · up to {{ row.batch_size }} IDs</li></ul>
      <section v-if="pending" aria-label="Captured advisory schedule"><p>{{ pending.input.providers.length }} providers captured. {{ pending.input.providers.length ? 'Versions and limits stay fixed for this request.' : 'New scheduling stops; existing history remains retained.' }}</p>
        <p v-if="stale" role="status">The policy changed; this request retains its original pin.</p>
        <details><summary>Captured schedule and exact policy pin</summary><pre>{{ JSON.stringify(pending.input, null, 2) }}</pre></details>
        <label><input v-model="confirmed" type="checkbox" :disabled="blocked || attempted"> I checked versions, providers and unattended collection limits.</label>
        <button :disabled="blocked || !confirmed || (stale && !attempted)" @click="publish">{{ committed ? 'Refresh committed schedule receipt' : attempted ? 'Retry identical schedule publication' : 'Publish advisory schedule' }}</button>
      </section>
      <button v-if="dirty || pending" :disabled="busy" @click="discard">Discard schedule draft</button>
      <details><summary>Schedule pins and limitations</summary><code>{{ policy.state || 'No schedule configured' }}</code><p v-for="(seconds, id) in policy.provider_minimum_seconds" :key="id">{{ id }}: minimum {{ seconds }} seconds between provider requests</p><ul><li v-for="item in policy.limitations" :key="item">{{ item }}</li></ul></details>
    </template>
  </TaskSurface>
</template>
<style scoped>
.advisory-schedule{margin-top:12px;min-width:0}.advisory-schedule fieldset{border:0;padding:0;min-width:0}.advisory-schedule label{display:grid;gap:4px;margin:8px 0}.advisory-schedule input:not([type=checkbox]),.advisory-schedule textarea,.advisory-schedule select{width:100%;max-width:100%;box-sizing:border-box}.advisory-schedule label:has(input[type=checkbox]){display:block}.advisory-schedule section{min-width:0;padding:8px 0}.advisory-schedule pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:250px;overflow:auto;font-size:.75rem}.advisory-schedule code,.advisory-schedule li{overflow-wrap:anywhere}.advisory-schedule button{margin:4px 8px 4px 0}.hint{color:var(--muted);font-size:.85rem}
</style>
