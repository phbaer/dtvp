<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
type Job = { id: string; status: string; version: string; context_id: string; vulnerability_id: string; state: string; result: Record<string, unknown>; capabilities: string[]; parent_job_id?: string }
type Capture = { endpoint: string; body: { request_id: string; expected: string; parent_report_sha256: string; question: string; user_guidance: string }; parent: Job }
const props = defineProps<{ project: string; state: string; version: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [boolean]; recorded: [job: Job] }>()
const parent = ref<Job | null>(null), expected = ref(''), question = ref(''), guidance = ref(''), confirmed = ref(false), busy = ref(false), error = ref(''), notice = ref(''), captured = ref<Capture | null>(null)
const locked = computed(() => !!parent.value || busy.value || !!captured.value)
const stale = computed(() => !!expected.value && expected.value !== props.state)
let sequence = 0
watch(locked, value => emit('locked', value), { flush: 'sync' })
function start(job: Job) {
  if (locked.value || props.disabled || job.status !== 'succeeded' || !job.capabilities.includes('follow_up') || typeof job.result.report_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(job.result.report_sha256)) return
  parent.value = JSON.parse(JSON.stringify(job)); expected.value = props.state; question.value = ''; guidance.value = ''; confirmed.value = false; error.value = ''; notice.value = ''
}
defineExpose({ start })
function clear() { parent.value = null; captured.value = null; expected.value = ''; question.value = ''; guidance.value = ''; confirmed.value = false; error.value = '' }
function discard() { if (busy.value) return; const uncertain = !!captured.value; ++sequence; clear(); notice.value = uncertain ? 'Input discarded. This does not cancel a follow-up job that may already have been recorded.' : '' }
async function submit() {
  if (busy.value || props.disabled || !parent.value) return
  if (!captured.value) {
    if (stale.value || !confirmed.value || !question.value.trim()) return
    captured.value = { endpoint: `/projects/${encodeURIComponent(props.project)}/versions/${encodeURIComponent(props.version)}/analysis-jobs/${encodeURIComponent(parent.value.id)}/follow-up`, body: { request_id: crypto.randomUUID(), expected: expected.value, parent_report_sha256: String(parent.value.result.report_sha256), question: question.value, user_guidance: guidance.value }, parent: JSON.parse(JSON.stringify(parent.value)) }
  }
  const request = captured.value, token = ++sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    const job = await knowledgeApi<Job>(request.endpoint, send(request.body))
    if (token !== sequence) return
    if (!job.id || job.parent_job_id !== request.parent.id || job.version !== request.parent.version || job.context_id !== request.parent.context_id || job.vulnerability_id !== request.parent.vulnerability_id) throw new Error('Returned job does not match the selected parent and scope.')
    clear(); notice.value = `Follow-up job ${job.id} recorded. Refresh its status explicitly; no assessment or approval was created.`; emit('recorded', job)
  } catch (err) { if (token === sequence) error.value = `${err instanceof Error ? err.message : 'Follow-up request failed'} Exact parent, report, question, source head and request ID remain fixed. Retry or discard explicitly.` }
  finally { if (token === sequence) busy.value = false }
}
onBeforeUnmount(() => { ++sequence; emit('locked', false) })
</script>
<template>
  <section v-if="parent || notice" class="analysis-follow-up" aria-label="Bound Agentyzer follow-up">
    <p v-if="notice" role="status">{{ notice }}</p>
    <template v-if="parent">
      <h4>Ask about this completed analysis</h4><p>{{ parent.vulnerability_id }} · {{ parent.version }} · parent {{ parent.id }}</p>
      <p class="hint">The backend checks the exact retained report, source and authenticated parent association. A follow-up creates a separate job and evidence; it does not replace a human assessment or approval.</p>
      <p v-if="stale" role="status">The workspace head changed. This input retains its original source pin; discard before starting a new request. A captured request can still be retried unchanged.</p>
      <p v-if="error" role="alert">{{ error }}</p>
      <form @submit.prevent="submit"><fieldset :disabled="busy || disabled || !!captured"><label>Follow-up question<textarea v-model="question" rows="3" maxlength="6000" required @input="confirmed = false" /></label><details><summary>Additional follow-up guidance</summary><label>Follow-up guidance<textarea v-model="guidance" rows="2" maxlength="6000" @input="confirmed = false" /></label></details><label class="confirmation"><input v-model="confirmed" type="checkbox"><span>I selected this exact parent report and question for a new source-bound analysis job.</span></label></fieldset><div class="actions"><button :disabled="busy || disabled || (!captured && (stale || !confirmed || !question.trim()))">{{ captured ? 'Retry exact follow-up request' : 'Queue bound follow-up' }}</button><button type="button" :disabled="busy" @click="discard">Discard follow-up input</button></div></form>
      <details><summary>Follow-up source and request pins</summary><pre>{{ JSON.stringify(captured ? { endpoint: captured.endpoint, ...captured.body, parent_job_id: captured.parent.id } : { parent_job_id: parent.id, parent_report_sha256: parent.result.report_sha256, expected: expected, context_id: parent.context_id }, null, 2) }}</pre></details>
      <p v-if="busy" role="status">Recording bound follow-up…</p>
    </template>
  </section>
</template>
<style scoped>
.analysis-follow-up{border-top:1px solid var(--line);padding-block:.7rem;min-width:0;overflow-wrap:anywhere}.analysis-follow-up fieldset{padding:0;border:0;min-width:0}.analysis-follow-up label{display:grid;gap:.3rem;margin-block:.6rem}.analysis-follow-up textarea{width:100%;box-sizing:border-box;min-width:0}.analysis-follow-up .confirmation{display:flex;align-items:start;gap:.4rem}.analysis-follow-up input[type=checkbox]{width:auto}.analysis-follow-up .actions{display:flex;flex-wrap:wrap;gap:.5rem}.analysis-follow-up pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:18rem;overflow:auto;font-size:.75rem}.hint{font-size:.85rem;color:var(--muted)}
</style>
