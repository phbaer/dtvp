<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api, send } from '../api'

type Run = { id: string; status: string; error: string; current: boolean; created_at: string; parent_job_id: string | null; result: { remote_status?: string; synthetic?: boolean; proposal_state?: string; rationale?: string; summary?: string; verdict?: string; confidence?: string; application_eligible?: boolean; rescoring_eligible?: boolean } }
const props = defineProps<{ findingId: string; stateVersion: number; evidenceRevision: number; enabled: boolean; mode: string; canRun: boolean; canAssess: boolean }>()
const emit = defineEmits<{ refresh: []; proposal: [state: string, rationale: string] }>()
const runs = ref<Run[]>([]), cursor = ref<string | null>(null), error = ref(''), notice = ref('')
const guidance = ref(''), question = ref(''), outcome = ref('eligible'), busy = ref(false)
const report = ref<Record<string, unknown> | null>(null)
const pending = computed(() => runs.value.some(run => ['queued', 'running'].includes(run.status)))
let timer: ReturnType<typeof setInterval>, sequence = 0, stopped = false
async function load(append = false) {
  const current = ++sequence
  try {
    const params = new URLSearchParams()
    if (append && cursor.value) params.set('cursor', cursor.value)
    const result = await api<{ items: Run[]; next_cursor: string | null }>(`/findings/${props.findingId}/analyses?${params}`)
    if (current !== sequence || stopped) return
    const completed = result.items.some(run => run.status === 'succeeded' && runs.value.some(old => old.id === run.id && old.status !== 'succeeded'))
    runs.value = append ? [...runs.value, ...result.items] : result.items; cursor.value = result.next_cursor
    if (completed) emit('refresh')
  } catch (err) { if (!stopped && current === sequence) error.value = err instanceof Error ? err.message : 'Could not load analyses' }
}
async function submit(parent?: Run) {
  busy.value = true; error.value = ''; notice.value = ''; report.value = null
  try {
    await api(`/findings/${props.findingId}/analyses`, send({ expected_version: props.stateVersion, guidance: guidance.value, demo_outcome: outcome.value, ...(parent ? { parent_job_id: parent.id, question: question.value } : {}) }))
    question.value = ''; notice.value = 'Analysis queued. Results remain proposals until you submit an assessment.'; await load()
  } catch (err) { error.value = err instanceof Error ? err.message : 'Could not submit analysis' }
  finally { busy.value = false }
}
async function cancel(run: Run) {
  busy.value = true
  try { await api(`/jobs/${run.id}/cancel`, send({})); await load(); notice.value = 'Result collection cancelled. A remote Agentyzer run may continue.' }
  catch (err) { error.value = err instanceof Error ? err.message : 'Cancel failed' }
  finally { busy.value = false }
}
async function showReport(run: Run) {
  busy.value = true
  try { report.value = await api(`/analyses/${run.id}/report`) }
  catch (err) { error.value = err instanceof Error ? err.message : 'Report unavailable' }
  finally { busy.value = false }
}
watch(() => props.evidenceRevision, () => { void load() })
onMounted(() => { void load(); timer = setInterval(() => { if (pending.value && !busy.value) void load() }, 1500) })
onBeforeUnmount(() => { stopped = true; sequence++; clearInterval(timer) })
</script>
<template>
  <section class="analysis-panel decision-record" aria-labelledby="analysis-title">
    <h2 id="analysis-title">Agentyzer code analysis</h2>
    <p v-if="mode === 'synthetic'" class="hint">Offline playground simulation. No code or credentials leave DTVP.</p>
    <p v-else class="hint">Agentyzer analyzes the configured repository. DTVP retains reports and your independent decisions.</p>
    <p v-if="!enabled" class="hint">Integration disabled. Configure the external service and bind this product to its repository.</p>
    <template v-if="canRun && enabled">
      <details><summary>Analysis options</summary><label>Analyst guidance <textarea v-model="guidance" rows="3" maxlength="6000"></textarea></label><label v-if="mode === 'synthetic'">Simulated outcome <select v-model="outcome"><option value="eligible">Eligible affected proposal</option><option value="inconclusive">Incomplete coverage</option><option value="failure">Service failure</option></select></label></details>
      <button :disabled="busy || pending" @click="submit()">Run code analysis</button>
    </template>
    <p v-if="error" role="alert" class="warning">{{ error }}</p><p v-if="notice" role="status" class="hint">{{ notice }}</p>
    <p v-if="!runs.length" class="hint">No analysis runs for this finding.</p>
    <article v-for="run in runs" :key="run.id" class="analysis-run">
      <div class="summary-line"><span class="badge">{{ ['queued', 'running'].includes(run.status) ? run.result.remote_status || run.status : run.status }}</span><span v-if="run.result.synthetic" class="badge">Synthetic</span><small>{{ new Date(run.created_at).toLocaleString() }}{{ run.parent_job_id ? ' · Follow-up' : '' }}</small></div>
      <p v-if="run.error" class="warning">{{ run.error }} Start a new analysis to retry against current evidence.</p>
      <template v-if="run.status === 'succeeded'">
        <strong>{{ run.result.verdict }} · {{ run.result.confidence }}</strong><p>{{ run.result.summary }}</p>
        <p v-if="!run.current" class="warning">Evidence changed after this analysis. The proposal requires a new run.</p>
        <p v-else-if="!run.result.proposal_state" class="hint">No applicable proposal: package/version correlation, eligibility or coverage checks did not permit one.</p>
        <details><summary>Analysis reasoning</summary><p>{{ run.result.rationale }}</p></details><div class="approval-actions"><button v-if="canAssess && run.current && run.result.proposal_state" :disabled="busy" @click="emit('proposal', run.result.proposal_state!, run.result.rationale || run.result.summary || '')">Use proposal in draft</button><button :disabled="busy" @click="showReport(run)">View full analysis report</button></div>
        <details v-if="canRun && enabled && run.current"><summary>Ask a follow-up</summary><label>Follow-up question <textarea v-model="question" rows="2" maxlength="6000"></textarea></label><button :disabled="busy || pending || !question.trim()" @click="submit(run)">Submit follow-up</button></details>
      </template>
      <button v-if="canRun && ['queued', 'running'].includes(run.status)" :disabled="busy" @click="cancel(run)">Cancel result collection</button>
    </article>
    <button v-if="cursor" :disabled="busy" @click="load(true)">Older analyses</button>
    <details v-if="report" open><summary>Full analysis report</summary><pre>{{ JSON.stringify(report, null, 2) }}</pre></details>
  </section>
</template>
