<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api, send } from '../api'
import type { Finding, RescoreProposal, RescoreRequest } from '../types'

type Metric = { key: string; name: string; base: boolean; values: { value: string; name: string }[] }
type Candidate = { id: string; source: string; eligible: boolean; reason: string; rationale: string; proposal: RescoreProposal | null }
const props = defineProps<{ finding: Finding; state: string; modelValue: RescoreRequest | null; disabled: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: RescoreRequest | null] }>()
const included = ref(Boolean(props.modelValue)), form = ref<RescoreRequest>(props.modelValue ? { ...props.modelValue } : { kind: 'manual', base_vector: props.finding.original_vectors[0]?.vector || '', vector: props.finding.original_vectors[0]?.vector || '', rationale: '', policy_digest: '', preview_digest: '', rule_basis: 'applicability' })
const metrics = ref<Metric[]>([]), values = ref<Record<string, string>>({}), candidates = ref<Candidate[]>([])
const inputsReady = ref(false)
const preview = ref<RescoreProposal | null>(null), error = ref(''), busy = ref(false), raw = ref(false)
const version = computed(() => props.finding.original_vectors.find(v => v.vector === form.value.base_vector)?.version || '')
let sequence = 0, stopped = false
function changed() { form.value.preview_digest = ''; preview.value = null; if (included.value) emit('update:modelValue', { ...form.value }) }
function metricChanged() {
  const extras = metrics.value.filter(metric => !metric.base && values.value[metric.key] && !['X', 'ND'].includes(values.value[metric.key]!)).map(metric => `${metric.key}:${values.value[metric.key]}`)
  form.value.vector = form.value.base_vector + (extras.length ? '/' + extras.join('/') : ''); changed()
}
async function load() {
  const current = ++sequence; inputsReady.value = false
  try {
    const result = await api<{ items: Candidate[]; policy_digest: string }>(`/findings/${props.finding.id}/rescoring/proposals`)
    if (current !== sequence || stopped) return
    candidates.value = result.items; form.value.policy_digest = result.policy_digest
    if (version.value) {
      const result = await api<{ metrics: Metric[] }>(`/cvss/metrics/${version.value}`)
      if (current !== sequence || stopped) return
      metrics.value = result.metrics
      const vector = form.value.vector.split('/').filter(item => item.includes(':') && !item.startsWith('CVSS:'))
      values.value = Object.fromEntries(vector.map(item => item.split(':')))
    }
    inputsReady.value = true
  } catch (err) { if (!stopped && current === sequence) error.value = err instanceof Error ? err.message : 'Rescoring inputs unavailable' }
}
async function calculate() {
  busy.value = true; error.value = ''
  try {
    const result = await api<{ proposal: RescoreProposal; preview_digest: string }>(`/findings/${props.finding.id}/rescoring/preview`, send({ expected_version: props.finding.state_version, state: props.state, rescoring: form.value }))
    if (stopped) return
    preview.value = result.proposal; form.value.preview_digest = result.preview_digest; emit('update:modelValue', { ...form.value })
  } catch (err) { if (!stopped) error.value = err instanceof Error ? err.message : 'Calculation failed' }
  finally { busy.value = false }
}
watch(included, value => { if (value) { void load(); changed() } else emit('update:modelValue', null) })
watch(() => form.value.base_vector, async value => { form.value.vector = value; values.value = {}; changed(); await load() })
watch(() => form.value.kind, () => { changed() })
watch(() => props.state, state => { if (state !== 'not_affected') form.value.rule_basis = 'applicability'; changed() })
watch(() => props.finding.state_version, () => { changed(); void load() })
watch(() => props.modelValue, value => { if (!value && included.value) included.value = false })
watch(() => props.finding.id, () => { changed() })
onBeforeUnmount(() => { stopped = true; sequence++ })
if (included.value) changed()
void load()
</script>
<template>
  <section class="rescore-editor">
    <label class="toggle"><input v-model="included" type="checkbox" :disabled="disabled || !finding.original_vectors.length"> Include contextual CVSS score</label>
    <p v-if="!finding.original_vectors.length" class="hint">No validated original Base vector is available. Resolve source evidence before rescoring.</p>
    <template v-if="included">
      <p class="hint">Base metrics stay unchanged. Preview this proposal before submitting it for independent review.</p>
      <label>Rescoring method <select v-model="form.kind" :disabled="disabled || busy"><option value="manual">Manual calculator</option><option value="rule">Version-specific applicability rule</option><option value="evidence">Reviewed provider proposal</option></select></label>
      <template v-if="form.kind !== 'evidence'"><label>Original Base vector <select v-model="form.base_vector" :disabled="disabled || busy"><option v-for="base in finding.original_vectors" :key="base.vector" :value="base.vector">CVSS {{ base.version }} · {{ base.score.toFixed(1) }}</option></select></label><code class="vector-line">{{ form.base_vector }}</code></template>
      <template v-if="form.kind === 'manual'"><details><summary>Environmental and temporal metrics</summary><div class="metric-grid"><label v-for="metric in metrics.filter(metric => !metric.base)" :key="metric.key">{{ metric.name }} <small>{{ metric.key }}</small><select v-model="values[metric.key]" :disabled="disabled || busy" @change="metricChanged"><option value="">Not defined</option><option v-for="value in metric.values" :key="value.value" :value="value.value">{{ value.name }} ({{ value.value }})</option></select></label></div></details><details :open="raw"><summary>Enter a contextual vector</summary><label>Contextual vector <textarea v-model="form.vector" rows="3" maxlength="1024" :disabled="disabled || busy" @input="changed"></textarea></label></details></template>
      <template v-if="form.kind === 'rule'"><label v-if="state === 'not_affected'">Rule basis <select v-model="form.rule_basis" @change="changed"><option value="applicability">Not affected</option><option value="false_positive">False positive</option></select></label><p class="hint">Uses this project's current rules for CVSS {{ version }}. The applicability decision still requires evidence.</p></template>
      <template v-if="form.kind === 'evidence'"><label>Provider result <select v-model="form.evidence_id" :disabled="disabled || busy" @change="changed"><option value="">Select a current result</option><option v-for="candidate in candidates" :key="candidate.id" :value="candidate.id" :disabled="!candidate.eligible">{{ candidate.source }} · {{ candidate.eligible ? candidate.proposal?.score.toFixed(1) : 'Unavailable' }}</option></select></label><p v-for="candidate in candidates.filter(candidate => !candidate.eligible)" :key="candidate.id" class="hint">{{ candidate.source }}: {{ candidate.reason }}</p><p v-if="!candidates.length" class="hint">No provider results yet. VScorer and eligible Agentyzer results can supply proposals.</p></template>
      <label>Context and scoring rationale <textarea v-model="form.rationale" rows="3" maxlength="6000" :disabled="disabled || busy" @input="changed" placeholder="Explain verified deployment conditions and evidence supporting these metrics."></textarea></label>
      <button type="button" :disabled="disabled || busy || !inputsReady || !form.rationale.trim()" @click="calculate">Preview contextual score</button>
      <p v-if="error" role="alert" class="warning">{{ error }}</p>
      <div v-if="preview" class="score-preview"><span>Original <strong>{{ preview.base_score.toFixed(1) }}</strong></span><span>Proposed <strong>{{ preview.score.toFixed(1) }}</strong></span><code class="vector-line">{{ preview.vector }}</code><p class="hint">A lower score does not establish that the component is unaffected. Approval applies to this occurrence and evidence revision.</p></div><p v-else class="hint">A current calculation preview is required before submission.</p>
    </template>
  </section>
</template>
