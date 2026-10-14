<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api, send } from '../api'
import type { Finding, RescoreProposal, RescoreRequest } from '../types'

type Metric = { key: string; name: string; base: boolean; values: { value: string; name: string }[] }
type Candidate = { id: string; source: string; eligible: boolean; reason: string; rationale: string; proposal: RescoreProposal | null }
const props = defineProps<{ finding: Finding; state: string; modelValue: RescoreRequest | null; disabled: boolean; assessmentRationale: string }>()
const emit = defineEmits<{ 'update:modelValue': [value: RescoreRequest | null]; preview: [value: RescoreProposal | null] }>()
const included = ref(Boolean(props.modelValue)), form = ref<RescoreRequest>(props.modelValue ? { ...props.modelValue } : { kind: 'rule', base_vector: props.finding.original_vectors[0]?.vector || '', vector: props.finding.original_vectors[0]?.vector || '', rationale: '', policy_digest: '', preview_digest: '', rule_basis: 'applicability' })
const metrics = ref<Metric[]>([]), values = ref<Record<string, string>>({}), candidates = ref<Candidate[]>([])
const inputsReady = ref(false)
const preview = ref<RescoreProposal | null>(null), error = ref(''), busy = ref(false), group = ref('requirements')
const version = computed(() => props.finding.original_vectors.find(v => v.vector === form.value.base_vector)?.version || '')
const groups = [
  { id: 'requirements', name: 'Security requirements', hint: 'How important are confidentiality, integrity and availability here?' },
  { id: 'deployment', name: 'Deployment conditions', hint: 'Which verified conditions differ in this deployment?' },
  { id: 'threat', name: 'Threat & remediation', hint: 'What is known about exploitation and available fixes?' },
]
function metricName(metric: Metric) { return metric.name.replace('Req.', 'Requirement') }
function groupFor(key: string) { return ['CR', 'IR', 'AR'].includes(key) ? 'requirements' : key.startsWith('M') || ['CDP', 'TD'].includes(key) ? 'deployment' : 'threat' }
const visibleMetrics = computed(() => metrics.value.filter(metric => !metric.base && groupFor(metric.key) === group.value))
const availableGroups = computed(() => groups.filter(item => metrics.value.some(metric => !metric.base && groupFor(metric.key) === item.id)))
let sequence = 0, calculation = 0, stopped = false
function changed() { calculation++; form.value.preview_digest = ''; preview.value = null; emit('preview', null); if (included.value) emit('update:modelValue', { ...form.value }) }
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
      values.value = { ...Object.fromEntries(result.metrics.map(metric => [metric.key, ''])), ...Object.fromEntries(vector.map(item => item.split(':'))) }
    }
    inputsReady.value = true
  } catch (err) { if (!stopped && current === sequence) error.value = err instanceof Error ? err.message : 'Rescoring inputs unavailable' }
}
async function calculate() {
  const current = ++calculation; busy.value = true; error.value = ''
  try {
    const result = await api<{ proposal: RescoreProposal; preview_digest: string }>(`/findings/${props.finding.id}/rescoring/preview`, send({ expected_version: props.finding.state_version, state: props.state, rescoring: form.value }))
    if (stopped || current !== calculation || !included.value) return
    preview.value = result.proposal; emit('preview', result.proposal); form.value.preview_digest = result.preview_digest; emit('update:modelValue', { ...form.value })
  } catch (err) { if (!stopped) error.value = err instanceof Error ? err.message : 'Calculation failed' }
  finally { busy.value = false }
}
watch(included, value => { if (value) { void load(); changed() } else { calculation++; preview.value = null; emit('preview', null); emit('update:modelValue', null) } })
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
    <label class="score-choice"><input v-model="included" type="checkbox" :disabled="disabled || !finding.original_vectors.length"><span><strong>Include contextual CVSS score</strong><small>Optional · Original {{ finding.original_score?.toFixed(1) || 'unknown' }} remains in the evidence.</small></span></label>
    <p v-if="!finding.original_vectors.length" class="hint">A validated Base vector is needed to rescore.</p>
    <template v-if="included">
      <fieldset class="scoring-methods"><legend>Choose how to assess severity</legend><label v-for="method in [{id:'rule',name:'Project rule',hint:'Apply the version-specific applicability policy.'},{id:'evidence',name:'Provider proposal',hint:'Review a VScorer or Agentyzer result.'},{id:'manual',name:'Deployment metrics',hint:'Adjust environmental and temporal conditions.'}]" :key="method.id" :class="{ selected: form.kind === method.id }"><input v-model="form.kind" type="radio" name="scoring-method" :value="method.id" :disabled="disabled || busy"><span><strong>{{ method.name }}</strong><small>{{ method.hint }}</small></span></label></fieldset>
      <template v-if="form.kind !== 'evidence'"><label v-if="finding.original_vectors.length > 1">Original Base vector <select v-model="form.base_vector" :disabled="disabled || busy"><option v-for="base in finding.original_vectors" :key="base.vector" :value="base.vector">CVSS {{ base.version }} · {{ base.score.toFixed(1) }}</option></select></label><p class="hint">CVSS {{ version }} · Base metrics remain fixed.</p></template>
      <template v-if="form.kind === 'manual'"><div class="metric-groups" role="group" aria-label="CVSS metric groups"><button v-for="item in availableGroups" :key="item.id" type="button" :aria-pressed="group === item.id" @click="group = item.id">{{ item.name }}</button></div><p class="hint">{{ groups.find(item => item.id === group)?.hint }}</p><div class="metric-grid"><label v-for="metric in visibleMetrics" :key="metric.key">{{ metricName(metric) }}<select v-model="values[metric.key]" :disabled="disabled || busy" @change="metricChanged"><option value="">Not defined</option><option v-for="value in metric.values" :key="value.value" :value="value.value">{{ value.name }} ({{ value.value }})</option></select></label></div><details><summary>Advanced vector input</summary><label>Contextual vector <textarea v-model="form.vector" rows="3" maxlength="1024" :disabled="disabled || busy" @input="changed"></textarea></label><button type="button" :disabled="disabled || busy" @click="load">Update metric controls from vector</button></details></template>
      <template v-if="form.kind === 'rule'"><label v-if="state === 'not_affected'">Rule basis <select v-model="form.rule_basis" :disabled="disabled || busy" @change="changed"><option value="applicability">Not affected</option><option value="false_positive">False positive</option></select></label><p class="hint">Project rule for {{ state.replaceAll('_', ' ') }}.</p></template>
      <template v-if="form.kind === 'evidence'"><label>Provider result <select v-model="form.evidence_id" :disabled="disabled || busy" @change="changed"><option value="">Select a current result</option><option v-for="candidate in candidates.filter(item => item.eligible)" :key="candidate.id" :value="candidate.id">{{ candidate.source }} · {{ candidate.proposal?.score.toFixed(1) }}</option></select></label><p v-if="!candidates.some(item => item.eligible)" class="hint">No eligible provider proposal. Use a project rule or deployment metrics.</p><details v-if="candidates.some(item => !item.eligible)"><summary>Unavailable results</summary><p v-for="candidate in candidates.filter(item => !item.eligible)" :key="candidate.id" class="hint">{{ candidate.source }}: {{ candidate.reason }}</p></details></template>
      <label>Context and scoring rationale <textarea v-model="form.rationale" rows="3" maxlength="6000" :disabled="disabled || busy" @input="changed" placeholder="Which verified conditions justify this score?"></textarea></label><button v-if="assessmentRationale && !form.rationale" type="button" class="text-link" :disabled="disabled || busy" @click="form.rationale = assessmentRationale; changed()">Use assessment rationale</button>
      <div class="score-calculation"><button type="button" class="primary" :disabled="disabled || busy || !inputsReady || !form.rationale.trim() || (form.kind === 'evidence' && !form.evidence_id)" @click="calculate">{{ busy ? 'Calculating…' : 'Preview contextual score' }}</button><span class="hint">{{ preview ? 'Preview ready' : 'Preview required to continue' }}</span></div>
      <p v-if="error" role="alert" class="warning">{{ error }}</p>
      <div v-if="preview" class="score-preview"><span>Original <strong>{{ preview.base_score.toFixed(1) }}</strong></span><span>Proposed <strong>{{ preview.score.toFixed(1) }}</strong></span><details><summary>Calculated vector</summary><code class="vector-line">{{ preview.vector }}</code></details></div>
    </template>
  </section>
</template>
