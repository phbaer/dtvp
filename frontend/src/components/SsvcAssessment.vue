<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import type { SsvcSelection } from '../knowledgeApi'
type Model = { id: string; version: string; sha256: string; name: string; outcome: string; decision_points: Record<string, { name: string; definition: string; values: { key: string; name: string; definition: string }[] }> }
const props = defineProps<{ modelValue: SsvcSelection | null; disabled?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [SsvcSelection | null] }>()
const models = ref<Model[]>([]), error = ref(''), loading = ref(false)
let alive = true
const model = computed(() => models.value.find(item => item.id === props.modelValue?.model && item.version === props.modelValue?.version && item.sha256 === props.modelValue?.model_sha256))
const points = computed(() => Object.entries(model.value?.decision_points || {}).filter(([key]) => key !== model.value?.outcome))
async function load() {
  if (models.value.length || loading.value) return
  loading.value = true; error.value = ''
  try { const data = await knowledgeApi<{ models: Model[] }>('/ssvc/models'); if (alive) models.value = data.models }
  catch (err) { if (alive) error.value = String(err) } finally { if (alive) loading.value = false }
}
function select(id: string) {
  const next = models.value.find(item => item.id === id)
  if (next) emit('update:modelValue', { model: next.id, version: next.version, model_sha256: next.sha256, answers: {}, rationale: '', evidence: [] })
}
function answer(key: string, value: string) { if (!props.modelValue) return; const answers = { ...props.modelValue.answers }; if (value) answers[key] = value; else delete answers[key]; emit('update:modelValue', { ...props.modelValue, answers }) }
function rationale(value: string) { if (props.modelValue) emit('update:modelValue', { ...props.modelValue, rationale: value }) }
function evidence(index: number, field: 'reference' | 'description', value: string) {
  if (!props.modelValue) return
  emit('update:modelValue', { ...props.modelValue, evidence: props.modelValue.evidence.map((item, current) => current === index ? { ...item, [field]: value } : item) })
}
function addEvidence() { if (props.modelValue && props.modelValue.evidence.length < 50) emit('update:modelValue', { ...props.modelValue, evidence: [...props.modelValue.evidence, { reference: '', description: '' }] }) }
function removeEvidence(index: number) { if (props.modelValue) emit('update:modelValue', { ...props.modelValue, evidence: props.modelValue.evidence.filter((_, current) => current !== index) }) }
onBeforeUnmount(() => { alive = false })
</script>
<template><details @toggle="($event.target as HTMLDetailsElement).open && load()"><summary>SSVC prioritization<template v-if="modelValue"> · {{ Object.values(modelValue.answers).filter(Boolean).length }} answers</template> (optional)</summary><section aria-label="SSVC assessment"><p class="hint">Decision support recorded with this assessment. Outcome and completeness are calculated by the server; SSVC does not replace applicability or approval.</p><p v-if="error" role="alert">{{ error }}</p><fieldset :disabled="disabled || loading"><label>SSVC decision model<select :value="modelValue?.model || ''" @change="($event.target as HTMLSelectElement).value ? select(($event.target as HTMLSelectElement).value) : emit('update:modelValue', null)"><option value="">No SSVC assessment</option><option v-for="item in models" :key="item.id" :value="item.id">{{ item.name }} {{ item.version }}</option></select></label><p v-if="modelValue && !model && !loading" class="warning">Recorded model is unavailable. Its selection remains retained; choose a current model explicitly to replace it.</p><button v-if="modelValue && !model && models.some(item => item.id === modelValue?.model)" type="button" :disabled="disabled" @click="select(modelValue.model)">Use current SSVC model and clear previous answers</button><div v-if="model" class="ssvc-points"><label v-for="[key, point] in points" :key="key" :title="point.definition">{{ point.name }}<select :value="modelValue?.answers[key] || ''" @change="answer(key, ($event.target as HTMLSelectElement).value)"><option value="">Select verified condition</option><option v-for="value in point.values" :key="value.key" :value="value.key" :title="value.definition">{{ value.name }}</option></select></label></div><template v-if="modelValue"><label>SSVC rationale<textarea :value="modelValue.rationale" rows="2" maxlength="6000" required @input="rationale(($event.target as HTMLTextAreaElement).value)"></textarea></label><details><summary>Supporting references ({{ modelValue.evidence.length }})</summary><div v-for="(item, index) in modelValue.evidence" :key="index"><label>SSVC reference {{ index + 1 }}<input :value="item.reference" required maxlength="2000" @input="evidence(index, 'reference', ($event.target as HTMLInputElement).value)"></label><label>SSVC evidence description {{ index + 1 }}<textarea :value="item.description" required maxlength="4000" rows="2" @input="evidence(index, 'description', ($event.target as HTMLTextAreaElement).value)"></textarea></label><button type="button" @click="removeEvidence(index)">Remove reference {{ index + 1 }}</button></div><button type="button" :disabled="modelValue.evidence.length >= 50" @click="addEvidence">Add SSVC reference</button></details></template></fieldset></section></details></template>
<style scoped>.ssvc-points{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px}fieldset{border:0;margin:0;padding:0}.ssvc-points label{font-size:.8rem}</style>
