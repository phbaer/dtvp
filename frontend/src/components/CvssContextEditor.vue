<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api } from '../api'
type Metric = { key: string; name: string; base: boolean; values: { value: string; name: string }[] }
const props = defineProps<{ baseVector: string; modelValue: string; disabled?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [string] }>()
const metrics = ref<Metric[]>([]), error = ref(''), busy = ref(false), group = ref('requirements')
const groups = [{ id: 'requirements', label: 'Security requirements' }, { id: 'deployment', label: 'Deployment conditions' }, { id: 'threat', label: 'Threat & remediation' }]
const grouping = (key: string) => ['CR', 'IR', 'AR'].includes(key) ? 'requirements' : key.startsWith('M') || ['CDP', 'TD'].includes(key) ? 'deployment' : 'threat'
const available = computed(() => groups.filter(item => metrics.value.some(metric => !metric.base && grouping(metric.key) === item.id)))
const visible = computed(() => metrics.value.filter(metric => !metric.base && grouping(metric.key) === group.value))
const values = computed(() => Object.fromEntries(props.modelValue.split('/').filter(item => !item.startsWith('CVSS:')).map(item => item.split(':'))))
let sequence = 0
async function load() {
  const current = ++sequence; busy.value = true; error.value = ''; metrics.value = []
  try {
    const version = props.baseVector.match(/^CVSS:(\d\.\d)\//)?.[1] || '2.0'
    const result = await api<{ metrics: Metric[] }>(`/cvss/metrics/${version}`)
    if (current !== sequence) return
    if (!Array.isArray(result.metrics)) throw new Error('Metric definitions unavailable; advanced vector input remains available.')
    metrics.value = result.metrics; group.value = available.value[0]?.id || 'requirements'
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Metric definitions unavailable' }
  finally { if (current === sequence) busy.value = false }
}
function change(key: string, value: string) {
  const changed = { ...values.value, [key]: value }
  const contextual = new Set(metrics.value.filter(metric => !metric.base).map(metric => metric.key))
  const base = props.baseVector.split('/').filter(item => !contextual.has(item.split(':')[0]!))
  const extras = metrics.value.filter(metric => !metric.base && changed[metric.key] && !['X', 'ND'].includes(changed[metric.key]!)).map(metric => `${metric.key}:${changed[metric.key]}`)
  emit('update:modelValue', [...base, ...extras].join('/'))
}
watch(() => props.baseVector, () => { if (props.baseVector) void load() }, { immediate: true })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <section class="cvss-context-editor" aria-label="Contextual CVSS metrics">
    <p class="hint">Source Base metrics stay fixed. Choose verified conditions for this context; scoring and review gates remain server-side.</p>
    <p v-if="error" role="status">{{ error }}</p>
    <div v-if="available.length" class="metric-groups" role="group" aria-label="CVSS metric groups"><button v-for="item in available" :key="item.id" type="button" :aria-pressed="group === item.id" @click="group = item.id">{{ item.label }}</button></div>
    <div class="metric-grid"><label v-for="metric in visible" :key="metric.key">{{ metric.name }}<select :value="values[metric.key] || ''" :disabled="disabled || busy" @change="change(metric.key, ($event.target as HTMLSelectElement).value)"><option value="">Not defined</option><option v-for="value in metric.values" :key="value.value" :value="value.value">{{ value.name }} ({{ value.value }})</option></select></label></div>
    <details><summary>Advanced vector input</summary><label>Proposed contextual vector<textarea :value="modelValue" rows="3" maxlength="2048" spellcheck="false" :disabled="disabled" @input="emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"></textarea></label></details>
  </section>
</template>
<style scoped>
.metric-groups{display:flex;gap:4px;flex-wrap:wrap;margin:8px 0}.metric-groups button{font-size:.78rem;padding:4px 8px}.metric-groups button[aria-pressed=true]{background:var(--accent-soft);border-color:var(--accent)}.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px}.metric-grid label{margin:0;font-size:.8rem}.cvss-context-editor{min-width:0}.cvss-context-editor textarea{font-size:.78rem}
</style>
