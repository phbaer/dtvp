<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api } from '../api'
import { metricDifference, vectorMetrics, vectorVersion, type VectorEntry } from '../lib/cvssComparison'
const props = defineProps<{ entries: VectorEntry[] }>()
const method = ref(''), baselineId = ref(''), all = ref(false), raw = ref(false)
type Metric = { key: string; name: string; base: boolean; values: { value: string; name: string }[] }
const catalog = ref<Metric[]>([]), catalogError = ref('')
const methods = computed(() => [...new Set(props.entries.map(e => vectorVersion(e.vector)))])
const rows = computed(() => props.entries.filter(e => vectorVersion(e.vector) === method.value))
const baseline = computed(() => rows.value.find(e => e.id === baselineId.value) || rows.value[0])
const original = computed(() => vectorMetrics(baseline.value?.vector || ''))
const keys = computed(() => {
  const supplied = new Set(rows.value.flatMap(e => Object.keys(vectorMetrics(e.vector))))
  const ordered = [...catalog.value.map(m => m.key).filter(k => supplied.has(k)), ...[...supplied].filter(k => !catalog.value.some(m => m.key === k))]
  return ordered.filter(k => all.value || rows.value.some(e => vectorMetrics(e.vector)[k] !== original.value[k]))
})
const metric = (key: string) => catalog.value.find(m => m.key === key)
const explain = (key: string, value?: string) => `${metric(key)?.name || key}: ${value ? metric(key)?.values.find(v => v.value === value)?.name || value : 'Not supplied; no zero score is implied'}`
let generation = 0
watch(methods, values => { if (!values.includes(method.value)) method.value = values[0] || '' }, { immediate: true })
watch(() => rows.value.map(e => e.id).join(','), () => { if (!rows.value.some(e => e.id === baselineId.value)) baselineId.value = rows.value[0]?.id || '' }, { immediate: true })
watch(method, async value => {
  const current = ++generation; catalog.value = []; catalogError.value = ''
  if (!value || value === 'Unknown') return
  try { const result = await api<{ metrics: Metric[] }>(`/cvss/metrics/${value}`); if (current === generation) { if (!Array.isArray(result.metrics)) throw Error('Metric descriptions unavailable'); catalog.value = result.metrics } }
  catch { if (current === generation) catalogError.value = 'Metric descriptions unavailable; exact metric keys and vectors remain readable.' }
}, { immediate: true })
</script>
<template>
  <section class="vector-comparison" aria-label="CVSS vector comparison">
    <div class="vector-heading"><h3>CVSS vectors</h3><div class="vector-controls"><label v-if="methods.length > 1">CVSS method<select v-model="method"><option v-for="version in methods" :key="version">{{ version }}</option></select></label><span v-else-if="method">CVSS {{ method }}</span><label v-if="rows.length">Compare against<select v-model="baselineId"><option v-for="row in rows" :key="row.id" :value="row.id">{{ row.label }} · {{ row.status }}</option></select></label><label><input v-model="all" type="checkbox">All metrics</label><label><input v-model="raw" type="checkbox">Full vectors</label></div></div>
    <p v-if="!entries.length" class="hint">No CVSS vectors supplied. Missing vectors are not zero scores.</p>
    <template v-else><p class="hint">Source ratings, proposals and publication stay distinct. Added/changed metrics are relative to the comparison baseline, not automatic adoption.</p><p v-if="catalogError" class="hint" role="status">{{ catalogError }}</p><div class="vector-scroll" tabindex="0" role="region" aria-label="Vector metrics"><table><thead><tr><th scope="col">Vector / status</th><th scope="col">Score</th><th v-for="key in keys" :key="key" scope="col" :title="metric(key)?.name">{{ key }}<small v-if="metric(key)">{{ metric(key)?.name }}</small></th></tr></thead><tbody><tr v-for="row in rows" :key="row.id"><th scope="row"><strong>{{ row.label }}</strong><small>{{ row.status }}</small><small v-if="row.id === baseline?.id">Comparison baseline</small><code v-if="raw">{{ row.vector }}</code><small v-if="row.baseVector">Derived from: <code>{{ row.baseVector }}</code></small></th><td>{{ row.score == null ? 'Not supplied' : row.score.toFixed(1) }}</td><td v-for="key in keys" :key="key"><span class="metric-cell" :class="{ added: metricDifference(original, vectorMetrics(row.vector), key) === 'Added', changed: metricDifference(original, vectorMetrics(row.vector), key).startsWith('Changed') }" :title="explain(key, vectorMetrics(row.vector)[key])">{{ vectorMetrics(row.vector)[key] || '—' }}<small>{{ metricDifference(original, vectorMetrics(row.vector), key) }}</small></span></td></tr></tbody></table></div><p v-if="!keys.length" class="hint">No metric differences within this CVSS method. Select All metrics to inspect the values.</p><p class="hint">Environmental modifiers remain separate from original Base metrics. Different CVSS versions are compared separately.</p></template>
  </section>
</template>
<style scoped>
.vector-comparison{min-width:0;padding:12px;border:1px solid var(--line);border-radius:6px;margin:12px 0;background:var(--surface)}.vector-heading{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.vector-heading h3{font-size:.95rem;margin:0}.vector-controls{display:flex;align-items:center;gap:10px;flex-wrap:wrap;min-width:0;font-size:.8rem}.vector-controls label{display:flex;align-items:center;gap:5px;margin:0;min-width:0}.vector-controls select{width:auto;max-width:260px;min-width:0;padding:4px;font-size:.8rem}.vector-controls input{width:auto;margin:0}.hint{font-size:.8rem;color:var(--muted);margin:7px 0;line-height:1.5}.vector-scroll{overflow:auto;max-width:100%}table{border-collapse:collapse;width:100%;font-size:.8rem}th,td{padding:7px;text-align:left;vertical-align:top;border-top:1px solid var(--line);white-space:nowrap}th{font-weight:500}th small{display:block;font-weight:400;color:var(--muted);max-width:160px;white-space:normal;font-size:.75rem}th:first-child{min-width:140px;max-width:280px;white-space:normal;overflow-wrap:anywhere}td{font-variant-numeric:tabular-nums}code{display:block;max-width:42ch;white-space:normal;overflow-wrap:anywhere;font-size:.75rem;margin-top:4px}.metric-cell{display:inline-block;padding:4px 7px;border-radius:4px;background:var(--bg)}.metric-cell small{display:block;font-size:.72rem}.metric-cell.added{background:var(--accent-soft);color:var(--accent)}.metric-cell.changed{border:1px solid var(--muted)}@media(max-width:550px){.vector-controls{align-items:flex-start}.vector-controls label:first-of-type{flex-wrap:wrap}.vector-controls select{max-width:210px}}
</style>
