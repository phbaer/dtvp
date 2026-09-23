<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, useId, watch } from 'vue'
import { getSsvcExploitation, getSsvcModels } from '../lib/api'
import { evaluateSsvc, ssvcLabel, ssvcModelId, type SsvcEnrichment, type SsvcModel, type SsvcSelection, type SsvcSummary } from '../lib/ssvc'

const props = withDefaults(defineProps<{
    modelValue: SsvcSelection | null; summary?: SsvcSummary; disabled?: boolean;
    cves?: string[]; active?: boolean; allowAutofill?: boolean;
}>(), { active: true, allowAutofill: true })
const emit = defineEmits<{ 'update:modelValue': [value: SsvcSelection | null] }>()
const models = ref<SsvcModel[]>([])
const error = ref('')
const loading = ref(true)
const id = useId()
const model = computed(() => props.modelValue
    ? models.value.find(m => ssvcModelId(m) === props.modelValue?.model && m.version === props.modelValue?.version)
    : models.value[0])
const points = computed(() => Object.entries(model.value?.decision_points || {}).filter(([key]) => key !== model.value?.outcome))
const outcome = computed(() => model.value ? evaluateSsvc(model.value, props.modelValue?.answers || {}) : null)
const decision = computed(() => model.value?.decision_points[model.value.outcome]?.values.find(v => v.key === outcome.value))
const exploitation = 'ssvc:E:1.1.0'
const cves = computed(() => [...new Set((props.cves || []).map(cve => cve.trim().toUpperCase()).filter(cve => /^CVE-\d{4}-\d{4,19}$/.test(cve)))].sort())
const enrichment = ref<SsvcEnrichment | null>(null)
const fetching = ref(false)
const fetchError = ref('')
const cooldown = ref(0)
let request = 0
let edited = false
let attempted = false
let timer: ReturnType<typeof setInterval> | undefined

async function fetchEvidence(refresh = false) {
    if (!cves.value.length || cves.value.length > 20 || !props.active || props.disabled || fetching.value || (cooldown.value > 0 && refresh)) return
    const sequence = ++request
    attempted = true
    fetching.value = true
    fetchError.value = ''
    try {
        const result = await getSsvcExploitation(cves.value, refresh)
        if (sequence !== request) return
        enrichment.value = result
        cooldown.value = result.retry_after
        if (result.auto_fill && props.active && !props.disabled && props.allowAutofill && !edited
            && !props.modelValue?.answers[exploitation] && !props.summary?.assessed && !props.summary?.invalid) useSuggestion()
    } catch {
        if (sequence === request) {
            fetchError.value = 'Could not fetch official evidence. Exploitation is unchanged.'
            cooldown.value = 60
        }
    } finally { if (sequence === request) fetching.value = false }
}

function useSuggestion() {
    const suggestion = enrichment.value?.suggestion
    if (!suggestion || !model.value) return
    update(exploitation, suggestion.value, suggestion.token)
}

function clear() {
    edited = true
    emit('update:modelValue', null)
}

watch(() => cves.value.join(','), () => {
    request++
    attempted = false
    edited = false
    fetching.value = false
    enrichment.value = null
    cooldown.value = 0
    fetchError.value = ''
})
watch(() => [props.active, props.disabled, model.value, cves.value.join(',')], () => {
    if (props.active && !props.disabled && model.value && !attempted) void fetchEvidence()
}, { immediate: true })
onMounted(() => { timer = setInterval(() => { if (cooldown.value > 0) cooldown.value-- }, 1000) })
onUnmounted(() => { request++; clearInterval(timer) })

async function load() {
    loading.value = true
    error.value = ''
    try { models.value = await getSsvcModels() }
    catch { error.value = 'Could not load SSVC rules.' }
    finally { loading.value = false }
}
onMounted(load)

function update(key: string, value: string, evidence?: string) {
    if (!model.value) return
    if (key === exploitation) edited = true
    const answers = { ...props.modelValue?.answers }
    if (value) answers[key] = value
    else delete answers[key]
    emit('update:modelValue', { model: ssvcModelId(model.value), version: model.value.version, answers, rationale: props.modelValue?.rationale || '',
        exploitation_evidence: key === exploitation ? evidence || null : props.modelValue?.exploitation_evidence })
}
function setRationale(value: string) {
    if (!model.value) return
    emit('update:modelValue', { model: ssvcModelId(model.value), version: model.value.version, answers: { ...props.modelValue?.answers }, rationale: value,
        exploitation_evidence: props.modelValue?.exploitation_evidence })
}
</script>

<template>
    <section class="space-y-3 rounded border border-gray-700 bg-gray-800 p-3" data-testid="ssvc-calculator">
        <div class="flex items-center justify-between gap-2">
            <h6 class="text-xs font-bold text-gray-300">SSVC · Deployment priority</h6>
            <button v-if="modelValue || summary?.assessed || summary?.invalid" type="button" :disabled="disabled" class="text-xs text-gray-400 hover:text-white disabled:opacity-50" @click="clear">Clear SSVC</button>
        </div>
        <p class="text-xs text-gray-400">Independent of CVSS. Saved with the global assessment for the selected findings.</p>
        <p v-if="summary" class="text-xs text-gray-400">Saved: {{ ssvcLabel(summary.status) }} · {{ summary.assessed }} assessed / {{ summary.assessed + summary.missing + summary.invalid }} findings</p>
        <p v-if="summary && ['MIXED', 'INVALID', 'INCOMPLETE'].includes(summary.status)" class="text-xs text-amber-300">Saved findings differ, are incomplete, or contain unsupported data. Editing replaces SSVC on the selected findings.</p>
        <p v-if="loading" class="text-xs text-gray-400">Loading rules…</p>
        <p v-else-if="error" role="alert" class="text-xs text-red-300">{{ error }} <button type="button" class="underline" @click="load">Retry</button></p>
        <p v-else-if="!model" role="alert" class="text-xs text-amber-300">Unsupported saved rule version. Clear SSVC to start a new assessment.</p>
        <template v-else>
            <p class="text-xs text-gray-400">CERT/CC {{ model.name }} · v{{ model.version }}</p>
            <div v-for="[key, point] in points" :key="key" class="space-y-1">
                <div class="flex items-center justify-between gap-2">
                    <label :for="`${id}-${key}`" class="block text-xs font-semibold text-gray-300">{{ point.name }}</label>
                    <button v-if="key === exploitation && cves.length && cves.length <= 20 && enrichment?.enabled !== false" type="button" data-testid="ssvc-refresh"
                        :disabled="disabled || fetching || cooldown > 0" class="text-xs text-blue-300 disabled:opacity-50" @click="fetchEvidence(true)">
                        {{ fetching ? 'Checking…' : cooldown > 0 ? `Refresh (${cooldown}s)` : 'Refresh evidence' }}
                    </button>
                </div>
                <select :id="`${id}-${key}`" :value="modelValue?.answers[key] || ''" :disabled="disabled" class="w-full rounded border border-gray-600 bg-gray-900 p-1.5 text-xs" @change="update(key, ($event.target as HTMLSelectElement).value)">
                    <option value="">Not assessed</option>
                    <option v-for="value in point.values" :key="value.key" :value="value.key">{{ value.name }}</option>
                </select>
                <p v-if="modelValue?.answers[key]" class="text-xs text-gray-400">{{ point.values.find(v => v.key === modelValue?.answers[key])?.definition }}</p>
                <div v-if="key === exploitation" class="space-y-1 text-xs text-gray-400">
                    <p v-if="!cves.length">No CVE identifier available for official-source lookup.</p>
                    <p v-else-if="cves.length > 20">More than 20 CVE aliases; assess Exploitation manually.</p>
                    <p v-if="fetchError" role="alert">{{ fetchError }}</p>
                    <p v-if="enrichment?.enabled === false">Official-source enrichment is disabled.</p>
                    <template v-if="enrichment?.enabled">
                        <p v-if="enrichment.suggestion">Suggested: {{ point.values.find(v => v.key === enrichment?.suggestion?.value)?.name }} · {{ enrichment.suggestion.source }}
                            <span v-if="enrichment.suggestion.stale" class="text-amber-300"> (stale evidence)</span>
                            <button v-if="modelValue?.exploitation_evidence !== enrichment.suggestion.token" type="button" data-testid="ssvc-use-suggestion" :disabled="disabled" class="ml-2 text-blue-300 disabled:opacity-50" @click="useSuggestion">Use suggestion</button>
                            <span v-else> · Selected; saved only with assessment.</span>
                        </p>
                        <p v-else>No conclusive suggestion. Absence from KEV does not mean no exploitation.</p>
                        <p v-for="source in enrichment.sources" :key="`${source.source}-${source.cve}`">
                            <a :href="source.url" target="_blank" rel="noopener noreferrer" class="text-blue-300">{{ source.source }} · {{ source.cve }} ↗</a>
                            · {{ source.status.replaceAll('_', ' ') }} · checked {{ source.checked_at || 'never' }}
                            <span v-if="source.assessed_at"> · source assessment {{ source.assessed_at }}</span>
                            <span v-if="source.error" class="text-amber-300"> · {{ source.error }}</span>
                        </p>
                    </template>
                </div>
                <details class="text-xs text-gray-400"><summary class="cursor-pointer">Definitions</summary><p v-if="point.definition">{{ point.definition }}</p><p v-for="value in point.values" :key="value.key" class="mt-1"><strong>{{ value.name }}:</strong> {{ value.definition }}</p></details>
            </div>
            <p role="status" class="text-sm font-semibold text-purple-200">Priority: {{ decision?.name || 'Incomplete — answer every question' }}</p>
            <p v-if="decision?.definition" class="text-xs text-gray-400">{{ decision.definition }}</p>
            <label :for="`${id}-rationale`" class="block text-xs font-semibold text-gray-300">SSVC rationale</label>
            <textarea :id="`${id}-rationale`" :value="modelValue?.rationale || ''" :disabled="disabled" maxlength="4000" rows="2" class="w-full rounded border border-gray-600 bg-gray-900 p-1.5 text-xs" @input="setRationale(($event.target as HTMLTextAreaElement).value)" />
            <p v-if="summary?.record" class="text-xs text-gray-500">Last assessed by {{ summary.record.assessor }} · {{ summary.record.assessed_at }}</p>
            <div class="flex gap-3 text-xs text-blue-300"><a :href="model.documentation" target="_blank" rel="noopener noreferrer">Model documentation ↗</a><a :href="model.calculator" target="_blank" rel="noopener noreferrer">Official calculator ↗</a></div>
        </template>
    </section>
</template>
