<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { Zap, Loader2, CheckCircle, XCircle, AlertTriangle, ChevronDown, ChevronUp, Clock } from 'lucide-vue-next'
import type { AnalysisQueueItem, CodeAnalysisAssessResponse, CodeAnalysisAssessment, CodeAnalysisComponentResult, CodeAnalysisCvssAdjustment, CodeAnalysisStepFindings } from '../lib/api'
import { analysisQueueStore } from '../lib/analysisQueueStore'

const ALL_COMPONENTS = '__all__'

const props = defineProps<{
    vulnId: string
    cvssVector?: string
    componentNames: string[]
}>()

const emit = defineEmits<{
    (e: 'apply-result', result: CodeAnalysisAssessResponse, components: string[]): void
}>()

const userGuidance = ref('')
const error = ref<string | null>(null)
const result = ref<CodeAnalysisAssessResponse | null>(null)
const stepsExpanded = ref(false)
const selectedComponent = ref<string>(ALL_COMPONENTS)
const submitting = ref(false)

// Track queue IDs for items submitted from this panel
const pendingQueueIds = ref<string[]>([])
const analyzedComponents = ref<string[]>([])

// Severity ordering for worst-wins merging
const VERDICT_SEVERITY: Record<string, number> = {
    affected: 3,
    inconclusive: 2,
    'not affected': 1,
    not_affected: 1,
}

const uniqueComponents = computed(() => {
    const seen = new Set<string>()
    return props.componentNames.filter(n => {
        const lower = n.toLowerCase()
        if (seen.has(lower)) return false
        seen.add(lower)
        return true
    })
})

const componentOptions = computed(() => {
    const items = uniqueComponents.value
    if (items.length <= 1) return items
    return [ALL_COMPONENTS, ...items]
})

// Find active queue items for this vulnerability
const activeQueueItems = computed(() => {
    return analysisQueueStore.items.value.filter(
        i => i.vuln_id === props.vulnId && (i.status === 'queued' || i.status === 'running')
    )
})

const queueStatus = computed(() => {
    if (activeQueueItems.value.length === 0) return 'idle'
    if (activeQueueItems.value.some(i => i.status === 'running')) return 'running'
    return 'queued'
})

const queuePosition = computed(() => {
    const queued = activeQueueItems.value.filter(i => i.status === 'queued')
    if (queued.length === 0) return 0
    return Math.min(...queued.map(i => i.position))
})

const statusLabel = computed(() => {
    if (submitting.value) return 'Submitting…'
    switch (queueStatus.value) {
        case 'idle': return result.value ? 'Complete' : ''
        case 'queued': return queuePosition.value > 0 ? `Queue #${queuePosition.value}` : 'Queued…'
        case 'running': return 'Analyzing…'
        default: return ''
    }
})

const statusClass = computed(() => {
    if (submitting.value) return 'text-gray-400'
    switch (queueStatus.value) {
        case 'queued': return 'text-yellow-400'
        case 'running': return 'text-blue-400'
        default: return result.value ? 'text-green-400' : 'text-gray-400'
    }
})

const isActive = computed(() =>
    submitting.value || activeQueueItems.value.length > 0
)

const verdictColor = computed(() => {
    if (!result.value) return ''
    const v = result.value.assessment.verdict.toLowerCase()
    if (v === 'affected') return 'text-red-400'
    if (v === 'not affected' || v === 'not_affected') return 'text-green-400'
    return 'text-yellow-400'
})

const confidenceBadge = computed(() => {
    if (!result.value) return ''
    const c = result.value.assessment.confidence.toLowerCase()
    if (c === 'high') return 'bg-green-700/30 text-green-300 border-green-600/40'
    if (c === 'medium') return 'bg-yellow-700/30 text-yellow-300 border-yellow-600/40'
    return 'bg-gray-700/30 text-gray-300 border-gray-600/40'
})

const stepStatusIcon = (status: string) => {
    if (status === 'pass') return CheckCircle
    if (status === 'fail') return XCircle
    return AlertTriangle
}

const stepStatusColor = (status: string) => {
    if (status === 'pass') return 'text-green-400'
    if (status === 'fail') return 'text-red-400'
    return 'text-yellow-400'
}

function worstCvss(a: CodeAnalysisCvssAdjustment | undefined, b: CodeAnalysisCvssAdjustment | undefined): CodeAnalysisCvssAdjustment | undefined {
    if (!a) return b
    if (!b) return a
    return a.adjusted_score >= b.adjusted_score ? a : b
}

function mergeCheckedVersions(results: { component: string; response: CodeAnalysisAssessResponse }[]): string[] {
    const merged = new Set<string>()
    for (const { response } of results) {
        for (const version of response.versions_checked || []) {
            if (version) {
                merged.add(version)
            }
        }
    }
    return [...merged]
}

function mergeResults(results: { component: string; response: CodeAnalysisAssessResponse }[]): CodeAnalysisAssessResponse {
    let worstAssessment: CodeAnalysisAssessment = results[0].response.assessment
    let allSteps: CodeAnalysisStepFindings[] = []
    const componentResults: CodeAnalysisComponentResult[] = []

    for (const { component, response } of results) {
        const cur = response.assessment
        const curSeverity = VERDICT_SEVERITY[cur.verdict.toLowerCase()] ?? 0
        const worstSeverity = VERDICT_SEVERITY[worstAssessment.verdict.toLowerCase()] ?? 0

        componentResults.push({
            component,
            assessment: cur,
            versions_checked: response.versions_checked,
        })

        if (curSeverity > worstSeverity ||
            (curSeverity === worstSeverity && (cur.adjusted_cvss?.adjusted_score ?? 0) > (worstAssessment.adjusted_cvss?.adjusted_score ?? 0))) {
            worstAssessment = {
                ...cur,
                adjusted_cvss: worstCvss(worstAssessment.adjusted_cvss, cur.adjusted_cvss),
                summary: cur.summary,
                reasoning: cur.reasoning,
            }
        } else {
            worstAssessment = {
                ...worstAssessment,
                adjusted_cvss: worstCvss(worstAssessment.adjusted_cvss, cur.adjusted_cvss),
            }
        }

        allSteps = allSteps.concat(response.steps.map(s => ({
            ...s,
            title: `[${component}] ${s.title}`,
        })))
    }

    const summaryParts = results.map(r => `${r.component}: ${r.response.assessment.verdict}`)
    worstAssessment = {
        ...worstAssessment,
        summary: `Combined analysis for ${results.length} components. ${summaryParts.join('; ')}`,
        reasoning: 'Global result merged from the latest completed analysis for each selected component.',
    }

    return {
        assessment: worstAssessment,
        steps: allSteps,
        versions_checked: mergeCheckedVersions(results),
        component_results: componentResults,
    }
}

// Collected results for multi-component merging
const collectedResults = ref<{ component: string; response: CodeAnalysisAssessResponse }[]>([])
let expectedTargets: string[] = []

const handleComponentComplete = (component: string, res: CodeAnalysisAssessResponse) => {
    collectedResults.value.push({ component, response: res })

    if (collectedResults.value.length >= expectedTargets.length) {
        // All components done — merge and set result
        if (collectedResults.value.length === 1) {
            result.value = collectedResults.value[0].response
        } else {
            result.value = mergeResults(collectedResults.value)
        }
        analyzedComponents.value = expectedTargets
    }
}

const handleComponentError = (component: string, err: string) => {
    error.value = `[${component}] ${err}`
}

const startScan = async () => {
    submitting.value = true
    error.value = null
    result.value = null
    collectedResults.value = []
    pendingQueueIds.value = []

    const targets = selectedComponent.value === ALL_COMPONENTS
        ? uniqueComponents.value
        : [selectedComponent.value]

    expectedTargets = [...targets]
    analyzedComponents.value = []

    try {
        for (const comp of targets) {
            const item = await analysisQueueStore.submit(
                props.vulnId,
                comp,
                props.cvssVector,
                userGuidance.value.trim() || undefined,
                (res) => handleComponentComplete(comp, res),
                (err) => handleComponentError(comp, err),
            )
            pendingQueueIds.value.push(item.queue_id)
        }
    } catch (e: any) {
        error.value = e?.message || 'Failed to submit to queue.'
    } finally {
        submitting.value = false
    }
}

const applyResult = () => {
    if (result.value) {
        emit('apply-result', result.value, analyzedComponents.value)
    }
}

// Completed queue items for this vuln (any component)
const completedQueueItems = computed(() => {
    return analysisQueueStore.items.value.filter(
        i => i.vuln_id === props.vulnId && i.status === 'completed'
    )
})

// Load the most recent completed result for the current component selection
const loadCompletedResult = async () => {
    if (isActive.value) return // Don't overwrite active state

    const targets = selectedComponent.value === ALL_COMPONENTS
        ? uniqueComponents.value
        : [selectedComponent.value]

    const completedForTargets = targets
        .map(comp => completedQueueItems.value.find(i => i.component_name === comp))
        .filter((i): i is NonNullable<typeof i> => !!i)

    if (completedForTargets.length === 0) return

    const results: { component: string; response: CodeAnalysisAssessResponse }[] = []

    for (const item of completedForTargets) {
        const res = await analysisQueueStore.fetchResult(item.queue_id)
        if (res) {
            results.push({ component: item.component_name, response: res })
        }
    }

    if (results.length === 0) return

    if (results.length === 1) {
        result.value = results[0].response
    } else {
        result.value = mergeResults(results)
    }
    analyzedComponents.value = results.map(r => r.component)
}

const viewCompletedResult = async (item: AnalysisQueueItem) => {
    const res = await analysisQueueStore.fetchResult(item.queue_id)
    if (!res) return

    result.value = res
    analyzedComponents.value = [item.component_name]
    if (selectedComponent.value !== item.component_name) {
        selectedComponent.value = item.component_name
    }
}

// On mount, check if there are completed results to display
onMounted(() => {
    loadCompletedResult()
})

// When the component selection changes, try loading completed results
watch(selectedComponent, () => {
    if (!isActive.value) {
        result.value = null
        loadCompletedResult()
    }
})
</script>

<template>
    <div class="border border-cyan-700/40 rounded bg-cyan-950/10 p-3 space-y-3">
        <div class="flex items-center justify-between">
            <h5 class="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-cyan-400">
                <Zap :size="14" />
                Code Analysis
            </h5>
            <div class="flex items-center gap-2">
                <span v-if="statusLabel" class="text-[10px] font-semibold" :class="statusClass">
                    <Loader2 v-if="queueStatus === 'running' || submitting" :size="10" class="inline animate-spin mr-1" />
                    <Clock v-else-if="queueStatus === 'queued'" :size="10" class="inline mr-1" />
                    {{ statusLabel }}
                </span>
            </div>
        </div>

        <!-- Active queue items for this vuln -->
        <div v-if="activeQueueItems.length > 0 || completedQueueItems.length > 0" class="space-y-1">
            <div
                v-for="qi in activeQueueItems"
                :key="qi.queue_id"
                class="flex items-center justify-between px-2 py-1 rounded text-[10px]"
                :class="{
                    'bg-yellow-900/20 border border-yellow-700/30': qi.status === 'queued',
                    'bg-blue-900/20 border border-blue-700/30': qi.status === 'running',
                }"
            >
                <div class="flex items-center gap-2">
                    <Loader2 v-if="qi.status === 'running'" :size="10" class="animate-spin text-blue-400" />
                    <Clock v-else :size="10" class="text-yellow-400" />
                    <span class="text-gray-300 font-mono">{{ qi.component_name }}</span>
                    <span v-if="qi.status === 'queued' && qi.position > 0" class="text-yellow-400 font-bold">#{{ qi.position }}</span>
                    <span class="uppercase font-semibold" :class="qi.status === 'running' ? 'text-blue-400' : 'text-yellow-400'">{{ qi.status }}</span>
                </div>
                <button
                    v-if="qi.status === 'queued'"
                    @click="analysisQueueStore.cancel(qi.queue_id)"
                    class="text-gray-600 hover:text-red-400 cursor-pointer text-[9px] uppercase font-bold"
                >
                    Cancel
                </button>
            </div>
            <!-- Completed queue items -->
            <div
                v-for="qi in completedQueueItems"
                :key="qi.queue_id"
                class="flex items-center justify-between px-2 py-1 rounded text-[10px] bg-green-900/10 border border-green-700/20 cursor-pointer hover:bg-green-900/20"
                @click="viewCompletedResult(qi)"
            >
                <div class="flex items-center gap-2">
                    <CheckCircle :size="10" class="text-green-400" />
                    <span class="text-gray-300 font-mono">{{ qi.component_name }}</span>
                    <span class="uppercase font-semibold text-green-400">completed</span>
                </div>
                <span class="text-[9px] text-cyan-400 font-semibold uppercase">View Result</span>
            </div>
        </div>

        <!-- Inputs row -->
        <div class="grid grid-cols-[1fr_1fr_auto] gap-3 items-end">
            <!-- Component selector -->
            <div>
                <label for="code-analysis-component" class="block text-[10px] font-semibold text-gray-500 uppercase mb-1">Component</label>
                <select
                    id="code-analysis-component"
                    v-model="selectedComponent"
                    :disabled="isActive"
                    class="w-full p-1.5 rounded bg-gray-900 border border-gray-700 focus:border-cyan-500 text-xs disabled:opacity-50"
                >
                    <option v-for="c in componentOptions" :key="c" :value="c">
                        {{ c === '__all__' ? `All Components (${uniqueComponents.length})` : c }}
                    </option>
                </select>
            </div>

            <!-- User guidance -->
            <div>
                <label for="code-analysis-guidance" class="block text-[10px] font-semibold text-gray-500 uppercase mb-1">Additional Guidance</label>
                <input
                    id="code-analysis-guidance"
                    v-model="userGuidance"
                    :disabled="isActive"
                    placeholder="e.g. Focus on HTTP request handlers…"
                    class="w-full p-1.5 rounded bg-gray-900 border border-gray-700 focus:border-cyan-500 text-xs disabled:opacity-50"
                />
            </div>

            <!-- Start button -->
            <button
                @click="startScan"
                :disabled="isActive"
                class="flex items-center justify-center gap-2 px-4 py-1.5 rounded text-xs font-bold transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap"
                :class="isActive
                    ? 'bg-cyan-900/40 text-cyan-400 border border-cyan-700/40'
                    : 'bg-cyan-600 hover:bg-cyan-700 text-white'"
            >
                <Loader2 v-if="isActive" :size="14" class="animate-spin" />
                <Zap v-else :size="14" />
                {{ isActive ? (queueStatus === 'running' ? 'Running…' : 'Queued') : 'Analyze' }}
            </button>
        </div>

        <!-- Error -->
        <div v-if="error" class="flex items-start gap-2 p-2 rounded bg-red-900/20 border border-red-700/40 text-xs text-red-300">
            <XCircle :size="14" class="shrink-0 mt-0.5" />
            <span>{{ error }}</span>
        </div>

        <!-- Result -->
        <div v-if="result" class="space-y-3">
            <!-- Verdict banner -->
            <div class="flex items-center justify-between p-2 rounded border" :class="{
                'bg-red-900/20 border-red-700/40': result.assessment.affected,
                'bg-green-900/20 border-green-700/40': !result.assessment.affected,
            }">
                <div class="flex items-center gap-2">
                    <component :is="result.assessment.affected ? AlertTriangle : CheckCircle" :size="16" :class="verdictColor" />
                    <span class="text-sm font-bold" :class="verdictColor">{{ result.assessment.verdict }}</span>
                </div>
                <div class="flex items-center gap-2">
                    <span class="text-[10px] px-2 py-0.5 rounded border" :class="confidenceBadge">
                        {{ result.assessment.confidence }} confidence
                    </span>
                    <span class="text-[10px] text-gray-400">{{ result.assessment.exposure }}</span>
                </div>
            </div>

            <!-- Summary + CVSS side by side -->
            <div class="grid md:grid-cols-2 gap-3">
                <div class="space-y-2">
                    <div class="text-xs text-gray-300">{{ result.assessment.summary }}</div>
                    <div v-if="result.versions_checked?.length" class="space-y-1">
                        <div class="text-[10px] font-semibold text-gray-500 uppercase">Versions Checked</div>
                        <ul class="text-[10px] text-gray-400 list-disc list-inside space-y-0.5">
                            <li v-for="version in result.versions_checked" :key="version">{{ version }}</li>
                        </ul>
                    </div>
                    <div class="text-[10px] text-gray-400 leading-relaxed">
                        <span class="font-semibold text-gray-500 uppercase">Reasoning: </span>{{ result.assessment.reasoning }}
                    </div>
                </div>

                <!-- CVSS adjustment -->
                <div v-if="result.assessment.adjusted_cvss" class="p-2 rounded bg-gray-800/50 border border-gray-700/50 space-y-1.5">
                    <div class="flex items-center gap-3 text-xs">
                        <span class="text-gray-500">CVSS</span>
                        <span class="font-mono font-bold text-yellow-400">{{ result.assessment.adjusted_cvss.original_score }}</span>
                        <span class="text-gray-600">→</span>
                        <span class="font-mono font-bold text-purple-400">{{ result.assessment.adjusted_cvss.adjusted_score }}</span>
                    </div>
                    <div v-if="result.assessment.adjusted_cvss.adjusted_vector" class="text-[10px] font-mono text-gray-500 truncate" :title="result.assessment.adjusted_cvss.adjusted_vector">
                        {{ result.assessment.adjusted_cvss.adjusted_vector }}
                    </div>
                    <div class="text-[10px] text-gray-400">{{ result.assessment.adjusted_cvss.summary }}</div>
                    <ul v-if="result.assessment.adjusted_cvss.reasons.length" class="text-[10px] text-gray-500 list-disc list-inside space-y-0.5">
                        <li v-for="(reason, i) in result.assessment.adjusted_cvss.reasons" :key="i">{{ reason }}</li>
                    </ul>
                </div>
            </div>

            <!-- Pipeline steps -->
            <div v-if="result.steps.length">
                <button
                    @click="stepsExpanded = !stepsExpanded"
                    class="flex items-center gap-1.5 text-[10px] font-semibold text-gray-500 hover:text-gray-400 cursor-pointer mb-1"
                >
                    <component :is="stepsExpanded ? ChevronUp : ChevronDown" :size="10" />
                    Pipeline Steps ({{ result.steps.length }})
                </button>
                <div v-if="stepsExpanded" class="grid md:grid-cols-2 gap-2">
                    <div v-for="(step, i) in result.steps" :key="i" class="p-2 rounded bg-gray-800/30 border border-gray-700/30">
                        <div class="flex items-center gap-2 mb-1">
                            <component :is="stepStatusIcon(step.status)" :size="12" :class="stepStatusColor(step.status)" />
                            <span class="text-[10px] font-semibold text-gray-300">{{ step.title }}</span>
                            <span class="text-[9px] font-mono text-gray-600">({{ step.step }})</span>
                        </div>
                        <ul v-if="step.evidence.length" class="text-[10px] text-gray-500 list-disc list-inside space-y-0.5 ml-4">
                            <li v-for="(ev, j) in step.evidence" :key="j">{{ ev }}</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Apply button -->
            <button
                @click="applyResult"
                class="w-full flex items-center justify-center gap-2 px-3 py-2 rounded text-xs font-bold bg-cyan-600 hover:bg-cyan-700 text-white transition-colors cursor-pointer"
            >
                <CheckCircle :size="14" />
                Apply to Assessment
            </button>
        </div>
    </div>
</template>
