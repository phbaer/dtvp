<script setup lang="ts">
import CodeAnalysisReport from './CodeAnalysisReport.vue'
import CodeAnalysisJobDiagnostics from './CodeAnalysisJobDiagnostics.vue'
import { ref, computed, watch, onMounted, onBeforeUnmount, inject } from 'vue'
import type { Ref } from 'vue'
import { Zap, Loader2, CheckCircle, XCircle, Clock, ClipboardCheck, Eye, Ban, Trash2, MoreHorizontal, RefreshCw } from '@lucide/vue'
import {
    codeAnalysisCleanupVulnerability,
    codeAnalysisGetResult,
    codeAnalysisListVulnerabilityResults,
    listCodeEvidence,
    withdrawCodeEvidence,
} from '../lib/api'
import type { AnalysisQueueItem, CodeAnalysisAssessResponse, CodeAnalysisAssessment, CodeAnalysisComponentResult, CodeAnalysisLlmConversationTurn, CodeAnalysisResultRecord, CodeAnalysisStepFindings, CodeEvidence, CodeEvidenceTarget } from '../lib/api'
import { analysisQueueStore } from '../lib/analysisQueueStore'
import { isCodeAnalysisApplicable, codeAnalysisAssessmentState, isCodeAnalysisResultWorse } from '../lib/codeAnalysisResult'
import type { CodeAnalysisComponentRun } from '../lib/codeAnalysisResult'
import type { AutomaticAssessmentStatus } from '../lib/vulnListIndex'
import { mergeEvidenceRows } from '../lib/codeEvidence'
import type { EvidenceFilter, EvidenceRow } from '../lib/codeEvidence'
import CodeAnalysisRunOutcome from './CodeAnalysisRunOutcome.vue'
import CodeAnalysisRunDetails from './CodeAnalysisRunDetails.vue'
import CodeAnalysisRunForm from './CodeAnalysisRunForm.vue'
import type { RunFormComponentStatus } from './CodeAnalysisRunForm.vue'
import CodeEvidenceList from './CodeEvidenceList.vue'
import CodeEvidenceReader from './CodeEvidenceReader.vue'

const props = defineProps<{
    vulnId: string
    vulnAliases?: string[]
    projectName?: string
    cvssVector?: string
    componentNames: string[]
    /** Visible vulnerable findings, distinct from analyzer application targets. */
    evidenceTargets?: Pick<CodeEvidenceTarget, 'component' | 'finding_uuid'>[]
    componentTeams?: Record<string, string>
    teamScope?: string
    teamScopeAliases?: string[]
    projectVersions?: string[]
    /** @deprecated Use projectVersions. */
    affectedProductVersions?: string[]
    assessedTeams?: Set<string>
    analysisGuidance?: string
    currentState?: string
    currentJustification?: string
    currentDetails?: string
    currentTeam?: string
    currentCvssScore?: number | string | null
    currentCvssVector?: string
    currentAssigned?: string[]
    assessmentStatus?: AutomaticAssessmentStatus | null
    isReviewer?: boolean
    /** Finding UUIDs Dependency-Track currently reports for this vulnerability. */
    reportedFindingUuids?: string[]
    /** Bumped by the card after every save, so the list marks what it used. */
    refreshKey?: number
    focusEvidenceId?: string
}>()

const emit = defineEmits<{
    (e: 'apply-result', result: CodeAnalysisAssessResponse, components: string[], analysisRunIds: string[], targetTeam?: string): void
    (e: 'apply-all-results', runs: CodeAnalysisComponentRun[]): void
    (e: 'result-change', result: CodeAnalysisAssessResponse | null, components: string[]): void
    (e: 'scope-results-change', available: boolean): void
    (e: 'proposals-change', runs: CodeAnalysisComponentRun[]): void
    (e: 'evidence-loaded', records: CodeEvidence[]): void
    (e: 'apply-evidence', payload: { evidenceId: string; title: string; summary: string; state?: string; justification?: string }): void
}>()

const sessionUser = inject<Ref<{ username?: string } | null> | null>('user', null)
const currentUsername = computed(() => String(sessionUser?.value?.username || ''))

const userGuidance = ref('')
const runFormOpen = ref(false)
const moreOpen = ref(false)
const agentEvidence = ref<CodeEvidence[]>([])
const evidenceLoading = ref(false)
const evidenceFilter = ref<EvidenceFilter>('all')
const showWithdrawn = ref(false)
const selectedAgentId = ref<string | null>(null)
watch([() => props.focusEvidenceId, agentEvidence], ([id]) => {
    if (id && agentEvidence.value.some(item => item.evidence_id === id)) selectedAgentId.value = id
})
const loadingRunId = ref<string | null>(null)
const evidenceBusy = ref(false)
let evidenceLoadCounter = 0
let visibilityObserver: IntersectionObserver | null = null
const panelRoot = ref<HTMLElement | null>(null)
const error = ref<string | null>(null)
const result = ref<CodeAnalysisAssessResponse | null>(null)
const selectedComponents = ref<Set<string>>(new Set())
const submitting = ref(false)
const persistedResults = ref<CodeAnalysisResultRecord[]>([])
const historyLoading = ref(false)
const historyLoaded = ref(false)
const historyError = ref<string | null>(null)
const selectedRunId = ref<string | null>(null)
const selectedFullRecord = ref<CodeAnalysisResultRecord | null>(null)
const followUpQuestion = ref('')
const followUpComponent = ref('')
const followUpSubmitting = ref(false)
const queueActionIds = ref<Set<string>>(new Set())
const deletingRunIds = ref<Set<string>>(new Set())
const cleanupOpen = ref(false)
const cleanupBusy = ref(false)
const cleanupAssessments = ref(true)
const cleanupRuns = ref(true)
const cleanupActive = ref(false)
const cleanupMessage = ref('')
const applyingAll = ref(false)
const combinedHydrating = ref(false)
const combinedHydrationError = ref<string | null>(null)
const HISTORY_RESULT_REFRESH_ATTEMPTS = 4
const HISTORY_RESULT_REFRESH_DELAY_MS = 500
const HISTORY_PAGE_SIZE = 500
let historyLoadCounter = 0
let combinedHydrationCounter = 0

// Track queue IDs for items submitted from this panel
const pendingQueueIds = ref<string[]>([])
const analyzedComponents = ref<string[]>([])
const activeResultRunIds = ref<string[]>([])

type AnalysisBatch = {
    expectedTargets: string[]
    collected: { component: string; response: CodeAnalysisAssessResponse }[]
    queueIds: string[]
}

let analysisBatchCounter = 0
const analysisBatches = new Map<string, AnalysisBatch>()

const uniqueComponents = computed(() => {
    const seen = new Set<string>()
    return props.componentNames
        .map(n => String(n || '').trim())
        .filter(Boolean)
        .filter(n => {
            const lower = n.toLowerCase()
            if (seen.has(lower)) return false
            seen.add(lower)
            return true
        })
})

const vulnerabilityIdKeys = computed(() => new Set(
    [props.vulnId, ...(props.vulnAliases || [])]
        .map(value => String(value || '').trim().toLocaleLowerCase())
        .filter(Boolean),
))

const relevantComponentKeys = computed(() => new Set(
    uniqueComponents.value.map(component => component.toLocaleLowerCase()),
))

const teamScopeKeys = computed(() => new Set(
    [props.teamScope, ...(props.teamScopeAliases || [])]
        .map(team => String(team || '').trim().toLocaleLowerCase())
        .filter(Boolean),
))
const teamScopeKey = computed(() => String(props.teamScope || '').trim().toLocaleLowerCase())
const matchesTeamScope = (item: { context_summary?: Record<string, any> | null }) => {
    if (!teamScopeKey.value) return true
    const targetTeam = String(item.context_summary?.target_team || '').trim().toLocaleLowerCase()
    // Older/manual records do not always retain target_team. Their component
    // scope is still authoritative, while an explicit different team is not.
    return !targetTeam || teamScopeKeys.value.has(targetTeam)
}

const allSelected = computed(() =>
    uniqueComponents.value.length > 0 && uniqueComponents.value.every(c => selectedComponents.value.has(c))
)

const hasOwnedTargets = computed(() => uniqueComponents.value.length > 0)

const latestPersistedResult = computed(() => persistedResults.value[0] || null)
const latestReusableResult = computed(() => persistedResults.value.find(isReusableRecord) || null)
const hasReusableAnalysis = computed(() => Boolean(
    latestReusableResult.value || transientCompletedRecords.value.some(isReusableRecord),
))
const effectiveAssessmentStatus = computed<AutomaticAssessmentStatus | null>(() => {
    if (!teamScopeKey.value) return props.assessmentStatus || null
    if (!historyLoaded.value) return null
    const reusableRecords = persistedResults.value.filter(isReusableRecord)
    if (reusableRecords.length === 0) return null

    const coveredComponents = new Set(
        reusableRecords.map(record => record.component_name.toLocaleLowerCase()),
    )
    if (uniqueComponents.value.some(component => !coveredComponents.has(component.toLocaleLowerCase()))) {
        return 'partial'
    }
    const hasAutomatic = reusableRecords.some(record => record.source === 'automatic')
    const hasManual = reusableRecords.some(record => record.source !== 'automatic')
    if (hasAutomatic && hasManual) return 'mixed'
    return hasAutomatic ? 'auto' : 'manual'
})
const assessmentStatusLabel = computed(() => ({
    auto: 'Automatic assessment available',
    manual: 'Manual assessment available',
    mixed: 'Automatic and manual assessments available',
    partial: 'Assessment coverage is partial',
}[effectiveAssessmentStatus.value || 'auto']))
const assessmentStatusClass = computed(() => ({
    auto: 'border-cyan-700/40 bg-cyan-950/30 text-cyan-300',
    manual: 'border-blue-700/40 bg-blue-950/30 text-blue-300',
    mixed: 'border-purple-700/40 bg-purple-950/30 text-purple-300',
    partial: 'border-amber-700/40 bg-amber-950/30 text-amber-300',
}[effectiveAssessmentStatus.value || 'auto']))
const followUpParentRunId = computed(() => selectedRunId.value || latestPersistedResult.value?.analysis_run_id || null)
const selectedPersistedResult = computed(() => {
    const runId = selectedRunId.value
    if (!runId) return null
    if (
        selectedFullRecord.value
        && (
            selectedFullRecord.value.analysis_run_id === runId
            || selectedFullRecord.value.queue_id === runId
        )
    ) {
        return selectedFullRecord.value
    }
    return persistedResults.value.find(record =>
        record.analysis_run_id === runId || record.queue_id === runId
    ) || null
})

function visibleComponentName(component: string) {
    const normalized = String(component || '').trim().toLowerCase()
    return uniqueComponents.value.find(candidate => candidate.toLowerCase() === normalized)
}

const recordVisibleComponent = (record: CodeAnalysisResultRecord) => {
    const candidates = [
        record.scan_target,
        record.component_name,
        ...(record.component_names || []),
    ]
    for (const candidate of candidates) {
        const visible = visibleComponentName(String(candidate || ''))
        if (visible) return visible
    }
    return null
}


const isReusableRecord = (record: CodeAnalysisResultRecord) => (
    record.source !== 'benchmark'
    && (!record.status || record.status === 'completed')
    && (record.result ? isCodeAnalysisApplicable(record.result) : record.summary?.application_eligible === true)
)

function toggleComponent(comp: string) {
    const next = new Set(selectedComponents.value)
    if (next.has(comp)) next.delete(comp)
    else next.add(comp)
    selectedComponents.value = next
}

function toggleAll() {
    if (allSelected.value) {
        selectedComponents.value = new Set()
    } else {
        selectedComponents.value = new Set(uniqueComponents.value)
    }
}

function buildLaunchGuidance(): string | undefined {
    const parts = [
        props.analysisGuidance?.trim(),
        userGuidance.value.trim(),
    ].filter(Boolean)
    return parts.length ? parts.join('\n\n') : undefined
}

const launchGuidancePreview = computed(() => buildLaunchGuidance() || '')

watch(uniqueComponents, (comps, previousComps) => {
    if (selectedComponents.value.size === 0) {
        if (previousComps === undefined && comps.length > 0) {
            selectedComponents.value = new Set(comps)
        }
        return
    }
    const selectedLower = new Set(
        [...selectedComponents.value].map(component => component.toLowerCase()),
    )
    const retained = comps.filter(component => selectedLower.has(component.toLowerCase()))
    selectedComponents.value = new Set(
        retained.length > 0 || comps.length === 0 ? retained : comps,
    )
}, { immediate: true })

// Find active queue items for this vulnerability
const activeQueueItems = computed(() => {
    return analysisQueueStore.items.value.filter(
        i => vulnerabilityIdKeys.value.has(String(i.vuln_id || '').toLocaleLowerCase())
            && relevantComponentKeys.value.has(String(i.component_name || '').toLocaleLowerCase())
            && matchesTeamScope(i)
            && (i.status === 'queued' || i.status === 'running')
    )
})

const failedDiagnosticItems = computed(() => analysisQueueStore.items.value.filter(
    i => vulnerabilityIdKeys.value.has(String(i.vuln_id || '').toLocaleLowerCase())
        && relevantComponentKeys.value.has(String(i.component_name || '').toLocaleLowerCase())
        && matchesTeamScope(i) && (i.status === 'failed' || i.status === 'cancelled')
))

const activeComponentNames = computed(() => new Set(
    activeQueueItems.value.map(item => item.component_name.toLowerCase()),
))

const startableSelectedComponents = computed(() =>
    [...selectedComponents.value].filter(component => !activeComponentNames.value.has(component.toLowerCase()))
)

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

const controlsBusy = computed(() => submitting.value || followUpSubmitting.value)
const canStartScan = computed(() =>
    !controlsBusy.value && hasOwnedTargets.value && startableSelectedComponents.value.length > 0
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

const stringifyTicketValue = (value: unknown): string => {
    if (value == null || value === '') return ''
    if (typeof value === 'string') return value.trim()
    if (typeof value === 'number' || typeof value === 'boolean') return String(value)
    try {
        return JSON.stringify(value)
    } catch {
        return String(value)
    }
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
    let worstResponse = results[0].response
    let allSteps: CodeAnalysisStepFindings[] = []
    let allConversationTurns: CodeAnalysisLlmConversationTurn[] = []
    const componentResults: CodeAnalysisComponentResult[] = []

    for (const { component, response } of results) {
        const cur = response.assessment
        componentResults.push({
            component,
            assessment: cur,
            versions_checked: response.versions_checked,
        })

        if (isCodeAnalysisResultWorse(response, worstResponse)) worstResponse = response

        allSteps = allSteps.concat(response.steps.map(s => ({
            ...s,
            title: `[${component}] ${s.title}`,
        })))
        allConversationTurns = allConversationTurns.concat(
            (response.llm_conversation || []).map(turn => ({
                ...turn,
                component: turn.component || component,
            }))
        )
    }

    let worstAssessment: CodeAnalysisAssessment = worstResponse.assessment
    const summaryParts = results.map(r => `${r.component}: ${r.response.assessment.verdict}`)
    const rationaleParts = results
        .map(({ component, response }) => {
            const rationale = String(response.assessment.reasoning || response.assessment.summary || '').trim()
            return rationale ? `${component}: ${rationale}` : ''
        })
        .filter(Boolean)
    const worstComponents = results
        .filter(({ response }) => response.assessment.verdict === worstAssessment.verdict)
        .map(({ component }) => component)
    const ticketParts = results
        .map(r => stringifyTicketValue(r.response.assessment.ticket_text))
        .filter(Boolean)
    const vulnerabilitySummary = worstAssessment.executive_summary?.vulnerability
        || results.map(({ response }) => response.assessment.executive_summary?.vulnerability).find(Boolean)
    const executiveReasons = [...new Set(results.flatMap(({ component, response }) => {
        const reasons = response.assessment.executive_summary?.why?.length
            ? response.assessment.executive_summary.why
            : [response.assessment.reasoning || response.assessment.summary].filter(Boolean)
        return reasons.map(reason => `${component}: ${reason}`)
    }))]
    const worstTargetSummary = worstComponents.length
        ? ` Controlling target(s): ${worstComponents.join(', ')}.`
        : ''
    worstAssessment = {
        ...worstAssessment,
        application_eligible: results.every(({ response }) => isCodeAnalysisApplicable(response)),
        rescoring_eligible: results.every(({ response }) => response.assessment.rescoring_eligible === true),
        ...(vulnerabilitySummary ? {
            executive_summary: {
                vulnerability: vulnerabilitySummary,
                assessment: `Disposition: ${worstAssessment.verdict}. Confidence: ${worstAssessment.confidence}. Exposure: ${worstAssessment.exposure}. Scope: combined assessment of ${results.length} targets.${worstTargetSummary}`,
                why: executiveReasons,
            },
        } : {}),
        summary: `Combined analysis for ${results.length} components. ${summaryParts.join('; ')}`,
        reasoning: [
            `Worst-case verdict: ${worstAssessment.verdict}${worstComponents.length ? ` (${worstComponents.join(', ')})` : ''}.`,
            ...rationaleParts,
        ].join(' '),
        ...(ticketParts.length ? { ticket_text: ticketParts.join('\n\n---\n\n') } : {}),
    }

    return {
        assessment: worstAssessment,
        steps: allSteps,
        versions_checked: mergeCheckedVersions(results),
        component_results: componentResults,
        llm_conversation: allConversationTurns,
    }
}

// Collected results for the latest displayed multi-component merge
const collectedResults = ref<{ component: string; response: CodeAnalysisAssessResponse }[]>([])

const beginAnalysisBatch = (targets: string[]): [string, AnalysisBatch] => {
    const batchId = `batch-${++analysisBatchCounter}`
    const batch: AnalysisBatch = {
        expectedTargets: [...targets],
        collected: [],
        queueIds: [],
    }
    analysisBatches.set(batchId, batch)
    return [batchId, batch]
}

type LoadPersistedResultsOptions = {
    expectedRunId?: string | null
    attempts?: number
    delayMs?: number
}

const waitFor = (delayMs: number) => new Promise(resolve => setTimeout(resolve, delayMs))

const recordMatchesRunId = (record: CodeAnalysisResultRecord, runId: string) =>
    record.analysis_run_id === runId || record.queue_id === runId

const handleComponentComplete = (
    batchId: string,
    component: string,
    res: CodeAnalysisAssessResponse,
    queueItem?: AnalysisQueueItem,
) => {
    const batch = analysisBatches.get(batchId)
    if (!batch) return
    batch.collected.push({ component, response: res })

    if (batch.collected.length >= batch.expectedTargets.length) {
        collectedResults.value = [...batch.collected]
        if (batch.collected.length === 1) {
            result.value = batch.collected[0].response
        } else {
            result.value = mergeResults(batch.collected)
        }
        analyzedComponents.value = batch.expectedTargets
        activeResultRunIds.value = [...batch.queueIds]
        const completedRunId = batch.expectedTargets.length === 1
            ? queueItem?.queue_id || batch.queueIds[0] || null
            : null
        selectedRunId.value = completedRunId
        selectedFullRecord.value = null
        followUpComponent.value = batch.expectedTargets[0] || ''
        analysisBatches.delete(batchId)
        void loadPersistedResults({
            expectedRunId: completedRunId,
            attempts: completedRunId ? HISTORY_RESULT_REFRESH_ATTEMPTS : 1,
            delayMs: HISTORY_RESULT_REFRESH_DELAY_MS,
        })
    }
}

const handleComponentError = (batchId: string, component: string, err: string) => {
    if (!analysisBatches.has(batchId)) return
    error.value = `[${component}] ${err}`
}

const startAnalysis = async () => {
    submitting.value = true
    error.value = null
    result.value = null
    selectedFullRecord.value = null
    collectedResults.value = []
    pendingQueueIds.value = []
    activeResultRunIds.value = []

    const targets = startableSelectedComponents.value
    if (targets.length === 0) {
        error.value = 'No selected component target is available for a new code analysis scan.'
        submitting.value = false
        return
    }

    analyzedComponents.value = []
    const [batchId, batch] = beginAnalysisBatch(targets)

    try {
        for (const comp of targets) {
            const item = await analysisQueueStore.submit(
                props.vulnId,
                comp,
                props.projectName,
                props.cvssVector,
                buildLaunchGuidance(),
                (res, item) => handleComponentComplete(batchId, comp, res, item),
                (err) => handleComponentError(batchId, comp, err),
                props.projectVersions || props.affectedProductVersions,
                'manual',
            )
            pendingQueueIds.value.push(item.queue_id)
            batch.queueIds.push(item.queue_id)
        }
    } catch (e: any) {
        error.value = e?.message || 'Failed to submit to queue.'
    } finally {
        submitting.value = false
    }
}

const startScan = async () => startAnalysis()

const loadPersistedResults = async (options: LoadPersistedResultsOptions = {}) => {
    const loadId = ++historyLoadCounter
    const expectedRunId = options.expectedRunId || null
    const attempts = Math.max(1, options.attempts ?? 1)
    const delayMs = Math.max(0, options.delayMs ?? 0)
    const componentNames = [...uniqueComponents.value]
    const vulnId = props.vulnId
    const vulnAliases = [...(props.vulnAliases || [])]
    const projectName = props.projectName || '_all_'
    historyLoading.value = true
    historyError.value = null
    try {
        if (componentNames.length === 0) {
            persistedResults.value = []
            return
        }
        for (let attempt = 0; attempt < attempts; attempt += 1) {
            const records: CodeAnalysisResultRecord[] = []
            let offset = 0
            while (true) {
                const page = await codeAnalysisListVulnerabilityResults(
                    projectName,
                    vulnId,
                    {
                        component_name: componentNames,
                        vuln_alias: vulnAliases,
                        limit: HISTORY_PAGE_SIZE,
                        offset,
                    },
                )
                if (loadId !== historyLoadCounter) return
                records.push(...page)
                if (page.length < HISTORY_PAGE_SIZE) break
                offset += page.length
            }
            const dedupedRecords = [...new Map(
                records
                    .filter(matchesTeamScope)
                    .map(record => [record.analysis_run_id, record]),
            ).values()]
            persistedResults.value = dedupedRecords

            const expectedRecord = expectedRunId
                ? dedupedRecords.find(record => recordMatchesRunId(record, expectedRunId))
                : null
            if (expectedRecord) {
                selectedRunId.value = expectedRecord.analysis_run_id
            }
            if (!followUpComponent.value && latestPersistedResult.value?.component_name) {
                followUpComponent.value = latestPersistedResult.value.component_name
            }
            if (!expectedRunId || expectedRecord || attempt === attempts - 1) {
                break
            }
            await waitFor(delayMs)
            if (loadId !== historyLoadCounter) return
        }
    } catch (err: any) {
        if (loadId !== historyLoadCounter) return
        historyError.value = err?.response?.data?.detail || err?.message || 'Unable to load analysis history.'
    } finally {
        if (loadId === historyLoadCounter) {
            historyLoaded.value = true
            historyLoading.value = false
        }
    }
}

const applyResult = () => {
    if (!isCodeAnalysisApplicable(result.value)) {
        error.value = "Analyzer result is unverified or ineligible; rerun analysis before applying it."
        return
    }
    if (result.value) {
        const persistedTeam = String(selectedPersistedResult.value?.context_summary?.target_team || '').trim()
        const mappedTeam = analyzedComponents.value
            .map(component => visibleComponentName(component) || component)
            .map(component => props.componentTeams?.[component] || '')
            .find(Boolean)
        emit(
            'apply-result',
            result.value,
            analyzedComponents.value,
            activeResultRunIds.value,
            persistedTeam || mappedTeam || undefined,
        )
    }
}

const transientCompletedRecords = computed<CodeAnalysisResultRecord[]>(() => {
    const recordedRunIds = new Set(persistedResults.value.flatMap(record => [
        record.analysis_run_id,
        record.queue_id || '',
    ]))
    const records = collectedResults.value.flatMap((entry, index): CodeAnalysisResultRecord[] => {
        const runId = activeResultRunIds.value[index] || selectedRunId.value || ''
        if (runId && recordedRunIds.has(runId)) return []
        return [{
            analysis_run_id: runId || `current-${entry.component}`,
            queue_id: runId || null,
            vuln_id: props.vulnId,
            component_name: entry.component,
            project_name: props.projectName,
            source: 'manual',
            finished_at: new Date().toISOString(),
            status: 'completed',
            context_summary: props.currentTeam ? { target_team: props.currentTeam } : null,
            summary: {
                affected: entry.response.assessment.verdict.toLocaleLowerCase() === 'affected',
                verdict: entry.response.assessment.verdict,
            },
            result: entry.response,
        }]
    })

    for (const item of completedQueueItems.value) {
        if (recordedRunIds.has(item.queue_id)) continue
        const response = item.queue_id === selectedRunId.value && result.value
            ? result.value
            : analysisQueueStore.getCachedResult(item.queue_id)
        if (!response) continue
        records.push({
            analysis_run_id: item.queue_id,
            queue_id: item.queue_id,
            vuln_id: item.vuln_id,
            component_name: item.component_name,
            project_name: item.project_name,
            source: item.source,
            submitted_by: item.submitted_by,
            submitted_at: item.submitted_at,
            started_at: item.started_at,
            finished_at: item.finished_at,
            status: item.status,
            context_summary: item.context_summary,
            summary: {
                affected: response.assessment.verdict.toLocaleLowerCase() === 'affected',
                verdict: response.assessment.verdict,
            },
            result: response,
        })
    }
    return records
})

// Latest completed result per owned component target, newest first. Include a
// completed queue result while persistence catches up so the combined draft is
// never empty immediately after an analyst opens a successful run.
const applyAllCandidates = computed(() => {
    const seen = new Set<string>()
    const candidates: { component: string, team: string, record: CodeAnalysisResultRecord }[] = []

    const eligibleRecords = [...persistedResults.value, ...transientCompletedRecords.value]
        .filter(isReusableRecord)
        .sort((left, right) => {
            const leftTime = Date.parse(left.finished_at || left.recorded_at || left.submitted_at || '') || 0
            const rightTime = Date.parse(right.finished_at || right.recorded_at || right.submitted_at || '') || 0
            return rightTime - leftTime || right.analysis_run_id.localeCompare(left.analysis_run_id)
        })

    for (const record of eligibleRecords) {

        const component = visibleComponentName(record.component_name)
        if (!component) continue

        const key = component.toLowerCase()
        if (seen.has(key)) continue
        seen.add(key)
        candidates.push({ component, team: props.componentTeams?.[component] || '', record })
    }

    return candidates
})

const applyAllTeams = computed(() => {
    const teams = new Map<string, string>()
    for (const candidate of applyAllCandidates.value) {
        const team = candidate.team.trim()
        if (team) teams.set(team.toLocaleLowerCase(), team)
    }
    return [...teams.values()]
})

const canApplyAllResults = computed(() => applyAllCandidates.value.length > 1 && applyAllTeams.value.length > 0)

const combinedCandidateRuns = computed<CodeAnalysisComponentRun[]>(() => applyAllCandidates.value.flatMap(candidate => (
    candidate.record.result
        ? [{
            component: candidate.component,
            result: candidate.record.result,
            runId: candidate.record.analysis_run_id,
        }]
        : []
)))

const combinedAssessmentPreview = computed<CodeAnalysisAssessResponse | null>(() => {
    const entries = combinedCandidateRuns.value.map(run => ({
        component: run.component,
        response: run.result,
    }))
    return entries.length ? mergeResults(entries) : null
})
const combinedTargetResults = computed(() => combinedAssessmentPreview.value?.component_results || [])
const combinedControllingTargets = computed(() => {
    const verdict = combinedAssessmentPreview.value?.assessment.verdict
    if (!verdict) return []
    return combinedTargetResults.value
        .filter(result => result.assessment.verdict === verdict)
        .map(result => result.component)
})
const allCombinedTargetsControlDecision = computed(() => (
    combinedTargetResults.value.length > 1
    && combinedControllingTargets.value.length === combinedTargetResults.value.length
))

const combinedMissingCandidates = computed(() => {
    const loaded = new Set(combinedCandidateRuns.value.map(run => run.component.toLocaleLowerCase()))
    return applyAllCandidates.value.filter(candidate => !loaded.has(candidate.component.toLocaleLowerCase()))
})

const combinedTargetReasons = (result: CodeAnalysisComponentResult): string[] => {
    const reasons = result.assessment.executive_summary?.why?.length
        ? result.assessment.executive_summary.why
        : [result.assessment.reasoning].filter(Boolean)
    const componentPrefix = `${result.component}:`.toLocaleLowerCase()
    return reasons.map(reason => {
        const text = String(reason || '').trim()
        return text.toLocaleLowerCase().startsWith(componentPrefix)
            ? text.slice(componentPrefix.length).trim()
            : text
    }).filter(Boolean)
}

const combinedTargetVerdictClass = (assessment: CodeAnalysisAssessment): string => {
    const verdict = assessment.verdict.trim().toLocaleLowerCase().replaceAll('_', ' ').replaceAll('-', ' ')
    if (assessment.affected || verdict === 'affected') return 'text-red-300'
    if (verdict.includes('probably') || verdict.includes('uncertain') || verdict.includes('inconclusive')) {
        return 'text-amber-300'
    }
    return 'text-green-300'
}
const combinedAssessmentPreviewState = computed(() => combinedAssessmentPreview.value
    ? codeAnalysisAssessmentState(combinedAssessmentPreview.value)
    : 'NOT_SET'
)
const combinedAssessmentPreviewBorderClass = computed(() => {
    if (combinedAssessmentPreviewState.value === 'EXPLOITABLE') return 'border-red-500/70 bg-red-950/15'
    if (combinedAssessmentPreviewState.value === 'IN_TRIAGE') return 'border-amber-500/70 bg-amber-950/15'
    return 'border-green-500/70 bg-green-950/10'
})
const combinedAssessmentPreviewTextClass = computed(() => {
    if (combinedAssessmentPreviewState.value === 'EXPLOITABLE') return 'text-red-300'
    if (combinedAssessmentPreviewState.value === 'IN_TRIAGE') return 'text-amber-300'
    return 'text-green-300'
})

const hydrateCombinedCandidates = async () => {
    const missing = applyAllCandidates.value.filter(candidate => !candidate.record.result)
    if (!missing.length) {
        combinedHydrationError.value = null
        return
    }

    const hydrationId = ++combinedHydrationCounter
    const requestedScope = teamScopeKey.value
    combinedHydrating.value = true
    combinedHydrationError.value = null
    const settled = await Promise.allSettled(missing.map(candidate => (
        codeAnalysisGetResult(candidate.record.analysis_run_id)
    )))
    if (hydrationId !== combinedHydrationCounter || requestedScope !== teamScopeKey.value) return

    const hydrated = new Map<string, CodeAnalysisResultRecord>()
    settled.forEach((outcome, index) => {
        if (outcome.status !== 'fulfilled' || !outcome.value?.result) return
        const record = outcome.value
        if (!relevantComponentKeys.value.has(record.component_name.toLocaleLowerCase()) || !matchesTeamScope(record)) return
        hydrated.set(missing[index].record.analysis_run_id, record)
    })
    if (hydrated.size) {
        persistedResults.value = persistedResults.value.map(record => (
            hydrated.get(record.analysis_run_id) || record
        ))
    }
    const failed = settled.length - hydrated.size
    if (failed > 0) {
        combinedHydrationError.value = `${failed} latest target result${failed === 1 ? '' : 's'} could not be loaded for the combined assessment.`
    }
    combinedHydrating.value = false
}

const applyAllTitle = computed(() => {
    const components = applyAllCandidates.value.map(candidate => candidate.component).join(', ')
    const targetTeams = applyAllTeams.value.join(', ')
    if (teamScopeKey.value) {
        return `Apply the latest analysis result of ${components} to the scoped ${targetTeams} assessment.`
    }
    return `Apply the latest analysis result of ${components} to ${targetTeams} `
        + 'and take the worst assessment over to the global assessment.'
})

const applyAllResults = async () => {
    if (applyingAll.value || !canApplyAllResults.value) return

    const requestedTeamScope = teamScopeKey.value
    applyingAll.value = true
    error.value = null
    try {
        const records = await Promise.all(applyAllCandidates.value.map(async candidate => ({
            component: candidate.component,
            record: candidate.record.result
                ? candidate.record
                : await codeAnalysisGetResult(candidate.record.analysis_run_id),
        })))

        const runs: CodeAnalysisComponentRun[] = records
            .filter(entry => entry.record.result)
            .map(entry => ({
                component: entry.component,
                result: entry.record.result as CodeAnalysisAssessResponse,
                runId: entry.record.analysis_run_id,
            }))

        if (requestedTeamScope !== teamScopeKey.value) return
        if (runs.length === 0) {
            error.value = 'No saved analysis result could be loaded for the analyzed components.'
            return
        }

        if (!runs.every(run => isCodeAnalysisApplicable(run.result))) {
            throw new Error("Some analyzer results are unverified or ineligible; rerun analysis.")
        }
        emit('apply-all-results', runs)
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Failed to load the saved analysis results.'
    } finally {
        applyingAll.value = false
    }
}

// Completed queue items for this vuln (any component)
const completedQueueItems = computed(() => {
    const persistedRunIds = new Set(persistedResults.value.flatMap(record => [
        record.analysis_run_id,
        record.queue_id || '',
    ]))
    return analysisQueueStore.items.value.filter(
        i => vulnerabilityIdKeys.value.has(String(i.vuln_id || '').toLocaleLowerCase())
            && relevantComponentKeys.value.has(String(i.component_name || '').toLocaleLowerCase())
            && matchesTeamScope(i)
            && i.status === 'completed'
            && !persistedRunIds.has(i.queue_id)
    )
})

const selectedRunQuestion = computed(() => (
    selectedPersistedResult.value?.follow_up_question
    || completedQueueItems.value.find(item => item.queue_id === selectedRunId.value)?.follow_up_question
    || null
))

const closeSelectedResult = () => {
    result.value = null
    selectedRunId.value = null
    selectedFullRecord.value = null
    analyzedComponents.value = []
    activeResultRunIds.value = []
    followUpQuestion.value = ''
}

const completedComponentNames = computed(() => {
    return new Set([
        ...completedQueueItems.value.map(i => i.component_name),
        ...persistedResults.value.map(record => record.component_name),
    ].filter(Boolean))
})

const assessedComponentNames = computed(() => {
    if (!props.componentTeams || !props.assessedTeams) return new Set<string>()
    const result = new Set<string>()
    for (const comp of uniqueComponents.value) {
        const team = props.componentTeams[comp]
        if (team && props.assessedTeams.has(team)) {
            result.add(comp)
        }
    }
    return result
})

const viewCompletedResult = async (item: AnalysisQueueItem) => {
    const requestedTeamScope = teamScopeKey.value
    const res = await analysisQueueStore.fetchResult(item.queue_id)
    if (
        !res
        || requestedTeamScope !== teamScopeKey.value
        || !relevantComponentKeys.value.has(item.component_name.toLocaleLowerCase())
        || !matchesTeamScope(item)
    ) return

    result.value = res
    analyzedComponents.value = [item.component_name]
    selectedRunId.value = item.queue_id
    activeResultRunIds.value = [item.queue_id]
    selectedFullRecord.value = null
    followUpComponent.value = item.component_name
    const visibleComponent = visibleComponentName(item.component_name)
    if (visibleComponent && !selectedComponents.value.has(visibleComponent)) {
        selectedComponents.value = new Set([visibleComponent])
    }
}

const toggleCompletedResult = async (item: AnalysisQueueItem) => {
    if (selectedRunId.value === item.queue_id && result.value) {
        closeSelectedResult()
        return
    }
    await viewCompletedResult(item)
}

const viewPersistedResult = async (record: CodeAnalysisResultRecord) => {
    const requestedTeamScope = teamScopeKey.value
    try {
        const full = record.result ? record : await codeAnalysisGetResult(record.analysis_run_id)
        if (
            !full.result
            || requestedTeamScope !== teamScopeKey.value
            || !relevantComponentKeys.value.has(full.component_name.toLocaleLowerCase())
            || !matchesTeamScope(full)
        ) return
        result.value = full.result
        analyzedComponents.value = [full.component_name]
        selectedRunId.value = full.analysis_run_id
        activeResultRunIds.value = [full.analysis_run_id]
        selectedFullRecord.value = full
        followUpComponent.value = full.component_name
        const visibleComponent = visibleComponentName(full.component_name)
        if (visibleComponent && !selectedComponents.value.has(visibleComponent)) {
            selectedComponents.value = new Set([visibleComponent])
        }
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Failed to load analysis result.'
    }
}

const applyPersistedResult = async (record: CodeAnalysisResultRecord) => {
    await viewPersistedResult(record)
    if (selectedRunId.value === record.analysis_run_id && result.value) {
        applyResult()
    }
}

const startFollowUp = async () => {
    const parentRunId = followUpParentRunId.value
    const question = followUpQuestion.value.trim()
    const target = followUpComponent.value.trim()
        || [...selectedComponents.value][0]
        || latestPersistedResult.value?.component_name
        || ''

    if (!parentRunId) {
        error.value = 'No prior analysis result is available for a follow-up.'
        return
    }
    if (!question) {
        error.value = 'Follow-up question is required.'
        return
    }
    if (!target) {
        error.value = 'Follow-up target is required.'
        return
    }

    followUpSubmitting.value = true
    error.value = null
    collectedResults.value = []
    pendingQueueIds.value = []
    activeResultRunIds.value = []
    analyzedComponents.value = []
    const [batchId, batch] = beginAnalysisBatch([target])

    try {
        const item = await analysisQueueStore.submitFollowUp(
            parentRunId,
            question,
            target,
            props.projectName,
            props.cvssVector,
            buildLaunchGuidance(),
            (res, item) => handleComponentComplete(batchId, target, res, item),
            (err) => handleComponentError(batchId, target, err),
        )
        pendingQueueIds.value.push(item.queue_id)
        batch.queueIds.push(item.queue_id)
        followUpQuestion.value = ''
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Failed to submit follow-up.'
    } finally {
        followUpSubmitting.value = false
    }
}

const cancelQueueItem = async (item: AnalysisQueueItem) => {
    const next = new Set(queueActionIds.value)
    next.add(item.queue_id)
    queueActionIds.value = next
    try {
        await analysisQueueStore.cancel(item.queue_id)
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Failed to update queue item.'
    } finally {
        const after = new Set(queueActionIds.value)
        after.delete(item.queue_id)
        queueActionIds.value = after
    }
}

const isQueueActionBusy = (queueId: string) => queueActionIds.value.has(queueId)

const isDeletingRun = (runId: string) => deletingRunIds.value.has(runId)

const removePersistedResult = async (record: CodeAnalysisResultRecord) => {
    const runId = record.analysis_run_id
    if (!runId || isDeletingRun(runId)) return
    const label = record.component_name || runId
    if (!window.confirm(`Remove the saved assessment and all run records for ${label}? This cannot be undone.`)) return

    const next = new Set(deletingRunIds.value)
    next.add(runId)
    deletingRunIds.value = next
    error.value = null
    historyError.value = null
    try {
        const cleanup = await codeAnalysisCleanupVulnerability(
            props.projectName || '_all_',
            props.vulnId,
            {
                vulnerability_aliases: props.vulnAliases || [],
                component_names: [record.component_name],
                analysis_run_ids: [runId],
                remove_assessments: true,
                remove_runs: true,
            },
        )
        persistedResults.value = persistedResults.value.filter(candidate =>
            !recordMatchesRunId(candidate, runId)
        )
        await analysisQueueStore.refreshStatus()
        if (cleanup.errors.length || cleanup.skipped_active_ids.length) {
            historyError.value = [
                ...cleanup.errors.map(issue => issue.detail),
                cleanup.skipped_active_ids.length
                    ? `${cleanup.skipped_active_ids.length} active run(s) were left in place.`
                    : '',
            ].filter(Boolean).join(' ')
        }
        if (selectedRunId.value === runId) {
            const replacement = persistedResults.value[0] || null
            if (replacement) {
                await viewPersistedResult(replacement)
            } else {
                selectedRunId.value = null
                selectedFullRecord.value = null
                result.value = null
                activeResultRunIds.value = []
                analyzedComponents.value = []
            }
        }
        if (!persistedResults.value.length) {
            followUpComponent.value = ''
        } else if (!followUpComponent.value || followUpComponent.value === record.component_name) {
            followUpComponent.value = persistedResults.value[0].component_name || ''
        }
    } catch (err: any) {
        historyError.value = err?.response?.data?.detail || err?.message || 'Unable to remove analysis run.'
    } finally {
        const after = new Set(deletingRunIds.value)
        after.delete(runId)
        deletingRunIds.value = after
    }
}

const cleanupVulnerability = async () => {
    if (cleanupBusy.value || (!cleanupAssessments.value && !cleanupRuns.value)) return
    const selected = [
        cleanupAssessments.value ? 'saved assessments' : '',
        cleanupRuns.value ? 'DTVP and Agentyzer run records' : '',
    ].filter(Boolean).join(' and ')
    const activeNotice = cleanupRuns.value && cleanupActive.value
        ? ' Active runs will be cancelled.'
        : ''
    if (!window.confirm(`Remove all ${selected} for ${props.vulnId} in this project?${activeNotice} This cannot be undone.`)) return

    cleanupBusy.value = true
    cleanupMessage.value = ''
    historyError.value = null
    try {
        const cleanup = await codeAnalysisCleanupVulnerability(
            props.projectName || '_all_',
            props.vulnId,
            {
                vulnerability_aliases: props.vulnAliases || [],
                remove_assessments: cleanupAssessments.value,
                remove_runs: cleanupRuns.value,
                cancel_active: cleanupActive.value,
            },
        )
        await analysisQueueStore.refreshStatus()
        await loadPersistedResults()
        selectedRunId.value = null
        selectedFullRecord.value = null
        result.value = null
        activeResultRunIds.value = []
        analyzedComponents.value = []
        collectedResults.value = []
        cleanupMessage.value = [
            `${cleanup.removed.assessments} assessment${cleanup.removed.assessments === 1 ? '' : 's'}`,
            `${cleanup.removed.dtvp_runs} DTVP run${cleanup.removed.dtvp_runs === 1 ? '' : 's'}`,
            `${cleanup.removed.agentyzer_jobs} Agentyzer job${cleanup.removed.agentyzer_jobs === 1 ? '' : 's'}`,
        ].join(', ') + ' removed.'
        const issues = [
            ...cleanup.warnings,
            ...cleanup.errors.map(issue => `${issue.id}: ${issue.detail}`),
            cleanup.skipped_active_ids.length
                ? `${cleanup.skipped_active_ids.length} active run(s) were left in place; enable active-run cancellation to remove them.`
                : '',
        ].filter(Boolean)
        if (issues.length) historyError.value = issues.join(' ')
    } catch (err: any) {
        historyError.value = err?.response?.data?.detail || err?.message || 'Unable to clean code analysis data.'
    } finally {
        cleanupBusy.value = false
    }
}


const sourceClass = (source?: string | null) => {
    if (source === 'benchmark') return 'text-amber-200 border-amber-700/40 bg-amber-950/25'
    if (source === 'automatic') return 'text-cyan-300 border-cyan-700/40 bg-cyan-900/20'
    if (source === 'follow-up') return 'text-blue-300 border-blue-700/40 bg-blue-900/20'
    return 'text-gray-300 border-gray-700 bg-gray-950'
}

const sourceLabel = (source?: string | null) => {
    if (source === 'automatic') return 'Auto'
    if (source === 'benchmark') return 'Benchmark'
    if (source === 'follow-up') return 'Follow-up'
    return 'Manual'
}


// -- one evidence list: analyzer runs and agent evidence --------------------

const analyzerConfigured = computed(() => {
    const status = (analysisQueueStore as any).sweepStatus?.value
    return status?.code_analysis_configured !== false
})

const scopeLine = computed(() => {
    const count = uniqueComponents.value.length
    if (props.teamScope) return `${props.teamScope} · ${count} component${count === 1 ? '' : 's'}`
    return 'All components'
})

/** Resets the list's disclosures when the scope changes. */
const evidenceScopeKey = computed(() => [props.vulnId, props.projectName || '', teamScopeKey.value, ...uniqueComponents.value, JSON.stringify(props.evidenceTargets)].join('\u0000'))

const targetLabel = computed(() => String(props.currentTeam || '').trim() || 'General')

const scopedAgentEvidence = computed(() => {
    if (props.evidenceTargets === undefined) return agentEvidence.value
    const findings = new Set(props.evidenceTargets.map(target => target.finding_uuid).filter(Boolean))
    return agentEvidence.value.filter(item => item.scope === 'vulnerability'
        || item.targets.some(target => Boolean(target.finding_uuid) && findings.has(target.finding_uuid)))
})
const visibleAgentEvidence = computed(() => scopedAgentEvidence.value.filter(item => showWithdrawn.value || !item.withdrawn))
const withdrawnCount = computed(() => scopedAgentEvidence.value.filter(item => item.withdrawn).length)

const evidenceGroups = computed(() => mergeEvidenceRows(
    persistedResults.value,
    visibleAgentEvidence.value,
    uniqueComponents.value,
    {
        componentOf: record => recordVisibleComponent(record),
        filter: evidenceFilter.value,
        agentComponentNames: props.evidenceTargets?.map(target => String(target.component || '').trim()).filter(Boolean),
    },
))

const selectedPersistedRowKey = computed(() => {
    const runId = loadingRunId.value || (result.value ? selectedRunId.value : null)
    if (!runId) return null
    const record = persistedResults.value.find(candidate => recordMatchesRunId(candidate, runId))
    return record ? `analyzer:${record.analysis_run_id}` : null
})

const selectedEvidenceKey = computed(() => (
    selectedAgentId.value ? `agent:${selectedAgentId.value}` : selectedPersistedRowKey.value
))

/** A selected result that is not a row of the list: a queue result. */
const showsTransientResult = computed(() => Boolean(result.value && !selectedPersistedRowKey.value && !selectedAgentId.value))

const statusOfComponent = (component: string): RunFormComponentStatus => {
    if (activeComponentNames.value.has(component.toLowerCase())) return 'active'
    if (assessedComponentNames.value.has(component)) return 'assessed'
    if (completedComponentNames.value.has(component)) return 'completed'
    return ''
}

const startLabel = computed(() => {
    if (submitting.value) return 'Submitting...'
    if (hasReusableAnalysis.value) return 'Run Again'
    if (activeQueueItems.value.length > 0) return 'Analyze More'
    return `Analyze ${selectedComponents.value.size || ''}`.trim()
})

const loadAgentEvidence = async () => {
    const loadId = ++evidenceLoadCounter
    const projectName = String(props.projectName || '').trim()
    if (!projectName || (props.evidenceTargets === undefined && uniqueComponents.value.length === 0)) {
        agentEvidence.value = []
        return
    }
    evidenceLoading.value = true
    try {
        const listed = await listCodeEvidence(projectName, props.vulnId, {
            vuln_alias: [...(props.vulnAliases || [])],
            ...(props.evidenceTargets === undefined ? { component_name: [...uniqueComponents.value] } : {}),
            include_withdrawn: true,
        })
        if (loadId !== evidenceLoadCounter) return
        agentEvidence.value = Array.isArray(listed?.items) ? listed.items : []
        emit('evidence-loaded', agentEvidence.value)
    } catch (err: any) {
        if (loadId !== evidenceLoadCounter) return
        historyError.value = err?.response?.data?.detail || err?.message || 'Unable to load code evidence.'
    } finally {
        if (loadId === evidenceLoadCounter) evidenceLoading.value = false
    }
}

const refreshAll = async () => {
    moreOpen.value = false
    await Promise.all([loadPersistedResults(), loadAgentEvidence()])
}

const openCleanup = () => {
    moreOpen.value = false
    cleanupOpen.value = true
}

const closeEvidence = () => {
    selectedAgentId.value = null
    loadingRunId.value = null
    closeSelectedResult()
}

const selectEvidenceRow = async (row: EvidenceRow) => {
    if (selectedEvidenceKey.value === row.key) {
        closeEvidence()
        return
    }
    if (row.kind === 'agent') {
        closeSelectedResult()
        selectedAgentId.value = row.id
        return
    }
    selectedAgentId.value = null
    if (!row.record) return
    loadingRunId.value = row.record.analysis_run_id
    try {
        await viewPersistedResult(row.record)
    } finally {
        if (loadingRunId.value === row.record.analysis_run_id) loadingRunId.value = null
    }
}

const applyEvidenceRow = async (row: EvidenceRow, options: { useSuggestion: boolean; summary?: string }) => {
    if (row.kind === 'analyzer') {
        if (row.record) await applyPersistedResult(row.record)
        return
    }
    const evidence = row.evidence
    if (!evidence || evidence.withdrawn) return
    emit('apply-evidence', {
        evidenceId: evidence.evidence_id,
        title: evidence.title,
        summary: options.summary || '',
        ...(options.useSuggestion && evidence.suggested_state
            ? {
                state: evidence.suggested_state,
                ...(evidence.suggested_justification ? { justification: evidence.suggested_justification } : {}),
            }
            : {}),
    })
}

const withdrawEvidenceRow = async (row: EvidenceRow, reason: string) => {
    if (!row.evidence) return
    evidenceBusy.value = true
    error.value = null
    try {
        const updated = await withdrawCodeEvidence(row.evidence.evidence_id, reason)
        agentEvidence.value = agentEvidence.value.map(item => (
            item.evidence_id === updated.evidence_id ? { ...item, ...updated, applications: item.applications } : item
        ))
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Unable to withdraw the evidence.'
    } finally {
        evidenceBusy.value = false
    }
}

const removeEvidenceRun = async (row: EvidenceRow) => {
    if (row.record) await removePersistedResult(row.record)
}

onMounted(() => {
    void loadAgentEvidence()
    // The tab is hidden with v-show; reload agent evidence and analyzer runs
    // whenever it is shown again, so a save made on another tab marks what
    // it used.
    if (typeof IntersectionObserver !== 'undefined' && panelRoot.value) {
        let visible = true
        visibilityObserver = new IntersectionObserver(entries => {
            const nowVisible = entries.some(entry => entry.isIntersecting)
            if (nowVisible && !visible) {
                void loadAgentEvidence()
                void loadPersistedResults()
            }
            visible = nowVisible
        })
        visibilityObserver.observe(panelRoot.value)
    }
})

onMounted(() => {
    void loadPersistedResults()
    document.addEventListener('click', handleClickOutside)
})

onBeforeUnmount(() => {
    document.removeEventListener('click', handleClickOutside)
    visibilityObserver?.disconnect()
})

watch([
    () => props.vulnId,
    () => props.projectName || '',
    () => (props.vulnAliases || []).join('\u0000'),
    () => uniqueComponents.value.join('\u0000'),
    () => JSON.stringify(props.evidenceTargets),
    teamScopeKey,
    () => [...teamScopeKeys.value].sort().join('\u0000'),
], (_current, previous) => {
    if (!previous) return
    analysisBatches.clear()
    persistedResults.value = []
    historyLoaded.value = false
    selectedRunId.value = null
    selectedFullRecord.value = null
    result.value = null
    analyzedComponents.value = []
    activeResultRunIds.value = []
    collectedResults.value = []
    pendingQueueIds.value = []
    followUpComponent.value = ''
    followUpQuestion.value = ''
    combinedHydrationCounter += 1
    combinedHydrating.value = false
    combinedHydrationError.value = null
    selectedAgentId.value = null
    agentEvidence.value = []
    void loadPersistedResults()
    void loadAgentEvidence()
})

// The panel can stay visible while the assessment is saved (assessment
// workspace), so a save also reloads what it marks as used.
watch(() => props.refreshKey, (current, previous) => {
    if (previous === undefined || current === previous) return
    void loadAgentEvidence()
    void loadPersistedResults()
})

watch([historyLoaded, hasReusableAnalysis], ([loaded, available]) => {
    emit('scope-results-change', loaded && available)
}, { immediate: true })

function handleClickOutside(e: MouseEvent) {
    const target = e.target as HTMLElement
    if (moreOpen.value && !target.closest('[data-panel-more]')) {
        moreOpen.value = false
    }
}

watch(selectedComponents, () => {
    if (!controlsBusy.value && activeQueueItems.value.length === 0) {
        result.value = null
        selectedRunId.value = null
        selectedFullRecord.value = null
        activeResultRunIds.value = []
    }
})

watch(result, (current) => {
    emit('result-change', current, analyzedComponents.value)
})

watch(analyzedComponents, (components) => {
    if (result.value) {
        emit('result-change', result.value, components)
    }
})

watch(
    () => applyAllCandidates.value
        .map(candidate => `${candidate.record.analysis_run_id}:${candidate.record.result ? 'loaded' : 'summary'}`)
        .join('|'),
    () => { void hydrateCombinedCandidates() },
    { immediate: true },
)

watch(combinedCandidateRuns, runs => {
    emit('proposals-change', runs)
}, { immediate: true })
</script>



<template>
    <div ref="panelRoot" class="flex flex-col gap-4" data-testid="code-evidence-panel">
        <header class="flex flex-wrap items-start justify-between gap-3 rounded-lg border border-cyan-800/40 bg-cyan-950/10 px-4 py-3">
            <div class="min-w-0">
                <h3 class="flex items-center gap-2 text-sm font-bold text-cyan-100">
                    <Zap :size="14" />
                    Code evidence
                </h3>
                <p class="mt-1 text-xs text-gray-400" data-testid="code-evidence-scope">{{ scopeLine }}</p>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <span v-if="statusLabel" class="inline-flex items-center gap-1 text-[11px] font-semibold" :class="statusClass">
                    <Loader2 v-if="queueStatus === 'running' || submitting" :size="11" class="animate-spin" />
                    <Clock v-else-if="queueStatus === 'queued'" :size="11" />
                    {{ statusLabel }}
                </span>
                <span
                    v-if="effectiveAssessmentStatus"
                    class="rounded border px-1.5 py-0.5 text-[10px] font-semibold"
                    :class="assessmentStatusClass"
                >{{ assessmentStatusLabel }}</span>
                <button
                    v-if="analyzerConfigured"
                    type="button"
                    data-testid="run-analysis-toggle"
                    :aria-expanded="runFormOpen ? 'true' : 'false'"
                    :disabled="!hasOwnedTargets"
                    class="inline-flex items-center gap-1.5 rounded bg-cyan-700 px-3 py-1.5 text-xs font-bold text-white hover:bg-cyan-600 disabled:cursor-not-allowed disabled:opacity-50"
                    @click="runFormOpen = !runFormOpen"
                >
                    <Zap :size="12" /> Run analysis
                </button>
                <div class="relative" data-panel-more>
                    <button
                        type="button"
                        data-testid="code-evidence-more"
                        aria-haspopup="menu"
                        :aria-expanded="moreOpen ? 'true' : 'false'"
                        class="inline-flex items-center gap-1 rounded border border-gray-700 px-2.5 py-1.5 text-xs font-semibold text-gray-300 hover:border-cyan-700/60 hover:text-cyan-200"
                        @click="moreOpen = !moreOpen"
                    >
                        <MoreHorizontal :size="13" /> More
                    </button>
                    <div v-if="moreOpen" role="menu" class="absolute right-0 z-20 mt-1 w-52 rounded border border-gray-700 bg-gray-900 py-1 shadow-lg">
                        <button type="button" role="menuitem" data-testid="code-evidence-refresh" class="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-gray-200 hover:bg-gray-800" @click="refreshAll">
                            <RefreshCw :size="12" /> Refresh
                        </button>
                        <button type="button" role="menuitem" data-testid="analysis-cleanup-toggle" class="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-red-300 hover:bg-gray-800" @click="openCleanup">
                            <Trash2 :size="12" /> Clean up analyzer data
                        </button>
                    </div>
                </div>
            </div>
        </header>

        <div v-if="!hasOwnedTargets" class="rounded border border-amber-700/40 bg-amber-900/15 px-3 py-2 text-xs text-amber-200">
            No team-assigned component target is available for code analysis.
        </div>

        <CodeAnalysisRunForm
            v-if="runFormOpen && analyzerConfigured"
            :components="uniqueComponents"
            :selected="[...selectedComponents]"
            :status-of="statusOfComponent"
            :guidance="userGuidance"
            :launch-guidance="launchGuidancePreview"
            :busy="controlsBusy"
            :submitting="submitting"
            :can-start="canStartScan"
            :start-label="startLabel"
            @toggle-component="toggleComponent"
            @toggle-all="toggleAll"
            @update:guidance="userGuidance = $event"
            @start="startScan"
        />

        <div
            v-if="cleanupOpen"
            data-testid="analysis-cleanup-panel"
            class="space-y-2 rounded border border-red-900/50 bg-red-950/10 p-3 text-xs"
        >
            <div class="flex items-start justify-between gap-2">
                <div>
                    <div class="font-semibold text-red-200">Clean {{ vulnId }} analyzer data</div>
                    <p class="mt-0.5 text-[10px] leading-relaxed text-gray-500">
                        Choose either store independently, or remove both for a complete cleanup. Agent evidence is never removed here; withdraw it in its reader.
                    </p>
                </div>
                <button type="button" class="text-[10px] text-gray-500 hover:text-gray-200" @click="cleanupOpen = false">Close</button>
            </div>
            <div class="flex flex-wrap gap-x-4 gap-y-2 text-[11px] text-gray-300">
                <label class="inline-flex items-center gap-1.5">
                    <input v-model="cleanupAssessments" type="checkbox" class="accent-red-500" />
                    Saved assessments
                </label>
                <label class="inline-flex items-center gap-1.5">
                    <input v-model="cleanupRuns" type="checkbox" class="accent-red-500" />
                    DTVP and Agentyzer runs
                </label>
                <label class="inline-flex items-center gap-1.5" :class="cleanupRuns ? '' : 'opacity-50'">
                    <input v-model="cleanupActive" type="checkbox" class="accent-red-500" :disabled="!cleanupRuns" />
                    Cancel active runs too
                </label>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <button
                    type="button"
                    data-testid="analysis-cleanup-submit"
                    class="inline-flex items-center gap-1 rounded bg-red-700 px-2.5 py-1.5 text-[10px] font-bold uppercase text-white hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-50"
                    :disabled="cleanupBusy || (!cleanupAssessments && !cleanupRuns)"
                    @click="cleanupVulnerability"
                >
                    <Loader2 v-if="cleanupBusy" :size="11" class="animate-spin" />
                    <Trash2 v-else :size="11" />
                    Clean selected data
                </button>
                <span v-if="cleanupMessage" class="text-[10px] text-emerald-300">{{ cleanupMessage }}</span>
            </div>
        </div>

        <section
            v-if="activeQueueItems.length || completedQueueItems.length || showsTransientResult"
            aria-label="Analyses in progress"
            data-testid="analysis-run-list"
            class="divide-y divide-gray-800/80 overflow-hidden rounded border border-gray-800/90 bg-gray-950/20"
        >
            <div v-for="item in activeQueueItems" :key="`active:${item.queue_id}`">
                <div
                    class="grid gap-2 px-3 py-2.5 text-[11px] md:grid-cols-[minmax(0,1fr)_auto]"
                    :class="item.status === 'running' ? 'bg-blue-950/10' : 'bg-yellow-950/10'"
                >
                    <div class="flex min-w-0 flex-wrap items-center gap-2">
                        <Loader2 v-if="item.status === 'running'" :size="12" class="animate-spin text-blue-400" />
                        <Clock v-else :size="12" class="text-yellow-400" />
                        <span class="min-w-0 truncate font-mono text-gray-200">{{ item.component_name }}</span>
                        <span v-if="item.source && item.source !== 'manual'" class="text-[9px] font-semibold uppercase" :class="sourceClass(item.source)">
                            {{ sourceLabel(item.source) }}
                        </span>
                        <span v-if="item.status === 'queued' && item.position > 0" class="font-bold text-yellow-400">#{{ item.position }}</span>
                        <span class="font-semibold uppercase" :class="item.status === 'running' ? 'text-blue-400' : 'text-yellow-400'">{{ item.status }}</span>
                    </div>
                    <button
                        type="button"
                        :disabled="isQueueActionBusy(item.queue_id)"
                        class="inline-flex items-center justify-center gap-1 rounded px-2 py-1 text-[9px] font-bold uppercase text-gray-500 hover:bg-red-950/20 hover:text-red-300 disabled:cursor-wait disabled:opacity-50"
                        @click="cancelQueueItem(item)"
                    >
                        <Loader2 v-if="isQueueActionBusy(item.queue_id)" :size="10" class="animate-spin" />
                        <Ban v-else :size="10" />
                        {{ item.status === 'running' ? 'Abort' : 'Cancel' }}
                    </button>
                </div>
                <CodeAnalysisJobDiagnostics class="px-3 pb-2" :job-id="item.job_id" :status="item.status" :report-markdown="item.result?.assessment?.report_markdown" :error-details="item.error_details" />
            </div>
            <div v-for="item in completedQueueItems" :key="`completed:${item.queue_id}`">
                <div class="grid gap-2 bg-green-950/10 px-3 py-2.5 text-[11px] md:grid-cols-[minmax(0,1fr)_auto]">
                    <div class="flex min-w-0 flex-wrap items-center gap-2">
                        <CheckCircle :size="12" class="text-green-400" />
                        <span class="min-w-0 truncate font-mono text-gray-200">{{ item.component_name }}</span>
                        <span v-if="item.source && item.source !== 'manual'" class="text-[9px] font-semibold uppercase" :class="sourceClass(item.source)">
                            {{ sourceLabel(item.source) }}
                        </span>
                        <span class="font-semibold uppercase text-green-400">completed</span>
                    </div>
                    <button
                        type="button"
                        class="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[9px] font-bold uppercase text-green-300 hover:bg-green-950/30"
                        :aria-expanded="selectedRunId === item.queue_id && result ? 'true' : 'false'"
                        @click="toggleCompletedResult(item)"
                    >
                        <Eye :size="11" />
                        {{ selectedRunId === item.queue_id && result ? 'Hide' : 'View' }}
                    </button>
                </div>
                <CodeAnalysisJobDiagnostics class="px-3 pb-2" :job-id="item.job_id" :status="item.status" :report-markdown="item.result?.assessment?.report_markdown" :error-details="item.error_details" />
            </div>
            <div v-if="showsTransientResult && result" class="space-y-2 px-3 pb-3 pt-1" data-testid="selected-analysis-run-details">
                <CodeAnalysisRunOutcome
                    :result="result"
                    :verdictClass="verdictColor"
                    :confidenceClass="confidenceBadge"
                    :runQuestion="selectedRunQuestion"
                    :canFollowUp="Boolean(followUpParentRunId)"
                    :followUpQuestion="followUpQuestion"
                    :followUpTarget="followUpComponent"
                    :followUpBusy="controlsBusy"
                    @update:followUpQuestion="followUpQuestion = $event"
                    @update:followUpTarget="followUpComponent = $event"
                    @follow-up="startFollowUp"
                    @apply="applyResult"
                    @close="closeSelectedResult"
                />
                <CodeAnalysisRunDetails
                    :key="`transient:${selectedRunId || 'current'}`"
                    :result="result"
                    :selected-record="selectedPersistedResult"
                    :latest-record="latestPersistedResult"
                    :vuln-id="vulnId"
                    :cvss-vector="cvssVector"
                    :component-names="uniqueComponents"
                    :selected-components="[...selectedComponents]"
                    :analyzed-components="analyzedComponents"
                    :component-teams="componentTeams"
                    :project-name="projectName"
                    :project-versions="projectVersions"
                    :affected-product-versions="affectedProductVersions"
                    :current-state="currentState"
                    :current-justification="currentJustification"
                    :current-details="currentDetails"
                    :current-team="currentTeam"
                    :current-cvss-score="currentCvssScore"
                    :current-cvss-vector="currentCvssVector"
                    :current-assigned="currentAssigned"
                />
            </div>
        </section>

        <CodeEvidenceList
            :key="evidenceScopeKey"
            :groups="evidenceGroups"
            :filter="evidenceFilter"
            :show-withdrawn="showWithdrawn"
            :withdrawn-count="withdrawnCount"
            :selected-key="selectedEvidenceKey"
            :loading="historyLoading || evidenceLoading"
            @update:filter="evidenceFilter = $event"
            @update:show-withdrawn="showWithdrawn = $event"
            @select="selectEvidenceRow"
        >
            <template #reader="{ row }">
                <CodeEvidenceReader
                    :row="row"
                    :result="row.kind === 'analyzer' ? result : null"
                    :loading="row.kind === 'analyzer' && (!result || loadingRunId === row.id)"
                    :applicable="row.kind === 'analyzer' && Boolean(row.record) && isReusableRecord(row.record!) && isCodeAnalysisApplicable(result)"
                    :target-label="targetLabel"
                    :current-user="currentUsername"
                    :is-reviewer="isReviewer"
                    :reported-finding-uuids="reportedFindingUuids"
                    :busy="evidenceBusy || (row.kind === 'analyzer' && isDeletingRun(row.id))"
                    @apply="applyEvidenceRow(row, $event)"
                    @attachments-change="loadAgentEvidence"
                    @withdraw="withdrawEvidenceRow(row, $event)"
                    @remove="removeEvidenceRun(row)"
                    @close="closeEvidence"
                >
                    <template v-if="row.kind === 'analyzer' && result && loadingRunId !== row.id" #details>
                        <CodeAnalysisRunDetails
                            :key="`run:${row.id}`"
                            :result="result"
                            :selected-record="selectedPersistedResult"
                            :latest-record="latestPersistedResult"
                            :vuln-id="vulnId"
                            :cvss-vector="cvssVector"
                            :component-names="uniqueComponents"
                            :selected-components="[...selectedComponents]"
                            :analyzed-components="analyzedComponents"
                            :component-teams="componentTeams"
                            :project-name="projectName"
                            :project-versions="projectVersions"
                            :affected-product-versions="affectedProductVersions"
                            :current-state="currentState"
                            :current-justification="currentJustification"
                            :current-details="currentDetails"
                            :current-team="currentTeam"
                            :current-cvss-score="currentCvssScore"
                            :current-cvss-vector="currentCvssVector"
                            :current-assigned="currentAssigned"
                            :run-question="selectedRunQuestion"
                            :can-follow-up="Boolean(followUpParentRunId)"
                            :follow-up-question="followUpQuestion"
                            :follow-up-target="followUpComponent"
                            :follow-up-busy="controlsBusy"
                            @update:follow-up-question="followUpQuestion = $event"
                            @update:follow-up-target="followUpComponent = $event"
                            @follow-up="startFollowUp"
                        />
                    </template>
                </CodeEvidenceReader>
            </template>
        </CodeEvidenceList>

        <div v-if="historyError" class="rounded border border-amber-700/40 bg-amber-900/15 px-3 py-2 text-xs text-amber-200">
            {{ historyError }}
        </div>
        <div v-for="item in failedDiagnosticItems" :key="item.queue_id" class="rounded border border-red-900/40 p-2">
            <span class="text-xs text-red-300">{{ item.component_name }} — {{ item.status }}</span>
            <CodeAnalysisJobDiagnostics :job-id="item.job_id" :error-details="item.error_details" />
        </div>
        <div v-if="error" class="flex items-start gap-2 rounded border border-red-700/40 bg-red-900/20 p-2 text-xs text-red-300">
            <XCircle :size="14" class="mt-0.5 shrink-0" />
            <span>{{ error }}</span>
        </div>

        <section
            v-if="applyAllCandidates.length"
            data-testid="combined-analysis-assessment"
            class="space-y-2 rounded border border-gray-800 bg-gray-950/25 px-4 py-3"
        >
            <div class="flex flex-wrap items-center justify-between gap-2">
                <h4 class="text-xs font-bold text-gray-200">Apply all latest analyzer results</h4>
                <button
                    v-if="canApplyAllResults"
                    type="button"
                    data-testid="apply-all-analysis-results"
                    :disabled="applyingAll || combinedHydrating"
                    :title="applyAllTitle"
                    class="inline-flex items-center gap-1.5 rounded bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white transition-colors hover:bg-cyan-700 disabled:cursor-wait disabled:opacity-50"
                    @click="applyAllResults"
                >
                    <Loader2 v-if="applyingAll" :size="12" class="animate-spin" />
                    <ClipboardCheck v-else :size="12" />
                    Use {{ applyAllCandidates.length }} latest results as draft
                </button>
                <button
                    v-else-if="applyAllCandidates.length === 1"
                    type="button"
                    data-testid="apply-single-analysis-result"
                    class="inline-flex items-center gap-1.5 rounded bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white transition-colors hover:bg-cyan-700"
                    @click="applyPersistedResult(applyAllCandidates[0].record)"
                >
                    <CheckCircle :size="12" />
                    Use result as draft
                </button>
            </div>

            <div v-if="combinedAssessmentPreview" class="border-l-2 px-3 py-1" :class="combinedAssessmentPreviewBorderClass" data-testid="combined-assessment-preview">
                <dl class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs md:grid-cols-4" data-testid="combined-decision-summary">
                    <div>
                        <dt class="text-[9px] font-semibold uppercase tracking-wide text-gray-600">Worst case</dt>
                        <dd class="mt-0.5 font-semibold" :class="combinedAssessmentPreviewTextClass">{{ combinedAssessmentPreview.assessment.verdict }}</dd>
                    </div>
                    <div>
                        <dt class="text-[9px] font-semibold uppercase tracking-wide text-gray-600">Confidence</dt>
                        <dd class="mt-0.5 text-gray-300">{{ combinedAssessmentPreview.assessment.confidence }}</dd>
                    </div>
                    <div>
                        <dt class="text-[9px] font-semibold uppercase tracking-wide text-gray-600">Exposure</dt>
                        <dd class="mt-0.5 text-gray-300">{{ combinedAssessmentPreview.assessment.exposure }}</dd>
                    </div>
                    <div>
                        <dt class="text-[9px] font-semibold uppercase tracking-wide text-gray-600">Scope</dt>
                        <dd class="mt-0.5 text-gray-300">
                            {{ combinedCandidateRuns.length }} of {{ applyAllCandidates.length }} targets loaded
                        </dd>
                    </div>
                </dl>
                <p v-if="combinedControllingTargets.length && !allCombinedTargetsControlDecision" class="mt-1 text-[10px] text-gray-400">
                    Controlling: <span class="font-mono">{{ combinedControllingTargets.join(', ') }}</span>
                </p>
                <details v-if="combinedTargetResults.length" class="mt-2" data-testid="combined-target-assessments">
                    <summary class="cursor-pointer text-[10px] font-semibold uppercase tracking-wide text-gray-500 hover:text-gray-300">
                        Target assessments ({{ combinedTargetResults.length }})
                    </summary>
                    <div class="mt-1.5 grid gap-2 xl:grid-cols-2">
                        <article
                            v-for="target in combinedTargetResults"
                            :key="target.component"
                            :data-component="target.component"
                            data-testid="combined-target-assessment"
                            class="rounded border border-gray-800 bg-gray-950/35 p-3"
                        >
                            <header class="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-gray-800/70 pb-2">
                                <h5 class="font-mono text-xs font-semibold text-gray-200">{{ target.component }}</h5>
                                <span class="text-[10px] font-bold uppercase" :class="combinedTargetVerdictClass(target.assessment)">{{ target.assessment.verdict }}</span>
                                <span class="text-[10px] text-gray-500">{{ target.assessment.confidence }} confidence · {{ target.assessment.exposure }}</span>
                            </header>
                            <CodeAnalysisReport v-if="target.assessment.report_markdown?.trim()" :markdown="target.assessment.report_markdown" />
                            <ul v-else-if="combinedTargetReasons(target).length" class="mt-2 list-disc space-y-1 pl-4 text-xs leading-relaxed text-gray-400">
                                <li v-for="reason in combinedTargetReasons(target)" :key="reason">{{ reason }}</li>
                            </ul>
                            <p v-else class="mt-2 text-xs leading-relaxed text-gray-400">{{ target.assessment.summary }}</p>
                        </article>
                    </div>
                </details>
            </div>
            <div v-if="combinedHydrating" class="flex items-center gap-2 text-[11px] text-gray-500">
                <Loader2 :size="11" class="animate-spin" /> Loading the latest target rationales
            </div>
            <div v-if="combinedHydrationError" class="text-[11px] text-amber-300">{{ combinedHydrationError }}</div>
            <p v-if="combinedMissingCandidates.length" class="text-[11px] text-gray-400">
                Awaiting target details:
                <span v-for="(candidate, index) in combinedMissingCandidates" :key="candidate.record.analysis_run_id" class="font-mono text-gray-300">{{ index ? ', ' : '' }}{{ candidate.component }} ({{ candidate.record.summary?.verdict || 'Completed' }})</span>
            </p>
            <p class="text-[11px] leading-relaxed text-gray-500">
                {{ applyAllCandidates.length > 1
                    ? 'The draft uses the most severe target verdict and keeps each target\'s evidence and run provenance. Review it on the Assessment tab before saving.'
                    : 'Only one target has a completed result, so its result is the complete scoped draft.' }}
            </p>
        </section>
    </div>
</template>
