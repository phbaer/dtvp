<script setup lang="ts">
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { Zap, Loader2, CheckCircle, XCircle, AlertTriangle, ChevronDown, ChevronUp, Clock, ClipboardCheck, History, Send, Ban, FileText, Copy, Trash2 } from 'lucide-vue-next'
import {
    codeAnalysisBenchmarkResult,
    codeAnalysisDeleteResult,
    codeAnalysisGetPrompts,
    codeAnalysisGetResult,
    codeAnalysisListVulnerabilityResults,
} from '../lib/api'
import type { AnalysisQueueItem, CodeAnalysisAssessResponse, CodeAnalysisAssessment, CodeAnalysisBenchmarkComparison, CodeAnalysisBenchmarkFinding, CodeAnalysisComponentResult, CodeAnalysisCvssAdjustment, CodeAnalysisLlmConversationTurn, CodeAnalysisLlmMessage, CodeAnalysisResultRecord, CodeAnalysisStepFindings } from '../lib/api'
import { analysisQueueStore } from '../lib/analysisQueueStore'
import { prepareCodeAnalysisResult } from '../lib/codeAnalysisResult'

const props = defineProps<{
    vulnId: string
    projectName?: string
    cvssVector?: string
    componentNames: string[]
    componentTeams?: Record<string, string>
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
}>()

const emit = defineEmits<{
    (e: 'apply-result', result: CodeAnalysisAssessResponse, components: string[]): void
    (e: 'result-change', result: CodeAnalysisAssessResponse | null, components: string[]): void
}>()

const userGuidance = ref('')
const error = ref<string | null>(null)
const result = ref<CodeAnalysisAssessResponse | null>(null)
const stepsExpanded = ref(false)
const coverageOpen = ref(false)
const assessmentSummaryOpen = ref(true)
const assessmentDraftOpen = ref(true)
const assessmentBenchmarkOpen = ref(true)
const ticketDraftOpen = ref(false)
const selectedComponents = ref<Set<string>>(new Set())
const componentDropdownOpen = ref(false)
const submitting = ref(false)
const persistedResults = ref<CodeAnalysisResultRecord[]>([])
const historyLoading = ref(false)
const historyError = ref<string | null>(null)
const selectedRunId = ref<string | null>(null)
const selectedFullRecord = ref<CodeAnalysisResultRecord | null>(null)
const followUpQuestion = ref('')
const followUpComponent = ref('')
const followUpSubmitting = ref(false)
const queueActionIds = ref<Set<string>>(new Set())
const deletingRunIds = ref<Set<string>>(new Set())
const systemPromptOpen = ref(false)
const systemPromptLoading = ref(false)
const systemPromptError = ref<string | null>(null)
const systemPromptPayload = ref<Record<string, any> | null>(null)
const ticketCopyState = ref<'idle' | 'copied' | 'error'>('idle')
const benchmarkComparison = ref<CodeAnalysisBenchmarkComparison | null>(null)
const benchmarkLoading = ref(false)
const benchmarkError = ref<string | null>(null)
const HISTORY_RESULT_REFRESH_ATTEMPTS = 4
const HISTORY_RESULT_REFRESH_DELAY_MS = 500
let benchmarkLoadCounter = 0

// Track queue IDs for items submitted from this panel
const pendingQueueIds = ref<string[]>([])
const analyzedComponents = ref<string[]>([])

type AnalysisBatch = {
    expectedTargets: string[]
    collected: { component: string; response: CodeAnalysisAssessResponse }[]
    queueIds: string[]
}

let analysisBatchCounter = 0
const analysisBatches = new Map<string, AnalysisBatch>()

// Severity ordering for worst-wins merging
const VERDICT_SEVERITY: Record<string, number> = {
    affected: 3,
    inconclusive: 2,
    'not affected': 1,
    not_affected: 1,
}

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

const allSelected = computed(() =>
    uniqueComponents.value.length > 0 && uniqueComponents.value.every(c => selectedComponents.value.has(c))
)

const noneSelected = computed(() => selectedComponents.value.size === 0)
const hasOwnedTargets = computed(() => uniqueComponents.value.length > 0)
const hasExistingAssessment = computed(() => {
    const state = String(props.currentState || '').trim().toUpperCase()
    return Boolean(state && state !== 'NOT_SET')
})

const visiblePersistedResults = computed(() => persistedResults.value.slice(0, 4))
const latestPersistedResult = computed(() => persistedResults.value[0] || null)
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

const selectionLabel = computed(() => {
    const total = uniqueComponents.value.length
    const count = selectedComponents.value.size
    if (total === 0) return 'No team-assigned targets'
    if (count === 0) return 'Select components…'
    if (count === total) return `All Components (${total})`
    if (count === 1) return [...selectedComponents.value][0]
    return `${count} of ${total} components`
})

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
const requestGuidancePreview = computed(() => {
    const selectedGuidance = stringifyPromptContent(selectedPersistedResult.value?.user_guidance)
    return selectedGuidance || launchGuidancePreview.value
})

type AssessmentDraftPreviewRow = {
    label: string
    before: string
    after: string
    changed: boolean
    mono?: boolean
}

const formatAssessmentValue = (value?: string | number | null) => {
    const text = String(value ?? '').trim()
    if (!text) return 'Not set'
    return text.replace(/_/g, ' ')
}

const summarizeDraftDetails = (value?: string | null) => {
    const text = String(value || '').trim()
    if (!text) return 'No details'
    const firstLine = text.split(/\r?\n/).find(line => line.trim())?.trim() || text
    return firstLine.length > 180 ? `${firstLine.slice(0, 177)}...` : firstLine
}

const formatAssignedUsers = (users?: string[]) => {
    const values = (users || []).map(user => String(user || '').trim()).filter(Boolean)
    return values.length ? values.join(', ') : 'None'
}

const draftPreviewComponents = computed(() => {
    const components = analyzedComponents.value.length
        ? analyzedComponents.value
        : [...selectedComponents.value]
    return components.length ? components : uniqueComponents.value
})

const draftTaggedComponents = computed(() =>
    draftPreviewComponents.value
        .map(name => ({ name, tag: props.componentTeams?.[name] || '' }))
        .filter(component => component.tag)
)

const assessmentDraftPreview = computed(() => {
    if (!result.value) return null
    const prepared = prepareCodeAnalysisResult(
        result.value,
        draftPreviewComponents.value,
        draftTaggedComponents.value,
        props.currentAssigned || [],
    )
    const currentScore = props.currentCvssScore == null || props.currentCvssScore === ''
        ? 'Not set'
        : String(props.currentCvssScore)
    const proposedScore = prepared.adjustedScore == null
        ? currentScore
        : String(prepared.adjustedScore)
    const currentVector = String(props.currentCvssVector || '').trim()
    const proposedVector = prepared.adjustedVector || currentVector
    const assignedAfter = prepared.teamDrafts[0]?.assigned || props.currentAssigned || []
    const rows: AssessmentDraftPreviewRow[] = [
        {
            label: 'State',
            before: formatAssessmentValue(props.currentState || 'NOT_SET'),
            after: formatAssessmentValue(prepared.targetState),
            changed: (props.currentState || 'NOT_SET') !== prepared.targetState,
        },
        {
            label: 'Justification',
            before: formatAssessmentValue(props.currentJustification || 'NOT_SET'),
            after: formatAssessmentValue(prepared.targetJustification),
            changed: (props.currentJustification || 'NOT_SET') !== prepared.targetJustification,
        },
        {
            label: 'Details',
            before: summarizeDraftDetails(props.currentDetails),
            after: summarizeDraftDetails(prepared.detailsText),
            changed: String(props.currentDetails || '').trim() !== prepared.detailsText.trim(),
        },
        {
            label: 'CVSS score',
            before: currentScore,
            after: proposedScore,
            changed: currentScore !== proposedScore,
            mono: true,
        },
        {
            label: 'CVSS vector',
            before: currentVector || 'Not set',
            after: proposedVector || 'Not set',
            changed: currentVector !== proposedVector,
            mono: true,
        },
        {
            label: 'Assigned users',
            before: formatAssignedUsers(props.currentAssigned),
            after: formatAssignedUsers(assignedAfter),
            changed: formatAssignedUsers(props.currentAssigned) !== formatAssignedUsers(assignedAfter),
        },
    ]

    return {
        targetTeam: prepared.firstTeam || 'Global',
        rows,
    }
})

const assessmentDraftChangeCount = computed(() =>
    assessmentDraftPreview.value?.rows.filter(row => row.changed).length || 0
)

type EvidenceQualityTone = 'green' | 'cyan' | 'blue' | 'amber' | 'yellow' | 'gray'

type EvidenceQualityBadge = {
    label: string
    detail: string
    tone: EvidenceQualityTone
}

const hasSourceLikeEvidence = (current: CodeAnalysisAssessResponse) => {
    const dependencyPresence = current.assessment.dependency_presence || {}
    if (dependencyPresence.repo_found === true) return true
    if (checkedVersionRows.value.some(row =>
        row.source !== '-'
        && /manifest|lock|pom|gradle|source|workspace|branch|tag|repo/i.test(row.source)
    )) return true
    return current.steps.some(step => {
        const text = [
            step.step,
            step.title,
            ...(step.evidence || []),
        ].join(' ')
        return /source|code|repository|repo|manifest|lock|call path|handler|usage|reachable/i.test(text)
    })
}

const hasExternalResearchEvidence = (current: CodeAnalysisAssessResponse) => {
    if ((current.assessment.advisory_sources || []).length > 0) return true
    return (current.llm_conversation || []).some(turn => conversationToolActivities(turn).length > 0)
}

const evidenceQualityBadges = computed<EvidenceQualityBadge[]>(() => {
    const current = result.value
    if (!current) return []

    const badges: EvidenceQualityBadge[] = []
    const dependencyPresence = current.assessment.dependency_presence || {}
    const versionConfirmed = checkedVersionRows.value.some(row =>
        (row.status === 'affected' || row.status === 'not affected')
        && row.version !== '-'
        && row.version.toLowerCase() !== 'unknown'
    )
    const sourceEvidence = hasSourceLikeEvidence(current)
    const externalResearch = hasExternalResearchEvidence(current)
    const sbomOnly = dependencyPresence.sbom_attributed === true && dependencyPresence.repo_found !== true
    const verdictText = current.assessment.verdict.toLowerCase()
    const inconclusive = verdictText.includes('inconclusive') || verdictText.includes('triage')

    if (versionConfirmed) {
        badges.push({
            label: 'Version confirmed',
            detail: 'At least one checked version has an affected/not-affected result.',
            tone: 'green',
        })
    } else if (checkedVersionRows.value.length > 0) {
        badges.push({
            label: 'Version uncertain',
            detail: 'Versions were checked, but no concrete affected/not-affected version was confirmed.',
            tone: 'yellow',
        })
    }

    if (sourceEvidence) {
        badges.push({
            label: 'Source evidence',
            detail: 'Repository, manifest, lockfile, code, or reachability evidence contributed to the result.',
            tone: 'cyan',
        })
    }

    if (sbomOnly) {
        badges.push({
            label: 'SBOM only',
            detail: 'The dependency is attributed by SBOM/input data and was not rediscovered locally.',
            tone: 'amber',
        })
    }

    if (externalResearch) {
        badges.push({
            label: 'External research',
            detail: 'Advisory sources or analyzer research tool activity are present.',
            tone: 'blue',
        })
    }

    if (inconclusive) {
        badges.push({
            label: 'Inconclusive',
            detail: 'The analyzer did not produce a final affected/not-affected conclusion.',
            tone: 'yellow',
        })
    }

    if (badges.length === 0) {
        badges.push({
            label: 'Limited evidence',
            detail: 'No version, source, SBOM, or external research markers were reported.',
            tone: 'gray',
        })
    }

    return badges
})

const evidenceQualityClass = (tone: EvidenceQualityTone) => {
    switch (tone) {
        case 'green': return 'border-green-700/40 bg-green-950/25 text-green-200'
        case 'cyan': return 'border-cyan-700/40 bg-cyan-950/25 text-cyan-200'
        case 'blue': return 'border-blue-700/40 bg-blue-950/25 text-blue-200'
        case 'amber': return 'border-amber-700/40 bg-amber-950/30 text-amber-200'
        case 'yellow': return 'border-yellow-700/40 bg-yellow-950/25 text-yellow-200'
        default: return 'border-gray-700/50 bg-gray-950/40 text-gray-300'
    }
}

// Auto-select all when component list is first populated
watch(uniqueComponents, (comps) => {
    if (selectedComponents.value.size === 0 && comps.length > 0) {
        selectedComponents.value = new Set(comps)
    }
}, { immediate: true })

// Find active queue items for this vulnerability
const activeQueueItems = computed(() => {
    return analysisQueueStore.items.value.filter(
        i => i.vuln_id === props.vulnId && (i.status === 'queued' || i.status === 'running')
    )
})

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

const hasAffectedResult = computed(() => {
    if (!result.value) return false
    return result.value.assessment.affected || result.value.assessment.verdict.toLowerCase() === 'affected'
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
    let allConversationTurns: CodeAnalysisLlmConversationTurn[] = []
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
        allConversationTurns = allConversationTurns.concat(
            (response.llm_conversation || []).map(turn => ({
                ...turn,
                component: turn.component || component,
            }))
        )
    }

    const summaryParts = results.map(r => `${r.component}: ${r.response.assessment.verdict}`)
    const ticketParts = results
        .map(r => stringifyTicketValue(r.response.assessment.ticket_text))
        .filter(Boolean)
    worstAssessment = {
        ...worstAssessment,
        summary: `Combined analysis for ${results.length} components. ${summaryParts.join('; ')}`,
        reasoning: 'Global result merged from the latest completed analysis for each selected component.',
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

const handleComponentError = (_batchId: string, component: string, err: string) => {
    error.value = `[${component}] ${err}`
}

const startAnalysis = async () => {
    submitting.value = true
    componentDropdownOpen.value = false
    error.value = null
    result.value = null
    selectedFullRecord.value = null
    benchmarkComparison.value = null
    benchmarkError.value = null
    collectedResults.value = []
    pendingQueueIds.value = []

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
                props.affectedProductVersions,
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
    const expectedRunId = options.expectedRunId || null
    const attempts = Math.max(1, options.attempts ?? 1)
    const delayMs = Math.max(0, options.delayMs ?? 0)
    historyLoading.value = true
    historyError.value = null
    try {
        const projectName = props.projectName || '_all_'
        for (let attempt = 0; attempt < attempts; attempt += 1) {
            const records = await codeAnalysisListVulnerabilityResults(
                projectName,
                props.vulnId,
                { limit: 20 },
            )
            persistedResults.value = records

            const expectedRecord = expectedRunId
                ? records.find(record => recordMatchesRunId(record, expectedRunId))
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
        }
    } catch (err: any) {
        historyError.value = err?.response?.data?.detail || err?.message || 'Unable to load analysis history.'
    } finally {
        historyLoading.value = false
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

// Load the most recent completed result for the current component selection
const loadCompletedResult = async () => {
    if (activeQueueItems.value.length > 0) return // Don't overwrite active state

    const targets = [...selectedComponents.value]

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
        selectedRunId.value = completedForTargets[0]?.queue_id || null
        selectedFullRecord.value = null
        followUpComponent.value = results[0].component
    } else {
        result.value = mergeResults(results)
        selectedRunId.value = null
        selectedFullRecord.value = null
        followUpComponent.value = results[0].component
    }
    analyzedComponents.value = results.map(r => r.component)
}

const viewCompletedResult = async (item: AnalysisQueueItem) => {
    const res = await analysisQueueStore.fetchResult(item.queue_id)
    if (!res) return

    result.value = res
    analyzedComponents.value = [item.component_name]
    selectedRunId.value = item.queue_id
    selectedFullRecord.value = null
    followUpComponent.value = item.component_name
    if (!selectedComponents.value.has(item.component_name)) {
        selectedComponents.value = new Set([item.component_name])
    }
}

const viewPersistedResult = async (record: CodeAnalysisResultRecord) => {
    try {
        const full = record.result ? record : await codeAnalysisGetResult(record.analysis_run_id)
        if (!full.result) return
        result.value = full.result
        analyzedComponents.value = [full.component_name]
        selectedRunId.value = full.analysis_run_id
        selectedFullRecord.value = full
        followUpComponent.value = full.component_name
        if (!selectedComponents.value.has(full.component_name)) {
            selectedComponents.value = new Set([full.component_name])
        }
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Failed to load analysis result.'
    }
}

const loadLatestPersistedResult = async () => {
    if (activeQueueItems.value.length > 0 || result.value) return
    const targets = new Set([...selectedComponents.value].map(component => component.toLowerCase()))
    const record = persistedResults.value.find(candidate =>
        targets.size === 0 || targets.has(candidate.component_name.toLowerCase())
    ) || latestPersistedResult.value
    if (record) {
        await viewPersistedResult(record)
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
    if (!window.confirm(`Remove saved analysis run for ${label}? This cannot be undone.`)) return

    const next = new Set(deletingRunIds.value)
    next.add(runId)
    deletingRunIds.value = next
    error.value = null
    historyError.value = null
    try {
        await codeAnalysisDeleteResult(runId)
        persistedResults.value = persistedResults.value.filter(candidate =>
            !recordMatchesRunId(candidate, runId)
        )
        if (selectedRunId.value === runId) {
            const replacement = persistedResults.value[0] || null
            if (replacement) {
                await viewPersistedResult(replacement)
            } else {
                selectedRunId.value = null
                selectedFullRecord.value = null
                result.value = null
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

const formatHistoryTimestamp = (value?: string | null) => {
    if (!value) return 'unknown'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return 'unknown'
    return date.toLocaleString([], {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
    })
}

const formatContextSummary = (record: CodeAnalysisResultRecord) => {
    const summary = record.context_summary || {}
    const versionCount = Array.isArray(summary.project_versions)
        ? summary.project_versions.length
        : null
    const instanceCount = typeof summary.instance_count === 'number'
        ? summary.instance_count
        : null
    const parts = [
        versionCount !== null ? `${versionCount} version${versionCount === 1 ? '' : 's'}` : '',
        instanceCount !== null ? `${instanceCount} finding${instanceCount === 1 ? '' : 's'}` : '',
    ].filter(Boolean)
    return parts.join(', ')
}

const uniqueTextValues = (values: Array<string | null | undefined>) => {
    const seen = new Set<string>()
    const result: string[] = []
    for (const value of values) {
        const text = String(value || '').trim()
        if (!text) continue
        const key = text.toLowerCase()
        if (seen.has(key)) continue
        seen.add(key)
        result.push(text)
    }
    return result
}

const ticketBulletList = (values: string[], fallback = 'Not reported') =>
    values.length
        ? values.map(value => `- ${value}`).join('\n')
        : `- ${fallback}`

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

const ticketContextComponents = computed(() => {
    const context = selectedPersistedResult.value?.context_summary
    const rows = Array.isArray(context?.components) ? context.components : []
    return rows
        .map((row: Record<string, any>) => {
            const name = stringifyTicketValue(row.component_name)
            const version = stringifyTicketValue(row.component_version)
            const projectVersion = stringifyTicketValue(row.project_version)
            const purl = stringifyTicketValue(row.component_purl)
            const chains = Array.isArray(row.dependency_chains)
                ? row.dependency_chains.map(stringifyTicketValue).filter(Boolean).slice(0, 2)
                : []
            return [
                name ? `${name}${version ? ` ${version}` : ''}` : '',
                projectVersion ? `project version ${projectVersion}` : '',
                purl ? `purl ${purl}` : '',
                chains.length ? `dependency path ${chains.join(' | ')}` : '',
            ].filter(Boolean).join(' - ')
        })
        .filter(Boolean)
        .slice(0, 10)
})

const ticketComponents = computed(() => {
    if (!result.value) return []
    return uniqueTextValues([
        ...(result.value.component_results || []).map(entry => entry.component),
        ...analyzedComponents.value,
        followUpComponent.value,
        selectedPersistedResult.value?.component_name,
        ...[...selectedComponents.value],
    ])
})

const ticketText = computed(() => {
    if (!result.value || !hasAffectedResult.value) return ''

    const assessment = result.value.assessment
    const generatedTicket = stringifyTicketValue(assessment.ticket_text)
    if (generatedTicket) return generatedTicket

    const projectName = props.projectName || selectedPersistedResult.value?.project_name || 'the product'
    const components = ticketComponents.value
    const componentLabel = components.length ? components.join(', ') : 'the affected component'
    const versionsChecked = uniqueTextValues(result.value.versions_checked || [])
    const componentResults = (result.value.component_results || [])
        .map(entry => {
            const versions = uniqueTextValues(entry.versions_checked || [])
            return `${entry.component}: ${entry.assessment.verdict} (${entry.assessment.confidence} confidence${versions.length ? `, versions ${versions.join(', ')}` : ''})`
        })
    const cvss = assessment.adjusted_cvss
    const cvssLines = cvss ? [
        `Original score: ${cvss.original_score}`,
        `Adjusted score: ${cvss.adjusted_score}`,
        cvss.original_vector ? `Original vector: ${cvss.original_vector}` : '',
        cvss.adjusted_vector ? `Adjusted vector: ${cvss.adjusted_vector}` : '',
        cvss.summary ? `CVSS assessment: ${cvss.summary}` : '',
    ].filter(Boolean) : []
    const remediationRecommendations = Array.isArray(assessment.remediation_view?.recommendations)
        ? assessment.remediation_view.recommendations.map(stringifyTicketValue).filter(Boolean)
        : []
    const fallbackRemediation = remediationRecommendations.length ? remediationRecommendations : [
        `Update the vulnerable dependency to a fixed version or safe range for ${props.vulnId}.`,
        'If the vulnerable dependency is transitive, update or replace the direct parent/intermediary dependency that resolves it, or add an explicit override/exclusion so the vulnerable version is no longer used.',
        'Add component-level validation, configuration guards, or wrappers only when a dependency update is not immediately available or additional mitigation is required.',
    ]

    return [
        `Title: ${props.vulnId} affects ${projectName} via ${componentLabel}`,
        '',
        'Issue',
        `${projectName} was assessed as affected by ${props.vulnId}. The affected target is ${componentLabel}.`,
        '',
        'Analysis',
        `- Verdict: ${assessment.verdict}`,
        `- Confidence: ${assessment.confidence}`,
        `- Exposure: ${assessment.exposure}`,
        `- Summary: ${assessment.summary}`,
        `- Reasoning: ${assessment.reasoning}`,
        `- Versions checked: ${versionsChecked.length ? versionsChecked.join(', ') : 'Not reported'}`,
        ...(props.cvssVector ? [`- Advisory CVSS vector: ${props.cvssVector}`] : []),
        '',
        'Affected Components And Context',
        ticketBulletList(
            ticketContextComponents.value.length ? ticketContextComponents.value : components,
            'No component context was reported',
        ),
        ...(componentResults.length ? ['', 'Component Results', ticketBulletList(componentResults)] : []),
        ...(cvssLines.length ? ['', 'CVSS', ticketBulletList(cvssLines)] : []),
        '',
        'Remediation',
        ticketBulletList(fallbackRemediation),
        '',
        'Validation',
        `- Rerun the dependency scan and confirm ${props.vulnId} no longer appears for ${projectName}.`,
        '- Rerun the code analysis or equivalent regression tests for the reachable code path described above.',
        '- Attach the updated SBOM/dependency tree and the validation result to this ticket before closure.',
    ].join('\n')
})

const copyTextWithFallback = (text: string) => {
    const textarea = document.createElement('textarea')
    textarea.value = text
    textarea.setAttribute('readonly', 'true')
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    document.body.appendChild(textarea)
    textarea.select()
    const copied = document.execCommand('copy')
    document.body.removeChild(textarea)
    if (!copied) throw new Error('Clipboard copy was not accepted by the browser.')
}

const copyTicketText = async () => {
    if (!ticketText.value) return
    ticketCopyState.value = 'idle'
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(ticketText.value)
        } else {
            copyTextWithFallback(ticketText.value)
        }
        ticketCopyState.value = 'copied'
        window.setTimeout(() => {
            if (ticketCopyState.value === 'copied') ticketCopyState.value = 'idle'
        }, 2000)
    } catch (err: any) {
        ticketCopyState.value = 'error'
        error.value = err?.message || 'Unable to copy ticket text.'
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

const benchmarkEvaluatorLabel = (comparison: CodeAnalysisBenchmarkComparison) => {
    if (comparison.evaluator?.probabilistic) {
        const model = comparison.evaluator.model ? ` · ${comparison.evaluator.model}` : ''
        return `Agentyzer probabilistic${model}`
    }
    return 'DTVP fallback'
}

const verdictClass = (record: CodeAnalysisResultRecord) =>
    record.summary?.affected ? 'text-red-300' : 'text-green-400'

const benchmarkRatingClass = (tone?: string) => {
    switch (tone) {
        case 'green': return 'border-green-700/40 bg-green-950/30 text-green-200'
        case 'cyan': return 'border-cyan-700/40 bg-cyan-950/30 text-cyan-200'
        case 'amber': return 'border-amber-700/40 bg-amber-950/30 text-amber-200'
        case 'orange': return 'border-orange-700/40 bg-orange-950/30 text-orange-200'
        case 'red': return 'border-red-700/40 bg-red-950/30 text-red-200'
        default: return 'border-gray-700/50 bg-gray-950/40 text-gray-300'
    }
}

const benchmarkFindingClass = (severity?: string) => {
    switch (severity) {
        case 'high': return 'border-red-700/40 bg-red-950/20 text-red-200'
        case 'warning': return 'border-amber-700/40 bg-amber-950/20 text-amber-200'
        default: return 'border-gray-800 bg-gray-950/35 text-gray-300'
    }
}

type BenchmarkAlignment = 'aligned' | 'different' | 'review'

type BenchmarkComparisonState = {
    key: 'state' | 'justification' | 'cvss' | 'cvss_vector'
    label: string
    alignment: BenchmarkAlignment
    detail: string
}

const benchmarkComparisonStates = computed<BenchmarkComparisonState[]>(() => {
    const comparison = benchmarkComparison.value
    if (!comparison) return []

    const existingScore = comparison.human.cvss_score
    const analysisScore = comparison.automated.cvss_score
    const scoreComparable = existingScore != null && analysisScore != null
    const vectorMatch = comparison.deltas.cvss_vector_match

    return [
        {
            key: 'state',
            label: 'State Agreement',
            alignment: comparison.deltas.state_match || comparison.deltas.state_family_match
                ? 'aligned'
                : 'different',
            detail: `${formatBenchmarkState(comparison.human.state)} ↔ ${formatBenchmarkState(comparison.automated.state)}`,
        },
        {
            key: 'justification',
            label: 'Justification Agreement',
            alignment: comparison.deltas.justification_match ? 'aligned' : 'different',
            detail: `${formatBenchmarkState(comparison.human.justification)} ↔ ${formatBenchmarkState(comparison.automated.justification)}`,
        },
        {
            key: 'cvss',
            label: 'CVSS Score Agreement',
            alignment: !scoreComparable
                ? 'review'
                : comparison.deltas.cvss_delta === 0
                    ? 'aligned'
                    : 'different',
            detail: `${formatBenchmarkCvss(existingScore)} ↔ ${formatBenchmarkCvss(analysisScore)}`,
        },
        {
            key: 'cvss_vector',
            label: 'CVSS Vector Agreement',
            alignment: vectorMatch == null ? 'review' : vectorMatch ? 'aligned' : 'different',
            detail: vectorMatch == null
                ? 'One or both vectors are not set'
                : vectorMatch
                    ? 'Vectors match'
                    : 'Vectors differ',
        },
    ]
})

const benchmarkAlignmentIcon = (alignment: BenchmarkAlignment) => {
    if (alignment === 'aligned') return CheckCircle
    if (alignment === 'different') return XCircle
    return AlertTriangle
}

const benchmarkAlignmentLabel = (alignment: BenchmarkAlignment) => {
    if (alignment === 'aligned') return 'Aligned'
    if (alignment === 'different') return 'Different'
    return 'Review'
}

const benchmarkAlignmentClass = (alignment: BenchmarkAlignment) => {
    if (alignment === 'aligned') return 'border-green-800/50 bg-green-950/20 text-green-200'
    if (alignment === 'different') return 'border-red-800/50 bg-red-950/20 text-red-200'
    return 'border-amber-800/50 bg-amber-950/20 text-amber-200'
}

const benchmarkAlignmentTextClass = (alignment: BenchmarkAlignment) => {
    if (alignment === 'aligned') return 'text-green-300'
    if (alignment === 'different') return 'text-red-300'
    return 'text-amber-300'
}

const benchmarkFindingAlignment = (finding: CodeAnalysisBenchmarkFinding): BenchmarkAlignment => {
    const structured = benchmarkComparisonStates.value.find(state => state.key === finding.kind)
    if (structured) return structured.alignment
    if (finding.severity === 'high') return 'different'
    if (finding.severity === 'warning') return 'review'
    return 'aligned'
}

const formatBenchmarkState = (value?: string | null) =>
    String(value || 'NOT_SET').replace(/_/g, ' ')

const formatBenchmarkCvss = (value?: number | null) =>
    value == null ? 'Not set' : Number(value).toFixed(1).replace(/\.0$/, '.0')

const buildBenchmarkRequest = () => ({
    current_team: props.currentTeam || 'General',
    current_state: props.currentState || 'NOT_SET',
    current_justification: props.currentJustification || 'NOT_SET',
    current_details: props.currentDetails || '',
    current_cvss_score: props.currentCvssScore ?? null,
    current_cvss_vector: props.currentCvssVector || '',
})

const loadBenchmarkComparison = async () => {
    const record = selectedPersistedResult.value
    if (!hasExistingAssessment.value || !record?.analysis_run_id || !result.value) {
        benchmarkComparison.value = null
        benchmarkError.value = null
        benchmarkLoading.value = false
        return
    }

    const loadId = ++benchmarkLoadCounter
    benchmarkLoading.value = true
    benchmarkError.value = null
    try {
        const comparison = await codeAnalysisBenchmarkResult(record.analysis_run_id, buildBenchmarkRequest())
        if (loadId === benchmarkLoadCounter) {
            benchmarkComparison.value = comparison
        }
    } catch (err: any) {
        if (loadId === benchmarkLoadCounter) {
            benchmarkComparison.value = null
            benchmarkError.value = err?.response?.data?.detail || err?.message || 'Unable to compare this analysis result.'
        }
    } finally {
        if (loadId === benchmarkLoadCounter) {
            benchmarkLoading.value = false
        }
    }
}

const loadSystemPrompts = async () => {
    if (systemPromptOpen.value) {
        systemPromptOpen.value = false
        return
    }
    systemPromptOpen.value = true
    if (llmConversationTurns.value.length > 0) return
    if (systemPromptPayload.value || systemPromptLoading.value) return
    systemPromptLoading.value = true
    systemPromptError.value = null
    try {
        systemPromptPayload.value = await codeAnalysisGetPrompts({
            include_values: true,
            system_only: false,
        })
    } catch (err: any) {
        systemPromptError.value = err?.response?.data?.detail || err?.message || 'Unable to load LLM conversation.'
    } finally {
        systemPromptLoading.value = false
    }
}

const systemPromptBundles = computed(() => {
    const bundles = systemPromptPayload.value?.bundles
    return Array.isArray(bundles) ? bundles : []
})

const llmConversationTurns = computed<CodeAnalysisLlmConversationTurn[]>(() => {
    const turns = result.value?.llm_conversation
    return Array.isArray(turns) ? turns : []
})

type ConversationPartKind =
    | 'system'
    | 'template'
    | 'task'
    | 'vulnerability'
    | 'generated'
    | 'guidance'
    | 'answer'
    | 'dynamic'

type ConversationMessagePart = {
    key: string
    label: string
    kind: ConversationPartKind
    content: string
}

type ConversationMessage = {
    role: string
    content: string
    parts: ConversationMessagePart[]
}

type ConversationToolActivity = {
    key: string
    kind: 'search' | 'download' | 'package' | 'source' | 'failed' | 'research'
    label: string
    target: string
    detail: string
    status: 'requested' | 'provided' | 'failed'
}

const classifyPromptLine = (line: string): { label: string; kind: ConversationPartKind } | null => {
    const normalized = line.trim()
    if (!normalized) return null

    if (/^--- YOUR PREVIOUS PARTIAL RESPONSE ---$/i.test(normalized)) {
        return { label: 'LLM · prior partial answer', kind: 'answer' }
    }
    if (/^--- RESEARCH RESULTS/i.test(normalized)) {
        return { label: 'Dynamic · research context', kind: 'generated' }
    }
    if (/^Now (?:analyze|perform|produce)\b/i.test(normalized)) {
        return { label: 'Dynamic · task instruction', kind: 'task' }
    }
    if (/^(?:VULNERABILITY|Vuln|ADVISORY|SUMMARY|Affected packages|AFFECTED PACKAGES|Affected ranges|Affected versions|Fixed versions|CVSS|CWEs|Vulnerable symbols|VULNERABLE SYMBOLS|Advisory data warnings|Critical advisory gaps|Advisory details)\b:?/i.test(normalized)) {
        return { label: 'Dynamic · vulnerability/advisory', kind: 'vulnerability' }
    }
    if (/^(?:ANALYST GUIDANCE|Additional reviewer guidance)\b:?/i.test(normalized)) {
        return { label: 'Dynamic · component guidance', kind: 'guidance' }
    }
    if (/^(?:SNIPPETS|STRUCTURE|FILES|FIRST-PASS FINDING|INTERMEDIARY PACKAGES|DEPENDENCY CHAINS|EVIDENCE)\b:?/i.test(normalized)) {
        return { label: 'Dynamic · source/dependency context', kind: 'generated' }
    }
    if (/^(?:Respond with EXACTLY|Do NOT restate)\b/i.test(normalized)) {
        return { label: 'Static · response contract', kind: 'template' }
    }
    return null
}

const splitUserPromptParts = (content: string): ConversationMessagePart[] => {
    const lineMatches = [...content.matchAll(/^.*$/gm)]
    const allMarkers = lineMatches
        .map(match => {
            const classified = classifyPromptLine(match[0])
            if (!classified || match.index == null) return null
            return {
                index: match.index,
                ...classified,
            }
        })
        .filter((marker): marker is { index: number; label: string; kind: ConversationPartKind } => Boolean(marker))
    const firstTaskMarker = allMarkers.find(marker => marker.kind === 'task')
    const markers = firstTaskMarker
        ? allMarkers.filter(marker => marker.index >= firstTaskMarker.index)
        : allMarkers

    if (markers.length === 0) {
        return [{
            key: 'dynamic-user-prompt',
            label: 'Dynamic · user prompt',
            kind: 'dynamic',
            content,
        }]
    }

    const parts: ConversationMessagePart[] = []
    if (markers[0].index > 0) {
        const prefix = content.slice(0, markers[0].index).trim()
        if (prefix) {
            parts.push({
                key: 'static-template-prefix',
                label: 'Static · prompt template prefix',
                kind: 'template',
                content: prefix,
            })
        }
    }

    markers.forEach((marker, index) => {
        const next = markers[index + 1]
        const raw = content.slice(marker.index, next?.index ?? content.length).trim()
        if (!raw) return
        parts.push({
            key: `prompt-part-${index}`,
            label: marker.label,
            kind: marker.kind,
            content: raw,
        })
    })

    return parts
}

const buildConversationParts = (role: string, content: string): ConversationMessagePart[] => {
    const normalizedRole = role.toLowerCase()
    if (normalizedRole === 'system') {
        return [{
            key: 'system-prompt',
            label: 'Static · system prompt',
            kind: 'system',
            content,
        }]
    }
    if (normalizedRole === 'tool') {
        return [{
            key: 'tool-result',
            label: 'Dynamic · tool result',
            kind: 'generated',
            content,
        }]
    }
    if (normalizedRole === 'user') {
        return splitUserPromptParts(content)
    }
    return [{
        key: `${normalizedRole || 'message'}-payload`,
        label: 'Dynamic · message payload',
        kind: 'dynamic',
        content,
    }]
}

const nativeToolCalls = (value: unknown): Record<string, any>[] => {
    if (!value || typeof value !== 'object') return []
    const calls = (value as Record<string, any>).tool_calls
    return Array.isArray(calls) ? calls.filter(call => call && typeof call === 'object') : []
}

const conversationMessageContent = (message: CodeAnalysisLlmMessage): string => {
    const content = stringifyPromptContent(message?.content)
    if (content) return content
    const calls = nativeToolCalls(message)
    return calls.length ? stringifyPromptContent(calls) : ''
}

const conversationMessages = (turn: CodeAnalysisLlmConversationTurn) => {
    const messages = Array.isArray(turn.messages) ? turn.messages : []
    return messages
        .map(message => ({
            role: String(message?.role || 'message'),
            content: conversationMessageContent(message),
        }))
        .filter(message => message.content)
        .map((message): ConversationMessage => ({
            ...message,
            parts: buildConversationParts(message.role, message.content),
        }))
}

const conversationResponse = (turn: CodeAnalysisLlmConversationTurn) => {
    const response = turn.response
    if (!response) return null
    if (typeof response === 'string') {
        const content = response.trim()
        return content ? { role: 'assistant', content } : null
    }
    const content = stringifyPromptContent(response.content)
    if (content) {
        return { role: String(response.role || 'assistant'), content }
    }
    const calls = nativeToolCalls(response)
    return calls.length
        ? { role: String(response.role || 'assistant'), content: stringifyPromptContent(calls) }
        : null
}

const toolLabelForDirective = (directive: string) => {
    const normalized = directive.toUpperCase()
    if (normalized === 'FETCH_SEARCH') return { kind: 'search' as const, label: 'Requested web search' }
    if (normalized === 'FETCH_URL') return { kind: 'download' as const, label: 'Requested URL download' }
    if (normalized === 'FETCH_PACKAGE') return { kind: 'package' as const, label: 'Requested package lookup' }
    if (normalized === 'FETCH_SOURCE') return { kind: 'source' as const, label: 'Requested source download' }
    return { kind: 'research' as const, label: 'Requested external resource' }
}

const toolLabelForNativeCall = (name: string) => {
    const normalized = name.toLowerCase()
    if (normalized === 'search_web') return { kind: 'search' as const, label: 'Requested web search' }
    if (normalized === 'fetch_url') return { kind: 'download' as const, label: 'Requested URL download' }
    if (normalized === 'fetch_package') return { kind: 'package' as const, label: 'Requested package lookup' }
    if (normalized === 'fetch_source') return { kind: 'source' as const, label: 'Requested source download' }
    return { kind: 'research' as const, label: 'Requested external resource' }
}

const nativeToolCallName = (call: Record<string, any>) => String(call?.function?.name || call?.name || '').trim()

const nativeToolCallArgs = (call: Record<string, any>): Record<string, any> => {
    const raw = call?.function?.arguments ?? call?.arguments ?? {}
    if (raw && typeof raw === 'object') return raw
    if (typeof raw !== 'string') return {}
    try {
        const parsed = JSON.parse(raw)
        return parsed && typeof parsed === 'object' ? parsed : {}
    } catch {
        return {}
    }
}

const nativeToolCallTarget = (call: Record<string, any>) => {
    const args = nativeToolCallArgs(call)
    return String(args.query || args.url || args.package || args.name || '').trim()
}

const analyzerRequiredToolLabel = (label: string) => label.replace(/^Requested\b/, 'Analyzer-required')

const toolResultMeta = (heading: string): Pick<ConversationToolActivity, 'kind' | 'label' | 'status'> | null => {
    const normalized = heading.trim().toLowerCase()
    if (normalized.startsWith('search results for')) {
        return { kind: 'search', label: 'Search results provided', status: 'provided' }
    }
    if (normalized.startsWith('search failed')) {
        return { kind: 'failed', label: 'Web search failed', status: 'failed' }
    }
    if (normalized.startsWith('fetched')) {
        return { kind: 'download', label: 'Downloaded URL text provided', status: 'provided' }
    }
    if (normalized.startsWith('fetch failed')) {
        return { kind: 'failed', label: 'URL download failed', status: 'failed' }
    }
    if (normalized.startsWith('package info')) {
        return { kind: 'package', label: 'Package metadata provided', status: 'provided' }
    }
    if (normalized.startsWith('package lookup failed')) {
        return { kind: 'failed', label: 'Package lookup failed', status: 'failed' }
    }
    if (normalized.startsWith('source of')) {
        return { kind: 'source', label: 'Source download provided', status: 'provided' }
    }
    if (normalized.startsWith('source fetch failed')) {
        return { kind: 'failed', label: 'Source download failed', status: 'failed' }
    }
    if (normalized.startsWith('tool call failed')) {
        return { kind: 'failed', label: 'Tool call failed', status: 'failed' }
    }
    return null
}

const conversationToolActivities = (turn: CodeAnalysisLlmConversationTurn): ConversationToolActivity[] => {
    const activities: ConversationToolActivity[] = []
    const seen = new Set<string>()
    const add = (activity: Omit<ConversationToolActivity, 'key'>) => {
        const key = `${activity.status}|${activity.label}|${activity.target}|${activity.detail}`
        if (seen.has(key)) return
        seen.add(key)
        activities.push({ ...activity, key })
    }

    const response = conversationResponse(turn)
    const responseContent = response?.content || ''
    const directivePattern = /^\s*FETCH_(SEARCH|URL|PACKAGE|SOURCE):\s*(.+)$/gim
    for (const call of nativeToolCalls(turn.response)) {
        const name = nativeToolCallName(call)
        const target = nativeToolCallTarget(call)
        const meta = toolLabelForNativeCall(name)
        add({
            kind: meta.kind,
            label: meta.label,
            target: target || name || 'external resource',
            detail: name || 'native tool call',
            status: 'requested',
        })
    }
    for (const match of responseContent.matchAll(directivePattern)) {
        const directive = `FETCH_${match[1].toUpperCase()}`
        const target = (match[2] || '').trim()
        if (!target) continue
        const meta = toolLabelForDirective(directive)
        add({
            kind: meta.kind,
            label: meta.label,
            target,
            detail: directive,
            status: 'requested',
        })
    }

    const messages = Array.isArray(turn.messages) ? turn.messages : []
    const resultPattern = /^---\s*(Search results for|Search failed|Fetched|Fetch failed|Package info|Package lookup failed|Source of|Source fetch failed|Tool call failed):?\s*(.*?)\s*---$/gim
    for (const message of messages) {
        const role = String(message?.role || '').toLowerCase()
        if (role !== 'user' && role !== 'tool') continue
        const content = stringifyPromptContent(message?.content)
        if (/MANDATORY EXTERNAL CHECK/im.test(content)) {
            for (const match of content.matchAll(directivePattern)) {
                const directive = `FETCH_${match[1].toUpperCase()}`
                const target = (match[2] || '').trim()
                if (!target) continue
                const meta = toolLabelForDirective(directive)
                add({
                    kind: meta.kind,
                    label: analyzerRequiredToolLabel(meta.label),
                    target,
                    detail: directive,
                    status: 'requested',
                })
            }
        }
        if (role !== 'tool' && !/^--- RESEARCH RESULTS/im.test(content)) continue
        for (const match of content.matchAll(resultPattern)) {
            const heading = match[1] || ''
            const target = (match[2] || '').trim()
            const meta = toolResultMeta(heading)
            if (!meta) continue
            add({
                ...meta,
                target: target || 'external resource',
                detail: heading,
            })
        }
    }

    return activities
}

const toolActivityClass = (activity: ConversationToolActivity) => {
    if (activity.status === 'failed' || activity.kind === 'failed') {
        return 'border-red-700/50 bg-red-950/30 text-red-200'
    }
    if (activity.status === 'requested') {
        return 'border-amber-600/50 bg-amber-950/30 text-amber-100'
    }
    if (activity.kind === 'search') return 'border-cyan-700/50 bg-cyan-950/30 text-cyan-100'
    if (activity.kind === 'download' || activity.kind === 'source') return 'border-blue-700/50 bg-blue-950/30 text-blue-100'
    return 'border-gray-700/60 bg-gray-900 text-gray-200'
}

const stringifyPromptContent = (value: unknown): string => {
    if (value == null) return ''
    if (typeof value === 'string') return value
    try {
        return JSON.stringify(value, null, 2)
    } catch {
        return String(value)
    }
}

type CheckedVersionRow = {
    key: string
    component: string
    ref: string
    refType: string
    productVersion: string
    version: string
    source: string
    status: string
    notes: string
}

const checkedVersionStatus = (value: unknown): string => {
    if (value === true) return 'affected'
    if (value === false) return 'not affected'
    const text = stringifyPromptContent(value).trim().toLowerCase()
    if (!text) return 'unknown'
    if (['yes', 'true', 'affected'].includes(text)) return 'affected'
    if (['no', 'false', 'ok', 'not affected', 'not_affected'].includes(text)) return 'not affected'
    return text
}

const checkedVersionStatusClass = (status: string) => {
    if (status === 'affected') return 'text-red-300 border-red-700/40 bg-red-950/30'
    if (status === 'not affected') return 'text-green-300 border-green-700/40 bg-green-950/30'
    return 'text-gray-300 border-gray-700/50 bg-gray-900/60'
}

const normalizeCheckedVersionRow = (
    entry: Record<string, unknown>,
    component = '',
): CheckedVersionRow | null => {
    const ref = stringifyPromptContent(entry.ref).trim()
        || stringifyPromptContent(entry.name).trim()
        || stringifyPromptContent(entry.branch).trim()
        || stringifyPromptContent(entry.tag).trim()
        || 'detected'
    const refType = stringifyPromptContent(entry.ref_type).trim()
        || stringifyPromptContent(entry.type).trim()
        || 'ref'
    const productVersion = stringifyPromptContent(entry.product_version).trim()
    const version = stringifyPromptContent(entry.version).trim()
        || stringifyPromptContent(entry.component_version).trim()
        || '-'
    const source = stringifyPromptContent(entry.source).trim() || '-'
    const notes = stringifyPromptContent(entry.notes).trim()
    const status = checkedVersionStatus(entry.affected)
    if (!ref && !version && !notes) return null
    return {
        key: [component, ref, refType, productVersion, version, source, status, notes].join('|'),
        component,
        ref,
        refType,
        productVersion,
        version,
        source,
        status,
        notes,
    }
}

const coverageFallbackComponent = computed(() => {
    const analyzed = analyzedComponents.value.map(value => String(value || '').trim()).filter(Boolean)
    if (analyzed.length === 1) return analyzed[0]
    const selected = [...selectedComponents.value].map(value => String(value || '').trim()).filter(Boolean)
    if (selected.length === 1) return selected[0]
    const persistedComponent = selectedPersistedResult.value?.component_name || latestPersistedResult.value?.component_name
    if (persistedComponent) return persistedComponent
    return uniqueComponents.value.length === 1 ? uniqueComponents.value[0] : ''
})

const coverageProductVersionLabel = (row: CheckedVersionRow) => {
    if (row.productVersion) return row.productVersion
    const refType = row.refType.toLowerCase()
    if (['lock', 'worktree', 'resolved'].includes(refType)) return 'Current workspace'
    return 'Not tied to product version'
}

const checkedVersionRows = computed<CheckedVersionRow[]>(() => {
    const current = result.value
    if (!current) return []

    const rows: CheckedVersionRow[] = []
    const seen = new Set<string>()
    const addRow = (row: CheckedVersionRow | null) => {
        if (!row || seen.has(row.key)) return
        seen.add(row.key)
        rows.push(row)
    }
    const addAssessmentRows = (assessment: CodeAnalysisAssessment | undefined, component = coverageFallbackComponent.value) => {
        const checked = assessment?.version_analysis?.checked_versions
        if (!Array.isArray(checked)) return
        for (const entry of checked) {
            if (!entry || typeof entry !== 'object') continue
            addRow(normalizeCheckedVersionRow(entry as Record<string, unknown>, component))
        }
    }

    const componentResults = current.component_results || []
    if (componentResults.length) {
        for (const componentResult of componentResults) {
            addAssessmentRows(componentResult.assessment, componentResult.component)
        }
        if (!rows.length) {
            addAssessmentRows(current.assessment)
        }
    } else {
        addAssessmentRows(current.assessment)
    }

    if (rows.length) return rows

    for (const version of current.versions_checked || []) {
        const component = coverageFallbackComponent.value
        addRow({
            key: `${component}|reported|version||${version}|unknown|`,
            component,
            ref: 'reported',
            refType: 'version',
            productVersion: '',
            version,
            source: '-',
            status: 'unknown',
            notes: '',
        })
    }
    for (const componentResult of componentResults) {
        for (const version of componentResult.versions_checked || []) {
            addRow({
                key: `${componentResult.component}|reported|version|${version}||unknown|`,
                component: componentResult.component,
                ref: 'reported',
                refType: 'version',
                productVersion: '',
                version,
                source: '-',
                status: 'unknown',
                notes: '',
            })
        }
    }

    return rows
})

const checkedVersionCoverageSummary = computed(() => {
    const rows = checkedVersionRows.value
    if (!rows.length) return 'No checked refs'
    const affected = rows.filter(row => row.status === 'affected').length
    const notAffected = rows.filter(row => row.status === 'not affected').length
    const unknown = rows.length - affected - notAffected
    const parts = [
        affected ? `${affected} affected` : '',
        notAffected ? `${notAffected} not affected` : '',
        unknown ? `${unknown} unknown` : '',
    ].filter(Boolean)
    return `${rows.length} checked ref${rows.length === 1 ? '' : 's'}${parts.length ? ` · ${parts.join(' · ')}` : ''}`
})

const llmConversationSummary = computed(() => {
    const turns = llmConversationTurns.value.length
    if (turns) return `${turns} LLM turn${turns === 1 ? '' : 's'}`
    if (systemPromptBundles.value.length > 0) return `${systemPromptBundles.value.length} prompt bundle${systemPromptBundles.value.length === 1 ? '' : 's'}`
    if (requestGuidancePreview.value) return 'Request guidance available'
    return 'No conversation reported'
})

const pipelineEvidenceSummary = computed(() => {
    const count = result.value?.steps.length || 0
    return count ? `${count} step${count === 1 ? '' : 's'}` : 'No pipeline steps'
})

const formatConversationMeta = (turn: CodeAnalysisLlmConversationTurn, index: number) => {
    const parts = [
        `Turn ${index + 1}`,
        turn.component || '',
        turn.model || '',
        turn.provider || turn.backend || '',
        turn.status && turn.status !== 'completed' ? turn.status : '',
    ].filter(Boolean)
    return parts.join(' · ')
}

const formatPromptValueLabel = (key: unknown) =>
    String(key || 'prompt').replace(/_/g, ' ')

const normalizeConversationRole = (role: string) => String(role || '').trim().toLowerCase()

const conversationActorLabel = (role: string) => {
    switch (normalizeConversationRole(role)) {
        case 'system':
            return 'System'
        case 'user':
            return 'User'
        case 'assistant':
            return 'LLM'
        case 'tool':
            return 'Tool'
        default:
            return role || 'Message'
    }
}

const conversationSentMeta = (role: string) => {
    switch (normalizeConversationRole(role)) {
        case 'system':
            return 'sent to LLM · static prompt'
        case 'user':
            return 'sent to LLM · request payload'
        case 'assistant':
            return 'sent to LLM · prior LLM message'
        case 'tool':
            return 'sent to LLM · tool result'
        default:
            return 'sent to LLM'
    }
}

const conversationRowClass = (role: string) =>
    normalizeConversationRole(role) === 'user' ? 'justify-end' : 'justify-start'

const conversationBubbleClass = (role: string) => {
    switch (normalizeConversationRole(role)) {
        case 'system':
            return 'border-blue-800/50 bg-blue-950/20 text-blue-100'
        case 'user':
            return 'border-cyan-700/50 bg-cyan-950/25 text-cyan-50'
        case 'assistant':
            return 'border-green-800/50 bg-green-950/20 text-green-100'
        case 'tool':
            return 'border-amber-700/50 bg-amber-950/20 text-amber-100'
        default:
            return 'border-gray-800 bg-gray-900 text-gray-300'
    }
}

const conversationPartLabelClass = (kind: ConversationPartKind) => {
    switch (kind) {
        case 'system':
            return 'text-blue-300'
        case 'template':
            return 'text-purple-300'
        case 'task':
            return 'text-cyan-300'
        case 'vulnerability':
            return 'text-amber-300'
        case 'generated':
            return 'text-teal-300'
        case 'guidance':
            return 'text-fuchsia-300'
        case 'answer':
            return 'text-green-300'
        default:
            return 'text-gray-400'
    }
}

// On mount, check if there are completed results to display
onMounted(() => {
    void (async () => {
        await loadPersistedResults()
        await loadCompletedResult()
        await loadLatestPersistedResult()
    })()
    document.addEventListener('click', handleClickOutside)
})

onBeforeUnmount(() => {
    document.removeEventListener('click', handleClickOutside)
})

function handleClickOutside(e: MouseEvent) {
    const target = e.target as HTMLElement
    if (componentDropdownOpen.value && !target.closest('.relative')) {
        componentDropdownOpen.value = false
    }
}

// When the component selection changes, try loading completed results
watch(selectedComponents, () => {
    if (!controlsBusy.value && activeQueueItems.value.length === 0) {
        result.value = null
        selectedRunId.value = null
        selectedFullRecord.value = null
        void (async () => {
            await loadCompletedResult()
            await loadLatestPersistedResult()
        })()
    }
})

watch(result, (current) => {
    coverageOpen.value = false
    stepsExpanded.value = false
    systemPromptOpen.value = false
    assessmentSummaryOpen.value = true
    assessmentDraftOpen.value = true
    assessmentBenchmarkOpen.value = true
    ticketDraftOpen.value = false
    emit('result-change', current, analyzedComponents.value)
})

watch([
    selectedPersistedResult,
    result,
    () => props.currentTeam,
    () => props.currentState,
    () => props.currentJustification,
    () => props.currentDetails,
    () => props.currentCvssScore,
    () => props.currentCvssVector,
], () => {
    void loadBenchmarkComparison()
})

watch(analyzedComponents, (components) => {
    if (result.value) {
        emit('result-change', result.value, components)
    }
})
</script>

<template>
    <div class="border border-cyan-700/40 rounded bg-gray-900/45 p-3 space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
            <h5 class="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-cyan-300">
                <Zap :size="14" />
                Code Analysis
            </h5>
            <span v-if="statusLabel" class="inline-flex items-center gap-1 text-[11px] font-semibold" :class="statusClass">
                <Loader2 v-if="queueStatus === 'running' || submitting" :size="11" class="animate-spin" />
                <Clock v-else-if="queueStatus === 'queued'" :size="11" />
                {{ statusLabel }}
            </span>
        </div>

        <div
            v-if="!hasOwnedTargets"
            class="rounded border border-amber-700/40 bg-amber-900/15 px-3 py-2 text-xs text-amber-200"
        >
            No team-assigned component target is available for code analysis.
        </div>

        <section class="rounded border border-gray-800 bg-gray-950/35 p-3">
            <div class="mb-3 flex flex-wrap items-start justify-between gap-3">
                <div>
                    <h6 class="text-[11px] font-bold uppercase tracking-wider text-cyan-300">Start Analysis</h6>
                    <p class="mt-1 text-xs leading-relaxed text-gray-500">Select one or more components, then press Analyze.</p>
                </div>
                <span v-if="hasOwnedTargets" class="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold uppercase text-gray-400">
                    {{ selectedComponents.size }} selected
                </span>
            </div>
            <div class="grid gap-3 items-end md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto_auto]">
                <div class="relative">
                    <label for="code-analysis-components" class="block text-[11px] font-semibold text-gray-500 uppercase mb-1">Components</label>
                    <button
                        id="code-analysis-components"
                        type="button"
                        @click="componentDropdownOpen = !componentDropdownOpen"
                        :disabled="controlsBusy || !hasOwnedTargets"
                        class="w-full p-2 rounded bg-gray-950 border border-gray-700 focus:border-cyan-500 text-xs disabled:opacity-50 text-left flex items-center justify-between cursor-pointer"
                    >
                        <span :class="noneSelected ? 'text-gray-500' : 'text-gray-200'" class="truncate">{{ selectionLabel }}</span>
                        <ChevronDown :size="12" class="shrink-0 text-gray-500 transition-transform" :class="{ 'rotate-180': componentDropdownOpen }" />
                    </button>
                    <div
                        v-if="componentDropdownOpen && !controlsBusy"
                        class="absolute z-20 mt-1 w-full max-h-48 overflow-y-auto rounded bg-gray-900 border border-gray-700 shadow-lg"
                    >
                        <label
                            v-if="uniqueComponents.length > 1"
                            class="flex items-center gap-2 px-2 py-1.5 text-xs hover:bg-gray-800 cursor-pointer border-b border-gray-700/50"
                        >
                            <input type="checkbox" :checked="allSelected" @change="toggleAll()" class="accent-cyan-500" />
                            <span class="text-gray-300 font-semibold">All ({{ uniqueComponents.length }})</span>
                        </label>
                        <label
                            v-for="c in uniqueComponents"
                            :key="c"
                            class="flex items-center gap-2 px-2 py-1.5 text-xs hover:bg-gray-800 cursor-pointer"
                        >
                            <input type="checkbox" :checked="selectedComponents.has(c)" @change="toggleComponent(c)" class="accent-cyan-500" />
                            <Clock v-if="activeComponentNames.has(c.toLowerCase())" :size="11" class="shrink-0 text-yellow-400" title="Analysis queued or running" />
                            <ClipboardCheck v-else-if="assessedComponentNames.has(c)" :size="11" class="shrink-0 text-purple-400" title="Team assessment exists" />
                            <CheckCircle v-else-if="completedComponentNames.has(c)" :size="11" class="shrink-0 text-green-400" title="Code analysis completed" />
                            <span class="font-mono truncate" :class="activeComponentNames.has(c.toLowerCase()) ? 'text-yellow-300' : assessedComponentNames.has(c) ? 'text-purple-300' : completedComponentNames.has(c) ? 'text-green-300' : 'text-gray-300'">{{ c }}</span>
                        </label>
                    </div>
                </div>

                <div>
                    <label for="code-analysis-guidance" class="block text-[11px] font-semibold text-gray-500 uppercase mb-1">Additional Guidance</label>
                    <input
                        id="code-analysis-guidance"
                        v-model="userGuidance"
                        :disabled="controlsBusy || !hasOwnedTargets"
                        placeholder="e.g. Focus on HTTP request handlers..."
                        class="w-full p-2 rounded bg-gray-950 border border-gray-700 focus:border-cyan-500 text-xs disabled:opacity-50"
                    />
                </div>

                <button
                    @click="startScan"
                    :disabled="!canStartScan"
                    class="flex items-center justify-center gap-2 px-4 py-2 rounded text-xs font-bold transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap"
                    :class="submitting
                        ? 'bg-cyan-900/40 text-cyan-400 border border-cyan-700/40'
                        : 'bg-cyan-600 hover:bg-cyan-700 text-white'"
                >
                    <Loader2 v-if="submitting" :size="14" class="animate-spin" />
                    <Zap v-else :size="14" />
                    {{ submitting ? 'Submitting...' : activeQueueItems.length > 0 ? 'Analyze More' : 'Analyze' }}
                </button>

            </div>
        </section>

        <section v-if="activeQueueItems.length > 0 || completedQueueItems.length > 0 || visiblePersistedResults.length > 0 || historyLoading" class="space-y-1.5 border-t border-gray-800/80 pt-3">
            <div class="flex items-center justify-between gap-3">
                <h6 class="text-[11px] font-bold uppercase tracking-wider text-gray-500">Runs &amp; History</h6>
                <span v-if="visiblePersistedResults.length > 0" class="text-[10px] text-gray-600">{{ visiblePersistedResults.length }} shown</span>
            </div>

            <div
                v-for="qi in activeQueueItems"
                :key="qi.queue_id"
                class="grid gap-2 rounded border px-2.5 py-1.5 text-[11px] md:grid-cols-[minmax(0,1fr)_auto]"
                :class="{
                    'bg-yellow-900/20 border-yellow-700/30': qi.status === 'queued',
                    'bg-blue-900/20 border-blue-700/30': qi.status === 'running',
                }"
            >
                <div class="flex min-w-0 flex-wrap items-center gap-2">
                    <Loader2 v-if="qi.status === 'running'" :size="12" class="animate-spin text-blue-400" />
                    <Clock v-else :size="12" class="text-yellow-400" />
                    <span class="min-w-0 truncate font-mono text-gray-200">{{ qi.component_name }}</span>
                    <span v-if="qi.source && qi.source !== 'manual'" class="rounded border px-1.5 py-0.5 text-[10px] uppercase font-semibold" :class="sourceClass(qi.source)">
                        {{ sourceLabel(qi.source) }}
                    </span>
                    <span v-if="qi.status === 'queued' && qi.position > 0" class="text-yellow-400 font-bold">#{{ qi.position }}</span>
                    <span class="uppercase font-semibold" :class="qi.status === 'running' ? 'text-blue-400' : 'text-yellow-400'">{{ qi.status }}</span>
                </div>
                <button
                    @click="cancelQueueItem(qi)"
                    :disabled="isQueueActionBusy(qi.queue_id)"
                    class="inline-flex items-center justify-center gap-1 rounded border border-transparent px-2 py-1 text-[10px] uppercase font-bold text-gray-500 hover:border-red-700/50 hover:bg-red-950/20 hover:text-red-300 cursor-pointer disabled:cursor-wait disabled:opacity-50"
                >
                    <Loader2 v-if="isQueueActionBusy(qi.queue_id)" :size="10" class="animate-spin" />
                    <Ban v-else :size="10" />
                    {{ qi.status === 'running' ? 'Abort' : 'Cancel' }}
                </button>
            </div>

            <div v-if="historyLoading" class="flex items-center gap-2 px-1 py-1 text-xs text-gray-500">
                <Loader2 :size="12" class="animate-spin" />
                Loading analysis history
            </div>

            <div
                v-for="qi in completedQueueItems"
                :key="qi.queue_id"
                class="grid gap-2 rounded border border-green-700/20 bg-green-900/10 px-2.5 py-1.5 text-[11px] cursor-pointer hover:bg-green-900/20 md:grid-cols-[minmax(0,1fr)_auto]"
                @click="viewCompletedResult(qi)"
            >
                <div class="flex min-w-0 flex-wrap items-center gap-2">
                    <CheckCircle :size="12" class="text-green-400" />
                    <span class="min-w-0 truncate font-mono text-gray-200">{{ qi.component_name }}</span>
                    <span v-if="qi.source && qi.source !== 'manual'" class="rounded border px-1.5 py-0.5 text-[10px] uppercase font-semibold" :class="sourceClass(qi.source)">
                        {{ sourceLabel(qi.source) }}
                    </span>
                    <span class="uppercase font-semibold text-green-400">completed</span>
                </div>
                <span class="text-[10px] text-cyan-400 font-semibold uppercase">View Result</span>
            </div>

            <div
                v-for="record in visiblePersistedResults"
                :key="record.analysis_run_id"
                class="grid gap-2 rounded border px-2.5 py-1.5 text-[11px] cursor-pointer hover:bg-cyan-900/15 md:grid-cols-[minmax(0,1fr)_auto]"
                :class="selectedRunId === record.analysis_run_id ? 'bg-cyan-900/20 border-cyan-700/40' : 'bg-gray-950/35 border-gray-700/40'"
                @click="viewPersistedResult(record)"
            >
                <div class="min-w-0">
                    <div class="flex min-w-0 flex-wrap items-center gap-2">
                        <History :size="12" class="shrink-0 text-cyan-400" />
                        <span class="min-w-0 truncate font-mono text-gray-200">{{ record.component_name }}</span>
                        <span class="shrink-0 rounded border px-1.5 py-0.5 text-[10px] uppercase font-semibold" :class="sourceClass(record.source)">
                            {{ sourceLabel(record.source) }}
                        </span>
                        <span class="shrink-0 uppercase font-semibold" :class="verdictClass(record)">
                            {{ record.summary?.verdict || 'saved' }}
                        </span>
                        <span class="text-[10px] text-gray-500">{{ formatHistoryTimestamp(record.finished_at || record.recorded_at) }}</span>
                    </div>
                    <div class="mt-0.5 flex min-w-0 flex-wrap gap-x-3 gap-y-0.5 pl-5 text-[10px] text-gray-600">
                        <span v-if="formatContextSummary(record)">{{ formatContextSummary(record) }}</span>
                        <span v-if="record.context_fingerprint" class="font-mono">ctx {{ record.context_fingerprint.slice(0, 8) }}</span>
                    </div>
                </div>
                <div class="flex shrink-0 items-center gap-2">
                    <span v-if="selectedRunId === record.analysis_run_id" class="text-[10px] font-semibold uppercase text-cyan-300">Selected</span>
                    <span class="text-[10px] text-cyan-400 font-semibold uppercase">View</span>
                    <button
                        type="button"
                        class="inline-flex h-6 w-6 items-center justify-center rounded border border-gray-700 text-gray-500 transition-colors hover:border-red-700/60 hover:bg-red-950/20 hover:text-red-300 disabled:cursor-wait disabled:opacity-50"
                        :disabled="isDeletingRun(record.analysis_run_id)"
                        :title="`Remove analysis run ${record.analysis_run_id}`"
                        aria-label="Remove analysis run"
                        @click.stop="removePersistedResult(record)"
                    >
                        <Loader2 v-if="isDeletingRun(record.analysis_run_id)" :size="12" class="animate-spin" />
                        <Trash2 v-else :size="12" />
                    </button>
                </div>
            </div>
        </section>

        <div v-if="historyError" class="rounded border border-amber-700/40 bg-amber-900/15 px-3 py-2 text-xs text-amber-200">
            {{ historyError }}
        </div>

        <section v-if="!result" class="space-y-2 border-t border-gray-800/80 pt-3">
            <button
                type="button"
                @click="loadSystemPrompts"
                class="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-gray-500 hover:text-cyan-300 cursor-pointer"
            >
                <Loader2 v-if="systemPromptLoading" :size="12" class="animate-spin" />
                <FileText v-else :size="12" />
                {{ systemPromptOpen ? 'Hide LLM Conversation' : 'LLM Conversation' }}
            </button>
            <div v-if="systemPromptOpen" class="rounded border border-gray-700/50 bg-gray-950/60 p-2">
                <div v-if="systemPromptLoading" class="flex items-center gap-2 text-xs text-gray-500">
                    <Loader2 :size="12" class="animate-spin" />
                    Loading conversation
                </div>
                <div v-else-if="systemPromptError" class="text-xs text-amber-300">
                    {{ systemPromptError }}
                </div>
                <div v-else-if="systemPromptBundles.length === 0 && !requestGuidancePreview" class="text-xs text-gray-500">
                    No LLM conversation reported
                </div>
                <div v-else class="max-h-72 overflow-auto space-y-2">
                    <div
                        v-for="bundle in systemPromptBundles"
                        :key="bundle.bundle"
                        class="space-y-1"
                    >
                        <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">{{ bundle.bundle }} configured prompt values (fallback, not a captured run)</div>
                        <pre
                            v-for="(value, key) in (bundle.values || {})"
                            :key="String(key)"
                            class="whitespace-pre-wrap break-words rounded bg-gray-900 p-2 text-[10px] leading-relaxed text-gray-300"
                        >{{ formatPromptValueLabel(key) }}:
{{ value }}</pre>
                    </div>
                    <div v-if="requestGuidancePreview" class="space-y-1">
                        <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">Additional request guidance sent to analyzer</div>
                        <pre class="whitespace-pre-wrap break-words rounded bg-gray-900 p-2 text-[10px] leading-relaxed text-gray-300">{{ requestGuidancePreview }}</pre>
                    </div>
                </div>
            </div>
        </section>

        <div v-if="error" class="flex items-start gap-2 p-2 rounded bg-red-900/20 border border-red-700/40 text-xs text-red-300">
            <XCircle :size="14" class="shrink-0 mt-0.5" />
            <span>{{ error }}</span>
        </div>

        <div v-if="result" class="space-y-4 border-t border-gray-800/80 pt-3">
            <h6 class="text-[11px] font-bold uppercase tracking-wider text-gray-500">Assessment Decision</h6>
            <section data-testid="assessment-decision" class="rounded border p-3" :class="{
                'bg-red-900/20 border-red-700/40': result.assessment.affected,
                'bg-green-900/20 border-green-700/40': !result.assessment.affected,
            }">
                <div class="flex flex-wrap items-start justify-between gap-3">
                    <div class="flex min-w-0 items-start gap-3">
                        <component :is="result.assessment.affected ? AlertTriangle : CheckCircle" :size="18" class="mt-0.5 shrink-0" :class="verdictColor" />
                        <div class="min-w-0">
                            <div class="text-[10px] font-bold uppercase tracking-wider text-gray-500">Verdict</div>
                            <div class="text-base font-bold" :class="verdictColor">{{ result.assessment.verdict }}</div>
                            <div class="mt-1 flex flex-wrap items-center gap-2">
                                <span class="text-[11px] px-2 py-0.5 rounded border" :class="confidenceBadge">
                                    {{ result.assessment.confidence }} confidence
                                </span>
                                <span class="text-[11px] text-gray-300">{{ result.assessment.exposure }}</span>
                            </div>
                        </div>
                    </div>
                    <button
                        @click="applyResult"
                        class="inline-flex items-center justify-center gap-2 px-3 py-2 rounded text-xs font-bold bg-cyan-600 hover:bg-cyan-700 text-white transition-colors cursor-pointer"
                    >
                        <CheckCircle :size="14" />
                        Use as Assessment Draft
                    </button>
                </div>
                <div class="mt-3 border-t border-white/10 pt-3">
                    <h6 class="mb-2 text-[11px] font-bold uppercase tracking-wider text-gray-400">Evidence Quality</h6>
                    <div class="flex flex-wrap gap-2">
                        <span
                            v-for="badge in evidenceQualityBadges"
                            :key="badge.label"
                            class="inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-semibold uppercase tracking-wide"
                            :class="evidenceQualityClass(badge.tone)"
                            :title="badge.detail"
                        >
                            {{ badge.label }}
                        </span>
                    </div>
                </div>
            </section>

            <section data-testid="assessment-summary" class="overflow-hidden rounded border border-cyan-900/50 bg-cyan-950/10">
                <button
                    type="button"
                    @click="assessmentSummaryOpen = !assessmentSummaryOpen"
                    class="flex w-full flex-wrap items-center justify-between gap-2 bg-cyan-950/20 px-3 py-2 text-left transition-colors hover:bg-cyan-950/30"
                    :aria-expanded="assessmentSummaryOpen"
                >
                    <span class="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-cyan-200">
                        <component :is="assessmentSummaryOpen ? ChevronUp : ChevronDown" :size="12" />
                        Summary
                    </span>
                    <span class="text-[10px] font-semibold text-gray-500">Rationale, final reasoning, and follow-up</span>
                </button>
                <div v-if="assessmentSummaryOpen" data-testid="assessment-summary-body" class="space-y-3 border-t border-cyan-900/40 p-3">
                    <p class="text-sm leading-relaxed text-gray-200">{{ result.assessment.summary }}</p>
                    <div v-if="result.assessment.reasoning" class="border-t border-cyan-900/30 pt-3">
                        <h6 class="mb-1 text-[10px] font-bold uppercase tracking-wider text-gray-500">Reasoning</h6>
                        <p class="text-xs leading-relaxed text-gray-400">{{ result.assessment.reasoning }}</p>
                    </div>
                    <div
                        v-if="followUpParentRunId"
                        class="grid items-end gap-3 border-t border-cyan-900/30 pt-3 md:grid-cols-[minmax(0,1fr)_minmax(8rem,14rem)_auto]"
                    >
                        <div>
                            <label for="code-analysis-follow-up" class="mb-1 block text-[11px] font-semibold uppercase text-gray-500">Follow-up Question</label>
                            <input
                                id="code-analysis-follow-up"
                                v-model="followUpQuestion"
                                :disabled="controlsBusy"
                                placeholder="e.g. Is the platform package affected?"
                                class="w-full rounded border border-gray-700 bg-gray-950 p-2 text-xs focus:border-cyan-500 disabled:opacity-50"
                                @keyup.enter="startFollowUp"
                            />
                        </div>
                        <div>
                            <label for="code-analysis-follow-up-target" class="mb-1 block text-[11px] font-semibold uppercase text-gray-500">Target</label>
                            <input
                                id="code-analysis-follow-up-target"
                                v-model="followUpComponent"
                                :disabled="controlsBusy"
                                class="w-full rounded border border-gray-700 bg-gray-950 p-2 font-mono text-xs focus:border-cyan-500 disabled:opacity-50"
                                @keyup.enter="startFollowUp"
                            />
                        </div>
                        <button
                            @click="startFollowUp"
                            :disabled="controlsBusy || !followUpParentRunId || !followUpQuestion.trim()"
                            class="flex items-center justify-center gap-2 whitespace-nowrap rounded bg-blue-600 px-4 py-2 text-xs font-bold text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
                        >
                            <Loader2 v-if="followUpSubmitting" :size="14" class="animate-spin" />
                            <Send v-else :size="14" />
                            Follow-up
                        </button>
                    </div>
                </div>
            </section>

            <section v-if="assessmentDraftPreview" data-testid="assessment-draft" class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                    <button
                        type="button"
                        @click="assessmentDraftOpen = !assessmentDraftOpen"
                        class="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-gray-950/60"
                        :aria-expanded="assessmentDraftOpen"
                    >
                        <span class="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-gray-400">
                            <component :is="assessmentDraftOpen ? ChevronUp : ChevronDown" :size="12" />
                            Assessment Draft
                        </span>
                        <span class="flex flex-wrap items-center gap-2">
                            <span class="font-semibold text-amber-300">{{ assessmentDraftChangeCount }} change{{ assessmentDraftChangeCount === 1 ? '' : 's' }}</span>
                            <span class="rounded border border-cyan-700/40 bg-cyan-950/30 px-2 py-0.5 font-semibold text-cyan-200">
                                Target {{ assessmentDraftPreview.targetTeam }}
                            </span>
                        </span>
                    </button>
                    <div v-if="assessmentDraftOpen" data-testid="assessment-draft-body" class="overflow-x-auto border-t border-gray-800 p-3">
                        <table class="min-w-full text-left text-[11px]">
                            <thead class="bg-gray-950/70 text-[10px] uppercase tracking-wider text-gray-500">
                                <tr>
                                    <th class="w-32 px-2 py-1.5 font-bold">Field</th>
                                    <th class="min-w-48 px-2 py-1.5 font-bold">Current</th>
                                    <th class="min-w-48 px-2 py-1.5 font-bold">Draft</th>
                                    <th class="w-24 px-2 py-1.5 font-bold">Status</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-800 bg-gray-950/30">
                                <tr v-for="row in assessmentDraftPreview.rows" :key="row.label" class="align-top">
                                    <td class="px-2 py-1.5 font-bold uppercase tracking-wider text-gray-500">{{ row.label }}</td>
                                    <td class="px-2 py-1.5 text-gray-500">
                                        <span class="break-words" :class="row.mono ? 'font-mono' : ''">{{ row.before }}</span>
                                    </td>
                                    <td class="px-2 py-1.5 text-gray-300">
                                        <span class="break-words" :class="row.mono ? 'font-mono' : ''">{{ row.after }}</span>
                                    </td>
                                    <td class="px-2 py-1.5">
                                        <span
                                            class="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase"
                                            :class="row.changed ? 'border-amber-700/40 bg-amber-950/25 text-amber-300' : 'border-gray-800 bg-gray-950/50 text-gray-600'"
                                        >
                                            {{ row.changed ? 'Change' : 'Same' }}
                                        </span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
            </section>

            <section v-if="hasExistingAssessment && selectedPersistedResult" data-testid="assessment-benchmark" class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                    <button
                        type="button"
                        @click="assessmentBenchmarkOpen = !assessmentBenchmarkOpen"
                        class="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-gray-950/60"
                        :aria-expanded="assessmentBenchmarkOpen"
                    >
                        <span class="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-gray-400">
                            <component :is="assessmentBenchmarkOpen ? ChevronUp : ChevronDown" :size="12" />
                            Assessment Benchmark
                        </span>
                        <span
                            v-if="benchmarkComparison"
                            class="inline-flex items-center gap-2 rounded border px-2 py-1 font-bold uppercase"
                            :class="benchmarkRatingClass(benchmarkComparison.rating.tone)"
                        >
                            Agreement <span class="font-mono">{{ benchmarkComparison.rating.score }}/{{ benchmarkComparison.rating.max_score }}</span>
                            <span>{{ benchmarkComparison.rating.grade }}</span>
                            <span>{{ benchmarkComparison.rating.label }}</span>
                        </span>
                    </button>
                    <div v-if="assessmentBenchmarkOpen" data-testid="assessment-benchmark-body" class="space-y-2 border-t border-gray-800 p-3">
                    <div v-if="benchmarkComparison" class="mb-2 flex flex-wrap items-center gap-2 text-[10px] text-gray-500">
                        <span class="rounded border border-gray-800 bg-gray-950/45 px-2 py-0.5 font-semibold uppercase">
                            {{ benchmarkEvaluatorLabel(benchmarkComparison) }}
                        </span>
                        <span v-if="benchmarkComparison.evaluator?.reason" class="text-amber-300">
                            {{ benchmarkComparison.evaluator.reason }}
                        </span>
                    </div>
                    <p v-if="benchmarkComparison" class="text-[10px] leading-relaxed text-gray-500">
                        The existing assessment is the current saved state. The analysis result is the selected run; neither side is assumed to be human-authored or ground truth.
                    </p>
                    <div v-if="benchmarkLoading" class="flex items-center gap-2 rounded border border-gray-800 bg-gray-950/35 px-3 py-2 text-xs text-gray-500">
                        <Loader2 :size="12" class="animate-spin" />
                        Comparing selected run with current assessment
                    </div>
                    <div v-else-if="benchmarkError" class="rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-200">
                        {{ benchmarkError }}
                    </div>
                    <div v-else-if="benchmarkComparison" class="space-y-2">
                        <div class="grid gap-3 md:grid-cols-2">
                            <div class="rounded border border-gray-700/60 bg-gray-950/45 p-3">
                                <div class="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 pb-2">
                                    <div class="text-[10px] font-bold uppercase tracking-wider text-gray-400">Existing Assessment</div>
                                    <div class="text-xs font-semibold text-gray-200">{{ formatBenchmarkState(benchmarkComparison.human.state) }}</div>
                                </div>
                                <div class="mt-3 grid gap-3">
                                    <div>
                                        <div class="text-[9px] font-bold uppercase tracking-wider text-gray-600">CVSS Score</div>
                                        <div class="mt-1 font-mono text-lg font-semibold text-gray-100">{{ formatBenchmarkCvss(benchmarkComparison.human.cvss_score) }}</div>
                                    </div>
                                    <div>
                                        <div class="text-[9px] font-bold uppercase tracking-wider text-gray-600">CVSS Vector</div>
                                        <div class="mt-1 break-all rounded bg-gray-950/80 p-2 font-mono text-[10px] leading-relaxed text-gray-300">{{ benchmarkComparison.human.cvss_vector || 'Not set' }}</div>
                                    </div>
                                    <div>
                                        <div class="text-[9px] font-bold uppercase tracking-wider text-gray-600">Justification</div>
                                        <div class="mt-1 text-xs text-gray-300">{{ formatBenchmarkState(benchmarkComparison.human.justification) }}</div>
                                    </div>
                                </div>
                            </div>
                            <div class="rounded border border-cyan-900/50 bg-cyan-950/10 p-3">
                                <div class="flex flex-wrap items-center justify-between gap-2 border-b border-cyan-900/30 pb-2">
                                    <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">Analysis Result</div>
                                    <div class="text-xs font-semibold text-gray-200">{{ formatBenchmarkState(benchmarkComparison.automated.state) }}</div>
                                </div>
                                <div class="mt-3 grid gap-3">
                                    <div>
                                        <div class="text-[9px] font-bold uppercase tracking-wider text-gray-600">CVSS Score</div>
                                        <div class="mt-1 font-mono text-lg font-semibold text-gray-100">{{ formatBenchmarkCvss(benchmarkComparison.automated.cvss_score) }}</div>
                                    </div>
                                    <div>
                                        <div class="text-[9px] font-bold uppercase tracking-wider text-gray-600">CVSS Vector</div>
                                        <div class="mt-1 break-all rounded bg-gray-950/80 p-2 font-mono text-[10px] leading-relaxed text-gray-300">{{ benchmarkComparison.automated.cvss_vector || 'Not set' }}</div>
                                    </div>
                                    <div>
                                        <div class="text-[9px] font-bold uppercase tracking-wider text-gray-600">Justification</div>
                                        <div class="mt-1 text-xs text-gray-300">{{ formatBenchmarkState(benchmarkComparison.automated.justification) }}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="rounded border border-gray-800 bg-gray-950/25 p-3">
                            <div class="mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-500">Comparison States</div>
                            <div class="grid gap-2 md:grid-cols-2">
                                <div
                                    v-for="state in benchmarkComparisonStates"
                                    :key="state.key"
                                    data-testid="benchmark-comparison-state"
                                    :data-alignment="state.alignment"
                                    class="flex items-start gap-2 rounded border p-2"
                                    :class="benchmarkAlignmentClass(state.alignment)"
                                >
                                    <component :is="benchmarkAlignmentIcon(state.alignment)" :size="15" class="mt-0.5 shrink-0" />
                                    <div class="min-w-0 flex-1">
                                        <div class="flex flex-wrap items-center justify-between gap-2">
                                            <span class="text-[10px] font-bold uppercase tracking-wider">{{ state.label }}</span>
                                            <span class="rounded border border-current/30 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider">
                                                {{ benchmarkAlignmentLabel(state.alignment) }}
                                            </span>
                                        </div>
                                        <div class="mt-1 break-words text-[10px] opacity-80">{{ state.detail }}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="rounded border border-gray-800 bg-gray-950/35 p-2 text-xs leading-relaxed text-gray-300">
                            {{ benchmarkComparison.recommendation }}
                        </div>
                        <div v-if="benchmarkComparison.reasoning_summary" class="rounded border border-cyan-900/40 bg-cyan-950/15 p-2 text-xs leading-relaxed text-cyan-100">
                            {{ benchmarkComparison.reasoning_summary }}
                        </div>
                        <div class="grid gap-2 md:grid-cols-2">
                            <div
                                v-for="finding in benchmarkComparison.findings"
                                :key="`${finding.kind}-${finding.title}`"
                                data-testid="benchmark-finding"
                                :data-alignment="benchmarkFindingAlignment(finding)"
                                class="flex items-start gap-2 rounded border p-2 text-xs"
                                :class="benchmarkFindingClass(finding.severity)"
                            >
                                <component
                                    :is="benchmarkAlignmentIcon(benchmarkFindingAlignment(finding))"
                                    :size="14"
                                    class="mt-0.5 shrink-0"
                                    :class="benchmarkAlignmentTextClass(benchmarkFindingAlignment(finding))"
                                />
                                <div class="min-w-0 flex-1">
                                    <div class="flex flex-wrap items-center justify-between gap-2">
                                        <span class="text-[10px] font-bold uppercase tracking-wider">{{ finding.title }}</span>
                                        <span
                                            class="text-[9px] font-bold uppercase tracking-wider"
                                            :class="benchmarkAlignmentTextClass(benchmarkFindingAlignment(finding))"
                                        >
                                            {{ benchmarkAlignmentLabel(benchmarkFindingAlignment(finding)) }}
                                        </span>
                                    </div>
                                    <div class="mt-1 leading-relaxed opacity-90">{{ finding.detail }}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    </div>
            </section>

            <section v-if="result.component_results?.length" class="space-y-2 border-t border-gray-800/80 pt-3">
                <h6 class="text-[11px] font-bold uppercase tracking-wider text-gray-500">Component Results</h6>
                <div class="grid gap-2 md:grid-cols-2">
                    <div
                        v-for="componentResult in result.component_results"
                        :key="componentResult.component"
                        class="rounded border border-gray-800 bg-gray-950/40 p-3"
                    >
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="font-mono text-xs text-gray-200">{{ componentResult.component }}</span>
                            <span class="text-[10px] font-bold uppercase" :class="componentResult.assessment.affected ? 'text-red-300' : 'text-green-300'">
                                {{ componentResult.assessment.verdict }}
                            </span>
                            <span class="text-[10px] text-gray-500">{{ componentResult.assessment.confidence }} confidence</span>
                        </div>
                        <p class="mt-2 text-xs leading-relaxed text-gray-400">{{ componentResult.assessment.summary }}</p>
                    </div>
                </div>
            </section>

            <section v-if="ticketText" data-testid="ticket-draft" class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                <div class="flex items-center gap-2 px-3 py-2 transition-colors hover:bg-gray-950/60">
                    <button
                        type="button"
                        @click="ticketDraftOpen = !ticketDraftOpen"
                        class="flex min-w-0 flex-1 items-center justify-between gap-2 text-left"
                        :aria-expanded="ticketDraftOpen"
                    >
                        <span class="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-red-200">
                            <component :is="ticketDraftOpen ? ChevronUp : ChevronDown" :size="12" />
                            <FileText :size="13" />
                            Ticket Draft
                        </span>
                        <span class="text-[10px] font-semibold text-gray-500">Developer-ready remediation ticket</span>
                    </button>
                    <button
                        type="button"
                        @click="copyTicketText"
                        class="inline-flex shrink-0 items-center gap-1.5 rounded bg-red-700 px-2.5 py-1 text-[10px] font-bold uppercase text-white hover:bg-red-600"
                    >
                        <CheckCircle v-if="ticketCopyState === 'copied'" :size="12" />
                        <Copy v-else :size="12" />
                        {{ ticketCopyState === 'copied' ? 'Copied' : 'Copy' }}
                    </button>
                </div>
                <div v-if="ticketDraftOpen" data-testid="ticket-draft-body" class="border-t border-red-800/40 bg-red-950/20 p-3">
                    <textarea
                        aria-label="Generated ticket text"
                        readonly
                        :value="ticketText"
                        class="min-h-64 w-full resize-y rounded border border-gray-700 bg-gray-950 p-2 font-mono text-xs leading-relaxed text-gray-300"
                    />
                </div>
                <div v-if="ticketCopyState === 'error'" class="border-t border-gray-800 px-3 py-2 text-[10px] text-amber-300">
                    Clipboard copy failed
                </div>
            </section>

            <section class="space-y-2 border-t border-gray-800/80 pt-3">
                <h6 class="text-[11px] font-bold uppercase tracking-wider text-gray-500">Analysis Artifacts</h6>

                <div class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                    <button
                        type="button"
                        @click="coverageOpen = !coverageOpen"
                        class="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-gray-950/60"
                    >
                        <span class="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-gray-500">
                            <component :is="coverageOpen ? ChevronUp : ChevronDown" :size="12" />
                            Version Coverage
                        </span>
                        <span class="text-[10px] font-semibold text-gray-500">{{ checkedVersionCoverageSummary }}</span>
                    </button>
                    <div v-if="coverageOpen" class="space-y-2 border-t border-gray-800 p-3">
                        <p class="text-[10px] leading-relaxed text-gray-500">
                            Product Version is populated for DTVP affected-version tag or branch checks. Workspace and lock-file rows describe the current analyzed checkout.
                        </p>
                        <div v-if="checkedVersionRows.length === 0" class="text-xs text-gray-500">No checked versions reported.</div>
                        <div v-else class="max-h-72 overflow-auto rounded border border-gray-800">
                            <table class="min-w-full table-fixed text-left text-[11px]">
                                <thead class="bg-gray-900/80 text-[10px] uppercase tracking-wider text-gray-500">
                                    <tr>
                                        <th class="w-36 px-2 py-1.5 font-bold">Component</th>
                                        <th class="w-32 px-2 py-1.5 font-bold">Product Version</th>
                                        <th class="w-40 px-2 py-1.5 font-bold">Checked Ref</th>
                                        <th class="w-28 px-2 py-1.5 font-bold">Version</th>
                                        <th class="w-28 px-2 py-1.5 font-bold">Source</th>
                                        <th class="w-28 px-2 py-1.5 font-bold">Status</th>
                                        <th class="min-w-48 px-2 py-1.5 font-bold">Notes</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-gray-800 bg-gray-950/35 text-gray-300">
                                    <tr v-for="row in checkedVersionRows" :key="row.key" class="align-top">
                                        <td class="px-2 py-1.5 font-mono text-gray-200">{{ row.component || '-' }}</td>
                                        <td class="px-2 py-1.5 text-gray-400">{{ coverageProductVersionLabel(row) }}</td>
                                        <td class="px-2 py-1.5">
                                            <div class="font-mono text-gray-100">{{ row.ref }}</div>
                                            <div class="text-[10px] uppercase text-gray-600">{{ row.refType }}</div>
                                        </td>
                                        <td class="px-2 py-1.5 font-mono text-gray-300">{{ row.version }}</td>
                                        <td class="px-2 py-1.5 text-gray-400">{{ row.source }}</td>
                                        <td class="px-2 py-1.5">
                                            <span class="inline-flex rounded border px-1.5 py-0.5 font-semibold uppercase" :class="checkedVersionStatusClass(row.status)">
                                                {{ row.status }}
                                            </span>
                                        </td>
                                        <td class="px-2 py-1.5 text-gray-400">{{ row.notes || '-' }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                    <button
                        type="button"
                        @click="loadSystemPrompts"
                        class="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-gray-950/60"
                    >
                        <span class="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-gray-500">
                            <Loader2 v-if="systemPromptLoading" :size="12" class="animate-spin" />
                            <component v-else :is="systemPromptOpen ? ChevronUp : ChevronDown" :size="12" />
                            LLM Conversation
                        </span>
                        <span class="text-[10px] font-semibold text-gray-500">{{ llmConversationSummary }}</span>
                    </button>
                    <div v-if="systemPromptOpen" class="border-t border-gray-700/50 bg-gray-950/60 p-2">
                        <div v-if="systemPromptLoading" class="flex items-center gap-2 text-xs text-gray-500">
                            <Loader2 :size="12" class="animate-spin" />
                            Loading conversation
                        </div>
                        <div v-else-if="systemPromptError" class="text-xs text-amber-300">
                            {{ systemPromptError }}
                        </div>
                        <div v-else-if="llmConversationTurns.length === 0 && systemPromptBundles.length === 0 && !requestGuidancePreview" class="text-xs text-gray-500">
                            No LLM conversation reported
                        </div>
                        <div v-else class="max-h-72 overflow-auto space-y-2">
                            <div v-if="llmConversationTurns.length > 0" class="space-y-2">
                                <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">Actual LLM conversation</div>
                                <div
                                    v-for="(turn, index) in llmConversationTurns"
                                    :key="`${turn.started_at || 'turn'}-${index}`"
                                    class="space-y-2 rounded border border-gray-800 bg-gray-950/70 p-2"
                                >
                                    <div class="flex flex-wrap items-center gap-x-2 gap-y-1 text-[9px] uppercase font-semibold text-gray-500">
                                        <span>{{ formatConversationMeta(turn, index) }}</span>
                                        <span v-if="turn.usage?.total_tokens" class="font-mono">{{ turn.usage.total_tokens }} tokens</span>
                                    </div>
                                    <div class="space-y-1.5">
                                        <div class="text-[9px] font-bold uppercase tracking-wider text-cyan-300">What was sent to the LLM</div>
                                        <div
                                            v-for="(message, messageIndex) in conversationMessages(turn)"
                                            :key="`message-${messageIndex}`"
                                            class="flex"
                                            :class="conversationRowClass(message.role)"
                                        >
                                            <div
                                                class="min-w-0 max-w-[92%] rounded border px-2.5 py-2 shadow-sm"
                                                :class="conversationBubbleClass(message.role)"
                                            >
                                                <div class="mb-1.5 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
                                                    <span class="text-[10px] font-bold uppercase tracking-wider">{{ conversationActorLabel(message.role) }}</span>
                                                    <span class="text-[9px] font-semibold uppercase tracking-wider opacity-70">{{ conversationSentMeta(message.role) }}</span>
                                                </div>
                                                <div
                                                    v-for="(part, partIndex) in message.parts"
                                                    :key="`${messageIndex}-${part.key}`"
                                                    class="space-y-1"
                                                    :class="partIndex > 0 ? 'mt-2 border-t border-white/10 pt-2' : ''"
                                                >
                                                    <div class="text-[9px] font-bold uppercase tracking-wider" :class="conversationPartLabelClass(part.kind)">{{ part.label }}</div>
                                                    <pre class="whitespace-pre-wrap break-words text-[10px] leading-relaxed">{{ part.content }}</pre>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <div v-if="conversationToolActivities(turn).length > 0" class="space-y-1.5">
                                        <div class="text-[9px] font-bold uppercase tracking-wider text-amber-300">Tool activity</div>
                                        <div class="flex flex-col gap-1">
                                            <div
                                                v-for="activity in conversationToolActivities(turn)"
                                                :key="activity.key"
                                                class="max-w-[92%] rounded border px-2.5 py-1.5 text-[10px]"
                                                :class="toolActivityClass(activity)"
                                            >
                                                <div class="flex flex-wrap items-center gap-x-2 gap-y-1">
                                                    <span class="font-bold uppercase tracking-wider">{{ activity.label }}</span>
                                                    <span class="rounded border border-current/30 px-1 py-0.5 font-mono text-[9px] uppercase opacity-80">{{ activity.status }}</span>
                                                </div>
                                                <div class="mt-1 break-words font-mono text-[10px] opacity-90">{{ activity.target }}</div>
                                            </div>
                                        </div>
                                    </div>
                                    <div v-if="conversationResponse(turn)" class="space-y-1.5">
                                        <div class="text-[9px] font-bold uppercase tracking-wider text-green-300">How the LLM answered</div>
                                        <div class="flex justify-start">
                                            <div class="min-w-0 max-w-[92%] rounded border px-2.5 py-2 shadow-sm" :class="conversationBubbleClass('assistant')">
                                                <div class="mb-1.5 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
                                                    <span class="text-[10px] font-bold uppercase tracking-wider">LLM</span>
                                                    <span class="text-[9px] font-semibold uppercase tracking-wider opacity-70">received from LLM · {{ conversationResponse(turn)?.role }} response</span>
                                                </div>
                                                <pre class="whitespace-pre-wrap break-words text-[10px] leading-relaxed">{{ conversationResponse(turn)?.content }}</pre>
                                            </div>
                                        </div>
                                    </div>
                                    <div v-if="turn.error" class="rounded bg-red-950/40 p-2 text-[10px] text-red-300">
                                        {{ turn.error }}
                                    </div>
                                </div>
                            </div>
                            <template v-if="llmConversationTurns.length === 0">
                                <div
                                    v-for="bundle in systemPromptBundles"
                                    :key="bundle.bundle"
                                    class="space-y-1"
                                >
                                    <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">{{ bundle.bundle }} configured prompt values (fallback, not a captured run)</div>
                                    <pre
                                        v-for="(value, key) in (bundle.values || {})"
                                        :key="String(key)"
                                        class="whitespace-pre-wrap break-words rounded bg-gray-900 p-2 text-[10px] leading-relaxed text-gray-300"
                                    >{{ formatPromptValueLabel(key) }}:
{{ value }}</pre>
                                </div>
                            </template>
                            <div v-if="llmConversationTurns.length === 0 && requestGuidancePreview" class="space-y-1">
                                <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">Additional request guidance sent to analyzer</div>
                                <pre class="whitespace-pre-wrap break-words rounded bg-gray-900 p-2 text-[10px] leading-relaxed text-gray-300">{{ requestGuidancePreview }}</pre>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                    <button
                        type="button"
                        @click="stepsExpanded = !stepsExpanded"
                        class="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-gray-950/60"
                    >
                        <span class="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-gray-500">
                            <component :is="stepsExpanded ? ChevronUp : ChevronDown" :size="12" />
                            Pipeline Evidence
                        </span>
                        <span class="text-[10px] font-semibold text-gray-500">{{ pipelineEvidenceSummary }}</span>
                    </button>
                    <div v-if="stepsExpanded" class="border-t border-gray-800 p-3">
                        <div v-if="!result.steps.length" class="text-xs text-gray-500">No pipeline evidence reported.</div>
                        <div v-else class="grid gap-2 md:grid-cols-2">
                            <div v-for="(step, i) in result.steps" :key="i" class="p-3 rounded bg-gray-950/40 border border-gray-800">
                                <div class="flex items-center gap-2 mb-1">
                                    <component :is="stepStatusIcon(step.status)" :size="13" :class="stepStatusColor(step.status)" />
                                    <span class="text-xs font-semibold text-gray-300">{{ step.title }}</span>
                                    <span class="text-[10px] font-mono text-gray-600">({{ step.step }})</span>
                                </div>
                                <ul v-if="step.evidence.length" class="text-xs text-gray-500 list-disc list-inside space-y-0.5 ml-4">
                                    <li v-for="(ev, j) in step.evidence" :key="j">{{ ev }}</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
        </div>

    </div>
</template>
