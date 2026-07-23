<script setup lang="ts">
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { Zap, Loader2, CheckCircle, XCircle, AlertTriangle, ChevronDown, ChevronUp, Clock, ClipboardCheck, Eye, History, Ban, FileText, Copy, ExternalLink, Trash2 } from 'lucide-vue-next'
import {
    codeAnalysisBenchmarkResult,
    codeAnalysisCleanupVulnerability,
    codeAnalysisGetPrompts,
    codeAnalysisGetResult,
    codeAnalysisListVulnerabilityResults,
} from '../lib/api'
import type { AnalysisQueueItem, CodeAnalysisAssessResponse, CodeAnalysisAssessment, CodeAnalysisBenchmarkComparison, CodeAnalysisBenchmarkFinding, CodeAnalysisComponentResult, CodeAnalysisLlmConversationTurn, CodeAnalysisLlmMessage, CodeAnalysisResultRecord, CodeAnalysisStepFindings } from '../lib/api'
import { analysisQueueStore } from '../lib/analysisQueueStore'
import { codeAnalysisAssessmentState, isCodeAnalysisResultWorse, prepareCodeAnalysisResult } from '../lib/codeAnalysisResult'
import type { CodeAnalysisComponentRun } from '../lib/codeAnalysisResult'
import { stringifyTicketValue, useCodeAnalysisTicketDraft } from '../lib/useCodeAnalysisTicketDraft'
import type { AutomaticAssessmentStatus } from '../lib/vulnListIndex'
import CodeAnalysisHistoryRow from './CodeAnalysisHistoryRow.vue'
import CodeAnalysisConversationViewport from './CodeAnalysisConversationViewport.vue'
import CodeAnalysisRunOutcome from './CodeAnalysisRunOutcome.vue'
import DetailSection from './DetailSection.vue'

const props = defineProps<{
    vulnId: string
    vulnAliases?: string[]
    projectName?: string
    cvssVector?: string
    componentNames: string[]
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
}>()

const emit = defineEmits<{
    (e: 'apply-result', result: CodeAnalysisAssessResponse, components: string[], analysisRunIds: string[], targetTeam?: string): void
    (e: 'apply-all-results', runs: CodeAnalysisComponentRun[]): void
    (e: 'result-change', result: CodeAnalysisAssessResponse | null, components: string[]): void
    (e: 'scope-results-change', available: boolean): void
    (e: 'proposals-change', runs: CodeAnalysisComponentRun[]): void
}>()

const userGuidance = ref('')
const error = ref<string | null>(null)
const result = ref<CodeAnalysisAssessResponse | null>(null)
const stepsExpanded = ref(false)
const coverageOpen = ref(false)
const assessmentDraftOpen = ref(false)
const assessmentBenchmarkOpen = ref(false)
const componentResultsOpen = ref(false)
const ticketDraftOpen = ref(false)
const selectedComponents = ref<Set<string>>(new Set())
const componentDropdownOpen = ref(false)
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
const expandedHistoryComponents = ref<Set<string>>(new Set())
const systemPromptOpen = ref(false)
const systemPromptLoading = ref(false)
const systemPromptError = ref<string | null>(null)
const systemPromptPayload = ref<Record<string, any> | null>(null)
const conversationCopyState = ref<Record<string, 'idle' | 'copied' | 'error'>>({})
type ConversationStage = 'request' | 'tools' | 'response'
const conversationStageOpen = ref<Record<string, boolean>>({})
const benchmarkComparison = ref<CodeAnalysisBenchmarkComparison | null>(null)
const benchmarkLoading = ref(false)
const benchmarkError = ref<string | null>(null)
const HISTORY_RESULT_REFRESH_ATTEMPTS = 4
const HISTORY_RESULT_REFRESH_DELAY_MS = 500
const HISTORY_PAGE_SIZE = 500
let benchmarkLoadCounter = 0
let historyLoadCounter = 0
let combinedHydrationCounter = 0
const conversationCopyTimers = new Map<string, ReturnType<typeof setTimeout>>()

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

const noneSelected = computed(() => selectedComponents.value.size === 0)
const hasOwnedTargets = computed(() => uniqueComponents.value.length > 0)
const hasExistingAssessment = computed(() => {
    const state = String(props.currentState || '').trim().toUpperCase()
    return Boolean(state && state !== 'NOT_SET')
})

const latestPersistedResult = computed(() => persistedResults.value[0] || null)
const latestReusableResult = computed(() => persistedResults.value.find(record => (
    record.source !== 'benchmark'
    && (!record.status || record.status === 'completed')
)) || null)
const hasReusableAnalysis = computed(() => Boolean(
    latestReusableResult.value || completedQueueItems.value.length > 0,
))
const effectiveAssessmentStatus = computed<AutomaticAssessmentStatus | null>(() => {
    if (!teamScopeKey.value) return props.assessmentStatus || null
    if (!historyLoaded.value) return null
    const reusableRecords = persistedResults.value.filter(record => (
        record.source !== 'benchmark'
        && (!record.status || record.status === 'completed')
    ))
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

const selectionLabel = computed(() => {
    const total = uniqueComponents.value.length
    const count = selectedComponents.value.size
    if (total === 0) return 'No team-assigned targets'
    if (count === 0) return 'Select components…'
    if (count === total) return `All Components (${total})`
    if (count === 1) return [...selectedComponents.value][0]
    return `${count} of ${total} components`
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

type AnalysisHistoryComponentGroup = {
    component: string
    team: string
    latest: CodeAnalysisResultRecord
    predecessors: CodeAnalysisResultRecord[]
    earlier: CodeAnalysisResultRecord[]
    total: number
}

const historyComponentGroups = computed<AnalysisHistoryComponentGroup[]>(() => {
    const recordsByComponent = new Map<string, CodeAnalysisResultRecord[]>()
    uniqueComponents.value.forEach(component => recordsByComponent.set(component, []))

    persistedResults.value.forEach(record => {
        if (record.source === 'benchmark') return
        const component = recordVisibleComponent(record)
        if (component) recordsByComponent.get(component)?.push(record)
    })

    return [...recordsByComponent.entries()].flatMap(([component, records]) => {
        if (!records.length) return []
        const sorted = [...records].sort((left, right) => {
            const leftTime = Date.parse(left.finished_at || left.recorded_at || left.submitted_at || '') || 0
            const rightTime = Date.parse(right.finished_at || right.recorded_at || right.submitted_at || '') || 0
            return rightTime - leftTime || right.analysis_run_id.localeCompare(left.analysis_run_id)
        })
        const byRunId = new Map(sorted.map(record => [record.analysis_run_id, record]))
        const latest = sorted[0]
        const predecessors: CodeAnalysisResultRecord[] = []
        const chainIds = new Set([latest.analysis_run_id])
        let parentId = latest.parent_run_id || ''
        while (parentId && !chainIds.has(parentId)) {
            const parent = byRunId.get(parentId)
            if (!parent) break
            predecessors.push(parent)
            chainIds.add(parent.analysis_run_id)
            parentId = parent.parent_run_id || ''
        }
        return [{
            component,
            team: props.componentTeams?.[component] || '',
            latest,
            predecessors,
            earlier: sorted.filter(record => !chainIds.has(record.analysis_run_id)),
            total: sorted.length,
        }]
    })
})

const historyRecordCount = computed(() => persistedResults.value.filter(record => record.source !== 'benchmark').length)

const isReusableRecord = (record: CodeAnalysisResultRecord) => (
    record.source !== 'benchmark'
    && (!record.status || record.status === 'completed')
)

const toggleComponentHistory = (component: string) => {
    const next = new Set(expandedHistoryComponents.value)
    const key = component.toLocaleLowerCase()
    if (next.has(key)) next.delete(key)
    else next.add(key)
    expandedHistoryComponents.value = next
}

const isComponentHistoryExpanded = (component: string) => (
    expandedHistoryComponents.value.has(component.toLocaleLowerCase())
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
const savedRunGuidance = computed(() =>
    stringifyPromptContent(selectedPersistedResult.value?.user_guidance).trim()
)
const selectedRunGuidanceRedacted = computed(() =>
    Boolean(selectedPersistedResult.value?.user_guidance_redacted)
)

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
        case 'green': return 'text-green-300'
        case 'cyan': return 'text-cyan-300'
        case 'blue': return 'text-blue-300'
        case 'amber': return 'text-amber-300'
        case 'yellow': return 'text-yellow-300'
        default: return 'text-gray-400'
    }
}

const presentedEvidenceQualityBadges = computed(() => evidenceQualityBadges.value.map(badge => ({
    label: badge.label,
    detail: badge.detail,
    className: evidenceQualityClass(badge.tone),
})))

// Keep selection canonical when a reused card receives a different component list.
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

const {
    jiraCreateUrl,
    ticketCopyState,
    ticketText,
    copyTicketText,
    createJiraIssue,
} = useCodeAnalysisTicketDraft({
    context: props,
    result,
    hasAffectedResult,
    selectedPersistedResult,
    selectedComponents,
    analyzedComponents,
    followUpComponent,
    error,
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
    componentDropdownOpen.value = false
    error.value = null
    result.value = null
    selectedFullRecord.value = null
    benchmarkComparison.value = null
    benchmarkError.value = null
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
        .filter(record => record.source !== 'benchmark' && (!record.status || record.status === 'completed'))
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

type AnalysisRunListEntry =
    | { key: string, kind: 'active', item: AnalysisQueueItem }
    | { key: string, kind: 'completed', item: AnalysisQueueItem }
    | { key: string, kind: 'persisted', record: CodeAnalysisResultRecord, team?: string, nested: boolean, component: string, earlierCount?: number, historyExpanded?: boolean }
    | { key: string, kind: 'history-label', label: string, tone: 'cyan' | 'gray' }
    | { key: string, kind: 'current' }

const analysisRunListEntries = computed<AnalysisRunListEntry[]>(() => {
    const entries: AnalysisRunListEntry[] = activeQueueItems.value.map(item => ({
        key: `active:${item.queue_id}`,
        kind: 'active',
        item,
    }))
    let selectedRowFound = false

    for (const item of completedQueueItems.value) {
        entries.push({ key: `completed:${item.queue_id}`, kind: 'completed', item })
        if (item.queue_id === selectedRunId.value) selectedRowFound = true
    }

    for (const group of historyComponentGroups.value) {
        entries.push({
            key: `persisted:${group.latest.analysis_run_id}`,
            kind: 'persisted',
            record: group.latest,
            team: group.team,
            nested: false,
            component: group.component,
            earlierCount: group.predecessors.length + group.earlier.length,
            historyExpanded: isComponentHistoryExpanded(group.component),
        })
        if (recordMatchesRunId(group.latest, selectedRunId.value || '')) selectedRowFound = true
        if (!isComponentHistoryExpanded(group.component)) continue

        if (group.predecessors.length) {
            entries.push({
                key: `label:${group.component}:follow-up`,
                kind: 'history-label',
                label: `Follow-up chain (${group.predecessors.length})`,
                tone: 'cyan',
            })
            for (const record of group.predecessors) {
                entries.push({
                    key: `persisted:${record.analysis_run_id}`,
                    kind: 'persisted',
                    record,
                    team: group.team,
                    nested: true,
                    component: group.component,
                })
                if (recordMatchesRunId(record, selectedRunId.value || '')) selectedRowFound = true
            }
        }
        if (group.earlier.length) {
            entries.push({
                key: `label:${group.component}:independent`,
                kind: 'history-label',
                label: `Independent runs (${group.earlier.length})`,
                tone: 'gray',
            })
            for (const record of group.earlier) {
                entries.push({
                    key: `persisted:${record.analysis_run_id}`,
                    kind: 'persisted',
                    record,
                    team: group.team,
                    nested: true,
                    component: group.component,
                })
                if (recordMatchesRunId(record, selectedRunId.value || '')) selectedRowFound = true
            }
        }
    }

    if (result.value && !selectedRowFound) entries.push({ key: 'current-result', kind: 'current' })
    return entries
})

const isSelectedAnalysisRunEntry = (entry: AnalysisRunListEntry): boolean => Boolean(result.value && (
    entry.kind === 'current'
    || (entry.kind === 'completed' && entry.item.queue_id === selectedRunId.value)
    || (entry.kind === 'persisted' && recordMatchesRunId(entry.record, selectedRunId.value || ''))
))

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
    benchmarkComparison.value = null
    benchmarkError.value = null
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

const togglePersistedResult = async (record: CodeAnalysisResultRecord) => {
    if (recordMatchesRunId(record, selectedRunId.value || '') && result.value) {
        closeSelectedResult()
        return
    }
    await viewPersistedResult(record)
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

const benchmarkEvaluatorLabel = (comparison: CodeAnalysisBenchmarkComparison) => {
    if (comparison.evaluator?.probabilistic) {
        const model = comparison.evaluator.model ? ` · ${comparison.evaluator.model}` : ''
        return `Agentyzer probabilistic${model}`
    }
    return 'DTVP fallback'
}

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
    kind: 'search' | 'download' | 'package' | 'source' | 'repository' | 'failed' | 'research'
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

const conversationRequestText = (messages: ConversationMessage[]) =>
    messages
        .map(message => `[${conversationActorLabel(message.role).toUpperCase()}]\n${message.content}`)
        .join('\n\n')

const copyConversationText = async (key: string, content: string) => {
    const text = content.trim()
    if (!text) return
    const existingTimer = conversationCopyTimers.get(key)
    if (existingTimer) clearTimeout(existingTimer)
    try {
        await navigator.clipboard.writeText(text)
        conversationCopyState.value = { ...conversationCopyState.value, [key]: 'copied' }
    } catch {
        conversationCopyState.value = { ...conversationCopyState.value, [key]: 'error' }
    }
    const timer = setTimeout(() => {
        conversationCopyState.value = { ...conversationCopyState.value, [key]: 'idle' }
        conversationCopyTimers.delete(key)
    }, 1800)
    conversationCopyTimers.set(key, timer)
}

const toolLabelForDirective = (directive: string) => {
    const normalized = directive.toUpperCase()
    if (normalized === 'FETCH_SEARCH') return { kind: 'search' as const, label: 'Requested web search' }
    if (normalized === 'FETCH_URL') return { kind: 'download' as const, label: 'Requested URL download' }
    if (normalized === 'FETCH_PACKAGE') return { kind: 'package' as const, label: 'Requested package lookup' }
    if (normalized === 'FETCH_SOURCE') return { kind: 'source' as const, label: 'Requested source download' }
    if (normalized === 'CLONE_REPOSITORY') return { kind: 'repository' as const, label: 'Requested local repository inspection' }
    return { kind: 'research' as const, label: 'Requested external resource' }
}

const toolLabelForNativeCall = (name: string) => {
    const normalized = name.toLowerCase()
    if (normalized === 'search_web') return { kind: 'search' as const, label: 'Requested web search' }
    if (normalized === 'fetch_url') return { kind: 'download' as const, label: 'Requested URL download' }
    if (normalized === 'fetch_package') return { kind: 'package' as const, label: 'Requested package lookup' }
    if (normalized === 'fetch_source') return { kind: 'source' as const, label: 'Requested source download' }
    if (normalized === 'clone_repository') return { kind: 'repository' as const, label: 'Requested local repository inspection' }
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
    const target = String(args.query || args.repository_url || args.url || args.package || args.name || '').trim()
    const focus = String(args.focus || '').trim()
    const revision = String(args.revision || args.ref || '').trim()
    return [target, focus, revision ? `ref ${revision}` : ''].filter(Boolean).join(' · ')
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
    if (normalized.startsWith('repository inspection')) {
        return { kind: 'repository', label: 'Local repository evidence provided', status: 'provided' }
    }
    if (normalized.startsWith('repository clone failed')) {
        return { kind: 'failed', label: 'Repository inspection failed', status: 'failed' }
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
    const directivePattern = /^\s*(FETCH_(?:SEARCH|URL|PACKAGE|SOURCE)|CLONE_REPOSITORY):\s*(.+)$/gim
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
        const directive = match[1].toUpperCase()
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
    const resultPattern = /^---\s*(Search results for|Search failed|Fetched|Fetch failed|Package info|Package lookup failed|Source of|Source fetch failed|Repository inspection|Repository clone failed|Tool call failed):?\s*(.*?)\s*---$/gim
    for (const message of messages) {
        const role = String(message?.role || '').toLowerCase()
        if (role !== 'user' && role !== 'tool') continue
        const content = stringifyPromptContent(message?.content)
        if (/MANDATORY EXTERNAL CHECK/im.test(content)) {
            for (const match of content.matchAll(directivePattern)) {
                const directive = match[1].toUpperCase()
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
    if (activity.kind === 'repository') return 'border-purple-700/50 bg-purple-950/30 text-purple-100'
    return 'border-gray-700/60 bg-gray-900 text-gray-200'
}

const llmConversationViewTurns = computed(() => llmConversationTurns.value.map((turn, index) => {
    const messages = conversationMessages(turn)
    return {
        key: `${turn.started_at || 'turn'}-${index}`,
        turn,
        messages,
        requestText: conversationRequestText(messages),
        activities: conversationToolActivities(turn),
        response: conversationResponse(turn),
    }
}))

type ConversationGuidanceEvidence = {
    key: string
    component: string
    content: string
    turns: number[]
}

const capturedConversationGuidance = computed<ConversationGuidanceEvidence[]>(() => {
    const evidence = new Map<string, ConversationGuidanceEvidence>()
    llmConversationViewTurns.value.forEach((conversation, index) => {
        conversation.messages.forEach(message => {
            message.parts
                .filter(part => part.kind === 'guidance')
                .forEach(part => {
                    const content = part.content
                        .replace(/^(?:ANALYST GUIDANCE|Additional reviewer guidance)\b\s*:?\s*/i, '')
                        .trim()
                    if (!content) return
                    const component = String(
                        conversation.turn.component
                        || selectedPersistedResult.value?.component_name
                        || analyzedComponents.value[0]
                        || '',
                    ).trim()
                    const key = `${component.toLocaleLowerCase()}\u0000${content}`
                    const existing = evidence.get(key)
                    if (existing) {
                        if (!existing.turns.includes(index + 1)) existing.turns.push(index + 1)
                        return
                    }
                    evidence.set(key, {
                        key,
                        component,
                        content,
                        turns: [index + 1],
                    })
                })
        })
    })
    return [...evidence.values()]
})

const conversationMetric = (value: unknown): number | null => {
    if (value == null || value === '') return null
    const numeric = typeof value === 'number' ? value : Number(value)
    return Number.isFinite(numeric) && numeric >= 0 ? numeric : null
}

const conversationUsageMetric = (turn: CodeAnalysisLlmConversationTurn, ...keys: string[]) => {
    for (const key of keys) {
        const value = conversationMetric(turn.usage?.[key])
        if (value != null) return value
    }
    return null
}

const conversationTimestamp = (value: unknown): number | null => {
    const timestamp = Date.parse(String(value || ''))
    return Number.isFinite(timestamp) ? timestamp : null
}

const formatConversationDuration = (milliseconds: number | null) => {
    if (milliseconds == null) return 'Not reported'
    if (milliseconds < 1_000) return `${Math.max(1, Math.round(milliseconds))} ms`
    const seconds = milliseconds / 1_000
    if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`
    const minutes = Math.floor(seconds / 60)
    const remaining = Math.round(seconds % 60)
    return `${minutes}m ${remaining}s`
}

const formatConversationTokens = (tokens: number | null) =>
    tokens == null ? 'Not reported' : Math.round(tokens).toLocaleString()

const llmConversationStatistics = computed(() => {
    const rows = llmConversationViewTurns.value.map((conversation, index) => {
        const startedAt = conversationTimestamp(conversation.turn.started_at)
        const finishedAt = conversationTimestamp(conversation.turn.finished_at)
        const durationMs = startedAt != null && finishedAt != null && finishedAt >= startedAt
            ? finishedAt - startedAt
            : null
        const promptTokens = conversationUsageMetric(conversation.turn, 'prompt_tokens', 'input_tokens')
        const completionTokens = conversationUsageMetric(conversation.turn, 'completion_tokens', 'output_tokens')
        const reportedTotal = conversationUsageMetric(conversation.turn, 'total_tokens')
        const totalTokens = reportedTotal ?? (
            promptTokens != null || completionTokens != null
                ? (promptTokens || 0) + (completionTokens || 0)
                : null
        )
        const requestedTools = conversation.activities.filter(activity =>
            activity.status === 'requested' && !activity.label.startsWith('Analyzer-required'),
        )
        const analyzerRequiredTools = conversation.activities.filter(activity =>
            activity.status === 'requested' && activity.label.startsWith('Analyzer-required'),
        )
        return {
            key: conversation.key,
            label: formatConversationMeta(conversation.turn, index),
            startedAt,
            finishedAt,
            durationMs,
            localDurationMs: null as number | null,
            outboundMessages: Array.isArray(conversation.turn.messages) ? conversation.turn.messages.length : 0,
            inboundMessages: conversation.turn.response ? 1 : 0,
            promptTokens,
            completionTokens,
            totalTokens,
            requestedTools: requestedTools.length,
            analyzerRequiredTools: analyzerRequiredTools.length,
            localToolResults: conversation.activities.filter(activity => activity.status !== 'requested').length,
            status: String(conversation.turn.status || 'unknown'),
            component: String(conversation.turn.component || ''),
            attempts: conversationMetric(conversation.turn.request?.attempts),
            contextAdaptations: Array.isArray(conversation.turn.request?.context_adaptations)
                ? conversation.turn.request.context_adaptations.length
                : 0,
        }
    })

    rows.forEach((row, index) => {
        const next = rows[index + 1]
        if (!next || row.finishedAt == null || next.startedAt == null) return
        if (row.component && next.component && row.component !== next.component) return
        if (next.startedAt >= row.finishedAt) row.localDurationMs = next.startedAt - row.finishedAt
    })

    const sumKnown = (values: Array<number | null>) => {
        const known = values.filter((value): value is number => value != null)
        return known.length ? known.reduce((total, value) => total + value, 0) : null
    }
    const started = rows.map(row => row.startedAt).filter((value): value is number => value != null)
    const finished = rows.map(row => row.finishedAt).filter((value): value is number => value != null)
    const capturedSpanMs = started.length && finished.length
        ? Math.max(...finished) - Math.min(...started)
        : null

    const uniqueLocalResults = new Map<string, ConversationToolActivity>()
    const uniqueAnalyzerRequests = new Set<string>()
    const toolTypeCounts = new Map<string, number>()
    let llmToolRequests = 0
    llmConversationViewTurns.value.forEach(conversation => {
        conversation.activities.forEach(activity => {
            if (activity.status === 'requested') {
                if (activity.label.startsWith('Analyzer-required')) {
                    uniqueAnalyzerRequests.add(activity.key)
                } else {
                    llmToolRequests += 1
                    toolTypeCounts.set(activity.kind, (toolTypeCounts.get(activity.kind) || 0) + 1)
                }
                return
            }
            uniqueLocalResults.set(activity.key, activity)
        })
    })
    const localToolResults = [...uniqueLocalResults.values()]
    const toolFailures = localToolResults.filter(activity => activity.status === 'failed').length
    const models = [...new Set(llmConversationTurns.value.map(turn => String(turn.model || '')).filter(Boolean))]
    const providers = [...new Set(llmConversationTurns.value.map(turn => String(turn.provider || turn.backend || '')).filter(Boolean))]
    const retries = rows.reduce((total, row) => total + Math.max(0, (row.attempts || 1) - 1), 0)
    const contextAdaptations = rows.reduce((total, row) => total + row.contextAdaptations, 0)
    const completedTurns = rows.filter(row => row.status === 'completed').length
    const totalCompletionTokens = sumKnown(rows.map(row => row.completionTokens))
    const totalDurationMs = sumKnown(rows.map(row => row.durationMs))

    return {
        rows,
        outboundMessages: rows.reduce((total, row) => total + row.outboundMessages, 0),
        inboundMessages: rows.reduce((total, row) => total + row.inboundMessages, 0),
        promptTokens: sumKnown(rows.map(row => row.promptTokens)),
        completionTokens: totalCompletionTokens,
        totalTokens: sumKnown(rows.map(row => row.totalTokens)),
        usageTurns: rows.filter(row => row.totalTokens != null).length,
        timedTurns: rows.filter(row => row.durationMs != null).length,
        requestCharacters: llmConversationViewTurns.value.reduce((total, conversation) => total + conversation.requestText.length, 0),
        responseCharacters: llmConversationViewTurns.value.reduce((total, conversation) => total + (conversation.response?.content.length || 0), 0),
        totalDurationMs,
        localDurationMs: sumKnown(rows.map(row => row.localDurationMs)),
        capturedSpanMs,
        llmToolRequests,
        analyzerRequiredTools: uniqueAnalyzerRequests.size,
        localToolResults: localToolResults.length,
        toolFailures,
        repositoryInspections: localToolResults.filter(activity => activity.kind === 'repository').length,
        toolTypes: [...toolTypeCounts.entries()].sort((left, right) => right[1] - left[1]),
        retries,
        contextAdaptations,
        completedTurns,
        failedTurns: rows.length - completedTurns,
        models,
        providers,
        throughput: totalCompletionTokens != null && totalDurationMs && totalDurationMs > 0
            ? totalCompletionTokens / (totalDurationMs / 1_000)
            : null,
    }
})

const conversationStageKey = (turnKey: string, stage: ConversationStage) => `${turnKey}:${stage}`
const conversationStageId = (index: number, stage: ConversationStage) => `llm-turn-${index + 1}-${stage}`
const isConversationStageOpen = (turnKey: string, stage: ConversationStage) =>
    conversationStageOpen.value[conversationStageKey(turnKey, stage)] ?? stage === 'response'

const conversationStages = computed(() => llmConversationViewTurns.value.flatMap(conversation => {
    const stages: ConversationStage[] = ['request']
    if (conversation.activities.length > 0) stages.push('tools')
    if (conversation.response) stages.push('response')
    return stages.map(stage => ({ turnKey: conversation.key, stage }))
}))

const allConversationStagesOpen = computed(() =>
    conversationStages.value.length > 0
    && conversationStages.value.every(({ turnKey, stage }) => isConversationStageOpen(turnKey, stage)),
)
const anyConversationStageOpen = computed(() =>
    conversationStages.value.some(({ turnKey, stage }) => isConversationStageOpen(turnKey, stage)),
)

const toggleConversationStage = (turnKey: string, stage: ConversationStage) => {
    const key = conversationStageKey(turnKey, stage)
    conversationStageOpen.value = {
        ...conversationStageOpen.value,
        [key]: !isConversationStageOpen(turnKey, stage),
    }
}

const setAllConversationStages = (open: boolean) => {
    conversationStageOpen.value = Object.fromEntries(
        conversationStages.value.map(({ turnKey, stage }) => [conversationStageKey(turnKey, stage), open]),
    )
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
    if (savedRunGuidance.value) return 'Saved guidance · use not verifiable'
    if (selectedRunGuidanceRedacted.value) return 'Guidance redacted'
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
            return 'Agentyzer → model · instruction'
        case 'user':
            return 'Agentyzer → model · request payload'
        case 'assistant':
            return 'model → Agentyzer · earlier response re-sent'
        case 'tool':
            return 'tool → Agentyzer → model · result'
        default:
            return 'Agentyzer → model'
    }
}

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

onMounted(() => {
    void loadPersistedResults()
    document.addEventListener('click', handleClickOutside)
})

onBeforeUnmount(() => {
    document.removeEventListener('click', handleClickOutside)
    for (const timer of conversationCopyTimers.values()) clearTimeout(timer)
    conversationCopyTimers.clear()
})

watch([
    () => props.vulnId,
    () => props.projectName || '',
    () => (props.vulnAliases || []).join('\u0000'),
    () => uniqueComponents.value.join('\u0000'),
    teamScopeKey,
    () => [...teamScopeKeys.value].sort().join('\u0000'),
], (_current, previous) => {
    if (!previous) return
    analysisBatches.clear()
    persistedResults.value = []
    expandedHistoryComponents.value = new Set()
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
    benchmarkLoadCounter += 1
    combinedHydrationCounter += 1
    combinedHydrating.value = false
    combinedHydrationError.value = null
    benchmarkComparison.value = null
    benchmarkError.value = null
    void loadPersistedResults()
})

watch([historyLoaded, hasReusableAnalysis], ([loaded, available]) => {
    emit('scope-results-change', loaded && available)
}, { immediate: true })

function handleClickOutside(e: MouseEvent) {
    const target = e.target as HTMLElement
    if (componentDropdownOpen.value && !target.closest('.relative')) {
        componentDropdownOpen.value = false
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
    coverageOpen.value = false
    stepsExpanded.value = false
    systemPromptOpen.value = false
    conversationCopyState.value = {}
    conversationStageOpen.value = {}
    assessmentDraftOpen.value = false
    assessmentBenchmarkOpen.value = false
    componentResultsOpen.value = false
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
    <div class="flex flex-col gap-5">
        <div class="order-0 flex flex-wrap items-start justify-between gap-3 rounded-lg border border-cyan-800/40 bg-cyan-950/10 px-4 py-3">
            <div>
                <h3 class="flex items-center gap-2 text-sm font-bold text-cyan-100">
                <Zap :size="14" />
                    Code evidence
                </h3>
                <p class="mt-1 max-w-4xl text-xs leading-relaxed text-gray-500">
                    Run analysis when evidence is missing, then review the latest result for every affected target before creating a combined assessment.
                </p>
            </div>
            <span v-if="statusLabel" class="inline-flex items-center gap-1 text-[11px] font-semibold" :class="statusClass">
                <Loader2 v-if="queueStatus === 'running' || submitting" :size="11" class="animate-spin" />
                <Clock v-else-if="queueStatus === 'queued'" :size="11" />
                {{ statusLabel }}
            </span>
        </div>

        <div
            v-if="!hasOwnedTargets"
            class="order-1 rounded border border-amber-700/40 bg-amber-900/15 px-3 py-2 text-xs text-amber-200"
        >
            No team-assigned component target is available for code analysis.
        </div>

        <DetailSection
            :step="isReviewer ? 'Code evidence · 2' : 'Code evidence · 1'"
            title="Analysis runs by target"
            description="Run analysis when evidence is missing, then inspect the latest stored result for each affected target. Older runs stay collapsed until needed."
            bodyClass="space-y-3"
            :class="isReviewer ? 'order-3' : 'order-2'"
            data-testid="analysis-runs-section"
        >
        <details
            :open="!hasReusableAnalysis"
            data-testid="new-analysis-section"
            class="group rounded border border-cyan-800/50 bg-gray-900/45"
        >
            <summary class="flex cursor-pointer list-none flex-wrap items-start justify-between gap-3 px-4 py-3 transition-colors hover:bg-cyan-950/15">
                <div class="flex min-w-0 items-start gap-3">
                    <span class="mt-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded border border-cyan-700/50 bg-cyan-950/35 text-cyan-300">
                        <ChevronDown :size="14" class="transition-transform group-open:rotate-180" />
                    </span>
                    <div>
                        <div class="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-500/80">New run</div>
                        <h4 class="mt-1 text-sm font-bold text-gray-100">Run new analysis</h4>
                        <p class="mt-1 text-xs leading-relaxed text-gray-500">
                            {{ hasReusableAnalysis ? 'A saved result already exists. Rerun only when the scope or evidence has changed.' : 'Select one or more components, then run the scoped analysis.' }}
                        </p>
                    </div>
                </div>
                <div class="flex items-center gap-2">
                    <span v-if="hasOwnedTargets" class="rounded border border-gray-700 bg-gray-950/50 px-2 py-1 text-[10px] font-semibold uppercase text-gray-400">
                        {{ selectedComponents.size }} selected
                    </span>
                    <span class="text-[10px] font-bold uppercase tracking-wide text-cyan-400">Expand</span>
                </div>
            </summary>
            <div class="grid items-end gap-3 border-t border-gray-800/90 p-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
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
                    data-testid="code-analysis-start"
                    class="flex items-center justify-center gap-2 px-4 py-2 rounded text-xs font-bold transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap"
                    :class="submitting
                        ? 'bg-cyan-900/40 text-cyan-400 border border-cyan-700/40'
                        : 'bg-cyan-600 hover:bg-cyan-700 text-white'"
                >
                    <Loader2 v-if="submitting" :size="14" class="animate-spin" />
                    <Zap v-else :size="14" />
                    {{ submitting ? 'Submitting...' : hasReusableAnalysis ? 'Run Again' : activeQueueItems.length > 0 ? 'Analyze More' : `Analyze ${selectedComponents.size || ''}`.trim() }}
                </button>

            </div>
            <section v-if="!result" class="space-y-2 border-t border-gray-800/90 px-4 py-3">
                <button
                    type="button"
                    @click="loadSystemPrompts"
                    class="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-gray-500 hover:text-cyan-300 cursor-pointer"
                >
                    <Loader2 v-if="systemPromptLoading" :size="12" class="animate-spin" />
                    <FileText v-else :size="12" />
                    {{ systemPromptOpen ? 'Hide analyzer request context' : 'Analyzer request context' }}
                </button>
                <div v-if="systemPromptOpen" class="rounded border border-gray-700/50 bg-gray-950/60 p-2">
                    <div v-if="systemPromptLoading" class="flex items-center gap-2 text-xs text-gray-500">
                        <Loader2 :size="12" class="animate-spin" />
                        Loading request context
                    </div>
                    <div v-else-if="systemPromptError" class="text-xs text-amber-300">
                        {{ systemPromptError }}
                    </div>
                    <div v-else-if="systemPromptBundles.length === 0 && !launchGuidancePreview" class="text-xs text-gray-500">
                        No analyzer request context is available.
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
                        <div v-if="launchGuidancePreview" class="space-y-1">
                            <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">Guidance prepared for the next analyzer request</div>
                            <pre class="whitespace-pre-wrap break-words rounded bg-gray-900 p-2 text-[10px] leading-relaxed text-gray-300">{{ launchGuidancePreview }}</pre>
                        </div>
                    </div>
                </div>
            </section>
        </details>

            <template #actions>
                <div class="flex shrink-0 flex-wrap items-center justify-end gap-2">
                    <span
                        v-if="effectiveAssessmentStatus"
                        class="rounded border px-1.5 py-0.5 text-[10px] font-semibold"
                        :class="assessmentStatusClass"
                    >
                        {{ assessmentStatusLabel }}
                    </span>
                    <span v-if="historyRecordCount > 0" class="text-[10px] text-gray-600">{{ historyRecordCount }} run{{ historyRecordCount === 1 ? '' : 's' }}</span>
                    <button
                        type="button"
                        :disabled="historyLoading"
                        class="inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1 text-[10px] font-bold uppercase text-gray-400 transition-colors hover:border-cyan-700/60 hover:text-cyan-300 disabled:cursor-wait disabled:opacity-50"
                        @click="loadPersistedResults()"
                    >
                        <Loader2 v-if="historyLoading" :size="10" class="animate-spin" />
                        <History v-else :size="10" />
                        {{ historyLoaded ? 'Refresh' : 'Load history' }}
                    </button>
                    <button
                        type="button"
                        data-testid="analysis-cleanup-toggle"
                        class="inline-flex items-center gap-1 rounded border border-red-900/60 px-2 py-1 text-[10px] font-bold uppercase text-red-300 transition-colors hover:bg-red-950/25"
                        :aria-expanded="cleanupOpen ? 'true' : 'false'"
                        @click="cleanupOpen = !cleanupOpen"
                    >
                        <Trash2 :size="10" />
                        Clean up
                    </button>
                </div>
            </template>

            <div
                v-if="cleanupOpen"
                data-testid="analysis-cleanup-panel"
                class="space-y-2 rounded border border-red-900/50 bg-red-950/10 p-3 text-xs"
            >
                <div>
                    <div class="font-semibold text-red-200">Clean {{ vulnId }} code-analysis data</div>
                    <p class="mt-0.5 text-[10px] leading-relaxed text-gray-500">
                        Choose either store independently, or remove both for a complete cleanup. The trash action on an individual row cleans only that run.
                    </p>
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

            <div
                role="list"
                aria-label="Analysis runs"
                data-testid="analysis-run-list"
                class="divide-y divide-gray-800/80 overflow-hidden rounded border border-gray-800/90 bg-gray-950/20"
            >
            <div v-if="historyLoading" role="listitem" aria-live="polite" class="flex items-center gap-2 px-3 py-2 text-xs text-gray-500">
                <Loader2 :size="12" class="animate-spin" />
                Loading analysis history
            </div>
            <template v-for="entry in analysisRunListEntries" :key="entry.key">
            <div
                role="listitem"
                :data-testid="entry.kind === 'persisted' && !entry.nested ? 'analysis-history-component-group' : undefined"
                :data-component="entry.kind === 'persisted' && !entry.nested ? entry.component : undefined"
                :class="[
                    isSelectedAnalysisRunEntry(entry) ? 'bg-cyan-950/10' : '',
                    entry.kind === 'persisted' && entry.nested ? 'border-l border-gray-800 pl-6' : '',
                ]"
            >
                <div
                    v-if="entry.kind === 'active'"
                    class="grid gap-2 px-3 py-2.5 text-[11px] md:grid-cols-[minmax(0,1fr)_auto]"
                    :class="entry.item.status === 'running' ? 'bg-blue-950/10' : 'bg-yellow-950/10'"
                >
                    <div class="flex min-w-0 flex-wrap items-center gap-2">
                        <Loader2 v-if="entry.item.status === 'running'" :size="12" class="animate-spin text-blue-400" />
                        <Clock v-else :size="12" class="text-yellow-400" />
                        <span class="min-w-0 truncate font-mono text-gray-200">{{ entry.item.component_name }}</span>
                        <span v-if="entry.item.source && entry.item.source !== 'manual'" class="text-[9px] font-semibold uppercase" :class="sourceClass(entry.item.source)">
                            {{ sourceLabel(entry.item.source) }}
                        </span>
                        <span v-if="entry.item.status === 'queued' && entry.item.position > 0" class="font-bold text-yellow-400">#{{ entry.item.position }}</span>
                        <span class="font-semibold uppercase" :class="entry.item.status === 'running' ? 'text-blue-400' : 'text-yellow-400'">{{ entry.item.status }}</span>
                    </div>
                    <button
                        type="button"
                        :disabled="isQueueActionBusy(entry.item.queue_id)"
                        class="inline-flex items-center justify-center gap-1 rounded px-2 py-1 text-[9px] font-bold uppercase text-gray-500 hover:bg-red-950/20 hover:text-red-300 disabled:cursor-wait disabled:opacity-50"
                        @click="cancelQueueItem(entry.item)"
                    >
                        <Loader2 v-if="isQueueActionBusy(entry.item.queue_id)" :size="10" class="animate-spin" />
                        <Ban v-else :size="10" />
                        {{ entry.item.status === 'running' ? 'Abort' : 'Cancel' }}
                    </button>
                </div>

                <div v-else-if="entry.kind === 'completed'" class="grid gap-2 bg-green-950/10 px-3 py-2.5 text-[11px] md:grid-cols-[minmax(0,1fr)_auto]">
                    <div class="flex min-w-0 flex-wrap items-center gap-2">
                        <CheckCircle :size="12" class="text-green-400" />
                        <span class="min-w-0 truncate font-mono text-gray-200">{{ entry.item.component_name }}</span>
                        <span v-if="entry.item.source && entry.item.source !== 'manual'" class="text-[9px] font-semibold uppercase" :class="sourceClass(entry.item.source)">
                            {{ sourceLabel(entry.item.source) }}
                        </span>
                        <span class="font-semibold uppercase text-green-400">completed</span>
                    </div>
                    <button
                        type="button"
                        class="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[9px] font-bold uppercase text-green-300 hover:bg-green-950/30"
                        :aria-expanded="isSelectedAnalysisRunEntry(entry) ? 'true' : 'false'"
                        @click="toggleCompletedResult(entry.item)"
                    >
                        <Eye :size="11" />
                        {{ isSelectedAnalysisRunEntry(entry) ? 'Hide' : 'View' }}
                    </button>
                </div>

                <CodeAnalysisHistoryRow
                    v-else-if="entry.kind === 'persisted'"
                    :record="entry.record"
                    :team="entry.team"
                    :nested="entry.nested"
                    :selected="isSelectedAnalysisRunEntry(entry)"
                    :deleting="isDeletingRun(entry.record.analysis_run_id)"
                    :canApply="isReusableRecord(entry.record)"
                    :earlierCount="entry.earlierCount"
                    :historyExpanded="entry.historyExpanded"
                    @select="togglePersistedResult"
                    @apply="applyPersistedResult"
                    @remove="removePersistedResult"
                    @toggle-history="toggleComponentHistory(entry.component)"
                />

                <div
                    v-else-if="entry.kind === 'history-label'"
                    class="bg-gray-950/25 px-8 py-1.5 text-[9px] font-semibold uppercase tracking-wide"
                    :class="entry.tone === 'cyan' ? 'text-cyan-500' : 'text-gray-500'"
                >
                    {{ entry.label }}
                </div>

                <div v-else class="grid gap-2 bg-green-950/10 px-3 py-2.5 text-[11px] md:grid-cols-[minmax(0,1fr)_auto]">
                    <div class="flex min-w-0 flex-wrap items-center gap-2">
                        <CheckCircle :size="12" class="text-green-400" />
                        <span class="font-semibold text-gray-200">Current analysis result</span>
                        <span class="truncate font-mono text-gray-500">{{ analyzedComponents.join(', ') }}</span>
                    </div>
                    <button type="button" class="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[9px] font-bold uppercase text-green-300 hover:bg-green-950/30" @click="closeSelectedResult">
                        <Eye :size="11" /> Hide
                    </button>
                </div>

        <div
            v-if="isSelectedAnalysisRunEntry(entry) && result"
            class="space-y-2 border-l-2 border-cyan-900/70 px-3 pb-3 pt-1"
            :class="entry.kind === 'persisted' && entry.nested ? 'ml-12' : 'ml-8'"
            data-testid="selected-analysis-run-details"
        >
        <CodeAnalysisRunOutcome
            :result="result"
            :verdictClass="verdictColor"
            :confidenceClass="confidenceBadge"
            :evidenceBadges="presentedEvidenceQualityBadges"
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
        <div class="space-y-1" data-testid="selected-analysis-supporting-evidence">

            <section v-if="assessmentDraftPreview" data-testid="assessment-draft" class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                    <button
                        type="button"
                        @click="assessmentDraftOpen = !assessmentDraftOpen"
                        class="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-gray-950/60"
                        :aria-expanded="assessmentDraftOpen"
                    >
                        <span class="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-400">
                            <component :is="assessmentDraftOpen ? ChevronUp : ChevronDown" :size="12" />
                            Assessment Draft
                        </span>
                        <span class="flex flex-wrap items-center gap-2 text-[10px]">
                            <span class="font-semibold text-amber-400">{{ assessmentDraftChangeCount }} change{{ assessmentDraftChangeCount === 1 ? '' : 's' }}</span>
                            <span class="text-cyan-300">Target {{ assessmentDraftPreview.targetTeam }}</span>
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
                        <span class="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-400">
                            <component :is="assessmentBenchmarkOpen ? ChevronUp : ChevronDown" :size="12" />
                            Assessment Benchmark
                        </span>
                        <span
                            v-if="benchmarkComparison"
                            class="inline-flex items-center gap-1.5 text-[10px] font-semibold"
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
                                        <div class="mt-1 font-mono text-sm font-semibold text-gray-100">{{ formatBenchmarkCvss(benchmarkComparison.human.cvss_score) }}</div>
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
                                        <div class="mt-1 font-mono text-sm font-semibold text-gray-100">{{ formatBenchmarkCvss(benchmarkComparison.automated.cvss_score) }}</div>
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

            <section v-if="result.component_results?.length" data-testid="component-results" class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                <button
                    type="button"
                    class="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-gray-950/60"
                    :aria-expanded="componentResultsOpen"
                    @click="componentResultsOpen = !componentResultsOpen"
                >
                    <span class="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-500">
                        <component :is="componentResultsOpen ? ChevronUp : ChevronDown" :size="12" />
                        Component results
                    </span>
                    <span class="text-[10px] text-gray-600">
                        {{ result.component_results.length }} target{{ result.component_results.length === 1 ? '' : 's' }}
                    </span>
                </button>
                <div v-if="componentResultsOpen" class="grid gap-2 border-t border-gray-800 p-2 md:grid-cols-2">
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
                        <div v-if="componentResult.assessment.executive_summary" class="mt-2 space-y-1.5">
                            <p class="text-xs leading-relaxed text-gray-400">{{ componentResult.assessment.executive_summary.vulnerability }}</p>
                            <p class="text-xs leading-relaxed text-gray-300">{{ componentResult.assessment.executive_summary.assessment }}</p>
                            <ul v-if="componentResult.assessment.executive_summary.why?.length" class="space-y-1 pl-4 text-xs leading-relaxed text-gray-400 list-disc">
                                <li v-for="reason in componentResult.assessment.executive_summary.why" :key="reason">{{ reason }}</li>
                            </ul>
                            <p v-else-if="componentResult.assessment.reasoning" class="text-xs leading-relaxed text-gray-400">
                                {{ componentResult.assessment.reasoning }}
                            </p>
                        </div>
                        <p v-else class="mt-2 text-xs leading-relaxed text-gray-400">{{ componentResult.assessment.summary }}</p>
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
                        v-if="jiraCreateUrl"
                        type="button"
                        @click="createJiraIssue"
                        title="Copy the ticket draft and open the Jira create screen"
                        class="inline-flex shrink-0 items-center gap-1.5 rounded border border-blue-700/70 bg-blue-950/60 px-2.5 py-1 text-[10px] font-bold uppercase text-blue-100 hover:bg-blue-900/70"
                    >
                        <ExternalLink :size="12" />
                        Create Jira issue
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

            <div class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                    <button
                        type="button"
                        @click="coverageOpen = !coverageOpen"
                        class="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-gray-950/60"
                        :aria-expanded="coverageOpen"
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
                        :aria-expanded="systemPromptOpen"
                    >
                        <span class="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-gray-500">
                            <Loader2 v-if="systemPromptLoading" :size="12" class="animate-spin" />
                            <component v-else :is="systemPromptOpen ? ChevronUp : ChevronDown" :size="12" />
                            LLM Conversation
                        </span>
                        <span class="text-[10px] font-semibold text-gray-500">{{ llmConversationSummary }}</span>
                    </button>
                    <CodeAnalysisConversationViewport v-if="systemPromptOpen">
                        <div v-if="systemPromptLoading" class="flex items-center gap-2 text-xs text-gray-500">
                            <Loader2 :size="12" class="animate-spin" />
                            Loading conversation
                        </div>
                        <div v-else-if="systemPromptError" class="rounded border border-amber-800/50 bg-amber-950/20 p-3 text-xs text-amber-300">
                            {{ systemPromptError }}
                        </div>
                        <div v-else-if="llmConversationTurns.length === 0 && systemPromptBundles.length === 0 && !savedRunGuidance && !selectedRunGuidanceRedacted" class="text-xs text-gray-500">
                            No LLM conversation reported
                        </div>
                        <div v-else class="space-y-5">
                            <div v-if="llmConversationTurns.length > 0" class="space-y-4">
                                <div class="flex flex-wrap items-end justify-between gap-2 border-b border-gray-800 pb-3">
                                    <div>
                                        <div class="text-[11px] font-bold uppercase tracking-wider text-cyan-300">Actual LLM conversation</div>
                                        <p class="mt-1 text-[11px] leading-relaxed text-gray-500">
                                            Captured run evidence. Each turn shows the assembled Agentyzer request before the model output it produced.
                                        </p>
                                    </div>
                                    <div class="flex flex-wrap items-center justify-end gap-1.5">
                                        <span class="rounded-full border border-gray-700 bg-gray-900 px-2 py-1 text-[9px] font-bold uppercase tracking-wider text-gray-400">
                                            {{ llmConversationTurns.length }} turn{{ llmConversationTurns.length === 1 ? '' : 's' }}
                                        </span>
                                        <button
                                            type="button"
                                            data-testid="expand-all-llm-stages"
                                            class="rounded px-2 py-1 text-[9px] font-semibold text-gray-400 transition-colors hover:bg-gray-800 hover:text-gray-200 disabled:cursor-default disabled:opacity-40"
                                            :disabled="allConversationStagesOpen"
                                            @click="setAllConversationStages(true)"
                                        >
                                            Expand all
                                        </button>
                                        <button
                                            type="button"
                                            data-testid="collapse-all-llm-stages"
                                            class="rounded px-2 py-1 text-[9px] font-semibold text-gray-400 transition-colors hover:bg-gray-800 hover:text-gray-200 disabled:cursor-default disabled:opacity-40"
                                            :disabled="!anyConversationStageOpen"
                                            @click="setAllConversationStages(false)"
                                        >
                                            Collapse all
                                        </button>
                                    </div>
                                </div>
                                <section
                                    class="overflow-hidden rounded-md border border-fuchsia-900/45 bg-fuchsia-950/10"
                                    data-testid="llm-guidance-evidence"
                                    aria-label="Additional guidance used"
                                >
                                    <div class="flex flex-wrap items-start justify-between gap-2 border-b border-fuchsia-900/35 px-3 py-2.5">
                                        <div>
                                            <h3 class="text-[11px] font-bold uppercase tracking-wider text-fuchsia-200">Additional guidance used</h3>
                                            <p class="mt-0.5 text-[10px] leading-relaxed text-gray-500">
                                                Guidance is reviewer context to investigate, not evidence of affectedness by itself.
                                            </p>
                                        </div>
                                        <span
                                            v-if="capturedConversationGuidance.length > 0"
                                            class="rounded-full border border-green-700/50 bg-green-950/30 px-2 py-1 text-[9px] font-bold uppercase tracking-wider text-green-300"
                                        >
                                            Captured in model request
                                        </span>
                                        <span
                                            v-else-if="savedRunGuidance"
                                            class="rounded-full border border-amber-700/50 bg-amber-950/30 px-2 py-1 text-[9px] font-bold uppercase tracking-wider text-amber-300"
                                        >
                                            Saved · use not verifiable
                                        </span>
                                        <span
                                            v-else-if="selectedRunGuidanceRedacted"
                                            class="rounded-full border border-amber-700/50 bg-amber-950/30 px-2 py-1 text-[9px] font-bold uppercase tracking-wider text-amber-300"
                                        >
                                            Redacted
                                        </span>
                                        <span v-else class="text-[9px] font-semibold uppercase tracking-wider text-gray-500">
                                            None captured
                                        </span>
                                    </div>
                                    <div v-if="capturedConversationGuidance.length > 0" class="divide-y divide-fuchsia-900/25">
                                        <article
                                            v-for="guidance in capturedConversationGuidance"
                                            :key="guidance.key"
                                            class="px-3 py-2.5"
                                        >
                                            <div class="mb-1.5 flex flex-wrap items-center gap-1.5 text-[9px] font-semibold text-gray-500">
                                                <span v-if="guidance.component" class="rounded bg-gray-900 px-1.5 py-0.5 text-gray-300">{{ guidance.component }}</span>
                                                <span>Model request turn{{ guidance.turns.length === 1 ? '' : 's' }} {{ guidance.turns.join(', ') }}</span>
                                            </div>
                                            <pre class="max-h-48 overflow-y-auto overscroll-auto whitespace-pre-wrap break-words rounded border border-fuchsia-900/30 bg-gray-950/50 p-2 text-[10px] leading-relaxed text-gray-300" tabindex="0">{{ guidance.content }}</pre>
                                        </article>
                                    </div>
                                    <div v-else-if="savedRunGuidance" class="space-y-2 px-3 py-2.5">
                                        <p class="text-[10px] leading-relaxed text-amber-200">
                                            DTVP saved this guidance with the analyzer request, but it was not found in the captured model messages. Without matching trace evidence, model use cannot be verified.
                                        </p>
                                        <pre class="max-h-48 overflow-y-auto overscroll-auto whitespace-pre-wrap break-words rounded border border-amber-900/35 bg-gray-950/50 p-2 text-[10px] leading-relaxed text-gray-300" tabindex="0">{{ savedRunGuidance }}</pre>
                                    </div>
                                    <p v-else-if="selectedRunGuidanceRedacted" class="px-3 py-2.5 text-[10px] leading-relaxed text-amber-200">
                                        Guidance and prompt trace content were removed by the result-storage policy, so this run cannot prove which additional guidance reached the model.
                                    </p>
                                    <p v-else class="px-3 py-2.5 text-[10px] leading-relaxed text-gray-500">
                                        No additional guidance marker was found in any captured model request for this run.
                                    </p>
                                </section>
                                <section
                                    class="overflow-hidden rounded-md border border-cyan-900/45 bg-cyan-950/10"
                                    data-testid="llm-conversation-summary"
                                    aria-label="LLM conversation summary"
                                >
                                    <div class="flex flex-wrap items-start justify-between gap-2 border-b border-cyan-900/35 px-3 py-2.5">
                                        <div>
                                            <h3 class="text-[11px] font-bold uppercase tracking-wider text-cyan-200">Conversation summary</h3>
                                            <p class="mt-0.5 text-[10px] leading-relaxed text-gray-500">
                                                Persisted message, token, timing, and tool telemetry for this trace.
                                            </p>
                                        </div>
                                        <span class="text-[9px] font-semibold text-gray-500">
                                            {{ llmConversationStatistics.completedTurns }}/{{ llmConversationStatistics.rows.length }} completed
                                        </span>
                                    </div>

                                    <dl class="grid divide-y divide-cyan-900/25 sm:grid-cols-2 sm:divide-x sm:divide-y-0 xl:grid-cols-4">
                                        <div class="px-3 py-2.5">
                                            <dt class="text-[9px] font-bold uppercase tracking-wider text-cyan-400">Local → LLM</dt>
                                            <dd class="mt-1 text-sm font-semibold text-gray-100" data-testid="llm-local-message-count">
                                                {{ llmConversationStatistics.outboundMessages.toLocaleString() }} messages
                                            </dd>
                                            <dd class="mt-0.5 text-[10px] text-gray-500">
                                                {{ formatConversationTokens(llmConversationStatistics.promptTokens) }} prompt tokens · {{ llmConversationStatistics.requestCharacters.toLocaleString() }} chars
                                            </dd>
                                        </div>
                                        <div class="px-3 py-2.5">
                                            <dt class="text-[9px] font-bold uppercase tracking-wider text-green-400">LLM → Local</dt>
                                            <dd class="mt-1 text-sm font-semibold text-gray-100" data-testid="llm-response-message-count">
                                                {{ llmConversationStatistics.inboundMessages.toLocaleString() }} responses
                                            </dd>
                                            <dd class="mt-0.5 text-[10px] text-gray-500">
                                                {{ formatConversationTokens(llmConversationStatistics.completionTokens) }} completion tokens · {{ llmConversationStatistics.responseCharacters.toLocaleString() }} chars
                                            </dd>
                                        </div>
                                        <div class="px-3 py-2.5">
                                            <dt class="text-[9px] font-bold uppercase tracking-wider text-purple-400">Captured time</dt>
                                            <dd class="mt-1 text-sm font-semibold text-gray-100" data-testid="llm-conversation-total-time">
                                                {{ formatConversationDuration(llmConversationStatistics.capturedSpanMs) }} altogether
                                            </dd>
                                            <dd class="mt-0.5 text-[10px] text-gray-500">
                                                {{ formatConversationDuration(llmConversationStatistics.totalDurationMs) }} LLM · {{ formatConversationDuration(llmConversationStatistics.localDurationMs) }} inferred local/tool
                                            </dd>
                                        </div>
                                        <div class="px-3 py-2.5">
                                            <dt class="text-[9px] font-bold uppercase tracking-wider text-amber-400">Tool activity</dt>
                                            <dd class="mt-1 text-sm font-semibold text-gray-100" data-testid="llm-tool-usage-summary">
                                                {{ llmConversationStatistics.llmToolRequests }} LLM requests · {{ llmConversationStatistics.localToolResults }} local results
                                            </dd>
                                            <dd class="mt-0.5 text-[10px] text-gray-500">
                                                {{ llmConversationStatistics.repositoryInspections }} repo · {{ llmConversationStatistics.toolFailures }} failed<span v-if="llmConversationStatistics.analyzerRequiredTools"> · {{ llmConversationStatistics.analyzerRequiredTools }} analyzer-required</span>
                                            </dd>
                                        </div>
                                    </dl>

                                    <div class="flex flex-wrap gap-x-4 gap-y-1 border-t border-cyan-900/25 px-3 py-2 text-[9px] text-gray-500">
                                        <span><strong class="font-semibold text-gray-300">Total tokens:</strong> {{ formatConversationTokens(llmConversationStatistics.totalTokens) }} ({{ llmConversationStatistics.usageTurns }}/{{ llmConversationStatistics.rows.length }} turns reported)</span>
                                        <span><strong class="font-semibold text-gray-300">Timing:</strong> {{ llmConversationStatistics.timedTurns }}/{{ llmConversationStatistics.rows.length }} turns reported</span>
                                        <span v-if="llmConversationStatistics.throughput != null"><strong class="font-semibold text-gray-300">Throughput:</strong> {{ llmConversationStatistics.throughput.toFixed(1) }} completion tokens/s</span>
                                        <span><strong class="font-semibold text-gray-300">Retries:</strong> {{ llmConversationStatistics.retries }}</span>
                                        <span><strong class="font-semibold text-gray-300">Context adaptations:</strong> {{ llmConversationStatistics.contextAdaptations }}</span>
                                        <span><strong class="font-semibold text-gray-300">Models:</strong> {{ llmConversationStatistics.models.join(', ') || 'Not reported' }}</span>
                                        <span><strong class="font-semibold text-gray-300">Providers:</strong> {{ llmConversationStatistics.providers.join(', ') || 'Not reported' }}</span>
                                        <span v-if="llmConversationStatistics.toolTypes.length"><strong class="font-semibold text-gray-300">Requested tools:</strong> {{ llmConversationStatistics.toolTypes.map(([kind, count]) => `${kind} ${count}`).join(' · ') }}</span>
                                    </div>

                                    <div
                                        class="max-h-64 overflow-auto overscroll-auto border-t border-cyan-900/25 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/50"
                                        tabindex="0"
                                        aria-label="Per-turn LLM conversation timing"
                                    >
                                        <table class="min-w-full text-left text-[10px]" data-testid="llm-conversation-timing-table">
                                            <thead class="bg-gray-950/55 text-[9px] font-bold uppercase tracking-wider text-gray-500">
                                                <tr>
                                                    <th class="px-3 py-1.5">Step</th>
                                                    <th class="px-2 py-1.5">Messages</th>
                                                    <th class="px-2 py-1.5">Tokens in / out</th>
                                                    <th class="px-2 py-1.5">LLM time</th>
                                                    <th class="px-2 py-1.5">Local/tool after</th>
                                                    <th class="px-2 py-1.5">Tools</th>
                                                    <th class="px-3 py-1.5 text-right">Status</th>
                                                </tr>
                                            </thead>
                                            <tbody class="divide-y divide-gray-800/70 text-gray-300">
                                                <tr v-for="row in llmConversationStatistics.rows" :key="`summary-${row.key}`">
                                                    <td class="whitespace-nowrap px-3 py-1.5 font-semibold">{{ row.label }}</td>
                                                    <td class="whitespace-nowrap px-2 py-1.5">{{ row.outboundMessages }} → · {{ row.inboundMessages }} ←</td>
                                                    <td class="whitespace-nowrap px-2 py-1.5 font-mono">{{ formatConversationTokens(row.promptTokens) }} / {{ formatConversationTokens(row.completionTokens) }}</td>
                                                    <td class="whitespace-nowrap px-2 py-1.5 font-mono">{{ formatConversationDuration(row.durationMs) }}</td>
                                                    <td class="whitespace-nowrap px-2 py-1.5 font-mono" :title="row.localDurationMs == null ? 'No following timestamp available' : 'Inferred from this LLM response finishing until the next LLM request starts'">
                                                        {{ formatConversationDuration(row.localDurationMs) }}
                                                    </td>
                                                    <td class="whitespace-nowrap px-2 py-1.5">{{ row.requestedTools }} LLM · {{ row.localToolResults }} local<span v-if="row.analyzerRequiredTools"> · {{ row.analyzerRequiredTools }} required</span></td>
                                                    <td class="whitespace-nowrap px-3 py-1.5 text-right uppercase" :class="row.status === 'completed' ? 'text-green-400' : 'text-amber-300'">{{ row.status }}</td>
                                                </tr>
                                            </tbody>
                                        </table>
                                    </div>
                                    <p class="border-t border-cyan-900/25 px-3 py-1.5 text-[9px] leading-relaxed text-gray-600">
                                        LLM time uses each persisted request timestamp. Local/tool time is the inferred gap before the next request; work before the first or after the final LLM call is not captured.
                                    </p>
                                </section>
                                <article
                                    v-for="(conversation, index) in llmConversationViewTurns"
                                    :key="conversation.key"
                                    class="rounded-md border border-gray-800 bg-gray-950/45"
                                    data-testid="llm-conversation-turn"
                                >
                                    <header class="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 bg-gray-900/45 px-3 py-2">
                                        <div class="text-[10px] font-bold uppercase tracking-wider text-gray-300">
                                            {{ formatConversationMeta(conversation.turn, index) }}
                                        </div>
                                        <span v-if="conversation.turn.usage?.total_tokens" class="font-mono text-[9px] text-gray-500">
                                            {{ conversation.turn.usage.total_tokens }} tokens
                                        </span>
                                    </header>

                                    <div class="relative ml-4 space-y-6 border-l border-gray-700/70 px-4 py-4 sm:ml-5 sm:pl-5">
                                        <section class="relative space-y-3">
                                            <span class="absolute -left-[1.62rem] top-0 flex h-5 w-5 items-center justify-center rounded-full border border-cyan-600 bg-cyan-950 text-[9px] font-bold text-cyan-200">1</span>
                                            <div class="flex flex-wrap items-start justify-between gap-2">
                                                <button
                                                    type="button"
                                                    class="group flex min-w-0 items-start gap-1.5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/50"
                                                    data-testid="llm-stage-toggle-request"
                                                    :aria-expanded="isConversationStageOpen(conversation.key, 'request')"
                                                    :aria-controls="conversationStageId(index, 'request')"
                                                    @click="toggleConversationStage(conversation.key, 'request')"
                                                >
                                                    <component :is="isConversationStageOpen(conversation.key, 'request') ? ChevronUp : ChevronDown" :size="13" class="mt-px shrink-0 text-cyan-400" />
                                                    <span>
                                                        <span class="block text-[11px] font-bold uppercase tracking-wider text-cyan-200">Request assembled by Agentyzer</span>
                                                        <span class="mt-0.5 block text-[10px] text-gray-500">{{ conversation.messages.length }} message{{ conversation.messages.length === 1 ? '' : 's' }} · complete model payload</span>
                                                    </span>
                                                </button>
                                                <div class="flex items-center gap-1.5">
                                                    <span class="rounded border border-cyan-700/50 bg-cyan-950/30 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-cyan-200">Agentyzer → Model</span>
                                                    <button
                                                        v-if="conversation.requestText"
                                                        type="button"
                                                        class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-semibold text-gray-400 hover:bg-gray-800 hover:text-gray-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
                                                        :aria-label="`Copy request for turn ${index + 1}`"
                                                        @click="copyConversationText(`request-${index}`, conversation.requestText)"
                                                    >
                                                        <Copy :size="10" />
                                                        {{ conversationCopyState[`request-${index}`] === 'copied' ? 'Copied' : conversationCopyState[`request-${index}`] === 'error' ? 'Copy failed' : 'Copy request' }}
                                                    </button>
                                                </div>
                                            </div>
                                            <div
                                                v-if="isConversationStageOpen(conversation.key, 'request')"
                                                :id="conversationStageId(index, 'request')"
                                                data-testid="llm-stage-content-request"
                                                class="max-h-96 space-y-2 overflow-y-auto overscroll-auto pr-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/50"
                                                tabindex="0"
                                                :aria-label="`Request content for turn ${index + 1}`"
                                            >
                                                <div
                                                    v-for="(message, messageIndex) in conversation.messages"
                                                    :key="`message-${messageIndex}`"
                                                    class="min-w-0 rounded border px-3 py-2.5 shadow-sm"
                                                    :class="conversationBubbleClass(message.role)"
                                                >
                                                    <div class="mb-2 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 border-b border-white/10 pb-1.5">
                                                        <span class="text-[10px] font-bold uppercase tracking-wider">{{ conversationActorLabel(message.role) }}</span>
                                                        <span class="text-[9px] font-semibold uppercase tracking-wider opacity-70">{{ conversationSentMeta(message.role) }}</span>
                                                    </div>
                                                    <div
                                                        v-for="(part, partIndex) in message.parts"
                                                        :key="`${messageIndex}-${part.key}`"
                                                        class="space-y-1"
                                                        :class="partIndex > 0 ? 'mt-3 border-t border-white/10 pt-2.5' : ''"
                                                    >
                                                        <div class="text-[9px] font-bold uppercase tracking-wider" :class="conversationPartLabelClass(part.kind)">{{ part.label }}</div>
                                                        <pre class="whitespace-pre-wrap break-words text-[11px] leading-relaxed">{{ part.content }}</pre>
                                                    </div>
                                                </div>
                                            </div>
                                        </section>

                                        <section v-if="conversation.activities.length > 0" class="relative space-y-3">
                                            <span class="absolute -left-[1.62rem] top-0 flex h-5 w-5 items-center justify-center rounded-full border border-amber-600 bg-amber-950 text-[9px] font-bold text-amber-200">2</span>
                                            <div class="flex flex-wrap items-start justify-between gap-2">
                                                <button
                                                    type="button"
                                                    class="group flex min-w-0 items-start gap-1.5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/50"
                                                    data-testid="llm-stage-toggle-tools"
                                                    :aria-expanded="isConversationStageOpen(conversation.key, 'tools')"
                                                    :aria-controls="conversationStageId(index, 'tools')"
                                                    @click="toggleConversationStage(conversation.key, 'tools')"
                                                >
                                                    <component :is="isConversationStageOpen(conversation.key, 'tools') ? ChevronUp : ChevronDown" :size="13" class="mt-px shrink-0 text-amber-400" />
                                                    <span>
                                                        <span class="block text-[11px] font-bold uppercase tracking-wider text-amber-200">Tool activity</span>
                                                        <span class="mt-0.5 block text-[10px] text-gray-500">{{ conversation.activities.length }} detected event{{ conversation.activities.length === 1 ? '' : 's' }}</span>
                                                    </span>
                                                </button>
                                                <span class="rounded border border-amber-700/50 bg-amber-950/30 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-amber-200">Agentyzer ↔ Tools</span>
                                            </div>
                                            <div
                                                v-if="isConversationStageOpen(conversation.key, 'tools')"
                                                :id="conversationStageId(index, 'tools')"
                                                data-testid="llm-stage-content-tools"
                                                class="max-h-80 grid gap-1.5 overflow-y-auto overscroll-auto pr-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/50 lg:grid-cols-2"
                                                tabindex="0"
                                                :aria-label="`Tool activity for turn ${index + 1}`"
                                            >
                                                <div
                                                    v-for="activity in conversation.activities"
                                                    :key="activity.key"
                                                    class="rounded border px-2.5 py-2 text-[10px]"
                                                    :class="toolActivityClass(activity)"
                                                >
                                                    <div class="flex flex-wrap items-center gap-x-2 gap-y-1">
                                                        <span class="font-bold uppercase tracking-wider">{{ activity.label }}</span>
                                                        <span class="rounded border border-current/30 px-1 py-0.5 font-mono text-[9px] uppercase opacity-80">{{ activity.status }}</span>
                                                    </div>
                                                    <div class="mt-1 break-words font-mono text-[10px] opacity-90">{{ activity.target }}</div>
                                                </div>
                                            </div>
                                        </section>

                                        <section v-if="conversation.response" class="relative space-y-3">
                                            <span class="absolute -left-[1.62rem] top-0 flex h-5 w-5 items-center justify-center rounded-full border border-green-600 bg-green-950 text-[9px] font-bold text-green-200">{{ conversation.activities.length > 0 ? 3 : 2 }}</span>
                                            <div class="flex flex-wrap items-start justify-between gap-2">
                                                <button
                                                    type="button"
                                                    class="group flex min-w-0 items-start gap-1.5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-green-500/50"
                                                    data-testid="llm-stage-toggle-response"
                                                    :aria-expanded="isConversationStageOpen(conversation.key, 'response')"
                                                    :aria-controls="conversationStageId(index, 'response')"
                                                    @click="toggleConversationStage(conversation.key, 'response')"
                                                >
                                                    <component :is="isConversationStageOpen(conversation.key, 'response') ? ChevronUp : ChevronDown" :size="13" class="mt-px shrink-0 text-green-400" />
                                                    <span>
                                                        <span class="block text-[11px] font-bold uppercase tracking-wider text-green-200">Model response</span>
                                                        <span class="mt-0.5 block text-[10px] text-gray-500">Raw answer · {{ conversation.response.content.length.toLocaleString() }} characters</span>
                                                    </span>
                                                </button>
                                                <div class="flex items-center gap-1.5">
                                                    <span class="rounded border border-green-700/50 bg-green-950/30 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-green-200">Model → Agentyzer</span>
                                                    <button
                                                        type="button"
                                                        class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-semibold text-gray-400 hover:bg-gray-800 hover:text-gray-200 focus:outline-none focus:ring-2 focus:ring-green-500/50"
                                                        :aria-label="`Copy model response for turn ${index + 1}`"
                                                        @click="copyConversationText(`response-${index}`, conversation.response?.content || '')"
                                                    >
                                                        <Copy :size="10" />
                                                        {{ conversationCopyState[`response-${index}`] === 'copied' ? 'Copied' : conversationCopyState[`response-${index}`] === 'error' ? 'Copy failed' : 'Copy response' }}
                                                    </button>
                                                </div>
                                            </div>
                                            <div
                                                v-if="isConversationStageOpen(conversation.key, 'response')"
                                                :id="conversationStageId(index, 'response')"
                                                data-testid="llm-stage-content-response"
                                                class="max-h-96 overflow-y-auto overscroll-auto rounded border px-3 py-2.5 shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-green-500/50"
                                                tabindex="0"
                                                :aria-label="`Model response for turn ${index + 1}`"
                                                :class="conversationBubbleClass('assistant')"
                                            >
                                                <div class="mb-2 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 border-b border-white/10 pb-1.5">
                                                    <span class="text-[10px] font-bold uppercase tracking-wider">Model output</span>
                                                    <span class="text-[9px] font-semibold uppercase tracking-wider opacity-70">{{ conversation.response?.role }} response · captured verbatim</span>
                                                </div>
                                                <pre class="whitespace-pre-wrap break-words text-[11px] leading-relaxed">{{ conversation.response?.content }}</pre>
                                            </div>
                                        </section>

                                        <div v-if="conversation.turn.error" class="rounded border border-red-800/50 bg-red-950/40 p-2 text-[10px] text-red-300">
                                            {{ conversation.turn.error }}
                                        </div>
                                    </div>
                                </article>
                            </div>

                            <template v-if="llmConversationTurns.length === 0">
                                <div class="rounded border border-amber-800/40 bg-amber-950/15 p-3 text-[10px] leading-relaxed text-amber-200">
                                    This run did not capture a conversation. Configured prompt values below are current fallbacks and may differ from what the model received.
                                </div>
                                <div
                                    v-for="bundle in systemPromptBundles"
                                    :key="bundle.bundle"
                                    class="space-y-2"
                                >
                                    <div class="text-[10px] font-bold uppercase tracking-wider text-cyan-300">{{ bundle.bundle }} configured prompt values · not captured from this run</div>
                                    <pre
                                        v-for="(value, key) in (bundle.values || {})"
                                        :key="String(key)"
                                        class="whitespace-pre-wrap break-words rounded border border-gray-800 bg-gray-900 p-3 text-[11px] leading-relaxed text-gray-300"
                                    >{{ formatPromptValueLabel(key) }}:
{{ value }}</pre>
                                </div>
                            </template>
                            <div v-if="llmConversationTurns.length === 0 && savedRunGuidance" class="space-y-2">
                                <div class="flex flex-wrap items-center justify-between gap-2">
                                    <div class="text-[10px] font-bold uppercase tracking-wider text-fuchsia-300">Saved additional guidance</div>
                                    <span class="rounded-full border border-amber-700/50 bg-amber-950/30 px-2 py-1 text-[9px] font-bold uppercase tracking-wider text-amber-300">Use not verifiable</span>
                                </div>
                                <p class="text-[10px] leading-relaxed text-amber-200">
                                    DTVP saved this guidance on the analyzer request, but no model conversation was captured for this run.
                                </p>
                                <pre class="max-h-48 overflow-y-auto overscroll-auto whitespace-pre-wrap break-words rounded border border-fuchsia-900/40 bg-fuchsia-950/15 p-3 text-[11px] leading-relaxed text-gray-300" tabindex="0">{{ savedRunGuidance }}</pre>
                            </div>
                            <div v-else-if="llmConversationTurns.length === 0 && selectedRunGuidanceRedacted" class="rounded border border-amber-800/40 bg-amber-950/15 p-3 text-[10px] leading-relaxed text-amber-200">
                                Additional guidance and prompt trace content were redacted by the result-storage policy, so model use cannot be verified for this run.
                            </div>
                        </div>
                    </CodeAnalysisConversationViewport>
                </div>

            <div class="overflow-hidden rounded border border-gray-800 bg-gray-950/40">
                    <button
                        type="button"
                        @click="stepsExpanded = !stepsExpanded"
                        class="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-gray-950/60"
                        :aria-expanded="stepsExpanded"
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
        </div>
        </div>
            </div>
            </template>
            <div
                v-if="historyLoaded && !historyLoading && analysisRunListEntries.length === 0"
                role="listitem"
                class="px-3 py-3 text-xs text-gray-500"
            >
                No analysis runs are stored for the components in this scope.
            </div>
            </div>

        <div v-if="historyError" class="rounded border border-amber-700/40 bg-amber-900/15 px-3 py-2 text-xs text-amber-200">
            {{ historyError }}
        </div>

        <div v-if="error" class="flex items-start gap-2 rounded border border-red-700/40 bg-red-900/20 p-2 text-xs text-red-300">
            <XCircle :size="14" class="mt-0.5 shrink-0" />
            <span>{{ error }}</span>
        </div>
        </DetailSection>

        <DetailSection
            :step="isReviewer ? 'Code evidence · 1' : 'Code evidence · 2'"
            title="Combined assessment"
            :description="isReviewer
                ? 'Review the worst-case proposal across the latest result for every affected target before inspecting individual runs.'
                : 'Combine the latest completed run for every affected target into one scoped assessment proposal.'"
            bodyClass="space-y-3"
            data-testid="combined-analysis-assessment"
            :class="isReviewer ? 'order-2' : 'order-3'"
        >
            <template #actions>
                <button
                    v-if="canApplyAllResults"
                    type="button"
                    data-testid="apply-all-analysis-results"
                    :disabled="applyingAll || combinedHydrating"
                    :title="applyAllTitle"
                    class="inline-flex items-center gap-1.5 rounded bg-cyan-600 px-3 py-2 text-xs font-bold text-white transition-colors hover:bg-cyan-700 disabled:cursor-wait disabled:opacity-50"
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
                    class="inline-flex items-center gap-1.5 rounded bg-cyan-600 px-3 py-2 text-xs font-bold text-white transition-colors hover:bg-cyan-700"
                    @click="applyPersistedResult(applyAllCandidates[0].record)"
                >
                    <CheckCircle :size="12" />
                    Use result as draft
                </button>
            </template>

            <div
                v-if="combinedAssessmentPreview"
                class="border-l-2 px-3 py-3"
                :class="combinedAssessmentPreviewBorderClass"
                data-testid="combined-assessment-preview"
            >
                <div class="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                    <span class="text-[9px] font-bold uppercase tracking-wider text-gray-500">Latest coverage</span>
                    <span class="text-[10px] text-gray-500">
                        {{ combinedCandidateRuns.length }} of {{ applyAllCandidates.length }} latest targets loaded
                    </span>
                </div>

                <div class="mt-3 space-y-3">
                    <div v-if="combinedAssessmentPreview.assessment.executive_summary?.vulnerability">
                        <p class="text-[9px] font-bold uppercase tracking-wider text-gray-500">Advisory</p>
                        <p class="mt-0.5 text-xs leading-relaxed text-gray-300">
                            {{ combinedAssessmentPreview.assessment.executive_summary.vulnerability }}
                        </p>
                    </div>

                    <div class="rounded border border-gray-800/80 bg-gray-950/25 p-2.5" data-testid="combined-decision-summary">
                        <p class="text-[9px] font-bold uppercase tracking-wider text-gray-500">Worst-case decision</p>
                        <dl class="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs md:grid-cols-4">
                            <div>
                                <dt class="text-[9px] font-semibold uppercase tracking-wide text-gray-600">Disposition</dt>
                                <dd class="mt-0.5 font-semibold" :class="combinedAssessmentPreviewTextClass">
                                    {{ combinedAssessmentPreview.assessment.verdict }}
                                </dd>
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
                                    {{ combinedTargetResults.length }} target{{ combinedTargetResults.length === 1 ? '' : 's' }}
                                </dd>
                            </div>
                        </dl>
                        <div v-if="combinedControllingTargets.length" class="mt-2 flex flex-wrap items-center gap-1.5 border-t border-gray-800/70 pt-2">
                            <span class="text-[9px] font-semibold uppercase tracking-wide text-gray-600">
                                Controlling target{{ combinedControllingTargets.length === 1 ? '' : 's' }}
                            </span>
                            <span v-if="allCombinedTargetsControlDecision" class="text-[10px] text-gray-300">
                                All {{ combinedTargetResults.length }} targets
                            </span>
                            <template v-else>
                                <span
                                    v-for="component in combinedControllingTargets"
                                    :key="component"
                                    class="rounded border border-gray-700/70 bg-gray-950/50 px-1.5 py-0.5 font-mono text-[10px] text-gray-300"
                                >
                                    {{ component }}
                                </span>
                            </template>
                        </div>
                    </div>

                    <div v-if="combinedTargetResults.length" data-testid="combined-target-assessments">
                        <div class="flex items-center justify-between gap-2">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-500">Target assessments</p>
                            <span class="text-[10px] text-gray-600">Latest completed result per target</span>
                        </div>
                        <div class="mt-1.5 grid gap-2 xl:grid-cols-2">
                            <article
                                v-for="target in combinedTargetResults"
                                :key="target.component"
                                :data-component="target.component"
                                data-testid="combined-target-assessment"
                                class="rounded border border-gray-800 bg-gray-950/35 p-3"
                            >
                                <header class="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-gray-800/70 pb-2">
                                    <h4 class="font-mono text-xs font-semibold text-gray-200">{{ target.component }}</h4>
                                    <span class="text-[10px] font-bold uppercase" :class="combinedTargetVerdictClass(target.assessment)">
                                        {{ target.assessment.verdict }}
                                    </span>
                                    <span class="text-[10px] text-gray-500">
                                        {{ target.assessment.confidence }} confidence · {{ target.assessment.exposure }}
                                    </span>
                                </header>
                                <div v-if="combinedTargetReasons(target).length" class="mt-2">
                                    <p class="text-[9px] font-semibold uppercase tracking-wide text-gray-600">Decision rationale</p>
                                    <ul class="mt-1 space-y-1 pl-4 text-xs leading-relaxed text-gray-400 list-disc">
                                        <li v-for="reason in combinedTargetReasons(target)" :key="reason">{{ reason }}</li>
                                    </ul>
                                </div>
                                <p v-else class="mt-2 text-xs leading-relaxed text-gray-400">
                                    {{ target.assessment.summary }}
                                </p>
                            </article>
                        </div>
                    </div>
                </div>
            </div>

            <div v-if="combinedHydrating" class="flex items-center gap-2 text-[11px] text-gray-500">
                <Loader2 :size="11" class="animate-spin" />
                Loading the latest target rationales
            </div>
            <div v-if="combinedHydrationError" class="text-[11px] text-amber-300">
                {{ combinedHydrationError }}
            </div>

            <div v-if="combinedMissingCandidates.length" class="divide-y divide-gray-800/70">
                <p class="px-1 pb-1 text-[9px] font-semibold uppercase tracking-wide text-gray-600">Awaiting target details</p>
                <div
                    v-for="candidate in combinedMissingCandidates"
                    :key="candidate.record.analysis_run_id"
                    class="flex items-center justify-between gap-3 px-1 py-1.5"
                >
                    <div class="min-w-0">
                        <div class="truncate font-mono text-xs text-gray-200">{{ candidate.component }}</div>
                        <div v-if="candidate.team" class="mt-0.5 text-[10px] text-blue-300">{{ candidate.team }}</div>
                    </div>
                    <span class="shrink-0 text-[9px] font-bold uppercase text-gray-400">
                        {{ candidate.record.summary?.verdict || 'Completed' }}
                    </span>
                </div>
            </div>
            <div v-else-if="!applyAllCandidates.length" class="rounded border border-gray-800 bg-gray-950/25 px-3 py-3 text-xs text-gray-500">
                No completed target results are available to combine yet. Run analysis above or wait for queued work to finish.
            </div>

            <p v-if="applyAllCandidates.length > 1" class="text-[11px] leading-relaxed text-gray-500">
                The draft uses the most severe target verdict and keeps each target's evidence and run provenance. Review the generated fields in Assessment before saving or submitting.
            </p>
            <p v-else-if="applyAllCandidates.length === 1" class="text-[11px] leading-relaxed text-gray-500">
                Only one target currently has a completed result, so its individual result is the complete scoped draft.
            </p>
        </DetailSection>

    </div>
</template>
