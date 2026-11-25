<script setup lang="ts">
/**
 * The technical details of one code-analyzer run: the assessment draft
 * preview, benchmark, component results, ticket draft, version coverage,
 * LLM conversation, pipeline evidence, and a follow-up question. Moved out
 * of CodeAnalysisPanel unchanged in behaviour; shown inside the evidence
 * reader under "Technical details".
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { AlertTriangle, CheckCircle, ChevronDown, ChevronUp, Copy, ExternalLink, FileText, Loader2, Send, XCircle } from '@lucide/vue'
import CodeAnalysisReport from './CodeAnalysisReport.vue'
import CodeAnalysisConversationViewport from './CodeAnalysisConversationViewport.vue'
import { codeAnalysisBenchmarkResult, codeAnalysisGetPrompts } from '../lib/api'
import type { CodeAnalysisAssessment, CodeAnalysisAssessResponse, CodeAnalysisBenchmarkComparison, CodeAnalysisBenchmarkFinding, CodeAnalysisLlmConversationTurn, CodeAnalysisLlmMessage, CodeAnalysisResultRecord } from '../lib/api'
import { isCodeAnalysisApplicable, prepareCodeAnalysisResult } from '../lib/codeAnalysisResult'
import { getRuntimeConfig } from '../lib/env'

const props = defineProps<{
    result: CodeAnalysisAssessResponse
    /** The saved run, when the result is one. */
    selectedRecord?: CodeAnalysisResultRecord | null
    /** The latest saved run in scope, for the coverage fallback. */
    latestRecord?: CodeAnalysisResultRecord | null
    vulnId: string
    cvssVector?: string
    /** Components in scope, the ones selected to run, and the ones analyzed. */
    componentNames: string[]
    selectedComponents?: string[]
    analyzedComponents?: string[]
    componentTeams?: Record<string, string>
    projectName?: string
    projectVersions?: string[]
    /** @deprecated Use projectVersions. */
    affectedProductVersions?: string[]
    currentState?: string
    currentJustification?: string
    currentDetails?: string
    currentTeam?: string
    currentCvssScore?: number | string | null
    currentCvssVector?: string
    currentAssigned?: string[]
    runQuestion?: string | null
    canFollowUp?: boolean
    followUpQuestion?: string
    followUpTarget?: string
    followUpBusy?: boolean
}>()

const emit = defineEmits<{
    (event: 'follow-up'): void
    (event: 'update:followUpQuestion', value: string): void
    (event: 'update:followUpTarget', value: string): void
}>()

const result = computed(() => props.result)
const error = ref<string | null>(null)
const selectedPersistedResult = computed(() => props.selectedRecord || null)
const latestPersistedResult = computed(() => props.latestRecord || null)
const uniqueComponents = computed(() => props.componentNames)
const selectedComponents = computed(() => new Set(props.selectedComponents || []))
const analyzedComponents = computed(() => props.analyzedComponents || [])
const hasExistingAssessment = computed(() => {
    const state = String(props.currentState || '').trim().toUpperCase()
    return Boolean(state && state !== 'NOT_SET')
})

const stepsExpanded = ref(false)
const coverageOpen = ref(false)
const assessmentDraftOpen = ref(false)
const assessmentBenchmarkOpen = ref(false)
const componentResultsOpen = ref(false)
const ticketDraftOpen = ref(false)
const systemPromptOpen = ref(false)
const systemPromptLoading = ref(false)
const systemPromptError = ref<string | null>(null)
const systemPromptPayload = ref<Record<string, any> | null>(null)
const conversationCopyState = ref<Record<string, 'idle' | 'copied' | 'error'>>({})
type ConversationStage = 'request' | 'tools' | 'response'
const conversationStageOpen = ref<Record<string, boolean>>({})
const ticketCopyState = ref<'idle' | 'copied' | 'error'>('idle')
const jiraCreateUrl = getRuntimeConfig('DTVP_JIRA_CREATE_URL', '').trim()
const benchmarkComparison = ref<CodeAnalysisBenchmarkComparison | null>(null)
const benchmarkLoading = ref(false)
const benchmarkError = ref<string | null>(null)
let benchmarkLoadCounter = 0
const conversationCopyTimers = new Map<string, ReturnType<typeof setTimeout>>()

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
    if (!result.value || !isCodeAnalysisApplicable(result.value)) return null
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

const hasAffectedResult = computed(() => {
    if (!result.value) return false
    return result.value.assessment.affected || result.value.assessment.verdict.toLowerCase() === 'affected'
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
        props.followUpTarget,
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

const createJiraIssue = async () => {
    if (!ticketText.value || !jiraCreateUrl) return

    let target: URL
    try {
        const baseUrl = window.location.origin === 'null'
            ? 'http://localhost/'
            : `${window.location.origin}/`
        target = new URL(jiraCreateUrl, baseUrl)
        if (target.protocol !== 'http:' && target.protocol !== 'https:') {
            throw new Error('Unsupported Jira URL protocol.')
        }
    } catch {
        error.value = 'The configured Jira create URL is invalid.'
        return
    }

    // Open synchronously from the click so popup blockers recognize the user action.
    // Jira receives its own browser cookies during this top-level navigation.
    window.open(target.toString(), '_blank', 'noopener,noreferrer')
    await copyTicketText()
}

const benchmarkEvaluatorLabel = (comparison: CodeAnalysisBenchmarkComparison) => {
    if (comparison.evaluator?.probabilistic) {
        const model = comparison.evaluator.model ? ` · ${comparison.evaluator.model}` : ''
        return `Agentyzer probabilistic${model}`
    }
    return 'River fallback'
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

onBeforeUnmount(() => {
    for (const timer of conversationCopyTimers.values()) clearTimeout(timer)
    conversationCopyTimers.clear()
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
}, { immediate: true })
</script>

<template>
        <div class="space-y-1" data-testid="selected-analysis-supporting-evidence">
            <div v-if="presentedEvidenceQualityBadges.length" class="flex flex-wrap items-center gap-x-2 gap-y-1 px-1 pb-1" data-testid="evidence-quality-badges">
                <span class="text-[9px] font-semibold uppercase tracking-wide text-gray-500">Evidence quality</span>
                <span
                    v-for="badge in presentedEvidenceQualityBadges"
                    :key="badge.label"
                    class="text-[9px] font-semibold uppercase tracking-wide"
                    :class="badge.className"
                    :title="badge.detail"
                >{{ badge.label }}</span>
            </div>
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
                        <CodeAnalysisReport v-if="componentResult.assessment.report_markdown?.trim()" :markdown="componentResult.assessment.report_markdown" />
                        <div v-else-if="componentResult.assessment.executive_summary" class="mt-2 space-y-1.5">
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
                            Product Version is populated for River affected-version tag or branch checks. Workspace and lock-file rows describe the current analyzed checkout.
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
                                            River saved this guidance with the analyzer request, but it was not found in the captured model messages. Without matching trace evidence, model use cannot be verified.
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
                                    River saved this guidance on the analyzer request, but no model conversation was captured for this run.
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
            <div v-if="runQuestion" class="px-1 text-[11px] leading-relaxed text-blue-200">
                <span class="font-semibold text-blue-400">Follow-up run:</span> {{ runQuestion }}
            </div>
            <div
                v-if="canFollowUp"
                class="grid items-end gap-2 rounded border border-gray-800 bg-gray-950/40 p-2 md:grid-cols-[minmax(0,1fr)_minmax(8rem,13rem)_auto]"
                data-testid="analysis-follow-up-controls"
            >
                <label class="min-w-0">
                    <span class="mb-1 block text-[9px] font-semibold uppercase tracking-wide text-gray-500">Ask a follow-up</span>
                    <input
                        id="code-analysis-follow-up"
                        :value="followUpQuestion"
                        :disabled="followUpBusy"
                        placeholder="e.g. Is the platform package affected?"
                        class="w-full rounded border border-gray-700 bg-gray-950 px-2 py-1.5 text-[11px] focus:border-cyan-500 disabled:opacity-50"
                        @input="emit('update:followUpQuestion', ($event.target as HTMLInputElement).value)"
                        @keyup.enter="emit('follow-up')"
                    />
                </label>
                <label class="min-w-0">
                    <span class="mb-1 block text-[9px] font-semibold uppercase tracking-wide text-gray-500">Target</span>
                    <input
                        id="code-analysis-follow-up-target"
                        :value="followUpTarget"
                        :disabled="followUpBusy"
                        class="w-full rounded border border-gray-700 bg-gray-950 px-2 py-1.5 font-mono text-[11px] focus:border-cyan-500 disabled:opacity-50"
                        @input="emit('update:followUpTarget', ($event.target as HTMLInputElement).value)"
                        @keyup.enter="emit('follow-up')"
                    />
                </label>
                <button
                    type="button"
                    :disabled="followUpBusy || !followUpQuestion?.trim()"
                    class="inline-flex items-center justify-center gap-1.5 rounded bg-blue-700 px-2.5 py-1.5 text-[10px] font-bold text-white transition-colors hover:bg-blue-600 disabled:opacity-50"
                    @click="emit('follow-up')"
                >
                    <Loader2 v-if="followUpBusy" :size="11" class="animate-spin" />
                    <Send v-else :size="11" />
                    Follow-up
                </button>
            </div>
            <div v-if="error" class="px-1 text-[10px] text-amber-300">{{ error }}</div>
        </div>
</template>
