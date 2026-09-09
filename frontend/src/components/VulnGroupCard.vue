<script setup lang="ts">
import { ref, computed, watch, inject, onMounted, onUnmounted, nextTick, type Component } from 'vue'
import { updateAssessment, getAssessmentDetails, getKnownUsers } from '../lib/api'
import { marked } from 'marked'

import type { GroupedVuln, AssessmentPayload, TMRescoreProposal } from '../types'
import { ChevronDown, ChevronUp, Shield, RefreshCw, AlertTriangle, Calculator, ExternalLink, CheckCircle, RotateCcw, Zap, X, Loader2, FileText, Bot, ShieldCheck, Tags, ArrowRight, CircleDot } from 'lucide-vue-next'

import { parseAssessmentBlocks, getAssessmentSyncDraft, parseJustificationFromText, hasGlobalAssessment, getAssessedTeams, isPendingReview as isPendingReviewHelper, getGroupLifecycle, getGroupTechnicalState, sanitizeAssessmentDetails, STATE_PRIORITY, type AssessmentBlock } from '../lib/assessment-helpers'
import { cleanStructuredAssessmentDetails, resolveAssessmentFormValues, resolveDependencyTrackConsensusInput, stripPendingReviewStatus } from '../lib/assessmentFormState'
import { getGroupAssessmentSyncIssues } from '../lib/assessmentSyncIssues'
import { buildRescoredVectorForState, normalizeCvssVectorInstance, type CvssVersion } from '../lib/cvssRescore'
import { buildMergedAssessmentData } from '../lib/mergedAssessmentData'
import { buildSavedAssessmentResultState, buildSavedOriginalAnalysis, prepareAssessmentSubmission } from '../lib/assessmentSubmission'
import { buildCodeAnalysisGlobalReferenceDraft, codeAnalysisAssessmentState, prepareCodeAnalysisResult, prepareCodeAnalysisResults, type CodeAnalysisComponentRun, type CodeAnalysisTeamDraft } from '../lib/codeAnalysisResult'
import { calculateScoreFromVector } from '../lib/cvss'
import { getDerivedGroupTags } from '../lib/dependency-team-selection'
import { buildTeamAliasGroups } from '../lib/team-mapping'
import { useVulnDependencyInfo } from '../lib/useVulnDependencyInfo'
import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'
import CvssVectorDisplay from './CvssVectorDisplay.vue'
import CustomSelect from './CustomSelect.vue'
import VulnGroupCardHeader from './VulnGroupCardHeader.vue'
import VulnGroupAssessmentDetails from './VulnGroupAssessmentDetails.vue'
import VulnGroupCardDependencies from './VulnGroupCardDependencies.vue'
import CalculatorModal from './CalculatorModal.vue'
import ConflictResolutionModal from './ConflictResolutionModal.vue'
import GenericModal from './GenericModal.vue'
import AssessmentReviewModal from './AssessmentReviewModal.vue'
import CodeAnalysisPanel from './CodeAnalysisPanel.vue'
import DetailSection from './DetailSection.vue'
import type { CodeAnalysisAssessResponse, CodeAnalysisCvssAdjustment } from '../lib/api'
import { parseAttributionTimestamp, type AutomaticAssessmentStatus } from '../lib/vulnListIndex'

const props = defineProps<{
    group: GroupedVuln
    inModal?: boolean
    hasAutomaticAssessment?: boolean
    automaticAssessmentStatus?: AutomaticAssessmentStatus | null
    activeTeamFilter?: string
    hasNextVulnerability?: boolean
}>()

const DESCRIPTION_FALLBACK = 'No description available.'

const sanitizeRenderedMarkdown = (html: string): string => html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .replace(/<(iframe|object|embed|form|input|button|textarea|select|option|link|meta)\b[^>]*>/gi, '')
    .replace(/<\/(iframe|object|embed|form|input|button|textarea|select|option)>/gi, '')
    .replace(/\son[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/\s(?:href|src)\s*=\s*(['"])\s*(?:javascript:|data:text\/html)[\s\S]*?\1/gi, '')

const renderAdvisoryMarkdown = (text?: string): string => {
    const source = text?.trim() || DESCRIPTION_FALLBACK
    return sanitizeRenderedMarkdown(marked.parse(source) as string)
}

const renderedDescription = computed(() => renderAdvisoryMarkdown(props.group.description))

const handleCloseOnEscape = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
        if (genericModal.value.show) {
            handleModalResponse(false)
        } else if (showConflictModal.value) {
            showConflictModal.value = false
        } else if (showCalculatorModal.value) {
            showCalculatorModal.value = false
        }
    }
}

onMounted(() => {
    globalThis.addEventListener('keydown', handleCloseOnEscape)
    globalThis.addEventListener('resize', handleViewportResize)
    nextTick(() => {
        if (headerEl.value) headerHeight.value = headerEl.value.offsetHeight
    })
    getKnownUsers().then(users => { knownUsers.value = users }).catch(() => {})
})

onUnmounted(() => {
    globalThis.removeEventListener('keydown', handleCloseOnEscape)
    globalThis.removeEventListener('resize', handleViewportResize)
    if (expanded.value && openCardCount > 0) {
        openCardCount -= 1
        if (openCardCount === 0) {
            unlockBodyScroll()
        }
    }
})

const user = inject<any>('user', ref({ role: 'ANALYST' }))
const teamMapping = inject<any>('teamMapping', ref({}))
const rescoreRules = inject<any>('rescoreRules', ref({ transitions: [] }))
const tmrescoreProposals = inject<any>('tmrescoreProposals', ref({}))

const emit = defineEmits([
    'update',
    'update:assessment',
    'toggle-expand',
    'close',
    'request-next',
])

const ANALYSIS_STATES = [
    { value: 'NOT_SET', label: 'Not Set', description: 'No analysis has been performed yet.' },
    { value: 'NOT_AFFECTED', label: 'Not Affected', description: 'The component is not affected by this vulnerability.' },
    { value: 'EXPLOITABLE', label: 'Exploitable', description: 'The vulnerability is exploitable in this component.' },
    { value: 'IN_TRIAGE', label: 'In Triage', description: 'The vulnerability is currently being investigated.' },
    { value: 'FALSE_POSITIVE', label: 'False Positive', description: 'This finding is a false positive.' },
    { value: 'RESOLVED', label: 'Resolved', description: 'The vulnerability has been resolved or mitigated.' },
]

const JUSTIFICATION_OPTIONS = [
    { value: 'NOT_SET', label: 'Not Set', description: 'No justification provided.' },
    { value: 'CODE_NOT_PRESENT', label: 'Code Not Present', description: 'The vulnerable code is not present in the component.' },
    { value: 'CODE_NOT_REACHABLE', label: 'Code Not Reachable', description: 'The vulnerable code is present but not reachable.' },
    { value: 'REQUIRES_CONFIGURATION', label: 'Requires Configuration', description: 'Exploitation requires a specific non-default configuration.' },
    { value: 'REQUIRES_DEPENDENCY', label: 'Requires Dependency', description: 'Exploitation requires an additional dependency not present.' },
    { value: 'REQUIRES_ENVIRONMENT', label: 'Requires Environment', description: 'Exploitation requires a specific environment.' },
    { value: 'PROTECTED_BY_COMPILER', label: 'Protected by Compiler', description: 'Protected by compiler-level security features.' },
    { value: 'PROTECTED_AT_RUNTIME', label: 'Protected at Runtime', description: 'Protected by runtime mitigation (e.g., ASLR, DEP).' },
    { value: 'PROTECTED_AT_PERIMETER', label: 'Protected at Perimeter', description: 'Protected by network or perimeter security controls.' },
    { value: 'PROTECTED_BY_MITIGATING_CONTROL', label: 'Protected by Mitigating Control', description: 'Protected by other mitigating controls.' },
]

let openCardCount = 0
let bodyScrollLockY = 0

const isDebugPersistenceEnabled = () => globalThis.localStorage?.getItem?.('dtvp_debug_persistence') === 'true'

const lockBodyScroll = () => {
    if (props.inModal) return
    if (globalThis.window === undefined || typeof document === 'undefined') return
    if (openCardCount > 0) return

    bodyScrollLockY = globalThis.scrollY || globalThis.pageYOffset || 0
    document.body.style.position = 'fixed'
    document.body.style.top = `-${bodyScrollLockY}px`
    document.body.style.left = '0'
    document.body.style.right = '0'
    document.body.style.width = '100%'
    document.body.style.overflow = 'hidden'
}

const unlockBodyScroll = () => {
    if (props.inModal) return
    if (globalThis.window === undefined || typeof document === 'undefined') return

    document.body.style.position = ''
    document.body.style.top = ''
    document.body.style.left = ''
    document.body.style.right = ''
    document.body.style.width = ''
    document.body.style.overflow = ''
    globalThis.scrollTo(0, bodyScrollLockY)
}

const expanded = ref(props.inModal ? true : false)
type DetailTab = 'overview' | 'analysis' | 'review' | 'mapping'
const activeDetailTab = ref<DetailTab>('overview')
const state = ref('NOT_SET')
const details = ref('')
const justification = ref('NOT_SET')
const suppressed = ref(false)
const selectedTeam = ref('')
const showAllAssessmentTeams = ref(false)
const scopedCodeAnalysisAvailable = ref(false)
// Removed onlyTargetSelectedTeam - team selection now automatically targets team instances
const updating = ref(false)
const loadingDetails = ref(false)
const showCalculatorModal = ref(false)
const showConflictModal = ref(false)
const conflictData = ref<any>(null)
const originalAnalysis = ref<Record<string, any>>({}) // Map finding_uuid -> Analysis Object
const assessmentPersistenceStatus = computed(() => {
    const analyses = Object.values(originalAnalysis.value)
    const failed = analyses.find(analysis =>
        ['error', 'failed'].includes(
            String(analysis?.dtvpSyncStatus || analysis?.dtvp_sync_status || '').toLowerCase(),
        ),
    )
    if (failed) {
        return {
            kind: 'error',
            label: 'Saved locally — Dependency-Track sync is retrying',
            detail: failed.dtvpSyncError || failed.dtvp_sync_error || '',
        }
    }

    const queued = analyses.some(analysis =>
        ['pending', 'syncing'].includes(
            String(analysis?.dtvpSyncStatus || analysis?.dtvp_sync_status || '').toLowerCase(),
        ),
    )
    return queued
        ? {
            kind: 'pending',
            label: 'Saved locally — syncing to Dependency-Track',
            detail: '',
        }
        : null
})
type AssessmentDraftState = {
    state: string
    details: string
    justification: string
    assigned: string[]
    evidenceReviewed: boolean
    versionCoverageChecked: boolean
    ticket: string
}
const teamDrafts = ref<Map<string, AssessmentDraftState>>(new Map())
const refreshCounter = ref(0)
const formTouched = ref(false)
const codeAnalysisDraftApplied = ref(false)
const codeAnalysisDraftSummary = ref('')
const codeAnalysisRunIds = ref<string[]>([])
const codeAnalysisProposalRuns = ref<CodeAnalysisComponentRun[]>([])
const automaticFallbackTeams = ref<Set<string>>(new Set())
const assessmentSubmitted = ref(false)
const latestCodeAnalysisCvssAdjustment = ref<CodeAnalysisCvssAdjustment | null>(null)
const latestCodeAnalysisCvssComponents = ref<string[]>([])

const isInternalUpdate = ref(false)
const showRawEdit = ref(false)
const rawDetails = ref('')
const rawDetailsTouched = ref(false)
const evidenceReviewed = ref(false)
const versionCoverageChecked = ref(false)
const ticketReference = ref('')
const assessmentTicketCopyState = ref<'idle' | 'copied' | 'error'>('idle')

// Assignee state
const currentAssigned = ref<string[]>([])
const assigneeInput = ref('')
const assigneeSuggestionsVisible = ref(false)
const knownUsers = ref<string[]>([])

const filteredUserSuggestions = computed(() => {
    const query = assigneeInput.value.trim().toLowerCase()
    if (!query) return knownUsers.value.filter(u => !currentAssigned.value.includes(u))
    return knownUsers.value.filter(u =>
        u.toLowerCase().includes(query) && !currentAssigned.value.includes(u)
    )
})

const addAssignee = (username: string) => {
    const trimmed = username.trim()
    if (trimmed && !currentAssigned.value.includes(trimmed)) {
        currentAssigned.value = [...currentAssigned.value, trimmed]
        formTouched.value = true
    }
}

const removeAssignee = (username: string) => {
    currentAssigned.value = currentAssigned.value.filter(u => u !== username)
    formTouched.value = true
}

const addAssigneeFromInput = () => {
    if (assigneeInput.value.trim()) {
        addAssignee(assigneeInput.value)
        assigneeInput.value = ''
        assigneeSuggestionsVisible.value = false
    }
}

const selectAssigneeSuggestion = (username: string) => {
    addAssignee(username)
    assigneeInput.value = ''
    assigneeSuggestionsVisible.value = false
}

const onAssigneeInput = () => {
    assigneeSuggestionsVisible.value = true
}

const headerEl = ref<HTMLElement | null>(null)
const detailsEl = ref<HTMLElement | null>(null)
const headerHeight = ref(48) // sensible default
const detailsMaxHeight = ref('calc(100vh - 8rem)')

const getStickyHeaderOffset = () => {
    if (typeof document === 'undefined') return 0
    const stickyHeader = document.querySelector('header.sticky.top-0') as HTMLElement | null
    const stickyHeight = stickyHeader?.getBoundingClientRect().height ?? 0
    return Math.max(0, Math.round(stickyHeight + 12))
}

const alignHeaderBelowStickyTop = () => {
    if (globalThis.window === undefined || !headerEl.value) return
    const targetTop = Math.max(0, globalThis.scrollY + headerEl.value.getBoundingClientRect().top - getStickyHeaderOffset())
    globalThis.scrollTo({ top: targetTop, behavior: 'auto' })
}

const getFixedFooterOffset = () => {
    if (typeof document === 'undefined') return 0
    const fixedFooter = document.querySelector('footer.fixed.bottom-0') as HTMLElement | null
    const footerHeight = fixedFooter?.getBoundingClientRect().height ?? 0
    // Keep a small gap above the footer overlay.
    return Math.max(0, Math.round(footerHeight + 8))
}

const updateExpandedDetailsMaxHeight = () => {
    if (globalThis.window === undefined || typeof document === 'undefined' || !detailsEl.value) return
    const viewportHeight = globalThis.innerHeight || document.documentElement.clientHeight
    const detailsTop = detailsEl.value.getBoundingClientRect().top
    const availableHeight = Math.floor(viewportHeight - detailsTop - getFixedFooterOffset() - 8)
    detailsMaxHeight.value = `${Math.max(220, availableHeight)}px`
}

const handleViewportResize = () => {
    if (expanded.value) {
        updateExpandedDetailsMaxHeight()
    }
}

const pendingScore = ref<number | null>(null)
const pendingVector = ref<string>('')
const activeVersion = ref<CvssVersion>('3.1')
const cvssInstance = ref<any>(null)
const isManualBaseMode = ref(false)
const initialVector = ref('')
const initialScore = ref<number | null>(null)
const isDerivedCvssScoreUpdate = ref(false)

const reviewModal = ref({
    show: false,
    blocks: [] as AssessmentBlock[],
    aggregatedState: 'NOT_SET',
    sanitizedText: '',
    duplicatesRemoved: 0,
    resolve: (_: boolean) => {}
})

const genericModal = ref({
    show: false,
    title: '',
    message: '',
    confirmOnly: false,
    confirmLabel: '',
    cancelLabel: '',
    discardLabel: '',
    resolve: (_: boolean) => {}
})

const promptConfirm = (
    title: string,
    message: string,
    confirmOnly = false,
    labels: { confirmLabel?: string; cancelLabel?: string; discardLabel?: string } = {},
) => {
    genericModal.value = {
        show: true,
        title,
        message,
        confirmOnly,
        confirmLabel: labels.confirmLabel || '',
        cancelLabel: labels.cancelLabel || '',
        discardLabel: labels.discardLabel || '',
        resolve: () => {}
    }
    return new Promise<boolean>((resolve) => {
        genericModal.value.resolve = resolve
    })
}

const showAlert = (title: string, message: string) => promptConfirm(title, message, true)

const promptReview = (rawText: string): Promise<boolean> => {
    const parsed = parseAssessmentBlocks(rawText)
    const sanitized = sanitizeAssessmentDetails(rawText)
    const dupsRemoved = parsed.length - sanitized.blocks.length

    reviewModal.value = {
        show: true,
        blocks: sanitized.blocks,
        aggregatedState: sanitized.aggregatedState,
        sanitizedText: sanitized.text,
        duplicatesRemoved: dupsRemoved,
        resolve: () => {}
    }
    return new Promise<boolean>((resolve) => {
        reviewModal.value.resolve = resolve
    })
}

const handleReviewConfirm = () => {
    reviewModal.value.show = false
    reviewModal.value.resolve(true)
}

const handleReviewCancel = () => {
    reviewModal.value.show = false
    reviewModal.value.resolve(false)
}

const confirmApplyDraftBeforeLeave = async (): Promise<boolean> => {
    if (!hasUnsavedDraft.value) return true

    const actionLabel = isReviewer.value ? 'Save' : 'Submit'
    const shouldApply = await promptConfirm(
        'Unsaved assessment',
        `${actionLabel} this assessment before leaving? Discard closes without saving, while Stay keeps the local edits open.`,
        false,
        { confirmLabel: actionLabel, cancelLabel: 'Stay', discardLabel: 'Discard' },
    )
    if (!shouldApply) return false

    if (!hasUnsavedDraft.value) return true

    await handleUpdate(false)
    return !hasUnsavedDraft.value
}

const requestClose = async () => {
    if (await confirmApplyDraftBeforeLeave()) {
        emit('close')
    }
}

defineExpose({
    confirmApplyDraftBeforeLeave,
})

const discardUnsavedDraft = () => {
    teamDrafts.value.clear()
    formTouched.value = false
    rawDetailsTouched.value = false
    codeAnalysisDraftApplied.value = false
    codeAnalysisDraftSummary.value = ''
    codeAnalysisRunIds.value = []
    automaticFallbackTeams.value = new Set()
    isManualBaseMode.value = false
    assigneeInput.value = ''
    assigneeSuggestionsVisible.value = false
    showConflictModal.value = false
    updateFormFromGroup(true)
    rawDetails.value = mergedAssessmentData.value.fullText
}

const handleModalResponse = (value: boolean | 'discard') => {
    genericModal.value.show = false
    if (value === 'discard') {
        discardUnsavedDraft()
        genericModal.value.resolve(true)
        return
    }
    genericModal.value.resolve(value)
}

const isReviewer = computed(() => {
    return user?.value?.role === 'REVIEWER'
})

const dependencyInfo = useVulnDependencyInfo({
    group: computed(() => props.group),
    teamMapping,
    refreshCounter,
    teamFilter: computed(() => props.activeTeamFilter || ''),
})
const unscopedDependencyInfo = useVulnDependencyInfo({
    group: computed(() => props.group),
    teamMapping,
    refreshCounter,
})

const allInstances = dependencyInfo.allInstances
const visibleInstances = dependencyInfo.visibleInstances
const visibleInstanceSet = computed(() => new Set(visibleInstances.value))
const activeTeamScope = dependencyInfo.activeTeam
const getInstanceTeamKey = dependencyInfo.getInstanceTeamKey
const instanceTeams = dependencyInfo.instanceTeams
const effectiveTags = dependencyInfo.effectiveTags
const teamAliasGroups = computed(() => buildTeamAliasGroups(teamMapping?.value || {}))
const activeTeamScopeAliases = computed(() => activeTeamScope.value
    ? teamAliasGroups.value[activeTeamScope.value] || []
    : []
)

const totalTargeted = computed(() => {
    if (selectedTeam.value) {
        const selectedTeamKey = selectedTeam.value.toLocaleLowerCase()
        const matched = allInstances.value.filter((inst, index) => (
            instanceTeams.value.get(getInstanceTeamKey(inst, index)) || []
        ).some(team => team.toLocaleLowerCase() === selectedTeamKey)).length
        // Legacy findings can carry only the vulnerability-level team tag.
        // Keep their assessment workflow usable until a component mapping exists.
        return matched > 0 ? matched : allInstances.value.length
    }
    return allInstances.value.length
})

const displayState = computed(() => {
    return getGroupLifecycle(props.group, effectiveTags.value, teamMapping?.value)
})

const assessmentSyncIssues = computed(() => getGroupAssessmentSyncIssues(props.group, {
    lifecycle: displayState.value,
    requiredTeamsOrTags: effectiveTags.value,
    teamMapping: teamMapping?.value || {},
}))

const technicalState = computed(() => {
    return getGroupTechnicalState(props.group)
})

const isPendingReview = computed(() => {
    return isPendingReviewHelper(props.group)
})

const isAssessed = computed(() => {
    return (
        hasGlobalAssessment(mergedAssessmentData.value.blocks) && !isPendingReview.value
    ) || displayState.value === 'ASSESSED_LEGACY'
})

const assessedFoldClass = computed(() => {
    if (displayState.value === 'INCOMPLETE') return 'bg-green-600/30'
    if (displayState.value === 'ASSESSED_LEGACY') return 'bg-sky-600'
    return 'bg-green-600'
})

const assessedIconClass = computed(() => {
    if (displayState.value === 'INCOMPLETE') return 'text-white/40'
    return 'text-white'
})

const canApprove = computed(() => {
    return user?.value?.role === 'REVIEWER' && isPendingReview.value
})

const lastRescoredScore = ref<number | null>(null)

const stableRescoredScore = computed<number | null>(() => {
    return props.group.rescored_cvss ?? null
})

const hasStableRescore = computed(() => {
    const base = props.group.cvss ?? props.group.cvss_score
    const rescored = stableRescoredScore.value
    if (rescored == null || base == null) return false
    return Math.abs(rescored - base) > 0.05
})

const matchedProposal = computed<TMRescoreProposal | null>(() => {
    const proposals = tmrescoreProposals?.value || {}
    const candidateIds = [props.group.id, ...(props.group.aliases || [])]
    for (const candidateId of candidateIds) {
        const normalized = String(candidateId || '').trim().toUpperCase()
        if (normalized && proposals[normalized]) {
            const proposal = proposals[normalized]
            const rescoredVector = proposal?.rescored_vector || null
            const originalVector = proposal?.original_vector || props.group.cvss_vector || null
            if (rescoredVector && (!originalVector || rescoredVector !== originalVector)) {
                return proposal
            }
        }
    }
    return null
})

const proposalResponseText = (proposal: TMRescoreProposal): string[] => {
    const responses = proposal.analysis?.response || []
    if (!Array.isArray(responses)) return []
    return responses
        .map((entry: any) => typeof entry === 'string' ? entry : entry?.detail || entry?.title || '')
        .filter(Boolean)
}

const codeAnalysisGuidance = computed(() => {
    const proposal = matchedProposal.value
    if (!proposal) return ''
    const parts: string[] = [
        'TMRescore/vscorer guidance. Treat this as reviewer context and verify it against code evidence.',
    ]
    if (proposal.analysis?.detail) {
        parts.push(`TMRescore reasoning: ${proposal.analysis.detail}`)
    }
    if (proposal.analysis?.state) {
        parts.push(`Suggested analysis state: ${proposal.analysis.state}`)
    }
    if (proposal.analysis?.justification) {
        parts.push(`Suggested justification: ${proposal.analysis.justification}`)
    }
    const responses = proposalResponseText(proposal)
    if (responses.length) {
        parts.push(`Suggested response: ${responses.join('; ')}`)
    }
    if (proposal.original_score != null || proposal.rescored_score != null) {
        parts.push(`Score guidance: ${proposal.original_score ?? 'unknown'} -> ${proposal.rescored_score ?? 'unknown'}`)
    }
    if (proposal.original_vector || proposal.rescored_vector) {
        parts.push(`Vector guidance: ${proposal.original_vector || 'unknown'} -> ${proposal.rescored_vector || 'unknown'}`)
    }
    if (proposal.cwe_descriptions && Object.keys(proposal.cwe_descriptions).length) {
        parts.push(`CWE guidance: ${JSON.stringify(proposal.cwe_descriptions)}`)
    }
    if (proposal.affected_refs?.length) {
        parts.push(`Affected refs from TMRescore: ${proposal.affected_refs.slice(0, 12).join(', ')}`)
    }
    if (proposal.evaluations) {
        parts.push(`TMRescore evaluations: ${JSON.stringify(proposal.evaluations).slice(0, 1200)}`)
    }
    return parts.join('\n')
})

const cvssVectorEntries = computed(() => {
    const entries: { vector: string, label: string, theme: 'purple' | 'teal' | 'gray', adjusted?: boolean }[] = []
    const proposal = matchedProposal.value
    // Original/base — always first
    if (props.group.cvss_vector) {
        entries.push({
            vector: props.group.cvss_vector,
            label: 'Original',
            theme: 'gray',
        })
    }
    // Proposed
    if (proposal?.rescored_vector) {
        entries.push({
            vector: proposal.rescored_vector,
            label: 'Proposed',
            theme: 'teal',
            adjusted: !!proposal.rescored_vector_adjusted,
        })
    }
    // Rescored — use pendingVector if the user is editing, otherwise the saved rescored_vector
    const effectiveRescored = pendingVector.value || props.group.rescored_vector
    if (effectiveRescored && effectiveRescored !== props.group.cvss_vector) {
        const adjusted = pendingVector.value ? undefined : Boolean(props.group.rescored_vector_adjusted)
        entries.push({
            vector: effectiveRescored,
            label: 'Rescored',
            theme: 'purple',
            adjusted,
        })
    }
    const codeAnalysisVector = latestCodeAnalysisCvssAdjustment.value?.adjusted_vector
    if (codeAnalysisVector && codeAnalysisVector !== props.group.cvss_vector && !entries.some(entry => entry.vector === codeAnalysisVector)) {
        entries.push({
            vector: codeAnalysisVector,
            label: 'Analyzer',
            theme: 'purple',
        })
    }
    return entries
})

const codeAnalysisCvssComponentLabel = computed(() => {
    const values = latestCodeAnalysisCvssComponents.value
        .map(component => String(component || '').trim())
        .filter(Boolean)
    if (!values.length) return ''
    if (values.length <= 2) return values.join(', ')
    return `${values.slice(0, 2).join(', ')} +${values.length - 2}`
})

const hasCodeAnalysisCvssNotes = computed(() => Boolean(
    latestCodeAnalysisCvssAdjustment.value?.summary ||
    latestCodeAnalysisCvssAdjustment.value?.reasons?.length ||
    codeAnalysisCvssComponentLabel.value,
))

const copyId = () => {
    navigator.clipboard.writeText(props.group.id)
}

const applyProposal = async () => {
    const proposal = matchedProposal.value
    if (!proposal || !proposal.rescored_vector) return

    // A threat-model proposal is reviewer context for the global assessment,
    // not a synthetic team assessment. Stage it in the normal form and let the
    // reviewer persist it with the card's save action.
    selectedTeam.value = ''
    await nextTick()

    pendingVector.value = proposal.rescored_vector
    const score = calculateScoreFromVector(proposal.rescored_vector)
    if (score !== null) pendingScore.value = score

    setCvssInstanceFromVector(proposal.rescored_vector)

    // Populate the analysis details from the proposal reasoning
    const parts: string[] = []
    parts.push('[TMRescore Proposal Applied]')
    if (proposal.analysis?.detail) {
        parts.push(`Reasoning: ${proposal.analysis.detail}`)
    }
    if (proposal.analysis?.state) {
        parts.push(`Suggested state: ${proposal.analysis.state}`)
    }
    if (proposal.analysis?.justification) {
        parts.push(`Justification: ${proposal.analysis.justification}`)
    }
    if (proposal.analysis?.response?.length) {
        const responses = proposal.analysis.response
            .map((r: any) => typeof r === 'string' ? r : r.detail || r.title || '')
            .filter(Boolean)
        if (responses.length > 0) {
            parts.push(`Analysis: ${responses.join('; ')}`)
        }
    }
    if (proposal.rescored_vector) {
        parts.push(`Vector: ${proposal.rescored_vector}`)
    }
    if (score !== null) {
        parts.push(`Score: ${score}`)
    }
    details.value = parts.join('\n')

    formTouched.value = true
}

const handleCodeAnalysisResult = async (
    result: CodeAnalysisAssessResponse,
    components: string[],
    analysisRunIds: string[] = [],
    persistedTargetTeam?: string,
) => {
    const taggedComponents = [...triggeringTaggedComponents.value]
    if (persistedTargetTeam && components.length === 1 && !taggedComponents.some(component =>
        component.name.toLocaleLowerCase() === components[0].toLocaleLowerCase()
    )) {
        taggedComponents.push({
            name: components[0],
            versions: [],
            tag: persistedTargetTeam,
        })
    }
    const prepared = prepareCodeAnalysisResult(
        result,
        components,
        taggedComponents,
        currentAssigned.value,
    )

    if (!prepared.firstTeam || prepared.teamDrafts.length === 0) {
        await showAlert(
            'Team Ownership Required',
            'The analyzed component is not mapped to a team, so this result cannot be staged as an assessment draft.',
        )
        return
    }

    // Let the team watcher finish preserving/restoring the previous form
    // before installing the analyzer draft. Otherwise its queued update can
    // replace the newly populated fields after navigation.
    selectedTeam.value = prepared.firstTeam
    await nextTick()
    automaticFallbackTeams.value = new Set([
        ...automaticFallbackTeams.value,
        prepared.firstTeam.toLocaleLowerCase(),
    ])

    for (const draft of prepared.teamDrafts) {
        const existingDraft = teamDrafts.value.get(draft.team)
        teamDrafts.value.set(draft.team, {
            state: draft.state,
            details: draft.details,
            justification: draft.justification,
            assigned: draft.assigned,
            evidenceReviewed: existingDraft?.evidenceReviewed ?? false,
            versionCoverageChecked: existingDraft?.versionCoverageChecked ?? false,
            ticket: existingDraft?.ticket ?? '',
        })
    }
    stageCodeAnalysisGlobalReference()

    const selectedDraft = prepared.teamDrafts.find(draft => draft.team === prepared.firstTeam)
        || prepared.teamDrafts[0]
    state.value = selectedDraft.state
    justification.value = selectedDraft.justification
    details.value = selectedDraft.details
    currentAssigned.value = [...selectedDraft.assigned]

    if (prepared.adjustedVector) {
        pendingVector.value = prepared.adjustedVector
    }
    if (prepared.adjustedScore != null) {
        pendingScore.value = prepared.adjustedScore
    }
    applyRescoreRulesForState(prepared.targetState)

    formTouched.value = true
    codeAnalysisDraftApplied.value = true
    codeAnalysisDraftSummary.value = ''
    codeAnalysisRunIds.value = [...analysisRunIds]
    setDetailTab('review', true)
}

/**
 * Applies the configured rescore rules on top of an analyzer proposal.
 *
 * States with a configured transition (`NOT_AFFECTED`, `FALSE_POSITIVE`) must
 * end up with the vector the rules define, so the rules run explicitly instead
 * of relying on the state watcher, which is skipped when the state is unchanged.
 * `applyStateRescore` is a no-op for states without a rule, leaving the
 * analyzer's own vector in place.
 */
const applyRescoreRulesForState = (targetState: string) => {
    if (!isReviewer.value) return
    applyStateRescore(targetState)
}

const stageCodeAnalysisGlobalReference = (): AssessmentDraftState | null => {
    const assessments = new Map<string, CodeAnalysisTeamDraft>()
    for (const block of mergedAssessmentData.value.blocks) {
        if (block.team.toLocaleLowerCase() === 'general') continue
        assessments.set(block.team.toLocaleLowerCase(), {
            team: block.team,
            state: block.state,
            details: block.details || '',
            justification: block.justification || 'NOT_SET',
            assigned: block.assigned ? [...block.assigned] : [],
        })
    }
    for (const [team, draft] of teamDrafts.value.entries()) {
        if (team.toLocaleLowerCase() === 'general') continue
        assessments.set(team.toLocaleLowerCase(), { team, ...draft })
    }

    const generalDraftEntry = [...teamDrafts.value.entries()]
        .find(([team]) => team.toLocaleLowerCase() === 'general')
    const savedGeneral = mergedAssessmentData.value.blocks
        .find(block => block.team.toLocaleLowerCase() === 'general')
    const activeGlobal = !selectedTeam.value && formTouched.value
        ? {
            team: 'General',
            state: state.value,
            details: details.value,
            justification: justification.value,
            assigned: [...currentAssigned.value],
        }
        : null
    let existingGlobal: CodeAnalysisTeamDraft | null = null
    if (generalDraftEntry) {
        existingGlobal = { team: 'General', ...generalDraftEntry[1] }
    } else if (activeGlobal) {
        existingGlobal = activeGlobal
    } else if (savedGeneral) {
        existingGlobal = {
            team: 'General',
            state: savedGeneral.state,
            details: savedGeneral.details || '',
            justification: savedGeneral.justification || 'NOT_SET',
            assigned: savedGeneral.assigned ? [...savedGeneral.assigned] : [],
        }
    }
    const prepared = buildCodeAnalysisGlobalReferenceDraft([...assessments.values()], existingGlobal)
    if (!prepared) return null

    for (const team of [...teamDrafts.value.keys()]) {
        if (team.toLocaleLowerCase() === 'general') teamDrafts.value.delete(team)
    }
    const staged: AssessmentDraftState = {
        state: prepared.state,
        details: prepared.details,
        justification: prepared.justification,
        assigned: [...prepared.assigned],
        evidenceReviewed: generalDraftEntry?.[1].evidenceReviewed ?? (activeGlobal ? evidenceReviewed.value : savedGeneral?.evidenceReviewed) ?? false,
        versionCoverageChecked: generalDraftEntry?.[1].versionCoverageChecked ?? (activeGlobal ? versionCoverageChecked.value : savedGeneral?.versionCoverageChecked) ?? false,
        ticket: generalDraftEntry?.[1].ticket ?? (activeGlobal ? ticketReference.value : savedGeneral?.ticket) ?? '',
    }
    teamDrafts.value.set('General', staged)
    return staged
}

/**
 * Stages the latest analyzer results as fallbacks for teams that do not already
 * have a manual assessment. The reviewer draft then uses the worst effective
 * state across authoritative team assessments and those analyzer fallbacks.
 */
const handleApplyAllCodeAnalysisResults = async (runs: CodeAnalysisComponentRun[]) => {
    const activeTeamKey = activeTeamScope.value.toLocaleLowerCase()
    const scopedRuns = activeTeamKey
        ? runs.filter(run => triggeringTaggedComponents.value.some(component => (
            component.name.toLocaleLowerCase() === run.component.toLocaleLowerCase()
            && component.tag.toLocaleLowerCase() === activeTeamKey
        )))
        : runs
    const prepared = prepareCodeAnalysisResults(scopedRuns, triggeringTaggedComponents.value, currentAssigned.value)

    if (prepared.teamDrafts.length === 0) {
        await showAlert('No Team Assessments', 'None of the analyzed components is mapped to a team.')
        return
    }

    if (activeTeamScope.value) {
        const scopedDraft = prepared.teamDrafts.find(draft => draft.team.toLocaleLowerCase() === activeTeamKey)
        if (!scopedDraft) {
            await showAlert(
                'No Scoped Team Assessment',
                `None of the selected analysis results belongs to ${activeTeamScope.value}.`,
            )
            return
        }

        selectedTeam.value = scopedDraft.team
        await nextTick()
        automaticFallbackTeams.value = new Set([
            ...automaticFallbackTeams.value,
            scopedDraft.team.toLocaleLowerCase(),
        ])
        const existingDraft = teamDrafts.value.get(scopedDraft.team)
        teamDrafts.value.set(scopedDraft.team, {
            state: scopedDraft.state,
            details: scopedDraft.details,
            justification: scopedDraft.justification,
            assigned: scopedDraft.assigned,
            evidenceReviewed: existingDraft?.evidenceReviewed ?? false,
            versionCoverageChecked: existingDraft?.versionCoverageChecked ?? false,
            ticket: existingDraft?.ticket ?? '',
        })
        stageCodeAnalysisGlobalReference()
        state.value = scopedDraft.state
        justification.value = scopedDraft.justification
        details.value = scopedDraft.details
        currentAssigned.value = [...scopedDraft.assigned]
        formTouched.value = true
        codeAnalysisDraftApplied.value = true
        codeAnalysisRunIds.value = [...prepared.runIds]
        codeAnalysisDraftSummary.value = [
            `Applied ${scopedRuns.length} scoped analyzer assessment${scopedRuns.length === 1 ? '' : 's'}`,
            `to ${scopedDraft.team}.`,
            `Combined state: ${scopedDraft.state.replace(/_/g, ' ')}.`,
        ].join(' ')
        setDetailTab('review', true)
        return
    }

    // Switch to the global assessment first: the selectedTeam watcher persists the
    // current form into its own team draft, which would otherwise overwrite the
    // analyzer drafts written below.
    selectedTeam.value = ''
    await nextTick()

    const fallbackTeams: string[] = []
    const preservedTeams: string[] = []
    for (const draft of prepared.teamDrafts) {
        const existingDraft = teamDrafts.value.get(draft.team)
        const savedBlock = mergedAssessmentData.value.blocks.find(block => (
            block.team.toLocaleLowerCase() === draft.team.toLocaleLowerCase()
        ))
        const hasTeamAssessment = Boolean(
            (existingDraft?.state && existingDraft.state !== 'NOT_SET')
            || (savedBlock?.state && savedBlock.state !== 'NOT_SET'),
        )
        if (hasTeamAssessment) {
            preservedTeams.push(draft.team)
            continue
        }
        teamDrafts.value.set(draft.team, {
            state: draft.state,
            details: draft.details,
            justification: draft.justification,
            assigned: draft.assigned,
            evidenceReviewed: existingDraft?.evidenceReviewed ?? false,
            versionCoverageChecked: existingDraft?.versionCoverageChecked ?? false,
            ticket: existingDraft?.ticket ?? '',
        })
        fallbackTeams.push(draft.team)
    }
    automaticFallbackTeams.value = new Set([
        ...automaticFallbackTeams.value,
        ...fallbackTeams.map(team => team.toLocaleLowerCase()),
    ])

    const unmappedRuns = scopedRuns.filter(run => !triggeringTaggedComponents.value.some(component => (
        component.name.toLocaleLowerCase() === run.component.toLocaleLowerCase()
        && Boolean(component.tag.trim())
    )))
    const unmappedPrepared = prepareCodeAnalysisResults(unmappedRuns, triggeringTaggedComponents.value, currentAssigned.value)
    const globalReference = stageCodeAnalysisGlobalReference()
    const effectiveWorst = [
        globalReference && {
            state: globalReference.state,
            justification: globalReference.justification,
        },
        ...(unmappedRuns.length ? [{
            state: unmappedPrepared.globalState,
            justification: unmappedPrepared.globalJustification,
        }] : []),
    ]
        .filter((assessment): assessment is { state: string, justification: string } => Boolean(assessment?.state && assessment.state !== 'NOT_SET'))
        .sort((left, right) => (STATE_PRIORITY[left.state] ?? 10) - (STATE_PRIORITY[right.state] ?? 10))[0]
    if (globalReference) {
        globalReference.state = effectiveWorst?.state || prepared.globalState
        globalReference.justification = effectiveWorst?.justification || prepared.globalJustification
        teamDrafts.value.set('General', globalReference)
        state.value = globalReference.state
        justification.value = globalReference.justification
        details.value = globalReference.details
    }
    formTouched.value = true

    if (globalReference && prepared.adjustedVector) {
        // The pendingVector watcher recalculates the score from the vector.
        pendingVector.value = prepared.adjustedVector
        setCvssInstanceFromVector(prepared.adjustedVector)
    }
    if (globalReference && prepared.adjustedScore != null) {
        pendingScore.value = prepared.adjustedScore
    }
    // The configured rules own the vector for the states they cover, so they run
    // after the analyzer proposal and on top of it.
    if (globalReference) applyRescoreRulesForState(state.value)

    codeAnalysisDraftApplied.value = true
    codeAnalysisRunIds.value = [...prepared.runIds]
    codeAnalysisDraftSummary.value = [
        `Applied ${runs.length} analyzer assessment${runs.length === 1 ? '' : 's'}`,
        `to ${fallbackTeams.length} team${fallbackTeams.length === 1 ? '' : 's'}`,
        fallbackTeams.length ? `(${fallbackTeams.join(', ')}).` : '',
        fallbackTeams.length ? 'Analyzer proposals fill only teams without a saved assessment.' : '',
        preservedTeams.length ? `Preserved saved team assessments for ${preservedTeams.join(', ')}.` : '',
        globalReference
            ? `The global assessment references those team blocks and uses the effective worst result: ${state.value.replace(/_/g, ' ')}.`
            : 'The existing global assessment was preserved.',
        ...(prepared.unmappedComponents.length
            ? [`No team is mapped for ${prepared.unmappedComponents.join(', ')}.`]
            : []),
    ].join(' ')
    setDetailTab('review', true)
}

const handleCodeAnalysisResultChange = (result: CodeAnalysisAssessResponse | null, components: string[]) => {
    latestCodeAnalysisCvssAdjustment.value = result?.assessment.adjusted_cvss ?? null
    latestCodeAnalysisCvssComponents.value = result?.assessment.adjusted_cvss ? components : []
}

const handleCodeAnalysisProposalsChange = (runs: CodeAnalysisComponentRun[]) => {
    codeAnalysisProposalRuns.value = runs
}

const applySelectedAutomaticProposal = () => {
    const proposal = selectedAutomaticProposal.value
    const team = selectedTeam.value
    if (!proposal || !team) return

    const existingDraft = teamDrafts.value.get(team)
    teamDrafts.value.set(team, {
        state: proposal.state,
        justification: proposal.justification,
        details: proposal.details,
        assigned: existingDraft?.assigned || [...currentAssigned.value],
        evidenceReviewed: existingDraft?.evidenceReviewed ?? evidenceReviewed.value,
        versionCoverageChecked: existingDraft?.versionCoverageChecked ?? versionCoverageChecked.value,
        ticket: existingDraft?.ticket ?? ticketReference.value,
    })
    stageCodeAnalysisGlobalReference()
    state.value = proposal.state
    justification.value = proposal.justification
    details.value = proposal.details
    formTouched.value = true
    codeAnalysisDraftApplied.value = true
    codeAnalysisRunIds.value = selectedAutomaticProposalRuns.value
        .map(run => run.runId)
        .filter((runId): runId is string => Boolean(runId))
    automaticFallbackTeams.value = new Set([
        ...automaticFallbackTeams.value,
        team.toLocaleLowerCase(),
    ])
    codeAnalysisDraftSummary.value = `Analyzer proposal selected for ${team}. Review it before saving or submitting.`
}

const markSelectedTeamAssessmentManual = () => {
    const teamKey = selectedTeam.value.toLocaleLowerCase()
    if (!teamKey || !automaticFallbackTeams.value.has(teamKey)) return
    const next = new Set(automaticFallbackTeams.value)
    next.delete(teamKey)
    automaticFallbackTeams.value = next
}

const applyEffectiveAssessmentSummary = async () => {
    const worst = effectiveAssessmentWorst.value
    if (!isReviewer.value || !worst) return

    const reference = buildCodeAnalysisGlobalReferenceDraft(effectiveTeamAssessments.value
        .filter(assessment => assessment.state !== 'NOT_SET')
        .map(assessment => ({
            team: assessment.team,
            state: assessment.state,
            justification: assessment.justification,
            details: assessment.details,
            assigned: [],
        })))
    if (!reference) return

    selectedTeam.value = ''
    await nextTick()
    state.value = reference.state
    justification.value = reference.justification
    details.value = reference.details
    formTouched.value = true
    applyRescoreRulesForState(reference.state)
}

const currentDisplayScore = computed(() => {
    if (pendingScore.value !== null) return pendingScore.value
    return props.group.rescored_cvss ?? (props.group.cvss || props.group.cvss_score) ?? 'N/A'
})

const isRescoredOrModified = computed(() => {
    const base = props.group.cvss || props.group.cvss_score
    const current = currentDisplayScore.value
    if (current === 'N/A' || base === undefined) return false
    return Math.abs(Number(current) - Number(base)) > 0.05
})

const approveAssessment = async (e: Event) => {
    e.stopPropagation() // Prevent card expansion
    if (!await promptConfirm('Approve Assessment', 'Approve this assessment? This will remove the pending status.')) return

    // Get current details from first instance (assuming grouped logic holds)
    const first = allInstances.value[0]
    if (!first) return

    // We update using the existing handleUpdate but need to make sure state is set correctly first
    // Since details.value is reactive, handleUpdate will pick it up
    updating.value = true
    try {
        await handleUpdate(true, true) // force=true, isApprove=true
    } finally {
        updating.value = false
    }
}



watch([showCalculatorModal, pendingVector], () => {
    if (showCalculatorModal.value) {
        let v = pendingVector.value?.trim() || ''
        try {
            if (v.startsWith('CVSS:4.0')) {
                activeVersion.value = '4.0'
                cvssInstance.value = new Cvss4P0(v)
            } else if (v.startsWith('CVSS:3.0')) {
                activeVersion.value = '3.0'
                cvssInstance.value = new Cvss3P0(v)
            } else if (v.startsWith('CVSS:3.')) {
                activeVersion.value = '3.1'
                cvssInstance.value = new Cvss3P1(v)
            } else if (v.startsWith('CVSS:2.0') || (v.includes('/') && !v.startsWith('CVSS:'))) {
                activeVersion.value = '2.0'
                cvssInstance.value = new Cvss2(v)
            } else {
                activeVersion.value = '3.1'
                cvssInstance.value = new Cvss3P1()
            }
        } catch {
             const fallback = visibleVersions.value[0] || '3.1'
             activeVersion.value = fallback as any
             resetToDefault(fallback)
        }
    }
})

const visibleVersions = computed<Array<'4.0' | '3.1' | '3.0' | '2.0'>>(() => {
    const v = pendingVector.value || ''
    if (v.startsWith('CVSS:4.0')) return ['4.0']
    if (v.startsWith('CVSS:3.1')) return ['3.1']
    if (v.startsWith('CVSS:3.0')) return ['3.0']
    if (v.startsWith('CVSS:2.0') || (v.includes('/') && !v.startsWith('CVSS:'))) return ['2.0']
    return ['4.0', '3.1', '3.0', '2.0']
})

const switchVersion = (ver: '4.0' | '3.1' | '3.0' | '2.0') => {
    activeVersion.value = ver
    resetToDefault(ver)
}

const resetToDefault = (ver: string) => {
    switch(ver) {
        case '4.0': cvssInstance.value = new Cvss4P0('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'); break;
        case '3.1': cvssInstance.value = new Cvss3P1('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'); break;
        case '3.0': cvssInstance.value = new Cvss3P0('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'); break;
        case '2.0': cvssInstance.value = new Cvss2('AV:N/AC:L/Au:N/C:N/I:N/A:N'); break;
    }
    updateVectorString()
}

const normalizeRescoredVector = () => {
    if (!cvssInstance.value) return
    pendingVector.value = normalizeCvssVectorInstance(
        cvssInstance.value,
        rescoreRules?.value?.metric_rules?.[activeVersion.value],
    )
}

const setCvssInstanceFromVector = (vector: string) => {
    if (!vector) return

    let v = vector.trim()
    try {
        if (v.startsWith('CVSS:4.0')) {
            cvssInstance.value = new Cvss4P0(v)
        } else if (v.startsWith('CVSS:3.0')) {
            cvssInstance.value = new Cvss3P0(v)
        } else if (v.startsWith('CVSS:3.1')) {
            cvssInstance.value = new Cvss3P1(v)
        } else if (v.startsWith('CVSS:2.0') || (v.includes('/') && !v.startsWith('CVSS:'))) {
            cvssInstance.value = new Cvss2(v)
        } else {
            // default to 3.1 fallback when version is missing
            cvssInstance.value = new Cvss3P1(v)
            activeVersion.value = '3.1'
        }
    } catch (e) {
        console.error('Failed to parse vector for instance set:', e)
    }
}

const updateVectorString = () => {
    if (!cvssInstance.value) return
    const raw = cvssInstance.value.toString()
    pendingVector.value = raw.split('/').filter((part: string) => !part.endsWith(':X')).join('/')
}

const cleanRescoredVector = () => {
    try {
        if (!pendingVector.value) return

        setCvssInstanceFromVector(pendingVector.value)
        normalizeRescoredVector()
        updateVectorString()

        const score = calculateScoreFromVector(pendingVector.value)
        if (score !== null) pendingScore.value = score
    } catch (e) {
        console.error('Failed to clean rescored vector:', e)
    }
}

const updateCalcVector = (componentShortName: string, value: string) => {
    try {
        cvssInstance.value.applyComponentString(componentShortName, value)
        updateVectorString()
    } catch (e) {
        console.error(e)
    }
}

const canEditBase = computed(() => {
    if (!isReviewer.value) return false

    // If a rescore rule matches the current state, we don't allow manual editing
    // unless the user explicitly cleared/reset it.
    const rules = rescoreRules?.value?.transitions || []
    const hasRuleMatch = rules.some((r: any) => {
        const triggerState = r?.trigger?.state ?? r?.from
        return triggerState === state.value
    })

    if (hasRuleMatch && !isManualBaseMode.value) return false

    // Explicitly unlocked via Clear
    if (isManualBaseMode.value) return true

    // Otherwise, stay read-only
    return false
})

const resetVector = () => {
    isManualBaseMode.value = false
    // Reset to the ORIGINAL baseline from Dependency-Track
    const original = props.group.cvss_vector
    if (original) {
        pendingVector.value = original
        try {
             if (original.startsWith('CVSS:4.0')) {
                 activeVersion.value = '4.0'
                 cvssInstance.value = new Cvss4P0(original)
             } else if (original.includes('3.0')) {
                  activeVersion.value = '3.0'
                  cvssInstance.value = new Cvss3P0(original)
             } else if (original.startsWith('CVSS:3.')) {
                  activeVersion.value = '3.1'
                  cvssInstance.value = new Cvss3P1(original)
             } else {
                 activeVersion.value = '2.0'
                 cvssInstance.value = new Cvss2(original)
             }
        } catch {}
        updateVectorString()
    } else {
        resetToDefault(activeVersion.value)
    }
}

const clearVector = () => {
    isManualBaseMode.value = true
    resetToDefault(activeVersion.value)
    pendingVector.value = ''
}

watch(pendingVector, (newVector) => {
    const score = calculateScoreFromVector(newVector)
    if (score !== null) {
        isDerivedCvssScoreUpdate.value = true
        try {
            pendingScore.value = score
        } finally {
            isDerivedCvssScoreUpdate.value = false
        }
    }
})

watch(pendingVector, (newVector, oldVector) => {
    if (!isInternalUpdate.value && newVector !== oldVector) {
        formTouched.value = true
    }
}, { flush: 'sync' })

watch(pendingScore, (newScore, oldScore) => {
    if (!isInternalUpdate.value && !isDerivedCvssScoreUpdate.value && newScore !== oldScore) {
        formTouched.value = true
    }
}, { flush: 'sync' })

const mergedAssessmentData = computed(() => {
    return buildMergedAssessmentData(allInstances.value, refreshCounter.value)
})

// [Persistence Debug] Watch state and details for changes
watch(state, (val, old) => {
    if (!isInternalUpdate.value && val !== old) {
        formTouched.value = true
        if (isDebugPersistenceEnabled()) {
            console.log('[Persistence Debug] state touched by user:', val);
        }
    }
}, { flush: 'sync' })
watch(details, (val, old) => {
    if (!isInternalUpdate.value && val !== old) {
        formTouched.value = true
        if (isDebugPersistenceEnabled()) {
            console.log('[Persistence Debug] details touched by user:', val.slice(0, 50) + '...');
        }
    }
}, { flush: 'sync' })

const appendUniqueComments = (targetComments: any[], sourceComments: any[]) => {
    for (const comment of sourceComments || []) {
        const isDuplicate = targetComments.some(existingComment => (
            existingComment.comment === comment.comment &&
            existingComment.timestamp === comment.timestamp
        ))
        if (!isDuplicate) {
            targetComments.push(comment)
        }
    }
}

const groupedAssessments = computed(() => {
    const groups = {} as Record<string, {
        state: string,
        details: string,
        isSuppressed: boolean,
        comments: any[],
        instances: {
            project_name: string,
            project_version: string,
            component_name: string,
            component_version: string,
            component_uuid: string,
            project_uuid: string,
            is_direct_dependency?: boolean | null,
            dependency_chains?: string[]
        }[]
    }>

    ((props.group && props.group.affected_versions) || []).forEach(v => {
        ((v && v.components) || []).forEach(c => {
            if (!visibleInstanceSet.value.has(c)) return
            const stateVal = (c && c.analysis_state) || 'NOT_SET'
            const detailsVal = c.analysis_details || ''
            const suppressedVal = !!c.is_suppressed

            // Group by state, details, and suppression — different details get separate boxes
            const key = `${stateVal}|${detailsVal}|${suppressedVal}`

            if (!Object.hasOwn(groups, key)) {
                groups[key] = {
                    state: stateVal,
                    details: detailsVal,
                    isSuppressed: suppressedVal,
                    comments: [],
                    instances: []
                }
            }

            const groupItem = groups[key];
            appendUniqueComments(groupItem.comments, c.analysis_comments || [])

            groupItem.instances.push({
                project_name: v.project_name || '',
                project_version: v.project_version || '',
                component_name: c.component_name,
                component_version: c.component_version,
                component_uuid: c.component_uuid,
                project_uuid: v.project_uuid,
                is_direct_dependency: c.is_direct_dependency ?? null,
                dependency_chains: c.dependency_chains || []
            })
        })
    })

    return Object.values(groups)
})


const updateFormFromGroup = (force = true) => {
    // If not forced and user has touched the form, don't overwrite
    if (!force && formTouched.value) {
        if (isDebugPersistenceEnabled()) {
            console.log('[Persistence Debug] updateFormFromGroup blocked by formTouched');
        }
        return
    }

    isInternalUpdate.value = true
    try {
        pendingScore.value = props.group.rescored_cvss ?? props.group.cvss_score ?? props.group.cvss ?? null
        pendingVector.value = props.group.rescored_vector || props.group.cvss_vector || ''
        // Keep activeVersion in sync with the actual vector version
        const pv = pendingVector.value
        if (pv.startsWith('CVSS:4.0')) activeVersion.value = '4.0'
        else if (pv.startsWith('CVSS:3.0')) activeVersion.value = '3.0'
        else if (pv.startsWith('CVSS:3.')) activeVersion.value = '3.1'
        else if (pv.startsWith('CVSS:2.0') || (pv.includes('/') && !pv.startsWith('CVSS:'))) activeVersion.value = '2.0'

        const formValues = resolveAssessmentFormValues({
            selectedTeam: selectedTeam.value,
            isReviewer: isReviewer.value,
            teamBlocks: mergedAssessmentData.value.blocks,
            instances: allInstances.value,
        })

        state.value = formValues.state
        details.value = formValues.details
        justification.value = formValues.justification

        // Initialize assigned users from the current team block
        const teamKey = selectedTeam.value || 'General'
        const assignedBlock = mergedAssessmentData.value.blocks.find(b => b.team === teamKey)
        currentAssigned.value = assignedBlock?.assigned ? [...assignedBlock.assigned] : []
        evidenceReviewed.value = Boolean(assignedBlock?.evidenceReviewed)
        versionCoverageChecked.value = Boolean(assignedBlock?.versionCoverageChecked)
        ticketReference.value = assignedBlock?.ticket || ''

        const firstSuppressed = allInstances.value.find(i => i.is_suppressed)
        suppressed.value = Boolean(firstSuppressed)

        // Set initial values for "touched" check
        initialVector.value = pendingVector.value
        initialScore.value = pendingScore.value

        // Restore draft if one exists for this team
        const draftKey = selectedTeam.value || 'General'
        const draft = teamDrafts.value.get(draftKey)
        if (draft) {
            state.value = draft.state
            details.value = draft.details
            justification.value = draft.justification
            currentAssigned.value = [...draft.assigned]
            evidenceReviewed.value = draft.evidenceReviewed
            versionCoverageChecked.value = draft.versionCoverageChecked
            ticketReference.value = draft.ticket
            formTouched.value = true
        } else if (force) {
            formTouched.value = false
        }
    } finally {
        isInternalUpdate.value = false
    }
}

const syncAllAssessments = () => {
    if (displayState.value !== 'INCOMPLETE') return

    const allBlocks = mergedAssessmentData.value.blocks

    if (allBlocks.length === 0) {
        showAlert('No Analysis Data', 'No assessments found to pull from.')
        return
    }

    const { dtStates, dtJustification } = resolveDependencyTrackConsensusInput(allInstances.value)

    const syncDraft = getAssessmentSyncDraft(allBlocks, dtStates, dtJustification)
    state.value = syncDraft.state
    justification.value = syncDraft.justification
    details.value = syncDraft.details

    // Always trigger a rescore for the resolved state, even if state.value
    // didn't change (the watcher's newState !== oldState guard would skip it).
    if (isReviewer.value) {
        applyStateRescore(syncDraft.state)
    }
}

const handleApplyAllAssessment = async (assessmentDetails: string, assessmentState: string, assessmentJustification: string) => {
    // Always apply to global assessment regardless of current team selection.
    // Must await nextTick so the selectedTeam watcher (updateFormFromGroup) runs
    // before we set the form values — otherwise it overwrites them.
    selectedTeam.value = ''
    await nextTick()

    // Parse the full structured text and extract only the General block's details.
    const blocks = parseAssessmentBlocks(assessmentDetails)
    const generalBlock = blocks.find(b => b.team === 'General')
    if (generalBlock) {
        details.value = stripPendingReviewStatus(generalBlock.details || '').trim()
        state.value = generalBlock.state || assessmentState || 'NOT_SET'
        justification.value = generalBlock.justification || assessmentJustification || 'NOT_SET'
    } else {
        details.value = cleanStructuredAssessmentDetails(assessmentDetails)
        state.value = assessmentState || 'NOT_SET'
        justification.value = assessmentJustification || 'NOT_SET'
    }
    formTouched.value = true

    // Explicitly trigger rescore — the watch(state) guard may skip it when
    // the state value hasn't changed (same pattern as syncAllAssessments).
    if (isReviewer.value) {
        applyStateRescore(state.value)
    }
}

const toggleRawEdit = () => {
    showRawEdit.value = !showRawEdit.value
    rawDetailsTouched.value = false
    if (showRawEdit.value) {
        rawDetails.value = mergedAssessmentData.value.fullText
    }
}

const handleAdoptTeamBlock = async (block: AssessmentBlock) => {
    // Always apply to global assessment regardless of current team selection.
    // Must await nextTick so the selectedTeam watcher (updateFormFromGroup) runs
    // before we set the form values — otherwise it overwrites them.
    selectedTeam.value = ''
    await nextTick()

    // Adopt the team block's assessment into the global form fields.
    // Only copy the team's details text (not a full structured document).
    state.value = block.state || 'NOT_SET'
    justification.value = block.justification || 'NOT_SET'
    details.value = stripPendingReviewStatus(block.details || '').trim()
    formTouched.value = true

    // Same as syncAllAssessments: the adopted state owns the rescore even
    // when the global assessment already carried it.
    applyRescoreRulesForState(state.value)
}

watch(selectedTeam, (_newTeam, oldTeam) => {
    assessmentTicketCopyState.value = 'idle'
    // Persist current tab's form edits before switching away
    if (oldTeam !== undefined && formTouched.value) {
        const draftKey = oldTeam || 'General'
        teamDrafts.value.set(draftKey, {
            state: state.value,
            details: details.value,
            justification: justification.value,
            assigned: [...currentAssigned.value],
            evidenceReviewed: evidenceReviewed.value,
            versionCoverageChecked: versionCoverageChecked.value,
            ticket: ticketReference.value,
        })
    }
    updateFormFromGroup()
})

watch(() => props.group, () => {
    assessmentSubmitted.value = false
    updateFormFromGroup(true)
}, { immediate: true })

watch(formTouched, (touched) => {
    if (touched) assessmentSubmitted.value = false
    if (
        !touched
        && activeDetailTab.value === 'review'
        && activeTeamScope.value
        && !showAllAssessmentTeams.value
        && scopedAssessmentTeam.value
    ) {
        selectedTeam.value = scopedAssessmentTeam.value
    }
})

// Keep raw details in sync with the merged assessment data when not manually edited
watch(() => mergedAssessmentData.value.fullText, (newText) => {
    if (showRawEdit.value && !rawDetailsTouched.value) {
        rawDetails.value = newText
    }
})


watch(expanded, (isOpen) => {
    emit('toggle-expand', props.group.id, isOpen)

    if (isOpen) {
        activeDetailTab.value = 'overview'
        const shouldLockAfterScroll = openCardCount === 0
        openCardCount += 1
        refreshDetails()
        nextTick(() => {
            // Measure header for badge height
            if (headerEl.value) {
                headerHeight.value = headerEl.value.offsetHeight
            }
            // Position the card header below the sticky app header.
            nextTick(() => {
                alignHeaderBelowStickyTop()
                nextTick(() => {
                    updateExpandedDetailsMaxHeight()
                })
                if (shouldLockAfterScroll) {
                    // Lock at the final aligned position so the opened card stays fully readable.
                    lockBodyScroll()
                }
            })
        })
    } else {
        if (openCardCount > 0) {
            openCardCount -= 1
        }
        if (openCardCount === 0) {
            unlockBodyScroll()
        }
    }
})
/**
 * Applies the configured rescore rules for a given state.
 * Extracted so it can be triggered explicitly (e.g. from syncAllAssessments)
 * without relying solely on the watch(state) guard.
 */
const applyStateRescore = (targetState: string) => {
    const rules = rescoreRules?.value?.transitions || []
    const result = buildRescoredVectorForState({
        rules,
        metricRules: rescoreRules?.value?.metric_rules,
        targetState,
        currentVector: pendingVector.value,
        baseVector: props.group.cvss_vector || '',
        fallbackVersion: activeVersion.value,
    })

    if (!result) return

    activeVersion.value = result.version
    pendingVector.value = result.vector
    setCvssInstanceFromVector(result.vector)
}

const rescoreRuleSyncPreview = computed(() => buildRescoredVectorForState({
    rules: rescoreRules?.value?.transitions || [],
    metricRules: rescoreRules?.value?.metric_rules,
    targetState: state.value,
    currentVector: pendingVector.value,
    baseVector: props.group.cvss_vector || '',
    fallbackVersion: activeVersion.value,
}))

const rescoreRulesOutOfSync = computed(() => Boolean(
    rescoreRuleSyncPreview.value &&
    rescoreRuleSyncPreview.value.vector !== pendingVector.value.trim(),
))

const syncRescoreRules = () => {
    applyStateRescore(state.value)
    formTouched.value = true
}

watch(state, (newState, oldState) => {
    // Only auto-rescore if we're changing states via user interaction.
    // We check `loadingDetails` to avoid rescoring during the initial data load.
    // Note: syncAllAssessments calls applyStateRescore() directly to
    // bypass the newState !== oldState guard when syncing.
    if (!loadingDetails.value && !updating.value && newState !== oldState && isReviewer.value) {
        applyStateRescore(newState)
    }
})

const refreshDetails = async () => {
    loadingDetails.value = true
    try {
        const instances = allInstances.value
        // Only fetch if we have instances
        if (instances.length === 0) return

        const detailsList = await getAssessmentDetails(instances)

        if (!detailsList) {
            console.error('Failed to fetch assessment details: getAssessmentDetails returned undefined')
            return
        }

        // Update local state and originalAnalysis map
        const newOriginals: Record<string, any> = {}

        for (const item of detailsList) {
             if (item.error) {
                 console.error(`Error fetching details for ${item.finding_uuid}:`, item.error)
                 await showAlert('Update Failed', `Failed to refresh details for a component: ${item.error}`)
                 continue
             }

             if (item.analysis) {
                 // Store original for conflict checking
                 if (item.finding_uuid) {
                     newOriginals[item.finding_uuid] = item.analysis
                 }

                 // Update the reactive object in the group
                 const targetProj = item.project_uuid
                 const targetComp = item.component_uuid
                 const targetVuln = item.vulnerability_uuid

                 props.group.affected_versions.forEach(v => {
                     if (v.project_uuid !== targetProj) return

                     v.components.forEach(c => {
                         if (c.component_uuid === targetComp && c.vulnerability_uuid === targetVuln) {
                             c.analysis_state = item.analysis.analysisState || item.analysis.analysis_state
                             c.analysis_details = item.analysis.analysisDetails || item.analysis.analysis_details
                             c.is_suppressed = item.analysis.isSuppressed || item.analysis.is_suppressed
                             c.justification = item.analysis.analysisJustification || item.analysis.justification || parseJustificationFromText(item.analysis.analysisDetails || item.analysis.analysis_details || '') || 'NOT_SET'
                             c.dtvp_revision = item.analysis.dtvpRevision ?? item.analysis.dtvp_revision
                             c.dtvp_sync_status = item.analysis.dtvpSyncStatus || item.analysis.dtvp_sync_status
                             c.dtvp_update_id = item.analysis.dtvpUpdateId || item.analysis.dtvp_update_id
                             c.dtvp_sync_error = item.analysis.dtvpSyncError || item.analysis.dtvp_sync_error
                             const comments = item.analysis.analysisComments || item.analysis.analysis_comments
                             if (comments) {
                                  c.analysis_comments = comments
                             }
                         }
                     })
                 })
             }
        }

        originalAnalysis.value = { ...originalAnalysis.value, ...newOriginals }

        // Refresh local form state from the first instance's new data
        updateFormFromGroup(false)

        // Mark these as initial for "touched" check
        initialVector.value = pendingVector.value
        initialScore.value = pendingScore.value

    } catch (e) {
        console.error("Failed to refresh details", e)
    } finally {
        loadingDetails.value = false
        refreshCounter.value++
        updateFormFromGroup(false)
    }
}


const handleUpdate = async (force: boolean = false, isApprove: boolean = false) => {
    if (!isReviewer.value && assessmentMissingFields.value.length > 0) {
        setDetailTab('review', true)
        await showAlert(
            'Assessment Incomplete',
            `Complete ${assessmentMissingFields.value.join(', ')} before submitting for review.`,
        )
        return
    }

    if (isDebugPersistenceEnabled()) {
        console.log('[Persistence Debug] handleUpdate started', {
            force,
            isApprove,
            selectedTeam: selectedTeam.value,
            currentState: state.value,
            currentDetails: details.value,
            formTouched: formTouched.value
        });
    }

    updating.value = true
    try {
        const currentUser = user.value?.username || 'unknown'
        const preparedSubmission = prepareAssessmentSubmission({
            allInstances: allInstances.value,
            originalAnalysis: originalAnalysis.value,
            selectedTeam: selectedTeam.value,
            state: state.value,
            details: details.value,
            justification: justification.value,
            currentAssigned: currentAssigned.value,
            evidenceReviewed: evidenceReviewed.value,
            versionCoverageChecked: versionCoverageChecked.value,
            ticket: ticketReference.value,
            teamDrafts: teamDrafts.value,
            isReviewer: isReviewer.value,
            pendingVector: pendingVector.value,
            pendingScore: pendingScore.value,
            initialVector: initialVector.value,
            initialScore: initialScore.value,
            originalVector: props.group.cvss_vector || '',
            originalScore: props.group.cvss_score ?? props.group.cvss ?? null,
            currentUser,
            isApprove,
            showRawEdit: showRawEdit.value,
            rawDetailsTouched: rawDetailsTouched.value,
            rawDetails: rawDetails.value,
            mergedAssessmentFullText: mergedAssessmentData.value.fullText,
            suppressed: suppressed.value,
            force,
        })
        const targetTeam = preparedSubmission.targetTeam
        teamDrafts.value = preparedSubmission.nextDrafts

        if (isDebugPersistenceEnabled()) {
            console.log('[Persistence Debug] handleUpdate merging details', {
                targetTeam,
                state: state.value,
                details: details.value,
                teamDraftsCount: teamDrafts.value.size,
                teamDraftKeys: [...teamDrafts.value.keys()]
            });
        }

        if (!targetTeam && !isReviewer.value) {
             await showAlert('Input Required', "Please select a team to assess.")
             return
        }
        const finalState = preparedSubmission.finalState

        if (!await confirmAssessmentReview(force, preparedSubmission.reviewText)) {
            return
        }

        const finalText = preparedSubmission.finalText
        const payload: AssessmentPayload = {
            ...preparedSubmission.payload,
            details: finalText,
            state: finalState,
            analysis_run_ids: [...codeAnalysisRunIds.value],
        }

        const results = await updateAssessment(payload)

        await handleAssessmentUpdateResults(results, finalState, finalText)
    } catch (err: any) {
        await handleAssessmentUpdateError(err)
    } finally {
        updating.value = false
    }
}

const handleUseServerState = () => {
    // Refresh details to get latest server state (which we technically have in conflictData but refresh is safer/simpler)
    refreshDetails()
    showConflictModal.value = false
}

const buildUpdatedGroup = (): GroupedVuln => {
    const affectedVersions = props.group.affected_versions.map(version => ({
        ...version,
        components: version.components.map(component => ({ ...component })),
    }))

    const derivedTags = getDerivedGroupTags(
        affectedVersions.flatMap(version => version.components),
        teamMapping?.value || {},
    )

    return {
        ...props.group,
        affected_versions: affectedVersions,
        tags: derivedTags,
    }
}

const handleMappingUpdated = async () => {
    await refreshDetails()
    emit('update', buildUpdatedGroup())
}

const originalSeverity = computed(() => {
    const base = props.group.cvss ?? props.group.cvss_score
    if (base != null && !Number.isNaN(Number(base))) return scoreSeverity(Number(base))
    return props.group.severity || 'UNKNOWN'
})

const scoreSeverity = (score: number): string => {
    if (score >= 9) return 'CRITICAL'
    if (score >= 7) return 'HIGH'
    if (score >= 4) return 'MEDIUM'
    if (score >= 0.1) return 'LOW'
    return 'INFO'
}

const rescoredSeverity = computed(() => {
    // Use stable group data first, then fall back to pending edits
    if (hasStableRescore.value) {
        return scoreSeverity(stableRescoredScore.value!)
    }
    if (!isRescoredOrModified.value) return null
    const score = Number(currentDisplayScore.value)
    if (Number.isNaN(score)) return null
    return scoreSeverity(score)
})

const hexToRgba = (hex: string, alpha: number) => {
    const cleaned = hex.replace('#', '').trim()
    const normalized = cleaned.length === 3
        ? cleaned.split('').map((char) => char + char).join('')
        : cleaned
    if (normalized.length !== 6) return hex

    const r = Number.parseInt(normalized.slice(0, 2), 16)
    const g = Number.parseInt(normalized.slice(2, 4), 16)
    const b = Number.parseInt(normalized.slice(4, 6), 16)
    return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

const severityHexMap: Record<string, string> = {
    'CRITICAL': '#dc2626', 'HIGH': '#ea580c', 'MEDIUM': '#ca8a04',
    'LOW': '#16a34a', 'INFO': '#2563eb', 'UNKNOWN': '#4b5563'
}
const severityHex = computed(() => severityHexMap[originalSeverity.value] ?? '#4b5563')
const originalSeverityFill = computed(() => hexToRgba(severityHex.value, 0.4))
const rescoredSeverityHex = computed(() => {
    if (!rescoredSeverity.value) return hexToRgba('#6b7280', 0.4)
    return hexToRgba(severityHexMap[rescoredSeverity.value] ?? '#4b5563', 0.4)
})


const cardStyle = computed(() => {
    switch (displayState.value) {
        case 'NOT_SET':
        case 'OPEN':
        case 'EXPLOITABLE':
            return 'bg-gray-800-warm border-gray-700 hover:bg-gray-750'
        case 'INCONSISTENT':
            return 'bg-gray-800 border-gray-700 hover:bg-gray-750 stripe-bg'
        default:
            return 'bg-gray-800 border-gray-700 hover:bg-gray-750'
    }
})


const dependencyRelationship = dependencyInfo.dependencyRelationship
const sortedAffectedProjectVersions = dependencyInfo.sortedAffectedProjectVersions

const externalLinks = computed(() => {
    const id = props.group.id
    const links: { label: string, url: string }[] = [
        ...(id?.startsWith('CVE-')
            ? [
                { label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}` },
                { label: 'MITRE', url: `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}` },
            ]
            : []),
        ...(id?.startsWith('GHSA-')
            ? [{ label: 'GitHub Advisory', url: `https://github.com/advisories/${encodeURIComponent(id)}` }]
            : []),
    ]
    for (const alias of props.group.aliases || []) {
        if (alias.startsWith('CVE-') && alias !== id) {
            links.push({ label: `NVD (${alias})`, url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(alias)}` })
        }
        if (alias.startsWith('GHSA-') && alias !== id) {
            links.push({ label: `GitHub (${alias})`, url: `https://github.com/advisories/${encodeURIComponent(alias)}` })
        }
    }
    return links
})

const assessmentScoreTitle = computed(() => {
    const vector = pendingVector.value || props.group.rescored_vector || props.group.cvss_vector || ''
    return vector ? `CVSS vector: ${vector}` : 'No CVSS vector available'
})
const hasUnsavedDraft = computed(() => formTouched.value || rawDetailsTouched.value)
const assessmentMissingFields = computed(() => {
    if (isReviewer.value) return []
    const missing: string[] = []
    if (!selectedTeam.value) missing.push('team')
    if (!state.value || state.value === 'NOT_SET') missing.push('analysis state')
    if (!details.value.trim()) missing.push('analysis details')
    if (state.value === 'NOT_AFFECTED' && (!justification.value || justification.value === 'NOT_SET')) {
        missing.push('justification')
    }
    return missing
})
const canApplyAssessment = computed(() => (
    !updating.value
    && !loadingDetails.value
    && totalTargeted.value > 0
    && hasUnsavedDraft.value
    && assessmentMissingFields.value.length === 0
))
const assessmentActionLabel = computed(() => {
    if (updating.value) return isReviewer.value ? 'Saving...' : 'Submitting...'
    if (isReviewer.value) return 'Save assessment'
    return selectedTeam.value
        ? `Submit ${selectedTeam.value} for review`
        : 'Select a team'
})
const reviewContextRescoredSeverity = computed(() => {
    if (!hasStableRescore.value && !isRescoredOrModified.value) return null
    const score = Number(currentDisplayScore.value)
    if (Number.isNaN(score)) return null
    return scoreSeverity(score)
})
const isTicketReferenceRequired = computed(() => (
    reviewContextRescoredSeverity.value === 'HIGH' ||
    reviewContextRescoredSeverity.value === 'CRITICAL'
))
const ticketReferenceMissing = computed(() => isTicketReferenceRequired.value && !ticketReference.value.trim())
const reviewContextRequiredTotal = computed(() => isTicketReferenceRequired.value ? 3 : 2)
const reviewContextRequiredCompleted = computed(() => [
    evidenceReviewed.value,
    versionCoverageChecked.value,
    ...(isTicketReferenceRequired.value ? [Boolean(ticketReference.value.trim())] : []),
].filter(Boolean).length)
const ticketRequirementHelp = computed(() => {
    if (isTicketReferenceRequired.value && reviewContextRescoredSeverity.value) {
        return `Required for ${reviewContextRescoredSeverity.value} after rescoring.`
    }
    return 'Optional unless rescoring leaves this High or Critical.'
})

const detailTabs = computed<Array<{ id: DetailTab, label: string, icon: Component }>>(() => [
    { id: 'overview', label: 'Context', icon: FileText },
    { id: 'analysis', label: 'Code Evidence', icon: Bot },
    { id: 'review', label: 'Assessment', icon: ShieldCheck },
    ...(isReviewer.value ? [{ id: 'mapping' as DetailTab, label: 'Team Mapping', icon: Tags }] : []),
])

const detailTabStatus = (tab: DetailTab) => {
    if (tab === 'overview') return `${visibleInstances.value.length}/${allInstances.value.length}`
    if (tab === 'analysis') {
        if (codeAnalysisAvailableForScope.value) return 'Ready'
        if (activeTeamScope.value) {
            return assessmentCompleteForScope.value || pendingReviewForScope.value ? '' : 'Needed'
        }
        return technicalState.value === 'NOT_SET' ? 'Needed' : ''
    }
    if (tab === 'review') {
        if (assessmentSubmitted.value || pendingReviewForScope.value) return 'Pending'
        if (assessmentCompleteForScope.value) return 'Done'
        if (hasUnsavedDraft.value) return assessmentMissingFields.value.length ? 'Incomplete' : 'Draft'
        return activeTeamScope.value ? 'Needed' : ''
    }
    return ''
}

const detailTabClass = (tab: DetailTab) =>
    activeDetailTab.value === tab
        ? 'border-cyan-400 text-cyan-100'
        : 'border-transparent text-gray-500 hover:border-gray-600 hover:text-gray-200'

const detailTabId = (tab: DetailTab) => `vuln-${props.group.id}-detail-tab-${tab}`
const detailTabPanelId = (tab: DetailTab) => `vuln-${props.group.id}-detail-panel-${tab}`

const setDetailTab = (tab: DetailTab, preserveReviewTeam = false) => {
    if (tab === 'review' && !preserveReviewTeam) {
        const matchingTeam = (
            activeTeamScope.value && !showAllAssessmentTeams.value
                ? scopedAssessmentTeam.value
                : (!selectedTeam.value && !isReviewer.value && allAssessmentTeams.value.length === 1
                    ? allAssessmentTeams.value[0]
                    : '')
        )
        if (matchingTeam) selectedTeam.value = matchingTeam
    }
    activeDetailTab.value = tab
    nextTick(() => {
        detailsEl.value?.scrollTo?.({ top: 0, behavior: 'smooth' })
    })
}

const uniqueComponents = dependencyInfo.uniqueComponents
const affectedTaggedComponents = dependencyInfo.affectedTaggedComponents
const triggeringTaggedComponents = dependencyInfo.triggeringTaggedComponents
const normalizedTags = dependencyInfo.normalizedTags
const allAssessmentTeams = computed(() => {
    const teams = normalizedTags.value.filter(team => team.toLocaleLowerCase() !== 'automation')
    for (const team of teamDrafts.value.keys()) {
        if (
            team.toLocaleLowerCase() !== 'automation'
            && team.toLocaleLowerCase() !== 'general'
            && !teams.some(candidate => candidate.toLocaleLowerCase() === team.toLocaleLowerCase())
        ) {
            teams.push(team)
        }
    }
    return teams
})
const preparedAutomaticProposals = computed(() => prepareCodeAnalysisResults(
    codeAnalysisProposalRuns.value,
    triggeringTaggedComponents.value,
    [],
))
const automaticTeamProposals = computed(() => new Map(
    preparedAutomaticProposals.value.teamDrafts.map(draft => [draft.team.toLocaleLowerCase(), draft]),
))
const selectedAutomaticProposal = computed(() => (
    selectedTeam.value
        ? automaticTeamProposals.value.get(selectedTeam.value.toLocaleLowerCase()) || null
        : null
))
const selectedAutomaticProposalRuns = computed(() => {
    const teamKey = selectedTeam.value.toLocaleLowerCase()
    if (!teamKey) return []
    return codeAnalysisProposalRuns.value.filter(run => triggeringTaggedComponents.value.some(component => (
        component.name.toLocaleLowerCase() === run.component.toLocaleLowerCase()
        && component.tag.toLocaleLowerCase() === teamKey
    )))
})
const selectedAutomaticProposalSummary = computed(() => {
    const runs = selectedAutomaticProposalRuns.value
    const worstRun = runs.find(run => codeAnalysisAssessmentState(run.result) === selectedAutomaticProposal.value?.state)
        || runs[0]
    if (!worstRun) return ''
    const summary = worstRun.result.assessment.executive_summary?.assessment
        || worstRun.result.assessment.summary
    const coverage = runs.length > 1 ? ` (${runs.length} targets; worst result shown)` : ''
    return `${worstRun.component}: ${summary}${coverage}`
})
const selectedAutomaticProposalRationale = computed(() => selectedAutomaticProposalRuns.value
    .map(run => run.result.assessment.executive_summary
        ? ''
        : `${run.component}: ${run.result.assessment.reasoning || run.result.assessment.summary}`)
    .filter(Boolean)
    .join(' '))
const assessmentComponentsByTeam = computed(() => {
    const componentsByTeam = new Map<string, string[]>()
    for (const component of unscopedDependencyInfo.triggeringTaggedComponents.value) {
        const teamKey = component.tag.toLocaleLowerCase()
        const components = componentsByTeam.get(teamKey) || []
        if (!components.some(name => name.toLocaleLowerCase() === component.name.toLocaleLowerCase())) {
            components.push(component.name)
        }
        componentsByTeam.set(teamKey, components)
    }
    return componentsByTeam
})
const selectedAssessmentTeamComponents = computed(() => (
    selectedTeam.value
        ? assessmentComponentsByTeam.value.get(selectedTeam.value.toLocaleLowerCase()) || []
        : []
))
const stringifyAssessmentTicketValue = (value: unknown): string => {
    if (value == null || value === '') return ''
    if (typeof value === 'string') return value.trim()
    if (typeof value === 'number' || typeof value === 'boolean') return String(value)
    try {
        return JSON.stringify(value)
    } catch {
        return String(value)
    }
}
const selectedTeamTicketText = computed(() => {
    const ticketTexts = selectedAutomaticProposalRuns.value
        .map(run => stringifyAssessmentTicketValue(run.result.assessment.ticket_text))
        .filter(Boolean)
    return [...new Set(ticketTexts)].join('\n\n---\n\n')
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
const copySelectedTeamTicket = async () => {
    if (!selectedTeamTicketText.value) return
    assessmentTicketCopyState.value = 'idle'
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(selectedTeamTicketText.value)
        } else {
            copyTextWithFallback(selectedTeamTicketText.value)
        }
        assessmentTicketCopyState.value = 'copied'
        globalThis.setTimeout(() => {
            if (assessmentTicketCopyState.value === 'copied') assessmentTicketCopyState.value = 'idle'
        }, 2000)
    } catch {
        assessmentTicketCopyState.value = 'error'
    }
}

type EffectiveTeamAssessment = {
    team: string
    state: string
    justification: string
    details: string
    source: 'team' | 'automatic' | 'missing'
}

const effectiveTeamAssessments = computed<EffectiveTeamAssessment[]>(() => allAssessmentTeams.value.map(team => {
    const teamKey = team.toLocaleLowerCase()
    const saved = mergedAssessmentData.value.blocks.find(block => block.team.toLocaleLowerCase() === teamKey)
    const draft = [...teamDrafts.value.entries()].find(([key]) => key.toLocaleLowerCase() === teamKey)?.[1]
    const isAutomaticFallback = automaticFallbackTeams.value.has(teamKey)
    const current = !isAutomaticFallback && selectedTeam.value.toLocaleLowerCase() === teamKey && state.value !== 'NOT_SET'
        ? {
            state: state.value,
            justification: justification.value,
            details: details.value,
        }
        : null
    const manual = current || (!isAutomaticFallback ? draft : null) || saved
    if (manual?.state && manual.state !== 'NOT_SET') {
        return {
            team,
            state: manual.state,
            justification: manual.justification || 'NOT_SET',
            details: manual.details || '',
            source: 'team',
        }
    }

    const proposal = automaticTeamProposals.value.get(teamKey)
    if (proposal?.state && proposal.state !== 'NOT_SET') {
        return {
            team,
            state: proposal.state,
            justification: proposal.justification,
            details: proposal.details,
            source: 'automatic',
        }
    }
    return { team, state: 'NOT_SET', justification: 'NOT_SET', details: '', source: 'missing' }
}))
const effectiveAssessmentWorst = computed(() => effectiveTeamAssessments.value
    .filter(assessment => assessment.state !== 'NOT_SET')
    .sort((left, right) => (STATE_PRIORITY[left.state] ?? 10) - (STATE_PRIORITY[right.state] ?? 10))[0] || null)
const scopedAssessmentTeam = computed(() => {
    if (!activeTeamScope.value || visibleInstances.value.length === 0) return ''
    const activeKey = activeTeamScope.value.toLocaleLowerCase()
    return allAssessmentTeams.value.find(team => team.toLocaleLowerCase() === activeKey) || ''
})
const teamTabs = computed(() => {
    if (!activeTeamScope.value || (isReviewer.value && showAllAssessmentTeams.value)) {
        return allAssessmentTeams.value
    }
    return scopedAssessmentTeam.value ? [scopedAssessmentTeam.value] : []
})
const scopedAssessmentProgress = computed(() => {
    if (!scopedAssessmentTeam.value || visibleInstances.value.length === 0) {
        return { complete: false, pending: false }
    }

    const teamKey = scopedAssessmentTeam.value.toLocaleLowerCase()
    let pending = false
    const covered = visibleInstances.value.every(instance => {
        const rawInstance = instance as Record<string, any>
        const instanceDetails = String(rawInstance.analysis_details || rawInstance.analysisDetails || '')
        const blocks = parseAssessmentBlocks(instanceDetails)
        const hasApplicableBlock = blocks.some(block => {
            const blockTeam = block.team.toLocaleLowerCase()
            return (
                (blockTeam === 'general' || blockTeam === teamKey)
                && Boolean(block.state)
                && block.state !== 'NOT_SET'
            )
        })
        const legacyAssessment = blocks.length === 0
            && String(rawInstance.analysis_state || rawInstance.analysisState || 'NOT_SET') !== 'NOT_SET'
        if ((hasApplicableBlock || legacyAssessment) && instanceDetails.includes('[Status: Pending Review]')) {
            pending = true
        }
        return hasApplicableBlock || legacyAssessment
    })

    return { complete: covered && !pending, pending }
})
const assessmentCompleteForScope = computed(() => activeTeamScope.value
    ? scopedAssessmentProgress.value.complete
    : displayState.value === 'ASSESSED' || displayState.value === 'ASSESSED_LEGACY'
)
const pendingReviewForScope = computed(() => activeTeamScope.value
    ? scopedAssessmentProgress.value.pending
    : isPendingReview.value
)
const codeAnalysisAvailableForScope = computed(() => activeTeamScope.value
    ? scopedCodeAnalysisAvailable.value
    : Boolean(props.automaticAssessmentStatus)
)
const codeAnalysisComponents = computed(() =>
    triggeringTaggedComponents.value.map(c => c.name)
        .map(name => String(name || '').trim())
        .filter(Boolean)
)
const codeAnalysisComponentTeams = computed(() =>
    Object.fromEntries(triggeringTaggedComponents.value.map(c => [c.name, c.tag]))
)
const hiddenTeamScopeInstanceCount = computed(() => Math.max(
    0,
    allInstances.value.length - visibleInstances.value.length,
))
const scopedAffectedProjectVersions = computed(() => {
    const versions = new Set<string>()
    for (const instance of visibleInstances.value) {
        const version = String((instance as Record<string, any>).project_version || '').trim()
        if (version) versions.add(version)
    }
    return [...versions].sort((left, right) => left.localeCompare(right, undefined, { numeric: true }))
})

type WorkflowActionId = 'mapping' | 'analysis' | 'assessment' | 'submit' | 'waiting' | 'done'
type WorkflowAction = {
    id: WorkflowActionId
    title: string
    detail: string
    label: string
    tone: 'amber' | 'cyan' | 'blue' | 'green' | 'purple'
}

const workflowAction = computed<WorkflowAction>(() => {
    const canMoveNext = Boolean(props.hasNextVulnerability)
    if (assessmentSubmitted.value) {
        return {
            id: isReviewer.value ? 'done' : 'waiting',
            title: isReviewer.value ? 'Assessment saved' : 'Assessment submitted for review',
            detail: isReviewer.value
                ? 'The assessment changes were saved successfully.'
                : 'No further analyst action is required for this vulnerability right now.',
            label: canMoveNext ? 'Next vulnerability' : '',
            tone: isReviewer.value ? 'green' : 'purple',
        }
    }
    if (pendingReviewForScope.value) {
        return {
            id: 'waiting',
            title: 'Waiting for reviewer',
            detail: 'The analyst assessment is pending reviewer approval.',
            label: canMoveNext ? 'Next vulnerability' : '',
            tone: 'purple',
        }
    }
    if (assessmentCompleteForScope.value) {
        return {
            id: 'done',
            title: 'Assessment complete',
            detail: 'This vulnerability is complete for the current workflow.',
            label: canMoveNext ? 'Next vulnerability' : '',
            tone: 'green',
        }
    }
    if (activeTeamScope.value && visibleInstances.value.length === 0) {
        return {
            id: 'mapping',
            title: 'Component mapping needs attention',
            detail: isReviewer.value
                ? `No component in this vulnerability resolves to ${activeTeamScope.value}. Review the mapping before continuing.`
                : `No component resolves to ${activeTeamScope.value}. Ask a reviewer to correct the team mapping.`,
            label: isReviewer.value ? 'Review team mapping' : 'View mapping details',
            tone: 'amber',
        }
    }
    if (hasUnsavedDraft.value) {
        if (assessmentMissingFields.value.length > 0) {
            return {
                id: 'assessment',
                title: 'Complete the assessment draft',
                detail: `Still needed: ${assessmentMissingFields.value.join(', ')}.`,
                label: 'Complete assessment',
                tone: 'amber',
            }
        }
        return {
            id: 'submit',
            title: isReviewer.value ? 'Assessment changes are ready' : 'Assessment draft is ready',
            detail: isReviewer.value
                ? 'Review the changed fields, then save the assessment.'
                : `Review the draft, then submit it for ${selectedTeam.value || 'team'} review.`,
            label: assessmentActionLabel.value,
            tone: 'blue',
        }
    }
    if (codeAnalysisAvailableForScope.value) {
        return {
            id: 'analysis',
            title: 'Code-analysis result available',
            detail: 'Review the latest scoped result before starting another run, then use it as an assessment draft if it is suitable.',
            label: 'Review code evidence',
            tone: 'cyan',
        }
    }
    if (!activeTeamScope.value && technicalState.value !== 'NOT_SET') {
        return {
            id: 'assessment',
            title: 'Record the team assessment',
            detail: 'The current evidence is ready to be turned into a team assessment.',
            label: 'Open assessment',
            tone: 'blue',
        }
    }
    return {
        id: codeAnalysisComponents.value.length ? 'analysis' : 'mapping',
        title: codeAnalysisComponents.value.length ? 'Gather code evidence' : 'Component mapping needs attention',
        detail: codeAnalysisComponents.value.length
            ? `Review existing history or analyze ${codeAnalysisComponents.value.length} scoped component${codeAnalysisComponents.value.length === 1 ? '' : 's'}.`
            : 'No team-assigned analysis target is available. Review the dependency context and mapping.',
        label: codeAnalysisComponents.value.length
            ? 'Open code evidence'
            : isReviewer.value ? 'Review team mapping' : 'Review context',
        tone: codeAnalysisComponents.value.length ? 'cyan' : 'amber',
    }
})

const workflowActionClass = computed(() => ({
    amber: 'border-amber-700/45 bg-amber-950/20 text-amber-100',
    cyan: 'border-cyan-700/45 bg-cyan-950/20 text-cyan-100',
    blue: 'border-blue-700/45 bg-blue-950/20 text-blue-100',
    green: 'border-green-700/45 bg-green-950/20 text-green-100',
    purple: 'border-purple-700/45 bg-purple-950/20 text-purple-100',
}[workflowAction.value.tone]))

const workflowActionTargetTab = computed<DetailTab | null>(() => {
    if (workflowAction.value.id === 'analysis') return 'analysis'
    if (workflowAction.value.id === 'assessment' || workflowAction.value.id === 'submit') return 'review'
    if (workflowAction.value.id === 'mapping') return isReviewer.value ? 'mapping' : 'overview'
    return null
})
const workflowActionAtDestination = computed(() => (
    workflowActionTargetTab.value !== null
    && activeDetailTab.value === workflowActionTargetTab.value
))
const workflowActionDetail = computed(() => {
    if (!workflowActionAtDestination.value) return workflowAction.value.detail
    if (workflowAction.value.id === 'analysis') {
        return codeAnalysisAvailableForScope.value
            ? 'Choose a target run below, review its outcome, then use it as an assessment draft when the evidence is suitable.'
            : 'Expand Run new analysis or review the latest stored run for each affected target below.'
    }
    if (workflowAction.value.id === 'assessment' || workflowAction.value.id === 'submit') {
        return assessmentMissingFields.value.length
            ? `Complete the highlighted assessment fields below: ${assessmentMissingFields.value.join(', ')}.`
            : `Review the ${selectedTeam.value || 'current'} assessment below, then ${isReviewer.value ? 'save it' : 'submit it for review'}.`
    }
    if (workflowAction.value.id === 'mapping') {
        return isReviewer.value
            ? 'Review the affected component mappings below and assign the missing team ownership.'
            : 'Review the affected component and dependency context below, then ask a reviewer to update ownership.'
    }
    return workflowAction.value.detail
})
const showWorkflowPrimaryAction = computed(() => (
    Boolean(workflowAction.value.label)
    && !workflowActionAtDestination.value
))

const handleWorkflowAction = () => {
    if (workflowAction.value.id === 'submit') {
        void handleUpdate(false)
        return
    }
    if (workflowAction.value.id === 'waiting' || workflowAction.value.id === 'done') {
        emit('request-next')
        return
    }
    if (workflowAction.value.id === 'mapping') {
        setDetailTab(isReviewer.value ? 'mapping' : 'overview')
        return
    }
    setDetailTab(workflowAction.value.id === 'analysis' ? 'analysis' : 'review')
}
const scopedHeaderTags = computed(() => activeTeamScope.value
    ? [activeTeamScope.value]
    : normalizedTags.value
)
const scopedComponentSummary = computed(() => {
    const names = uniqueComponents.value.map(component => component.name)
    if (names.length <= 2) return names.join(', ')
    return `${names[0]}, ${names[1]} +${names.length - 2}`
})
const scopedOldestAttributedOnMs = computed(() => {
    const values = visibleInstances.value
        .map(instance => parseAttributionTimestamp(instance.attributed_on))
        .filter((value): value is number => value != null)
    return values.length ? Math.min(...values) : null
})
const codeAnalysisProjectName = computed(() => {
    const names = new Set(
        (props.group.affected_versions || [])
            .map(version => String(version.project_name || '').trim())
            .filter(Boolean),
    )
    return names.size === 1 ? [...names][0] : undefined
})

const hasAssessedAliasForTag = (tag: string, assessed: Set<string>) => {
    if (!teamMapping?.value) {
        return false
    }

    for (const mappingVal of Object.values(teamMapping.value)) {
        if (!Array.isArray(mappingVal) || mappingVal.length <= 1 || mappingVal[0] !== tag) {
            continue
        }

        return mappingVal.slice(1).some(alias => assessed.has(alias))
    }

    return false
}

const assessedTeams = computed(() => {
    const assessed = getAssessedTeams(props.group)
    const matchedTeams = new Set<string>()

    for (const tag of normalizedTags.value) {
        // A primary tag is assessed if it OR any of its aliases are assessed
        if (assessed.has(tag) || hasAssessedAliasForTag(tag, assessed)) {
            matchedTeams.add(tag)
        }
    }

    return matchedTeams
})

const applySuccessfulAssessmentUpdate = (success: any, results: any[], finalState: string, finalText: string) => {
    const savedResult = buildSavedAssessmentResultState({
        success,
        isReviewer: isReviewer.value,
        pendingVector: pendingVector.value,
        pendingScore: pendingScore.value,
        baseVector: props.group.cvss_vector,
        existingRescoredVector: props.group.rescored_vector,
        existingRescoredCvss: props.group.rescored_cvss,
        suppressed: suppressed.value,
        currentAssigned: currentAssigned.value,
    })
    emit('update:assessment', {
        ...savedResult.emittedAssessment,
        dtvp_results: results.filter(result => result.status === 'success'),
    })

    isInternalUpdate.value = true
    try {
        initialVector.value = savedResult.nextInitialVector
        initialScore.value = savedResult.nextInitialScore
        pendingVector.value = savedResult.nextPendingVector
        pendingScore.value = savedResult.nextInitialScore
    } finally {
        isInternalUpdate.value = false
    }
    isManualBaseMode.value = false
    lastRescoredScore.value = savedResult.nextLastRescoredScore
    showConflictModal.value = false

    Object.assign(originalAnalysis.value, buildSavedOriginalAnalysis({
        allInstances: allInstances.value,
        finalState,
        finalText,
        suppressed: suppressed.value,
        results,
    }))
    teamDrafts.value.clear()
    formTouched.value = false
    rawDetailsTouched.value = false
    codeAnalysisDraftApplied.value = false
    codeAnalysisDraftSummary.value = ''
    codeAnalysisRunIds.value = []
    automaticFallbackTeams.value = new Set()
}

const handleAssessmentUpdateResults = async (results: any[], finalState: string, finalText: string) => {
    const errors = results.filter((r: any) => r.status === 'error')
    if (errors.length > 0) {
        console.error('Update completed with errors:', errors)
        await showAlert('Update Partial', `Assessment updated with ${errors.length} errors. Check console for details.`)
        return
    }

    const success = results.find((r: any) => r.status === 'success')
    if (success) {
        applySuccessfulAssessmentUpdate(success, results, finalState, finalText)
        await nextTick()
        assessmentSubmitted.value = true
    }
}

const confirmAssessmentReview = async (force: boolean, reviewText: string) => {
    if (force) {
        return true
    }

    updating.value = false
    const approved = await promptReview(reviewText)
    if (!approved && isDebugPersistenceEnabled()) {
        console.log('[Persistence Debug] handleUpdate cancelled by user in review');
    }
    updating.value = approved
    return approved
}

const handleAssessmentUpdateError = async (err: any) => {
    if (err.response?.status === 409) {
        conflictData.value = err.response.data.conflicts
        showConflictModal.value = true
        return
    }

    await showAlert('Error', 'Failed to update assessment')
    console.error(err)
}

const toggleAssessmentTeamScope = () => {
    showAllAssessmentTeams.value = !showAllAssessmentTeams.value
    if (!showAllAssessmentTeams.value && scopedAssessmentTeam.value) {
        selectedTeam.value = scopedAssessmentTeam.value
    }
}

watch(activeTeamScope, () => {
    showAllAssessmentTeams.value = false
    scopedCodeAnalysisAvailable.value = false
    if (activeTeamScope.value) {
        selectedTeam.value = scopedAssessmentTeam.value
    }
}, { immediate: true })

const teamBlockMeta = (team: string): AssessmentBlock | undefined => {
    return mergedAssessmentData.value.blocks.find(b => b.team === team)
}

const teamBlockStateColor = (state?: string): string => {
    if (!state || state === 'NOT_SET') return 'bg-gray-500'
    if (state === 'EXPLOITABLE' || state === 'IN_TRIAGE') return 'bg-red-500'
    if (state === 'NOT_AFFECTED' || state === 'RESOLVED' || state === 'FALSE_POSITIVE') return 'bg-green-500'
    return 'bg-yellow-500'
}

</script>

<template>
    <div :class="['vuln-card relative border rounded-lg transition-colors', inModal ? 'overflow-hidden' : (expanded ? 'overflow-visible z-40' : 'overflow-hidden'), cardStyle]">
    <!-- Criticality Badges — header-height only -->
    <div
        class="absolute top-0 left-0 z-20 pointer-events-none flex"
        :style="{ height: headerHeight + 'px' }"
        data-testid="criticality-badge-slot"
    >
        <!-- Original severity badge with chevron and shadow -->
        <div class="relative z-20 h-full w-10 flex items-center justify-center" data-testid="severity-badge">
            <svg class="absolute inset-0 w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 40 100">
                <defs>
                    <filter id="badge-chevron-shadow" x="-8" y="-8" width="56" height="116" filterUnits="userSpaceOnUse">
                        <feDropShadow dx="3" dy="2" stdDeviation="4" flood-color="rgba(0,0,0,0.45)" />
                    </filter>
                </defs>
                <polygon :fill="originalSeverityFill" filter="url(#badge-chevron-shadow)" points="0,0 32,0 40,50 32,100 0,100" />
            </svg>
            <span class="relative z-10 text-[9px] font-black uppercase tracking-[0.22em] [writing-mode:vertical-rl] rotate-180 whitespace-nowrap text-white">
                {{ originalSeverity }}
            </span>
        </div>
        <!-- Rescored severity badge with inward left notch and right chevron -->
        <div class="relative z-10 h-full w-9 -ml-2 flex items-center justify-end" data-testid="rescored-severity-badge">
            <div
                class="absolute inset-0"
                :style="{
                    backgroundColor: rescoredSeverityHex,
                    clipPath: 'polygon(0 0, 77.78% 0, 100% 50%, 77.78% 100%, 0 100%, 22.22% 50%)'
                }"
            ></div>
            <span class="relative z-10 pl-3 text-[8px] font-black uppercase tracking-[0.18em] [writing-mode:vertical-rl] rotate-180 whitespace-nowrap text-white">
                {{ rescoredSeverity || 'N/A' }}
            </span>
        </div>
    </div>
    <!-- Assessed Corner Fold -->
    <div v-if="isAssessed && !inModal" class="absolute top-0 right-0 pointer-events-none z-20">
        <div
            class="w-8 h-8 flex justify-end items-start p-1 uppercase"
            :class="assessedFoldClass"
            :title="displayState === 'ASSESSED_LEGACY' ? 'Legacy assessed' : 'Assessed'"
            style="clip-path: polygon(100% 0, 0 0, 100% 100%)"
        >
            <CheckCircle :size="12" :class="assessedIconClass" />
        </div>
    </div>
    <!-- Header -->
    <div
        ref="headerEl"
        @click="!inModal && (expanded = !expanded)"
        class="pl-[76px] pr-4 py-3 flex items-start transition-all relative overflow-hidden"
        :class="inModal ? '' : 'cursor-pointer hover:bg-white/2'"
    >

        <VulnGroupCardHeader
            :group="group"
            :displayState="displayState"
            :technicalState="technicalState"
            :isRescoredOrModified="isRescoredOrModified || hasStableRescore"
            :currentDisplayScore="currentDisplayScore"
            :pendingScore="pendingScore"
            :stableRescoredScore="stableRescoredScore"
            :hasStableRescore="hasStableRescore"
            :normalizedTags="scopedHeaderTags"
            :assessedTeams="assessedTeams"
            @copy-id="copyId"
            :expanded="expanded"
            :canApprove="canApprove"
            :isPendingReview="isPendingReview"
            :dependencyRelationship="dependencyRelationship"
            :assignees="group.assignees || []"
            :showExpandToggle="!inModal"
            :hasAutomaticAssessment="props.hasAutomaticAssessment"
            :automaticAssessmentStatus="props.automaticAssessmentStatus"
            :hasTmrescoreAnalysis="!!matchedProposal"
            :scoreTitle="assessmentScoreTitle"
            :hasUnsavedDraft="hasUnsavedDraft"
            :instanceCountOverride="visibleInstances.length"
            :oldestAttributedOnMsOverride="scopedOldestAttributedOnMs"
            :componentSummaryOverride="scopedComponentSummary"
            @approve-assessment="approveAssessment"
        >
            <template v-if="inModal" #actions>
                <button
                    type="button"
                    class="relative z-30 mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded border border-gray-700/80 bg-gray-950/70 text-gray-300 transition-colors hover:bg-gray-800 hover:text-white"
                    title="Close details"
                    @click.stop="requestClose"
                >
                    <X :size="15" />
                    <span class="sr-only">Close details</span>
                </button>
            </template>
        </VulnGroupCardHeader>
    </div>
            <!-- Expanded Details -->
    <div v-if="expanded" ref="detailsEl" class="px-4 pb-4 border-t border-gray-700 overflow-y-auto" :style="inModal ? {} : { maxHeight: detailsMaxHeight }">
        <div data-vuln-card-sticky-nav class="sticky top-0 z-30 -mx-4 mb-5 border-b border-gray-700/80 bg-gray-900/95 px-4 shadow-lg backdrop-blur">
            <div class="-mx-4 flex flex-wrap items-end gap-2 px-4">
                <div class="flex min-w-0 flex-1 flex-wrap items-end" role="tablist" aria-label="Vulnerability detail sections">
                    <button
                        v-for="tab in detailTabs"
                        :key="tab.id"
                        :id="detailTabId(tab.id)"
                        type="button"
                        role="tab"
                        :aria-selected="activeDetailTab === tab.id ? 'true' : 'false'"
                        :aria-controls="detailTabPanelId(tab.id)"
                        class="-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-[11px] font-semibold uppercase tracking-wide transition-colors"
                        :class="detailTabClass(tab.id)"
                        @click="setDetailTab(tab.id)"
                    >
                        <component :is="tab.icon" :size="13" aria-hidden="true" />
                        {{ tab.label }}
                        <span
                            v-if="detailTabStatus(tab.id)"
                            class="rounded-full border border-current/20 bg-black/20 px-1.5 py-0.5 text-[9px] normal-case tracking-normal opacity-80"
                            :data-testid="`detail-tab-status-${tab.id}`"
                        >
                            {{ detailTabStatus(tab.id) }}
                        </span>
                    </button>
                </div>
                <div
                    v-if="assessmentPersistenceStatus"
                    data-testid="assessment-persistence-status"
                    class="my-1.5 inline-flex shrink-0 items-center gap-1.5 rounded border px-2 py-1 text-[10px] font-semibold"
                    :class="assessmentPersistenceStatus.kind === 'error'
                        ? 'border-red-800/70 bg-red-950/50 text-red-300'
                        : 'border-amber-700/70 bg-amber-950/40 text-amber-200'"
                    :title="assessmentPersistenceStatus.detail || assessmentPersistenceStatus.label"
                    role="status"
                >
                    <AlertTriangle v-if="assessmentPersistenceStatus.kind === 'error'" :size="12" />
                    <Loader2 v-else :size="12" class="animate-spin" />
                    {{ assessmentPersistenceStatus.label }}
                </div>
            </div>
        </div>

        <section
            data-testid="analyst-next-action"
            class="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border px-3 py-3"
            :class="workflowActionClass"
        >
            <div class="flex min-w-0 flex-1 items-start gap-2.5">
                <CircleDot :size="16" class="mt-0.5 shrink-0 opacity-80" />
                <div class="min-w-0">
                    <div class="text-[10px] font-black uppercase tracking-widest opacity-65">Next action</div>
                    <div class="mt-0.5 text-sm font-bold">{{ workflowAction.title }}</div>
                    <p class="mt-0.5 text-xs leading-relaxed opacity-75">{{ workflowActionDetail }}</p>
                    <div v-if="workflowActionAtDestination" class="mt-1.5 inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide opacity-65">
                        <CheckCircle :size="11" />
                        You are at the next step
                    </div>
                </div>
            </div>
            <button
                v-if="showWorkflowPrimaryAction"
                type="button"
                data-testid="workflow-primary-action"
                class="inline-flex shrink-0 items-center gap-1.5 rounded border border-current/30 bg-black/20 px-3 py-2 text-xs font-bold transition-colors hover:bg-black/35 disabled:cursor-not-allowed disabled:opacity-45"
                :disabled="workflowAction.id === 'submit' && !canApplyAssessment"
                @click="handleWorkflowAction"
            >
                <Loader2 v-if="updating" :size="13" class="animate-spin" />
                <ArrowRight v-else :size="13" />
                {{ workflowAction.label }}
            </button>
        </section>

        <section
            v-show="activeDetailTab === 'overview'"
            :id="detailTabPanelId('overview')"
            :aria-labelledby="detailTabId('overview')"
            class="space-y-5 pt-1"
            role="tabpanel"
        >
            <DetailSection
                step="Context · 1"
                title="Description & references"
                description="Understand the advisory before evaluating where it appears in this project."
            >
                <h5 v-if="group.title && group.title !== group.id" class="mb-2 text-base font-semibold text-gray-100">{{ group.title }}</h5>
                <div
                    class="advisory-markdown text-sm text-gray-400 leading-relaxed"
                    data-testid="vuln-description"
                    v-html="renderedDescription"
                ></div>
                <div v-if="externalLinks.length" class="mt-3 flex flex-wrap items-center gap-2 text-[10px]">
                    <span class="font-bold uppercase tracking-wider text-gray-600">References</span>
                    <a
                        v-for="link in externalLinks"
                        :key="link.url"
                        :href="link.url"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-300 border border-blue-800/40 hover:bg-blue-900/50 hover:text-blue-200 transition-colors"
                    >
                        <ExternalLink :size="9" />
                        {{ link.label }}
                    </a>
                </div>
            </DetailSection>

            <DetailSection
                step="Context · 2"
                title="Finding scope & affected components"
                description="See where the vulnerability was found, which team owns the current scope, and the exact components that require analysis."
                bodyClass="space-y-3"
            >
                <div class="flex flex-wrap items-center gap-2 text-[11px]">
                    <span class="font-bold uppercase tracking-wider text-gray-500">Found in project versions</span>
                    <span
                        v-for="version in scopedAffectedProjectVersions"
                        :key="version"
                        data-testid="context-project-version"
                        class="rounded border border-gray-700 bg-gray-950/45 px-2 py-1 font-mono text-gray-300"
                    >
                        {{ version }}
                    </span>
                    <span v-if="scopedAffectedProjectVersions.length === 0" class="text-gray-600">No matching project versions</span>
                </div>

                <div
                    v-if="activeTeamScope"
                    data-testid="vulnerability-team-scope"
                    class="flex flex-wrap items-center justify-between gap-2 rounded border border-blue-800/40 bg-blue-950/20 px-3 py-2 text-[11px] text-blue-200"
                >
                    <span>Owning team scope: <strong>{{ activeTeamScope }}</strong></span>
                    <span class="text-blue-300/70">
                        {{ visibleInstances.length }} of {{ allInstances.length }} finding{{ allInstances.length === 1 ? '' : 's' }} shown
                        <template v-if="hiddenTeamScopeInstanceCount"> · {{ hiddenTeamScopeInstanceCount }} outside this team</template>
                    </span>
                </div>

                <div
                    v-if="activeTeamScope && visibleInstances.length === 0"
                    class="rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-200"
                >
                    No components in this vulnerability currently resolve to {{ activeTeamScope }}.
                </div>

            <div
                v-if="triggeringTaggedComponents.length > 0 || affectedTaggedComponents.length > 0 || uniqueComponents.length > 0"
                class="grid gap-4 rounded border border-gray-800/80 bg-gray-950/30 p-3 lg:grid-cols-3"
            >
                <div v-if="triggeringTaggedComponents.length > 0" data-testid="triggering-team-components" class="space-y-2">
                    <h4 class="text-[10px] font-bold uppercase tracking-wider text-gray-500">Triggering team-mapped components</h4>
                    <div class="flex flex-wrap gap-1.5">
                        <span
                            v-for="comp in triggeringTaggedComponents"
                            :key="comp.name"
                            class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-gray-800 text-gray-300 border border-gray-700"
                        >
                            {{ comp.name }}
                            <span v-if="comp.versions.length" class="text-gray-500">@{{ comp.versions.join(', ') }}</span>
                            <span class="ml-2 text-[10px] font-normal text-blue-300">({{ comp.tag }})</span>
                        </span>
                    </div>
                </div>

                <div v-if="affectedTaggedComponents.length > 0" class="space-y-2">
                    <h4 class="text-[10px] font-bold uppercase tracking-wider text-gray-500">Affected components with team tags</h4>
                    <div class="flex flex-wrap gap-1.5">
                        <span
                            v-for="comp in affectedTaggedComponents"
                            :key="comp.name"
                            class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-gray-800 text-gray-300 border border-gray-700"
                        >
                            {{ comp.name }}
                            <span v-if="comp.versions.length" class="text-gray-500">@{{ comp.versions.join(', ') }}</span>
                            <span class="ml-2 text-[10px] font-normal text-blue-300">({{ comp.tag }})</span>
                        </span>
                    </div>
                </div>

                <div v-if="uniqueComponents.length > 0" data-testid="affected-components" class="space-y-2">
                    <h4 class="text-[10px] font-bold uppercase tracking-wider text-gray-500">Affected Components</h4>
                    <div class="flex flex-wrap gap-1.5">
                        <span
                            v-for="comp in uniqueComponents"
                            :key="comp.name"
                            class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-gray-800 text-gray-300 border border-gray-700"
                        >
                            {{ comp.name }}<span class="text-gray-500">@{{ comp.versions.join(', ') }}</span>
                        </span>
                    </div>
                </div>
            </div>
            </DetailSection>

            <DetailSection
                step="Context · 3"
                title="Dependency context"
                description="Trace how each affected component enters the product and confirm the dependency relationship used for analysis."
                data-testid="dependency-context"
            >
                <VulnGroupCardDependencies
                    :instances="visibleInstances"
                    :embedded="false"
                    :showTitle="false"
                    @mapping-updated="handleMappingUpdated"
                />
            </DetailSection>

            <DetailSection
                step="Context · 4"
                title="Existing assessment evidence"
                description="Read-only evidence already stored for findings in the current component scope. Create or change the assessment in the Assessment tab."
                bodyClass="space-y-3"
                data-testid="vulnerability-assessments"
            >
                <VulnGroupAssessmentDetails
                    v-for="assessment in groupedAssessments"
                    :key="`${assessment.state}-${assessment.instances.length}`"
                    :assessment="assessment"
                    :isReviewer="isReviewer"
                    :showDependencies="false"
                    @apply-all="handleApplyAllAssessment"
                    @adopt-team="handleAdoptTeamBlock"
                    @mapping-updated="handleMappingUpdated"
                />
            </DetailSection>
        </section>

        <section
            v-show="activeDetailTab === 'analysis'"
            :id="detailTabPanelId('analysis')"
            :aria-labelledby="detailTabId('analysis')"
            class="space-y-3"
            role="tabpanel"
        >
            <CodeAnalysisPanel
                :vulnId="group.id"
                :vulnAliases="group.aliases"
                :projectName="codeAnalysisProjectName"
                :cvssVector="group.cvss_vector"
                :componentNames="codeAnalysisComponents"
                :componentTeams="codeAnalysisComponentTeams"
                :teamScope="activeTeamScope"
                :teamScopeAliases="activeTeamScopeAliases"
                :projectVersions="sortedAffectedProjectVersions"
                :assessedTeams="assessedTeams"
                :analysisGuidance="codeAnalysisGuidance"
                :currentState="state"
                :currentJustification="justification"
                :currentDetails="details"
                :currentTeam="activeTeamScope || selectedTeam || 'General'"
                :currentCvssScore="pendingScore"
                :currentCvssVector="pendingVector"
                :currentAssigned="currentAssigned"
                :assessmentStatus="props.automaticAssessmentStatus"
                :isReviewer="isReviewer"
                @apply-result="handleCodeAnalysisResult"
                @apply-all-results="handleApplyAllCodeAnalysisResults"
                @result-change="handleCodeAnalysisResultChange"
                @scope-results-change="scopedCodeAnalysisAvailable = $event"
                @proposals-change="handleCodeAnalysisProposalsChange"
            />
        </section>

        <section
            v-show="activeDetailTab === 'review'"
            :id="detailTabPanelId('review')"
            :aria-labelledby="detailTabId('review')"
            class="space-y-3"
            role="tabpanel"
        >
            <div class="rounded-lg border border-blue-800/40 bg-blue-950/10 px-4 py-3">
                <h3 class="flex items-center gap-2 text-sm font-bold text-blue-100">
                    <Shield :size="15" class="text-blue-400" />
                    Assessment
                </h3>
                <p class="mt-1 max-w-4xl text-xs leading-relaxed text-gray-500">
                    Confirm the scope, record the decision and rationale, then complete the review checks before saving or submitting.
                </p>
            </div>
            <div
                v-if="!isReviewer"
                data-testid="assessment-completeness"
                class="rounded border px-3 py-2.5 text-xs"
                :class="assessmentMissingFields.length
                    ? 'border-amber-700/40 bg-amber-950/20 text-amber-100'
                    : 'border-green-700/40 bg-green-950/20 text-green-100'"
            >
                <div class="font-bold">
                    {{ assessmentMissingFields.length ? 'Assessment needs input' : 'Assessment is ready to submit' }}
                </div>
                <div class="mt-1 opacity-75">
                    <template v-if="assessmentMissingFields.length">
                        Complete {{ assessmentMissingFields.join(', ') }}.
                    </template>
                    <template v-else>
                        Review the team, state, justification, and details before submitting for review.
                    </template>
                </div>
            </div>
            <div
                v-if="codeAnalysisDraftApplied"
                data-testid="code-analysis-draft-banner"
                class="rounded border border-cyan-700/40 bg-cyan-950/20 px-3 py-2 text-xs text-cyan-200"
            >
                {{ codeAnalysisDraftSummary || 'Code analysis draft loaded into the assessment fields.' }}
                Review and {{ isReviewer ? 'save' : 'submit' }} when ready.
            </div>
            <div class="h-fit space-y-5">
                    <!-- Team Tabs -->
                    <DetailSection
                        step="Assessment · 1"
                        :title="selectedTeam ? `Team Assessment: ${selectedTeam}` : isReviewer ? 'Global Assessment' : 'Team Assessment'"
                        :description="selectedTeam ? `Editing the ${selectedTeam} team assessment.` : isReviewer ? 'Editing the global assessment.' : 'Select the team assessment to edit.'"
                    >
                        <div
                            v-if="activeTeamScope"
                            data-testid="assessment-team-scope"
                            class="mb-2 flex flex-wrap items-center justify-between gap-2 rounded border border-blue-800/40 bg-blue-950/20 px-3 py-2 text-[11px] text-blue-200"
                        >
                            <span>
                                Assessment scope: <strong>{{ activeTeamScope }}</strong>
                                <template v-if="!isReviewer"> · other teams are hidden</template>
                            </span>
                            <button
                                v-if="isReviewer"
                                type="button"
                                data-testid="toggle-assessment-team-scope"
                                class="rounded border border-blue-700/60 bg-blue-900/30 px-2 py-1 font-semibold text-blue-100 transition-colors hover:bg-blue-900/55"
                                @click="toggleAssessmentTeamScope"
                            >
                                {{ showAllAssessmentTeams ? `Focus ${activeTeamScope}` : 'Show all teams' }}
                            </button>
                        </div>
                        <div class="flex flex-wrap gap-0 border-b border-gray-700">
                            <button
                                v-if="isReviewer"
                                @click="selectedTeam = ''"
                                :class="[
                                    'px-3 py-1.5 text-xs font-semibold border-b-2 transition-colors cursor-pointer',
                                    !selectedTeam
                                        ? 'border-purple-500 text-purple-300 bg-purple-950/20'
                                        : 'border-transparent text-gray-500 hover:text-gray-300'
                                ]"
                            >
                                Global
                                <span v-if="teamBlockMeta('General')" class="ml-1 inline-block w-1.5 h-1.5 rounded-full" :class="teamBlockStateColor(teamBlockMeta('General')!.state)"></span>
                            </button>
                            <button
                                v-for="team in teamTabs"
                                :key="team"
                                data-testid="review-team-tab"
                                @click="selectedTeam = team"
                                :class="[
                                    'px-3 py-1.5 text-xs font-semibold border-b-2 transition-colors cursor-pointer',
                                    selectedTeam === team
                                        ? 'border-blue-500 text-blue-300 bg-blue-950/20'
                                        : 'border-transparent text-gray-500 hover:text-gray-300'
                                ]"
                            >
                                {{ team }}
                                <span v-if="assessedTeams.has(team)" class="ml-1 inline-block w-1.5 h-1.5 rounded-full" :class="teamBlockStateColor(teamBlockMeta(team)?.state)"></span>
                            </button>
                        </div>

                        <div
                            v-if="selectedTeam"
                            data-testid="assessment-team-components"
                            class="mt-2 flex flex-wrap items-center gap-1.5 text-[10px]"
                        >
                            <span class="font-semibold uppercase tracking-wide text-gray-500">
                                {{ selectedAssessmentTeamComponents.length === 1 ? 'Component' : 'Components' }} for {{ selectedTeam }}:
                            </span>
                            <span
                                v-for="component in selectedAssessmentTeamComponents"
                                :key="component"
                                class="rounded border border-blue-800/60 bg-blue-950/30 px-1.5 py-0.5 font-mono text-blue-200"
                            >
                                {{ component }}
                            </span>
                            <span v-if="selectedAssessmentTeamComponents.length === 0" class="text-amber-300">
                                No mapped component
                            </span>
                        </div>

                        <!-- Block header metadata (read-only) -->
                        <div v-if="teamBlockMeta(selectedTeam || 'General')" class="flex flex-wrap items-center gap-2 mt-2 text-[10px] text-gray-500">
                            <span v-if="teamBlockMeta(selectedTeam || 'General')!.user && teamBlockMeta(selectedTeam || 'General')!.user !== 'Unknown'">
                                Assessed by <span class="text-gray-400">{{ teamBlockMeta(selectedTeam || 'General')!.user }}</span>
                            </span>
                            <span v-if="teamBlockMeta(selectedTeam || 'General')!.timestamp">
                                {{ new Date(teamBlockMeta(selectedTeam || 'General')!.timestamp!).toLocaleDateString() }}
                            </span>
                        </div>

                        <div
                            v-if="isReviewer && !selectedTeam && effectiveTeamAssessments.length"
                            data-testid="effective-team-assessment-summary"
                            class="mt-3 border-l-2 border-purple-500/60 bg-purple-950/10 px-3 py-2.5"
                        >
                            <div class="flex flex-wrap items-start justify-between gap-3">
                                <div>
                                    <div class="text-[9px] font-bold uppercase tracking-wider text-purple-300">Effective team summary</div>
                                    <div class="mt-0.5 text-xs text-gray-400">
                                        Team assessments take precedence; the latest analyzer proposal fills only missing teams.
                                    </div>
                                </div>
                                <div class="flex items-center gap-2">
                                    <span v-if="effectiveAssessmentWorst" class="text-[10px] text-gray-500">
                                        Worst: <strong class="text-gray-200">{{ effectiveAssessmentWorst.state.replaceAll('_', ' ') }}</strong>
                                    </span>
                                    <button
                                        v-if="effectiveAssessmentWorst"
                                        type="button"
                                        data-testid="use-effective-assessment-summary"
                                        class="rounded bg-purple-700/70 px-2.5 py-1.5 text-[10px] font-bold text-white hover:bg-purple-600"
                                        @click="applyEffectiveAssessmentSummary"
                                    >
                                        Use for global assessment
                                    </button>
                                </div>
                            </div>
                            <div class="mt-2 divide-y divide-gray-800/70">
                                <div
                                    v-for="assessment in effectiveTeamAssessments"
                                    :key="assessment.team"
                                    class="flex flex-wrap items-center justify-between gap-2 py-1.5 text-[10px]"
                                >
                                    <span class="font-semibold text-gray-300">{{ assessment.team }}</span>
                                    <span class="flex items-center gap-2">
                                        <span :class="assessment.source === 'team' ? 'text-blue-300' : assessment.source === 'automatic' ? 'text-cyan-300' : 'text-gray-600'">
                                            {{ assessment.source === 'team' ? 'Team assessment' : assessment.source === 'automatic' ? 'Analyzer fallback' : 'Missing' }}
                                        </span>
                                        <span class="font-semibold text-gray-400">{{ assessment.state.replaceAll('_', ' ') }}</span>
                                    </span>
                                </div>
                            </div>
                        </div>
                    </DetailSection>

                    <DetailSection
                        step="Assessment · 2"
                        title="Decision & rationale"
                        description="Set the assessment state, justification, technical rationale, ownership, and any reviewer-only rescoring context."
                        data-testid="assessment-decision-section"
                    >
                    <template #actions>
                        <div class="flex shrink-0 items-center gap-2" data-testid="assessment-decision-actions">
                            <button
                                type="button"
                                @click="() => handleUpdate(false)"
                                :disabled="!canApplyAssessment"
                                data-testid="assessment-submit-button"
                                class="rounded bg-blue-600 px-3 py-2 text-xs font-bold text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                                {{ assessmentActionLabel }}
                            </button>
                            <button
                                type="button"
                                @click="refreshDetails"
                                :disabled="updating || loadingDetails"
                                class="rounded border border-gray-600 bg-gray-800 px-3 py-2 text-gray-300 transition-colors hover:bg-gray-700 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
                                title="Reload from server (discard local changes)"
                                aria-label="Reload assessment from server"
                            >
                                <RefreshCw :size="14" :class="{ 'animate-spin': loadingDetails }" />
                            </button>
                        </div>
                    </template>
                    <div
                        v-if="selectedTeam && selectedAutomaticProposal"
                        data-testid="automatic-assessment-proposal"
                        class="mb-4 border-l-2 border-cyan-500/70 bg-cyan-950/10 px-3 py-2.5"
                    >
                        <div class="flex flex-wrap items-start justify-between gap-3">
                            <div class="min-w-0 flex-1">
                                <div class="flex flex-wrap items-center gap-2">
                                    <span class="text-[9px] font-bold uppercase tracking-wider text-cyan-300">Analyzer proposal</span>
                                    <span class="text-xs font-bold text-gray-200">{{ selectedAutomaticProposal.state.replaceAll('_', ' ') }}</span>
                                    <span class="text-[10px] text-gray-500">{{ selectedAutomaticProposalRuns.length }} target{{ selectedAutomaticProposalRuns.length === 1 ? '' : 's' }}</span>
                                </div>
                                <p v-if="selectedAutomaticProposalSummary" class="mt-1 text-xs leading-relaxed text-gray-300">
                                    {{ selectedAutomaticProposalSummary }}
                                </p>
                                <p v-if="selectedAutomaticProposalRationale" class="mt-1 text-[11px] leading-relaxed text-gray-500">
                                    <span class="font-semibold text-gray-400">Rationale:</span> {{ selectedAutomaticProposalRationale }}
                                </p>
                                <p class="mt-1.5 text-[10px] text-gray-600">
                                    {{ teamBlockMeta(selectedTeam)?.state && teamBlockMeta(selectedTeam)?.state !== 'NOT_SET'
                                        ? 'The saved team assessment remains authoritative unless you choose this proposal and save it.'
                                        : 'Until the team saves an assessment, reviewers use this proposal as the team fallback.' }}
                                </p>
                            </div>
                            <div class="flex shrink-0 flex-wrap items-center gap-2">
                                <button
                                    v-if="selectedTeamTicketText"
                                    type="button"
                                    data-testid="copy-team-ticket"
                                    class="rounded border border-cyan-700/70 bg-cyan-950/40 px-2.5 py-1.5 text-[10px] font-bold text-cyan-100 hover:bg-cyan-900/60"
                                    :class="assessmentTicketCopyState === 'error' ? 'border-amber-600/80 text-amber-200' : ''"
                                    @click="copySelectedTeamTicket"
                                >
                                    {{ assessmentTicketCopyState === 'copied'
                                        ? 'Ticket copied'
                                        : assessmentTicketCopyState === 'error'
                                            ? 'Copy failed'
                                            : 'Copy ticket' }}
                                </button>
                                <button
                                    type="button"
                                    data-testid="use-automatic-assessment-proposal"
                                    class="rounded bg-cyan-700/80 px-2.5 py-1.5 text-[10px] font-bold text-white hover:bg-cyan-600"
                                    @click="applySelectedAutomaticProposal"
                                >
                                    Use proposal
                                </button>
                            </div>
                        </div>
                    </div>
                    <div :class="isReviewer && !selectedTeam ? 'grid items-start gap-4 xl:grid-cols-2' : ''">
                        <section
                            v-if="isReviewer && !selectedTeam"
                            data-testid="global-cvss-rescoring"
                            class="min-w-0 space-y-4 rounded border border-gray-700 bg-gray-900/45 p-3"
                        >
                            <div class="flex flex-wrap items-center justify-between gap-2">
                                <h5 class="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-gray-300">
                                    <Calculator :size="13" class="text-purple-300" />
                                    CVSS & Rescoring
                                </h5>
                                <span class="text-[10px] text-gray-500">Applied with the global assessment</span>
                            </div>

                            <div class="rounded border border-gray-700 bg-gray-800 p-3">
                                <h6 class="mb-2 flex items-center gap-2 text-xs font-bold text-gray-300">
                                    <Calculator :size="12" />
                                    CVSS Calculator
                                </h6>

                                <div class="mb-2">
                                    <label for="cvss-vector-input" class="mb-1 flex justify-between text-xs font-semibold text-gray-500">
                                        <span>Vector String</span>
                                        <div class="flex items-center gap-2">
                                            <button
                                                @click="resetVector"
                                                class="flex cursor-pointer items-center gap-1 text-gray-400 hover:text-white"
                                                title="Reset to Original"
                                            >
                                                <RotateCcw :size="10" />
                                            </button>
                                            <button
                                                v-if="rescoreRulesOutOfSync"
                                                data-testid="sync-rescore-rules"
                                                @click="syncRescoreRules"
                                                class="flex cursor-pointer items-center gap-1 text-amber-300 hover:text-amber-200"
                                                title="Apply the configured rules for the current assessment state; then save the assessment"
                                            >
                                                <RefreshCw :size="10" /> Sync rules
                                            </button>
                                            <button
                                                @click="cleanRescoredVector"
                                                class="flex cursor-pointer items-center gap-1 text-purple-300 hover:text-purple-200"
                                                title="Clean unresolved modifiers/requirements"
                                            >
                                                Clean
                                            </button>
                                            <button
                                                @click="showCalculatorModal = true"
                                                class="flex cursor-pointer items-center gap-1 text-blue-400 hover:text-blue-300"
                                            >
                                                <ExternalLink :size="10" /> Visual Calculator
                                            </button>
                                        </div>
                                    </label>
                                    <input
                                        id="cvss-vector-input"
                                        v-model="pendingVector"
                                        type="text"
                                        placeholder="CVSS:4.0/AV:N/..."
                                        class="w-full rounded border border-gray-600 bg-gray-900 p-1.5 font-mono text-xs focus:border-blue-500"
                                    />
                                    <div v-if="group.cvss_vector && group.cvss_vector !== pendingVector" class="mt-1 flex gap-1.5 truncate text-[9px] text-gray-500/60">
                                        <span class="shrink-0 font-bold uppercase">Original:</span>
                                        <span class="truncate italic">{{ group.cvss_vector }}</span>
                                    </div>
                                </div>

                                <div class="flex items-center justify-between">
                                    <label for="cvss-score-input" class="block text-xs font-semibold text-gray-500">Score</label>
                                    <input
                                        id="cvss-score-input"
                                        v-model.number="pendingScore"
                                        type="number"
                                        :readonly="!canEditBase"
                                        step="0.1"
                                        min="0"
                                        max="10"
                                        class="w-16 rounded border border-gray-600 bg-gray-900 p-1.5 text-right text-sm font-bold text-yellow-400 focus:border-blue-500 disabled:opacity-50"
                                        :class="{ 'cursor-not-allowed text-gray-500': !canEditBase }"
                                    />
                                </div>
                            </div>

                            <section v-if="cvssVectorEntries.length || matchedProposal || latestCodeAnalysisCvssAdjustment" class="space-y-3">
                                <div v-if="matchedProposal" class="flex justify-end">
                                    <button
                                        @click="applyProposal"
                                        class="inline-flex cursor-pointer items-center gap-1 rounded border border-teal-500/40 bg-teal-600/25 px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide text-teal-200 transition-colors hover:bg-teal-600/45 hover:text-white"
                                    >
                                        <Zap :size="10" />
                                        Use Proposal Draft
                                    </button>
                                </div>

                                <CvssVectorDisplay
                                    v-if="cvssVectorEntries.length"
                                    :vectors="cvssVectorEntries"
                                />

                                <div
                                    v-if="hasCodeAnalysisCvssNotes && latestCodeAnalysisCvssAdjustment"
                                    class="rounded border border-gray-800 bg-gray-900/45 px-3 py-2 text-xs leading-relaxed text-gray-400"
                                >
                                    <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
                                        <span class="font-bold uppercase tracking-wider text-gray-500">Analyzer notes</span>
                                        <span v-if="codeAnalysisCvssComponentLabel" class="text-[10px] font-semibold uppercase tracking-wide text-gray-600">
                                            {{ codeAnalysisCvssComponentLabel }}
                                        </span>
                                    </div>
                                    <p v-if="latestCodeAnalysisCvssAdjustment.summary" class="mt-1">
                                        {{ latestCodeAnalysisCvssAdjustment.summary }}
                                    </p>
                                    <ul v-if="latestCodeAnalysisCvssAdjustment.reasons?.length" class="mt-1 list-inside list-disc space-y-0.5 text-gray-500">
                                        <li v-for="(reason, idx) in latestCodeAnalysisCvssAdjustment.reasons" :key="idx">{{ reason }}</li>
                                    </ul>
                                </div>

                                <div v-if="matchedProposal" class="rounded border border-teal-800/45 bg-teal-950/15 p-3">
                                    <div class="mb-2 flex items-center justify-between gap-2">
                                        <h6 class="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-teal-300">
                                            <Zap :size="12" />
                                            Threat Model Proposal
                                        </h6>
                                        <div class="flex items-center gap-3 text-xs">
                                            <div class="font-bold text-teal-300">
                                                {{ matchedProposal.rescored_score ?? 'N/A' }}
                                                <span v-if="matchedProposal.rescored_severity" class="ml-1 text-[9px] uppercase opacity-70">({{ matchedProposal.rescored_severity }})</span>
                                            </div>
                                            <div v-if="matchedProposal.original_score != null" class="text-gray-500">
                                                <span class="text-[9px] uppercase">from</span>
                                                {{ matchedProposal.original_score }}
                                                <span v-if="matchedProposal.original_severity" class="ml-1 text-[9px] uppercase opacity-70">({{ matchedProposal.original_severity }})</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div v-if="matchedProposal.analysis?.detail" class="mt-2 border-t border-teal-800/30 pt-2 text-xs leading-relaxed text-gray-400">
                                        <span class="mb-0.5 block text-[9px] font-bold uppercase text-gray-500">Reasoning</span>
                                        {{ matchedProposal.analysis.detail }}
                                    </div>
                                    <div v-if="matchedProposal.analysis?.response?.length" class="mt-2 border-t border-teal-800/30 pt-2 text-xs leading-relaxed text-gray-400">
                                        <span class="mb-0.5 block text-[9px] font-bold uppercase text-gray-500">Analysis</span>
                                        <ul class="list-inside list-disc space-y-0.5">
                                            <li v-for="(resp, idx) in matchedProposal.analysis.response" :key="idx">
                                                {{ typeof resp === 'string' ? resp : (resp.detail || resp.title || '') }}
                                            </li>
                                        </ul>
                                    </div>
                                </div>
                            </section>
                        </section>

                        <!-- Assessment Section (Reviewer Global or Team Selected) -->
                        <div v-if="selectedTeam || isReviewer" :class="['border rounded p-3', selectedTeam ? 'border-blue-700/50 bg-blue-950/20' : 'border-purple-700/50 bg-purple-950/20']">
                            <div class="space-y-3">
                                <div>
                                    <label id="analysis-state-label" for="analysis-state-select" class="block text-xs font-semibold text-gray-400 mb-1">Analysis State</label>
                                    <CustomSelect
                                        id="analysis-state-select"
                                        aria-labelledby="analysis-state-label"
                                        :modelValue="state"
                                        @update:modelValue="state = $event; formTouched = true; markSelectedTeamAssessmentManual()"
                                        :options="ANALYSIS_STATES"
                                        size="sm"
                                    />
                                </div>

                                <div v-if="state === 'NOT_AFFECTED'">
                                    <label id="justification-label" for="justification-select" class="block text-xs font-semibold text-gray-400 mb-1">Justification</label>
                                    <CustomSelect
                                        id="justification-select"
                                        aria-labelledby="justification-label"
                                        :modelValue="justification"
                                        @update:modelValue="justification = $event; formTouched = true; markSelectedTeamAssessmentManual()"
                                        :options="JUSTIFICATION_OPTIONS"
                                        size="sm"
                                    />
                                </div>

                                <div>
                                    <label for="analysis-details-textarea" class="block text-xs font-semibold text-gray-400 mb-1">Analysis Details</label>
                                    <textarea
                                        id="analysis-details-textarea"
                                        v-model="details"
                                        @input="formTouched = true; markSelectedTeamAssessmentManual()"
                                        placeholder="Technical details..."
                                        class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500 h-48 resize-y text-sm"
                                    ></textarea>
                                </div>

                                <!-- Assignees -->
                                <div>
                                    <label for="assigned-users-input" class="block text-xs font-semibold text-gray-400 mb-1">Assigned Users</label>
                                    <div class="flex flex-wrap gap-1 mb-1.5">
                                        <span
                                            v-for="assignee in currentAssigned"
                                            :key="assignee"
                                            class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-blue-500/20 text-blue-200 text-[11px] font-medium"
                                        >
                                            {{ assignee }}
                                            <button @click="removeAssignee(assignee)" class="hover:text-white text-blue-300/70 leading-none cursor-pointer">&times;</button>
                                        </span>
                                    </div>
                                    <div class="relative">
                                        <input
                                            id="assigned-users-input"
                                            v-model="assigneeInput"
                                            @input="onAssigneeInput"
                                            @keydown.enter.prevent="addAssigneeFromInput"
                                            @keydown.tab.prevent="addAssigneeFromInput"
                                            type="text"
                                            placeholder="Type username and press Enter..."
                                            class="w-full p-1.5 rounded bg-gray-900 border border-gray-600 focus:border-blue-500 text-xs"
                                            @blur="assigneeSuggestionsVisible = false"
                                        />
                                        <div v-if="assigneeSuggestionsVisible && filteredUserSuggestions.length > 0"
                                             class="absolute z-50 mt-1 w-full bg-gray-800 border border-gray-600 rounded shadow-lg max-h-32 overflow-y-auto">
                                            <button
                                                v-for="suggestion in filteredUserSuggestions"
                                                :key="suggestion"
                                                @mousedown.prevent="selectAssigneeSuggestion(suggestion)"
                                                class="w-full text-left px-3 py-1.5 text-xs text-gray-300 hover:bg-blue-500/20 hover:text-blue-200 transition-colors cursor-pointer"
                                            >
                                                {{ suggestion }}
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div v-if="isReviewer" data-testid="review-context" class="rounded border border-gray-700 bg-gray-900/45 p-3">
                                    <div class="mb-2 flex flex-wrap items-center justify-between gap-2">
                                        <h5 class="text-xs font-bold uppercase tracking-wider text-gray-400">Review Context</h5>
                                        <span
                                            class="text-[10px] font-semibold"
                                            :class="ticketReferenceMissing ? 'text-amber-300' : 'text-gray-500'"
                                        >
                                            {{ reviewContextRequiredCompleted }}/{{ reviewContextRequiredTotal }} required
                                        </span>
                                    </div>
                                    <div class="grid gap-2 sm:grid-cols-2">
                                        <label class="flex items-center gap-2 rounded border border-gray-800 bg-gray-950/40 px-2 py-1.5 text-xs text-gray-300">
                                            <input
                                                v-model="evidenceReviewed"
                                                type="checkbox"
                                                class="h-3.5 w-3.5 rounded border-gray-600 bg-gray-900 text-blue-500"
                                                @change="formTouched = true"
                                            />
                                            Evidence reviewed
                                        </label>
                                        <label class="flex items-center gap-2 rounded border border-gray-800 bg-gray-950/40 px-2 py-1.5 text-xs text-gray-300">
                                            <input
                                                v-model="versionCoverageChecked"
                                                type="checkbox"
                                                class="h-3.5 w-3.5 rounded border-gray-600 bg-gray-900 text-blue-500"
                                                @change="formTouched = true"
                                            />
                                            Version coverage checked
                                        </label>
                                        <label class="sm:col-span-2">
                                            <span class="mb-1 flex flex-wrap items-center justify-between gap-2">
                                                <span class="block text-[11px] font-semibold uppercase tracking-wide text-gray-500">Ticket reference</span>
                                                <span
                                                    data-testid="ticket-requirement-badge"
                                                    class="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide"
                                                    :class="isTicketReferenceRequired
                                                        ? 'border-amber-700/50 bg-amber-950/30 text-amber-200'
                                                        : 'border-gray-700 bg-gray-950/50 text-gray-500'"
                                                >
                                                    {{ isTicketReferenceRequired ? 'Required' : 'Optional' }}
                                                </span>
                                            </span>
                                            <input
                                                v-model="ticketReference"
                                                type="text"
                                                placeholder="e.g. SEC-1234 or remediation ticket"
                                                :aria-required="isTicketReferenceRequired ? 'true' : 'false'"
                                                class="w-full rounded border bg-gray-950 px-2 py-1.5 text-xs text-gray-200 focus:border-blue-500"
                                                :class="ticketReferenceMissing ? 'border-amber-600/80' : 'border-gray-700'"
                                                @input="formTouched = true"
                                            />
                                            <span class="mt-1 block text-[10px] text-gray-600">{{ ticketRequirementHelp }}</span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- No-Team Section (Prompt for non-reviewers) -->
                    <div v-if="!selectedTeam && !isReviewer" class="p-4 rounded border border-gray-700 bg-gray-800/50 flex flex-col items-center justify-center text-center space-y-2">
                        <Shield :size="32" class="text-blue-500/50" />
                        <h4 class="text-sm font-bold text-gray-300">{{ activeTeamScope ? 'Team Mapping Required' : 'Select a Team Tab' }}</h4>
                        <p class="text-xs text-gray-400 max-w-xs">
                          {{ activeTeamScope
                              ? `No component assessment target currently resolves to ${activeTeamScope}. Ask a reviewer to correct the mapping.`
                              : 'Global assessments are restricted to reviewers. Select a team tab above to provide an assessment.' }}
                        </p>
                    </div>

                    <div v-if="isReviewer && (!activeTeamScope || showAllAssessmentTeams || !selectedTeam)">
                        <button
                            @click="toggleRawEdit"
                            class="text-xs text-gray-500 hover:text-gray-300 transition-colors cursor-pointer flex items-center gap-1"
                        >
                            <ChevronDown v-if="!showRawEdit" :size="12" />
                            <ChevronUp v-else :size="12" />
                            Raw Assessment Text
                        </button>
                        <div v-if="showRawEdit" class="mt-1">
                            <textarea
                                v-model="rawDetails"
                                @input="rawDetailsTouched = true; formTouched = true"
                                class="w-full p-2 rounded bg-gray-900 border border-gray-700 text-gray-300 text-xs font-mono h-32 resize-y"
                            ></textarea>
                            <p class="text-[10px] text-gray-600 mt-0.5">Edit the full structured assessment text. Changes here override block-level edits on submit.</p>
                        </div>
                    </div>

                    <div v-if="isReviewer && (!activeTeamScope || showAllAssessmentTeams || !selectedTeam)" class="flex items-center gap-2">
                        <input
                            type="checkbox"
                            :id="`suppress-${group.id}`"
                            v-model="suppressed"
                            class="w-4 h-4 rounded"
                            @change="formTouched = true"
                        />
                        <label :for="`suppress-${group.id}`" class="text-sm">Suppress this vulnerability</label>
                    </div>

                    <div
                        v-if="isReviewer && !selectedTeam && mergedAssessmentData.blocks.length > 0 && (assessmentSyncIssues.length > 0 || displayState === 'INCOMPLETE')"
                        class="pt-2 border-t border-gray-700 mt-2"
                    >
                        <div
                            v-if="assessmentSyncIssues.length > 0"
                            data-testid="assessment-sync-reasons"
                            class="mb-2 rounded border p-2.5"
                            :class="displayState === 'INCONSISTENT'
                                ? 'border-indigo-500/30 bg-indigo-950/20'
                                : 'border-amber-600/30 bg-amber-950/20'"
                        >
                            <div
                                class="mb-1.5 text-[10px] font-black uppercase tracking-widest"
                                :class="displayState === 'INCONSISTENT' ? 'text-indigo-300' : 'text-amber-400'"
                            >
                                {{ displayState === 'INCONSISTENT'
                                    ? 'Why manual resolution is needed'
                                    : 'Why synchronization is needed' }}
                            </div>
                            <div
                                v-for="issue in assessmentSyncIssues"
                                :key="issue.code"
                                class="text-[11px] leading-relaxed"
                                :class="issue.kind === 'inconsistent' ? 'text-indigo-100/80' : 'text-amber-100/80'"
                            >
                                <span
                                    class="font-bold"
                                    :class="issue.kind === 'inconsistent' ? 'text-indigo-300' : 'text-amber-300'"
                                >{{ issue.label }}:</span>
                                {{ issue.detail }}
                            </div>
                        </div>
                        <button
                            v-if="displayState === 'INCOMPLETE'"
                            data-testid="sync-all-assessments"
                            @click="syncAllAssessments"
                            class="w-full mb-2 bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-500 border border-yellow-600/50 font-bold py-1.5 rounded text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
                        >
                            <AlertTriangle :size="14" />
                            Sync all
                        </button>
                    </div>
                    </DetailSection>
            </div>
        </section>

        <section
            v-if="isReviewer"
            v-show="activeDetailTab === 'mapping'"
            :id="detailTabPanelId('mapping')"
            :aria-labelledby="detailTabId('mapping')"
            class="space-y-3"
            role="tabpanel"
        >
            <div class="rounded-lg border border-purple-800/40 bg-purple-950/10 px-4 py-3">
                <h3 class="flex items-center gap-2 text-sm font-bold text-purple-100">
                    <Tags :size="15" class="text-purple-400" />
                    Team mapping
                </h3>
                <p class="mt-1 max-w-4xl text-xs leading-relaxed text-gray-500">
                    Confirm component ownership so Context, Code Evidence, and Assessment use the same team scope.
                </p>
            </div>
            <DetailSection
                step="Team mapping · 1"
                title="Affected component ownership"
                description="Review or change the mapping for components visible in this vulnerability."
            >
                <VulnGroupCardDependencies
                    :instances="visibleInstances"
                    mode="mapping"
                    @mapping-updated="handleMappingUpdated"
                />
            </DetailSection>
        </section>
    </div>

    <!-- Grouped Calculator Modal -->
    <CalculatorModal
      v-if="isReviewer"
      :show="showCalculatorModal"
      :activeVersion="activeVersion"
      :visibleVersions="visibleVersions"
      :canEditBase="canEditBase"
      :pendingVector="pendingVector"
      :pendingScore="pendingScore"
      :cvssInstance="cvssInstance"
      @close="showCalculatorModal = false"
      @clear="clearVector"
      @reset="resetVector"
      @switch-version="switchVersion"
      @update-vector="updateCalcVector"
    />

    <!-- Conflict Resolution Modal -->
    <ConflictResolutionModal
      :show="showConflictModal"
      :conflictData="conflictData"
      @close="showConflictModal = false"
      @use-server-state="handleUseServerState"
      @force-overwrite="() => handleUpdate(true)"
    />

    <GenericModal
      :show="genericModal.show"
      :title="genericModal.title"
      :message="genericModal.message"
      :confirmOnly="genericModal.confirmOnly"
      :confirmLabel="genericModal.confirmLabel"
      :cancelLabel="genericModal.cancelLabel"
      :discardLabel="genericModal.discardLabel"
      @response="handleModalResponse"
    />

    <AssessmentReviewModal
      :show="reviewModal.show"
      :blocks="reviewModal.blocks"
      :aggregatedState="reviewModal.aggregatedState"
      :sanitizedText="reviewModal.sanitizedText"
      :duplicatesRemoved="reviewModal.duplicatesRemoved"
      :isReviewer="isReviewer"
      :selectedTeam="selectedTeam"
      @confirm="handleReviewConfirm"
      @cancel="handleReviewCancel"
    />
</div>
</template>

<style scoped>
@reference "../style.css";

.scale-in-center {
	animation: scale-in-center 0.15s cubic-bezier(0.250, 0.460, 0.450, 0.940) both;
}
@keyframes scale-in-center {
  0% { transform: scale(0.95); opacity: 0; }
  100% { transform: scale(1); opacity: 1; }
}

.stripe-bg {
    background-image: repeating-linear-gradient(
        45deg,
        transparent,
        transparent 10px,
        rgba(99, 102, 241, 0.03) 10px,
        rgba(99, 102, 241, 0.03) 20px
    );
}

.advisory-markdown :deep(p) {
    @apply mb-3 last:mb-0;
}

.advisory-markdown :deep(ul) {
    @apply mb-3 ml-5 list-disc space-y-1;
}

.advisory-markdown :deep(ol) {
    @apply mb-3 ml-5 list-decimal space-y-1;
}

.advisory-markdown :deep(li) {
    @apply pl-1;
}

.advisory-markdown :deep(a) {
    @apply text-blue-300 underline decoration-blue-500/60 underline-offset-2 break-words;
}

.advisory-markdown :deep(code) {
    @apply rounded bg-gray-900 px-1.5 py-0.5 font-mono text-[0.95em] text-pink-300;
}

.advisory-markdown :deep(pre) {
    @apply mb-3 overflow-x-auto rounded-lg border border-gray-800 bg-gray-950 p-3 text-gray-200;
}

.advisory-markdown :deep(pre code) {
    @apply bg-transparent p-0 text-inherit;
}

.advisory-markdown :deep(blockquote) {
    @apply mb-3 border-l-2 border-gray-700 pl-4 italic text-gray-300;
}

.advisory-markdown :deep(strong) {
    @apply font-semibold text-gray-200;
}
</style>
