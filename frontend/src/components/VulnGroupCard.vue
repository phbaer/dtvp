<script setup lang="ts">
import { ref, computed, watch, inject, onMounted, onUnmounted, nextTick } from 'vue'
import { updateAssessment, getAssessmentDetails, getKnownUsers } from '../lib/api'
import { marked } from 'marked'

import type { GroupedVuln, AssessmentPayload, TMRescoreProposal } from '../types'
import { ChevronDown, ChevronUp, Shield, RefreshCw, AlertTriangle, Calculator, ExternalLink, CheckCircle, RotateCcw, Package, Layers, ShieldOff, Zap } from 'lucide-vue-next'

import { parseAssessmentBlocks, getConsensusAssessment, parseJustificationFromText, hasGlobalAssessment, getAssessedTeams, isPendingReview as isPendingReviewHelper, getGroupLifecycle, getGroupTechnicalState, sanitizeAssessmentDetails, type AssessmentBlock } from '../lib/assessment-helpers'
import { cleanStructuredAssessmentDetails, resolveAssessmentFormValues, resolveDependencyTrackConsensusInput, stripPendingReviewStatus } from '../lib/assessmentFormState'
import { buildRescoredVectorForState, normalizeCvssVectorInstance, type CvssVersion } from '../lib/cvssRescore'
import { buildMergedAssessmentData } from '../lib/mergedAssessmentData'
import { buildSavedAssessmentResultState, buildSavedOriginalAnalysis, prepareAssessmentSubmission } from '../lib/assessmentSubmission'
import { prepareCodeAnalysisResult } from '../lib/codeAnalysisResult'
import { calculateScoreFromVector } from '../lib/cvss'
import { getDerivedGroupTags } from '../lib/dependency-team-selection'
import { useVulnDependencyInfo } from '../lib/useVulnDependencyInfo'
import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'
import CvssVectorDisplay from './CvssVectorDisplay.vue'
import CustomSelect from './CustomSelect.vue'
import VulnGroupCardHeader from './VulnGroupCardHeader.vue'
import VulnGroupAssessmentDetails from './VulnGroupAssessmentDetails.vue'
import CalculatorModal from './CalculatorModal.vue'
import ConflictResolutionModal from './ConflictResolutionModal.vue'
import GenericModal from './GenericModal.vue'
import AssessmentReviewModal from './AssessmentReviewModal.vue'
import CodeAnalysisPanel from './CodeAnalysisPanel.vue'
import type { CodeAnalysisAssessResponse } from '../lib/api'

const props = defineProps<{
  group: GroupedVuln
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

const emit = defineEmits(['update', 'update:assessment', 'toggle-expand'])

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
    if (globalThis.window === undefined || typeof document === 'undefined') return

    document.body.style.position = ''
    document.body.style.top = ''
    document.body.style.left = ''
    document.body.style.right = ''
    document.body.style.width = ''
    document.body.style.overflow = ''
    globalThis.scrollTo(0, bodyScrollLockY)
}

const expanded = ref(false)
const state = ref('NOT_SET')
const details = ref('')
const justification = ref('NOT_SET')
const comment = ref('')
const suppressed = ref(false)
const selectedTeam = ref('')
// Removed onlyTargetSelectedTeam - team selection now automatically targets team instances
const updating = ref(false)
const loadingDetails = ref(false)
const showCalculatorModal = ref(false)
const showConflictModal = ref(false)
const conflictData = ref<any>(null)
const originalAnalysis = ref<Record<string, any>>({}) // Map finding_uuid -> Analysis Object
const teamDrafts = ref<Map<string, { state: string, details: string, justification: string, assigned: string[] }>>(new Map())
const refreshCounter = ref(0)
const formTouched = ref(false)

const isInternalUpdate = ref(false)
const showRawEdit = ref(false)
const rawDetails = ref('')
const rawDetailsTouched = ref(false)

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
    resolve: (_: boolean) => {}
})

const promptConfirm = (title: string, message: string, confirmOnly = false) => {
    genericModal.value = {
        show: true,
        title,
        message,
        confirmOnly,
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

const handleModalResponse = (value: boolean) => {
    genericModal.value.show = false
    genericModal.value.resolve(value)
}

const isReviewer = computed(() => {
    return user?.value?.role === 'REVIEWER'
})

const dependencyInfo = useVulnDependencyInfo({
    group: computed(() => props.group),
    teamMapping,
    refreshCounter,
})

const allInstances = dependencyInfo.allInstances
const getInstanceTeamKey = dependencyInfo.getInstanceTeamKey
const instanceTeams = dependencyInfo.instanceTeams
const effectiveTags = dependencyInfo.effectiveTags

const totalTargeted = computed(() => {
    // When a team is selected, automatically target only that team's instances
    // Fall back to all instances if no instances have the team tag (e.g. virtual teams like 'automation')
    if (selectedTeam.value) {
        const matched = allInstances.value.filter((inst, index) => {
            return (instanceTeams.value.get(getInstanceTeamKey(inst, index)) || []).includes(selectedTeam.value)
        }).length
        return matched > 0 ? matched : allInstances.value.length
    }
    return allInstances.value.length
})

const displayState = computed(() => {
    return getGroupLifecycle(props.group, effectiveTags.value, teamMapping?.value)
})

const technicalState = computed(() => {
    return getGroupTechnicalState(props.group)
})

const consensusButtonLabel = computed(() => {
    return displayState.value === 'INCOMPLETE' ? 'Sync all' : 'Apply worst assessment'

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
    return entries
})

const copyId = () => {
    navigator.clipboard.writeText(props.group.id)
}

const applyProposal = async () => {
    const proposal = matchedProposal.value
    if (!proposal || !proposal.rescored_vector) return

    // Set team first — this triggers updateFormFromGroup via the selectedTeam watcher.
    // We must wait for that reset to complete before applying proposal values.
    selectedTeam.value = 'automation'
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

    // Auto-submit immediately so the automation block is persisted to all
    // instances.  This way, when the user subsequently switches to their own
    // team and submits their assessment, the merge logic already sees the
    // automation block from the server/cache — no second apply needed.
    await handleUpdate(false)
}

const handleCodeAnalysisResult = async (result: CodeAnalysisAssessResponse, components: string[]) => {
    const prepared = prepareCodeAnalysisResult(
        result,
        components,
        triggeringTaggedComponents.value,
        currentAssigned.value,
    )

    for (const draft of prepared.teamDrafts) {
        teamDrafts.value.set(draft.team, {
            state: draft.state,
            details: draft.details,
            justification: draft.justification,
            assigned: draft.assigned,
        })
    }

    selectedTeam.value = prepared.firstTeam ?? ''
    state.value = prepared.targetState
    justification.value = prepared.targetJustification
    details.value = prepared.detailsText

    if (prepared.adjustedVector) {
        pendingVector.value = prepared.adjustedVector
    }
    if (prepared.adjustedScore != null) {
        pendingScore.value = prepared.adjustedScore
    }

    formTouched.value = true
    await handleUpdate(false)
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
            } else if (v.startsWith('CVSS:3.')) {
                activeVersion.value = '3.1'
                if (v.startsWith('CVSS:3.0')) v = v.replace('CVSS:3.0', 'CVSS:3.1')
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
    pendingVector.value = normalizeCvssVectorInstance(cvssInstance.value)
}

const setCvssInstanceFromVector = (vector: string) => {
    if (!vector) return

    let v = vector.trim()
    try {
        if (v.startsWith('CVSS:4.0')) {
            cvssInstance.value = new Cvss4P0(v)
        } else if (v.startsWith('CVSS:3.0')) {
            v = v.replace('CVSS:3.0', 'CVSS:3.1')
            cvssInstance.value = new Cvss3P1(v)
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
        pendingScore.value = score
    }
})

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
})
watch(details, (val, old) => {
    if (!isInternalUpdate.value && val !== old) {
        formTouched.value = true
        if (isDebugPersistenceEnabled()) {
            console.log('[Persistence Debug] details touched by user:', val.slice(0, 50) + '...');
        }
    }
})

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

        comment.value = ''
        
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
            formTouched.value = true
        } else if (force) {
            formTouched.value = false
        }
    } finally {
        isInternalUpdate.value = false
    }
}

const applyConsensusAssessment = () => {
    const allBlocks = mergedAssessmentData.value.blocks
    
    if (allBlocks.length === 0) {
        showAlert('No Analysis Data', 'No assessments found to pull from.')
        return
    }

    const { dtStates, dtJustification } = resolveDependencyTrackConsensusInput(allInstances.value)

    const consensus = getConsensusAssessment(allBlocks, displayState.value as string, dtStates, dtJustification)
    state.value = consensus.state
    justification.value = consensus.justification
    details.value = consensus.details

    // Always trigger a rescore for the resolved state, even if state.value
    // didn't change (the watcher's newState !== oldState guard would skip it).
    if (isReviewer.value) {
        applyStateRescore(consensus.state)
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
    // the state value hasn't changed (same pattern as applyConsensusAssessment).
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
}

watch(selectedTeam, (_newTeam, oldTeam) => {
    // Persist current tab's form edits before switching away
    if (oldTeam !== undefined && formTouched.value) {
        const draftKey = oldTeam || 'General'
        teamDrafts.value.set(draftKey, {
            state: state.value,
            details: details.value,
            justification: justification.value,
            assigned: [...currentAssigned.value]
        })
    }
    updateFormFromGroup()
})

watch(() => props.group, () => updateFormFromGroup(true), { immediate: true })

// Keep raw details in sync with the merged assessment data when not manually edited
watch(() => mergedAssessmentData.value.fullText, (newText) => {
    if (showRawEdit.value && !rawDetailsTouched.value) {
        rawDetails.value = newText
    }
})


watch(expanded, (isOpen) => {
    emit('toggle-expand', props.group.id, isOpen)

    if (isOpen) {
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
 * Extracted so it can be triggered explicitly (e.g. from applyConsensusAssessment)
 * without relying solely on the watch(state) guard.
 */
const applyStateRescore = (targetState: string) => {
    const rules = rescoreRules?.value?.transitions || []
    const result = buildRescoredVectorForState({
        rules,
        targetState,
        currentVector: pendingVector.value,
        fallbackVersion: activeVersion.value,
    })

    if (!result) return

    activeVersion.value = result.version
    pendingVector.value = result.vector
    setCvssInstanceFromVector(result.vector)
}

watch(state, (newState, oldState) => {
    // Only auto-rescore if we're changing states via user interaction.
    // We check `loadingDetails` to avoid rescoring during the initial data load.
    // Note: applyConsensusAssessment calls applyStateRescore() directly to
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
            comment: comment.value,
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


const stateColor = computed(() => {
    switch (technicalState.value) {
        case 'NOT_AFFECTED': return 'text-green-400'
        case 'EXPLOITABLE': return 'text-red-400'
        case 'NOT_SET': return 'text-gray-400'
        case 'IN_TRIAGE': return 'text-amber-400'
        case 'FALSE_POSITIVE': return 'text-teal-400'
        case 'RESOLVED': return 'text-purple-400'
        case 'INCOMPLETE': return 'text-amber-500'
        case 'INCONSISTENT': return 'text-indigo-400'
        default: return 'text-gray-300'
    }
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

const instanceStats = computed(() => {
    const instances = allInstances.value
    const componentSet = new Set(instances.map(i => `${i.component_name}@${i.component_version}`))
    const suppressed = instances.filter(i => i.is_suppressed).length
    return {
        findings: instances.length,
        components: componentSet.size,
        suppressed,
        versions: sortedAffectedProjectVersions.value.length
    }
})

const uniqueComponents = dependencyInfo.uniqueComponents
const affectedTaggedComponents = dependencyInfo.affectedTaggedComponents
const triggeringTaggedComponents = dependencyInfo.triggeringTaggedComponents
const normalizedTags = dependencyInfo.normalizedTags

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

const applySuccessfulAssessmentUpdate = (success: any, finalState: string, finalText: string) => {
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
    emit('update:assessment', savedResult.emittedAssessment)

    pendingScore.value = null
    pendingVector.value = savedResult.nextPendingVector
    initialVector.value = savedResult.nextInitialVector
    initialScore.value = savedResult.nextInitialScore
    isManualBaseMode.value = false
    lastRescoredScore.value = savedResult.nextLastRescoredScore
    showConflictModal.value = false

    Object.assign(originalAnalysis.value, buildSavedOriginalAnalysis({
        allInstances: allInstances.value,
        finalState,
        finalText,
        suppressed: suppressed.value,
    }))
    teamDrafts.value.clear()
    formTouched.value = false
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
        applySuccessfulAssessmentUpdate(success, finalState, finalText)
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

const teamTabs = computed(() => {
    const tags = [...normalizedTags.value]
    if (!tags.includes('automation')) tags.push('automation')
    return tags
})

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
    <div :class="['vuln-card relative border rounded-lg transition-colors', expanded ? 'overflow-visible z-40' : 'overflow-hidden', cardStyle]">
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
    <div v-if="isAssessed" class="absolute top-0 right-0 pointer-events-none z-20">
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
        @click="expanded = !expanded" 
        class="pl-[76px] pr-4 py-3 flex items-start cursor-pointer hover:bg-white/2 transition-all relative overflow-hidden"
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
            :normalizedTags="normalizedTags"
            :assessedTeams="assessedTeams"
            @copy-id="copyId"
            :expanded="expanded"
            :canApprove="canApprove"
            :isPendingReview="isPendingReview"
            :dependencyRelationship="dependencyRelationship"
            :assignees="group.assignees || []"
            @approve-assessment="approveAssessment"
        />
    </div>
            <!-- Expanded Details -->
    <div v-if="expanded" ref="detailsEl" class="pl-4 pr-4 py-4 border-t border-gray-700 overflow-y-auto" :style="{ maxHeight: detailsMaxHeight }">
        <!-- Top bar: External refs + Quick stats -->
        <div class="flex flex-wrap items-center gap-2 mb-3 text-[10px]">
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
            <span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
                <Layers :size="9" />
                {{ instanceStats.findings }} finding{{ instanceStats.findings !== 1 ? 's' : '' }}
            </span>
            <span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
                <Package :size="9" />
                {{ instanceStats.components }} component{{ instanceStats.components !== 1 ? 's' : '' }}
            </span>
            <span v-if="isReviewer && instanceStats.suppressed > 0" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-yellow-900/30 text-yellow-400 border border-yellow-800/40">
                <ShieldOff :size="9" />
                {{ instanceStats.suppressed }} suppressed
            </span>
            <span v-if="dependencyRelationship !== 'UNKNOWN'" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border" :class="dependencyRelationship === 'DIRECT' ? 'bg-red-900/20 text-red-400 border-red-800/40' : 'bg-gray-800 text-gray-400 border-gray-700'">
                {{ dependencyRelationship === 'DIRECT' ? '⬤' : '◌' }}
                {{ dependencyRelationship.toLowerCase() }} dependency
            </span>
            <span v-if="technicalState && technicalState !== 'NOT_SET'" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border bg-gray-800 border-gray-700" :class="stateColor">
                {{ technicalState.replace(/_/g, ' ') }}
            </span>
        </div>

        <!-- Metadata: Aliases + Versions -->
        <div class="flex flex-wrap gap-x-6 gap-y-1 text-xs text-gray-500 mb-3">
            <span v-if="isReviewer && group.aliases?.length">
                <span class="text-gray-600 font-bold uppercase text-[10px]">Aliases</span>
                <span class="ml-1.5">{{ group.aliases.join(', ') }}</span>
            </span>
            <span>
                <span class="text-gray-600 font-bold uppercase text-[10px]">Versions</span>
                <span class="ml-1.5">{{ sortedAffectedProjectVersions.join(', ') || 'N/A' }}</span>
            </span>
        </div>

        <!-- CVSS Vectors + Metric Breakdown (Reviewers only) -->
        <CvssVectorDisplay
            v-if="isReviewer && cvssVectorEntries.length"
            :vectors="cvssVectorEntries"
            class="mb-4"
        />

        <!-- TMRescore Proposal (Reviewers only) -->
        <div v-if="isReviewer && matchedProposal" class="mb-4 p-3 rounded border border-gray-700 bg-gray-850">
            <div class="flex items-center justify-between mb-2">
                <h5 class="text-xs font-bold uppercase tracking-wider text-teal-300 flex items-center gap-1.5">
                    <Zap :size="12" />
                    Threat Model Proposal
                </h5>
                <button
                    v-if="isReviewer"
                    @click="applyProposal"
                    class="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-bold uppercase tracking-wide bg-teal-600/30 text-teal-200 border border-teal-500/40 hover:bg-teal-600/50 hover:text-white transition-colors cursor-pointer"
                >
                    <Zap :size="10" />
                    Apply Proposal
                </button>
            </div>
            <div class="text-xs">
                <div class="flex items-center gap-3">
                    <div class="text-teal-300 font-bold">
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
            <div v-if="matchedProposal.analysis?.detail" class="mt-2 text-xs text-gray-400 leading-relaxed border-t border-teal-800/30 pt-2">
                <span class="text-gray-500 uppercase text-[9px] font-bold block mb-0.5">Reasoning</span>
                {{ matchedProposal.analysis.detail }}
            </div>
            <div v-if="matchedProposal.analysis?.response?.length" class="mt-2 text-xs text-gray-400 leading-relaxed border-t border-teal-800/30 pt-2">
                <span class="text-gray-500 uppercase text-[9px] font-bold block mb-0.5">Analysis</span>
                <ul class="list-disc list-inside space-y-0.5">
                    <li v-for="(resp, idx) in matchedProposal.analysis.response" :key="idx">
                        {{ typeof resp === 'string' ? resp : (resp.detail || resp.title || '') }}
                    </li>
                </ul>
            </div>

        </div>

        <!-- Code Analysis Panel -->
        <CodeAnalysisPanel
            :vulnId="group.id"
            :cvssVector="group.cvss_vector"
            :componentNames="triggeringTaggedComponents.map(c => c.name)"
            @apply-result="handleCodeAnalysisResult"
            class="mb-4"
        />

        <div class="grid md:grid-cols-2 gap-8">
            <div>
                    <!-- Title + Description -->
                    <h4 v-if="group.title && group.title !== group.id" class="font-semibold text-gray-200 mb-1">{{ group.title }}</h4>
                    <h4 v-else class="font-semibold mb-2 text-gray-300">Description</h4>
                    <div
                        class="advisory-markdown text-sm text-gray-400 mb-4 leading-relaxed"
                        data-testid="vuln-description"
                        v-html="renderedDescription"
                    ></div>

                    <div v-if="triggeringTaggedComponents.length > 0" class="mb-4">
                        <h4 class="text-[10px] font-bold uppercase tracking-wider text-gray-600 mb-2">Triggering team-mapped components</h4>
                        <div class="flex flex-wrap gap-1.5">
                            <span
                                v-for="comp in triggeringTaggedComponents"
                                :key="comp.name"
                                class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-gray-800 text-gray-300 border border-gray-700"
                            >
                                {{ comp.name }}
                                <span v-if="comp.versions.length" class="text-gray-500">@{{ comp.versions.join(', ') }}</span>
                                <span class="ml-2 text-[10px] font-normal text-blue-300">({{ comp.tag }})</span>
                            </span>
                        </div>
                    </div>

                    <div v-if="affectedTaggedComponents.length > 0" class="mb-4">
                        <h4 class="text-[10px] font-bold uppercase tracking-wider text-gray-600 mb-2">Affected components with team tags</h4>
                        <div class="flex flex-wrap gap-1.5">
                            <span
                                v-for="comp in affectedTaggedComponents"
                                :key="comp.name"
                                class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-gray-800 text-gray-300 border border-gray-700"
                            >
                                {{ comp.name }}
                                <span v-if="comp.versions.length" class="text-gray-500">@{{ comp.versions.join(', ') }}</span>
                                <span class="ml-2 text-[10px] font-normal text-blue-300">({{ comp.tag }})</span>
                            </span>
                        </div>
                    </div>

                    <!-- Affected Components Summary (Reviewers only) -->
                    <div v-if="isReviewer && uniqueComponents.length > 0" class="mb-4">
                        <h4 class="text-[10px] font-bold uppercase tracking-wider text-gray-600 mb-2">Affected Components</h4>
                        <div class="flex flex-wrap gap-1.5">
                            <span
                                v-for="comp in uniqueComponents"
                                :key="comp.name"
                                class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-gray-800 text-gray-300 border border-gray-700"
                            >
                                {{ comp.name }}<span class="text-gray-500">@{{ comp.versions.join(', ') }}</span>
                            </span>
                        </div>
                    </div>

                    <div class="mt-4">
                         <h4 class="text-[10px] font-bold uppercase tracking-wider text-gray-600 mb-2">Analysis Details & Comments</h4>
                         
                         <VulnGroupAssessmentDetails
                             v-for="assessment in groupedAssessments"
                             :key="`${assessment.state}-${assessment.instances.length}`"
                             :assessment="assessment"
                             :isReviewer="isReviewer"
                             @apply-all="handleApplyAllAssessment"
                             @adopt-team="handleAdoptTeamBlock"
                             @mapping-updated="handleMappingUpdated"
                         />
                     </div>
                 </div>
            <div class="bg-gray-850 p-4 rounded border border-gray-700 h-fit">
                <h4 class="font-bold flex items-center gap-2 mb-4">
                    <Shield :size="16" class="text-blue-400"/>
                    {{ selectedTeam ? `Team Assessment: ${selectedTeam}` : 'Global Assessment' }}
                </h4>
                
                <div class="space-y-4">
                    <!-- CVSS Calculator Section (For Reviewers) -->
                    <div v-if="isReviewer" class="p-3 border border-gray-700 rounded bg-gray-800">
                        <h5 class="text-xs font-bold text-gray-300 mb-2 flex items-center gap-2">
                            <Calculator :size="12" />
                            CVSS Calculator
                        </h5>
                        
                        <div class="mb-2">
                            <label for="cvss-vector-input" class="block text-xs font-semibold text-gray-500 mb-1 flex justify-between">
                                <span>Vector String</span>
                                <div class="flex items-center gap-2">
                                    <button 
                                        @click="resetVector" 
                                        class="text-gray-400 hover:text-white flex items-center gap-1 cursor-pointer"
                                        title="Reset to Original"
                                    >
                                        <RotateCcw :size="10" />
                                    </button>
                                    <button 
                                        @click="cleanRescoredVector"
                                        class="text-purple-300 hover:text-purple-200 flex items-center gap-1 cursor-pointer"
                                        title="Clean unresolved modifiers/requirements"
                                    >
                                        Clean
                                    </button>
                                    <button @click="showCalculatorModal = true" class="text-blue-400 hover:text-blue-300 flex items-center gap-1 cursor-pointer">
                                        <ExternalLink :size="10" /> Visual Calculator
                                    </button>
                                </div>
                            </label>
                            <input 
                                id="cvss-vector-input"
                                v-model="pendingVector"
                                type="text" 
                                placeholder="CVSS:4.0/AV:N/..."
                                class="w-full p-1.5 rounded bg-gray-900 border border-gray-600 focus:border-blue-500 text-xs font-mono"
                            />
                            <div v-if="group.cvss_vector && group.cvss_vector !== pendingVector" class="mt-1 text-[9px] text-gray-500/60 flex gap-1.5 truncate">
                                <span class="uppercase font-bold shrink-0">Original:</span>
                                <span class="truncate italic">{{ group.cvss_vector }}</span>
                            </div>
                        </div>
                        
                        <div class="flex items-center justify-between">
                            <label for="cvss-score-input" class="block text-xs font-semibold text-gray-500">Score</label>
                            <div class="flex gap-2">
                                <input 
                                    id="cvss-score-input"
                                    v-model="pendingScore"
                                    type="number" 
                                    :readonly="!canEditBase"
                                    step="0.1" 
                                    min="0" 
                                    max="10" 
                                    class="w-16 p-1.5 text-right rounded bg-gray-900 border border-gray-600 focus:border-blue-500 text-sm font-bold text-yellow-400 disabled:opacity-50"
                                    :class="{ 'cursor-not-allowed text-gray-500': !canEditBase }"
                                />
                            </div>
                        </div>
                    </div>

                    <!-- Team Tabs -->
                    <div>
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

                        <!-- Block header metadata (read-only) -->
                        <div v-if="teamBlockMeta(selectedTeam || 'General')" class="flex flex-wrap items-center gap-2 mt-2 text-[10px] text-gray-500">
                            <span v-if="teamBlockMeta(selectedTeam || 'General')!.user && teamBlockMeta(selectedTeam || 'General')!.user !== 'Unknown'">
                                Assessed by <span class="text-gray-400">{{ teamBlockMeta(selectedTeam || 'General')!.user }}</span>
                            </span>
                            <span v-if="teamBlockMeta(selectedTeam || 'General')!.timestamp">
                                {{ new Date(teamBlockMeta(selectedTeam || 'General')!.timestamp!).toLocaleDateString() }}
                            </span>
                        </div>
                    </div>

                    <!-- Assessment Section (Reviewer Global or Team Selected) -->
                    <div v-if="selectedTeam || isReviewer" :class="['border rounded p-3', selectedTeam ? 'border-blue-700/50 bg-blue-950/20' : 'border-purple-700/50 bg-purple-950/20']">
                        <div class="space-y-3">
                            <div>
                                <label id="analysis-state-label" for="analysis-state-select" class="block text-xs font-semibold text-gray-400 mb-1">Analysis State</label>
                                <CustomSelect
                                    id="analysis-state-select"
                                    aria-labelledby="analysis-state-label"
                                    :modelValue="state"
                                    @update:modelValue="state = $event; formTouched = true"
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
                                    @update:modelValue="justification = $event"
                                    :options="JUSTIFICATION_OPTIONS"
                                    size="sm"
                                />
                            </div>

                            <div>
                                <label for="analysis-details-textarea" class="block text-xs font-semibold text-gray-400 mb-1">Analysis Details</label>
                                <textarea
                                    id="analysis-details-textarea"
                                    v-model="details"
                                    @input="formTouched = true"
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
                        </div>
                    </div>

                    <!-- No-Team Section (Prompt for non-reviewers) -->
                    <div v-if="!selectedTeam && !isReviewer" class="p-4 rounded border border-gray-700 bg-gray-800/50 flex flex-col items-center justify-center text-center space-y-2">
                        <Shield :size="32" class="text-blue-500/50" />
                        <h4 class="text-sm font-bold text-gray-300">Select a Team Tab</h4>
                        <p class="text-xs text-gray-400 max-w-xs">
                          Global assessments are restricted to reviewers. Select a team tab above to provide an assessment.
                        </p>
                    </div>

                    <div v-if="isReviewer">
                        <label for="assessment-comment-textarea" class="block text-xs font-semibold text-gray-400 mb-1">Comment</label>
                        <textarea 
                            id="assessment-comment-textarea"
                            v-model="comment"
                            placeholder="Add a comment for audit trail..."
                            class="w-full p-2 rounded bg-gray-800 border border-gray-600 focus:border-blue-500 h-24"
                        ></textarea>
                    </div>

                    <div v-if="isReviewer">
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
                    
                    <div v-if="isReviewer" class="flex items-center gap-2">
                        <input 
                            type="checkbox" 
                            :id="`suppress-${group.id}`"
                            v-model="suppressed"
                            class="w-4 h-4 rounded"
                        />
                        <label :for="`suppress-${group.id}`" class="text-sm">Suppress this vulnerability</label>
                    </div>
                    
                    <div v-if="isReviewer && !selectedTeam && mergedAssessmentData.blocks.length > 0" class="pt-2 border-t border-gray-700 mt-2">
                        <button 
                            @click="applyConsensusAssessment"
                            class="w-full mb-2 bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-500 border border-yellow-600/50 font-bold py-1.5 rounded text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
                        >
                            <AlertTriangle :size="14" />
                            {{ consensusButtonLabel }}
                        </button>
                    </div>

                    <div class="flex gap-2">
                        <button 
                            @click="() => handleUpdate(false)"
                            :disabled="updating || loadingDetails || totalTargeted === 0"
                            class="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition-colors disabled:opacity-50 cursor-pointer"
                        >
                            {{ updating ? 'Updating...' : 'Apply' }}
                        </button>
                        <button
                            @click="refreshDetails"
                            :disabled="updating || loadingDetails"
                            class="px-3 py-2 rounded border border-gray-600 bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white transition-colors disabled:opacity-50 cursor-pointer"
                            title="Reload from server (discard local changes)"
                        >
                            <RefreshCw :size="14" :class="{ 'animate-spin': loadingDetails }" />
                        </button>
                    </div>
                </div>
            </div>
        </div>
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
