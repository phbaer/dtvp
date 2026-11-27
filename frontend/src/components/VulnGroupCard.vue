<script setup lang="ts">
import { ref, computed, watch, inject, onMounted, onUnmounted, nextTick, type Component, type Ref } from 'vue'
import { updateAssessment, getAssessmentDetails, getKnownUsers, deleteAssessment, previewGroupRepair, requestAssessmentChanges } from '../lib/api'
import type { AssessmentChangesTarget, EarlierAssessment } from '../lib/api'
import EarlierAssessments from './EarlierAssessments.vue'
import { marked } from 'marked'

import type { GroupedVuln, AssessmentPayload, TMRescoreProposal } from '../types'
import { ChevronDown, ChevronUp, Shield, RefreshCw, AlertTriangle, Calculator, ExternalLink, CheckCircle, RotateCcw, Zap, X, Loader2, FileText, Bot, ShieldCheck, Eraser, Brush, Wrench, MoreHorizontal, EyeOff, Maximize2, Minimize2, Info } from '@lucide/vue'

import { ANALYSIS_RESPONSE_OPTIONS, parseAssessmentResponse, parseAssessmentBlocks, getAssessmentSyncDraft, parseJustificationFromText, getAssessedTeams, isPendingReview as isPendingReviewHelper, getGroupGlobalDecision, getGroupLifecycle, getGroupTechnicalState, sanitizeAssessmentDetails, normalizeTags, STATE_PRIORITY, assessmentTeamKey, assessmentVariantKey, type AssessmentBlock } from '../lib/assessment-helpers'
import { AMBIGUOUS_SCOPE, BASE_SCOPE, getAssessmentScopes } from '../lib/assessmentScopes'
import { cleanStructuredAssessmentDetails, resolveAssessmentFormValues, resolveDependencyTrackConsensusInput, stripPendingReviewStatus } from '../lib/assessmentFormState'
import { getApprovalUnavailableReason, getGroupAssessmentSyncIssues } from '../lib/assessmentSyncIssues'
import { getGroupChangesRequestedTeams, teamChangesRequestsForFindings } from '../lib/assessmentChanges'
import { evidenceSources } from '../lib/evidence'
import { cardSeverityTint, savedRescoredScore } from '../lib/vulnCardSeverity'
import { hasPendingReviewMarker } from '../lib/assessmentScopes'
import { buildRescoredVectorForState, normalizeCvssVectorInstance, type CvssVersion } from '../lib/cvssRescore'
import { buildMergedAssessmentData } from '../lib/mergedAssessmentData'
import { buildSavedAssessmentResultState, buildSavedOriginalAnalysis, prepareAssessmentSubmission } from '../lib/assessmentSubmission'
import { isCodeAnalysisApplicable, buildCodeAnalysisGlobalReferenceDraft, codeAnalysisAssessmentState, prepareCodeAnalysisResult, prepareCodeAnalysisResults, type CodeAnalysisComponentRun, type CodeAnalysisTeamDraft } from '../lib/codeAnalysisResult'
import { unusableEvidenceId } from '../lib/codeEvidence'
import { calculateScoreFromVector } from '../lib/cvss'
import { hasGlobalAssessmentData } from '../lib/assessmentCleanup'
import { buildTeamAliasGroups, type TeamRosterEntry } from '../lib/team-mapping'
import { useVulnDependencyInfo } from '../lib/useVulnDependencyInfo'
import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'
import CvssVectorDisplay from './CvssVectorDisplay.vue'
import CustomSelect from './CustomSelect.vue'
import VulnGroupCardHeader from './VulnGroupCardHeader.vue'
import VulnGroupAssessmentDetails from './VulnGroupAssessmentDetails.vue'
import FindingMatrix from './FindingMatrix.vue'
import ReportedFindingScope from './ReportedFindingScope.vue'
import CalculatorModal from './CalculatorModal.vue'
import SsvcCalculator from './SsvcCalculator.vue'
import { summarizeSsvc, ssvcReviewText, stripSsvcDocumentation, type SsvcSelection } from '../lib/ssvc'
import ConflictResolutionModal from './ConflictResolutionModal.vue'
import ClearAssessmentModal from './ClearAssessmentModal.vue'
import BulkWorkflowModal from './BulkWorkflowModal.vue'
import AssessmentHistory from './AssessmentHistory.vue'
import GenericModal from './GenericModal.vue'
import AssessmentReviewModal from './AssessmentReviewModal.vue'
import RequestAssessmentChangesDialog from './RequestAssessmentChangesDialog.vue'
import CodeAnalysisPanel from './CodeAnalysisPanel.vue'
import DetailSection from './DetailSection.vue'
import VulnAboutSummary from './VulnAboutSummary.vue'
import TeamAssessmentOverview from './TeamAssessmentOverview.vue'
import { buildTeamOverview, resolveTeamAlias, stateLabel as stateLabelOf } from '../lib/teamOverview'
import { sortVersions } from '../lib/version'
import type { CodeAnalysisAssessResponse, CodeAnalysisCvssAdjustment } from '../lib/api'
import { originalSeverityOf, scoreSeverity, parseAttributionTimestamp, type AutomaticAssessmentStatus } from '../lib/vulnListIndex'

const props = defineProps<{
    group: GroupedVuln
    inModal?: boolean
    hasAutomaticAssessment?: boolean
    automaticAssessmentStatus?: AutomaticAssessmentStatus | null
    activeTeamFilter?: string
    /** Show the context and the assessment form side by side (inspector only). */
    workspace?: boolean
    /** The host can open the assessment workspace (wide enough viewport). */
    workspaceAvailable?: boolean
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
        } else if (isWorkspace.value && showMoreMenu.value) {
            // In the workspace the first Esc closes the menu, a second one
            // leaves the workspace.
            showMoreMenu.value = false
        }
    }
}

onMounted(() => {
    globalThis.addEventListener('keydown', handleCloseOnEscape)
    globalThis.addEventListener('resize', handleViewportResize)
    getKnownUsers().then(users => { knownUsers.value = users }).catch(() => {})
    if (props.inModal && canApprove.value) void openApproval(false)
})

onUnmounted(() => {
    if (formHighlightTimer) clearTimeout(formHighlightTimer)
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
const vulnTaskId = inject<Ref<string | null>>('vulnTaskId', ref(null))

const emit = defineEmits([
    'update',
    'update:assessment',
    'toggle-expand',
    'close',
    'toggle-workspace',
])

const ANALYSIS_STATES = [
    { value: 'NOT_SET', label: 'Not Set', description: 'No decision for this assessment.' },
    { value: 'EXPLOITABLE', label: 'Exploitable', description: 'The vulnerability is exploitable in this component.' },
    { value: 'IN_TRIAGE', label: 'In Triage', description: 'The vulnerability is currently being investigated.' },
    { value: 'RESOLVED', label: 'Resolved', description: 'The vulnerability has been resolved or mitigated.' },
    { value: 'NOT_AFFECTED', label: 'Not Affected', description: 'The component is not affected by this vulnerability.' },
    { value: 'FALSE_POSITIVE', label: 'False Positive', description: 'This finding is a false positive.' },
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

const RESPONSE_OPTIONS = ANALYSIS_RESPONSE_OPTIONS.map(option => ({ ...option }))

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
type DetailTab = 'overview' | 'analysis' | 'review'
// In the assessment workspace this is only ever 'overview' or 'analysis': it
// says what the left pane shows, and the form is always visible beside it.
const activeDetailTab = ref<DetailTab>('overview')
const isWorkspace = computed(() => !!props.inModal && !!props.workspace)
/** The one test for "the assessment form is visible". */
const reviewVisible = computed(() => isWorkspace.value || activeDetailTab.value === 'review')
const state = ref('NOT_SET')
const details = ref('')
const justification = ref('NOT_SET')
// What is done about the finding. One value for the Global assessment,
// edited on its form only; like SSVC it survives a switch to a team tab.
const response = ref('NOT_SET')
const responseTouched = ref(false)
const suppressed = ref(false)
const selectedTeam = ref('')
const showAllAssessmentTeams = ref(false)
// Set once the user picks the Global or a team tab (or an action moves to
// Global for them). From then on the team filter no longer preselects its
// team over that choice; a change of the filter or of the vulnerability
// starts over.
const teamTabChosen = ref(false)
const scopedCodeAnalysisAvailable = ref(false)
// Removed onlyTargetSelectedTeam - team selection now automatically targets team instances
const updating = ref(false)
const loadingDetails = ref(false)
const showCalculatorModal = ref(false)
const showConflictModal = ref(false)
const conflictData = ref<any>(null)
const originalAnalysis = ref<Record<string, any>>({}) // Map finding_uuid -> Analysis Object
const syncStatusOf = (analysis: any): string =>
    String(analysis?.dtvpSyncStatus || analysis?.dtvp_sync_status || '').toLowerCase()

// DTVP is the record. While an export is waiting or failing, the backend
// reports what Dependency-Track still holds when that differs; the export
// overwrites it. This is information only, there is nothing to decide.
const sourceOutOfDate = computed(() => allInstances.value.some((instance: any) => {
    // A reload or save gives the freshest state; until then the state
    // that came with the vulnerability detail is what we know.
    const analysis = originalAnalysis.value[instance.finding_uuid] ?? {
        dtvpSyncStatus: instance.sync_status || instance.dtvp_sync_status,
        dtvpRemote: instance.source_assessment,
    }
    return !!analysis?.dtvpRemote
        && ['pending', 'syncing', 'error', 'failed'].includes(syncStatusOf(analysis))
}))

// Tell the list about a change that did not come from the save form, the
// way a save does. `update` would mean "ownership changed" and makes the
// project view run the whole project query again and rebuild this card.
const emitRefreshedAssessment = (globalCleared = false) => {
    emit('update:assessment', {
        ...(globalCleared ? { rescored_cvss: null, rescored_vector: null } : {}),
        dtvp_results: allInstances.value.map((instance: any) => ({
            status: 'success',
            uuid: instance.finding_uuid,
            new_state: instance.analysis_state,
            new_details: instance.analysis_details,
            suppressed: instance.is_suppressed,
            revision: instance.dtvp_revision,
            sync_status: instance.dtvp_sync_status,
            update_id: instance.dtvp_update_id,
            source_assessment: instance.source_assessment ?? null,
        })),
    })
}

// Clearing one team's assessment, the Global one, or the whole assessment:
// a new revision without a decision or text for that scope, exported.
const showClearModal = ref(false)
const clearingAssessment = ref(false)
const clearAssessmentError = ref('')
const reviewRequest = ref<(AssessmentChangesTarget & { withdraw: boolean }) | null>(null)
const requestingChanges = ref(false)
const requestChangesError = ref('')
const requestChangesStale = ref(false)
const historyRefreshKey = ref(0)
const assessedTeamNames = computed(() => {
    const names = new Map<string, string>()
    for (const instance of allInstances.value) {
        const details = originalAnalysis.value[instance.finding_uuid]?.analysisDetails
            ?? instance.analysis_details
            ?? ''
        for (const block of parseAssessmentBlocks(details)) {
            if (block.historical) continue
            names.set(block.team.toLocaleLowerCase(), block.team)
        }
    }
    return Array.from(names.values())
})

// Every action of the card uses one button shape; only the role changes.
// Plain utility classes, as everywhere else in the templates.
const actionButton = 'inline-flex h-8 items-center gap-1.5 rounded border px-3 text-xs font-bold transition-colors disabled:cursor-not-allowed disabled:opacity-50'
const actionButtonPrimary = 'border-blue-600 bg-blue-600 text-white hover:bg-blue-700'
const actionButtonApprove = 'border-green-600 bg-green-600 text-white hover:bg-green-700'
const actionButtonSecondary = 'border-gray-600 bg-gray-800 text-gray-300 hover:bg-gray-700 hover:text-white'
const findingMatrixRef = ref<{ openDifferences: () => void } | null>(null)
const assessmentVariantCount = computed(() => groupedAssessments.value.length)
// Version overrides (ADR 0010), read-only until scoped saves exist: which
// versions have their own assessment, and whether it is approved.
const versionOverrideScopes = computed(() => {
    const view = getAssessmentScopes(props.group)
    if (!view.hasOverrides) return []
    const versionsOf = (scope: (typeof view.scopes)[number]) => scope.versions
        .map(version => version.version || version.project_uuid)
        .join(', ')
    return [
        ...view.scopes
            .filter(scope => scope.name !== BASE_SCOPE && scope.instances.length > 0)
            .map(scope => ({ key: scope.name, label: scope.label || scope.name, versions: versionsOf(scope), pending: scope.pending, ambiguous: false })),
        ...(view.ambiguous.length ? [{ key: AMBIGUOUS_SCOPE, label: 'two overrides', versions: '', pending: false, ambiguous: true }] : []),
    ]
})
const differingFindingCount = computed(() => visibleInstances.value.length - Math.max(
    0,
    ...groupedAssessments.value.map(assessment => assessment.instances.length),
))
const inconsistencyIssues = computed(() => assessmentSyncIssues.value.filter(issue => issue.kind === 'inconsistent'))
const incompleteIssues = computed(() => assessmentSyncIssues.value.filter(issue => issue.kind === 'incomplete'))
const approvalIssues = computed(() => assessmentSyncIssues.value.filter(issue => issue.kind === 'approval'))
/**
 * The team assessments that count: historical records are listed in
 * mergedAssessmentData too, but they are not any team's current decision.
 */
const activeAssessmentBlocks = computed(() => mergedAssessmentData.value.blocks.filter(block => !block.historical))
/** The decision of every team, when the teams do not agree. */
const conflictingTeamStates = computed(() => {
    const entries = activeAssessmentBlocks.value
        .filter(block => block.team.toLocaleLowerCase() !== 'general' && block.state && block.state !== 'NOT_SET')
        .map(block => ({ team: block.team, state: block.state }))
    return new Set(entries.map(entry => entry.state)).size > 1 ? entries : []
})
/** The findings in scope, each with the project version it belongs to. */
const matrixInstances = computed(() => {
    const versionOf = new Map<unknown, string>()
    for (const version of props.group.affected_versions || []) {
        for (const component of version.components || []) versionOf.set(component, version.project_version || '')
    }
    return visibleInstances.value.map(instance => (
        instance.project_version
            ? instance
            : { ...instance, project_version: versionOf.get(instance) || '' }
    ))
})

/**
 * Shows, on the Context tab, which findings differ and in which fields.
 * In the workspace this changes only the left pane; the form stays in view.
 */
const openDifferences = async () => {
    setDetailTab('overview')
    await nextTick()
    findingMatrixRef.value?.openDifferences()
    await nextTick()
    detailsEl.value?.querySelector?.('[data-testid="finding-differences"]')
        ?.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' })
}

/** Puts one version of the assessment into the Global form; saving applies it to every finding. */
const applyFindingVariant = async (variantDetails: string, variantState: string) => {
    await handleApplyAllAssessment(variantDetails, variantState, '')
    void revealAssessmentForm()
}

/** Apply from the evidence cards in Context · 3: fill the Global form and show it. */
const onEvidenceApplyAll = async (assessmentDetails: string, assessmentState: string, assessmentJustification: string) => {
    await handleApplyAllAssessment(assessmentDetails, assessmentState, assessmentJustification)
    void revealAssessmentForm()
}

/** Adopt a team block from the evidence cards in Context · 3 and show the form. */
const onEvidenceAdoptTeam = async (block: AssessmentBlock) => {
    await handleAdoptTeamBlock(block)
    void revealAssessmentForm()
}

const showMoreMenu = ref(false)
const canChangeSuppression = computed(() => (
    isReviewer.value && (!activeTeamScope.value || showAllAssessmentTeams.value || !selectedTeam.value)
))
const suppressedInstanceCount = computed(() => allInstances.value.filter(instance => instance.is_suppressed).length)

const clearModalMode = ref<'clear' | 'cleanup'>('clear')
const clearSelectedOnly = ref(false)
const selectedAssessmentName = computed(() => selectedTeam.value || 'Global')
const canClearGlobalAssessment = computed(() => isReviewer.value && hasGlobalAssessmentData(
    allInstances.value.map(instance => ({
        ...instance,
        analysis_details: originalAnalysis.value[instance.finding_uuid]?.analysisDetails
            ?? instance.analysis_details ?? '',
    })),
))
const canClearSelectedAssessment = computed(() => (
    selectedTeam.value
        ? assessedTeamNames.value.some(team => assessmentTeamKey(team) === assessmentTeamKey(selectedTeam.value))
        : canClearGlobalAssessment.value
))
const openClearModal = (selectedOnly = false) => {
    clearAssessmentError.value = ''
    clearModalMode.value = 'clear'
    clearSelectedOnly.value = selectedOnly
    showClearModal.value = true
}
const changeAssessmentState = (value: string) => {
    if (value === 'NOT_SET' && canClearSelectedAssessment.value) {
        openClearModal(true)
        return
    }
    state.value = value
    formTouched.value = true
    markSelectedTeamAssessmentManual()
}
/** The assessment cleanup: versions of the assessment, kept or cleared per finding. */
const openCleanupModal = () => {
    clearAssessmentError.value = ''
    clearModalMode.value = 'cleanup'
    showClearModal.value = true
}
/** Every finding with the project version it belongs to, for the cleanup. */
const cleanupInstances = computed(() => {
    const versionOf = new Map<unknown, string>()
    for (const version of props.group.affected_versions || []) {
        for (const component of version.components || []) versionOf.set(component, version.project_version || '')
    }
    return allInstances.value.map(instance => (
        instance.project_version ? instance : { ...instance, project_version: versionOf.get(instance) || '' }
    ))
})
// Repair…: the bulk Repair Assessments workflow for this vulnerability only.
// Offered when a repair applies; the stages are named from its preview.
interface RepairStage { id: string; label: string }
const repairStages = ref<RepairStage[]>([])
const showRepairModal = ref(false)
let repairCheck = 0
const checkRepair = async () => {
    const check = ++repairCheck
    const taskId = vulnTaskId.value
    if (!isReviewer.value || !taskId || !props.group?.id) {
        repairStages.value = []
        return
    }
    try {
        const preview = await previewGroupRepair(taskId, props.group.id)
        if (check !== repairCheck) return
        const item = preview.items.find(entry => entry.group_id === props.group.id)
        const topics = new Map((preview.topics || []).map(topic => [topic.id, topic.label]))
        repairStages.value = item?.repairable
            ? (Array.isArray(item.repairs) ? item.repairs : []).map((repair: any) => ({
                id: String(repair.id),
                label: topics.get(repair.id) || String(repair.label || repair.id),
            }))
            : []
    } catch {
        // No repair offered when the check fails; the bulk workflow remains.
        if (check === repairCheck) repairStages.value = []
    }
}
const repairTitle = computed(() => (repairStages.value.length
    ? `Repair Assessments for this vulnerability: ${repairStages.value.map(stage => stage.label).join(', ')}`
    : ''))
const openRepairModal = () => {
    showClearModal.value = false
    showRepairModal.value = true
}
const onRepairApplied = async () => {
    await refreshDetails()
    historyRefreshKey.value += 1
    emitRefreshedAssessment()
}

const onAssessmentCleaned = async () => {
    showClearModal.value = false
    await refreshDetails()
    historyRefreshKey.value += 1
    emitRefreshedAssessment()
}

const confirmClearAssessment = async (team: string | null) => {
    if (clearingAssessment.value) return
    clearingAssessment.value = true
    clearAssessmentError.value = ''
    try {
        await deleteAssessment(allInstances.value, team)
        showClearModal.value = false
        const clearedKey = assessmentTeamKey(team)
        if (team === null) {
            discardUnsavedDraft()
        } else {
            for (const name of teamDrafts.value.keys()) {
                if (assessmentTeamKey(name) === clearedKey) teamDrafts.value.delete(name)
            }
            for (const name of takeoverSources.value.keys()) {
                if (assessmentTeamKey(name) === clearedKey) takeoverSources.value.delete(name)
            }
            if (clearedKey === 'general') {
                resetRescoring.value = false
                isManualBaseMode.value = false
                ssvcTouched.value = false
                responseTouched.value = false
                pendingSsvc.value = savedSsvc.value.record
                approvalPrefilled.value = false
            }
            if (clearedKey === assessmentTeamKey(selectedTeam.value || 'General')) {
                formTouched.value = false
                codeAnalysisDraftApplied.value = false
            }
        }
        await refreshDetails()
        historyRefreshKey.value += 1
        emitRefreshedAssessment(team === null || clearedKey === 'general')
    } catch (err: any) {
        clearAssessmentError.value = err?.response?.status === 409
            ? 'The assessment changed while this dialog was open. Reload and try again.'
            : err?.response?.data?.detail || err?.message || 'The assessment could not be cleared.'
    } finally {
        clearingAssessment.value = false
    }
}

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
            label: sourceOutOfDate.value
                ? 'Saved locally — Dependency-Track is out of date, export is retrying'
                : 'Saved locally — Dependency-Track sync is retrying',
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
            label: sourceOutOfDate.value
                ? 'Saved locally — Dependency-Track is out of date'
                : 'Saved locally — syncing to Dependency-Track',
            detail: sourceOutOfDate.value
                ? 'Dependency-Track holds a different value. The next export overwrites it.'
                : '',
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
const takeoverSources = ref<Map<string, string>>(new Map())
const refreshCounter = ref(0)
const formTouched = ref(false)
const codeAnalysisDraftApplied = ref(false)
const codeAnalysisDraftSummary = ref('')
const codeAnalysisRunIds = ref<string[]>([])
const codeEvidenceByTeam = ref<Record<string, string[]>>({})
const codeEvidenceTitles = ref<Record<string, string>>({})
const requestedEvidenceId = ref('')
const openSupportingEvidence = async (id: string) => {
    requestedEvidenceId.value = ''
    setDetailTab('analysis', true)
    await nextTick()
    requestedEvidenceId.value = id
}
const dirtyEvidenceTeams = ref(new Set<string>())
const evidenceTeam = computed(() => selectedTeam.value || 'General')
const codeEvidenceIds = computed({
    get: () => codeEvidenceByTeam.value[evidenceTeam.value] || [],
    set: (ids: string[]) => {
        codeEvidenceByTeam.value[evidenceTeam.value] = ids
        dirtyEvidenceTeams.value.add(evidenceTeam.value)
    },
})
const loadEvidenceSelections = (records: import('../lib/api').CodeEvidence[]) => {
    const visible = new Set(visibleInstances.value.map(instance => instance.finding_uuid))
    const latest = new Map<string, number>()
    for (const record of records) {
        codeEvidenceTitles.value[record.evidence_id] = record.title
        for (const app of record.applications || []) {
            if (!app.team || !visible.has(app.finding_uuid)) continue
            const key = `${app.team}:${app.finding_uuid}`
            latest.set(key, Math.max(latest.get(key) ?? -1, app.assessment_revision ?? -1))
        }
    }
    const byTeam: Record<string, string[]> = {}
    for (const record of records) for (const app of record.applications || []) {
        if (!app.team || !visible.has(app.finding_uuid)) continue
        byTeam[app.team] ||= []
        if (app.selected !== false && app.assessment_revision === latest.get(`${app.team}:${app.finding_uuid}`) && !byTeam[app.team].includes(record.evidence_id)) byTeam[app.team].push(record.evidence_id)
    }
    for (const [team, ids] of Object.entries(byTeam)) if (!dirtyEvidenceTeams.value.has(team)) codeEvidenceByTeam.value[team] = ids
}
const removeSelectedEvidence = (id: string) => { codeEvidenceIds.value = codeEvidenceIds.value.filter(value => value !== id) }
const codeAnalysisProposalRuns = ref<CodeAnalysisComponentRun[]>([])
const automaticFallbackTeams = ref<Set<string>>(new Set())
const assessmentSubmitted = ref(false)
const latestCodeAnalysisCvssAdjustment = ref<CodeAnalysisCvssAdjustment | null>(null)
const latestCodeAnalysisCvssComponents = ref<string[]>([])

const isInternalUpdate = ref(false)
const showGeneratedText = ref(false)
const generatedTextCopyState = ref<'idle' | 'copied' | 'error'>('idle')
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
const cardEl = ref<HTMLElement | null>(null)
// The two panes of the assessment workspace; plain wrappers in tab mode.
const contextPaneEl = ref<HTMLElement | null>(null)
const assessmentPaneEl = ref<HTMLElement | null>(null)
const workspaceHeadingEl = ref<HTMLElement | null>(null)
const formHighlight = ref(false)
let formHighlightTimer: ReturnType<typeof setTimeout> | null = null
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
const resetRescoring = ref(false)
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

    const resubmit = Boolean(selectedTeamChangeRequests.value.length)
    const actionLabel = resubmit ? 'Resubmit' : isReviewer.value ? 'Save' : 'Submit'
    const shouldApply = await promptConfirm(
        'Unsaved assessment',
        `${actionLabel} this assessment before leaving? Discard closes without saving, while Stay keeps the local edits open.`,
        false,
        { confirmLabel: actionLabel, cancelLabel: 'Stay', discardLabel: 'Discard' },
    )
    if (!shouldApply) return false

    if (!hasUnsavedDraft.value) return true

    await handleUpdate(false, false, resubmit)
    return !hasUnsavedDraft.value
}

const requestClose = async () => {
    if (await confirmApplyDraftBeforeLeave()) {
        emit('close')
    }
}

/** A modal or menu of this card is open; Esc belongs to it, not to the workspace. */
const hasOpenOverlay = () => Boolean(
    genericModal.value.show
    || showConflictModal.value
    || showCalculatorModal.value
    || showClearModal.value
    || reviewModal.value.show
    || Boolean(reviewRequest.value)
    || showMoreMenu.value
)

defineExpose({
    confirmApplyDraftBeforeLeave,
    hasOpenOverlay,
})

const changeResponse = (value: string) => {
    response.value = value
    responseTouched.value = true
    formTouched.value = true
}

const discardUnsavedDraft = () => {
    resetRescoring.value = false
    ssvcTouched.value = false
    responseTouched.value = false
    pendingSsvc.value = savedSsvc.value.record
    teamDrafts.value.clear()
    takeoverSources.value.clear()
    formTouched.value = false
    codeAnalysisDraftApplied.value = false
    codeAnalysisDraftSummary.value = ''
    codeAnalysisRunIds.value = []
    codeEvidenceByTeam.value = {}
    dirtyEvidenceTeams.value = new Set()
    automaticFallbackTeams.value = new Set()
    isManualBaseMode.value = false
    assigneeInput.value = ''
    assigneeSuggestionsVisible.value = false
    showConflictModal.value = false
    updateFormFromGroup(true)
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
/** Findings Dependency-Track reports now; evidence about none of them is stale. */
const reportedFindingUuids = computed(() => allInstances.value
    .map(instance => instance.finding_uuid)
    .filter((uuid): uuid is string => Boolean(uuid)))
const savedSsvc = computed(() => summarizeSsvc(allInstances.value.map(instance => instance.analysis_details || instance.analysisDetails || '')))
const pendingSsvc = ref<SsvcSelection | null>(null)
const ssvcTouched = ref(false)
watch(savedSsvc, summary => {
    if (!ssvcTouched.value) pendingSsvc.value = summary.record
}, { immediate: true })
const changeSsvc = (selection: SsvcSelection | null) => {
    pendingSsvc.value = selection
    ssvcTouched.value = true
    assessmentSubmitted.value = false
}
const visibleInstances = dependencyInfo.visibleInstances
const visibleInstanceSet = computed(() => new Set(visibleInstances.value))
const activeTeamScope = dependencyInfo.activeTeam
const getInstanceTeamKey = dependencyInfo.getInstanceTeamKey
const instanceTeams = dependencyInfo.instanceTeams
const effectiveTags = dependencyInfo.effectiveTags
const teamRoster = inject<Ref<TeamRosterEntry[]>>('teamRoster', ref([]))
const teamAliasGroups = computed(() => buildTeamAliasGroups(teamMapping?.value || {}, teamRoster.value))
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
const changesRequestedTeams = computed(() => getGroupChangesRequestedTeams(props.group))

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

// Approval is for a vulnerability that is Ready for approval only; the
// server refuses it otherwise (docs/assessment-model.md#lifecycle-decision-table).
const canApprove = computed(() => {
    return user?.value?.role === 'REVIEWER' && isPendingReview.value
        && !changesRequestedTeams.value.length && displayState.value === 'NEEDS_APPROVAL'
})
const approvalUnavailableReason = computed(() => user?.value?.role === 'REVIEWER'
    ? getApprovalUnavailableReason(props.group, {
        lifecycle: displayState.value,
        requiredTeamsOrTags: effectiveTags.value,
        teamMapping: teamMapping?.value || {},
    })
    : '')

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
    await moveToGlobalForm()

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
    void revealAssessmentForm()
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

/** Agent code evidence a person chose to use: standalone rationale, and the
 * suggested decision only when it was ticked. Nothing is saved here. */
const handleApplyCodeEvidence = (payload: { evidenceId: string; title: string; summary: string; state?: string; justification?: string }) => {
    const current = details.value.trimEnd()
    if (payload.summary) details.value = current ? `${current}\n\n${payload.summary}` : payload.summary
    codeEvidenceTitles.value[payload.evidenceId] = payload.title
    if (payload.state) {
        state.value = payload.state
        justification.value = payload.justification || 'NOT_SET'
        applyRescoreRulesForState(payload.state)
    }
    formTouched.value = true
    codeAnalysisDraftApplied.value = true
    codeAnalysisDraftSummary.value = 'Supporting evidence selected. Review the assessment rationale before saving.'
    if (!codeEvidenceIds.value.includes(payload.evidenceId)) {
        codeEvidenceIds.value = [...codeEvidenceIds.value, payload.evidenceId]
    }
    setDetailTab('review', true)
}

const stageCodeAnalysisGlobalReference = (): AssessmentDraftState | null => {
    const assessments = new Map<string, CodeAnalysisTeamDraft>()
    for (const block of activeAssessmentBlocks.value) {
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
    const savedGeneral = activeAssessmentBlocks.value
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
        void revealAssessmentForm()
        return
    }

    // Switch to the global assessment first: the selectedTeam watcher persists the
    // current form into its own team draft, which would otherwise overwrite the
    // analyzer drafts written below.
    await moveToGlobalForm()

    const fallbackTeams: string[] = []
    const preservedTeams: string[] = []
    for (const draft of prepared.teamDrafts) {
        const existingDraft = teamDrafts.value.get(draft.team)
        const savedBlock = activeAssessmentBlocks.value.find(block => (
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
    void revealAssessmentForm()
}

const handleCodeAnalysisResultChange = (result: CodeAnalysisAssessResponse | null, components: string[]) => {
    const adjustment = isCodeAnalysisApplicable(result) && result?.assessment.rescoring_eligible === true
        ? result.assessment.adjusted_cvss ?? null : null
    latestCodeAnalysisCvssAdjustment.value = adjustment
    latestCodeAnalysisCvssComponents.value = adjustment ? components : []
}

const handleCodeAnalysisProposalsChange = (runs: CodeAnalysisComponentRun[]) => {
    codeAnalysisProposalRuns.value = runs.filter(run => isCodeAnalysisApplicable(run.result))
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

    await moveToGlobalForm()
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

const hasSavedGlobalAssessment = computed(() => activeAssessmentBlocks.value.some(block =>
    assessmentTeamKey(block.team) === 'general' && block.state !== 'NOT_SET'
))
/** True while the Global form holds a decision taken over from the teams. */
const approvalPrefilled = ref(false)

const whenDetailsLoaded = () => loadingDetails.value
    ? new Promise<void>(resolve => {
        const stop = watch(loadingDetails, loading => {
            if (!loading) {
                stop()
                resolve()
            }
        })
    })
    : Promise.resolve()

/**
 * Brings a reviewer to the one place where a pending assessment is approved:
 * the Global assessment. An explicit approval action can prepare a draft
 * from the team decisions when there is no saved Global decision.
 */
const openApproval = async (prefill = true) => {
    if (!canApprove.value) return
    if (!expanded.value) expanded.value = true
    await nextTick()
    await whenDetailsLoaded()
    if (!canApprove.value) return
    if (!reviewVisible.value) setDetailTab('review', true)
    if (selectedTeam.value) await moveToGlobalForm()
    if (prefill && !hasSavedGlobalAssessment.value && !formTouched.value && effectiveAssessmentWorst.value) {
        await applyEffectiveAssessmentSummary()
        approvalPrefilled.value = true
    }
}

const requestApproval = (e?: Event) => {
    e?.stopPropagation() // Prevent card expansion
    void openApproval()
}

const approvalBlockedReason = computed(() => {
    if (state.value === 'NOT_SET') return 'Set the Global decision first.'
    if (assessmentMissingFields.value.length > 0) return `Still needed: ${assessmentMissingFields.value.join(', ')}.`
    return ''
})
const approvalAtForm = computed(() => (
    reviewVisible.value && !selectedTeam.value
    && !(state.value === 'NOT_SET' && !hasSavedGlobalAssessment.value
        && !formTouched.value && effectiveAssessmentWorst.value)
))
const canApproveNow = computed(() => (
    canApprove.value
    && approvalAtForm.value
    && !updating.value
    && !loadingDetails.value
    && !approvalBlockedReason.value
))

/** Saves the Global assessment as shown and clears the pending status. */
const approveAssessment = async () => {
    if (!canApproveNow.value) return
    updating.value = true
    try {
        await handleUpdate(true, true) // force=true, isApprove=true
        approvalPrefilled.value = false
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
    } else {
        pendingVector.value = ''
        cvssInstance.value = null
    }
    pendingScore.value = props.group.cvss_score ?? props.group.cvss
        ?? calculateScoreFromVector(original || '')
    // Reset is an explicit removal, including a redundant stored rescore.
    resetRescoring.value = true
    formTouched.value = true
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
        resetRescoring.value = false
        formTouched.value = true
    }
}, { flush: 'sync' })

watch(pendingScore, (newScore, oldScore) => {
    if (!isInternalUpdate.value && !isDerivedCvssScoreUpdate.value && newScore !== oldScore) {
        resetRescoring.value = false
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

            // Group by state, details, and suppression — different details
            // get separate boxes, as in the finding matrix: whitespace, who
            // assessed when, records of one finding and the order of the
            // team blocks alone are the same assessment.
            const key = `${stateVal}|${assessmentVariantKey(detailsVal)}|${suppressedVal}`

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
        // A rescored vector can be stored without its score. Derive it here:
        // the vector watcher only runs when the vector changes, so it does
        // not recover the score when this form is rebuilt for another tab.
        const storedRescoredVector = resetRescoring.value ? '' : props.group.rescored_vector || ''
        pendingScore.value = (resetRescoring.value ? null : props.group.rescored_cvss)
            ?? (storedRescoredVector ? calculateScoreFromVector(storedRescoredVector) : null)
            ?? props.group.cvss_score ?? props.group.cvss
            ?? calculateScoreFromVector(props.group.cvss_vector || '')
        pendingVector.value = storedRescoredVector || props.group.cvss_vector || ''
        // Keep activeVersion in sync with the actual vector version
        const pv = pendingVector.value
        if (pv.startsWith('CVSS:4.0')) activeVersion.value = '4.0'
        else if (pv.startsWith('CVSS:3.0')) activeVersion.value = '3.0'
        else if (pv.startsWith('CVSS:3.')) activeVersion.value = '3.1'
        else if (pv.startsWith('CVSS:2.0') || (pv.includes('/') && !pv.startsWith('CVSS:'))) activeVersion.value = '2.0'

        const formValues = resolveAssessmentFormValues({
            selectedTeam: selectedTeam.value,
            isReviewer: isReviewer.value,
            teamBlocks: activeAssessmentBlocks.value,
            instances: allInstances.value,
        })

        state.value = formValues.state
        details.value = stripSsvcDocumentation(formValues.details).trim()
        justification.value = formValues.justification
        // An unsaved choice stays while team tabs are switched or the group
        // is loaded again; a reload or discard without one shows the stored.
        if (!responseTouched.value) {
            response.value = mergedAssessmentData.value.response || 'NOT_SET'
        }

        // Initialize assigned users from the current team block
        const teamKey = selectedTeam.value || 'General'
        const assignedBlock = activeAssessmentBlocks.value.find(b => b.team === teamKey)
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

    const allBlocks = activeAssessmentBlocks.value

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

// Set while a handler deliberately moves to the Global form. Switching
// resets formTouched, and the formTouched watcher below would otherwise
// return a team-scoped analyst to their team's form before the handler
// fills the Global one.
let forcingGlobalForm = false

/** Switches to the Global form and waits until the switch has settled. */
const moveToGlobalForm = async () => {
    teamTabChosen.value = true
    forcingGlobalForm = true
    try {
        selectedTeam.value = ''
        await nextTick()
    } finally {
        forcingGlobalForm = false
    }
}

const handleApplyAllAssessment = async (assessmentDetails: string, assessmentState: string, assessmentJustification: string) => {
    // Always apply to global assessment regardless of current team selection.
    // Must await nextTick so the selectedTeam watcher (updateFormFromGroup) runs
    // before we set the form values — otherwise it overwrites them.
    await moveToGlobalForm()

    // Parse the full structured text and extract only the General block's details.
    const blocks = parseAssessmentBlocks(assessmentDetails)
    const generalBlock = blocks.find(b => b.team === 'General' && !b.historical)
    if (generalBlock) {
        details.value = stripPendingReviewStatus(stripSsvcDocumentation(generalBlock.details || '')).trim()
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

/** The stored text of the findings, as the server generated it. */
const generatedAssessmentText = computed(() => mergedAssessmentData.value.fullText.trim())
const copyGeneratedText = async () => {
    generatedTextCopyState.value = 'idle'
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(generatedAssessmentText.value)
        } else {
            copyTextWithFallback(generatedAssessmentText.value)
        }
        generatedTextCopyState.value = 'copied'
        globalThis.setTimeout(() => {
            if (generatedTextCopyState.value === 'copied') generatedTextCopyState.value = 'idle'
        }, 2000)
    } catch {
        generatedTextCopyState.value = 'error'
    }
}

const handleAdoptTeamBlock = async (
    block: Pick<AssessmentBlock, 'state' | 'justification'> & { details?: string },
    withText = true,
) => {
    // Always apply to global assessment regardless of current team selection.
    // Must await nextTick so the selectedTeam watcher (updateFormFromGroup) runs
    // before we set the form values — otherwise it overwrites them.
    await moveToGlobalForm()

    // Adopt the team block's assessment into the global form fields.
    // Only copy the team's details text (not a full structured document).
    state.value = block.state || 'NOT_SET'
    justification.value = block.justification || 'NOT_SET'
    if (withText) details.value = stripPendingReviewStatus(stripSsvcDocumentation(block.details || '')).trim()
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

watch(() => props.group.id, () => {
    resetRescoring.value = false
    takeoverSources.value.clear()
    teamTabChosen.value = false
})

watch(() => props.group, (group, previousGroup) => {
    assessmentSubmitted.value = false
    updateFormFromGroup(group.id !== previousGroup?.id)
}, { immediate: true })

watch(formTouched, (touched) => {
    if (touched) assessmentSubmitted.value = false
    if (
        !touched
        && !forcingGlobalForm
        && !teamTabChosen.value
        && reviewVisible.value
        && activeTeamScope.value
        && !showAllAssessmentTeams.value
        && scopedAssessmentTeam.value
    ) {
        selectedTeam.value = scopedAssessmentTeam.value
    }
})



watch(expanded, (isOpen) => {
    emit('toggle-expand', props.group.id, isOpen)

    if (isOpen) {
        activeDetailTab.value = 'overview'
        const shouldLockAfterScroll = openCardCount === 0
        openCardCount += 1
        refreshDetails()
        if (canApprove.value) void openApproval(false)
        nextTick(() => {
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
    if (!isInternalUpdate.value && !selectedTeam.value && !loadingDetails.value
        && !updating.value && newState !== oldState && isReviewer.value) {
        applyStateRescore(newState)
    }
}, { flush: 'sync' })

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
                             c.sync_status = c.dtvp_sync_status
                             c.source_assessment = item.analysis.dtvpRemote || null
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


const handleUpdate = async (force = false, isApprove = false, resubmit = false) => {
    if (!isReviewer.value && assessmentMissingFields.value.length > 0) {
        void revealAssessmentForm()
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
            // Saved with the Global assessment only, like SSVC.
            response: selectedTeam.value ? undefined : response.value,
            teamDrafts: teamDrafts.value,
            takeoverSources: takeoverSources.value,
            isReviewer: isReviewer.value,
            pendingVector: pendingVector.value,
            pendingScore: pendingScore.value,
            resetRescoring: resetRescoring.value,
            initialVector: initialVector.value,
            initialScore: initialScore.value,
            originalVector: props.group.cvss_vector || '',
            originalScore: props.group.cvss_score ?? props.group.cvss ?? null,
            currentUser,
            isApprove,
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

        const reviewText = ssvcTouched.value && !selectedTeam.value
            ? ssvcReviewText(preparedSubmission.reviewText, pendingSsvc.value)
            : preparedSubmission.reviewText
        if (!await confirmAssessmentReview(force, reviewText)) {
            return
        }

        const finalText = preparedSubmission.finalText
        const payload: AssessmentPayload = {
            ...preparedSubmission.payload,
            ...((isApprove || resubmit) && vulnTaskId.value ? {
                review_task_id: vulnTaskId.value,
                review_group_id: props.group.id,
            } : {}),
            ...(resubmit ? { resubmit_changes: true } : {}),
            ...(ssvcTouched.value && !selectedTeam.value ? { ssvc: pendingSsvc.value && {
                model: pendingSsvc.value.model,
                version: pendingSsvc.value.version,
                answers: pendingSsvc.value.answers,
                rationale: pendingSsvc.value.rationale,
                exploitation_evidence: pendingSsvc.value.exploitation_evidence,
            } } : {}),
            state: finalState,
            analysis_run_ids: [...codeAnalysisRunIds.value],
            code_evidence_by_team: Object.fromEntries([...dirtyEvidenceTeams.value].map(team => [team, codeEvidenceByTeam.value[team] || []])),
        }

        const results = await updateAssessment(payload)

        await handleAssessmentUpdateResults(results, finalState, finalText)
    } catch (err: any) {
        if (resubmit && err?.response?.status === 409) {
            await showAlert('Resubmission changed',
                'The saved assessment changed. Reload the details before resubmitting.')
        } else {
            await handleAssessmentUpdateError(err)
        }
    } finally {
        updating.value = false
    }
}

const handleUseServerState = () => {
    // Refresh details to get latest server state (which we technically have in conflictData but refresh is safer/simpler)
    refreshDetails()
    showConflictModal.value = false
}

const handleMappingUpdated = async () => {
    await refreshDetails()
    emit('update')
}

const originalSeverity = computed(() => originalSeverityOf(props.group))
const savedRescore = computed(() => savedRescoredScore(props.group))
const displayedRescore = computed(() => savedRescore.value
    ?? (isRescoredOrModified.value ? pendingScore.value : null))
const rescoredSeverity = computed(() => displayedRescore.value == null
    ? null : scoreSeverity(displayedRescore.value))
const severityTint = computed(() => cardSeverityTint(
    originalSeverity.value, savedRescore.value == null ? null : scoreSeverity(savedRescore.value),
))

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
const hasUnsavedDraft = computed(() => formTouched.value || ssvcTouched.value || responseTouched.value || resetRescoring.value)
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
    && (formTouched.value || ((ssvcTouched.value || responseTouched.value || resetRescoring.value) && !selectedTeam.value)
        || (Boolean(vulnTaskId.value) && selectedTeamChangeRequests.value.length > 0
            && state.value !== 'NOT_SET' && Boolean(details.value.trim())))
    && assessmentMissingFields.value.length === 0
))
const assessmentActionLabel = computed(() => {
    if (updating.value) return isReviewer.value ? 'Saving...' : 'Submitting...'
    if (selectedTeamChangeRequests.value.length) return `Resubmit ${selectedTeam.value} for review`
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
])

// The workspace shows the form beside the tabs, so its tab goes away there.
const visibleDetailTabs = computed(() => (
    isWorkspace.value ? detailTabs.value.filter(tab => tab.id !== 'review') : detailTabs.value
))

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

/** Preselects the team the user is scoped to, as opening the Assessment tab does. */
const autoSelectReviewTeam = () => {
    if (teamTabChosen.value) return
    const matchingTeam = (
        activeTeamScope.value && !showAllAssessmentTeams.value
            ? scopedAssessmentTeam.value
            : (!selectedTeam.value && !isReviewer.value && allAssessmentTeams.value.length === 1
                ? allAssessmentTeams.value[0]
                : '')
    )
    if (matchingTeam) selectedTeam.value = matchingTeam
}

const setDetailTab = (tab: DetailTab, preserveReviewTeam = false) => {
    if (isWorkspace.value) {
        // The form is always visible in the workspace: the review "tab" only
        // scrolls its pane, every other tab changes the left pane alone.
        if (tab === 'review') {
            if (!preserveReviewTeam) autoSelectReviewTeam()
            nextTick(() => {
                assessmentPaneEl.value?.scrollTo?.({ top: 0, behavior: 'smooth' })
            })
            return
        }
        activeDetailTab.value = tab
        nextTick(() => {
            contextPaneEl.value?.scrollTo?.({ top: 0, behavior: 'smooth' })
        })
        return
    }
    if (tab === 'review' && !preserveReviewTeam) autoSelectReviewTeam()
    activeDetailTab.value = tab
    nextTick(() => {
        const details = detailsEl.value
        const card = cardEl.value
        if (props.inModal && card && details) {
            // Reset the tab's content without scrolling away a visible header.
            card.scrollTop = Math.min(card.scrollTop, details.offsetTop)
        } else {
            details?.scrollTo?.({ top: 0, behavior: 'smooth' })
        }
    })
}

/**
 * Shows the form after an action filled it. In tab mode that opens the
 * Assessment tab; in the workspace the left pane stays where it is and the
 * decision section scrolls into view, briefly highlighted.
 */
const revealAssessmentForm = async () => {
    if (!isWorkspace.value) {
        setDetailTab('review', true)
        return
    }
    await nextTick()
    assessmentPaneEl.value
        ?.querySelector?.('[data-testid="assessment-decision-section"]')
        ?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
    formHighlight.value = true
    if (formHighlightTimer) clearTimeout(formHighlightTimer)
    formHighlightTimer = setTimeout(() => {
        formHighlight.value = false
        formHighlightTimer = null
    }, 1500)
}

const toggleWorkspace = () => emit('toggle-workspace')

const uniqueComponents = dependencyInfo.uniqueComponents
const triggeringTaggedComponents = dependencyInfo.triggeringTaggedComponents
const normalizedTags = dependencyInfo.normalizedTags
const UNASSIGNED_TEAM = 'Unassigned'
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
    // A finding whose components belong to no team can still be assessed.
    if (teams.length === 0) teams.push(UNASSIGNED_TEAM)
    return teams
})
const previousTeamAssessments = computed(() => {
    const currentTeams = new Set(allAssessmentTeams.value.map(team => team.toLocaleLowerCase()))
    return mergedAssessmentData.value.blocks.filter(block =>
        block.team.toLocaleLowerCase() !== 'general'
        && !currentTeams.has((normalizeTags([block.team], teamMapping?.value || {})[0] || block.team).toLocaleLowerCase())
        && block.state !== 'NOT_SET'
    )
})

const usePreviousTeamAssessment = (block: AssessmentBlock) => {
    if (!selectedTeam.value || !previousTeamAssessments.value.includes(block)) return
    state.value = block.state
    justification.value = block.justification || 'NOT_SET'
    details.value = stripPendingReviewStatus(stripSsvcDocumentation(block.details || '')).trim()
    currentAssigned.value = []
    evidenceReviewed.value = false
    versionCoverageChecked.value = false
    ticketReference.value = ''
    takeoverSources.value.set(selectedTeam.value, block.team)
    formTouched.value = true
}

// No finding of the vulnerability has an assessment: offer what DTVP still
// holds for gone findings of it in the same versions (EarlierAssessments).
const assessmentEmpty = computed(() => allInstances.value.length > 0 && allInstances.value.every((instance: any) =>
    String(instance.analysis_state || instance.analysisState || 'NOT_SET') === 'NOT_SET'
    && !String(instance.analysis_details || instance.analysisDetails || '').trim()
))
const earlierFindings = computed(() => (props.group.affected_versions || []).flatMap((version: any) =>
    (version.components || []).map((instance: any) => ({
        project_uuid: String(instance.project_uuid || version.project_uuid || ''),
        vulnerability_uuid: String(instance.vulnerability_uuid || ''),
        project_version: String(instance.project_version || version.project_version || ''),
    }))
))
/** Fill the form from an earlier assessment; nothing is saved. With a team
 * open, that team's block if the record has one, else the decision. */
const useEarlierAssessment = (entry: EarlierAssessment) => {
    const teamKey = (name: string) => (normalizeTags([name], teamMapping?.value || {})[0] || name).toLocaleLowerCase()
    const block = selectedTeam.value
        ? entry.teams.find(team => teamKey(team.team) === teamKey(selectedTeam.value))
        : undefined
    state.value = block?.state || entry.state
    justification.value = block?.justification || entry.justification || 'NOT_SET'
    details.value = stripPendingReviewStatus(stripSsvcDocumentation(block?.details ?? entry.details ?? '')).trim()
    if (!selectedTeam.value && entry.response && entry.response !== 'NOT_SET') {
        response.value = entry.response
        responseTouched.value = true
    }
    formTouched.value = true
}

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
/** The form's scope follows its selected team, independently of the list's
 * team filter. Ownership is the backend-resolved ownership of each finding;
 * a shared component name or a mapped ancestor does not identify its versions. */
const assessmentScopeInstances = computed(() => {
    const versionOf = new Map<unknown, string>()
    for (const version of props.group.affected_versions || []) {
        for (const instance of version.components || []) versionOf.set(instance, version.project_version || '')
    }
    const selected = selectedTeam.value ? canonicalReviewTeam(selectedTeam.value) : ''
    return allInstances.value.filter((instance, index) => !selected || (
        unscopedDependencyInfo.instanceTeams.value.get(unscopedDependencyInfo.getInstanceTeamKey(instance, index)) || []
    ).some(team => canonicalReviewTeam(team) === selected)).map(instance => (
        instance.project_version ? instance : { ...instance, project_version: versionOf.get(instance) || '' }
    ))
})
const selectedAssessmentTeamAliases = computed(() => selectedTeam.value
    ? Object.entries(teamAliasGroups.value).find(([primary]) => canonicalReviewTeam(primary) === canonicalReviewTeam(selectedTeam.value))?.[1] || []
    : [])
const assessmentScopeComponents = computed(() => {
    const versionsByName = new Map<string, Set<string>>()
    for (const instance of assessmentScopeInstances.value) {
        const name = [instance.component_group, instance.component_name].filter(Boolean).join('/') || 'Unknown component'
        if (!versionsByName.has(name)) versionsByName.set(name, new Set())
        if (instance.component_version) versionsByName.get(name)!.add(instance.component_version)
    }
    return [...versionsByName].map(([name, versions]) => ({
        name, versions: [...versions].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })),
    })).sort((a, b) => a.name.localeCompare(b.name))
})
const assessmentScopeProjectVersions = computed(() => sortVersions([...new Set(
    assessmentScopeInstances.value.map(instance => instance.project_version).filter((version): version is string => !!version),
)], true))
const selectedAssessmentTeamComponents = computed(() => selectedTeam.value
    ? [...new Set(assessmentScopeInstances.value.map(instance => (
        `${[instance.component_group, instance.component_name].filter(Boolean).join('/') || 'Unknown component'}@${instance.component_version || '(unknown)'}`
    )))].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
    : [])
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
    const saved = activeAssessmentBlocks.value.find(block => block.team.toLocaleLowerCase() === teamKey)
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
// What every team decided, above the Global form (TeamAssessmentOverview).
const teamOverview = computed(() => buildTeamOverview({
    teams: effectiveTeamAssessments.value,
    blocks: mergedAssessmentData.value.blocks,
    aliasGroups: teamAliasGroups.value,
    changesRequestedTeams: changesRequestedTeams.value,
    componentsByTeam: assessmentComponentsByTeam.value,
    pendingReview: mergedAssessmentData.value.isPending,
    globalState: selectedTeam.value ? '' : (state.value === 'NOT_SET' ? groupGlobalDecision.value.state : state.value),
}))
/** "Open" in the overview: the team's tab, shown even when the team filter hides it. */
const openTeamFromOverview = (team: string) => {
    if (!teamTabs.value.includes(team)) showAllAssessmentTeams.value = true
    chooseTeamTab(team)
}
/** Former teams' assessments are listed with the stored evidence on the Context tab. */
const showFormerTeamAssessments = async () => {
    setDetailTab('overview')
    await nextTick()
    detailsEl.value?.querySelector?.('[data-testid="vulnerability-assessments"]')
        ?.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' })
}
/** The saved effective Global decision: the reviewer's, or the worst team decision. */
const groupGlobalDecision = computed(() => getGroupGlobalDecision(props.group))
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

    const teamKey = canonicalReviewTeam(scopedAssessmentTeam.value)
    if (changesRequestedTeams.value.some(team => canonicalReviewTeam(team) === teamKey)) {
        return { complete: false, pending: false }
    }
    let pending = false
    const covered = visibleInstances.value.every(instance => {
        const rawInstance = instance as Record<string, any>
        const instanceDetails = String(rawInstance.analysis_details || rawInstance.analysisDetails || '')
        const blocks = parseAssessmentBlocks(instanceDetails).filter(block => !block.historical)
        const hasApplicableBlock = blocks.some(block => {
            const blockTeam = canonicalReviewTeam(block.team)
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
    : Boolean(props.hasAutomaticAssessment || props.automaticAssessmentStatus)
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
    if (!selectedTeam.value && results.every(result => result.status === 'success')) resetRescoring.value = false
    if (!selectedTeam.value && results.every(result => result.status === 'success')) ssvcTouched.value = false
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
    takeoverSources.value.clear()
    formTouched.value = false
    // What was stored is what the form shows from here on. A choice made
    // on the Global form and not saved there yet stays.
    if (!selectedTeam.value || !responseTouched.value) {
        responseTouched.value = false
        response.value = parseAssessmentResponse(success.new_details || finalText) || 'NOT_SET'
    }
    codeAnalysisDraftApplied.value = false
    codeAnalysisDraftSummary.value = ''
    codeAnalysisRunIds.value = []
    codeEvidenceByTeam.value = {}
    dirtyEvidenceTeams.value = new Set()
    automaticFallbackTeams.value = new Set()
}

const handleAssessmentUpdateResults = async (results: any[], finalState: string, finalText: string) => {
    historyRefreshKey.value += 1
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

    const unusable = unusableEvidenceId(err.response?.data?.detail)
    if (unusable && codeEvidenceIds.value.includes(unusable)) {
        // Keep the draft; only stop recording this evidence as used.
        codeEvidenceIds.value = codeEvidenceIds.value.filter(id => id !== unusable)
        await showAlert(
            'Code evidence removed',
            `${err.response.data.detail}. It is no longer recorded as used by this draft; ` +
            'remove its reference line from the text if it no longer applies, then save again.',
        )
        return
    }

    await showAlert('Error', 'Failed to update assessment')
    console.error(err)
}

const toggleAssessmentTeamScope = () => {
    teamTabChosen.value = false
    showAllAssessmentTeams.value = !showAllAssessmentTeams.value
    if (!showAllAssessmentTeams.value && scopedAssessmentTeam.value) {
        selectedTeam.value = scopedAssessmentTeam.value
    }
}

watch(activeTeamScope, () => {
    teamTabChosen.value = false
    showAllAssessmentTeams.value = false
    scopedCodeAnalysisAvailable.value = false
    if (activeTeamScope.value) {
        selectedTeam.value = scopedAssessmentTeam.value
    }
}, { immediate: true })

// Entering the workspace keeps every draft and the chosen team: the card is
// the same instance, only its layout changes.
watch(isWorkspace, (open, wasOpen) => {
    if (open) {
        if (activeDetailTab.value === 'review') {
            // The user was on the form and already chose the team there.
            activeDetailTab.value = 'overview'
        } else {
            autoSelectReviewTeam()
        }
        void nextTick(() => workspaceHeadingEl.value?.focus())
    } else if (wasOpen) {
        // Leaving lands on the form the user was just working in.
        activeDetailTab.value = 'review'
    }
}, { immediate: true })

const teamBlockMeta = (team: string): AssessmentBlock | undefined => {
    return activeAssessmentBlocks.value.find(b => b.team === team)
}

/** The user picks the Global ('') or a team tab; that choice stays. */
const chooseTeamTab = (team: string) => {
    teamTabChosen.value = true
    selectedTeam.value = team
}

/** Every component of the vulnerability, for the clear confirmation. */
const allComponentNames = computed(() => Array.from(new Set(
    allInstances.value.map(instance => instance.component_name).filter(Boolean),
)).sort())

/** The saved block of the Global or team assessment being edited. */
const selectedBlockMeta = computed(() => teamBlockMeta(selectedTeam.value || 'General'))
const changeRequests = computed(() => teamChangesRequestsForFindings(allInstances.value))
const canonicalReviewTeam = (team: string) =>
    resolveTeamAlias(team, teamAliasGroups.value).trim().toLowerCase()
const selectedTeamChangeRequests = computed(() => selectedTeam.value
    ? changeRequests.value.filter(request => canonicalReviewTeam(request.team) === canonicalReviewTeam(selectedTeam.value))
    : [])
const visibleChangeRequests = computed(() => selectedTeam.value
    ? selectedTeamChangeRequests.value
    : isReviewer.value ? changeRequests.value : [])
const withdrawableRequestTeams = computed(() => isReviewer.value && vulnTaskId.value
    ? [...new Set(visibleChangeRequests.value.map(request => request.team))]
    : [])
const canRequestChanges = computed(() => Boolean(
    isReviewer.value && selectedTeam.value && vulnTaskId.value
    && !selectedTeamChangeRequests.value.length && !updating.value && !loadingDetails.value
    && allInstances.value.some(instance => {
        const text = instance.analysis_details ?? instance.analysisDetails ?? ''
        if (!hasPendingReviewMarker(text)) return false
        const block = parseAssessmentBlocks(text).find(block =>
            !block.historical && block.state && block.state !== 'NOT_SET'
            && canonicalReviewTeam(block.team) === canonicalReviewTeam(selectedTeam.value))
        return Boolean(block && !block.reviewer)
    }),
))
const openReviewChangeAction = (team: string, withdraw = false) => {
    const taskId = vulnTaskId.value
    if (!taskId || loadingDetails.value || updating.value) return
    if (withdraw ? !withdrawableRequestTeams.value.includes(team) : !canRequestChanges.value) return
    const revisions: Record<string, number> = {}
    for (const instance of allInstances.value) {
        if (!instance.finding_uuid) continue
        const stored = originalAnalysis.value[instance.finding_uuid]
        revisions[instance.finding_uuid] = stored?.dtvpRevision ?? stored?.dtvp_revision ?? instance.dtvp_revision ?? 0
    }
    requestChangesError.value = ''
    requestChangesStale.value = false
    reviewRequest.value = { task_id: taskId, group_id: props.group.id, team, revisions, withdraw }
}
const submitRequestChanges = async (rationale: string) => {
    if (!reviewRequest.value || requestingChanges.value || requestChangesStale.value) return
    const { withdraw, ...target } = reviewRequest.value
    if (!withdraw && !rationale.trim()) return
    requestingChanges.value = true
    requestChangesError.value = ''
    try {
        const results = await requestAssessmentChanges(withdraw
            ? { ...target, action: 'withdraw' }
            : { ...target, rationale })
        reviewRequest.value = null
        await refreshDetails()
        historyRefreshKey.value += 1
        emit('update:assessment', { dtvp_results: results })
    } catch (error: any) {
        requestChangesStale.value = error?.response?.status === 409
        requestChangesError.value = requestChangesStale.value
            ? 'The assessment changed. Close this dialog, reload the details, and try again.'
            : typeof error?.response?.data?.detail === 'string'
                ? error.response.data.detail
                : 'The change request could not be saved. Try again.'
    } finally {
        requestingChanges.value = false
    }
}
const selectedBlockMetaText = computed(() => {
    const block = selectedBlockMeta.value
    if (!block) return ''
    const user = block.user && block.user.toLowerCase() !== 'unknown' ? `Assessed by ${block.user}` : ''
    const date = block.timestamp ? new Date(block.timestamp).toLocaleDateString() : ''
    const review = block.reviewer ? `Reviewed by ${block.reviewer}${block.reviewedAt ? `, ${new Date(block.reviewedAt).toLocaleString()}` : ' (approval time not recorded)'}` : ''
    return [[user, date].filter(Boolean).join(', '), review].filter(Boolean).join(' · ')
})

/** Project versions of the findings in scope, newest first. */
const visibleProjectVersions = computed(() => {
    const visible = new Set<unknown>(visibleInstances.value)
    return sortVersions(Array.from(new Set(
        (props.group.affected_versions || [])
            .filter(version => version.components?.some(component => visible.has(component)))
            .map(version => version.project_version)
            .filter((version): version is string => !!version),
    )), true)
})

const teamBlockStateColor = (state?: string): string => {
    if (!state || state === 'NOT_SET') return 'bg-gray-500'
    if (state === 'EXPLOITABLE' || state === 'IN_TRIAGE') return 'bg-red-500'
    if (state === 'NOT_AFFECTED' || state === 'RESOLVED' || state === 'FALSE_POSITIVE') return 'bg-green-500'
    return 'bg-yellow-500'
}


// Whether Repair… applies: checked again after every change of the assessment.
watch(() => [props.group?.id, vulnTaskId.value, isReviewer.value, historyRefreshKey.value] as const, () => {
    void checkRepair()
}, { immediate: true })
</script>

<template>
    <div
        ref="cardEl"
        class="vuln-card relative min-w-0 max-w-full rounded-lg border transition-colors"
        :class="[
            isWorkspace ? 'flex h-full flex-col overflow-hidden'
                : inModal ? 'h-full min-h-0 overflow-y-auto overscroll-contain'
                : expanded ? 'overflow-visible z-40' : 'overflow-hidden',
            'border-gray-700 bg-gray-800',
        ]"
    >
    <!-- Header -->
    <div
        ref="headerEl"
        data-testid="expanded-vulnerability-header"
        @click="!inModal && (expanded = !expanded)"
        class="flex items-start px-4 py-2 transition-colors"
        :style="{ backgroundColor: severityTint }"
        :class="[inModal ? '' : 'cursor-pointer', isWorkspace ? 'shrink-0' : '']"
    >

        <VulnGroupCardHeader
            :group="group"
            :displayState="displayState"
            :technicalState="technicalState"
            :originalSeverity="originalSeverity"
            :rescoredSeverity="rescoredSeverity"
            :rescoredScore="displayedRescore"
            :normalizedTags="scopedHeaderTags"
            :assessedTeams="assessedTeams"
            :missingAssessmentTeams="teamOverview.missingTeams"
            @copy-id="copyId"
            :expanded="expanded"
            :canApprove="canApprove"
            :approvalUnavailableReason="approvalUnavailableReason"
            :isPendingReview="isPendingReview"
            :dependencyRelationship="dependencyRelationship"
            :showExpandToggle="!inModal"
            :hasAutomaticAssessment="props.hasAutomaticAssessment"
            :automaticAssessmentStatus="props.automaticAssessmentStatus"
            :scoreTitle="assessmentScoreTitle"
            :hasUnsavedDraft="hasUnsavedDraft"
            :instanceCountOverride="visibleInstances.length"
            :versionCount="visibleProjectVersions.length"
            :suppressedCount="suppressedInstanceCount"
            :changesRequestedTeams="changesRequestedTeams"
            :oldestAttributedOnMsOverride="scopedOldestAttributedOnMs"
            :componentSummaryOverride="scopedComponentSummary"
            @approve-assessment="requestApproval"
        >
            <template v-if="inModal" #actions>
                <button
                    v-if="workspaceAvailable"
                    type="button"
                    data-testid="workspace-toggle"
                    class="relative z-30 mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded border transition-colors"
                    :class="isWorkspace
                        ? 'border-cyan-600/70 bg-cyan-950/60 text-cyan-100 hover:bg-cyan-900/60'
                        : 'border-gray-700/80 bg-gray-950/70 text-gray-300 hover:bg-gray-800 hover:text-white'"
                    :title="isWorkspace ? 'Leave assessment workspace' : 'Open assessment workspace'"
                    :aria-label="isWorkspace ? 'Leave assessment workspace' : 'Open assessment workspace'"
                    :aria-pressed="isWorkspace ? 'true' : 'false'"
                    @click.stop="toggleWorkspace"
                >
                    <Minimize2 v-if="isWorkspace" :size="15" aria-hidden="true" />
                    <Maximize2 v-else :size="15" aria-hidden="true" />
                </button>
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
    <div
        v-if="expanded"
        ref="detailsEl"
        :class="isWorkspace
            ? 'flex min-h-0 flex-1 flex-col overflow-hidden px-4 border-t border-gray-700'
            : ['px-4 pb-4 border-t border-gray-700', !inModal && 'overflow-y-auto']"
        :style="inModal ? undefined : { maxHeight: detailsMaxHeight }"
    >
        <div data-vuln-card-sticky-nav class="sticky top-0 z-30 -mx-4 mb-5 border-b border-gray-700/80 bg-gray-900/95 px-4 shadow-lg backdrop-blur" :class="isWorkspace ? 'shrink-0' : ''">
            <div class="-mx-4 flex flex-wrap items-end gap-2 px-4">
                <div class="flex min-w-0 grow basis-[min(100%,22rem)] flex-wrap items-end" role="tablist" aria-label="Vulnerability detail sections">
                    <button
                        v-for="tab in visibleDetailTabs"
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
                        <component
                            :is="tab.icon"
                            :size="13"
                            :class="{ 'text-blue-300': tab.id === 'analysis' && codeAnalysisAvailableForScope }"
                            :title="tab.id === 'analysis' && codeAnalysisAvailableForScope ? 'Code-analysis result available' : undefined"
                            :data-testid="tab.id === 'analysis' && codeAnalysisAvailableForScope ? 'automatic-assessment-badge' : undefined"
                            aria-hidden="true"
                        />
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
                <div class="my-1.5 flex max-w-full flex-wrap items-center gap-2" data-testid="assessment-actions">
                    <button
                        v-if="canApprove"
                        type="button"
                        :disabled="approvalAtForm && !canApproveNow"
                        :title="approvalAtForm
                            ? (approvalBlockedReason || (groupGlobalDecision.source === 'manual'
                                ? 'Save this Global assessment and remove the pending review status'
                                : 'Record this Global decision (the worst team assessment unless you changed it) as the Global assessment and remove the pending review status'))
                            : 'Open the Global assessment to check and approve it'"
                        data-testid="assessment-approve-button"
                        :class="[actionButton, actionButtonApprove]"
                        @click="approvalAtForm ? approveAssessment() : requestApproval()"
                    >
                        <CheckCircle :size="13" />
                        {{ approvalAtForm ? 'Approve' : 'Review & approve' }}
                    </button>
                    <button
                        type="button"
                        @click="() => handleUpdate(false, false, selectedTeamChangeRequests.length > 0)"
                        :disabled="!canApplyAssessment"
                        :title="canApprove ? 'Saves your changes. The assessment stays pending review until you approve it.' : undefined"
                        data-testid="assessment-submit-button"
                        :class="[actionButton, canApprove ? actionButtonSecondary : actionButtonPrimary]"
                    >
                        {{ assessmentActionLabel }}
                    </button>
                    <button
                        type="button"
                        @click="refreshDetails"
                        :disabled="updating || loadingDetails"
                        :class="[actionButton, actionButtonSecondary]"
                        title="Reload from server (discard local changes)"
                        aria-label="Reload assessment from server"
                    >
                        <RefreshCw :size="14" :class="{ 'animate-spin': loadingDetails }" />
                    </button>
                    <div class="relative">
                        <button
                            type="button"
                            :class="[actionButton, actionButtonSecondary]"
                            title="More actions"
                            aria-label="More actions"
                            aria-haspopup="menu"
                            :aria-expanded="showMoreMenu ? 'true' : 'false'"
                            data-testid="assessment-more-button"
                            @click="showMoreMenu = !showMoreMenu"
                        >
                            <MoreHorizontal :size="14" />
                        </button>
                        <div v-if="showMoreMenu" class="fixed inset-0 z-40" aria-hidden="true" @click="showMoreMenu = false"></div>
                        <div
                            v-if="showMoreMenu"
                            role="menu"
                            data-testid="assessment-more-menu"
                            class="absolute right-0 z-50 mt-1 w-64 rounded border border-gray-700 bg-gray-900 py-1 text-left text-xs shadow-xl"
                            @keydown.esc.prevent="showMoreMenu = false"
                        >
                            <label
                                v-if="canChangeSuppression"
                                :for="`suppress-${group.id}`"
                                role="menuitemcheckbox"
                                :aria-checked="suppressed ? 'true' : 'false'"
                                class="flex cursor-pointer items-start gap-2 px-3 py-2 text-gray-300 hover:bg-gray-800"
                            >
                                <input
                                    type="checkbox"
                                    :id="`suppress-${group.id}`"
                                    v-model="suppressed"
                                    class="mt-0.5 h-3.5 w-3.5 rounded"
                                    @change="formTouched = true"
                                />
                                <span>
                                    <span class="flex items-center gap-1.5 font-semibold"><EyeOff :size="12" /> Suppress in Dependency-Track</span>
                                    <span class="mt-0.5 block text-[10px] leading-snug text-gray-500">Takes effect when the assessment is saved.</span>
                                </span>
                            </label>
                            <button
                                type="button"
                                role="menuitem"
                                :disabled="updating || loadingDetails || (assessedTeamNames.length === 0 && !canClearGlobalAssessment)"
                                class="flex w-full items-center gap-1.5 px-3 py-2 text-left font-semibold text-indigo-200 hover:bg-indigo-950/50 disabled:cursor-not-allowed disabled:opacity-40"
                                data-testid="assessment-cleanup-button"
                                @click="showMoreMenu = false; openCleanupModal()"
                            >
                                <Brush :size="12" /> Clean up assessment…
                            </button>
                            <button
                                v-if="repairStages.length > 0"
                                type="button"
                                role="menuitem"
                                :disabled="updating || loadingDetails"
                                class="flex w-full items-start gap-1.5 px-3 py-2 text-left font-semibold text-amber-200 hover:bg-amber-950/40 disabled:cursor-not-allowed disabled:opacity-40"
                                :title="repairTitle"
                                data-testid="assessment-repair-button"
                                @click="showMoreMenu = false; openRepairModal()"
                            >
                                <Wrench :size="12" class="mt-0.5 shrink-0" />
                                <span>
                                    Repair…
                                    <span class="mt-0.5 block text-[10px] font-normal leading-snug text-gray-500">{{ repairStages.map(stage => stage.label).join(', ') }}</span>
                                </span>
                            </button>
                            <button
                                type="button"
                                role="menuitem"
                                :disabled="updating || loadingDetails || (assessedTeamNames.length === 0 && !canClearGlobalAssessment)"
                                class="flex w-full items-center gap-1.5 px-3 py-2 text-left font-semibold text-red-300 hover:bg-red-950/50 disabled:cursor-not-allowed disabled:opacity-40"
                                data-testid="assessment-clear-button"
                                @click="showMoreMenu = false; openClearModal()"
                            >
                                <Eraser :size="12" /> Clear assessment…
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            <div
                v-if="approvalUnavailableReason"
                data-testid="approval-unavailable-reason"
                class="mb-1.5 rounded border border-yellow-700/40 bg-yellow-950/20 px-2 py-1 text-[11px] leading-relaxed text-yellow-100/80"
            >
                {{ approvalUnavailableReason }}
            </div>
        </div>

        <!-- In tab mode these wrappers are display: contents and change nothing. -->
        <div
            data-testid="workspace-columns"
            :class="isWorkspace
                ? 'grid min-h-0 flex-1 gap-4 grid-cols-[minmax(0,1fr)_minmax(34rem,42rem)] 2xl:grid-cols-[minmax(0,1fr)_minmax(36rem,48rem)]'
                : 'contents'"
        >
        <div
            ref="contextPaneEl"
            data-testid="workspace-context-pane"
            :class="isWorkspace ? 'min-h-0 min-w-0 overflow-y-auto overscroll-contain pb-4 pr-1' : 'contents'"
            :role="isWorkspace ? 'region' : undefined"
            :aria-label="isWorkspace ? 'Context' : undefined"
        >
        <div
            v-if="versionOverrideScopes.length > 0"
            data-testid="card-version-scopes"
            class="mb-3 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-300"
        >
            <span class="text-slate-500">Version overrides:</span>
            <span
                v-for="scope in versionOverrideScopes"
                :key="scope.key"
                data-testid="card-version-scope"
                class="rounded border px-1.5 py-0.5"
                :class="scope.ambiguous ? 'border-red-400/40 text-red-200' : 'border-sky-400/30 text-sky-200'"
            >
                {{ scope.label }}<template v-if="scope.versions"> · {{ scope.versions }}</template><template v-if="scope.pending"> · pending approval</template>
            </span>
        </div>
        <div
            v-if="inconsistencyIssues.length > 0 || assessmentVariantCount > 1"
            data-testid="card-differences-banner"
            :data-inconsistent="inconsistencyIssues.length > 0"
            class="mb-4 flex flex-wrap items-start justify-between gap-3 rounded border px-3 py-2 text-xs"
            :class="inconsistencyIssues.length > 0
                ? 'border-indigo-500/40 bg-indigo-950/30 text-indigo-100'
                : 'border-white/10 bg-white/[0.03] text-slate-300'"
            role="status"
        >
            <div class="flex min-w-0 grow basis-[min(100%,20rem)] items-start gap-2">
                <!-- Only an inconsistency is a warning. Findings that carry
                     different assessments (teams or versions decide
                     differently) are expected and only noted. -->
                <AlertTriangle v-if="inconsistencyIssues.length > 0" :size="14" class="mt-0.5 shrink-0 text-indigo-300" />
                <Info v-else :size="14" class="mt-0.5 shrink-0 text-slate-400" />
                <div class="min-w-0 space-y-1 [overflow-wrap:anywhere]">
                    <div :class="inconsistencyIssues.length > 0 ? 'font-bold' : 'font-semibold'">
                        {{ inconsistencyIssues.length > 0 ? 'Why this is inconsistent' : 'Assessments differ between findings' }}
                    </div>
                    <div v-if="assessmentVariantCount > 1" data-testid="card-differences-variants">
                        <strong>{{ differingFindingCount }} of {{ visibleInstances.length }}</strong>
                        findings carry a different assessment than the rest
                        ({{ assessmentVariantCount }} different assessments).
                    </div>
                    <div v-for="issue in inconsistencyIssues" :key="issue.code" data-testid="card-inconsistency-reason">
                        <strong class="text-indigo-200">{{ issue.label }}:</strong> {{ issue.detail }}
                    </div>
                    <div v-if="conflictingTeamStates.length > 1" class="flex flex-wrap items-center gap-1.5" data-testid="card-team-states">
                        <span class="text-indigo-200/80">Team decisions:</span>
                        <span
                            v-for="entry in conflictingTeamStates"
                            :key="entry.team"
                            class="rounded border border-indigo-400/30 bg-black/20 px-1.5 py-0.5"
                        >
                            {{ entry.team }} <strong>{{ entry.state.replaceAll('_', ' ').toLowerCase() }}</strong>
                        </span>
                    </div>
                </div>
            </div>
            <div class="flex flex-wrap gap-2">
                <button
                    v-if="assessmentVariantCount > 1"
                    type="button"
                    :class="[actionButton, actionButtonSecondary]"
                    data-testid="card-differences-open"
                    @click="openDifferences"
                >
                    Show differences
                </button>
                <button
                    v-if="(inconsistencyIssues.length > 0 || assessmentVariantCount > 1) && assessedTeamNames.length > 0"
                    type="button"
                    :class="[actionButton, actionButtonSecondary]"
                    :disabled="updating || loadingDetails"
                    title="Keep one version of the assessment for every finding, or clear stray ones, with a preview before saving"
                    data-testid="card-differences-cleanup"
                    @click="openCleanupModal"
                >
                    <Brush :size="12" /> Clean up…
                </button>
                <button
                    v-if="repairStages.length > 0"
                    type="button"
                    :class="[actionButton, actionButtonSecondary]"
                    :disabled="updating || loadingDetails"
                    :title="repairTitle"
                    :aria-label="repairTitle"
                    data-testid="card-differences-repair"
                    @click="openRepairModal"
                >
                    <Wrench :size="12" /> Repair…
                </button>
            </div>
        </div>

        <section
            v-show="activeDetailTab === 'overview'"
            :id="detailTabPanelId('overview')"
            :aria-labelledby="detailTabId('overview')"
            class="space-y-5 pt-1"
            role="tabpanel"
        >
            <DetailSection
                title="Description & references"
                help="Understand the advisory before evaluating where it appears in this project."
            >
                <p v-if="evidenceSources(group).includes('CISA_SSVC')" class="mb-2 text-xs text-gray-300">
                    CISA Vulnrichment exploitation assessment available in the SSVC calculator.
                </p>
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
                title="Where it was found"
                help="Every reported component by product version, with its team and the assessment of each finding. Open a component to see how it enters the product."
                data-testid="where-found"
                bodyClass="space-y-3"
            >
                <FindingMatrix
                    ref="findingMatrixRef"
                    :instances="matrixInstances"
                    :canApply="isReviewer"
                    :banner="false"
                    @apply-variant="applyFindingVariant"
                />

                <div
                    v-if="activeTeamScope && hiddenTeamScopeInstanceCount"
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

            <!-- The matrix shows each component's team; this says which
                 mapped component gives it: the component itself, one above
                 it in a chain, or the catch-all. -->
            <div
                v-if="triggeringTaggedComponents.length > 0"
                data-testid="triggering-team-components"
                class="min-w-0 space-y-2 rounded border border-gray-800/80 bg-gray-950/30 p-3"
            >
                <h5 class="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-500">
                    Team-mapped components
                    <span
                        class="inline-flex cursor-help normal-case tracking-normal"
                        title="The components whose team mapping assigns the teams above: the affected component itself or a component above it in a dependency chain. Without a mapping the catch-all '*' assigns the team."
                    >
                        <Info :size="11" aria-hidden="true" />
                    </span>
                </h5>
                <div class="flex flex-wrap gap-1.5 overflow-x-auto pb-1">
                    <span
                        v-for="comp in triggeringTaggedComponents"
                        :key="comp.name"
                        data-testid="triggering-team-component"
                        :data-catch-all="comp.catchAll ? 'true' : undefined"
                        class="inline-flex shrink-0 items-center whitespace-nowrap px-2 py-0.5 rounded text-[11px] font-mono border"
                        :class="comp.catchAll ? 'bg-amber-950/30 text-amber-100 border-amber-700/50' : 'bg-gray-800 text-gray-300 border-gray-700'"
                        :title="comp.catchAll
                            ? `Neither this component nor any component of its chain is in the team mapping, so the catch-all '*' gives the team ${comp.tag}. Add one of these names to the mapping to give it a team.`
                            : undefined"
                    >
                        {{ comp.name }}
                        <span v-if="comp.versions.length" class="text-gray-500">@{{ comp.versions.join(', ') }}</span>
                        <span v-if="comp.under?.length" class="ml-1 font-sans text-amber-200/70">under {{ comp.under.join(', ') }}</span>
                        <span class="ml-2 text-[10px] font-normal" :class="comp.catchAll ? 'text-amber-300' : 'text-blue-300'">({{ comp.tag }}<template v-if="comp.catchAll">; no team mapping, catch-all '*'</template>)</span>
                    </span>
                </div>
            </div>
            </DetailSection>

            <DetailSection
                title="Existing assessment evidence"
                :help="isWorkspace
                    ? 'Read-only evidence already stored for findings in the current component scope. Create or change the assessment in the form on the right.'
                    : 'Read-only evidence already stored for findings in the current component scope. Create or change the assessment in the Assessment tab.'"
                bodyClass="space-y-3"
                data-testid="vulnerability-assessments"
            >
                <VulnGroupAssessmentDetails
                    v-for="assessment in groupedAssessments"
                    :key="`${assessment.state}-${assessment.instances.length}`"
                    :assessment="assessment"
                    :isReviewer="isReviewer"
                    :showDependencies="false"
                    @apply-all="onEvidenceApplyAll"
                    @adopt-team="onEvidenceAdoptTeam"
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
                :evidenceTargets="visibleInstances.map(instance => ({ component: instance.component_name, finding_uuid: instance.finding_uuid }))"
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
                :reportedFindingUuids="reportedFindingUuids"
                :refreshKey="historyRefreshKey"
                :focusEvidenceId="requestedEvidenceId"
                @apply-result="handleCodeAnalysisResult"
                @apply-all-results="handleApplyAllCodeAnalysisResults"
                @result-change="handleCodeAnalysisResultChange"
                @scope-results-change="scopedCodeAnalysisAvailable = $event"
                @proposals-change="handleCodeAnalysisProposalsChange"
                @apply-evidence="handleApplyCodeEvidence"
                @evidence-loaded="loadEvidenceSelections"
            />
        </section>
        </div>

        <div
            ref="assessmentPaneEl"
            data-testid="workspace-assessment-pane"
            :class="isWorkspace ? 'min-h-0 overflow-y-auto overscroll-contain pb-4 pr-1 border-l border-gray-800 pl-4' : 'contents'"
        >
        <h3
            v-if="isWorkspace"
            :id="`vuln-${group.id}-workspace-assessment-heading`"
            ref="workspaceHeadingEl"
            data-testid="workspace-assessment-heading"
            tabindex="-1"
            title="The context is on the left; save with the action bar above."
            class="mb-3 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-cyan-100 outline-none"
        >
            <ShieldCheck :size="13" aria-hidden="true" />
            Assessment
            <span
                v-if="detailTabStatus('review')"
                class="rounded-full border border-current/20 bg-black/20 px-1.5 py-0.5 text-[9px] normal-case tracking-normal opacity-80"
                data-testid="detail-tab-status-review"
            >
                {{ detailTabStatus('review') }}
            </span>
        </h3>
        <section
            v-show="reviewVisible"
            :id="detailTabPanelId('review')"
            :aria-labelledby="isWorkspace ? `vuln-${group.id}-workspace-assessment-heading` : detailTabId('review')"
            class="space-y-3"
            :role="isWorkspace ? 'region' : 'tabpanel'"
        >
            <div class="h-fit space-y-4">
                    <!-- Who assesses: the Global or a team assessment. The tabs
                         are the heading; the scope note only says what the team
                         filter hides. -->
                    <section
                        data-testid="assessment-scope"
                        class="rounded-lg border border-gray-700/70 bg-gray-900/45 px-4 pb-3 pt-2"
                        :aria-labelledby="`vuln-${group.id}-assessment-scope-heading`"
                    >
                        <h4 :id="`vuln-${group.id}-assessment-scope-heading`" class="sr-only">
                            {{ selectedTeam ? `Team Assessment: ${selectedTeam}` : isReviewer ? 'Global Assessment' : 'Team Assessment' }}
                        </h4>
                        <div class="flex flex-wrap items-end justify-between gap-x-3 gap-y-1 border-b border-gray-700">
                            <div class="flex flex-wrap gap-0">
                                <button
                                    v-if="isReviewer"
                                    @click="chooseTeamTab('')"
                                    :aria-pressed="!selectedTeam ? 'true' : 'false'"
                                    :class="[
                                        '-mb-px px-3 py-1.5 text-xs font-semibold border-b-2 transition-colors cursor-pointer',
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
                                    @click="chooseTeamTab(team)"
                                    :aria-pressed="selectedTeam === team ? 'true' : 'false'"
                                    :class="[
                                        '-mb-px max-w-full px-3 py-1.5 text-left text-xs font-semibold border-b-2 transition-colors cursor-pointer [overflow-wrap:anywhere]',
                                        selectedTeam === team
                                            ? 'border-blue-500 text-blue-300 bg-blue-950/20'
                                            : 'border-transparent text-gray-500 hover:text-gray-300'
                                    ]"
                                >
                                    {{ team }}
                                    <span
                                        v-if="changesRequestedTeams.some(requestedTeam => canonicalReviewTeam(requestedTeam) === canonicalReviewTeam(team))"
                                        class="ml-1 text-amber-200"
                                    >· Changes requested</span>
                                    <span v-if="assessedTeams.has(team)" class="ml-1 inline-block w-1.5 h-1.5 rounded-full" :class="teamBlockStateColor(teamBlockMeta(team)?.state)"></span>
                                </button>
                            </div>
                            <div
                                v-if="activeTeamScope"
                                data-testid="assessment-team-scope"
                                class="mb-1 flex flex-wrap items-center gap-2 text-[11px] text-blue-200/70"
                            >
                                <span v-if="!isReviewer" :title="`The team filter shows only ${activeTeamScope}.`">
                                    Other teams are hidden by the team filter
                                </span>
                                <button
                                    v-if="isReviewer"
                                    type="button"
                                    data-testid="toggle-assessment-team-scope"
                                    class="rounded border border-blue-700/60 bg-blue-900/30 px-2 py-0.5 font-semibold text-blue-100 transition-colors hover:bg-blue-900/55"
                                    @click="toggleAssessmentTeamScope"
                                >
                                    {{ showAllAssessmentTeams ? `Focus ${activeTeamScope}` : 'Show all teams' }}
                                </button>
                            </div>
                        </div>

                        <div
                            v-if="selectedTeam || selectedBlockMetaText"
                            class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-gray-500"
                        >
                            <span
                                v-if="selectedTeam"
                                data-testid="assessment-team-components"
                                class="flex flex-wrap items-center gap-1.5"
                            >
                                <span>{{ selectedAssessmentTeamComponents.length === 1 ? 'Component' : 'Components' }}:</span>
                                <span
                                    v-for="component in selectedAssessmentTeamComponents"
                                    :key="component"
                                    class="rounded border border-blue-800/60 bg-blue-950/30 px-1.5 py-0.5 font-mono text-blue-200"
                                >
                                    {{ component }}
                                </span>
                                <span v-if="selectedAssessmentTeamComponents.length === 0" class="text-amber-300">
                                    No confirmed component ownership
                                </span>
                            </span>
                            <!-- Block header metadata (read-only) -->
                            <span v-if="selectedBlockMetaText" data-testid="assessment-block-meta">{{ selectedBlockMetaText }}</span>
                            <button
                                v-if="canRequestChanges"
                                type="button"
                                class="ml-auto rounded border border-amber-600/50 px-2 py-1 text-xs font-semibold text-amber-200 hover:bg-amber-900/40"
                                @click="openReviewChangeAction(selectedTeam)"
                            >Request changes</button>
                        </div>

                        <section
                            v-if="visibleChangeRequests.length"
                            data-testid="assessment-changes-requested"
                            class="mt-3 rounded border border-amber-700/50 bg-amber-950/30 p-3 text-xs text-amber-100"
                        >
                            <h5 class="font-semibold">Changes requested</h5>
                            <div
                                v-for="request in visibleChangeRequests"
                                :key="`${request.team}-${request.requested_at_ms}-${request.reviewer}-${request.rationale}`"
                                class="mt-2 space-y-1"
                            >
                                <p v-if="!selectedTeam" class="font-semibold">{{ request.team }}</p>
                                <p class="whitespace-pre-wrap break-words">{{ request.rationale }}</p>
                                <p class="text-amber-200/75">{{ request.reviewer }} · {{ new Date(request.requested_at_ms).toLocaleDateString() }}</p>
                            </div>
                            <p v-if="selectedTeam" class="mt-2 text-amber-200/75">Update this assessment and resubmit it for review.</p>
                            <div v-if="withdrawableRequestTeams.length" class="mt-2 flex flex-wrap gap-2">
                                <button
                                    v-for="team in withdrawableRequestTeams"
                                    :key="team"
                                    type="button"
                                    :disabled="updating || loadingDetails"
                                    class="rounded border border-amber-600/50 px-2 py-1 text-xs font-semibold text-amber-200 hover:bg-amber-900/40 disabled:opacity-50"
                                    @click="openReviewChangeAction(team, true)"
                                >Withdraw request for {{ team }}</button>
                            </div>
                        </section>

                        <div
                            v-if="selectedTeam && previousTeamAssessments.length && !teamBlockMeta(selectedTeam)"
                            data-testid="previous-team-assessments"
                            class="mt-3 rounded border border-amber-700/40 bg-amber-950/20 p-3 text-xs"
                        >
                            <div class="font-semibold text-amber-100">Previous team assessments</div>
                            <p class="mt-1 text-amber-200/75">Use an earlier decision as a draft. Check the evidence and version scope before submitting for {{ selectedTeam }}.</p>
                            <div v-for="block in previousTeamAssessments" :key="block.team" class="mt-2 flex items-start justify-between gap-3 border-t border-amber-700/30 pt-2">
                                <div class="min-w-0 text-amber-100">
                                    <strong>{{ block.team }}</strong> · {{ block.state.replaceAll('_', ' ') }}
                                    <span v-if="block.user" class="text-amber-200/60"> · {{ block.user }}</span>
                                    <p class="mt-0.5 line-clamp-2 text-amber-200/70">{{ block.details }}</p>
                                </div>
                                <button type="button" :data-testid="`use-previous-team-${block.team}`" class="shrink-0 rounded border border-amber-500/40 px-2 py-1 font-semibold text-amber-100 hover:bg-amber-500/15" @click="usePreviousTeamAssessment(block)">Use as draft</button>
                            </div>
                        </div>

                        <EarlierAssessments
                            v-if="assessmentEmpty"
                            :findings="earlierFindings"
                            @use="useEarlierAssessment"
                        />

                        <div
                            v-if="approvalPrefilled && !selectedTeam"
                            data-testid="approval-prefilled-note"
                            class="mt-3 rounded border border-green-700/40 bg-green-950/20 px-3 py-2 text-[11px] leading-relaxed text-green-100/90"
                            role="status"
                        >
                            No reviewer has set the Global decision, so it is derived: the worst of the team assessments<template v-if="groupGlobalDecision.source === 'derived'">,
                            {{ stateLabelOf(groupGlobalDecision.state) }} ({{ groupGlobalDecision.teams.join(', ') }})</template>, with the rescoring rule for that state applied.
                            Approve records it as the Global assessment unless you change it here. Nothing is saved until you press Approve.
                        </div>
                        <!-- What each team decided; the worst state is what the
                             Global decision takes over. -->
                        <TeamAssessmentOverview
                            v-if="isReviewer && !selectedTeam && teamOverview.rows.length"
                            :overview="teamOverview"
                            :worstState="effectiveAssessmentWorst?.state || ''"
                            :globalDecision="groupGlobalDecision"
                            @open="openTeamFromOverview"
                            @use-as-global="row => handleAdoptTeamBlock(row, false)"
                            @use-worst="applyEffectiveAssessmentSummary"
                            @show-former="showFormerTeamAssessments"
                        />
                    </section>

                    <ReportedFindingScope
                        :instances="assessmentScopeInstances"
                        :team="selectedTeam"
                        :teamAliases="selectedAssessmentTeamAliases"
                    />

                    <VulnAboutSummary
                        :vulnId="group.id"
                        :title="group.title"
                        :description="group.description"
                        :cwes="group.cwes"
                        :recommendation="group.recommendation"
                        :cvssVector="group.cvss_vector"
                        :components="assessmentScopeComponents"
                        :projectVersions="assessmentScopeProjectVersions"
                        :links="externalLinks"
                        :collapsed="isWorkspace"
                    />
                    <div
                        v-if="codeAnalysisDraftApplied"
                        data-testid="code-analysis-draft-banner"
                        class="rounded border border-cyan-700/40 bg-cyan-950/20 px-3 py-2 text-xs text-cyan-200"
                    >
                        {{ codeAnalysisDraftSummary || 'Code analysis draft loaded into the assessment fields.' }}
                        Review and {{ isReviewer ? 'save' : 'submit' }} when ready.
                    </div>

                    <DetailSection
                        title="Decision & rationale"
                        help="Set the assessment state, justification, technical rationale, ownership, and any reviewer-only rescoring context."
                        data-testid="assessment-decision-section"
                        :class="formHighlight ? 'ring-2 ring-indigo-400' : ''"
                    >
                        <template #actions>
                            <button
                                v-if="canClearSelectedAssessment"
                                type="button"
                                :class="[actionButton, 'border-red-800/70 text-red-300 hover:bg-red-950/50']"
                                :disabled="updating || loadingDetails || clearingAssessment"
                                data-testid="clear-selected-assessment"
                                @click="openClearModal(true)"
                            >
                                Clear {{ selectedAssessmentName }} assessment…
                            </button>
                        </template>
                    <p
                        v-if="assessmentMissingFields.length"
                        data-testid="assessment-completeness"
                        class="mb-3 text-[11px] text-amber-200/90"
                    >
                        Still needed to submit: {{ assessmentMissingFields.join(', ') }}.
                    </p>
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
                    <p v-if="ssvcTouched && selectedTeam" class="mb-3 text-xs text-amber-300">Unsaved SSVC changes: return to the global assessment to save them.</p>
                    <p v-if="responseTouched && selectedTeam" class="mb-3 text-xs text-amber-300" data-testid="unsaved-response-hint">Unsaved response: return to the global assessment to save it.</p>
                    <div :class="isReviewer && !selectedTeam ? (isWorkspace ? 'grid items-start gap-4' : 'grid items-start gap-4 xl:grid-cols-2') : ''">
                        <!-- Assessment Section (Reviewer Global or Team Selected) -->
                        <div v-if="selectedTeam || isReviewer" :class="['border rounded p-3', selectedTeam ? 'border-blue-700/50 bg-blue-950/20' : 'border-purple-700/50 bg-purple-950/20']">
                            <div class="space-y-3">
                                <div>
                                    <label id="analysis-state-label" for="analysis-state-select" class="block text-xs font-semibold text-gray-400 mb-1">Analysis State</label>
                                    <CustomSelect
                                        id="analysis-state-select"
                                        aria-labelledby="analysis-state-label"
                                        :modelValue="state"
                                        @update:modelValue="changeAssessmentState"
                                        :options="ANALYSIS_STATES"
                                        size="sm"
                                    />
                                    <p
                                        v-if="isReviewer && !selectedTeam && state === 'NOT_SET' && groupGlobalDecision.source === 'derived'"
                                        class="mt-1 text-xs text-gray-400"
                                    >
                                        Effective state: {{ stateLabelOf(groupGlobalDecision.state) }}, derived from team assessments.
                                    </p>
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

                                <!-- The response is the Global assessment's: one value for the finding. -->
                                <div v-if="!selectedTeam && isReviewer" data-testid="analysis-response-field">
                                    <label id="response-label" for="response-select" class="block text-xs font-semibold text-gray-400 mb-1">Response</label>
                                    <CustomSelect
                                        id="response-select"
                                        aria-labelledby="response-label"
                                        :modelValue="response"
                                        @update:modelValue="changeResponse($event)"
                                        :options="RESPONSE_OPTIONS"
                                        size="sm"
                                    />
                                </div>

                                <div>

                                    <section class="mb-3 space-y-1 print:hidden" data-testid="assessment-supporting-evidence">
                                        <p class="text-xs font-semibold text-gray-400">Supporting evidence (stored in DTVP)</p>
                                        <div v-for="id in codeEvidenceIds" :key="id" class="flex items-center gap-2 text-xs text-gray-300">
                                            <button type="button" class="text-cyan-300 underline" @click="openSupportingEvidence(id)">{{ codeEvidenceTitles[id] || 'Supporting evidence' }}</button>
                                            <button type="button" class="text-amber-300" :aria-label="`Remove supporting evidence ${codeEvidenceTitles[id] || ''}`" @click="removeSelectedEvidence(id)">Remove</button>
                                        </div>
                                        <p v-if="!codeEvidenceIds.length" class="text-xs text-gray-500">No supporting evidence selected. The assessment rationale must explain the decision.</p>
                                    </section>
                                    <label for="analysis-details-textarea" class="block text-xs font-semibold text-gray-400 mb-1">{{ selectedTeam ? 'Analysis Details' : 'Global rationale' }}</label>
                                    <p v-if="isReviewer && !selectedTeam" data-testid="global-rationale-guidance" class="mb-2 text-xs text-gray-400">Review the team rationales above and write a synthesis here, preserving consumer and release differences. Saving records it in the Global assessment; a derived state alone is not a reviewer rationale.</p>
                                    <textarea
                                        id="analysis-details-textarea"
                                        v-model="details"
                                        @input="formTouched = true; markSelectedTeamAssessmentManual()"
                                        :placeholder="selectedTeam ? 'Explain the consumer and release scope, exposure, observations, limitations, decision rationale and required action.' : 'Synthesize the team conclusions. Preserve material differences between consumers and justify any severity change.'"
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
                        <section
                            v-if="isReviewer && !selectedTeam"
                            data-testid="global-cvss-rescoring"
                            class="min-w-0 space-y-4 rounded border border-gray-700 bg-gray-900/45 p-3"
                        >
                            <div class="flex flex-wrap items-center justify-between gap-2">
                                <h5 class="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-gray-300">
                                    <Calculator :size="13" class="text-purple-300" />
                                    CVSS & SSVC
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
                                    <p v-if="resetRescoring" data-testid="rescore-reset-hint" role="status" class="mt-1 text-xs text-amber-200">
                                        Rescoring will be removed when you save the Global assessment.
                                    </p>
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

                            <SsvcCalculator :model-value="pendingSsvc" :summary="savedSsvc" :disabled="updating || loadingDetails"
                                :cves="[group.id, ...(group.aliases || [])]" :active="reviewVisible"
                                :allow-autofill="!ssvcTouched && savedSsvc.status === 'UNASSESSED'" @update:model-value="changeSsvc" />
                        </section>

                    </div>

                    <!-- No-Team Section (Prompt for non-reviewers) -->
                    <div v-if="!selectedTeam && !isReviewer" class="p-4 rounded border border-gray-700 bg-gray-800/50 flex flex-col items-center justify-center text-center space-y-2">
                        <Shield :size="32" class="text-blue-500/50" />
                        <h4 class="text-sm font-bold text-gray-300">{{ activeTeamScope ? `Nothing here for ${activeTeamScope}` : 'Select a Team Tab' }}</h4>
                        <p class="text-xs text-gray-400 max-w-xs">
                          {{ activeTeamScope
                              ? `No component of this vulnerability belongs to ${activeTeamScope}. Clear the team filter to assess it, or ask a reviewer to change the team mapping in Settings.`
                              : 'Global assessments are restricted to reviewers. Select a team tab above to provide an assessment.' }}
                        </p>
                    </div>

                    <!-- The stored text is generated from the fields above; it
                         is shown read-only, for checking what is exported. -->
                    <div v-if="isReviewer && generatedAssessmentText" data-testid="generated-assessment-text">
                        <button
                            type="button"
                            data-testid="generated-assessment-text-toggle"
                            class="flex cursor-pointer items-center gap-1 text-xs text-gray-500 transition-colors hover:text-gray-300"
                            :aria-expanded="showGeneratedText ? 'true' : 'false'"
                            @click="showGeneratedText = !showGeneratedText"
                        >
                            <ChevronDown v-if="!showGeneratedText" :size="12" />
                            <ChevronUp v-else :size="12" />
                            Show generated text
                        </button>
                        <div v-if="showGeneratedText" class="mt-1 space-y-1">
                            <div class="flex flex-wrap items-center justify-between gap-2 text-[10px] text-gray-600">
                                <span>As stored and exported to Dependency-Track; generated from the assessment fields, read-only.</span>
                                <button
                                    type="button"
                                    data-testid="copy-generated-assessment-text"
                                    class="rounded border border-gray-700 px-2 py-0.5 font-semibold text-gray-300 hover:bg-gray-800"
                                    @click="copyGeneratedText"
                                >
                                    {{ generatedTextCopyState === 'copied' ? 'Copied' : generatedTextCopyState === 'error' ? 'Copy failed' : 'Copy' }}
                                </button>
                            </div>
                            <pre
                                data-testid="generated-assessment-text-body"
                                class="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded border border-gray-800 bg-gray-950/60 p-2 font-mono text-[11px] text-gray-400"
                            >{{ generatedAssessmentText }}</pre>
                        </div>
                    </div>


                    <!-- Ready for approval although teams have no block of their
                         own: approving the Global assessment completes it. -->
                    <div
                        v-if="isReviewer && !selectedTeam && displayState === 'NEEDS_APPROVAL' && approvalIssues.length > 0"
                        data-testid="assessment-approval-reasons"
                        class="pt-2 border-t border-gray-700 mt-2"
                    >
                        <div class="rounded border border-purple-600/30 bg-purple-950/20 p-2.5">
                            <div class="mb-1.5 text-[10px] font-black uppercase tracking-widest text-purple-300">
                                What completes it
                            </div>
                            <div
                                v-for="issue in approvalIssues"
                                :key="issue.code"
                                class="text-[11px] leading-relaxed text-purple-100/80"
                            >
                                <span class="font-bold text-purple-300">{{ issue.label }}:</span>
                                {{ issue.detail }}
                            </div>
                        </div>
                    </div>

                    <!-- Why the coverage is incomplete, with the repair. Why it is
                         inconsistent is said once, in the banner above the tabs. -->
                    <div
                        v-if="isReviewer && !selectedTeam && mergedAssessmentData.blocks.length > 0 && displayState === 'INCOMPLETE'"
                        class="pt-2 border-t border-gray-700 mt-2"
                    >
                        <div
                            v-if="incompleteIssues.length > 0"
                            data-testid="assessment-sync-reasons"
                            class="mb-2 rounded border border-amber-600/30 bg-amber-950/20 p-2.5"
                        >
                            <div class="mb-1.5 text-[10px] font-black uppercase tracking-widest text-amber-400">
                                Why synchronization is needed
                            </div>
                            <div
                                v-for="issue in incompleteIssues"
                                :key="issue.code"
                                class="text-[11px] leading-relaxed text-amber-100/80"
                            >
                                <span class="font-bold text-amber-300">{{ issue.label }}:</span>
                                {{ issue.detail }}
                            </div>
                        </div>
                        <button
                            data-testid="sync-all-assessments"
                            @click="syncAllAssessments"
                            class="w-full mb-2 bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-500 border border-yellow-600/50 font-bold py-1.5 rounded text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
                        >
                            <AlertTriangle :size="14" />
                            Sync all
                        </button>
                        <button
                            v-if="repairStages.length > 0"
                            type="button"
                            data-testid="sync-repair"
                            :title="repairTitle"
                            class="w-full mb-2 bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-600 font-bold py-1.5 rounded text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
                            @click="openRepairModal"
                        >
                            <Wrench :size="14" />
                            Repair… <span class="font-normal text-gray-400">({{ repairStages.map(stage => stage.label).join(', ') }})</span>
                        </button>
                    </div>
                    </DetailSection>

                    <DetailSection
                        title="History"
                        help="Every version of this assessment recorded in DTVP: who changed it, when, and how, including deletions and values adopted from Dependency-Track."
                        data-testid="assessment-history-section"
                    >
                        <AssessmentHistory :instances="allInstances" :refresh-key="historyRefreshKey" />
                    </DetailSection>
            </div>
        </section>
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

    <ClearAssessmentModal
      :show="showClearModal"
      :mode="clearModalMode"
      :scope-only="clearSelectedOnly"
      :instances="cleanupInstances"
      :repair-stages="repairStages"
      :team="selectedTeam"
      :assessed-teams="assessedTeamNames"
      :is-reviewer="isReviewer"
      :finding-count="allInstances.length"
      :versions="sortedAffectedProjectVersions"
      :components="allComponentNames"
      :busy="clearingAssessment"
      :error="clearAssessmentError"
      @close="showClearModal = false"
      @confirm="confirmClearAssessment"
      @cleaned="onAssessmentCleaned"
      @repair="openRepairModal"
    />

    <RequestAssessmentChangesDialog
      v-if="reviewRequest"
      :team="reviewRequest.team"
      :withdraw="reviewRequest.withdraw"
      :busy="requestingChanges"
      :error="requestChangesError"
      :stale="requestChangesStale"
      @close="reviewRequest = null"
      @request="submitRequestChanges"
    />

    <BulkWorkflowModal
      v-if="isReviewer && vulnTaskId"
      :show="showRepairModal"
      :task-id="vulnTaskId"
      :group-id="group.id"
      @close="showRepairModal = false; void checkRepair()"
      @applied="onRepairApplied"
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
