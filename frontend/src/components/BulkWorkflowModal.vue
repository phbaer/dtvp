<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { AlertTriangle, CheckCircle, Copy, Download, ExternalLink, History, Layers, Loader2, Upload, X } from '@lucide/vue'
import {
    applyBulkWorkflow,
    buildBulkWorkflowDocument,
    bulkWorkflowFilters,
    getBulkWorkflowSummary,
    previewBulkWorkflow,
    uploadBulkWorkflowSource,
    readBulkWorkflowSourceHistory,
    type BulkWorkflowApplyResponse,
    type BulkWorkflowErrorDetail,
    type BulkWorkflowFilters,
    type BulkWorkflowPreviewItem,
    type BulkWorkflowPreviewResponse,
    type BulkWorkflowSourceUpload,
    type BulkWorkflowSummaryItem,
    type BulkWorkflowTaskStatus,
    type RescoreRuleSyncPreviewFinding,
    type TaskVulnGroupListQuery,
} from '../lib/api'
import {
    AUTOMATIC_ASSESSMENT_OUTCOME_OPTIONS,
    AUTOMATIC_ASSESSMENT_RESCORE_OPTIONS,
    automaticAssessmentRescoreState,
    type AutomaticAssessmentOutcome,
    type AutomaticAssessmentRescoreState,
} from '../lib/automaticAssessmentFilters'
import { getRuntimeConfig } from '../lib/env'

const props = withDefaults(defineProps<{
    show: boolean
    taskId: string | null
    query?: TaskVulnGroupListQuery
    /**
     * One vulnerability: Repair Assessments for this group only (the card's
     * Repair…), without the workflow list and the list's filters.
     */
    groupId?: string
    /** The list filters are the user's own, not the untouched role default. */
    listFiltersCustom?: boolean
    /** The list filters in words (the list's filter chips). */
    scopeLabels?: string[]
}>(), {
    query: () => ({}),
    groupId: '',
    listFiltersCustom: false,
    scopeLabels: () => [],
})
/**
 * Which findings a workflow looks at: the current list (its filters), or the
 * whole project (all versions, no list filters). The role default of the
 * list (a reviewer's Awaiting review) would hide what most workflows are for,
 * such as findings to synchronize across versions; so the whole project is
 * the default unless the user set filters.
 */
type BulkScope = 'list' | 'project'
const scope = ref<BulkScope>('project')
const scopeFilters = (value: BulkScope): BulkWorkflowFilters =>
    value === 'list' ? bulkWorkflowFilters(props.query) : {}
const REPAIR_WORKFLOW_ID = 'assessment-repair'

const emit = defineEmits<{
    close: []
    applied: [result: BulkWorkflowApplyResponse]
}>()

const loading = ref(false)
const processing = ref(false)
const error = ref('')
const workflows = ref<BulkWorkflowSummaryItem[]>([])
const selectedWorkflowId = ref('')
const preview = ref<BulkWorkflowPreviewResponse | null>(null)
const selectedIds = ref<Set<string>>(new Set())
// Groups that changed since the preview was shown (after a refused apply).
const changedGroupIds = ref<Set<string>>(new Set())
// Said above the preview when the preview was reloaded after a change; kept
// out of the error state, which replaces the preview list.
const changeNotice = ref('')
const appliedResult = ref<BulkWorkflowApplyResponse | null>(null)
const activeFilters = ref<BulkWorkflowFilters>({})
const documentLoading = ref(false)
const operationMessage = ref('')
const operationProgress = ref(0)
const ticketCopyState = ref<Record<string, 'copied' | 'error'>>({})
const jiraCreateUrl = getRuntimeConfig('DTVP_JIRA_CREATE_URL', '').trim()
const previewCache = new Map<string, BulkWorkflowPreviewResponse>()
let previewRequestId = 0
// The uploaded file of a workflow that reads one (requires_source).
const sourceUpload = ref<BulkWorkflowSourceUpload | null>(null)
const sourceFileName = ref('')
const sourceUploading = ref(false)
const RESTORE_WORKFLOW_ID = 'team-assessment-restore'

type AutomaticOutcomeFilter = 'ALL' | AutomaticAssessmentOutcome
type AutomaticRescoreFilter = 'ALL' | AutomaticAssessmentRescoreState

const automaticOutcomeOptions: Array<{ value: AutomaticOutcomeFilter; label: string }> = [
    { value: 'ALL', label: 'All' },
    ...AUTOMATIC_ASSESSMENT_OUTCOME_OPTIONS,
]
const automaticRescoreOptions: Array<{ value: AutomaticRescoreFilter; label: string }> = [
    { value: 'ALL', label: 'All' },
    ...AUTOMATIC_ASSESSMENT_RESCORE_OPTIONS,
]
const automaticOutcomeFilters = ref<Set<AutomaticAssessmentOutcome>>(new Set())
const automaticRescoreFilters = ref<Set<AutomaticAssessmentRescoreState>>(new Set())

const selectedWorkflow = computed(() =>
    workflows.value.find(workflow => workflow.id === selectedWorkflowId.value) || null
)
const workflowRequiresSource = (workflowId: string) =>
    !!workflows.value.find(workflow => workflow.id === workflowId)?.requires_source
const sourceIdFor = (workflowId: string) =>
    workflowRequiresSource(workflowId) ? sourceUpload.value?.source_id : undefined
const previewCacheKey = (workflowId: string) => {
    const sourceId = sourceIdFor(workflowId)
    return sourceId ? `${workflowId}:${sourceId}` : workflowId
}
// Arguments appended only for a workflow that reads an upload, so the calls
// of the other workflows stay as they were.
const sourceArgs = (workflowId: string): [string] | [] => {
    const sourceId = sourceIdFor(workflowId)
    return sourceId ? [sourceId] : []
}
const selectableIds = computed(() => preview.value?.selectable_group_ids || [])
const selectedFindingCount = computed(() =>
    (preview.value?.items || [])
        .filter(item => selectedIds.value.has(item.group_id))
        .reduce((total, item) => total + Number(
            item.eligible_finding_count
            || item.finding_count
            || item.recoverable_finding_count
            || item.syncable_finding_count
            || 0
        ) + (includeNewIds.value.has(item.group_id) ? Number(item.new_finding_count || 0) : 0), 0)
)

const itemSelectable = (item: BulkWorkflowPreviewItem) =>
    selectableIds.value.includes(item.group_id)

// Findings a new project version added stay unassessed unless the reviewer
// includes them, per vulnerability.
const includeNewIds = ref<Set<string>>(new Set())
const newFindingCount = (item: BulkWorkflowPreviewItem) => Number(item.new_finding_count || 0)
// "1 new finding in version 2.1 (lib-a@1.0)": where the new findings are.
const newFindingsWhere = (item: BulkWorkflowPreviewItem) => {
    const places: string[] = Array.isArray(item.new_finding_places) ? item.new_finding_places : []
    const count = plural(newFindingCount(item), 'new finding')
    if (!places.length) return `${count} of a new version`
    return `${count} in ${places.length === 1 ? 'version' : 'versions'} ${places.join(', ')}`
}
const offersNewFindings = (item: BulkWorkflowPreviewItem) =>
    selectedWorkflowId.value === 'assessment-repair' && newFindingCount(item) > 0 && itemSelectable(item)
const toggleIncludeNew = (item: BulkWorkflowPreviewItem) => {
    if (processing.value || !offersNewFindings(item)) return
    const next = new Set(includeNewIds.value)
    if (next.has(item.group_id)) {
        next.delete(item.group_id)
    } else {
        next.add(item.group_id)
        // Including the new findings is a decision about this vulnerability.
        if (!selectedIds.value.has(item.group_id)) {
            selectedIds.value = new Set([...selectedIds.value, item.group_id])
        }
    }
    includeNewIds.value = next
}

const automaticItemMatchesFilters = (item: BulkWorkflowPreviewItem) =>
    (automaticOutcomeFilters.value.size === 0
        || automaticOutcomeFilters.value.has(item.verdict_bucket as AutomaticAssessmentOutcome))
    && (automaticRescoreFilters.value.size === 0
        || automaticRescoreFilters.value.has(automaticAssessmentRescoreState(item.rescore)))

const visiblePreviewItems = computed(() => {
    const items = preview.value?.items || []
    if (selectedWorkflowId.value !== 'automatic-assessments') return items
    return items.filter(automaticItemMatchesFilters)
})
const visibleSelectableIds = computed(() =>
    visiblePreviewItems.value
        .filter(itemSelectable)
        .map(item => item.group_id)
)
const allSelected = computed(() =>
    visibleSelectableIds.value.length > 0
    && visibleSelectableIds.value.every(groupId => selectedIds.value.has(groupId))
)

// Items that need a human decision first start unselected; the reviewer opts in.
const defaultSelection = (result: BulkWorkflowPreviewResponse) => {
    const reviewFirst = new Set(
        result.items.filter(item => item.requires_review).map(item => item.group_id)
    )
    return new Set(result.selectable_group_ids.filter(groupId => !reviewFirst.has(groupId)))
}

interface SelectionGroup {
    id: string
    label: string
    ids: string[]
    selected: number
}

// One toggle per repair topic, plus one for everything that needs review first.
const selectionGroups = computed<SelectionGroup[]>(() => {
    const topics = preview.value?.topics || []
    if (!topics.length) return [newFindingsGroup()].filter(entry => entry.ids.length > 0)
    const selectable = visiblePreviewItems.value.filter(itemSelectable)
    const group = (id: string, label: string, items: BulkWorkflowPreviewItem[]): SelectionGroup => {
        const ids = items.map(item => item.group_id)
        return { id, label, ids, selected: ids.filter(groupId => selectedIds.value.has(groupId)).length }
    }
    return [
        ...topics.map(topic => group(
            topic.id,
            topic.label,
            selectable.filter(item => itemRepairs(item).some(repair => repair.id === topic.id)),
        )),
        group('review-first', 'Needs review', selectable.filter(item => item.requires_review)),
        newFindingsGroup(),
    ].filter(entry => entry.ids.length > 0)
})

// Including the new findings of every vulnerability that offers it; counts
// the vulnerabilities whose new findings are included, not the selection.
function newFindingsGroup(): SelectionGroup {
    const ids = visiblePreviewItems.value.filter(offersNewFindings).map(item => item.group_id)
    return { id: NEW_FINDINGS_GROUP, label: 'New findings', ids, selected: ids.filter(groupId => includeNewIds.value.has(groupId)).length }
}

const NEW_FINDINGS_GROUP = 'new-findings'

const toggleSelectionGroup = (group: SelectionGroup) => {
    if (processing.value) return
    if (group.id === NEW_FINDINGS_GROUP) {
        const include = group.selected < group.ids.length
        const nextIncluded = new Set(includeNewIds.value)
        const nextSelected = new Set(selectedIds.value)
        for (const groupId of group.ids) {
            if (include) {
                nextIncluded.add(groupId)
                // Including the new findings is a decision about this vulnerability.
                nextSelected.add(groupId)
            } else {
                nextIncluded.delete(groupId)
            }
        }
        includeNewIds.value = nextIncluded
        selectedIds.value = nextSelected
        return
    }
    const next = new Set(selectedIds.value)
    const selectAll = group.selected < group.ids.length
    for (const groupId of group.ids) {
        if (selectAll) next.add(groupId)
        else next.delete(groupId)
    }
    selectedIds.value = next
}

const rescoreRuleFindings = (item: BulkWorkflowPreviewItem) =>
    Array.isArray(item.rescore_findings)
        ? item.rescore_findings as RescoreRuleSyncPreviewFinding[]
        : []

const firstRescoreRuleFinding = (item: BulkWorkflowPreviewItem) => {
    const findings = rescoreRuleFindings(item)
    return findings.find(finding => finding.status === 'ready') || findings[0]
}

const rescoreRuleReasons = (item: BulkWorkflowPreviewItem) =>
    [...new Set(rescoreRuleFindings(item).flatMap(finding => finding.reasons || []))]

const itemRepairs = (item: BulkWorkflowPreviewItem) =>
    (Array.isArray(item.repairs) ? item.repairs : []) as Array<{ id: string; label: string }>

const itemReviewNotes = (item: BulkWorkflowPreviewItem) =>
    (Array.isArray(item.review) ? item.review : []) as string[]

interface RestoreBlock {
    project_version?: string | null
    component_name?: string | null
    component_version?: string | null
    match: string
    team: string
    state: string
    justification?: string | null
    assessed_by?: string | null
    date?: string | null
    ticket?: string | null
    source_historical?: boolean
    text_excerpt?: string
}

const restoreBlocks = (item: BulkWorkflowPreviewItem) =>
    (Array.isArray(item.blocks) ? item.blocks : []) as RestoreBlock[]

const restoreNotes = (item: BulkWorkflowPreviewItem) =>
    (Array.isArray(item.notes) ? item.notes : []) as Array<Record<string, any>>

const restoreNoteText = (note: Record<string, any>) =>
    note.kind === 'present_ticket_missing'
        ? `${note.team} is present, but ${(note.tickets || []).join(', ')} is named nowhere (not written)`
        : `${note.team} is missing; ${note.copied_to} was copied from it (restored as historical)`

const unmatchedCounts = computed(() =>
    (preview.value?.summary?.unmatched || {}) as Record<string, number>
)
const unmatchedTotal = computed(() =>
    Object.values(unmatchedCounts.value).reduce((total, count) => total + Number(count || 0), 0)
)
const unmatchedSamples = computed(() =>
    (preview.value?.summary?.unmatched_samples || []) as Array<Record<string, any>>
)

const formatCvssScore = (score: number | null | undefined) =>
    score == null ? '—' : Number(score).toFixed(1)

const updateOperationStatus = (status: BulkWorkflowTaskStatus) => {
    operationMessage.value = status.message || ''
    operationProgress.value = Number(status.progress || 0)
}

const itemStatus = (item: BulkWorkflowPreviewItem) => {
    if (selectedWorkflowId.value === 'automatic-assessments') {
        const verdict = String(item.verdict_bucket || 'INCONCLUSIVE')
        return verdict === 'INCONCLUSIVE' ? 'UNCERTAIN' : verdict.replaceAll('_', ' ')
    }
    if (selectedWorkflowId.value === 'assessment-repair') {
        if (!item.repairable) return 'Manual review'
        return item.requires_review ? 'Review first' : 'Ready'
    }
    return item.status || 'Ready'
}

const plural = (count: number, singular: string) =>
    `${count} ${singular}${count === 1 ? '' : 's'}`

const automaticAssessmentDetail = (item: BulkWorkflowPreviewItem) => {
    const runCount = (item.run_ids || []).length
    const replaced = Number(item.preexisting_finding_count || 0)
    const teams = (item.teams || []) as string[]
    const unowned = (item.unowned_components || []) as string[]
    const teamDetail = teams.length
        ? `${plural(teams.length, 'team assessment')}: ${teams.join(', ')}`
        : 'global assessment only'
    const replacedDetail = replaced
        ? `${plural(replaced, 'existing assessment')} will be replaced`
        : ''
    return [
        `${item.eligible_finding_count || 0} ready`,
        plural(runCount, 'analysis run'),
        teamDetail,
        replacedDetail,
        unowned.length ? `no team for ${unowned.join(', ')}` : '',
    ].filter(Boolean).join(' · ')
}

const itemDetail = (item: BulkWorkflowPreviewItem) => {
    if (selectedWorkflowId.value === 'automatic-assessments') {
        return automaticAssessmentDetail(item)
    }
    if (selectedWorkflowId.value === 'assessment-repair') {
        if (!item.repairable) return 'No automatic repair available'
        const updated = Number(item.finding_count || 0)
        const added = includeNewIds.value.has(item.group_id) ? newFindingCount(item) : 0
        if (!updated && !added && newFindingCount(item)) return 'Only findings of a new version are not synchronized'
        return `${plural(updated + added, 'finding')} will be updated`
    }
    if (selectedWorkflowId.value === RESTORE_WORKFLOW_ID) {
        if (!item.restore_count) return 'Notes only; nothing to restore'
        return `${item.restore_count || 0} team assessments on ${item.finding_count || 0} findings`
    }
    return `${item.finding_count || 0} findings`
}

const resetAutomaticAssessmentFilters = () => {
    automaticOutcomeFilters.value = new Set()
    automaticRescoreFilters.value = new Set()
}

const loadPreview = async (workflowId: string) => {
    if (!props.taskId) return
    const requestId = ++previewRequestId
    selectedWorkflowId.value = workflowId
    preview.value = null
    selectedIds.value = new Set()
    includeNewIds.value = new Set()
    changedGroupIds.value = new Set()
    changeNotice.value = ''
    appliedResult.value = null
    ticketCopyState.value = {}
    error.value = ''
    operationMessage.value = ''
    operationProgress.value = 0
    resetAutomaticAssessmentFilters()
    if (workflowRequiresSource(workflowId) && !sourceUpload.value) {
        // Nothing to preview before a file is uploaded.
        loading.value = false
        return
    }
    const cacheKey = previewCacheKey(workflowId)
    const cached = previewCache.get(cacheKey)
    if (cached) {
        loading.value = false
        preview.value = cached
        selectedIds.value = defaultSelection(cached)
        includeNewIds.value = new Set()
        return
    }
    loading.value = true
    try {
        const result = await previewBulkWorkflow(
            workflowId,
            props.taskId,
            activeFilters.value,
            status => {
                if (requestId === previewRequestId) updateOperationStatus(status)
            },
            ...sourceArgs(workflowId),
        )
        if (requestId !== previewRequestId) return
        previewCache.set(cacheKey, result)
        preview.value = result
        selectedIds.value = defaultSelection(result)
        includeNewIds.value = new Set()
        workflows.value = workflows.value.map(workflow =>
            workflow.id === workflowId
                ? {
                    ...workflow,
                    candidate_count: result.selectable_group_ids.length,
                    summary: result.summary,
                }
                : workflow
        )
    } catch (err: any) {
        if (requestId !== previewRequestId) return
        error.value = err?.response?.data?.detail || err?.message || 'Unable to preview this workflow.'
    } finally {
        if (requestId === previewRequestId) loading.value = false
    }
}

const loadWorkflows = async () => {
    if (!props.taskId) return
    loading.value = true
    error.value = ''
    if (!props.groupId) scope.value = props.listFiltersCustom ? 'list' : 'project'
    activeFilters.value = props.groupId ? { group_id: props.groupId } : scopeFilters(scope.value)
    workflows.value = []
    selectedWorkflowId.value = ''
    preview.value = null
    appliedResult.value = null
    operationMessage.value = ''
    operationProgress.value = 0
    resetAutomaticAssessmentFilters()
    previewCache.clear()
    sourceUpload.value = null
    sourceFileName.value = ''
    previewRequestId += 1
    try {
        const response = await getBulkWorkflowSummary(props.taskId, activeFilters.value)
        workflows.value = props.groupId
            ? response.workflows.filter(workflow => workflow.id === REPAIR_WORKFLOW_ID)
            : response.workflows
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Unable to load bulk workflows.'
        loading.value = false
        return
    }
    loading.value = false
    if (props.groupId) await loadPreview(REPAIR_WORKFLOW_ID)
}

// The other input of the restore: the history the source kept of each
// finding in view, instead of an export file.
const readSourceHistory = async () => {
    const workflowId = selectedWorkflowId.value
    if (!props.taskId || !workflowId) return
    previewRequestId += 1
    preview.value = null
    selectedIds.value = new Set()
    includeNewIds.value = new Set()
    appliedResult.value = null
    sourceUpload.value = null
    sourceFileName.value = 'Dependency-Track history'
    error.value = ''
    sourceUploading.value = true
    try {
        sourceUpload.value = await readBulkWorkflowSourceHistory(props.taskId, activeFilters.value, status => {
            operationMessage.value = status.message || ''
            operationProgress.value = status.progress || 0
        })
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Unable to read the history.'
        return
    } finally {
        sourceUploading.value = false
    }
    await loadPreview(workflowId)
}

const chooseSourceFile = async (event: Event) => {
    const input = event.target as HTMLInputElement
    const file = input.files?.[0]
    const workflowId = selectedWorkflowId.value
    if (!file || !workflowId) return
    // Another file: the preview of the previous one no longer applies.
    previewRequestId += 1
    preview.value = null
    selectedIds.value = new Set()
    includeNewIds.value = new Set()
    appliedResult.value = null
    sourceUpload.value = null
    sourceFileName.value = file.name
    error.value = ''
    sourceUploading.value = true
    try {
        sourceUpload.value = await uploadBulkWorkflowSource(file)
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Unable to read this file.'
        return
    } finally {
        sourceUploading.value = false
        input.value = ''
    }
    await loadPreview(workflowId)
}

const formatSourceTime = (value: string) => {
    const date = new Date(value)
    return value && !Number.isNaN(date.getTime()) ? date.toLocaleString() : value || 'unknown'
}

const toggleItem = (item: BulkWorkflowPreviewItem) => {
    if (processing.value || !itemSelectable(item)) return
    const next = new Set(selectedIds.value)
    if (next.has(item.group_id)) next.delete(item.group_id)
    else next.add(item.group_id)
    selectedIds.value = next
}

const toggleAll = () => {
    const next = new Set(selectedIds.value)
    for (const groupId of visibleSelectableIds.value) {
        if (allSelected.value) next.delete(groupId)
        else next.add(groupId)
    }
    selectedIds.value = next
}

const selectFilteredAutomaticAssessments = () => {
    selectedIds.value = new Set(visibleSelectableIds.value)
}

const automaticOutcomeFilterSelected = (value: AutomaticOutcomeFilter) =>
    value === 'ALL'
        ? automaticOutcomeFilters.value.size === 0
        : automaticOutcomeFilters.value.has(value)

const automaticRescoreFilterSelected = (value: AutomaticRescoreFilter) =>
    value === 'ALL'
        ? automaticRescoreFilters.value.size === 0
        : automaticRescoreFilters.value.has(value)

const toggleAutomaticOutcomeFilter = (value: AutomaticOutcomeFilter) => {
    const next = new Set(automaticOutcomeFilters.value)
    if (value === 'ALL') next.clear()
    else if (next.has(value)) next.delete(value)
    else next.add(value)
    automaticOutcomeFilters.value = next
    selectFilteredAutomaticAssessments()
}

const toggleAutomaticRescoreFilter = (value: AutomaticRescoreFilter) => {
    const next = new Set(automaticRescoreFilters.value)
    if (value === 'ALL') next.clear()
    else if (next.has(value)) next.delete(value)
    else next.add(value)
    automaticRescoreFilters.value = next
    selectFilteredAutomaticAssessments()
}

const clearAutomaticAssessmentFilters = () => {
    resetAutomaticAssessmentFilters()
    selectFilteredAutomaticAssessments()
}

const copyTicket = async (item: BulkWorkflowPreviewItem) => {
    try {
        await navigator.clipboard.writeText(String(item.ticket_text || ''))
        ticketCopyState.value = { ...ticketCopyState.value, [item.group_id]: 'copied' }
    } catch {
        ticketCopyState.value = { ...ticketCopyState.value, [item.group_id]: 'error' }
    }
}

const createJiraTicket = async (item: BulkWorkflowPreviewItem) => {
    await copyTicket(item)
    if (jiraCreateUrl) window.open(jiraCreateUrl, '_blank', 'noopener,noreferrer')
}

const exportTicketDocument = async () => {
    if (!props.taskId || !preview.value || selectedIds.value.size === 0) return
    documentLoading.value = true
    error.value = ''
    operationMessage.value = ''
    operationProgress.value = 0
    try {
        const markdown = await buildBulkWorkflowDocument(
            preview.value.workflow.id,
            props.taskId,
            activeFilters.value,
            Array.from(selectedIds.value),
            preview.value.preview_token,
            updateOperationStatus,
            sourceArgs(preview.value.workflow.id)[0],
            selectedFingerprints(),
            selectedItems(),
        )
        const url = URL.createObjectURL(new Blob([markdown], { type: 'text/markdown;charset=utf-8' }))
        const link = document.createElement('a')
        link.href = url
        link.download = 'automatic-assessment-tickets.md'
        link.click()
        URL.revokeObjectURL(url)
    } catch (err: any) {
        error.value = err?.response?.data?.detail || err?.message || 'Unable to export ticket drafts.'
    } finally {
        documentLoading.value = false
    }
}

// The fingerprints of the selected groups, as the preview showed them.
const selectedFingerprints = (): Record<string, string> => {
    const known = preview.value?.group_fingerprints || {}
    return Object.fromEntries(
        Array.from(selectedIds.value)
            .filter(groupId => known[groupId] !== undefined)
            .map(groupId => [groupId, known[groupId]]),
    )
}

// The preview items of the selected groups, as shown (the server diffs them
// when a selected group changed).
const selectedItems = (): Record<string, BulkWorkflowPreviewItem> => {
    const shown = preview.value?.items || []
    return Object.fromEntries(
        shown.filter(item => selectedIds.value.has(item.group_id)).map(item => [item.group_id, item]),
    )
}

// Names each changed group with the fields that changed, e.g.
// "CVE-2025-10256 (finding_count, repairs[])".
const describeChanges = (changed: string[], changes: BulkWorkflowErrorDetail['changes'] = {}) =>
    changed.map(groupId => {
        const paths = (changes?.[groupId] || []).map(change => change.path)
        return paths.length ? `${groupId} (${paths.slice(0, 4).join(', ')})` : groupId
    }).join('; ')

// A selected group changed since the preview: the preview is reloaded, the
// selection of the groups that did not change is kept, and the changed ones
// are named and marked.
const reloadAfterChange = async (changed: string[], changes: BulkWorkflowErrorDetail['changes'] = {}) => {
    const workflowId = preview.value?.workflow.id
    if (!workflowId) return
    const keptIds = Array.from(selectedIds.value).filter(id => !changed.includes(id))
    const keptNew = Array.from(includeNewIds.value).filter(id => !changed.includes(id))
    // The cached preview is the one that went stale.
    previewCache.delete(previewCacheKey(workflowId))
    await loadPreview(workflowId)
    if (!preview.value) return
    const selectable = new Set(preview.value.selectable_group_ids)
    selectedIds.value = new Set(keptIds.filter(id => selectable.has(id)))
    includeNewIds.value = new Set(keptNew.filter(id => selectedIds.value.has(id)))
    changedGroupIds.value = new Set(changed)
    changeNotice.value = changed.length
        ? `${changed.length} selected group(s) changed since the preview: ${describeChanges(changed, changes)}. `
            + 'The preview was reloaded and the other selections are kept; review the changed groups, then apply again.'
        : ''
}

const applySelected = async () => {
    if (!props.taskId || !preview.value || selectedIds.value.size === 0) return
    processing.value = true
    error.value = ''
    operationMessage.value = ''
    operationProgress.value = 0
    changeNotice.value = ''
    const includeNew = Array.from(includeNewIds.value).filter(id => selectedIds.value.has(id))
    const source = sourceArgs(preview.value.workflow.id)
    try {
        const result = await applyBulkWorkflow(
            preview.value.workflow.id,
            props.taskId,
            activeFilters.value,
            Array.from(selectedIds.value),
            preview.value.preview_token,
            updateOperationStatus,
            source[0],
            includeNew,
            selectedFingerprints(),
            selectedItems(),
        )
        appliedResult.value = result
        // What was written changes the candidates of every workflow: a cached
        // preview from before is stale, and applying it again would be
        // refused (changed since the preview). Choosing a workflow prepares
        // the preview again.
        previewCache.clear()
        emit('applied', result)
    } catch (err: any) {
        if (err?.detail?.code === 'preview_changed') {
            await reloadAfterChange(err.detail.changed_groups || [], err.detail.changes || {})
        } else {
            error.value = err?.response?.data?.detail || err?.message || 'Bulk workflow failed.'
        }
    } finally {
        processing.value = false
    }
}

const changeScope = async (value: BulkScope) => {
    if (processing.value || scope.value === value) return
    scope.value = value
    activeFilters.value = scopeFilters(value)
    previewCache.clear()
    workflows.value = workflows.value.map(workflow => ({ ...workflow, candidate_count: null, summary: {} }))
    if (selectedWorkflowId.value) await loadPreview(selectedWorkflowId.value)
}

const close = () => {
    if (!processing.value) emit('close')
}

watch(() => props.show, show => {
    if (show) void loadWorkflows()
})
</script>

<template>
    <div v-if="show" class="fixed inset-0 z-[10000] flex items-center justify-center bg-[#0a0a12]/80 p-4 backdrop-blur-md">
        <div class="flex max-h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-2xl border border-white/10 bg-[#12121e] shadow-2xl">
            <header class="flex items-center justify-between border-b border-white/5 bg-blue-500/10 px-8 py-6">
                <div class="flex items-center gap-4">
                    <div class="flex h-12 w-12 items-center justify-center rounded-xl border border-blue-400/30 bg-blue-500/20">
                        <Layers :size="25" class="text-blue-200" />
                    </div>
                    <div>
                        <h2 v-if="groupId" class="text-2xl font-extrabold text-white" data-testid="bulk-workflow-group-title">Repair {{ groupId }}</h2>
                        <h2 v-else class="text-2xl font-extrabold text-white">Bulk Changes</h2>
                        <p v-if="groupId" class="text-xs text-slate-400">The Repair Assessments workflow, for this vulnerability only.</p>
                        <p v-else class="text-xs text-slate-400">Choose one workflow and where it looks for candidates.</p>
                    </div>
                </div>
                <button type="button" class="rounded-full p-2 text-slate-500 hover:bg-white/5 hover:text-white" :disabled="processing" @click="close">
                    <X :size="20" />
                </button>
            </header>

            <div
                v-if="!groupId"
                class="flex flex-wrap items-center gap-3 border-b border-white/5 bg-black/20 px-8 py-3 text-xs"
                data-testid="bulk-workflow-scope"
            >
                <span class="text-[10px] font-black uppercase tracking-widest text-slate-500">Scope</span>
                <div class="inline-flex overflow-hidden rounded-lg border border-white/10" role="radiogroup" aria-label="Scope">
                    <button
                        type="button"
                        role="radio"
                        :aria-checked="scope === 'project' ? 'true' : 'false'"
                        class="px-3 py-1.5 font-bold transition-colors"
                        :class="scope === 'project' ? 'bg-blue-500/25 text-white' : 'text-slate-400 hover:bg-white/5'"
                        :disabled="processing"
                        data-testid="bulk-workflow-scope-project"
                        @click="changeScope('project')"
                    >
                        Whole project
                    </button>
                    <button
                        type="button"
                        role="radio"
                        :aria-checked="scope === 'list' ? 'true' : 'false'"
                        class="border-l border-white/10 px-3 py-1.5 font-bold transition-colors"
                        :class="scope === 'list' ? 'bg-blue-500/25 text-white' : 'text-slate-400 hover:bg-white/5'"
                        :disabled="processing"
                        data-testid="bulk-workflow-scope-list"
                        @click="changeScope('list')"
                    >
                        Current list
                    </button>
                </div>
                <span class="min-w-0 flex-1 text-slate-400" data-testid="bulk-workflow-scope-description">
                    <template v-if="scope === 'project'">All versions, no list filters.</template>
                    <template v-else>{{ scopeLabels.length ? scopeLabels.join(' · ') : 'No list filters' }}</template>
                </span>
            </div>

            <div class="grid min-h-0 flex-1 overflow-hidden" :class="groupId ? 'grid-cols-1' : 'grid-cols-[280px_minmax(0,1fr)]'">
                <aside v-if="!groupId" class="overflow-y-auto border-r border-white/5 bg-black/20 p-4">
                    <div class="mb-3 px-2 text-[10px] font-black uppercase tracking-widest text-slate-600">
                        Workflows
                    </div>
                    <button
                        v-for="workflow in workflows"
                        :key="workflow.id"
                        type="button"
                        class="mb-2 w-full rounded-xl border p-3 text-left transition-colors"
                        :class="selectedWorkflowId === workflow.id ? 'border-blue-400/40 bg-blue-500/10' : 'border-white/5 bg-white/[0.02] hover:bg-white/[0.05]'"
                        :disabled="processing || !!workflow.unavailable_reason"
                        :data-testid="`bulk-workflow-${workflow.id}`"
                        @click="loadPreview(workflow.id)"
                    >
                        <div class="flex items-center justify-between gap-3">
                            <span class="text-xs font-bold text-white">{{ workflow.label }}</span>
                            <span class="rounded-full bg-black/30 px-2 py-0.5 font-mono text-[10px] text-blue-200">{{ workflow.candidate_count ?? '…' }}</span>
                        </div>
                        <p class="mt-1 text-[10px] leading-relaxed text-slate-500">{{ workflow.unavailable_reason || workflow.description }}</p>
                    </button>
                </aside>

                <main
                    class="flex min-h-0 flex-col gap-4 p-6"
                    :class="selectedWorkflow?.requires_source ? 'overflow-y-auto' : 'overflow-hidden'"
                >
                    <section
                        v-if="selectedWorkflow?.requires_source && !appliedResult"
                        class="shrink-0 space-y-2 rounded-xl border border-white/5 bg-black/20 p-3"
                        data-testid="bulk-workflow-source"
                    >
                        <div class="flex flex-wrap items-center gap-3">
                            <label
                                class="inline-flex shrink-0 cursor-pointer items-center gap-2 rounded-lg border border-blue-400/20 bg-blue-500/5 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-blue-200"
                                :class="{ 'pointer-events-none opacity-50': processing || sourceUploading }"
                            >
                                <Loader2 v-if="sourceUploading" :size="12" class="animate-spin" />
                                <Upload v-else :size="12" />
                                {{ sourceUpload ? 'Choose another file' : 'Choose export' }}
                                <input
                                    type="file"
                                    accept=".json,application/json"
                                    class="sr-only"
                                    data-testid="bulk-workflow-source-input"
                                    :disabled="processing || sourceUploading"
                                    @change="chooseSourceFile"
                                >
                            </label>
                            <button
                                type="button"
                                class="inline-flex shrink-0 items-center gap-2 rounded-lg border border-blue-400/20 bg-blue-500/5 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-blue-200 disabled:opacity-50"
                                data-testid="bulk-workflow-source-history"
                                :disabled="processing || sourceUploading"
                                title="Read the texts each finding in view held over time from Dependency-Track's audit trail"
                                @click="readSourceHistory"
                            >
                                <Loader2 v-if="sourceUploading && sourceFileName === 'Dependency-Track history'" :size="12" class="animate-spin" />
                                <History v-else :size="12" />
                                Read Dependency-Track history
                            </button>
                            <p v-if="!sourceUpload" class="min-w-0 flex-1 text-[11px] text-slate-400">
                                A CycloneDX VDR that Dependency-Track exported for this project (River's own export does not work), or Dependency-Track's history of each finding in view. Either stays in server memory only.
                            </p>
                            <p
                                v-else
                                class="min-w-0 flex-1 text-[11px] leading-relaxed text-slate-300"
                                data-testid="bulk-workflow-source-summary"
                            >
                                <span class="font-bold text-white">{{ sourceFileName }}</span>
                                · {{ sourceUpload.summary.tool || 'unknown tool' }} {{ sourceUpload.summary.tool_version }}
                                <template v-if="sourceUpload.summary.project_name || sourceUpload.summary.project_version">· project {{ sourceUpload.summary.project_name || 'unknown' }} {{ sourceUpload.summary.project_version }}</template>
                                · {{ sourceUpload.summary.project_name ? 'exported' : 'read' }} {{ formatSourceTime(sourceUpload.summary.timestamp) }}
                                · SHA-256 <span class="font-mono">{{ sourceUpload.summary.sha256.slice(0, 12) }}</span>
                                · {{ sourceUpload.entries }} entries, {{ sourceUpload.team_blocks }} team assessments
                            </p>
                        </div>
                        <p
                            v-for="warning in sourceUpload?.summary.warnings || []"
                            :key="warning"
                            class="rounded-lg border border-amber-400/20 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-100"
                            data-testid="bulk-workflow-source-warning"
                        >{{ warning }}</p>
                    </section>
                    <p
                        v-if="changeNotice"
                        data-testid="bulk-workflow-changed"
                        class="rounded-xl border border-amber-400/30 bg-amber-500/10 p-3 text-sm text-amber-100"
                        role="status"
                    >{{ changeNotice }}</p>
                    <div v-if="loading" class="flex flex-1 items-center justify-center gap-3 text-sm font-semibold text-blue-200">
                        <Loader2 :size="22" class="animate-spin" />
                        {{ operationMessage || 'Preparing workflow preview' }}
                        <span v-if="operationProgress" class="font-mono text-xs text-blue-300/70">{{ operationProgress }}%</span>
                    </div>
                    <div v-else-if="error" data-testid="bulk-workflow-error" class="rounded-xl border border-red-400/20 bg-red-500/10 p-4 text-sm text-red-100">
                        {{ error }}
                    </div>
                    <div v-else-if="appliedResult" data-testid="bulk-workflow-completion" class="flex flex-1 flex-col items-center justify-center text-center">
                        <CheckCircle :size="44" class="text-emerald-300" />
                        <h3 class="mt-3 text-lg font-bold text-white">{{ appliedResult.workflow.label }} complete</h3>
                        <p class="mt-2 text-xs text-slate-400">
                            {{ appliedResult.summary.succeeded || 0 }} applied · {{ appliedResult.summary.queued || 0 }} queued · {{ appliedResult.summary.failed || 0 }} failed
                        </p>
                        <p
                            v-if="appliedResult.summary.changed_since_preview"
                            class="mt-1 text-xs text-amber-200"
                            data-testid="bulk-workflow-changed-since-preview"
                        >
                            {{ appliedResult.summary.changed_since_preview }} changed since the preview and were left as they are; prepare the preview again to include them.
                        </p>
                        <p
                            v-if="appliedResult.summary.new_finding"
                            class="mt-1 text-xs text-slate-300"
                            data-testid="bulk-workflow-new-findings-left"
                        >
                            {{ plural(appliedResult.summary.new_finding, 'new finding') }} of a new version left unassessed.
                        </p>
                    </div>
                    <div v-else-if="!preview && selectedWorkflow?.requires_source" data-testid="bulk-workflow-source-empty-state" class="flex flex-1 flex-col items-center justify-center text-center">
                        <Upload :size="40" class="text-blue-300" />
                        <h3 class="mt-3 font-bold text-white">Upload an export to prepare the preview</h3>
                        <p class="mt-1 max-w-md text-xs text-slate-500">Nothing is written before you review the preview and apply a selection.</p>
                    </div>
                    <div v-else-if="!preview" data-testid="bulk-workflow-empty-state" class="flex flex-1 flex-col items-center justify-center text-center">
                        <Layers :size="40" class="text-blue-300" />
                        <h3 class="mt-3 font-bold text-white">Select a bulk workflow</h3>
                        <p class="mt-1 max-w-md text-xs text-slate-500">A preview is prepared only for the workflow you choose. Active vulnerability filters remain in effect.</p>
                    </div>
                    <template v-else-if="preview && selectedWorkflow">
                        <div class="flex items-start justify-between gap-4">
                            <div>
                                <h3 class="text-lg font-bold text-white">{{ selectedWorkflow.label }}</h3>
                                <p class="mt-1 text-xs text-slate-400">{{ selectedWorkflow.description }}</p>
                            </div>
                            <button type="button" class="rounded-lg border border-blue-400/20 bg-blue-500/5 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-blue-200" @click="toggleAll">
                                {{ allSelected ? 'Deselect all' : 'Select all' }}
                            </button>
                        </div>

                        <div
                            v-if="selectionGroups.length"
                            class="flex flex-wrap items-center gap-2 rounded-xl border border-white/5 bg-black/20 p-3"
                            data-testid="bulk-workflow-selection-groups"
                        >
                            <span class="text-[10px] font-black uppercase tracking-wider text-slate-500">Select</span>
                            <button
                                v-for="group in selectionGroups"
                                :key="group.id"
                                type="button"
                                class="rounded-lg border px-2.5 py-1.5 text-[10px] font-bold transition-colors"
                                :class="group.selected === group.ids.length
                                    ? 'border-blue-300/50 bg-blue-500/20 text-blue-100'
                                    : group.id === 'review-first'
                                        ? 'border-amber-400/25 bg-amber-500/5 text-amber-100 hover:bg-amber-500/10'
                                        : 'border-white/10 text-slate-300 hover:bg-white/5'"
                                :aria-pressed="group.selected === group.ids.length"
                                :title="group.id === NEW_FINDINGS_GROUP
                                    ? (group.selected === group.ids.length ? 'Leave the new findings of every vulnerability unassessed' : 'Synchronize the new findings of every vulnerability as well')
                                    : group.selected === group.ids.length ? `Deselect all: ${group.label}` : `Select all: ${group.label}`"
                                :data-testid="`bulk-workflow-select-${group.id}`"
                                @click="toggleSelectionGroup(group)"
                            >
                                {{ group.label }} · {{ group.selected }}/{{ group.ids.length }}
                            </button>
                            <span class="text-[10px] text-slate-500">Vulnerabilities that need review first start unselected.</span>
                        </div>

                        <p
                            v-for="note in preview.notes || []"
                            :key="note"
                            data-testid="bulk-workflow-note"
                            class="rounded-xl border border-amber-400/20 bg-amber-500/10 p-3 text-[11px] text-amber-100"
                        >{{ note }}</p>

                        <details
                            v-if="selectedWorkflowId === RESTORE_WORKFLOW_ID"
                            class="shrink-0 rounded-xl border border-white/5 bg-black/20 p-3 text-[11px] text-slate-300"
                            data-testid="bulk-workflow-unmatched"
                        >
                            <summary class="cursor-pointer font-bold text-slate-200">
                                Unmatched entries · {{ unmatchedTotal }}
                                <span class="ml-2 font-normal text-slate-500">
                                    {{ unmatchedCounts.no_finding_in_view || 0 }} no finding in view ·
                                    {{ unmatchedCounts.ambiguous || 0 }} ambiguous ·
                                    {{ unmatchedCounts.other_project || 0 }} other project
                                </span>
                            </summary>
                            <p class="mt-2 text-slate-500">{{ preview.summary.unmatched_note }}</p>
                            <ul v-if="unmatchedSamples.length" class="mt-2 max-h-40 space-y-0.5 overflow-y-auto font-mono text-[10px]">
                                <li v-for="(sample, index) in unmatchedSamples" :key="index">
                                    {{ sample.id }} · {{ sample.component_name || 'unknown component' }} {{ sample.component_version || '' }} · {{ sample.reason }}
                                </li>
                            </ul>
                        </details>

                        <div v-if="selectedWorkflowId === 'automatic-assessments'" class="space-y-3" data-testid="automatic-assessment-actions">
                            <div class="space-y-2 rounded-xl border border-white/5 bg-black/20 p-3">
                                <div class="flex flex-wrap items-center gap-2" data-testid="automatic-assessment-outcome-filters">
                                    <span class="w-24 shrink-0 text-[10px] font-black uppercase tracking-wider text-slate-500">Outcome</span>
                                    <button
                                        v-for="option in automaticOutcomeOptions"
                                        :key="option.value"
                                        type="button"
                                        class="rounded-lg border px-3 py-1.5 text-[10px] font-bold transition-colors"
                                        :class="automaticOutcomeFilterSelected(option.value)
                                            ? 'border-blue-300/50 bg-blue-500/20 text-blue-100'
                                            : 'border-white/10 text-slate-400 hover:bg-white/5 hover:text-slate-200'"
                                        :aria-pressed="automaticOutcomeFilterSelected(option.value)"
                                        :data-testid="`automatic-outcome-filter-${option.value.toLowerCase()}`"
                                        @click="toggleAutomaticOutcomeFilter(option.value)"
                                    >
                                        {{ option.label }}
                                    </button>
                                </div>
                                <div class="flex flex-wrap items-center gap-2" data-testid="automatic-assessment-rescore-filters">
                                    <span class="w-24 shrink-0 text-[10px] font-black uppercase tracking-wider text-slate-500">Proposed rescore</span>
                                    <button
                                        v-for="option in automaticRescoreOptions"
                                        :key="option.value"
                                        type="button"
                                        class="rounded-lg border px-3 py-1.5 text-[10px] font-bold transition-colors"
                                        :class="automaticRescoreFilterSelected(option.value)
                                            ? 'border-blue-300/50 bg-blue-500/20 text-blue-100'
                                            : 'border-white/10 text-slate-400 hover:bg-white/5 hover:text-slate-200'"
                                        :aria-pressed="automaticRescoreFilterSelected(option.value)"
                                        :data-testid="`automatic-rescore-filter-${option.value.toLowerCase()}`"
                                        @click="toggleAutomaticRescoreFilter(option.value)"
                                    >
                                        {{ option.label }}
                                    </button>
                                </div>
                                <div class="flex items-center justify-between gap-3 pt-1 text-[10px] text-slate-500">
                                    <span data-testid="automatic-assessment-filter-count">
                                        Showing {{ visiblePreviewItems.length }} of {{ preview.items.length }} candidate{{ preview.items.length === 1 ? '' : 's' }}
                                    </span>
                                    <span>Filters also set the selection for apply.</span>
                                </div>
                            </div>
                            <div class="flex items-start gap-2 rounded-lg border border-blue-400/20 bg-blue-500/10 px-3 py-2 text-[10px] leading-relaxed text-blue-100" data-testid="automatic-assessment-rescore-notice">
                                <AlertTriangle :size="14" class="mt-0.5 shrink-0" />
                                Applying an automatic assessment writes one assessment per owning team plus a global assessment that takes the worst result's state and its CVSS rescore. The shown rescore is written to every eligible finding; items without a proposed rescore leave CVSS unchanged.
                            </div>
                        </div>

                        <div v-if="preview.items.length === 0" class="flex flex-1 flex-col items-center justify-center text-center">
                            <CheckCircle :size="40" class="text-emerald-300" />
                            <h4 class="mt-3 font-bold text-white">No matching changes</h4>
                            <p class="mt-1 text-xs text-slate-500">The active filters and this workflow have no candidates in common.</p>
                            <p
                                v-if="selectedWorkflowId === 'automatic-assessments'"
                                class="mt-3 max-w-xl rounded-lg border border-white/5 bg-black/20 px-3 py-2 font-mono text-[10px] leading-relaxed text-slate-400"
                                data-testid="automatic-assessment-diagnostics"
                            >
                                {{ preview.summary.stored_analysis_results || 0 }} saved result(s) scanned ·
                                {{ preview.summary.usable_assessment_results || 0 }} usable assessment(s) ·
                                {{ preview.summary.matched_analysis_results || 0 }} matched result(s) ·
                                {{ preview.summary.already_applied_findings || 0 }} already-applied finding(s)
                            </p>
                        </div>
                        <div
                            v-else-if="visiblePreviewItems.length === 0"
                            class="flex flex-1 flex-col items-center justify-center text-center"
                            data-testid="automatic-assessment-filter-empty"
                        >
                            <Layers :size="40" class="text-blue-300" />
                            <h4 class="mt-3 font-bold text-white">No candidates match these filters</h4>
                            <p class="mt-1 text-xs text-slate-500">Choose another outcome or proposed rescore severity.</p>
                            <button
                                type="button"
                                class="mt-4 rounded-lg border border-blue-400/20 bg-blue-500/5 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-blue-200"
                                data-testid="automatic-assessment-clear-filters"
                                @click="clearAutomaticAssessmentFilters"
                            >
                                Clear filters
                            </button>
                        </div>
                        <div
                            v-else
                            class="min-h-0 flex-1 overflow-y-auto rounded-xl border border-white/5 bg-black/20"
                            :class="{ 'min-h-48': selectedWorkflowId === RESTORE_WORKFLOW_ID }"
                        >
                            <div
                                v-for="item in visiblePreviewItems"
                                :key="item.group_id"
                                role="button"
                                tabindex="0"
                                class="grid w-full grid-cols-[48px_minmax(0,1fr)_220px] items-center gap-4 border-b border-white/5 px-5 py-4 text-left last:border-0"
                                :class="[
                                    itemSelectable(item) ? 'hover:bg-white/[0.04]' : 'cursor-default opacity-60',
                                    selectedIds.has(item.group_id) ? 'bg-blue-500/10' : '',
                                    changedGroupIds.has(item.group_id) ? 'ring-1 ring-inset ring-amber-400/60 bg-amber-500/10' : '',
                                ]"
                                :data-changed="changedGroupIds.has(item.group_id) ? 'true' : undefined"
                                :data-testid="`bulk-workflow-item-${item.group_id}`"
                                @click="toggleItem(item)"
                                @keydown.space.prevent="toggleItem(item)"
                                @keydown.enter.prevent="toggleItem(item)"
                            >
                                <span class="flex h-5 w-5 items-center justify-center rounded border-2" :class="selectedIds.has(item.group_id) ? 'border-blue-300 bg-blue-500' : 'border-white/10'">
                                    <CheckCircle v-if="selectedIds.has(item.group_id)" :size="12" />
                                </span>
                                <span class="min-w-0">
                                    <span class="block truncate text-sm font-bold text-white">{{ item.group_id }}</span>
                                    <span
                                        v-if="item.title && item.title !== item.group_id"
                                        class="block truncate text-[11px] italic text-slate-500"
                                    >{{ item.title }}</span>
                                    <span class="mt-1 block text-[10px] text-slate-400">{{ itemDetail(item) }}</span>
                                    <span
                                        v-if="newFindingCount(item) && !offersNewFindings(item)"
                                        class="mt-1 block text-[10px] text-sky-200"
                                        :data-testid="`new-findings-${item.group_id}`"
                                    >{{ newFindingsWhere(item) }}, not assessed by this workflow</span>
                                    <label
                                        v-if="offersNewFindings(item)"
                                        class="mt-1 flex w-fit cursor-pointer items-center gap-2 text-[10px] text-sky-200"
                                        :data-testid="`new-findings-${item.group_id}`"
                                        @click.stop
                                        @keydown.stop
                                    >
                                        <input
                                            type="checkbox"
                                            class="h-3 w-3"
                                            :checked="includeNewIds.has(item.group_id)"
                                            :disabled="processing"
                                            :data-testid="`include-new-findings-${item.group_id}`"
                                            @change="toggleIncludeNew(item)"
                                        />
                                        <span>{{ newFindingsWhere(item) }}, not synchronized. Synchronize {{ newFindingCount(item) === 1 ? 'it' : 'them' }} as well</span>
                                    </label>
                                    <span
                                        v-if="selectedWorkflowId === 'assessment-repair'"
                                        class="mt-2 flex flex-wrap gap-1.5"
                                        :data-testid="`repair-labels-${item.group_id}`"
                                    >
                                        <span
                                            v-for="repair in itemRepairs(item)"
                                            :key="repair.id"
                                            class="rounded border border-emerald-400/25 bg-emerald-500/10 px-2 py-1 text-[10px] font-semibold leading-snug text-emerald-100"
                                            :data-testid="`repair-label-${repair.id}-${item.group_id}`"
                                        >{{ repair.label }}</span>
                                        <span
                                            v-for="note in itemReviewNotes(item)"
                                            :key="note"
                                            class="rounded border border-amber-400/25 bg-amber-500/10 px-2 py-1 text-[10px] font-semibold leading-snug text-amber-100"
                                        >{{ note }}</span>
                                    </span>
                                    <span
                                        v-if="selectedWorkflowId === RESTORE_WORKFLOW_ID && (itemReviewNotes(item).length || restoreNotes(item).length)"
                                        class="mt-2 flex flex-wrap gap-1.5"
                                        :data-testid="`restore-review-${item.group_id}`"
                                    >
                                        <span
                                            v-for="note in itemReviewNotes(item)"
                                            :key="note"
                                            class="rounded border border-amber-400/25 bg-amber-500/10 px-2 py-1 text-[10px] font-semibold leading-snug text-amber-100"
                                        >{{ note }}</span>
                                        <span
                                            v-for="(note, index) in restoreNotes(item)"
                                            :key="`note-${index}`"
                                            class="rounded border border-white/10 px-2 py-1 text-[10px] leading-snug text-slate-300"
                                        >{{ restoreNoteText(note) }}</span>
                                    </span>
                                    <details
                                        v-if="selectedWorkflowId === RESTORE_WORKFLOW_ID && restoreBlocks(item).length"
                                        class="mt-2 block rounded-lg border border-white/5 bg-black/20 p-2"
                                        :data-testid="`restore-blocks-${item.group_id}`"
                                        @click.stop
                                        @keydown.stop
                                    >
                                        <summary class="cursor-pointer text-[10px] font-bold text-blue-200">Team assessments to restore</summary>
                                        <span
                                            v-for="(block, index) in restoreBlocks(item)"
                                            :key="index"
                                            class="mt-2 block border-t border-white/5 pt-2 text-[10px] leading-relaxed text-slate-300"
                                        >
                                            <span class="block font-bold text-white">
                                                {{ block.team }} · {{ block.state }} · {{ block.date || 'undated' }} · {{ block.assessed_by || 'unknown assessor' }}<template v-if="block.ticket"> · {{ block.ticket }}</template>
                                            </span>
                                            <span class="block text-slate-500">
                                                {{ block.component_name }} {{ block.component_version }} · {{ block.project_version }} · matched by {{ block.match }}
                                            </span>
                                            <span v-if="block.text_excerpt" class="mt-1 block whitespace-pre-wrap text-slate-400">{{ block.text_excerpt }}</span>
                                        </span>
                                    </details>
                                    <span
                                        v-if="selectedWorkflowId === 'assessment-repair' && rescoreRuleFindings(item).length"
                                        class="mt-3 block space-y-2 rounded-lg border border-white/5 bg-black/20 p-3"
                                        :data-testid="`rescore-rule-change-${item.group_id}`"
                                    >
                                        <span class="grid grid-cols-[64px_minmax(0,1fr)] gap-3">
                                            <span class="text-[9px] font-black uppercase tracking-wider text-slate-500">Original</span>
                                            <span class="min-w-0">
                                                <span class="block font-mono text-[10px] font-bold text-slate-300">Score {{ formatCvssScore(firstRescoreRuleFinding(item)?.current_score) }}</span>
                                                <span class="mt-0.5 block break-all font-mono text-[10px] leading-relaxed text-slate-500">{{ firstRescoreRuleFinding(item)?.current_vector || 'No stored vector' }}</span>
                                            </span>
                                        </span>
                                        <span class="grid grid-cols-[64px_minmax(0,1fr)] gap-3">
                                            <span class="text-[9px] font-black uppercase tracking-wider text-blue-300">Fixed</span>
                                            <span class="min-w-0">
                                                <span class="block font-mono text-[10px] font-bold text-blue-100">Score {{ formatCvssScore(firstRescoreRuleFinding(item)?.proposed_score) }}</span>
                                                <span class="mt-0.5 block break-all font-mono text-[10px] leading-relaxed text-blue-200/80">{{ firstRescoreRuleFinding(item)?.proposed_vector || 'Manual review required' }}</span>
                                            </span>
                                        </span>
                                        <span
                                            v-if="rescoreRuleReasons(item).length"
                                            class="block border-t border-white/5 pt-2 text-[10px] leading-relaxed text-amber-200"
                                            :data-testid="`rescore-rule-reasons-${item.group_id}`"
                                        >
                                            {{ rescoreRuleReasons(item).join(' · ') }}
                                        </span>
                                    </span>
                                    <span
                                        v-else-if="selectedWorkflowId === 'automatic-assessments' && item.rescore"
                                        class="mt-3 block space-y-2 rounded-lg border border-blue-400/15 bg-blue-500/5 p-3"
                                        :data-testid="`automatic-assessment-rescore-${item.group_id}`"
                                    >
                                        <span class="grid grid-cols-[72px_minmax(0,1fr)] gap-3">
                                            <span class="text-[9px] font-black uppercase tracking-wider text-slate-500">Current</span>
                                            <span class="min-w-0">
                                                <span class="block font-mono text-[10px] font-bold text-slate-300">Score {{ formatCvssScore(item.rescore.current_score ?? item.rescore.original_score) }}</span>
                                                <span class="mt-0.5 block break-all font-mono text-[10px] leading-relaxed text-slate-500">{{ item.rescore.current_vector || item.rescore.original_vector || 'No stored vector' }}</span>
                                            </span>
                                        </span>
                                        <span class="grid grid-cols-[72px_minmax(0,1fr)] gap-3">
                                            <span class="text-[9px] font-black uppercase tracking-wider text-blue-300">Will apply</span>
                                            <span class="min-w-0">
                                                <span class="block font-mono text-[10px] font-bold text-blue-100">
                                                    Score {{ formatCvssScore(item.rescore.proposed_score) }}
                                                    <span v-if="item.rescore.proposed_severity" class="ml-1 text-green-300">· {{ item.rescore.proposed_severity }}</span>
                                                </span>
                                                <span class="mt-0.5 block break-all font-mono text-[10px] leading-relaxed text-blue-200/80">{{ item.rescore.proposed_vector || 'Score-only rescore' }}</span>
                                            </span>
                                        </span>
                                    </span>
                                    <span
                                        v-else-if="selectedWorkflowId === 'automatic-assessments'"
                                        class="mt-2 block text-[10px] text-slate-500"
                                    >
                                        CVSS rescore: no change proposed
                                    </span>
                                </span>
                                <span class="flex flex-col items-end gap-2 text-right">
                                    <span class="inline-block rounded border border-blue-400/20 bg-blue-500/5 px-2 py-1 text-[10px] font-bold uppercase text-blue-200">{{ itemStatus(item) }}</span>
                                    <span v-if="selectedWorkflowId === 'automatic-assessments' && item.ticket_text" class="flex items-center justify-end gap-1.5">
                                        <button type="button" class="inline-flex items-center gap-1 rounded border border-white/10 px-2 py-1 text-[9px] font-bold text-slate-300 hover:bg-white/5" :data-testid="`copy-ticket-${item.group_id}`" @click.stop="copyTicket(item)">
                                            <Copy :size="11" /> {{ ticketCopyState[item.group_id] === 'copied' ? 'Copied' : 'Copy ticket' }}
                                        </button>
                                        <button v-if="jiraCreateUrl" type="button" class="inline-flex items-center gap-1 rounded border border-blue-400/20 px-2 py-1 text-[9px] font-bold text-blue-200 hover:bg-blue-500/10" :data-testid="`jira-ticket-${item.group_id}`" @click.stop="createJiraTicket(item)">
                                            <ExternalLink :size="11" /> Jira
                                        </button>
                                    </span>
                                </span>
                            </div>
                        </div>

                        <div
                            v-if="processing || documentLoading"
                            data-testid="bulk-workflow-operation-status"
                            class="flex items-center gap-3 rounded-xl border border-blue-400/20 bg-blue-500/10 p-3 text-[11px] text-blue-100"
                        >
                            <Loader2 :size="16" class="shrink-0 animate-spin" />
                            <span class="flex-1">{{ operationMessage || 'Starting bulk workflow operation...' }}</span>
                            <span class="font-mono text-[10px] text-blue-200">{{ operationProgress }}%</span>
                        </div>

                        <div class="flex items-center gap-3 rounded-xl border border-amber-400/20 bg-amber-500/10 p-3 text-[11px] text-amber-100">
                            <AlertTriangle :size="18" class="shrink-0" />
                            <span v-if="selectedWorkflowId === 'automatic-assessments'">
                                This applies the shown states, assessment details, and CVSS rescores for {{ selectedIds.size }} vulnerability group{{ selectedIds.size === 1 ? '' : 's' }} to approximately {{ selectedFindingCount }} findings. The preview is revalidated before writing.
                            </span>
                            <span v-else>
                                This applies {{ selectedIds.size }} vulnerability group{{ selectedIds.size === 1 ? '' : 's' }} and approximately {{ selectedFindingCount }} findings. The preview is revalidated before writing.
                            </span>
                        </div>
                    </template>
                </main>
            </div>

            <footer class="flex items-center justify-end gap-3 border-t border-white/5 bg-black/40 px-8 py-5">
                <button type="button" class="px-6 py-2 text-xs font-bold text-slate-500 hover:text-white" :disabled="processing" @click="close">
                    {{ appliedResult ? 'Close' : 'Cancel' }}
                </button>
                <button
                    v-if="preview && !appliedResult && selectedWorkflow?.supports_document"
                    type="button"
                    class="inline-flex items-center gap-2 rounded-xl border border-blue-400/20 bg-blue-500/5 px-5 py-2.5 text-xs font-black uppercase text-blue-200 disabled:opacity-50"
                    :disabled="processing || documentLoading || selectedIds.size === 0"
                    data-testid="bulk-workflow-document"
                    @click="exportTicketDocument"
                >
                    <Loader2 v-if="documentLoading" :size="14" class="animate-spin" />
                    <Download v-else :size="14" /> Export tickets
                </button>
                <button
                    v-if="preview && !appliedResult"
                    type="button"
                    class="inline-flex items-center gap-2 rounded-xl bg-blue-500 px-6 py-2.5 text-xs font-black uppercase text-slate-950 disabled:opacity-50"
                    :disabled="processing || selectedIds.size === 0"
                    data-testid="bulk-workflow-apply"
                    @click="applySelected"
                >
                    <Loader2 v-if="processing" :size="14" class="animate-spin" />
                    Apply selected ({{ selectedIds.size }})
                </button>
            </footer>
        </div>
    </div>
</template>
