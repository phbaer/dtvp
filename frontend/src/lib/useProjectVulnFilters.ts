import { computed, onActivated, onMounted, onUnmounted, ref, watch, type ComputedRef } from 'vue'
import type { Router } from 'vue-router'
import type { FilterState } from './projectVulnFilterPresets'
import {
    normalizeFilterSelection,
    parseVulnSearchQuery,
} from './vulnListIndex'
import { legacyCutoff, normalizeCutoff, normalizeCutoffBasis, normalizeCutoffMode, type CutoffBasis, type CutoffMode } from './cutoff'
import type { DependencyRelationship, TMRescoreProposalFilter } from './vulnListIndex'
import type { AutomaticAssessmentFilter } from './vulnListIndex'
import {
    AUTOMATIC_ASSESSMENT_OUTCOME_OPTIONS,
    AUTOMATIC_ASSESSMENT_RESCORE_OPTIONS,
    type AutomaticAssessmentOutcome,
    type AutomaticAssessmentRescoreState,
} from './automaticAssessmentFilters'
import type { InconsistencyReason } from '../types'
import { normalizeInconsistencyReasons } from './inconsistency'
import { useDebouncedValue } from './useDebouncedValue'
import { ANALYST_WORK_FILTERS, VISIBLE_LIFECYCLE_FILTERS } from './projectLifecycleFilters'

const normalizeTeamAssessment = (value: string) => ['MISSING', 'DOCUMENTED'].includes(value.toUpperCase()) ? value.toUpperCase() : 'ANY'
const sameSelection = (left: readonly string[], right: readonly string[]) =>
    left.length === right.length && left.every(value => right.includes(value))

export const ALL_LIFECYCLE_FILTERS = VISIBLE_LIFECYCLE_FILTERS
export const DEFAULT_REVIEWER_LIFECYCLE_FILTERS = ALL_LIFECYCLE_FILTERS
export const DEFAULT_ANALYST_LIFECYCLE_FILTERS = ANALYST_WORK_FILTERS

// Migrate retired filter choices in shared URLs to the visible categories.
// NEEDS_APPROVAL meant "any pending review" on the server, which is Awaiting
// review; hydrateFiltersFromQuery maps it there. Combined with other statuses
// it was an OR that Awaiting review (an AND) cannot express; there it stays
// the nearest status, Ready for approval.
const normalizeLifecycleSelection = (values: string[]) => Array.from(new Set(values.filter(value => value !== '__NO_MATCH__').map(value => {
    if (value === 'NEEDS_APPROVAL') return 'READY_FOR_APPROVAL'
    if (value === 'ASSESSED_LEGACY') return 'ASSESSED'
    if (value === 'CONFLICTING' || value === 'INCONSISTENT') return 'INCOMPLETE'
    return value
})))
export const DEFAULT_ANALYSIS_FILTERS = [
    'NOT_SET',
    'EXPLOITABLE',
    'IN_TRIAGE',
    'RESOLVED',
    'FALSE_POSITIVE',
    'NOT_AFFECTED',
]

interface ProjectVulnFilterRoute {
    query: Record<string, unknown>
    path?: string
}

interface ProjectVulnFilterRouter {
    replace: Router['replace']
}

interface UseProjectVulnFiltersOptions {
    route: ProjectVulnFilterRoute
    router: ProjectVulnFilterRouter
    currentUserRole: ComputedRef<string>
    /**
     * The query string of the effective default view (ADR 0015) for a
     * project opened without filter parameters; null for the built-in
     * default. Failures fall back to the built-in default.
     */
    resolveDefaultQuery?: () => Promise<string | null>
}

const firstQueryValue = (value: unknown) => Array.isArray(value) ? value[0] : value

const queryString = (value: unknown) => {
    const first = firstQueryValue(value)
    return first == null ? '' : String(first)
}

const queryStringList = (value: unknown) => {
    const values = Array.isArray(value) ? value : [value]
    return values
        .filter(entry => entry != null && entry !== '')
        .map(entry => String(entry))
}

const FILTER_QUERY_KEYS = new Set([
    'q',
    'lifecycle',
    'analysis',
    'inconsistency_reason',
    'team_assessment',
    'original_severity',
    'ssvc',
    'evidence',
    'tag',
    'teams',
    'id',
    'cve',
    'component',
    'assignee',
    'dependency',
    'versions',
    'sort',
    'order',
    'tmrescore',
    'automatic_assessment',
    'auto_assessment',
    'automatic_assessment_outcome',
    'automatic_assessment_rescore',
    'cvss_mismatch',
    'not_rescored',
    'new_findings',
    'changes_requested',
    'mcp_assessments',
    'awaiting_review',
    'cutoff',
    'cutoff_mode',
    'cutoff_basis',
    // Retired (ADR 0015): read as a relative cutoff.
    'attributed_before_days',
    'attribution_mode',
    'attribution_age_days',
    'age_days',
])

/** The parameters a saved view keeps: every filter except retired ones. */
export const SAVED_VIEW_QUERY_KEYS = [...FILTER_QUERY_KEYS].filter(key => ![
    'tag', 'cve', 'auto_assessment', 'attributed_before_days', 'attribution_mode', 'attribution_age_days', 'age_days',
].includes(key))

/** A query string as the route query object it stands for. */
export const parseFilterQueryString = (query: string): Record<string, string | string[]> => {
    const result: Record<string, string | string[]> = {}
    new URLSearchParams(query.replace(/^\?/, '')).forEach((value, key) => {
        const existing = result[key]
        if (existing === undefined) result[key] = value
        else result[key] = Array.isArray(existing) ? [...existing, value] : [existing, value]
    })
    return result
}

/** The filter parameters of a route query as a sorted query string. */
export const filterQueryString = (query: Record<string, unknown>): string => {
    const params = new URLSearchParams()
    for (const key of [...SAVED_VIEW_QUERY_KEYS].sort()) {
        const values = queryStringList(query[key])
        for (const value of [...values].sort()) params.append(key, value)
    }
    return params.toString()
}

export function useProjectVulnFilters({
    route,
    router,
    currentUserRole,
    resolveDefaultQuery,
}: UseProjectVulnFiltersOptions) {
    const smartSearchInput = ref('')
    const {
        value: appliedSmartSearchInput,
        flush: flushSmartSearchFilter,
    } = useDebouncedValue(smartSearchInput, {
        delayMs: 400,
        immediateWhen: value => !value.trim(),
    })
    const parsedSmartSearch = computed(() => parseVulnSearchQuery(appliedSmartSearchInput.value))
    const liveParsedSmartSearch = computed(() => parseVulnSearchQuery(smartSearchInput.value))
    const teamFilters = ref<string[]>([])
    const tagFilter = computed({
        get: () => teamFilters.value.length === 1 ? teamFilters.value[0]! : '',
        set: (team: string) => { teamFilters.value = team ? [team] : [] },
    })
    const idFilter = ref('')
    const componentFilter = ref('')
    const assigneeFilter = ref('')
    const dependencyFilter = ref<DependencyRelationship[]>(['DIRECT', 'TRANSITIVE', 'UNKNOWN'])
    const tmrescoreProposalFilter = ref<TMRescoreProposalFilter[]>(['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'])
    const automaticAssessmentFilter = ref<AutomaticAssessmentFilter[]>(['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'])
    const automaticAssessmentOutcomeFilter = ref<AutomaticAssessmentOutcome[]>(
        AUTOMATIC_ASSESSMENT_OUTCOME_OPTIONS.map(option => option.value),
    )
    const automaticAssessmentRescoreFilter = ref<AutomaticAssessmentRescoreState[]>(
        AUTOMATIC_ASSESSMENT_RESCORE_OPTIONS.map(option => option.value),
    )
    const cvssVersionMismatchOnly = ref(false)
    const notRescoredOnly = ref(false)
    const newFindingsOnly = ref(false)
    const changesRequestedOnly = ref(false)
    const mcpAssessmentsOnly = ref(false)
    const awaitingReviewOnly = ref(false)
    const cutoff = ref('')
    const cutoffMode = ref<CutoffMode>('before')
    const cutoffBasis = ref<CutoffBasis>('published')
    // The query of the effective default view; Reset returns to it.
    const defaultViewQuery = ref<string | null>(null)
    const lifecycleFilters = ref<string[]>([])
    const defaultTeamAssessmentFilter = computed(() => currentUserRole.value === 'REVIEWER' ? 'ANY' : 'MISSING')
    const teamAssessmentFilter = ref('ANY')
    const inconsistencyReasonFilters = ref<InconsistencyReason[]>([])
    const analysisFilters = ref<string[]>([])
    const originalSeverityFilters = ref<string[]>([])
    const ssvcFilters = ref<string[]>([])
    const evidenceFilters = ref<string[]>([])
    const filtersReady = ref(false)
    const sortBy = ref('rescored-severity')
    const sortOrder = ref<'asc' | 'desc'>('desc')
    const versionFilterInput = ref('')
    const copiedUrl = ref(false)

    let filterUrlSyncTimer: ReturnType<typeof setTimeout> | null = null

    const defaultLifecycleFilters = computed(() =>
        currentUserRole.value === 'REVIEWER'
            ? DEFAULT_REVIEWER_LIFECYCLE_FILTERS
            : DEFAULT_ANALYST_LIFECYCLE_FILTERS
    )
    const defaultAnalysisFilters = DEFAULT_ANALYSIS_FILTERS
    let lifecycleFollowsRole = true
    let teamAssessmentFollowsRole = true
    // Reviewers start on Awaiting review, analysts without it.
    const defaultAwaitingReviewOnly = computed(() => currentUserRole.value === 'REVIEWER')
    let awaitingReviewFollowsRole = true

    const versionFilterList = computed(() => {
        return versionFilterInput.value
            .split(',')
            .map(v => v.trim())
            .filter(v => v.length > 0)
    })

    const selectedDependencyFilters = computed(() => normalizeFilterSelection(dependencyFilter.value))
    const selectedTMRescoreProposalFilters = computed(() => normalizeFilterSelection(tmrescoreProposalFilter.value))
    const selectedAutomaticAssessmentFilters = computed(() => normalizeFilterSelection(automaticAssessmentFilter.value))
    const selectedAutomaticAssessmentOutcomeFilters = computed(() =>
        normalizeFilterSelection(automaticAssessmentOutcomeFilter.value)
    )
    const selectedAutomaticAssessmentRescoreFilters = computed(() =>
        normalizeFilterSelection(automaticAssessmentRescoreFilter.value)
    )

    const resetToBuiltInDefaults = () => {
        lifecycleFollowsRole = true
        teamAssessmentFollowsRole = true
        awaitingReviewFollowsRole = true
        originalSeverityFilters.value = []
        ssvcFilters.value = []
        evidenceFilters.value = []
        analysisFilters.value = [...DEFAULT_ANALYSIS_FILTERS]
        lifecycleFilters.value = currentUserRole.value === 'REVIEWER'
            ? [...DEFAULT_REVIEWER_LIFECYCLE_FILTERS]
            : [...DEFAULT_ANALYST_LIFECYCLE_FILTERS]
        teamAssessmentFilter.value = 'ANY'
        inconsistencyReasonFilters.value = []
        idFilter.value = ''
        tagFilter.value = ''
        smartSearchInput.value = ''
        componentFilter.value = ''
        assigneeFilter.value = ''
        dependencyFilter.value = ['DIRECT', 'TRANSITIVE', 'UNKNOWN']
        tmrescoreProposalFilter.value = ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL']
        automaticAssessmentFilter.value = ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT']
        automaticAssessmentOutcomeFilter.value = AUTOMATIC_ASSESSMENT_OUTCOME_OPTIONS.map(option => option.value)
        automaticAssessmentRescoreFilter.value = AUTOMATIC_ASSESSMENT_RESCORE_OPTIONS.map(option => option.value)
        versionFilterInput.value = ''
        cvssVersionMismatchOnly.value = false
        notRescoredOnly.value = false
        newFindingsOnly.value = false
        changesRequestedOnly.value = false
        mcpAssessmentsOnly.value = false
        awaitingReviewOnly.value = defaultAwaitingReviewOnly.value
        cutoff.value = ''
        cutoffMode.value = 'before'
        cutoffBasis.value = 'published'
        sortBy.value = 'rescored-severity'
        sortOrder.value = 'desc'
    }

    const hasFilterQueryParams = (query: Record<string, unknown>) => {
        return Object.entries(query).some(([key, value]) => {
            if (!FILTER_QUERY_KEYS.has(key)) return false
            if (Array.isArray(value)) return value.length > 0
            return value !== undefined && value !== null && value !== ''
        })
    }

    const hasNarrowingQueryParams = (query: Record<string, unknown>) =>
        hasFilterQueryParams(Object.fromEntries(
            Object.entries(query).filter(([key]) => key !== 'sort' && key !== 'order'),
        ))

    const hydrateFiltersFromQuery = (q: Record<string, unknown> = route.query) => {
        originalSeverityFilters.value = queryStringList(q.original_severity).flatMap(v => v.split(',')).map(v => v.trim().toUpperCase()).filter(Boolean)
        ssvcFilters.value = queryStringList(q.ssvc).flatMap(v => v.split(',')).map(v => v.trim().toUpperCase()).filter(Boolean)
        evidenceFilters.value = queryStringList(q.evidence).flatMap(v => v.split(',')).map(v => v.trim().toUpperCase()).filter(Boolean)
        if (!hasFilterQueryParams(q)) {
            resetToBuiltInDefaults()
            flushSmartSearchFilter()
            filtersReady.value = true
            return
        }

        if (q.q) smartSearchInput.value = queryStringList(q.q).join(' ')
        const rawLifecycle = queryStringList(q.lifecycle).map(value => value.toUpperCase())
        const legacyPendingReview = rawLifecycle.includes('NEEDS_APPROVAL')
            && rawLifecycle.every(value => ['NEEDS_APPROVAL', 'READY_FOR_APPROVAL'].includes(value))
        if (legacyPendingReview) {
            // An old link to "needs approval": everything pending review.
            lifecycleFilters.value = [...ALL_LIFECYCLE_FILTERS]
            lifecycleFollowsRole = sameSelection(lifecycleFilters.value, defaultLifecycleFilters.value)
        } else if (q.lifecycle) {
            lifecycleFilters.value = normalizeLifecycleSelection(queryStringList(q.lifecycle))
            lifecycleFollowsRole = sameSelection(lifecycleFilters.value, defaultLifecycleFilters.value)
        } else {
            lifecycleFilters.value = [...defaultLifecycleFilters.value]
            lifecycleFollowsRole = true
        }

        if (q.analysis) {
            analysisFilters.value = queryStringList(q.analysis)
        } else {
            analysisFilters.value = [...DEFAULT_ANALYSIS_FILTERS]
        }

        if (q.inconsistency_reason) {
            inconsistencyReasonFilters.value = normalizeInconsistencyReasons(
                queryStringList(q.inconsistency_reason),
            )
        }

        teamFilters.value = q.teams ? queryStringList(q.teams) : (q.tag ? [queryString(q.tag)] : [])
        teamAssessmentFilter.value = !teamFilters.value.length ? 'ANY'
            : q.team_assessment == null ? defaultTeamAssessmentFilter.value
            : normalizeTeamAssessment(queryString(q.team_assessment))
        teamAssessmentFollowsRole = !teamFilters.value.length
            || q.team_assessment == null
            || teamAssessmentFilter.value === defaultTeamAssessmentFilter.value
        if (q.id) idFilter.value = queryString(q.id)
        else if (q.cve) idFilter.value = queryString(q.cve)

        if (q.component) componentFilter.value = queryString(q.component)
        if (q.assignee) assigneeFilter.value = queryString(q.assignee)
        if (q.dependency) {
            dependencyFilter.value = queryStringList(q.dependency)
                .map(v => v.toUpperCase() as DependencyRelationship)
        }
        if (q.versions) versionFilterInput.value = queryStringList(q.versions).join(',')
        if (q.tmrescore) {
            tmrescoreProposalFilter.value = queryStringList(q.tmrescore)
                .map(v => v.toUpperCase() as TMRescoreProposalFilter)
        }
        const automaticAssessmentQuery = q.automatic_assessment ?? q.auto_assessment
        if (automaticAssessmentQuery) {
            automaticAssessmentFilter.value = queryStringList(automaticAssessmentQuery)
                .map(v => v.toUpperCase() as AutomaticAssessmentFilter)
        }
        if (q.automatic_assessment_outcome) {
            automaticAssessmentOutcomeFilter.value = queryStringList(q.automatic_assessment_outcome)
                .map(v => v.toUpperCase() as AutomaticAssessmentOutcome)
        }
        if (q.automatic_assessment_rescore) {
            automaticAssessmentRescoreFilter.value = queryStringList(q.automatic_assessment_rescore)
                .map(v => v.toUpperCase() as AutomaticAssessmentRescoreState)
        }
        if (q.cvss_mismatch === 'true') cvssVersionMismatchOnly.value = true
        if (q.not_rescored === 'true') notRescoredOnly.value = true
        if (q.new_findings === 'true') newFindingsOnly.value = true
        if (q.changes_requested === 'true') changesRequestedOnly.value = true
        if (q.mcp_assessments === 'true') mcpAssessmentsOnly.value = true
        // Awaiting review is written whenever it is on, and as false when a
        // reviewer turned it off. A link without it that holds other filters
        // (an old one) means off; one with only the sort follows the role.
        const awaitingReviewParam = queryString(q.awaiting_review)
        awaitingReviewOnly.value = legacyPendingReview || awaitingReviewParam === 'true'
            || (!awaitingReviewParam && !hasNarrowingQueryParams(q) && defaultAwaitingReviewOnly.value)
        awaitingReviewFollowsRole = awaitingReviewOnly.value === defaultAwaitingReviewOnly.value
        const legacy = legacyCutoff(
            firstQueryValue(q.attributed_before_days ?? q.attribution_age_days ?? q.age_days),
            queryString(q.attribution_mode),
        )
        const linkCutoff = normalizeCutoff(queryString(q.cutoff))
        if (linkCutoff) {
            cutoff.value = linkCutoff
            cutoffMode.value = normalizeCutoffMode(queryString(q.cutoff_mode))
            cutoffBasis.value = normalizeCutoffBasis(queryString(q.cutoff_basis))
        } else if (legacy) {
            cutoff.value = legacy.cutoff
            cutoffMode.value = legacy.cutoffMode
            cutoffBasis.value = legacy.cutoffBasis
        }
        if (q.sort) sortBy.value = queryString(q.sort)
        if (q.order) sortOrder.value = queryString(q.order) as 'asc' | 'desc'

        flushSmartSearchFilter()
        filtersReady.value = true
    }

    // One mapping from the selection to the URL query: the address bar and
    // the copied link are the same. Retired parameters are dropped once they
    // were read (hydrateFiltersFromQuery maps them to their replacements).
    const filterQuery = () => {
        const query: Record<string, unknown> = { ...route.query }
        const setList = (key: string, values: readonly string[]) => {
            if (values.length) query[key] = [...values]
            else delete query[key]
        }
        const setText = (key: string, value: string) => {
            if (value) query[key] = value
            else delete query[key]
        }
        const setFlag = (key: string, value: boolean) => {
            if (value) query[key] = 'true'
            else delete query[key]
        }
        for (const retired of ['tag', 'cve', 'auto_assessment', 'attributed_from', 'attributed_to', 'attributed_not', 'attribution_age_days', 'age_days', 'attributed_before_days', 'attribution_mode']) {
            delete query[retired]
        }

        setText('q', smartSearchInput.value.trim())
        if (lifecycleFollowsRole) delete query.lifecycle
        else query.lifecycle = lifecycleFilters.value.length ? [...lifecycleFilters.value] : ['__NO_MATCH__']
        if (awaitingReviewOnly.value) query.awaiting_review = 'true'
        else if (!awaitingReviewFollowsRole) query.awaiting_review = 'false'
        else delete query.awaiting_review
        setList('analysis', analysisFilters.value)
        setList('teams', teamFilters.value)
        if (teamFilters.value.length && !teamAssessmentFollowsRole) query.team_assessment = teamAssessmentFilter.value
        else delete query.team_assessment
        setText('versions', versionFilterInput.value)
        setText('id', idFilter.value)
        setText('component', componentFilter.value)
        setText('assignee', assigneeFilter.value)

        setList('inconsistency_reason', inconsistencyReasonFilters.value)
        setFlag('new_findings', newFindingsOnly.value)
        setFlag('changes_requested', changesRequestedOnly.value)
        setFlag('mcp_assessments', mcpAssessmentsOnly.value)
        setList('original_severity', originalSeverityFilters.value)
        setList('ssvc', ssvcFilters.value)
        setList('evidence', evidenceFilters.value)
        setList('dependency', selectedDependencyFilters.value)
        setFlag('cvss_mismatch', cvssVersionMismatchOnly.value)
        setFlag('not_rescored', notRescoredOnly.value)
        setText('cutoff', cutoff.value)
        if (cutoff.value && cutoffMode.value === 'after') query.cutoff_mode = 'after'
        else delete query.cutoff_mode
        // Always named with a cutoff, so links and saved views show the same
        // whatever becomes the default.
        if (cutoff.value) query.cutoff_basis = cutoffBasis.value
        else delete query.cutoff_basis

        // Legacy, removed in 2.1.0 (#342).
        setList('tmrescore', selectedTMRescoreProposalFilters.value)
        setList('automatic_assessment', selectedAutomaticAssessmentFilters.value)
        setList('automatic_assessment_outcome', selectedAutomaticAssessmentOutcomeFilters.value)
        setList('automatic_assessment_rescore', selectedAutomaticAssessmentRescoreFilters.value)

        query.sort = sortBy.value
        query.order = sortOrder.value
        return query
    }

    const filterUrl = computed(() => {
        const params = new URLSearchParams()
        Object.entries(filterQuery()).forEach(([key, value]) => {
            if (Array.isArray(value)) {
                value.forEach(item => params.append(key, String(item)))
            } else if (value != null && value !== '') {
                params.set(key, String(value))
            }
        })

        const path = (route.path || '/') as string
        return `${window.location.origin}${path}${params.toString() ? `?${params.toString()}` : ''}`
    })

    const copyFilterUrl = async () => {
        const link = filterUrl.value
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(link)
            } else {
                const textarea = document.createElement('textarea')
                document.body.appendChild(textarea)
                textarea.value = link
                textarea.select()
                document.execCommand('copy')
                document.body.removeChild(textarea)
            }
            copiedUrl.value = true
            setTimeout(() => copiedUrl.value = false, 2000)
        } catch (err) {
            console.error('Failed to copy URL', err)
        }
    }

    const syncFilterQueryToUrl = () => {
        router.replace({ path: route.path || '/', query: filterQuery() as any }).catch(() => {})
    }

    const filterState = computed<FilterState>(() => ({
        originalSeverityFilters: originalSeverityFilters.value,
        ssvcFilters: ssvcFilters.value,
        evidenceFilters: evidenceFilters.value,
        sortBy: sortBy.value,
        sortOrder: sortOrder.value,
        dependencyFilter: selectedDependencyFilters.value,
        tmrescoreFilter: selectedTMRescoreProposalFilters.value,
        automaticAssessmentFilter: selectedAutomaticAssessmentFilters.value,
        automaticAssessmentOutcomeFilter: selectedAutomaticAssessmentOutcomeFilters.value,
        automaticAssessmentRescoreFilter: selectedAutomaticAssessmentRescoreFilters.value,
        idFilter: idFilter.value,
        tagFilter: tagFilter.value,
        teamFilters: teamFilters.value,
        componentFilter: componentFilter.value,
        assigneeFilter: assigneeFilter.value,
        versionFilterInput: versionFilterInput.value,
        lifecycleFilters: lifecycleFilters.value,
        teamAssessmentFilter: teamAssessmentFilter.value,
        inconsistencyReasonFilters: inconsistencyReasonFilters.value,
        analysisFilters: analysisFilters.value,
        cvssVersionMismatchOnly: cvssVersionMismatchOnly.value,
        notRescoredOnly: notRescoredOnly.value,
        newFindingsOnly: newFindingsOnly.value,
        changesRequestedOnly: changesRequestedOnly.value,
        mcpAssessmentsOnly: mcpAssessmentsOnly.value,
        awaitingReviewOnly: awaitingReviewOnly.value,
        cutoff: cutoff.value,
        cutoffMode: cutoffMode.value,
        cutoffBasis: cutoffBasis.value,
    }))

    const handleFilterUpdate = (newFilters: FilterState) => {
        if (!sameSelection(newFilters.lifecycleFilters, lifecycleFilters.value)) lifecycleFollowsRole = false
        if (!!newFilters.awaitingReviewOnly !== awaitingReviewOnly.value) awaitingReviewFollowsRole = false
        if (teamFilters.value.length && newFilters.teamAssessmentFilter !== teamAssessmentFilter.value) {
            teamAssessmentFollowsRole = false
        }
        originalSeverityFilters.value = newFilters.originalSeverityFilters || []
        ssvcFilters.value = newFilters.ssvcFilters || []
        evidenceFilters.value = newFilters.evidenceFilters || []
        sortBy.value = newFilters.sortBy
        sortOrder.value = newFilters.sortOrder
        dependencyFilter.value = newFilters.dependencyFilter
        tmrescoreProposalFilter.value = newFilters.tmrescoreFilter
        automaticAssessmentFilter.value = newFilters.automaticAssessmentFilter
        automaticAssessmentOutcomeFilter.value = newFilters.automaticAssessmentOutcomeFilter
        automaticAssessmentRescoreFilter.value = newFilters.automaticAssessmentRescoreFilter
        idFilter.value = newFilters.idFilter
        const previousTeams = [...teamFilters.value]
        teamFilters.value = newFilters.tagFilter !== tagFilter.value
            ? (newFilters.tagFilter ? [newFilters.tagFilter] : [])
            : [...(newFilters.teamFilters || teamFilters.value)]
        if (!teamFilters.value.length || !previousTeams.length) teamAssessmentFollowsRole = true
        componentFilter.value = newFilters.componentFilter
        assigneeFilter.value = newFilters.assigneeFilter
        versionFilterInput.value = newFilters.versionFilterInput
        inconsistencyReasonFilters.value = newFilters.inconsistencyReasonFilters || []
        lifecycleFilters.value = [...newFilters.lifecycleFilters]
        teamAssessmentFilter.value = !teamFilters.value.length ? 'ANY'
            : !previousTeams.length ? defaultTeamAssessmentFilter.value
            : normalizeTeamAssessment(newFilters.teamAssessmentFilter || 'ANY')
        analysisFilters.value = newFilters.analysisFilters
        cvssVersionMismatchOnly.value = newFilters.cvssVersionMismatchOnly
        notRescoredOnly.value = !!newFilters.notRescoredOnly
        newFindingsOnly.value = !!newFilters.newFindingsOnly
        changesRequestedOnly.value = !!newFilters.changesRequestedOnly
        mcpAssessmentsOnly.value = !!newFilters.mcpAssessmentsOnly
        awaitingReviewOnly.value = !!newFilters.awaitingReviewOnly
        cutoff.value = normalizeCutoff(newFilters.cutoff)
        cutoffMode.value = normalizeCutoffMode(newFilters.cutoffMode)
        cutoffBasis.value = normalizeCutoffBasis(newFilters.cutoffBasis)
    }

    watch(currentUserRole, (role, previousRole) => {
        if (!filtersReady.value || role === previousRole) return
        if (lifecycleFollowsRole) lifecycleFilters.value = [...defaultLifecycleFilters.value]
        if (awaitingReviewFollowsRole) awaitingReviewOnly.value = defaultAwaitingReviewOnly.value
        if (teamAssessmentFollowsRole && teamFilters.value.length) {
            teamAssessmentFilter.value = defaultTeamAssessmentFilter.value
        }
    })

    watch([
        originalSeverityFilters,
        ssvcFilters,
        evidenceFilters,
        smartSearchInput,
        lifecycleFilters,
        teamAssessmentFilter,
        inconsistencyReasonFilters,
        analysisFilters,
        tagFilter,
        teamFilters,
        idFilter,
        componentFilter,
        assigneeFilter,
        dependencyFilter,
        tmrescoreProposalFilter,
        automaticAssessmentFilter,
        automaticAssessmentOutcomeFilter,
        automaticAssessmentRescoreFilter,
        versionFilterInput,
        cvssVersionMismatchOnly,
        notRescoredOnly,
        newFindingsOnly,
        changesRequestedOnly,
        mcpAssessmentsOnly,
        awaitingReviewOnly,
        cutoff,
        cutoffMode,
        cutoffBasis,
        sortBy,
        sortOrder,
    ], () => {
        if (filterUrlSyncTimer) clearTimeout(filterUrlSyncTimer)
        filterUrlSyncTimer = setTimeout(() => {
            filterUrlSyncTimer = null
            syncFilterQueryToUrl()
        }, 200)
    }, { deep: true })

    // The filter state as a saved view keeps it: the canonical query string
    // of the filter parameters.
    // Filters at their built-in value are left out: a missing parameter
    // means that value.
    const savedViewQuery = () => {
        const query = filterQuery()
        const unrestricted: Record<string, readonly string[]> = {
            analysis: DEFAULT_ANALYSIS_FILTERS,
            dependency: ['DIRECT', 'TRANSITIVE', 'UNKNOWN'],
            tmrescore: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'],
            automatic_assessment: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'],
            automatic_assessment_outcome: AUTOMATIC_ASSESSMENT_OUTCOME_OPTIONS.map(option => option.value),
            automatic_assessment_rescore: AUTOMATIC_ASSESSMENT_RESCORE_OPTIONS.map(option => option.value),
            sort: ['rescored-severity'],
            order: ['desc'],
        }
        for (const [key, values] of Object.entries(unrestricted)) {
            if (sameSelection(queryStringList(query[key]), values)) delete query[key]
        }
        return filterQueryString(query)
    }

    const nonFilterQuery = () => Object.fromEntries(
        Object.entries(route.query).filter(([key]) => !FILTER_QUERY_KEYS.has(key)),
    )

    /** Show a saved view: its filters replace the current ones. */
    const applyFilterQuery = (query: string) => {
        const parsed = parseFilterQueryString(query)
        // What the view leaves out is at its built-in value.
        resetToBuiltInDefaults()
        hydrateFiltersFromQuery(parsed)
        router.replace({ path: route.path || '/', query: { ...nonFilterQuery(), ...parsed } as any }).catch(() => {})
    }

    /** Reset returns to the effective default view, else the built-in one. */
    const resetFilters = () => {
        if (defaultViewQuery.value != null) {
            applyFilterQuery(defaultViewQuery.value)
            return
        }
        resetToBuiltInDefaults()
    }

    const loadDefaultView = async () => {
        if (!resolveDefaultQuery) return null
        try {
            defaultViewQuery.value = await resolveDefaultQuery()
        } catch {
            defaultViewQuery.value = null
        }
        return defaultViewQuery.value
    }

    const hydrateOnOpen = async () => {
        if (!hasFilterQueryParams(route.query) && resolveDefaultQuery) {
            const query = await loadDefaultView()
            // The user may have chosen filters meanwhile.
            if (filtersReady.value) return
            if (query != null) {
                applyFilterQuery(query)
                return
            }
        } else {
            void loadDefaultView()
        }
        hydrateFiltersFromQuery()
    }

    onMounted(() => { void hydrateOnOpen() })
    // A kept-alive project view opened again through a link with other
    // filters (a short link) takes them.
    onActivated(() => {
        if (!filtersReady.value) return
        if (filterQueryString(route.query) === filterQueryString(filterQuery())) return
        if (!hasFilterQueryParams(route.query)) return
        resetToBuiltInDefaults()
        hydrateFiltersFromQuery()
    })

    onUnmounted(() => {
        if (filterUrlSyncTimer) {
            clearTimeout(filterUrlSyncTimer)
            filterUrlSyncTimer = null
        }
    })

    return {
        smartSearchInput,
        originalSeverityFilters,
        ssvcFilters,
        evidenceFilters,
        appliedSmartSearchInput,
        flushSmartSearchFilter,
        parsedSmartSearch,
        liveParsedSmartSearch,
        tagFilter,
        teamFilters,
        idFilter,
        componentFilter,
        assigneeFilter,
        dependencyFilter,
        tmrescoreProposalFilter,
        automaticAssessmentFilter,
        automaticAssessmentOutcomeFilter,
        automaticAssessmentRescoreFilter,
        cvssVersionMismatchOnly,
        notRescoredOnly,
        newFindingsOnly,
        changesRequestedOnly,
        mcpAssessmentsOnly,
        awaitingReviewOnly,
        cutoff,
        cutoffMode,
        cutoffBasis,
        lifecycleFilters,
        teamAssessmentFilter,
        inconsistencyReasonFilters,
        analysisFilters,
        filtersReady,
        sortBy,
        sortOrder,
        versionFilterInput,
        versionFilterList,
        selectedDependencyFilters,
        selectedTMRescoreProposalFilters,
        selectedAutomaticAssessmentFilters,
        selectedAutomaticAssessmentOutcomeFilters,
        selectedAutomaticAssessmentRescoreFilters,
        copiedUrl,
        filterUrl,
        copyFilterUrl,
        resetFilters,
        resetToBuiltInDefaults,
        savedViewQuery,
        applyFilterQuery,
        defaultViewQuery,
        loadDefaultView,
        filterState,
        handleFilterUpdate,
        defaultTeamAssessmentFilter,
        defaultLifecycleFilters,
        defaultAwaitingReviewOnly,
        defaultAnalysisFilters,
    }
}
