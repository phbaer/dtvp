import { computed, onMounted, onUnmounted, ref, watch, type ComputedRef } from 'vue'
import type { Router } from 'vue-router'
import type { FilterState } from '../components/FilterSidebar.vue'
import {
    normalizeAttributionAgeDays,
    normalizeFilterSelection,
    parseVulnSearchQuery,
} from './vulnListIndex'
import type { DependencyRelationship, TMRescoreProposalFilter } from './vulnListIndex'
import type { AutomaticAssessmentFilter } from './vulnListIndex'
import type { InconsistencyReason } from '../types'
import { normalizeInconsistencyReasons } from './inconsistency'
import { useDebouncedValue } from './useDebouncedValue'

export const DEFAULT_REVIEWER_LIFECYCLE_FILTERS = [
    'OPEN',
    'ASSESSED',
    'ASSESSED_LEGACY',
    'INCOMPLETE',
    'INCONSISTENT',
    'NEEDS_APPROVAL',
]
export const DEFAULT_ANALYST_LIFECYCLE_FILTERS = ['OPEN']
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
    'tag',
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
    'cvss_mismatch',
    'attributed_before_days',
    'attribution_mode',
    'attribution_age_days',
    'age_days',
])

export function useProjectVulnFilters({
    route,
    router,
    currentUserRole,
}: UseProjectVulnFiltersOptions) {
    const smartSearchInput = ref('')
    const {
        value: appliedSmartSearchInput,
        flush: flushSmartSearchFilter,
    } = useDebouncedValue(smartSearchInput, {
        delayMs: 120,
        immediateWhen: value => !value.trim(),
    })
    const parsedSmartSearch = computed(() => parseVulnSearchQuery(appliedSmartSearchInput.value))
    const liveParsedSmartSearch = computed(() => parseVulnSearchQuery(smartSearchInput.value))
    const tagFilter = ref('')
    const idFilter = ref('')
    const componentFilter = ref('')
    const assigneeFilter = ref('')
    const dependencyFilter = ref<DependencyRelationship[]>(['DIRECT', 'TRANSITIVE', 'UNKNOWN'])
    const tmrescoreProposalFilter = ref<TMRescoreProposalFilter[]>(['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'])
    const automaticAssessmentFilter = ref<AutomaticAssessmentFilter[]>(['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'])
    const cvssVersionMismatchOnly = ref(false)
    const attributionAgeDays = ref<number | null>(null)
    const attributionAgeMode = ref<'older' | 'younger'>('older')
    const lifecycleFilters = ref<string[]>([])
    const inconsistencyReasonFilters = ref<InconsistencyReason[]>([])
    const analysisFilters = ref<string[]>([])
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

    const versionFilterList = computed(() => {
        return versionFilterInput.value
            .split(',')
            .map(v => v.trim())
            .filter(v => v.length > 0)
    })

    const selectedDependencyFilters = computed(() => normalizeFilterSelection(dependencyFilter.value))
    const selectedTMRescoreProposalFilters = computed(() => normalizeFilterSelection(tmrescoreProposalFilter.value))
    const selectedAutomaticAssessmentFilters = computed(() => normalizeFilterSelection(automaticAssessmentFilter.value))

    const resetFilters = () => {
        analysisFilters.value = [...DEFAULT_ANALYSIS_FILTERS]
        lifecycleFilters.value = currentUserRole.value === 'REVIEWER'
            ? [...DEFAULT_REVIEWER_LIFECYCLE_FILTERS]
            : [...DEFAULT_ANALYST_LIFECYCLE_FILTERS]
        inconsistencyReasonFilters.value = []
        idFilter.value = ''
        tagFilter.value = ''
        smartSearchInput.value = ''
        componentFilter.value = ''
        assigneeFilter.value = ''
        dependencyFilter.value = ['DIRECT', 'TRANSITIVE', 'UNKNOWN']
        tmrescoreProposalFilter.value = ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL']
        automaticAssessmentFilter.value = ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT']
        versionFilterInput.value = ''
        cvssVersionMismatchOnly.value = false
        attributionAgeDays.value = null
        attributionAgeMode.value = 'older'
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

    const hydrateFiltersFromQuery = () => {
        const q = route.query
        if (!hasFilterQueryParams(q)) {
            resetFilters()
            flushSmartSearchFilter()
            filtersReady.value = true
            return
        }

        if (q.q) smartSearchInput.value = queryStringList(q.q).join(' ')
        if (q.lifecycle) {
            lifecycleFilters.value = queryStringList(q.lifecycle)
        } else {
            lifecycleFilters.value = currentUserRole.value === 'REVIEWER'
                ? [...DEFAULT_REVIEWER_LIFECYCLE_FILTERS]
                : [...DEFAULT_ANALYST_LIFECYCLE_FILTERS]
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
            if (
                inconsistencyReasonFilters.value.length > 0
                && !lifecycleFilters.value.includes('INCONSISTENT')
            ) {
                lifecycleFilters.value.push('INCONSISTENT')
            }
        }

        if (q.tag) tagFilter.value = queryString(q.tag)
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
        if (q.cvss_mismatch === 'true') cvssVersionMismatchOnly.value = true
        const legacyDays = normalizeAttributionAgeDays(
            firstQueryValue(q.attributed_before_days ?? q.attribution_age_days ?? q.age_days),
        )
        if (legacyDays != null) {
            attributionAgeDays.value = legacyDays
            attributionAgeMode.value = queryString(q.attribution_mode) === 'younger' ? 'younger' : 'older'
        }
        if (q.sort) sortBy.value = queryString(q.sort)
        if (q.order) sortOrder.value = queryString(q.order) as 'asc' | 'desc'

        flushSmartSearchFilter()
        filtersReady.value = true
    }

    const filterUrl = computed(() => {
        const query: Record<string, string | string[]> = {
            ...(route.query as Record<string, string | string[]>),
        }

        if (selectedDependencyFilters.value.length > 0) query.dependency = selectedDependencyFilters.value
        else delete query.dependency

        if (versionFilterInput.value) query.versions = versionFilterInput.value
        else delete query.versions

        if (selectedTMRescoreProposalFilters.value.length > 0) query.tmrescore = selectedTMRescoreProposalFilters.value
        else delete query.tmrescore

        if (selectedAutomaticAssessmentFilters.value.length > 0) query.automatic_assessment = selectedAutomaticAssessmentFilters.value
        else delete query.automatic_assessment
        delete query.auto_assessment

        if (inconsistencyReasonFilters.value.length > 0) query.inconsistency_reason = inconsistencyReasonFilters.value
        else delete query.inconsistency_reason

        if (attributionAgeDays.value == null) {
            delete query.attributed_before_days
            delete query.attribution_mode
        } else {
            query.attributed_before_days = String(attributionAgeDays.value)
            query.attribution_mode = attributionAgeMode.value
        }
        delete query.attributed_from
        delete query.attributed_to
        delete query.attributed_not
        delete query.attribution_age_days
        delete query.age_days

        if (smartSearchInput.value.trim()) query.q = smartSearchInput.value.trim()
        else delete query.q

        const params = new URLSearchParams()
        Object.entries(query).forEach(([key, value]) => {
            if (Array.isArray(value)) {
                value.forEach(item => params.append(key, item))
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
        const query = { ...route.query }

        if (smartSearchInput.value.trim()) query.q = smartSearchInput.value.trim()
        else delete query.q

        if (lifecycleFilters.value.length > 0) query.lifecycle = lifecycleFilters.value
        else delete query.lifecycle

        if (analysisFilters.value.length > 0) query.analysis = analysisFilters.value
        else delete query.analysis

        if (inconsistencyReasonFilters.value.length > 0) query.inconsistency_reason = inconsistencyReasonFilters.value
        else delete query.inconsistency_reason

        if (tagFilter.value) query.tag = tagFilter.value
        else delete query.tag

        if (idFilter.value) query.id = idFilter.value
        else delete query.id

        if (componentFilter.value) query.component = componentFilter.value
        else delete query.component

        if (assigneeFilter.value) query.assignee = assigneeFilter.value
        else delete query.assignee

        if (selectedDependencyFilters.value.length > 0) query.dependency = selectedDependencyFilters.value
        else delete query.dependency

        if (versionFilterInput.value) query.versions = versionFilterInput.value
        else delete query.versions

        if (selectedTMRescoreProposalFilters.value.length > 0) query.tmrescore = selectedTMRescoreProposalFilters.value
        else delete query.tmrescore

        if (selectedAutomaticAssessmentFilters.value.length > 0) query.automatic_assessment = selectedAutomaticAssessmentFilters.value
        else delete query.automatic_assessment
        delete query.auto_assessment

        if (cvssVersionMismatchOnly.value) query.cvss_mismatch = 'true'
        else delete query.cvss_mismatch

        if (attributionAgeDays.value == null) {
            delete query.attributed_before_days
            delete query.attribution_mode
        } else {
            query.attributed_before_days = String(attributionAgeDays.value)
            query.attribution_mode = attributionAgeMode.value
        }
        delete query.attributed_from
        delete query.attributed_to
        delete query.attributed_not
        delete query.attribution_age_days
        delete query.age_days

        query.sort = sortBy.value
        query.order = sortOrder.value

        router.replace({ path: route.path || '/', query: query as any }).catch(() => {})
    }

    const filterState = computed<FilterState>(() => ({
        sortBy: sortBy.value,
        sortOrder: sortOrder.value,
        dependencyFilter: selectedDependencyFilters.value,
        tmrescoreFilter: selectedTMRescoreProposalFilters.value,
        automaticAssessmentFilter: selectedAutomaticAssessmentFilters.value,
        idFilter: idFilter.value,
        tagFilter: tagFilter.value,
        componentFilter: componentFilter.value,
        assigneeFilter: assigneeFilter.value,
        versionFilterInput: versionFilterInput.value,
        lifecycleFilters: lifecycleFilters.value,
        inconsistencyReasonFilters: inconsistencyReasonFilters.value,
        analysisFilters: analysisFilters.value,
        cvssVersionMismatchOnly: cvssVersionMismatchOnly.value,
        attributionAgeDays: attributionAgeDays.value,
        attributionAgeMode: attributionAgeMode.value,
    }))

    const handleFilterUpdate = (newFilters: FilterState) => {
        sortBy.value = newFilters.sortBy
        sortOrder.value = newFilters.sortOrder
        dependencyFilter.value = newFilters.dependencyFilter
        tmrescoreProposalFilter.value = newFilters.tmrescoreFilter
        automaticAssessmentFilter.value = newFilters.automaticAssessmentFilter
        idFilter.value = newFilters.idFilter
        tagFilter.value = newFilters.tagFilter
        componentFilter.value = newFilters.componentFilter
        assigneeFilter.value = newFilters.assigneeFilter
        versionFilterInput.value = newFilters.versionFilterInput
        inconsistencyReasonFilters.value = newFilters.inconsistencyReasonFilters || []
        lifecycleFilters.value = inconsistencyReasonFilters.value.length > 0
            ? Array.from(new Set([...newFilters.lifecycleFilters, 'INCONSISTENT']))
            : newFilters.lifecycleFilters
        analysisFilters.value = newFilters.analysisFilters
        cvssVersionMismatchOnly.value = newFilters.cvssVersionMismatchOnly
        attributionAgeDays.value = normalizeAttributionAgeDays(newFilters.attributionAgeDays)
        attributionAgeMode.value = newFilters.attributionAgeMode === 'younger' ? 'younger' : 'older'
    }

    watch(currentUserRole, (newRole, oldRole) => {
        if (!newRole || newRole === oldRole) return

        analysisFilters.value = [...DEFAULT_ANALYSIS_FILTERS]
        inconsistencyReasonFilters.value = []
        lifecycleFilters.value = newRole === 'REVIEWER'
            ? [...DEFAULT_REVIEWER_LIFECYCLE_FILTERS]
            : [...DEFAULT_ANALYST_LIFECYCLE_FILTERS]
    })

    watch([
        smartSearchInput,
        lifecycleFilters,
        inconsistencyReasonFilters,
        analysisFilters,
        tagFilter,
        idFilter,
        componentFilter,
        assigneeFilter,
        dependencyFilter,
        tmrescoreProposalFilter,
        automaticAssessmentFilter,
        versionFilterInput,
        cvssVersionMismatchOnly,
        attributionAgeDays,
        attributionAgeMode,
        sortBy,
        sortOrder,
    ], () => {
        if (filterUrlSyncTimer) clearTimeout(filterUrlSyncTimer)
        filterUrlSyncTimer = setTimeout(() => {
            filterUrlSyncTimer = null
            syncFilterQueryToUrl()
        }, 200)
    }, { deep: true })

    onMounted(hydrateFiltersFromQuery)

    onUnmounted(() => {
        if (filterUrlSyncTimer) {
            clearTimeout(filterUrlSyncTimer)
            filterUrlSyncTimer = null
        }
    })

    return {
        smartSearchInput,
        appliedSmartSearchInput,
        flushSmartSearchFilter,
        parsedSmartSearch,
        liveParsedSmartSearch,
        tagFilter,
        idFilter,
        componentFilter,
        assigneeFilter,
        dependencyFilter,
        tmrescoreProposalFilter,
        automaticAssessmentFilter,
        cvssVersionMismatchOnly,
        attributionAgeDays,
        attributionAgeMode,
        lifecycleFilters,
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
        copiedUrl,
        filterUrl,
        copyFilterUrl,
        resetFilters,
        filterState,
        handleFilterUpdate,
        defaultLifecycleFilters,
        defaultAnalysisFilters,
    }
}
