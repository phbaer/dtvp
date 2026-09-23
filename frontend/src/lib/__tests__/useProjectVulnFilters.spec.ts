import { mount } from '@vue/test-utils'
import { computed, defineComponent, nextTick, reactive, ref } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
    DEFAULT_ANALYSIS_FILTERS,
    DEFAULT_ANALYST_LIFECYCLE_FILTERS,
    DEFAULT_REVIEWER_LIFECYCLE_FILTERS,
    useProjectVulnFilters,
} from '../useProjectVulnFilters'

type ProjectVulnFilters = ReturnType<typeof useProjectVulnFilters>

const mountHarness = (options: {
    query?: Record<string, unknown>
    role?: string
} = {}) => {
    const route = reactive({
        path: '/projects/p1/Project',
        query: { ...(options.query || {}) },
    })
    const role = ref(options.role || 'ANALYST')
    const router = {
        replace: vi.fn((location: { query: Record<string, unknown> }) => Promise.resolve(location)),
    }
    let filters!: ProjectVulnFilters

    const Harness = defineComponent({
        setup() {
            filters = useProjectVulnFilters({
                route,
                router: router as any,
                currentUserRole: computed(() => role.value),
            })
            return {}
        },
        template: '<div />',
    })

    const wrapper = mount(Harness)
    return { wrapper, filters, role, router }
}

describe('useProjectVulnFilters', () => {
    it('roundtrips evidence filters through URLs, sidebar updates and reset', async () => {
        vi.useFakeTimers()
        const { filters, wrapper, router } = mountHarness({ query: { evidence: ['kev,cisa_ssvc', 'not_checked'] } })
        expect(filters.evidenceFilters.value).toEqual(['KEV', 'CISA_SSVC', 'NOT_CHECKED'])
        expect(filters.filterUrl.value).toContain('evidence=KEV')
        filters.handleFilterUpdate({ ...filters.filterState.value, evidenceFilters: ['STALE'] })
        await nextTick()
        await vi.advanceTimersByTimeAsync(250)
        expect(router.replace).toHaveBeenLastCalledWith(expect.objectContaining({ query: expect.objectContaining({ evidence: ['STALE'] }) }))
        filters.resetFilters()
        expect(filters.evidenceFilters.value).toEqual([])
        expect(filters.filterUrl.value).not.toContain('evidence=')
        await nextTick()
        await vi.advanceTimersByTimeAsync(250)
        expect(router.replace.mock.lastCall?.[0].query).not.toHaveProperty('evidence')
        wrapper.unmount()
    })
    it('roundtrips original severity and SSVC filters and resets them to unrestricted', async () => {
        vi.useFakeTimers()
        const { filters, wrapper, router } = mountHarness({ query: { original_severity: 'critical,high', ssvc: ['immediate', 'mixed'] } })
        expect(filters.originalSeverityFilters.value).toEqual(['CRITICAL', 'HIGH'])
        expect(filters.ssvcFilters.value).toEqual(['IMMEDIATE', 'MIXED'])
        expect(filters.filterUrl.value).toContain('original_severity=CRITICAL')
        expect(filters.filterUrl.value).toContain('ssvc=MIXED')
        filters.handleFilterUpdate({ ...filters.filterState.value, originalSeverityFilters: ['INFO'], ssvcFilters: ['UNASSESSED'] })
        await nextTick()
        await vi.advanceTimersByTimeAsync(250)
        expect(router.replace).toHaveBeenLastCalledWith(expect.objectContaining({ query: expect.objectContaining({ original_severity: ['INFO'], ssvc: ['UNASSESSED'] }) }))
        filters.resetFilters()
        expect(filters.originalSeverityFilters.value).toEqual([])
        expect(filters.ssvcFilters.value).toEqual([])
        expect(filters.filterUrl.value).not.toContain('ssvc=')
        wrapper.unmount()
    })
    afterEach(() => {
        vi.useRealTimers()
        vi.clearAllMocks()
    })

    it('hydrates all vulnerability filter state from route query params', async () => {
        const { filters, wrapper } = mountHarness({
            role: 'REVIEWER',
            query: {
                q: 'spring team:platform',
                lifecycle: ['OPEN', 'INCOMPLETE'],
                inconsistency_reason: ['analysis_state_mismatch', 'assessment_details_mismatch'],
                analysis: 'NOT_SET',
                id: 'CVE-1',
                component: 'spring-core',
                assignee: 'alice',
                dependency: ['direct', 'unknown'],
                versions: '1.0.0, 2.0.0',
                tmrescore: 'with_proposal',
                automatic_assessment: 'with_automatic_assessment',
                automatic_assessment_outcome: ['affected', 'probably_affected'],
                automatic_assessment_rescore: 'low',
                cvss_mismatch: 'true',
                attributed_before_days: '14',
                attribution_mode: 'younger',
                sort: 'id',
                order: 'asc',
            },
        })

        await nextTick()

        expect(filters.filtersReady.value).toBe(true)
        expect(filters.smartSearchInput.value).toBe('spring team:platform')
        expect(filters.parsedSmartSearch.value.textTerms).toEqual(['spring'])
        expect(filters.parsedSmartSearch.value.teamTerms).toEqual(['platform'])
        expect(filters.lifecycleFilters.value).toEqual(['OPEN', 'INCOMPLETE', 'INCONSISTENT'])
        expect(filters.inconsistencyReasonFilters.value).toEqual([
            'ANALYSIS_STATE_MISMATCH',
            'ASSESSMENT_DETAILS_MISMATCH',
        ])
        expect(filters.analysisFilters.value).toEqual(['NOT_SET'])
        expect(filters.idFilter.value).toBe('CVE-1')
        expect(filters.componentFilter.value).toBe('spring-core')
        expect(filters.assigneeFilter.value).toBe('alice')
        expect(filters.selectedDependencyFilters.value).toEqual(['DIRECT', 'UNKNOWN'])
        expect(filters.versionFilterList.value).toEqual(['1.0.0', '2.0.0'])
        expect(filters.selectedTMRescoreProposalFilters.value).toEqual(['WITH_PROPOSAL'])
        expect(filters.selectedAutomaticAssessmentFilters.value).toEqual(['WITH_AUTOMATIC_ASSESSMENT'])
        expect(filters.selectedAutomaticAssessmentOutcomeFilters.value).toEqual(['AFFECTED', 'PROBABLY_AFFECTED'])
        expect(filters.selectedAutomaticAssessmentRescoreFilters.value).toEqual(['LOW'])
        expect(filters.cvssVersionMismatchOnly.value).toBe(true)
        expect(filters.attributionAgeDays.value).toBe(14)
        expect(filters.attributionAgeMode.value).toBe('younger')
        expect(filters.sortBy.value).toBe('id')
        expect(filters.sortOrder.value).toBe('asc')

        wrapper.unmount()
    })

    it('treats single-filter URLs as real filter URLs', async () => {
        const { filters, wrapper } = mountHarness({
            query: {
                versions: '3.0.0, 3.1.0',
            },
        })

        await nextTick()

        expect(filters.filtersReady.value).toBe(true)
        expect(filters.versionFilterList.value).toEqual(['3.0.0', '3.1.0'])

        wrapper.unmount()

        const dependencyOnly = mountHarness({
            query: {
                dependency: 'transitive',
            },
        })

        await nextTick()

        expect(dependencyOnly.filters.filtersReady.value).toBe(true)
        expect(dependencyOnly.filters.selectedDependencyFilters.value).toEqual(['TRANSITIVE'])

        dependencyOnly.wrapper.unmount()
    })

    it('resets lifecycle defaults when the current role changes', async () => {
        const { filters, role, wrapper } = mountHarness({ role: 'ANALYST' })
        await nextTick()

        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_ANALYST_LIFECYCLE_FILTERS)
        expect(filters.analysisFilters.value).toEqual(DEFAULT_ANALYSIS_FILTERS)

        role.value = 'REVIEWER'
        await nextTick()

        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_REVIEWER_LIFECYCLE_FILTERS)
        expect(filters.analysisFilters.value).toEqual(DEFAULT_ANALYSIS_FILTERS)

        wrapper.unmount()
    })

    it('defaults and resets analysts to all unfinished assessments, without overriding explicit URLs', () => {
        const { filters, wrapper } = mountHarness()
        expect(filters.lifecycleFilters.value).toEqual(['OPEN', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL'])
        // Default values need not be repeated in the shareable URL.
        expect(filters.filterUrl.value).not.toContain('lifecycle=')
        filters.lifecycleFilters.value = ['ASSESSED']
        filters.resetFilters()
        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_ANALYST_LIFECYCLE_FILTERS)
        wrapper.unmount()
        const explicit = mountHarness({ query: { lifecycle: ['OPEN'] } })
        expect(explicit.filters.lifecycleFilters.value).toEqual(['OPEN'])
        explicit.wrapper.unmount()
        const otherFilter = mountHarness({ query: { tag: 'Security' } })
        expect(otherFilter.filters.lifecycleFilters.value).toEqual(DEFAULT_ANALYST_LIFECYCLE_FILTERS)
        otherFilter.wrapper.unmount()
    })

    it('debounces URL synchronization after filter changes', async () => {
        vi.useFakeTimers()
        const { filters, router, wrapper } = mountHarness({ role: 'REVIEWER' })
        await nextTick()
        vi.advanceTimersByTime(200)
        await nextTick()
        router.replace.mockClear()

        filters.idFilter.value = 'CVE-2'
        await nextTick()
        vi.advanceTimersByTime(199)
        await nextTick()
        expect(router.replace).not.toHaveBeenCalled()

        vi.advanceTimersByTime(1)
        await nextTick()

        expect(router.replace).toHaveBeenCalledTimes(1)
        const query = router.replace.mock.calls[0][0]?.query as Record<string, unknown>
        expect(query.id).toBe('CVE-2')
        expect(query.lifecycle).toEqual(DEFAULT_REVIEWER_LIFECYCLE_FILTERS)
        expect(query.analysis).toEqual(DEFAULT_ANALYSIS_FILTERS)
        expect(query.sort).toBe('rescored-severity')
        expect(query.order).toBe('desc')

        wrapper.unmount()
    })
})
