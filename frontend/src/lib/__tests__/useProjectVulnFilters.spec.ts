import { mount } from '@vue/test-utils'
import { computed, defineComponent, nextTick, reactive, ref } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
    DEFAULT_ANALYSIS_FILTERS,
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

        expect(filters.lifecycleFilters.value).toEqual(['OPEN'])
        expect(filters.analysisFilters.value).toEqual(DEFAULT_ANALYSIS_FILTERS)

        role.value = 'REVIEWER'
        await nextTick()

        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_REVIEWER_LIFECYCLE_FILTERS)
        expect(filters.analysisFilters.value).toEqual(DEFAULT_ANALYSIS_FILTERS)

        wrapper.unmount()
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
