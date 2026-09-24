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
    it('Documented preserves lifecycle, roundtrips URLs, and resets to Any', async () => {
        vi.useFakeTimers()
        const { filters, wrapper, router } = mountHarness({ role: 'REVIEWER', query: { teams: ['Security'], lifecycle: ['READY_FOR_APPROVAL'] } })
        expect(filters.lifecycleFilters.value).toEqual(['READY_FOR_APPROVAL'])
        filters.handleFilterUpdate({ ...filters.filterState.value, teamAssessmentFilter: 'DOCUMENTED' })
        expect(filters.lifecycleFilters.value).toEqual(['READY_FOR_APPROVAL'])
        expect(filters.filterUrl.value).toContain('team_assessment=DOCUMENTED')
        expect(filters.filterUrl.value).not.toContain('lifecycle=ASSESSED')
        await nextTick()
        await vi.advanceTimersByTimeAsync(250)
        expect(router.replace.mock.lastCall?.[0].query.team_assessment).toBe('DOCUMENTED')
        filters.handleFilterUpdate({ ...filters.filterState.value, lifecycleFilters: ['INCOMPLETE'] })
        expect(filters.lifecycleFilters.value).toEqual(['INCOMPLETE'])
        filters.resetFilters()
        expect(filters.teamAssessmentFilter.value).toBe('ANY')
        expect(filters.filterUrl.value).not.toContain('team_assessment=')
        wrapper.unmount()
    })

    it('hydrates documented links using role defaults and respects explicit lifecycle', () => {
        const first = mountHarness({ role: 'REVIEWER', query: { teams: ['Security'], team_assessment: 'DOCUMENTED' } })
        expect(first.filters.teamAssessmentFilter.value).toBe('DOCUMENTED')
        expect(first.filters.lifecycleFilters.value).toEqual(DEFAULT_REVIEWER_LIFECYCLE_FILTERS)
        first.wrapper.unmount()
        const second = mountHarness({ query: { team_assessment: 'DOCUMENTED', lifecycle: 'INCOMPLETE' } })
        expect(second.filters.lifecycleFilters.value).toEqual(['INCOMPLETE'])
        second.wrapper.unmount()
    })

    it.each(['ANALYST', 'REVIEWER'])('preserves %s lifecycle selections through every team assessment choice', async (role) => {
        vi.useFakeTimers()
        const { filters, wrapper, router } = mountHarness({ role, query: { teams: ['Security'] } })
        for (const [index, lifecycle] of [filters.lifecycleFilters.value, ['INCOMPLETE', 'ASSESSED'], []].entries()) {
            filters.handleFilterUpdate({ ...filters.filterState.value, lifecycleFilters: [...lifecycle] })
            for (const coverage of ['DOCUMENTED', 'MISSING', 'ANY', 'DOCUMENTED']) {
                filters.handleFilterUpdate({ ...filters.filterState.value, teamAssessmentFilter: coverage })
                expect(filters.lifecycleFilters.value).toEqual(lifecycle)
                await nextTick()
                await vi.advanceTimersByTimeAsync(250)
                expect(router.replace.mock.lastCall?.[0].query.lifecycle).toEqual(
                    index === 0 ? undefined : lifecycle.length ? lifecycle : ['__NO_MATCH__'],
                )
            }
        }
        wrapper.unmount()
    })

    it('ignores coverage without teams and clears coverage when the last team is removed', () => {
        const { filters, wrapper } = mountHarness({ query: { team_assessment: 'DOCUMENTED' } })
        expect(filters.teamAssessmentFilter.value).toBe('ANY')
        filters.handleFilterUpdate({ ...filters.filterState.value, teamFilters: ['Security', 'Platform'] })
        expect(filters.teamAssessmentFilter.value).toBe('MISSING')
        filters.handleFilterUpdate({ ...filters.filterState.value, teamAssessmentFilter: 'DOCUMENTED' })
        filters.handleFilterUpdate({ ...filters.filterState.value, teamFilters: ['Platform'] })
        expect(filters.teamAssessmentFilter.value).toBe('DOCUMENTED')
        filters.handleFilterUpdate({ ...filters.filterState.value, teamFilters: [] })
        expect(filters.teamAssessmentFilter.value).toBe('ANY')
        expect(filters.filterUrl.value).not.toContain('team_assessment=')
        wrapper.unmount()
    })

    it('roundtrips an explicitly empty overall status selection', () => {
        const { filters, wrapper } = mountHarness({ query: { lifecycle: ['__NO_MATCH__'] } })
        expect(filters.lifecycleFilters.value).toEqual([])
        expect(filters.filterUrl.value).toContain('lifecycle=__NO_MATCH__')
        wrapper.unmount()
    })

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
        expect(filters.lifecycleFilters.value).toEqual(['OPEN', 'INCOMPLETE'])
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

    it('migrates retired URL categories to visible lifecycle choices', () => {
        const { filters, wrapper } = mountHarness({ query: {
            lifecycle: ['NEEDS_APPROVAL', 'ASSESSED_LEGACY', 'ASSESSED', 'CONFLICTING'],
        } })
        expect(filters.lifecycleFilters.value).toEqual(['READY_FOR_APPROVAL', 'ASSESSED', 'INCOMPLETE'])
        wrapper.unmount()
    })

    it('switches untouched defaults with the role, including selected-team coverage', async () => {
        vi.useFakeTimers()
        const { filters, role, router, wrapper } = mountHarness({ role: 'ANALYST', query: { teams: ['Security'] } })
        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_ANALYST_LIFECYCLE_FILTERS)
        expect(filters.teamAssessmentFilter.value).toBe('MISSING')
        role.value = 'REVIEWER'
        await nextTick()
        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_REVIEWER_LIFECYCLE_FILTERS)
        expect(filters.teamAssessmentFilter.value).toBe('ANY')
        await vi.advanceTimersByTimeAsync(250)
        expect(router.replace.mock.lastCall?.[0].query.lifecycle).toBeUndefined()
        expect(router.replace.mock.lastCall?.[0].query.team_assessment).toBeUndefined()
        role.value = 'ANALYST'
        await nextTick()
        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_ANALYST_LIFECYCLE_FILTERS)
        expect(filters.teamAssessmentFilter.value).toBe('MISSING')
        wrapper.unmount()
    })

    it('recognizes role defaults serialized by older URLs', async () => {
        const { filters, role, wrapper } = mountHarness({
            role: 'ANALYST',
            query: { teams: ['Security'], lifecycle: ['OPEN', 'INCOMPLETE'], team_assessment: 'MISSING' },
        })
        role.value = 'REVIEWER'
        await nextTick()
        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_REVIEWER_LIFECYCLE_FILTERS)
        expect(filters.teamAssessmentFilter.value).toBe('ANY')
        expect(filters.filterUrl.value).not.toContain('lifecycle=')
        expect(filters.filterUrl.value).not.toContain('team_assessment=')
        wrapper.unmount()
    })

    it('preserves explicit status and assessment selections when the role changes', async () => {
        const { filters, role, wrapper } = mountHarness({
            role: 'ANALYST',
            query: { teams: ['Security'], lifecycle: ['INCOMPLETE'], team_assessment: 'DOCUMENTED' },
        })
        role.value = 'REVIEWER'
        await nextTick()
        expect(filters.lifecycleFilters.value).toEqual(['INCOMPLETE'])
        expect(filters.teamAssessmentFilter.value).toBe('DOCUMENTED')
        wrapper.unmount()
    })

    it('keeps a changed status independent of role defaults', async () => {
        const { filters, role, wrapper } = mountHarness({ role: 'ANALYST' })
        filters.handleFilterUpdate({ ...filters.filterState.value, lifecycleFilters: ['ASSESSED'] })
        role.value = 'REVIEWER'
        await nextTick()
        expect(filters.lifecycleFilters.value).toEqual(['ASSESSED'])
        wrapper.unmount()
    })

    it('defaults analysts to Missing but persists explicit Any across reloads', async () => {
        vi.useFakeTimers()
        const { filters, router, wrapper } = mountHarness()
        expect(filters.teamAssessmentFilter.value).toBe('ANY')
        filters.handleFilterUpdate({ ...filters.filterState.value, teamFilters: ['Security'] })
        expect(filters.teamAssessmentFilter.value).toBe('MISSING')
        filters.handleFilterUpdate({ ...filters.filterState.value, teamAssessmentFilter: 'ANY' })
        expect(filters.filterUrl.value).toContain('team_assessment=ANY')
        await nextTick()
        await vi.advanceTimersByTimeAsync(250)
        expect(router.replace.mock.lastCall?.[0].query.team_assessment).toBe('ANY')
        const reloaded = mountHarness({ query: router.replace.mock.lastCall?.[0].query })
        expect(reloaded.filters.teamAssessmentFilter.value).toBe('ANY')
        reloaded.filters.resetFilters()
        expect(reloaded.filters.teamAssessmentFilter.value).toBe('ANY')
        wrapper.unmount()
        reloaded.wrapper.unmount()
    })

    it('defaults and resets analysts to work needing analysis, without overriding explicit URLs', () => {
        const { filters, wrapper } = mountHarness()
        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_ANALYST_LIFECYCLE_FILTERS)
        // Default values need not be repeated in the shareable URL.
        expect(filters.filterUrl.value).not.toContain('lifecycle=')
        filters.lifecycleFilters.value = ['ASSESSED']
        filters.resetFilters()
        expect(filters.lifecycleFilters.value).toEqual(DEFAULT_ANALYST_LIFECYCLE_FILTERS)
        expect(filters.teamAssessmentFilter.value).toBe('ANY')
        wrapper.unmount()
        const explicit = mountHarness({ query: { lifecycle: ['OPEN'] } })
        expect(explicit.filters.lifecycleFilters.value).toEqual(['OPEN'])
        explicit.wrapper.unmount()
        const otherFilter = mountHarness({ query: { tag: 'Security' } })
        expect(otherFilter.filters.lifecycleFilters.value).toEqual(DEFAULT_ANALYST_LIFECYCLE_FILTERS)
        otherFilter.wrapper.unmount()
    })

    it('migrates distinct conflict URLs into the visible Incomplete choice', () => {
        const { filters, wrapper } = mountHarness({ query: { lifecycle: ['INCONSISTENT'] } })
        expect(filters.lifecycleFilters.value).toEqual(['INCOMPLETE'])
        expect(filters.filterUrl.value).toContain('lifecycle=INCOMPLETE')
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
        expect(query.lifecycle).toBeUndefined()
        expect(query.analysis).toEqual(DEFAULT_ANALYSIS_FILTERS)
        expect(query.sort).toBe('rescored-severity')
        expect(query.order).toBe('desc')

        wrapper.unmount()
    })
})
