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
    it('roundtrips and resets the Changes requested filter', async () => {
        const { wrapper, filters } = mountHarness({ query: { changes_requested: 'true', awaiting_review: 'false' } })
        await nextTick()
        expect(filters.changesRequestedOnly.value).toBe(true)
        expect(filters.filterUrl.value).toContain('changes_requested=true')
        filters.resetFilters()
        expect(filters.changesRequestedOnly.value).toBe(false)
        wrapper.unmount()
    })
    it('roundtrips and resets the MCP assessments filter', async () => {
        const { wrapper, filters } = mountHarness({ query: { mcp_assessments: 'true', awaiting_review: 'false' } })
        await nextTick()
        expect(filters.mcpAssessmentsOnly.value).toBe(true)
        expect(filters.filterUrl.value).toContain('mcp_assessments=true')
        filters.resetFilters()
        expect(filters.mcpAssessmentsOnly.value).toBe(false)
        wrapper.unmount()
    })
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
                not_rescored: 'true',
                new_findings: 'true',
                awaiting_review: 'true',
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
        expect(filters.notRescoredOnly.value).toBe(true)
        expect(filters.filterUrl.value).toContain('not_rescored=true')
        expect(filters.newFindingsOnly.value).toBe(true)
        expect(filters.filterUrl.value).toContain('new_findings=true')
        expect(filters.awaitingReviewOnly.value).toBe(true)
        expect(filters.filterUrl.value).toContain('awaiting_review=true')
        // Retired attribution-age parameters are a relative cutoff (ADR 0015).
        expect(filters.cutoff.value).toBe('14d')
        expect(filters.cutoffMode.value).toBe('after')
        expect(filters.filterUrl.value).toContain('cutoff=14d')
        expect(filters.filterUrl.value).toContain('cutoff_mode=after')
        expect(filters.filterUrl.value).not.toContain('attributed_before_days')
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

    it('keeps awaiting review in the address bar and the copied link alike', async () => {
        vi.useFakeTimers()
        const { filters, wrapper, router } = mountHarness({ role: 'ANALYST' })
        await nextTick()
        expect(filters.awaitingReviewOnly.value).toBe(false)
        filters.handleFilterUpdate({ ...filters.filterState.value, awaitingReviewOnly: true })
        expect(filters.filterUrl.value).toContain('awaiting_review=true')
        await vi.advanceTimersByTimeAsync(250)
        const query = router.replace.mock.lastCall![0].query
        expect(query.awaiting_review).toBe('true')
        // The link is built from the same query as the address bar.
        const linkParams = new URL(filters.filterUrl.value).searchParams
        expect(Object.fromEntries(linkParams)).toEqual(Object.fromEntries(
            Object.entries(query).map(([key, value]) => [key, Array.isArray(value) ? String(value.at(-1)) : String(value)]),
        ))
        filters.resetFilters()
        expect(filters.awaitingReviewOnly.value).toBe(false)
        expect(filters.filterUrl.value).not.toContain('awaiting_review')
        vi.useRealTimers()
        wrapper.unmount()
    })

    it('maps retired parameters of saved links to their replacements', async () => {
        vi.useFakeTimers()
        const { filters, wrapper, router } = mountHarness({
            role: 'REVIEWER',
            query: {
                tag: 'Platform',
                cve: 'CVE-2026-1',
                auto_assessment: 'with_automatic_assessment',
                age_days: '30',
                lifecycle: ['READY_FOR_APPROVAL', 'CONFLICTING'],
            },
        })
        await nextTick()
        expect(filters.teamFilters.value).toEqual(['Platform'])
        expect(filters.idFilter.value).toBe('CVE-2026-1')
        expect(filters.selectedAutomaticAssessmentFilters.value).toEqual(['WITH_AUTOMATIC_ASSESSMENT'])
        expect(filters.cutoff.value).toBe('30d')
        expect(filters.lifecycleFilters.value).toEqual(['READY_FOR_APPROVAL', 'INCOMPLETE'])
        // An old link with other filters and no awaiting_review: off, also for reviewers.
        expect(filters.awaitingReviewOnly.value).toBe(false)
        filters.handleFilterUpdate({ ...filters.filterState.value, sortBy: 'id' })
        await vi.advanceTimersByTimeAsync(250)
        const query = router.replace.mock.lastCall![0].query
        expect(query).toMatchObject({ teams: ['Platform'], id: 'CVE-2026-1', cutoff: '30d' })
        for (const retired of ['tag', 'cve', 'auto_assessment', 'age_days', 'attributed_before_days', 'attribution_mode']) expect(query).not.toHaveProperty(retired)
        vi.useRealTimers()
        wrapper.unmount()
    })

    it('maps an old needs-approval link to Awaiting review', async () => {
        const { filters, wrapper } = mountHarness({ role: 'ANALYST', query: { lifecycle: 'NEEDS_APPROVAL' } })
        await nextTick()
        expect(filters.awaitingReviewOnly.value).toBe(true)
        expect(filters.lifecycleFilters.value).toEqual(['OPEN', 'INCOMPLETE', 'READY_FOR_APPROVAL', 'ASSESSED'])
        expect(filters.filterUrl.value).toContain('awaiting_review=true')
        expect(filters.filterUrl.value).not.toContain('NEEDS_APPROVAL')
        wrapper.unmount()
        // Combined with another status it was an OR; the nearest status stays.
        const mixed = mountHarness({ role: 'ANALYST', query: { lifecycle: ['OPEN', 'NEEDS_APPROVAL'] } })
        await nextTick()
        expect(mixed.filters.awaitingReviewOnly.value).toBe(false)
        expect(mixed.filters.lifecycleFilters.value).toEqual(['OPEN', 'READY_FOR_APPROVAL'])
        mixed.wrapper.unmount()
    })

    it('starts reviewers on Awaiting review as a role default that explicit choices override', async () => {
        vi.useFakeTimers()
        const { filters, wrapper, router, role } = mountHarness({ role: 'REVIEWER' })
        await nextTick()
        expect(filters.awaitingReviewOnly.value).toBe(true)
        expect(filters.defaultAwaitingReviewOnly.value).toBe(true)
        // Written while on, so a reload with the sort in the URL keeps it.
        expect(filters.filterUrl.value).toContain('awaiting_review=true')

        // Untouched, it follows the role.
        role.value = 'ANALYST'
        await nextTick()
        expect(filters.awaitingReviewOnly.value).toBe(false)
        role.value = 'REVIEWER'
        await nextTick()
        expect(filters.awaitingReviewOnly.value).toBe(true)

        // Turned off by the reviewer: explicit, survives a role change and the URL.
        filters.handleFilterUpdate({ ...filters.filterState.value, awaitingReviewOnly: false })
        await vi.advanceTimersByTimeAsync(250)
        expect(router.replace.mock.lastCall![0].query.awaiting_review).toBe('false')
        role.value = 'ANALYST'
        await nextTick()
        role.value = 'REVIEWER'
        await nextTick()
        expect(filters.awaitingReviewOnly.value).toBe(false)

        // Reset returns to the role default.
        filters.resetFilters()
        expect(filters.awaitingReviewOnly.value).toBe(true)
        vi.useRealTimers()
        wrapper.unmount()

        const analyst = mountHarness({ role: 'ANALYST' })
        await nextTick()
        expect(analyst.filters.awaitingReviewOnly.value).toBe(false)
        expect(analyst.filters.filterUrl.value).not.toContain('awaiting_review')
        analyst.wrapper.unmount()
    })

    it('reads the reviewer default from a URL that holds only the sort, and off from an explicit one', async () => {
        const sortOnly = mountHarness({ role: 'REVIEWER', query: { sort: 'id', order: 'asc' } })
        await nextTick()
        expect(sortOnly.filters.awaitingReviewOnly.value).toBe(true)
        sortOnly.wrapper.unmount()
        const off = mountHarness({ role: 'REVIEWER', query: { awaiting_review: 'false', sort: 'id', order: 'asc' } })
        await nextTick()
        expect(off.filters.awaitingReviewOnly.value).toBe(false)
        expect(off.filters.filterUrl.value).toContain('awaiting_review=false')
        off.wrapper.unmount()
    })
})

describe('useProjectVulnFilters with saved views (ADR 0015)', () => {
    const mountWithDefault = (query: Record<string, unknown>, resolveDefaultQuery: () => Promise<string | null>) => {
        const route = reactive({ path: '/project/Project', query: { ...query } })
        const router = {
            replace: vi.fn((location: { query: Record<string, unknown> }) => {
                route.query = { ...location.query }
                return Promise.resolve(location)
            }),
        }
        let filters!: ProjectVulnFilters
        const wrapper = mount(defineComponent({
            setup() {
                filters = useProjectVulnFilters({
                    route,
                    router: router as any,
                    currentUserRole: computed(() => 'REVIEWER'),
                    resolveDefaultQuery,
                })
                return {}
            },
            template: '<div />',
        }))
        return { wrapper, filters, router, route }
    }
    const flush = () => new Promise(resolve => setTimeout(resolve, 0))

    it('opens a project without filters on the effective default view, and Reset returns to it', async () => {
        const resolve = vi.fn(async () => 'cutoff=2026-03-01&versions=7.1.1&awaiting_review=false')
        const { wrapper, filters, router } = mountWithDefault({}, resolve)
        expect(filters.filtersReady.value).toBe(false)
        await flush()
        expect(filters.filtersReady.value).toBe(true)
        expect(filters.cutoff.value).toBe('2026-03-01')
        expect(filters.versionFilterInput.value).toBe('7.1.1')
        expect(filters.awaitingReviewOnly.value).toBe(false)
        expect(router.replace).toHaveBeenCalled()

        filters.handleFilterUpdate({ ...filters.filterState.value, cutoff: '', versionFilterInput: '' })
        expect(filters.cutoff.value).toBe('')
        filters.resetFilters()
        expect(filters.cutoff.value).toBe('2026-03-01')
        expect(filters.versionFilterInput.value).toBe('7.1.1')

        // Without a default view Reset gives the built-in role default.
        filters.defaultViewQuery.value = null
        filters.resetFilters()
        expect(filters.cutoff.value).toBe('')
        expect(filters.awaitingReviewOnly.value).toBe(true)
        wrapper.unmount()
    })

    it('lets the URL win over the default view and falls back to the built-in default on errors', async () => {
        const { wrapper, filters } = mountWithDefault({ versions: '2.0' }, async () => 'cutoff=2026-03-01')
        expect(filters.filtersReady.value).toBe(true)
        expect(filters.versionFilterInput.value).toBe('2.0')
        expect(filters.cutoff.value).toBe('')
        await flush()
        expect(filters.defaultViewQuery.value).toBe('cutoff=2026-03-01')
        wrapper.unmount()

        const failing = mountWithDefault({}, async () => { throw new Error('offline') })
        await flush()
        expect(failing.filters.filtersReady.value).toBe(true)
        expect(failing.filters.awaitingReviewOnly.value).toBe(true)
        failing.wrapper.unmount()
    })

    it('gives the canonical query string of the filters to save', async () => {
        const { wrapper, filters } = mountWithDefault(
            { versions: '7.1.1', cutoff: '30d', cutoff_mode: 'after', vuln: 'CVE-1', lifecycle: ['OPEN', 'INCOMPLETE'] },
            async () => null,
        )
        const query = filters.savedViewQuery()
        expect(query).toContain('cutoff=30d')
        expect(query).toContain('cutoff_mode=after')
        expect(query).toContain('lifecycle=INCOMPLETE&lifecycle=OPEN')
        expect(query).not.toContain('vuln=')
        expect(query.indexOf('cutoff=')).toBeLessThan(query.indexOf('versions='))
        wrapper.unmount()
    })
})
