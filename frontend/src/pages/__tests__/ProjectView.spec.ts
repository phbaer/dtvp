import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { codeAnalysisListResults, drainTaskVulnGroupDetails, getGroupedVulns, getStatistics, getTaskStatistics, getTaskVulnGroup, getTaskVulnGroups, getTMRescoreProposals } from '../../lib/api'
import { projectHeaderState } from '../../lib/projectHeaderStore'
import { useRoute } from 'vue-router'
import { defaultAnalysisFilters, defaultLifecycleFilters, defaultStatusFilters, mountProjectView, updateProjectViewState } from './projectViewTestUtils'

vi.mock('../../lib/api', () => ({
    drainTaskVulnGroupDetails: vi.fn(),
    drainTaskVulnGroups: vi.fn(),
    getGroupedVulns: vi.fn(),
    getTaskVulnGroup: vi.fn(),
    getTaskVulnGroups: vi.fn(() => Promise.resolve({
        items: [],
        total: 0,
        filtered: 0,
        offset: 0,
        limit: 250,
        sort: 'rescored-severity',
        order: 'desc',
    })),
    getStatistics: vi.fn(() => Promise.resolve({
        severity_counts: {},
        state_counts: {},
        total_unique: 0,
        total_findings: 0,
        affected_projects_count: 0,
        version_counts: {},
        version_severity_counts: {},
        major_version_severity_counts: {},
        major_version_counts: {},
        major_version_details: {},
    })),
    getTaskStatistics: vi.fn(() => Promise.resolve({
        severity_counts: {},
        state_counts: {},
        total_unique: 0,
        total_findings: 0,
        affected_projects_count: 0,
        version_counts: {},
        version_severity_counts: {},
        major_version_severity_counts: {},
        major_version_counts: {},
        major_version_details: {},
    })),
    getCacheStatus: vi.fn(() => Promise.resolve({ fully_cached: false, last_refreshed_at: null, projects: 0, active_projects: 0, cached_findings: 0, cached_boms: 0, cached_analyses: 0, pending_updates: 0 })),
    codeAnalysisListResults: vi.fn(() => Promise.resolve([])),
    getTeamMapping: vi.fn(() => Promise.resolve({})),
    getRescoreRules: vi.fn(() => Promise.resolve({ transitions: [] })),
    previewRescoreRuleSync: vi.fn(() => Promise.resolve({ task_id: 'task-1', items: [], summary: { groups: 0 } })),
    getTMRescoreProposals: vi.fn(() => Promise.resolve({ proposals: {} }))
}))

const replaceSpy = vi.fn(() => Promise.resolve())
vi.mock('vue-router', () => ({
    useRoute: vi.fn(() => ({ params: {}, query: {} })),
    useRouter: vi.fn(() => ({ replace: replaceSpy })),
    RouterLink: { template: '<a><slot /></a>' }
}))

// Mock child component
vi.mock('../../components/VulnRowCompact.vue', () => ({
    default: {
        name: 'VulnRowCompact',
        template: `
            <div class="vuln-group-card vuln-card" data-testid="group-card" @click="$emit('select', item.group)">
                <button data-testid="emit-update" @click="$emit('update', item.group)">emit update</button>
            </div>
        `,
        props: ['item'],
        emits: ['select', 'update', 'update:assessment']
    }
}))

vi.mock('../../components/VulnDetailInspector.vue', () => ({
    default: {
        name: 'VulnDetailInspector',
        template: `
            <aside data-testid="detail-inspector">
                <span>{{ group.id }}</span>
                <button data-testid="close-inspector" @click="$emit('close')">close</button>
            </aside>
        `,
        props: ['group'],
        emits: ['close', 'update', 'update:assessment']
    }
}))

vi.mock('../../components/BulkResolveIncompleteModal.vue', () => ({
    default: {
        name: 'BulkResolveIncompleteModal',
        template: '<div v-if="show" data-testid="bulk-resolve-modal">{{ incompleteGroups.map(group => group.id).join(",") }}</div>',
        props: ['show', 'incompleteGroups'],
        emits: ['close', 'updated']
    }
}))

describe('ProjectView.vue', () => {
    const writeTextSpy = vi.fn(() => Promise.resolve())

    beforeEach(() => {
        vi.clearAllMocks()
        projectHeaderState.viewMode.value = 'analysis'
        projectHeaderState.lastProjectName.value = null
        projectHeaderState.lastProjectPath.value = null
        projectHeaderState.incompleteCount.value = 0
        projectHeaderState.bulkSyncHandler.value = null
        projectHeaderState.rescoreRuleSyncCount.value = 0
        projectHeaderState.rescoreRuleSyncHandler.value = null
        Object.defineProperty(navigator, 'clipboard', {
            value: { writeText: writeTextSpy },
            writable: true,
            configurable: true
        })
        vi.mocked(useRoute).mockReturnValue({
            params: { name: 'TestProject' }, query: {}
        } as any)
    })

    it('fetches vulnerabilities on mount', async () => {
        const mockGroups = [{ id: '1', title: 'Vuln 1' }]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        await updateProjectViewState(wrapper, { statusFilters: defaultStatusFilters })

        expect(getGroupedVulns).toHaveBeenCalledWith('TestProject', undefined, expect.any(Function), {
            responseMode: 'summary',
            deferResult: true,
            skipResultDownload: true,
            useEventStream: true,
            taskWindowLimit: 250,
            onTaskId: expect.any(Function),
            onPartialResultAvailable: expect.any(Function),
            onTaskCompleted: expect.any(Function),
        })
        // Child component should be rendered
        expect(wrapper.findAll('.vuln-group-card')).toHaveLength(1)
    })

    it('handles error state', async () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })
        vi.mocked(getGroupedVulns).mockRejectedValue(new Error('Failed'))

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        expect(wrapper.text()).toContain('Failed to load vulnerabilities')
        consoleSpy.mockRestore()
    })

    it('handles empty state', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue([])

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        expect(wrapper.text()).toContain('No vulnerabilities found')
    })

    it('marks and filters vulnerabilities with automatic assessment results', async () => {
        vi.mocked(codeAnalysisListResults).mockResolvedValue([
            {
                analysis_run_id: 'run-auto-1',
                vuln_id: 'GHSA-AUTO',
                component_name: 'CompA',
                source: 'automatic',
            } as any,
        ])
        vi.mocked(getGroupedVulns).mockResolvedValue([
            {
                id: 'CVE-AUTO',
                aliases: ['GHSA-AUTO'],
                affected_versions: [{ components: [{ component_name: 'CompA', analysis_state: 'NOT_SET' }] }],
            },
            {
                id: 'CVE-MANUAL',
                affected_versions: [{ components: [{ component_name: 'CompB', analysis_state: 'NOT_SET' }] }],
            },
        ] as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })
        await flushPromises()
        await wrapper.vm.$nextTick()

        const autoItem = (wrapper.vm as any).listItems.find((item: any) => item.id === 'CVE-AUTO')
        expect(autoItem.hasAutomaticAssessment).toBe(true)

        ;(wrapper.vm as any).automaticAssessmentFilter = ['WITH_AUTOMATIC_ASSESSMENT']
        await wrapper.vm.$nextTick()
        expect((wrapper.vm as any).filteredGroups.map((group: any) => group.id)).toEqual(['CVE-AUTO'])

        ;(wrapper.vm as any).automaticAssessmentFilter = ['WITHOUT_AUTOMATIC_ASSESSMENT']
        await wrapper.vm.$nextTick()
        expect((wrapper.vm as any).filteredGroups.map((group: any) => group.id)).toEqual(['CVE-MANUAL'])
    })

    it('filters by direct dependency and versions', async () => {
        const mockGroups = [
            {
                id: '1',
                title: 'Direct vuln',
                affected_versions: [
                    { project_version: '1.0', components: [{ is_direct_dependency: true }] }
                ]
            },
            {
                id: '2',
                title: 'Transitive vuln',
                affected_versions: [
                    { project_version: '2.0', components: [{ is_direct_dependency: false }] }
                ]
            }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        expect(wrapper.findAll('.vuln-group-card').length).toBe(2)

        ;(wrapper.vm as any).dependencyFilter = ['DIRECT']
        await flushPromises()
        expect(wrapper.findAll('.vuln-group-card').length).toBe(1)

        ;(wrapper.vm as any).dependencyFilter = ['DIRECT', 'TRANSITIVE', 'UNKNOWN']
        ;(wrapper.vm as any).versionFilterInput = '1.0'
        await flushPromises()
        expect(wrapper.findAll('.vuln-group-card').length).toBe(1)

        ;(wrapper.vm as any).versionFilterInput = '2.0'
        await flushPromises()
        expect(wrapper.findAll('.vuln-group-card').length).toBe(1)

        ;(wrapper.vm as any).versionFilterInput = '1.0,2.0'
        await flushPromises()
        expect(wrapper.findAll('.vuln-group-card').length).toBe(2)

        // Verify dependency relationship badge counts
        expect(wrapper.text()).toContain('Direct')
        expect(wrapper.text()).toContain('Transitive')

        // Query update should occur for state-driven filters
        await new Promise(resolve => setTimeout(resolve, 250))
        await flushPromises()
        expect(replaceSpy).toHaveBeenCalled()
        const lastCall = replaceSpy.mock.calls[replaceSpy.mock.calls.length - 1] as any[] | undefined
        const latestQuery = lastCall?.[0]?.query
        expect(latestQuery).toMatchObject({ versions: '1.0,2.0' })
    })

    it('copies the current filter URL to clipboard', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue([{ id: '1', affected_versions: [] } as any])

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        const copyBtn = wrapper.findAll('button').find(b => b.text().includes('Copy filter URL'))
        expect(copyBtn).toBeDefined()
        if (!copyBtn) {
            throw new Error('Copy button not found')
        }

        await copyBtn.trigger('click')

        expect(writeTextSpy).toHaveBeenCalled()
    })

    it('updates local state on assessment update', async () => {
        const mockGroup = {
            id: '1',
            title: 'Vuln 1',
            rescored_cvss: null,
            affected_versions: [
                {
                    components: [
                        { analysis_state: 'NOT_SET' }
                    ]
                }
            ]
        }
        vi.mocked(getGroupedVulns).mockResolvedValue([mockGroup] as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        // Ensure visible
        await updateProjectViewState(wrapper, {
            lifecycleFilters: [...defaultLifecycleFilters, 'ASSESSED_LEGACY', 'NEEDS_APPROVAL'],
            analysisFilters: defaultAnalysisFilters,
        })

        const updateData = {
            rescored_cvss: 5.0,
            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            analysis_state: 'EXPLOITABLE',
            analysis_details: 'Details',
            is_suppressed: false
        }

        await wrapper.findComponent({ name: 'VulnRowCompact' }).vm.$emit('update:assessment', updateData)
        await flushPromises()

        const updatedGroup = (wrapper.findComponent({ name: 'VulnRowCompact' }).props('item') as any).group
        expect(updatedGroup.rescored_cvss).toBe(5.0)
        expect(updatedGroup.affected_versions?.[0]?.components?.[0]?.analysis_state).toBe('EXPLOITABLE')
        expect(updatedGroup.affected_versions?.[0]?.components?.[0]).not.toHaveProperty('analysis_details')
        expect(mockGroup.rescored_cvss).toBeNull()
    })

    it('opens a single detail inspector when selecting a vulnerability row', async () => {
        const mockGroups = [
            { id: 'CVE-1', title: 'First', affected_versions: [] },
            { id: 'CVE-2', title: 'Second', affected_versions: [] },
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        const rows = wrapper.findAllComponents({ name: 'VulnRowCompact' })
        await rows[1].vm.$emit('select', mockGroups[1])

        expect(wrapper.findAllComponents({ name: 'VulnDetailInspector' })).toHaveLength(1)
        expect(wrapper.get('[data-testid="detail-inspector"]').text()).toContain('CVE-2')
        expect(replaceSpy).toHaveBeenCalledWith(expect.objectContaining({
            query: expect.objectContaining({ vuln: 'CVE-2' }),
        }))
    })

    it('closes the selected inspector and removes the vulnerability query param', async () => {
        const mockGroup = { id: 'CVE-1', title: 'First', affected_versions: [] }
        vi.mocked(getGroupedVulns).mockResolvedValue([mockGroup] as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        await wrapper.findComponent({ name: 'VulnRowCompact' }).vm.$emit('select', mockGroup)
        await wrapper.get('[data-testid="close-inspector"]').trigger('click')

        expect(wrapper.findAllComponents({ name: 'VulnDetailInspector' })).toHaveLength(0)
        const lastCall = replaceSpy.mock.calls[replaceSpy.mock.calls.length - 1] as any[] | undefined
        expect(lastCall?.[0]?.query?.vuln).toBeUndefined()
    })

    it('refreshes statistics when assessment update occurs in statistics mode', async () => {
        const mockGroup = {
            id: '1',
            title: 'Vuln 1',
            rescored_cvss: null,
            affected_versions: [{ components: [{ analysis_state: 'NOT_SET' }] }]
        }
        vi.mocked(getGroupedVulns).mockResolvedValue([mockGroup] as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        ;(wrapper.vm as any).viewMode = 'analysis'
        ;(wrapper.vm as any).stats = { total_unique: 0 } // mark stats loaded

        const updateData = {
            rescored_cvss: 5.0,
            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            analysis_state: 'EXPLOITABLE',
            analysis_details: 'Details',
            is_suppressed: false
        }

        await wrapper.findComponent({ name: 'VulnRowCompact' }).vm.$emit('update:assessment', updateData)

        // Not in statistics mode yet, so update should only mark dirty, not fetch.
        expect(getStatistics).not.toHaveBeenCalled()

        ;(wrapper.vm as any).viewMode = 'statistics'
        await flushPromises()

        expect(getStatistics).toHaveBeenCalled()
    })

    it('loads statistics from the active vulnerability task when available', async () => {
        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, _progress, options: any) => {
            options?.onTaskId?.('task-statistics')
            return [] as any
        })
        vi.mocked(getTaskStatistics).mockResolvedValue({
            severity_counts: { HIGH: 1 },
            state_counts: { NOT_SET: 1 },
            total_unique: 1,
            total_findings: 1,
            affected_projects_count: 1,
            version_counts: { '1.0.0': 1 },
        } as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })

        ;(wrapper.vm as any).viewMode = 'statistics'
        await flushPromises()

        expect(getTaskStatistics).toHaveBeenCalledWith('task-statistics')
        expect(getStatistics).not.toHaveBeenCalled()
    })

    it('updates only the local group on team mapping update without refetching vulnerabilities', async () => {
        const mockGroup = {
            id: '1',
            title: 'Vuln 1',
            tags: ['OldTeam'],
            affected_versions: [
                {
                    components: [
                        { component_name: 'lib-a', dependency_chains: ['lib-a -> app'] }
                    ]
                }
            ]
        }
        vi.mocked(getGroupedVulns).mockResolvedValue([mockGroup] as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })
        expect(getGroupedVulns).toHaveBeenCalledTimes(1)

        const updatedGroup = {
            ...mockGroup,
            tags: ['NewTeam'],
        }

        await (wrapper.vm as any).handleTeamMappingUpdated(updatedGroup)
        await flushPromises()

        expect((wrapper.vm as any).groups[0].tags).toEqual(['NewTeam'])
        expect(getGroupedVulns).toHaveBeenCalledTimes(1)
    })

    it('loads the first backend task window instead of draining all groups', async () => {
        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, _progress, options: any) => {
            options?.onTaskId?.('task-windowed-list')
            return [] as any
        })
        vi.mocked(getTaskVulnGroups).mockResolvedValue({
            items: [
                {
                    id: 'CVE-WINDOW-1',
                    title: 'Windowed',
                    list_metadata: {
                        lifecycle: 'OPEN',
                        is_open: true,
                        is_pending: false,
                        technical_state: 'NOT_SET',
                    },
                    affected_versions: [],
                },
            ],
            total: 300,
            filtered: 300,
            counts: {
                all: {
                    total: 300,
                    lifecycle: { OPEN: 300 },
                    analysis: { NOT_SET: 300 },
                    dependency_relationship: { direct: 0, transitive: 0, unknown: 300 },
                    cvss_version_mismatch: 0,
                    versions: {},
                    tags: {},
                    assignees: {},
                    components: {},
                },
                filtered: {
                    total: 300,
                    lifecycle: { OPEN: 300 },
                    analysis: { NOT_SET: 300 },
                    dependency_relationship: { direct: 0, transitive: 0, unknown: 300 },
                    cvss_version_mismatch: 0,
                    versions: {},
                    tags: {},
                    assignees: {},
                    components: {},
                },
            },
            offset: 0,
            limit: 250,
            sort: 'rescored-severity',
            order: 'desc',
        } as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })
        await flushPromises()
        await wrapper.vm.$nextTick()

        expect(getGroupedVulns).toHaveBeenCalledWith('TestProject', undefined, expect.any(Function), {
            responseMode: 'summary',
            deferResult: true,
            skipResultDownload: true,
            useEventStream: true,
            taskWindowLimit: 250,
            onTaskId: expect.any(Function),
            onPartialResultAvailable: expect.any(Function),
            onTaskCompleted: expect.any(Function),
        })
        expect(getTaskVulnGroups).toHaveBeenCalledWith('task-windowed-list', expect.objectContaining({
            offset: 0,
            limit: 250,
            sort: 'rescored-severity',
            order: 'desc',
        }))
        expect(wrapper.findAll('.vuln-group-card')).toHaveLength(1)
        expect(wrapper.text()).toContain('300')
    })

    it('refreshes backend task windows as partial grouping progress advances', async () => {
        const taskWindow = (id: string, total: number, partial: boolean, completed?: number) => {
            const counts = {
                total,
                lifecycle: { OPEN: total },
                analysis: { NOT_SET: total },
                dependency_relationship: { direct: 0, transitive: 0, unknown: total },
                cvss_version_mismatch: 0,
                versions: {},
                tags: {},
                assignees: {},
                components: {},
            }
            return {
                items: [
                    {
                        id,
                        title: id,
                        list_metadata: {
                            lifecycle: 'OPEN',
                            is_open: true,
                            is_pending: false,
                            technical_state: 'NOT_SET',
                        },
                        affected_versions: [],
                    },
                ],
                total,
                filtered: total,
                counts: { all: counts, filtered: counts },
                offset: 0,
                limit: 250,
                sort: 'rescored-severity',
                order: 'desc',
                partial,
                partial_versions_completed: completed,
                partial_total_versions: partial ? 29 : null,
            }
        }

        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, _progress, options: any) => {
            options?.onTaskId?.('task-progress')
            await options?.onPartialResultAvailable?.('task-progress', {
                status: 'running',
                message: 'Processed version 12',
                progress: 37,
                partial_result_available: true,
                partial_versions_completed: 12,
                partial_total_versions: 29,
            })
            await options?.onPartialResultAvailable?.('task-progress', {
                status: 'running',
                message: 'Processed version 13',
                progress: 40,
                partial_result_available: true,
                partial_versions_completed: 13,
                partial_total_versions: 29,
            })
            await options?.onTaskCompleted?.('task-progress', {
                status: 'completed',
                message: 'Done',
                progress: 100,
                partial_result_available: false,
            })
            return [] as any
        })
        vi.mocked(getTaskVulnGroups)
            .mockResolvedValueOnce(taskWindow('CVE-PARTIAL-12', 12, true, 12) as any)
            .mockResolvedValueOnce(taskWindow('CVE-COMPLETE', 29, false) as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })
        await flushPromises()
        await wrapper.vm.$nextTick()

        expect(getTaskVulnGroups).toHaveBeenCalledTimes(2)
        expect(wrapper.text()).not.toContain('Results and counts will keep updating')
        expect(wrapper.text()).toContain('29')
    })

    it('does not describe a 29 of 29 partial window as still loading snapshots', async () => {
        const counts = {
            total: 29,
            lifecycle: { OPEN: 29 },
            analysis: { NOT_SET: 29 },
            dependency_relationship: { direct: 0, transitive: 0, unknown: 29 },
            cvss_version_mismatch: 0,
            versions: {},
            tags: {},
            assignees: {},
            components: {},
        }

        vi.mocked(getGroupedVulns).mockImplementation((_name, _cve, _progress, options: any) => {
            options?.onTaskId?.('task-full-partial')
            options?.onPartialResultAvailable?.('task-full-partial', {
                status: 'running',
                message: 'Published partial vulnerability window for 29/29 project versions.',
                progress: 90,
                partial_result_available: true,
                partial_versions_completed: 29,
                partial_total_versions: 29,
                versions_completed: 29,
                versions_total: 29,
            })
            return new Promise(() => {}) as any
        })
        vi.mocked(getTaskVulnGroups).mockResolvedValue({
            items: [],
            total: 29,
            filtered: 29,
            counts: { all: counts, filtered: counts },
            offset: 0,
            limit: 250,
            sort: 'rescored-severity',
            order: 'desc',
            partial: true,
            partial_versions_completed: 29,
            partial_total_versions: 29,
            versions_completed: 29,
            versions_total: 29,
        } as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject', flush: false })
        await flushPromises()
        await wrapper.vm.$nextTick()

        expect(wrapper.text()).toContain('All project-version snapshots are loaded')
        expect(wrapper.text()).not.toContain('0 still')
        expect(wrapper.text()).not.toContain('0 project-version snapshots are still loading')
    })

    it('displays backend-filtered task windows without a second local filter pass', async () => {
        vi.mocked(useRoute).mockReturnValue({
            params: { name: 'TestProject' },
            query: { q: 'backend-only' },
        } as any)
        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, _progress, options: any) => {
            options?.onTaskId?.('task-backend-owned-filter')
            return [] as any
        })
        vi.mocked(getTaskVulnGroups).mockResolvedValue({
            items: [
                {
                    id: 'CVE-WINDOW-NONLOCAL',
                    title: 'Plain window row',
                    list_metadata: {
                        lifecycle: 'OPEN',
                        is_open: true,
                        is_pending: false,
                        technical_state: 'NOT_SET',
                    },
                    affected_versions: [],
                },
            ],
            total: 1,
            filtered: 1,
            counts: {
                all: {
                    total: 1,
                    lifecycle: { OPEN: 1 },
                    analysis: { NOT_SET: 1 },
                    dependency_relationship: { direct: 0, transitive: 0, unknown: 1 },
                    cvss_version_mismatch: 0,
                    versions: {},
                    tags: {},
                    assignees: {},
                    components: {},
                },
                filtered: {
                    total: 1,
                    lifecycle: { OPEN: 1 },
                    analysis: { NOT_SET: 1 },
                    dependency_relationship: { direct: 0, transitive: 0, unknown: 1 },
                    cvss_version_mismatch: 0,
                    versions: {},
                    tags: {},
                    assignees: {},
                    components: {},
                },
            },
            offset: 0,
            limit: 250,
            sort: 'rescored-severity',
            order: 'desc',
        } as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })
        await flushPromises()
        await wrapper.vm.$nextTick()

        expect(getTaskVulnGroups).toHaveBeenCalledWith('task-backend-owned-filter', expect.objectContaining({
            q: 'backend-only',
            offset: 0,
            limit: 250,
        }))
        expect((wrapper.vm as any).filteredGroups.map((group: any) => group.id)).toEqual(['CVE-WINDOW-NONLOCAL'])
        expect(wrapper.findAll('.vuln-group-card')).toHaveLength(1)
    })

    it('passes meaningful tmrescore proposal ids to backend task windows', async () => {
        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, _progress, options: any) => {
            options?.onTaskId?.('task-tm-window')
            return [] as any
        })
        vi.mocked(getTMRescoreProposals).mockResolvedValue({
            proposals: {
                V1: {
                    vuln_id: 'V1',
                    rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    original_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    rescored_score: 9.8,
                    original_score: 9.8,
                },
                'ALIAS-2': {
                    vuln_id: 'V2',
                    rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L',
                    original_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    rescored_score: 7.9,
                    original_score: 8.5,
                },
            },
        } as any)
        vi.mocked(getTaskVulnGroups).mockResolvedValue({
            items: [],
            total: 2,
            filtered: 1,
            offset: 0,
            limit: 250,
            sort: 'rescored-severity',
            order: 'desc',
        } as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })
        await flushPromises()
        vi.mocked(getTaskVulnGroups).mockClear()

        ;(wrapper.vm as any).tmrescoreProposalFilter = ['WITH_PROPOSAL']
        await flushPromises()
        await wrapper.vm.$nextTick()

        expect(getTaskVulnGroups).toHaveBeenCalled()
        const lastCall = vi.mocked(getTaskVulnGroups).mock.calls.at(-1)
        expect(lastCall?.[0]).toBe('task-tm-window')
        expect(lastCall?.[1]).toEqual(expect.objectContaining({
            tmrescore: ['WITH_PROPOSAL'],
            tmrescore_proposal_ids: expect.arrayContaining(['ALIAS-2', 'V2']),
        }))
        expect(lastCall?.[1]?.tmrescore_proposal_ids).not.toContain('V1')
        expect(drainTaskVulnGroupDetails).not.toHaveBeenCalled()
    })

    it('passes automatic assessment result ids to backend task windows', async () => {
        vi.mocked(codeAnalysisListResults).mockResolvedValue([
            {
                analysis_run_id: 'run-auto-1',
                vuln_id: 'CVE-AUTO',
                component_name: 'CompA',
                source: 'automatic',
            } as any,
        ])
        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, _progress, options: any) => {
            options?.onTaskId?.('task-auto-window')
            return [] as any
        })
        vi.mocked(getTaskVulnGroups).mockResolvedValue({
            items: [],
            total: 2,
            filtered: 1,
            offset: 0,
            limit: 250,
            sort: 'rescored-severity',
            order: 'desc',
        } as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })
        await flushPromises()
        vi.mocked(getTaskVulnGroups).mockClear()

        ;(wrapper.vm as any).automaticAssessmentFilter = ['WITH_AUTOMATIC_ASSESSMENT']
        await flushPromises()
        await wrapper.vm.$nextTick()

        const lastCall = vi.mocked(getTaskVulnGroups).mock.calls.at(-1)
        expect(lastCall?.[0]).toBe('task-auto-window')
        expect(lastCall?.[1]).toEqual(expect.objectContaining({
            automatic_assessment: ['WITH_AUTOMATIC_ASSESSMENT'],
            automatic_assessment_ids: ['cve-auto'],
        }))
    })

    it('prepares bulk sync from backend incomplete full-detail windows', async () => {
        const taskCounts = (total: number, incomplete: number, needsApproval: number) => ({
            total,
            lifecycle: {
                OPEN: 0,
                ASSESSED: 0,
                ASSESSED_LEGACY: 0,
                INCOMPLETE: incomplete,
                INCONSISTENT: 0,
                NEEDS_APPROVAL: needsApproval,
            },
            analysis: { NOT_SET: total },
            dependency_relationship: { direct: 0, transitive: 0, unknown: total },
            cvss_version_mismatch: 0,
            versions: {},
            tags: {},
            assignees: {},
            components: {},
        })
        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, _progress, options: any) => {
            options?.onTaskId?.('task-1')
            return [
                {
                    id: 'CVE-VISIBLE',
                    list_metadata: { lifecycle: 'OPEN' },
                    affected_versions: [],
                },
            ] as any
        })
        vi.mocked(getTaskVulnGroups).mockResolvedValue({
            items: [
                {
                    id: 'CVE-VISIBLE',
                    list_metadata: { lifecycle: 'OPEN' },
                    affected_versions: [],
                },
            ],
            total: 6,
            filtered: 1,
            counts: {
                all: taskCounts(6, 4, 3),
                filtered: taskCounts(1, 1, 0),
            },
            offset: 0,
            limit: 250,
            sort: 'rescored-severity',
            order: 'desc',
        } as any)
        vi.mocked(drainTaskVulnGroupDetails).mockResolvedValue([{
            id: 'CVE-INCOMPLETE',
            title: 'Needs sync',
            affected_versions: [
                {
                    project_version: '1.0.0',
                    components: [
                        {
                            component_name: 'library-a',
                            analysis_state: 'NOT_SET',
                            analysis_details: '--- [Team: Team A] [State: EXPLOITABLE] ---',
                        },
                    ],
                },
            ],
        }] as any)

        const wrapper = await mountProjectView({ routeName: 'TestProject' })
        ;(wrapper.vm as any).componentFilter = 'library-a'
        await flushPromises()

        projectHeaderState.bulkSyncHandler.value?.()
        await flushPromises()
        await wrapper.vm.$nextTick()

        expect(projectHeaderState.incompleteCount.value).toBe(1)
        expect(drainTaskVulnGroupDetails).toHaveBeenCalledWith(
            'task-1',
            expect.objectContaining({
                component: 'library-a',
                lifecycle: ['INCOMPLETE'],
                sort: 'id',
                order: 'asc',
            }),
            { limit: 1000 },
        )
        expect(getTaskVulnGroup).not.toHaveBeenCalledWith('task-1', 'CVE-INCOMPLETE')
        expect(wrapper.get('[data-testid="bulk-resolve-modal"]').text()).toContain('CVE-INCOMPLETE')
    })

    it('does not fetch if route param name is undefined', async () => {
        vi.mocked(useRoute).mockReturnValue({
            params: {}, query: {}
        } as any)

        await mountProjectView({ routeName: undefined })
        expect(getGroupedVulns).not.toHaveBeenCalled()
    })

    it('handles _all_ project name context', async () => {
        vi.mocked(useRoute).mockReturnValue({
            params: { name: '_all_' }, query: {}
        } as any)

        const wrapper = await mountProjectView({ routeName: '_all_', flush: false })

        expect(wrapper.text()).toContain('Starting global search')
        // "All Projects" text is rendered in App.vue header, not inside ProjectView

        await flushPromises()

        expect(getGroupedVulns).toHaveBeenCalledWith('', undefined, expect.any(Function), {
            responseMode: 'summary',
            deferResult: true,
            skipResultDownload: true,
            useEventStream: true,
            taskWindowLimit: 250,
            onTaskId: expect.any(Function),
            onPartialResultAvailable: expect.any(Function),
            onTaskCompleted: expect.any(Function),
        })
    })
})
