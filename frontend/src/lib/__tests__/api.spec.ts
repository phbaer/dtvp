import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
    analysisQueueCancel,
    analysisQueueCancelQueued,
    analysisQueueClear,
    analysisQueueGet,
    analysisQueueList,
    analysisQueueSubmit,
    analysisQueueSubmitFollowUp,
    drainTaskVulnGroupDetails,
    drainTaskVulnGroups,
    getProjects,
    getGroupedVulns,
    getTaskStatus,
    getTaskStatistics,
    getTaskVulnGroup,
    getTaskVulnGroupDetailsWindow,
    getTaskVulnGroups,
    updateAssessment,
    login,
    logout,
    checkSession,
    getVersion,
    getDependencyChains,
    getChangelog,
    getCacheStatus,
    getTMRescoreContext,
    getTMRescoreProjectState,
    getTMRescoreSyntheticSbomDownloadUrl,
    getTMRescoreSyntheticSbomSummary,
    applyProjectArchiveImport,
    applyBulkWorkflow,
    buildBulkWorkflowDocument,
    bulkWorkflowFilters,
    applyAssessmentRestore,
    applyRescoreRuleSync,
    getProjectArchiveSnapshotDownloadUrl,
    getBulkWorkflowSummary,
    getProjectArchiveTask,
    getProjectArchiveTaskDownloadUrl,
    listProjectArchiveSnapshots,
    previewAssessmentRestore,
    previewBulkWorkflow,
    previewRescoreRuleSync,
    resumeTMRescoreAnalysis,
    runTMRescoreAnalysis,
    startProjectArchiveExport,
    streamProjectArchiveTaskEvents,
    uploadProjectArchiveImport,
    waitForProjectArchiveTask,
} from '../api'

const mocks = vi.hoisted(() => ({
    delete: vi.fn(),
    get: vi.fn(),
    post: vi.fn(),
    createConfig: undefined as any,
}))

vi.mock('axios', () => {
    return {
        default: {
            create: vi.fn((config) => {
                mocks.createConfig = config
                return {
                    delete: mocks.delete,
                    get: mocks.get,
                    post: mocks.post,
                    interceptors: {
                        request: { use: vi.fn(), eject: vi.fn() },
                        response: { use: vi.fn(), eject: vi.fn() }
                    }
                }
            }),
            get: mocks.get,
            post: mocks.post,
        }
    }
})

describe('api.ts', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.useRealTimers()
    })

    afterEach(() => {
        vi.useRealTimers()
        vi.unstubAllGlobals()
        vi.restoreAllMocks()
    })

    it.each([
        ['restore preview', previewAssessmentRestore, '/assessments/restore-preview'],
        ['restore apply', applyAssessmentRestore, '/assessments/restore-apply'],
        ['rule-sync preview', previewRescoreRuleSync, '/assessments/rescore-rule-preview'],
        ['rule-sync apply', applyRescoreRuleSync, '/assessments/rescore-rule-apply'],
    ] as const)('preserves an empty bulk selection for %s', async (_label, request, endpoint) => {
        mocks.post.mockResolvedValue({ data: {} })

        await request('task-1', [])

        expect(mocks.post).toHaveBeenCalledWith(endpoint, {
            task_id: 'task-1',
            group_ids: [],
        })
    })

    it('serializes array query params as repeated keys for FastAPI list filters', () => {
        expect(mocks.createConfig).toEqual(expect.objectContaining({
            paramsSerializer: { indexes: null },
        }))
    })

    it('removes list-window controls from bulk workflow filters', () => {
        expect(bulkWorkflowFilters({
            q: 'openssl',
            lifecycle: ['INCOMPLETE'],
            sort: 'id',
            order: 'asc',
            offset: 10,
            cursor: 'next',
            limit: 25,
        })).toEqual({ q: 'openssl', lifecycle: ['INCOMPLETE'] })
    })

    it('starts and polls long-running bulk workflow operations', async () => {
        mocks.post
            .mockResolvedValueOnce({ data: {} })
            .mockResolvedValueOnce({ data: { task_id: 'operation-preview' } })
            .mockResolvedValueOnce({ data: { task_id: 'operation-apply' } })
            .mockResolvedValueOnce({ data: { task_id: 'operation-document' } })
        mocks.get.mockImplementation(async (url: string) => {
            const results: Record<string, unknown> = {
                '/bulk-workflows/tasks/operation-preview': { preview_token: 'preview-result' },
                '/bulk-workflows/tasks/operation-apply': { summary: { succeeded: 1 } },
                '/bulk-workflows/tasks/operation-document': '# Ticket drafts\n',
            }
            return {
                data: {
                    id: url.split('/').at(-1),
                    status: 'completed',
                    message: 'Done',
                    progress: 100,
                    result: results[url],
                },
            }
        })
        const filters = { q: 'openssl', component: 'runtime' }

        await getBulkWorkflowSummary('task-1', filters)
        await previewBulkWorkflow('incomplete-sync', 'task-1', filters)
        await applyBulkWorkflow('incomplete-sync', 'task-1', filters, ['CVE-1'], 'token-1')
        await buildBulkWorkflowDocument('automatic-assessments', 'task-1', filters, ['CVE-1'], 'token-2')

        expect(mocks.post).toHaveBeenNthCalledWith(1, '/bulk-workflows/summary', {
            task_id: 'task-1', filters,
        })
        expect(mocks.post).toHaveBeenNthCalledWith(2, '/bulk-workflows/incomplete-sync/preview-task', {
            task_id: 'task-1', filters,
        })
        expect(mocks.get).toHaveBeenNthCalledWith(1, '/bulk-workflows/tasks/operation-preview')
        expect(mocks.post).toHaveBeenNthCalledWith(3, '/bulk-workflows/incomplete-sync/apply-task', {
            task_id: 'task-1',
            filters,
            group_ids: ['CVE-1'],
            preview_token: 'token-1',
        })
        expect(mocks.get).toHaveBeenNthCalledWith(2, '/bulk-workflows/tasks/operation-apply')
        expect(mocks.post).toHaveBeenNthCalledWith(4, '/bulk-workflows/automatic-assessments/document-task', {
            task_id: 'task-1',
            filters,
            group_ids: ['CVE-1'],
            preview_token: 'token-2',
        })
        expect(mocks.get).toHaveBeenNthCalledWith(3, '/bulk-workflows/tasks/operation-document')
    })

    it('getProjects calls /projects', async () => {
        const mockData = [{ name: 'P1' }]
        mocks.get.mockResolvedValue({ data: mockData })

        const result = await getProjects('query')

        expect(mocks.get).toHaveBeenCalledWith('/projects', { params: { name: 'query' } })
        expect(result).toEqual(mockData)
    })

    it('getVersion calls /version', async () => {
        const mockData = { version: '1.0.0', build: 'abc' }
        mocks.get.mockResolvedValue({ data: mockData })

        const result = await getVersion()

        expect(mocks.get).toHaveBeenCalledWith('/version')
        expect(result).toEqual(mockData)
    })

    it('getChangelog calls /changelog', async () => {
        const mockData = { content: '# Changelog' }
        mocks.get.mockResolvedValue({ data: mockData })

        const result = await getChangelog()

        expect(mocks.get).toHaveBeenCalledWith('/changelog')
        expect(result).toEqual(mockData)
    })

    it('getCacheStatus calls /cache-status', async () => {
        const mockData = { fully_cached: true, last_refreshed_at: '2026-04-09T12:00:00Z' }
        mocks.get.mockResolvedValue({ data: mockData })

        const result = await getCacheStatus()

        expect(mocks.get).toHaveBeenCalledWith('/cache-status')
        expect(result).toEqual(mockData)
    })

    it('project archive helpers call the archive endpoints', async () => {
        mocks.post.mockResolvedValueOnce({ data: { task_id: 'export-task' } })
        mocks.get
            .mockResolvedValueOnce({ data: { id: 'export-task', status: 'completed' } })
            .mockResolvedValueOnce({ data: [{ filename: 'archive.dtvp-project-archive.zip' }] })
        const file = new File(['zip'], 'archive.zip', { type: 'application/zip' })

        await expect(startProjectArchiveExport({ project_name: 'ArchiveApp', refresh: true })).resolves.toEqual({ task_id: 'export-task' })
        await expect(getProjectArchiveTask('export-task')).resolves.toEqual({ id: 'export-task', status: 'completed' })
        await expect(listProjectArchiveSnapshots()).resolves.toEqual([{ filename: 'archive.dtvp-project-archive.zip' }])

        mocks.post.mockResolvedValueOnce({ data: { task_id: 'import-task' } })
        await expect(uploadProjectArchiveImport(file)).resolves.toEqual({ task_id: 'import-task' })
        expect(mocks.post).toHaveBeenCalledWith('/project-archives/imports', expect.any(FormData))

        mocks.post.mockResolvedValueOnce({ data: { task_id: 'import-task' } })
        await expect(applyProjectArchiveImport('import-task', 'update')).resolves.toEqual({ task_id: 'import-task' })
        expect(mocks.post).toHaveBeenCalledWith('/project-archives/imports/import-task/apply', { mode: 'update' })

        expect(getProjectArchiveTaskDownloadUrl('export-task')).toContain('/project-archives/tasks/export-task/download')
        expect(getProjectArchiveSnapshotDownloadUrl('archive.dtvp-project-archive.zip')).toContain('/project-archives/snapshots/archive.dtvp-project-archive.zip/download')
    })

    it('waitForProjectArchiveTask polls archive task progress by default', async () => {
        const running = { id: 'archive-task', status: 'running', progress: 25, message: 'Running export' }
        const completed = { id: 'archive-task', status: 'completed', progress: 100, message: 'Archive ready' }
        const onProgress = vi.fn()
        mocks.get
            .mockResolvedValueOnce({ data: running })
            .mockResolvedValueOnce({ data: completed })

        vi.useFakeTimers()
        const promise = waitForProjectArchiveTask('archive-task', onProgress, { pollIntervalMs: 250 })

        await vi.advanceTimersByTimeAsync(0)
        await vi.advanceTimersByTimeAsync(250)
        await expect(promise).resolves.toEqual(completed)

        expect(mocks.get).toHaveBeenCalledWith('/project-archives/tasks/archive-task')
        expect(onProgress).toHaveBeenCalledWith(running)
        expect(onProgress).toHaveBeenCalledWith(completed)
        vi.useRealTimers()
    })

    it('streams newline-delimited archive status updates across chunk boundaries', async () => {
        const encoder = new TextEncoder()
        const read = vi.fn()
            .mockResolvedValueOnce({
                done: false,
                value: encoder.encode('{"id":"archive-task","status":"running","progress":25}\n{"id":"archive-task",'),
            })
            .mockResolvedValueOnce({
                done: true,
                value: encoder.encode('"status":"completed","progress":100}'),
            })
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            body: { getReader: () => ({ read }) },
        })
        vi.stubGlobal('fetch', fetchMock)
        const onStatus = vi.fn()

        await streamProjectArchiveTaskEvents('archive/task', onStatus)

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/project-archives/tasks/archive%2Ftask/events'),
            { credentials: 'include' },
        )
        expect(onStatus).toHaveBeenNthCalledWith(1, expect.objectContaining({ status: 'running', progress: 25 }))
        expect(onStatus).toHaveBeenNthCalledWith(2, expect.objectContaining({ status: 'completed', progress: 100 }))
    })

    it.each([
        ['fetch is unavailable', undefined],
        ['the server rejects the stream', vi.fn().mockResolvedValue({ ok: false, body: null })],
    ])('rejects archive event streaming when %s', async (_label, fetchImplementation) => {
        vi.stubGlobal('fetch', fetchImplementation)

        await expect(streamProjectArchiveTaskEvents('archive-task', vi.fn()))
            .rejects.toThrow('Archive task event stream unavailable')
    })

    it('falls back to polling when the archive event stream fails before a terminal status', async () => {
        vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('stream offline')))
        const warning = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
        const completed = { id: 'archive-task', status: 'completed', progress: 100, message: 'Ready' }
        mocks.get.mockResolvedValue({ data: completed })

        await expect(waitForProjectArchiveTask('archive-task', undefined, { useEventStream: true }))
            .resolves.toEqual(completed)

        expect(warning).toHaveBeenCalledWith(
            'Archive task event stream failed; falling back to polling.',
            expect.any(Error),
        )
        expect(mocks.get).toHaveBeenCalledWith('/project-archives/tasks/archive-task')
    })

    it('does not hide a failed terminal status received from the archive event stream', async () => {
        const encoder = new TextEncoder()
        const read = vi.fn().mockResolvedValue({
            done: false,
            value: encoder.encode('{"id":"archive-task","status":"failed","error":"Invalid archive"}\n'),
        })
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            body: { getReader: () => ({ read }) },
        }))

        await expect(waitForProjectArchiveTask('archive-task', undefined, { useEventStream: true }))
            .rejects.toThrow('Invalid archive')
        expect(mocks.get).not.toHaveBeenCalled()
    })

    it('rejects archive polling when the task disappears', async () => {
        mocks.get.mockResolvedValue({
            data: { id: 'archive-task', status: 'not_found', progress: 0, message: 'Missing' },
        })

        await expect(waitForProjectArchiveTask('archive-task'))
            .rejects.toThrow('Archive task not found')
    })

    it('forwards analysis queue commands and URL-encodes queue identifiers', async () => {
        const submitted = { queue_id: 'queue/1', status: 'queued' }
        const followUp = { queue_id: 'queue/2', status: 'queued' }
        mocks.post
            .mockResolvedValueOnce({ data: submitted })
            .mockResolvedValueOnce({ data: followUp })
            .mockResolvedValueOnce({ data: { status: 'cleared', removed: 2 } })
            .mockResolvedValueOnce({ data: { status: 'cleared', removed: 1 } })
            .mockResolvedValueOnce({ data: { status: 'cancelled', cancelled: 3 } })
        mocks.get
            .mockResolvedValueOnce({ data: [submitted] })
            .mockResolvedValueOnce({ data: submitted })
        mocks.delete.mockResolvedValue({ data: { status: 'cancelled' } })

        await expect(analysisQueueSubmit({ vuln_id: 'CVE-1', component_name: 'library' }))
            .resolves.toEqual(submitted)
        await expect(analysisQueueSubmitFollowUp({ parent_run_id: 'run-1', question: 'Why?' }))
            .resolves.toEqual(followUp)
        await expect(analysisQueueList()).resolves.toEqual([submitted])
        await expect(analysisQueueGet('queue/1')).resolves.toEqual(submitted)
        await expect(analysisQueueCancel('queue/1')).resolves.toEqual({ status: 'cancelled' })
        await expect(analysisQueueClear(['failed', 'cancelled'])).resolves.toEqual({ status: 'cleared', removed: 2 })
        await expect(analysisQueueClear()).resolves.toEqual({ status: 'cleared', removed: 1 })
        await expect(analysisQueueCancelQueued()).resolves.toEqual({ status: 'cancelled', cancelled: 3 })

        expect(mocks.get).toHaveBeenLastCalledWith('/analysis-queue/queue%2F1')
        expect(mocks.delete).toHaveBeenCalledWith('/analysis-queue/queue%2F1')
        expect(mocks.post).toHaveBeenCalledWith('/analysis-queue/clear', { statuses: ['failed', 'cancelled'] })
        expect(mocks.post).toHaveBeenCalledWith('/analysis-queue/clear', {})
    })

    it('propagates analysis queue API failures to the calling store', async () => {
        const failure = new Error('queue unavailable')
        mocks.get.mockRejectedValue(failure)

        await expect(analysisQueueGet('queue-1')).rejects.toBe(failure)
        await expect(analysisQueueList()).rejects.toBe(failure)
    })

    it('getGroupedVulns starts task and polls for result', async () => {
        const mockTaskStart = { task_id: 'task-123' }
        const mockTaskRunning = { status: 'running', progress: 50, message: 'Loading...' }
        const mockTaskCompleted = { status: 'completed', result: [{ id: '1' }] }

        mocks.post.mockResolvedValue({ data: mockTaskStart })

        // Mock sequential GET calls: first running, then completed
        mocks.get
            .mockResolvedValueOnce({ data: mockTaskRunning })
            .mockResolvedValueOnce({ data: mockTaskCompleted })

        vi.useFakeTimers()

        const promise = getGroupedVulns('Test')

        // Fast-forward time to trigger interval
        await vi.advanceTimersByTimeAsync(1100)
        await vi.advanceTimersByTimeAsync(1100)

        const result = await promise

        expect(mocks.post).toHaveBeenCalledWith('/tasks/group-vulns', null, { params: { name: 'Test', response_mode: 'full' } })
        expect(mocks.get).toHaveBeenCalledWith('/tasks/task-123')
        expect(result).toEqual(mockTaskCompleted.result)

        vi.useRealTimers()
    })

    it('getGroupedVulns can request summary mode and expose the task id', async () => {
        const mockTaskStart = { task_id: 'task-summary' }
        const mockTaskCompleted = { status: 'completed', result: [{ id: 'CVE-1', list_metadata: { lifecycle: 'OPEN' } }] }
        const onTaskId = vi.fn()

        mocks.post.mockResolvedValue({ data: mockTaskStart })
        mocks.get.mockResolvedValueOnce({ data: mockTaskCompleted })

        vi.useFakeTimers()
        const promise = getGroupedVulns('Test', 'CVE-1', undefined, {
            responseMode: 'summary',
            onTaskId,
        })

        await vi.advanceTimersByTimeAsync(1100)
        const result = await promise

        expect(mocks.post).toHaveBeenCalledWith('/tasks/group-vulns', null, {
            params: { name: 'Test', response_mode: 'summary', cve: 'CVE-1' },
        })
        expect(onTaskId).toHaveBeenCalledWith('task-summary')
        expect(result).toEqual(mockTaskCompleted.result)
        vi.useRealTimers()
    })

    it('getGroupedVulns reports partial result availability while polling', async () => {
        const mockTaskStart = { task_id: 'task-partial' }
        const mockTaskRunning = {
            status: 'running',
            progress: 35,
            message: 'Processed version 1',
            partial_result_available: true,
            partial_versions_completed: 1,
            partial_total_versions: 3,
        }
        const mockTaskCompleted = { status: 'completed', result: [{ id: 'CVE-1' }] }
        const onPartialResultAvailable = vi.fn()
        const onTaskCompleted = vi.fn()

        mocks.post.mockResolvedValue({ data: mockTaskStart })
        mocks.get
            .mockResolvedValueOnce({ data: mockTaskRunning })
            .mockResolvedValueOnce({ data: mockTaskCompleted })

        vi.useFakeTimers()
        const promise = getGroupedVulns('Test', undefined, undefined, {
            responseMode: 'summary',
            onPartialResultAvailable,
            onTaskCompleted,
        })

        await vi.advanceTimersByTimeAsync(1100)
        await vi.advanceTimersByTimeAsync(1100)
        await promise

        expect(onPartialResultAvailable).toHaveBeenCalledWith('task-partial', mockTaskRunning)
        expect(onTaskCompleted).toHaveBeenCalledWith('task-partial', mockTaskCompleted)
        vi.useRealTimers()
    })

    it('getGroupedVulns can consume the task event stream', async () => {
        const mockTaskStart = { task_id: 'task-events' }
        const runningEvent = {
            status: 'running',
            progress: 25,
            message: 'Processed version 1',
            partial_result_available: true,
        }
        const completedEvent = {
            status: 'completed',
            progress: 100,
            message: 'Done',
            result: [{ id: 'CVE-1' }],
        }
        const encoder = new TextEncoder()
        const body = new ReadableStream({
            start(controller) {
                controller.enqueue(encoder.encode(`${JSON.stringify(runningEvent)}\n`))
                controller.enqueue(encoder.encode(`${JSON.stringify(completedEvent)}\n`))
                controller.close()
            },
        })
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            body,
        })
        vi.stubGlobal('fetch', fetchMock)
        const onPartialResultAvailable = vi.fn()
        const onTaskCompleted = vi.fn()
        const onProgress = vi.fn()

        mocks.post.mockResolvedValue({ data: mockTaskStart })

        const result = await getGroupedVulns('Test', undefined, onProgress, {
            useEventStream: true,
            onPartialResultAvailable,
            onTaskCompleted,
        })

        expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/api/tasks/task-events/events'), {
            credentials: 'include',
        })
        expect(mocks.get).not.toHaveBeenCalled()
        expect(onPartialResultAvailable).toHaveBeenCalledWith('task-events', runningEvent)
        expect(onTaskCompleted).toHaveBeenCalledWith('task-events', completedEvent)
        expect(onProgress).toHaveBeenCalledWith('Done', 100, undefined)
        expect(result).toEqual([{ id: 'CVE-1' }])
        vi.unstubAllGlobals()
    })

    it('getGroupedVulns can defer result download and drain task windows', async () => {
        const mockTaskStart = { task_id: 'task-windowed' }
        const mockTaskRunning = { status: 'running', progress: 50, message: 'Loading...', log: ['Loading...'] }
        const mockTaskCompleted = { status: 'completed', progress: 100, message: 'Done', log: ['Done'], result_mode: 'summary' }
        const firstWindow = {
            items: [{ id: 'CVE-1' }],
            total: 2,
            filtered: 2,
            offset: 0,
            limit: 1,
            next_cursor: 'cursor-1',
            sort: 'id',
            order: 'asc',
        }
        const secondWindow = {
            items: [{ id: 'CVE-2' }],
            total: 2,
            filtered: 2,
            offset: 1,
            limit: 1,
            next_cursor: null,
            sort: 'id',
            order: 'asc',
        }

        mocks.post.mockResolvedValue({ data: mockTaskStart })
        mocks.get
            .mockResolvedValueOnce({ data: mockTaskRunning })
            .mockResolvedValueOnce({ data: mockTaskCompleted })
            .mockResolvedValueOnce({ data: firstWindow })
            .mockResolvedValueOnce({ data: secondWindow })

        vi.useFakeTimers()
        const onProgress = vi.fn()
        const promise = getGroupedVulns('Test', undefined, onProgress, {
            responseMode: 'summary',
            deferResult: true,
            taskWindowLimit: 1,
        })

        await vi.advanceTimersByTimeAsync(1100)
        await vi.advanceTimersByTimeAsync(1100)
        const result = await promise

        expect(mocks.post).toHaveBeenCalledWith('/tasks/group-vulns', null, {
            params: { name: 'Test', response_mode: 'summary' },
        })
        expect(mocks.get).toHaveBeenNthCalledWith(1, '/tasks/task-windowed', {
            params: { include_result: false },
        })
        expect(mocks.get).toHaveBeenNthCalledWith(2, '/tasks/task-windowed', {
            params: { include_result: false },
        })
        expect(mocks.get).toHaveBeenNthCalledWith(3, '/tasks/task-windowed/groups', {
            params: { offset: 0, limit: 1, sort: 'id', order: 'asc' },
        })
        expect(mocks.get).toHaveBeenNthCalledWith(4, '/tasks/task-windowed/groups', {
            params: { limit: 1, sort: 'id', order: 'asc', cursor: 'cursor-1' },
        })
        expect(result).toEqual([{ id: 'CVE-1' }, { id: 'CVE-2' }])
        expect(onProgress).toHaveBeenCalledWith('Loading vulnerability list (2/2)...', 100, ['Done'])
        vi.useRealTimers()
    })

    it('getGroupedVulns can skip completed result download for caller-managed windows', async () => {
        const mockTaskStart = { task_id: 'task-window-owner' }
        const mockTaskCompleted = {
            status: 'completed',
            progress: 100,
            message: 'Done',
            log: ['Done'],
            result_mode: 'summary',
        }

        mocks.post.mockResolvedValue({ data: mockTaskStart })
        mocks.get.mockResolvedValueOnce({ data: mockTaskCompleted })

        vi.useFakeTimers()
        const resultPromise = getGroupedVulns('Test', undefined, undefined, {
            responseMode: 'summary',
            deferResult: true,
            skipResultDownload: true,
        })

        await vi.advanceTimersByTimeAsync(1100)
        const result = await resultPromise

        expect(mocks.get).toHaveBeenCalledTimes(1)
        expect(mocks.get).toHaveBeenCalledWith('/tasks/task-window-owner', {
            params: { include_result: false },
        })
        expect(result).toEqual([])
        vi.useRealTimers()
    })

    it('getTaskStatus can omit completed task results', async () => {
        const mockData = {
            status: 'completed',
            progress: 100,
            message: 'Done',
            result_mode: 'summary',
        }
        mocks.get.mockResolvedValue({ data: mockData })

        const result = await getTaskStatus('task-summary', { includeResult: false })

        expect(mocks.get).toHaveBeenCalledWith('/tasks/task-summary', {
            params: { include_result: false },
        })
        expect(result).toEqual(mockData)
    })

    it('getTaskStatistics fetches statistics for a completed task', async () => {
        const mockStats = {
            severity_counts: { HIGH: 1 },
            state_counts: { NOT_SET: 1 },
            total_unique: 1,
            total_findings: 1,
            affected_projects_count: 1,
            version_counts: { '1.0.0': 1 },
        }
        mocks.get.mockResolvedValue({ data: mockStats })

        const result = await getTaskStatistics('task 1')

        expect(mocks.get).toHaveBeenCalledWith('/tasks/task%201/statistics')
        expect(result).toEqual(mockStats)
    })

    it('getTaskVulnGroup fetches a single full group from a task', async () => {
        const mockData = { id: 'GHSA/with/slash' }
        mocks.get.mockResolvedValue({ data: mockData })

        const result = await getTaskVulnGroup('task 1', 'GHSA/with/slash')

        expect(mocks.get).toHaveBeenCalledWith('/tasks/task%201/groups/GHSA%2Fwith%2Fslash')
        expect(result).toEqual(mockData)
    })

    it('getTaskVulnGroups fetches a filtered task result window', async () => {
        const mockData = {
            items: [{ id: 'CVE-1' }],
            total: 10,
            filtered: 3,
            counts: {
                all: {
                    total: 10,
                    lifecycle: { OPEN: 6, ASSESSED: 4 },
                    analysis: { NOT_SET: 5, IN_TRIAGE: 2 },
                    dependency_relationship: { direct: 7, transitive: 2, unknown: 1 },
                    cvss_version_mismatch: 1,
                    versions: { '2.0.0': 3 },
                    tags: { TeamA: 2 },
                    assignees: { alice: 1 },
                    components: { 'library-a': 2 },
                },
                filtered: {
                    total: 3,
                    lifecycle: { OPEN: 3 },
                    analysis: { NOT_SET: 2, IN_TRIAGE: 1 },
                    dependency_relationship: { direct: 3, transitive: 0, unknown: 0 },
                    cvss_version_mismatch: 1,
                    versions: { '2.0.0': 3 },
                    tags: { TeamA: 2 },
                    assignees: { alice: 1 },
                    components: { 'library-a': 2 },
                },
            },
            offset: 2,
            limit: 1,
            sort: 'id',
            order: 'asc',
        }
        mocks.get.mockResolvedValue({ data: mockData })

        const result = await getTaskVulnGroups('task 1', {
            lifecycle: ['OPEN'],
            dependency: ['DIRECT', 'TRANSITIVE'],
            versions: ['2.0.0'],
            cvss_mismatch: true,
            tmrescore: ['WITH_PROPOSAL'],
            tmrescore_proposal_ids: ['CVE-1', 'GHSA-1'],
            sort: 'id',
            order: 'asc',
            offset: 2,
            cursor: 'cursor-2',
            limit: 1,
        })

        expect(mocks.get).toHaveBeenCalledWith('/tasks/task%201/groups', {
            params: {
                lifecycle: ['OPEN'],
                dependency: ['DIRECT', 'TRANSITIVE'],
                versions: ['2.0.0'],
                cvss_mismatch: true,
                tmrescore: ['WITH_PROPOSAL'],
                tmrescore_proposal_ids: ['CVE-1', 'GHSA-1'],
                sort: 'id',
                order: 'asc',
                offset: 2,
                cursor: 'cursor-2',
                limit: 1,
            },
        })
        expect(result).toEqual(mockData)
    })

    it('getTaskVulnGroupDetailsWindow fetches a filtered full-detail task result window', async () => {
        const mockData = {
            items: [{ id: 'CVE-1', affected_versions: [{ components: [{ analysis_details: 'full notes' }] }] }],
            total: 10,
            filtered: 1,
            offset: 0,
            limit: 1,
            sort: 'id',
            order: 'asc',
            result_mode: 'full',
            source_result_mode: 'summary',
        }
        mocks.get.mockResolvedValue({ data: mockData })

        const result = await getTaskVulnGroupDetailsWindow('task 1', {
            lifecycle: ['INCOMPLETE'],
            component: 'library-a',
            sort: 'id',
            order: 'asc',
            offset: 0,
            limit: 1,
        })

        expect(mocks.get).toHaveBeenCalledWith('/tasks/task%201/group-details', {
            params: {
                lifecycle: ['INCOMPLETE'],
                component: 'library-a',
                sort: 'id',
                order: 'asc',
                offset: 0,
                limit: 1,
            },
        })
        expect(result).toEqual(mockData)
    })

    it('drainTaskVulnGroups drains filtered windows with stable paging', async () => {
        const firstWindow = {
            items: [{ id: 'CVE-1' }],
            total: 5,
            filtered: 2,
            offset: 0,
            limit: 1,
            next_cursor: 'cursor-1',
            sort: 'severity',
            order: 'desc',
        }
        const secondWindow = {
            items: [{ id: 'CVE-2' }],
            total: 5,
            filtered: 2,
            offset: 1,
            limit: 1,
            next_cursor: null,
            sort: 'severity',
            order: 'desc',
        }
        const progress = vi.fn()

        mocks.get
            .mockResolvedValueOnce({ data: firstWindow })
            .mockResolvedValueOnce({ data: secondWindow })

        const result = await drainTaskVulnGroups('task 1', {
            lifecycle: ['INCOMPLETE'],
            sort: 'severity',
            order: 'desc',
        }, {
            limit: 1,
            log: ['Ready'],
            onProgress: progress,
        })

        expect(mocks.get).toHaveBeenNthCalledWith(1, '/tasks/task%201/groups', {
            params: {
                lifecycle: ['INCOMPLETE'],
                offset: 0,
                limit: 1,
                sort: 'severity',
                order: 'desc',
            },
        })
        expect(mocks.get).toHaveBeenNthCalledWith(2, '/tasks/task%201/groups', {
            params: {
                lifecycle: ['INCOMPLETE'],
                limit: 1,
                sort: 'severity',
                order: 'desc',
                cursor: 'cursor-1',
            },
        })
        expect(progress).toHaveBeenLastCalledWith(2, 2, ['Ready'])
        expect(result).toEqual([{ id: 'CVE-1' }, { id: 'CVE-2' }])
    })

    it('drainTaskVulnGroupDetails drains full-detail windows with stable paging', async () => {
        const firstWindow = {
            items: [{ id: 'CVE-1', affected_versions: [{ components: [{ analysis_details: 'one' }] }] }],
            total: 5,
            filtered: 2,
            offset: 0,
            limit: 1,
            next_cursor: 'cursor-1',
            sort: 'id',
            order: 'asc',
            result_mode: 'full',
        }
        const secondWindow = {
            items: [{ id: 'CVE-2', affected_versions: [{ components: [{ analysis_details: 'two' }] }] }],
            total: 5,
            filtered: 2,
            offset: 1,
            limit: 1,
            next_cursor: null,
            sort: 'id',
            order: 'asc',
            result_mode: 'full',
        }
        const progress = vi.fn()

        mocks.get
            .mockResolvedValueOnce({ data: firstWindow })
            .mockResolvedValueOnce({ data: secondWindow })

        const result = await drainTaskVulnGroupDetails('task 1', {
            lifecycle: ['INCOMPLETE'],
        }, {
            limit: 1,
            log: ['Ready'],
            onProgress: progress,
        })

        expect(mocks.get).toHaveBeenNthCalledWith(1, '/tasks/task%201/group-details', {
            params: {
                lifecycle: ['INCOMPLETE'],
                offset: 0,
                limit: 1,
                sort: 'id',
                order: 'asc',
            },
        })
        expect(mocks.get).toHaveBeenNthCalledWith(2, '/tasks/task%201/group-details', {
            params: {
                lifecycle: ['INCOMPLETE'],
                limit: 1,
                sort: 'id',
                order: 'asc',
                cursor: 'cursor-1',
            },
        })
        expect(progress).toHaveBeenLastCalledWith(2, 2, ['Ready'])
        expect(result).toEqual([...firstWindow.items, ...secondWindow.items])
    })

    it('getGroupedVulns reports progress', async () => {
        const mockTaskStart = { task_id: 'task-123' }
        const mockTaskRunning = { status: 'running', progress: 50, message: 'Step 1', log: ['Starting...', 'Step 1'] }
        const mockTaskCompleted = { status: 'completed', result: [] }

        mocks.post.mockResolvedValue({ data: mockTaskStart })
        mocks.get
            .mockResolvedValueOnce({ data: mockTaskRunning })
            .mockResolvedValueOnce({ data: mockTaskCompleted })

        vi.useFakeTimers()
        const onProgress = vi.fn()
        const promise = getGroupedVulns('Test', undefined, onProgress)

        await vi.advanceTimersByTimeAsync(1100)
        await vi.advanceTimersByTimeAsync(1100)

        await promise
        expect(onProgress).toHaveBeenCalledWith('Step 1', 50, ['Starting...', 'Step 1'])
        vi.useRealTimers()
    })

    it('getGroupedVulns throws error on task failure', async () => {
        const mockTaskStart = { task_id: 'task-err' }
        const mockTaskFailed = { status: 'failed', message: 'Task Failed', progress: 0 }

        mocks.post.mockResolvedValue({ data: mockTaskStart })
        mocks.get.mockResolvedValueOnce({ data: mockTaskFailed })

        vi.useFakeTimers()
        const promise = getGroupedVulns('Test')

        const assertion = expect(promise).rejects.toThrow('Task Failed')

        await vi.advanceTimersByTimeAsync(1100)

        await assertion
        vi.useRealTimers()
    })

    it('getGroupedVulns throws error on polling network error', async () => {
        const mockTaskStart = { task_id: 'task-net-err' }
        mocks.post.mockResolvedValue({ data: mockTaskStart })
        mocks.get.mockRejectedValue(new Error('Network Error'))

        vi.useFakeTimers()
        const promise = getGroupedVulns('Test')

        const assertion = expect(promise).rejects.toThrow('Network Error')

        await vi.advanceTimersByTimeAsync(1100)

        await assertion
        vi.useRealTimers()
    })

    it('updateAssessment calls /assessment', async () => {
        const payload: any = { status: 'ok' }
        mocks.post.mockResolvedValue({ data: { result: 'ok' } })

        const result = await updateAssessment(payload)

        expect(mocks.post).toHaveBeenCalledWith('/assessment', payload)
        expect(result).toEqual({ result: 'ok' })
    })

    it('login redirects', () => {
        Object.defineProperty(window, 'location', {
            value: { href: '' },
            writable: true
        })

        login()
        expect(window.location.href).toContain('/auth/login')
    })

    it('logout uses a credentialed POST before redirecting', async () => {
        Object.defineProperty(window, 'location', {
            value: { href: '' },
            writable: true
        })
        mocks.post.mockResolvedValue({ status: 200 })

        await logout()

        expect(mocks.post).toHaveBeenCalledWith(
            expect.stringContaining('/auth/logout'),
            undefined,
            { withCredentials: true },
        )
        expect(window.location.href).toContain('/login')
    })

    it('checkSession returns true on success', async () => {
        mocks.get.mockResolvedValue({ status: 200 })

        const result = await checkSession()
        expect(result).toBe(true)
        expect(mocks.get).toHaveBeenCalled()
    })

    it('checkSession returns false on failure', async () => {
        mocks.get.mockRejectedValue(new Error('401'))

        const result = await checkSession()
        expect(result).toBe(false)
    })

    it('getDependencyChains calls correct endpoint', async () => {
        const mockResponse = ['A->B']
        mocks.get.mockResolvedValue({ data: mockResponse })

        const result = await getDependencyChains('p1', 'c1')

        expect(mocks.get).toHaveBeenCalledWith('/project/p1/component/c1/dependency-chains')
        expect(result).toEqual(mockResponse)
    })

    it('getGroupedVulns handles missing result in completed task', async () => {
        const mockTaskStart = { task_id: 'task-123' }
        const mockTaskCompleted = { status: 'completed' } // No result field

        mocks.post.mockResolvedValue({ data: mockTaskStart })
        mocks.get.mockResolvedValueOnce({ data: mockTaskCompleted })

        vi.useFakeTimers()
        const promise = getGroupedVulns('Test')
        await vi.advanceTimersByTimeAsync(1100)
        const result = await promise
        expect(result).toEqual([])
        vi.useRealTimers()
    })

    it('getTMRescoreContext calls the project context endpoint', async () => {
        const mockData = { enabled: true, latest_version: '1.10.0' }
        mocks.get.mockResolvedValue({ data: mockData })

        const result = await getTMRescoreContext('Example App')

        expect(mocks.get).toHaveBeenCalledWith('/projects/Example%20App/tmrescore/context')
        expect(result).toEqual(mockData)
    })

    it('runTMRescoreAnalysis posts multipart form data', async () => {
        mocks.post.mockResolvedValue({ data: {
            session_id: 'session-1',
            status: 'completed',
            total_cves: 2,
            rescored_count: 1,
            avg_score_reduction: 0.4,
            elapsed_seconds: 1.2,
            scope: 'merged_versions',
            recommended_scope: 'merged_versions',
            latest_version: '1.0.0',
            analyzed_versions: ['1.0.0'],
            sbom_component_count: 3,
            sbom_vulnerability_count: 2,
            strategy_note: 'Merged multi-version analysis keeps findings attached.',
            download_urls: {
                json: '/api/tmrescore/sessions/session-1/results/json',
                vex: '/api/tmrescore/sessions/session-1/results/vex',
            },
        } })

        const result = await runTMRescoreAnalysis('Example App', {
            scope: 'merged_versions',
            threatmodel: new File(['tm7'], 'model.tm7', { type: 'application/octet-stream' }),
            whatIf: true,
            enrich: true,
        })

        expect(mocks.post).toHaveBeenCalledTimes(1)
        expect(mocks.post.mock.calls[0]?.[0]).toBe('/projects/Example%20App/tmrescore/analyze')
        const formData = mocks.post.mock.calls[0]?.[1] as FormData
        expect(formData).toBeInstanceOf(FormData)
        expect(formData.get('enrich')).toBe('true')
        expect(formData.has('ollama_model')).toBe(false)
        expect(result.session_id).toBe('session-1')
        expect(result.status).toBe('completed')
    })

    it('getTMRescoreSyntheticSbomDownloadUrl builds an API download URL', () => {
        const url = getTMRescoreSyntheticSbomDownloadUrl('Example App', 'merged_versions')

        expect(url).toContain('/api/projects/Example%20App/tmrescore/sbom?scope=merged_versions')
    })

    it('getTMRescoreSyntheticSbomSummary fetches preflight SBOM counts', async () => {
        mocks.get.mockResolvedValue({ data: {
            scope: 'merged_versions',
            latest_version: '1.0.0',
            analyzed_versions: ['0.9.0', '1.0.0'],
            component_count: 5,
            vulnerability_count: 2,
            strategy_note: 'Merged multi-version analysis keeps findings attached.',
        } })

        const result = await getTMRescoreSyntheticSbomSummary('Example App', 'merged_versions')

        expect(mocks.get).toHaveBeenCalledWith('/projects/Example%20App/tmrescore/sbom/summary', {
            params: { scope: 'merged_versions' },
        })
        expect(result.component_count).toBe(5)
        expect(result.vulnerability_count).toBe(2)
    })

    it('getTMRescoreProjectState fetches the cached backend state for a project', async () => {
        mocks.get.mockResolvedValue({ data: {
            session_id: 'session-1',
            status: 'running',
            progress: 64,
            message: 'Rescoring vulnerabilities against the threat model...',
            log: ['Queued tmrescore analysis.'],
            scope: 'merged_versions',
            latest_version: '1.0.0',
            analyzed_versions: ['1.0.0'],
            llm_enrichment: { enabled: false, ollama_model: null },
            result: null,
        } })

        const result = await getTMRescoreProjectState('Example App')

        expect(mocks.get).toHaveBeenCalledWith('/projects/Example%20App/tmrescore/state')
        expect(result.session_id).toBe('session-1')
        expect(result.progress).toBe(64)
    })

    it('resumeTMRescoreAnalysis treats a skeptic gate failure as a terminal result', async () => {
        mocks.get.mockResolvedValue({ data: {
            session_id: 'session-1',
            status: 'skeptic_gate_failed',
            total_cves: 2,
            rescored_count: 1,
            avg_score_reduction: 0.5,
            elapsed_seconds: 3.2,
            scope: 'merged_versions',
            recommended_scope: 'merged_versions',
            latest_version: '1.0.0',
            analyzed_versions: ['1.0.0'],
            sbom_component_count: 3,
            sbom_vulnerability_count: 2,
            strategy_note: 'Merged multi-version analysis keeps findings attached.',
            download_urls: {
                json: '/api/tmrescore/sessions/session-1/results/json',
                vex: '/api/tmrescore/sessions/session-1/results/vex',
            },
        } })

        const onAnalysisProgress = vi.fn()
        const result = await resumeTMRescoreAnalysis('session-1', {
            session_id: 'session-1',
            status: 'skeptic_gate_failed',
            progress: 100,
            message: 'TMRescore analysis completed.',
            log: ['TMRescore analysis completed.'],
            scope: 'merged_versions',
            latest_version: '1.0.0',
            analyzed_versions: ['1.0.0'],
            llm_enrichment: { enabled: false, ollama_model: null },
            result: null,
        }, { onAnalysisProgress })

        expect(onAnalysisProgress).toHaveBeenCalledTimes(1)
        expect(mocks.get).toHaveBeenCalledWith('/tmrescore/sessions/session-1/results')
        expect(result.status).toBe('skeptic_gate_failed')
    })

    it('runTMRescoreAnalysis polls the tmrescore progress endpoint until completion', async () => {
        vi.useFakeTimers()
        mocks.post.mockResolvedValue({ data: {
            session_id: 'session-1',
            status: 'running',
            progress: 10,
            message: 'Queued tmrescore analysis.',
            log: ['Queued tmrescore analysis.'],
        } })
        mocks.get
            .mockResolvedValueOnce({ data: {
                session_id: 'session-1',
                status: 'completed',
                progress: 100,
                message: 'TMRescore analysis completed.',
                log: ['Queued tmrescore analysis.', 'TMRescore analysis completed.'],
                result: null,
            } })
            .mockResolvedValueOnce({ data: {
                session_id: 'session-1',
                status: 'completed',
                total_cves: 2,
                rescored_count: 1,
                avg_score_reduction: 0.5,
                elapsed_seconds: 3.2,
                scope: 'merged_versions',
                recommended_scope: 'merged_versions',
                latest_version: '1.0.0',
                analyzed_versions: ['1.0.0'],
                sbom_component_count: 3,
                sbom_vulnerability_count: 2,
                strategy_note: 'Merged multi-version analysis keeps findings attached.',
                download_urls: {
                    json: '/api/tmrescore/sessions/session-1/results/json',
                    vex: '/api/tmrescore/sessions/session-1/results/vex',
                },
            } })

        const onAnalysisProgress = vi.fn()
        const promise = runTMRescoreAnalysis('Example App', {
            scope: 'merged_versions',
            threatmodel: new File(['tm7'], 'model.tm7', { type: 'application/octet-stream' }),
            countermeasures: new File(['mitigations: []'], 'countermeasures.yaml', { type: 'application/x-yaml' }),
            mitreEnrichment: true,
            offline: false,
        }, {
            onAnalysisProgress,
            pollIntervalMs: 1000,
        })

        await vi.advanceTimersByTimeAsync(1100)
        const result = await promise

        expect(mocks.get).toHaveBeenCalledWith('/tmrescore/sessions/session-1/progress')
        expect(mocks.get).toHaveBeenCalledWith('/tmrescore/sessions/session-1/results')
        const submittedForm = mocks.post.mock.calls[0][1] as FormData
        expect(submittedForm.get('mitre_enrichment')).toBe('true')
        expect(submittedForm.get('offline')).toBe('false')
        expect((submittedForm.get('countermeasures') as File).name).toBe('countermeasures.yaml')
        expect(onAnalysisProgress).toHaveBeenCalledTimes(2)
        expect(result.session_id).toBe('session-1')
        expect(result.status).toBe('completed')
        vi.useRealTimers()
    })
})
