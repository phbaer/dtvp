import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
    getProjects,
    getGroupedVulns,
    updateAssessment,
    login,
    checkSession,
    getVersion,
    getDependencyChains,
    getChangelog,
    getCacheStatus,
    getTMRescoreContext,
    getTMRescoreProjectState,
    getTMRescoreSyntheticSbomDownloadUrl,
    getTMRescoreSyntheticSbomSummary,
    resumeTMRescoreAnalysis,
    runTMRescoreAnalysis,
} from '../api'

const mocks = vi.hoisted(() => ({
    get: vi.fn(),
    post: vi.fn(),
}))

vi.mock('axios', () => {
    return {
        default: {
            create: vi.fn(() => ({
                get: mocks.get,
                post: mocks.post,
                interceptors: {
                    request: { use: vi.fn(), eject: vi.fn() },
                    response: { use: vi.fn(), eject: vi.fn() }
                }
            })),
            get: mocks.get
        }
    }
})

describe('api.ts', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.useRealTimers()
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

        expect(mocks.post).toHaveBeenCalledWith('/tasks/group-vulns', null, { params: { name: 'Test' } })
        expect(mocks.get).toHaveBeenCalledWith('/tasks/task-123')
        expect(result).toEqual(mockTaskCompleted.result)

        vi.useRealTimers()
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
            ollamaModel: 'llama3.1:8b',
        })

        expect(mocks.post).toHaveBeenCalledTimes(1)
        expect(mocks.post.mock.calls[0]?.[0]).toBe('/projects/Example%20App/tmrescore/analyze')
        const formData = mocks.post.mock.calls[0]?.[1] as FormData
        expect(formData).toBeInstanceOf(FormData)
        expect(formData.get('enrich')).toBe('true')
        expect(formData.get('ollama_model')).toBe('llama3.1:8b')
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

    it('resumeTMRescoreAnalysis fetches final results for a completed cached state', async () => {
        mocks.get.mockResolvedValue({ data: {
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
        const result = await resumeTMRescoreAnalysis('session-1', {
            session_id: 'session-1',
            status: 'completed',
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
        expect(result.status).toBe('completed')
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
        }, {
            onAnalysisProgress,
            pollIntervalMs: 1000,
        })

        await vi.advanceTimersByTimeAsync(1100)
        const result = await promise

        expect(mocks.get).toHaveBeenCalledWith('/tmrescore/sessions/session-1/progress')
        expect(mocks.get).toHaveBeenCalledWith('/tmrescore/sessions/session-1/results')
        expect(onAnalysisProgress).toHaveBeenCalledTimes(2)
        expect(result.session_id).toBe('session-1')
        expect(result.status).toBe('completed')
        vi.useRealTimers()
    })
})
