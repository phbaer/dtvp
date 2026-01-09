import { describe, it, expect, vi, beforeEach } from 'vitest'
import { getProjects, getGroupedVulns, updateAssessment, login, checkSession, getVersion } from '../api'

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
        const mockTaskRunning = { status: 'running', progress: 50, message: 'Step 1' }
        const mockTaskCompleted = { status: 'completed', result: [] }

        mocks.post.mockResolvedValue({ data: mockTaskStart })
        mocks.get
            .mockResolvedValueOnce({ data: mockTaskRunning })
            .mockResolvedValueOnce({ data: mockTaskCompleted })

        vi.useFakeTimers()
        const onProgress = vi.fn()
        const promise = getGroupedVulns('Test', onProgress)

        await vi.advanceTimersByTimeAsync(1100)
        await vi.advanceTimersByTimeAsync(1100)

        await promise
        expect(onProgress).toHaveBeenCalledWith('Step 1', 50)
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
})
