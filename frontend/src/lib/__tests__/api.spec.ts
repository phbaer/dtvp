import { describe, it, expect, vi, beforeEach } from 'vitest'
import axios from 'axios'
import { getProjects, getGroupedVulns, updateAssessment, login, checkSession } from '../api'

vi.mock('axios', () => {
    const mockGet = vi.fn()
    const mockPost = vi.fn()
    return {
        default: {
            create: vi.fn(() => ({
                get: mockGet,
                post: mockPost,
                interceptors: {
                    request: { use: vi.fn(), eject: vi.fn() },
                    response: { use: vi.fn(), eject: vi.fn() }
                }
            })),
            get: vi.fn()
        },
        _mockGet: mockGet,
        _mockPost: mockPost
    }
})

// @ts-ignore
import * as axiosPkg from 'axios'
const { _mockGet, _mockPost } = axiosPkg as any

describe('api.ts', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.useRealTimers()
    })

    it('getProjects calls /projects', async () => {
        const mockData = [{ name: 'P1' }]
        _mockGet.mockResolvedValue({ data: mockData })

        const result = await getProjects('query')

        expect(_mockGet).toHaveBeenCalledWith('/projects', { params: { name: 'query' } })
        expect(result).toEqual(mockData)
    })

    it('getGroupedVulns starts task and polls for result', async () => {
        const mockTaskStart = { task_id: 'task-123' }
        const mockTaskRunning = { status: 'running', progress: 50, message: 'Loading...' }
        const mockTaskCompleted = { status: 'completed', result: [{ id: '1' }] }

        _mockPost.mockResolvedValue({ data: mockTaskStart })

        // Mock sequential GET calls: first running, then completed
        _mockGet
            .mockResolvedValueOnce({ data: mockTaskRunning })
            .mockResolvedValueOnce({ data: mockTaskCompleted })

        // Use vi.useFakeTimers to fast-forward polling intervals
        vi.useFakeTimers()

        const promise = getGroupedVulns('Test')

        // Fast-forward time to trigger interval
        await vi.advanceTimersByTimeAsync(1100)
        await vi.advanceTimersByTimeAsync(1100)

        const result = await promise

        expect(_mockPost).toHaveBeenCalledWith('/tasks/group-vulns', null, { params: { name: 'Test' } })
        expect(_mockGet).toHaveBeenCalledWith('/tasks/task-123')
        expect(result).toEqual(mockTaskCompleted.result)

        vi.useRealTimers()
    })

    it('getGroupedVulns reports progress', async () => {
        const mockTaskStart = { task_id: 'task-123' }
        const mockTaskRunning = { status: 'running', progress: 50, message: 'Step 1' }
        const mockTaskCompleted = { status: 'completed', result: [] }

        _mockPost.mockResolvedValue({ data: mockTaskStart })
        _mockGet
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

        _mockPost.mockResolvedValue({ data: mockTaskStart })
        _mockGet.mockResolvedValueOnce({ data: mockTaskFailed })

        vi.useFakeTimers()
        const promise = getGroupedVulns('Test')

        const assertion = expect(promise).rejects.toThrow('Task Failed')

        await vi.advanceTimersByTimeAsync(1100)

        await assertion
        vi.useRealTimers()
    })

    it('getGroupedVulns throws error on polling network error', async () => {
        const mockTaskStart = { task_id: 'task-net-err' }
        _mockPost.mockResolvedValue({ data: mockTaskStart })
        _mockGet.mockRejectedValue(new Error('Network Error'))

        vi.useFakeTimers()
        const promise = getGroupedVulns('Test')

        const assertion = expect(promise).rejects.toThrow('Network Error')

        await vi.advanceTimersByTimeAsync(1100)

        await assertion
        vi.useRealTimers()
    })

    it('updateAssessment calls /assessment', async () => {
        const payload: any = { status: 'ok' }
        _mockPost.mockResolvedValue({ data: { result: 'ok' } })

        const result = await updateAssessment(payload)

        expect(_mockPost).toHaveBeenCalledWith('/assessment', payload)
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
        // @ts-ignore
        axios.get.mockResolvedValue({ status: 200 })

        const result = await checkSession()
        expect(result).toBe(true)
        expect(axios.get).toHaveBeenCalled()
    })

    it('checkSession returns false on failure', async () => {
        // @ts-ignore
        axios.get.mockRejectedValue(new Error('401'))

        const result = await checkSession()
        expect(result).toBe(false)
    })
})
