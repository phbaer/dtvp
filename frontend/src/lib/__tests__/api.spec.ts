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
    })

    it('getProjects calls /projects', async () => {
        const mockData = [{ name: 'P1' }]
        _mockGet.mockResolvedValue({ data: mockData })

        const result = await getProjects('query')

        expect(_mockGet).toHaveBeenCalledWith('/projects', { params: { name: 'query' } })
        expect(result).toEqual(mockData)
    })

    it('getGroupedVulns calls /projects/:name/grouped-vulnerabilities', async () => {
        const mockData = [{ id: '1' }]
        _mockGet.mockResolvedValue({ data: mockData })

        const result = await getGroupedVulns('Test')

        expect(_mockGet).toHaveBeenCalledWith('/projects/Test/grouped-vulnerabilities')
        expect(result).toEqual(mockData)
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
