import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

describe('api.ts initialization', () => {
    beforeEach(() => {
        vi.resetModules()
        // Mock axios to track create calls
        vi.mock('axios', () => ({
            default: {
                create: vi.fn(() => ({
                    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
                    get: vi.fn(),
                    post: vi.fn()
                }))
            }
        }))
    })

    afterEach(() => {
        vi.unstubAllGlobals()
    })

    it('uses default baseURL when no config provided', async () => {
        vi.doMock('../env', () => ({
            getRuntimeConfig: (key: string, def: string) => def
        }))

        await import('../api') // Triggers module execution
        const axios = (await import('axios')).default

        // Defaults: API_URL='http://localhost:8000', CONTEXT_PATH='/'
        // CONTEXT_PATH='/' replaced to ''
        // API_BASE = http://localhost:8000 + '' + '/api'
        expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({
            baseURL: 'http://localhost:8000/api'
        }))
    })

    it('respects custom API_URL', async () => {
        vi.doMock('../env', () => ({
            getRuntimeConfig: (key: string, def: string) => {
                if (key === 'DTVP_API_URL') return 'https://custom-api.com'
                return def
            }
        }))

        await import('../api')
        const axios = (await import('axios')).default

        expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({
            baseURL: 'https://custom-api.com/api'
        }))
    })

    it('handles context path with leading slash', async () => {
        vi.doMock('../env', () => ({
            getRuntimeConfig: (key: string, def: string) => {
                if (key === 'DTVP_CONTEXT_PATH') return '/my-app'
                return def
            }
        }))

        await import('../api')
        const axios = (await import('axios')).default

        // CONTEXT_PATH='/my-app' -> NORMALIZED='/my-app'
        // API_BASE = http://localhost:8000 + /my-app + /api
        expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({
            baseURL: 'http://localhost:8000/my-app/api'
        }))
    })

    it('normalizes context path missing leading slash', async () => {
        vi.doMock('../env', () => ({
            getRuntimeConfig: (key: string, def: string) => {
                if (key === 'DTVP_CONTEXT_PATH') return 'my-app' // Missing slash
                return def
            }
        }))

        await import('../api')
        const axios = (await import('axios')).default

        // CONTEXT_PATH='my-app' -> NORMALIZED='/my-app'
        expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({
            baseURL: 'http://localhost:8000/my-app/api'
        }))
    })
})
