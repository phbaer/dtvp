import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('axios', () => ({
    default: {
        create: vi.fn(() => ({
            interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
            get: vi.fn(),
            post: vi.fn()
        }))
    }
}))

describe('api.ts initialization', () => {
    beforeEach(() => {
        vi.resetModules()
        vi.clearAllMocks()
    })

    afterEach(() => {
        vi.unstubAllGlobals()
    })

    it('uses default baseURL (window.location.origin) when no config provided', async () => {
        vi.doMock('../env', () => ({
            getRuntimeConfig: (_key: string, def: string) => def
        }))
        // Emulate window.location.origin
        const originalLocation = window.location;
        Object.defineProperty(window, 'location', {
            configurable: true,
            value: { origin: 'http://test-origin.com' },
        });

        await import('../api') // Triggers module execution
        const axios = (await import('axios')).default

        // Defaults: FRONTEND_URL=window.location.origin, CONTEXT_PATH='/'
        // CONTEXT_PATH='/' replaced to ''
        // API_BASE = http://test-origin.com + '' + '/api'
        expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({
            baseURL: 'http://test-origin.com/api'
        }))

        // Restore
        Object.defineProperty(window, 'location', { value: originalLocation });
    })

    it('respects custom FRONTEND_URL', async () => {
        vi.doMock('../env', () => ({
            getRuntimeConfig: (key: string, def: string) => {
                if (key === 'DTVP_FRONTEND_URL') return 'https://custom-domain.com'
                return def
            }
        }))

        await import('../api')
        const axios = (await import('axios')).default

        expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({
            baseURL: 'https://custom-domain.com/api'
        }))
    })

    it('handles context path with leading slash', async () => {
        vi.doMock('../env', () => ({
            getRuntimeConfig: (key: string, def: string) => {
                if (key === 'DTVP_CONTEXT_PATH') return '/my-app'
                // Default FRONTEND_URL fallback
                if (key === 'DTVP_FRONTEND_URL') return 'http://localhost:8000'
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

    it('does not duplicate context path if FRONTEND_URL already contains it', async () => {
        vi.doMock('../env', () => ({
            getRuntimeConfig: (key: string, def: string) => {
                if (key === 'DTVP_CONTEXT_PATH') return '/my-app'
                if (key === 'DTVP_FRONTEND_URL') return 'http://localhost:8000/my-app'
                return def
            }
        }))

        await import('../api')
        const axios = (await import('axios')).default

        // Ensure we don't end up with http://localhost:8000/my-app/my-app/api
        expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({
            baseURL: 'http://localhost:8000/my-app/api'
        }))
    })

    it('normalizes context path missing leading slash', async () => {
        vi.doMock('../env', () => ({
            getRuntimeConfig: (key: string, def: string) => {
                if (key === 'DTVP_CONTEXT_PATH') return 'my-app' // Missing slash
                if (key === 'DTVP_FRONTEND_URL') return 'http://localhost:8000'
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
