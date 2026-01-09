import { describe, it, expect, afterEach } from 'vitest'
import { getRuntimeConfig } from '../env'

describe('env.ts', () => {
    afterEach(() => {
        // Cleanup global window object
        delete (window as any).__env__
    })

    it('returns default value if window.__env__ is undefined', () => {
        expect(getRuntimeConfig('DTVP_FRONTEND_URL', 'default')).toBe('default')
    })

    it('returns default value if key is missing', () => {
        (window as any).__env__ = {}
        expect(getRuntimeConfig('DTVP_FRONTEND_URL', 'default')).toBe('default')
    })

    it('returns default value if value is placeholder (starts with ${)', () => {
        (window as any).__env__ = {
            DTVP_FRONTEND_URL: '${DTVP_FRONTEND_URL}'
        }
        expect(getRuntimeConfig('DTVP_FRONTEND_URL', 'default')).toBe('default')
    })

    it('returns valid value if present', () => {
        (window as any).__env__ = {
            DTVP_FRONTEND_URL: 'https://api.example.com'
        }
        expect(getRuntimeConfig('DTVP_FRONTEND_URL', 'default')).toBe('https://api.example.com')
    })
})
