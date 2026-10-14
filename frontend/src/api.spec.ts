import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, send } from './api'

afterEach(() => vi.unstubAllGlobals())
describe('API authentication and errors', () => {
  it('includes session request token and preserves actionable conflict errors', async () => {
    document.cookie = 'dtvp_csrf=synthetic-token'
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: 'Evidence changed' }), { status: 409 }))
    vi.stubGlobal('fetch', fetch)
    await expect(api('/findings/f/decisions', send({ rationale: 'Keep draft' }))).rejects.toThrow('Evidence changed')
    const headers = fetch.mock.calls[0]![1].headers as Headers
    expect(headers.get('X-CSRF-Token')).toBe('synthetic-token')
    expect(fetch.mock.calls[0]![1].credentials).toBe('same-origin')
  })
  it('keeps authorization status available to the UI', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', { status: 401 })))
    await expect(api('/me')).rejects.toBeInstanceOf(ApiError)
  })
})
