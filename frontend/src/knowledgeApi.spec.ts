import { afterEach, expect, test, vi } from 'vitest'
import { knowledgeApi } from './knowledgeApi'
afterEach(() => vi.unstubAllGlobals())
test('transport defaults JSON but preserves explicit raw ZIP content type and current CSRF', async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) })
  vi.stubGlobal('fetch', fetch)
  document.cookie = 'dtvp_csrf=current-token; path=/'
  await knowledgeApi('/example', { method: 'POST', body: JSON.stringify({ explicit: true }) })
  const json = fetch.mock.calls[0]![1] as RequestInit
  expect(new Headers(json.headers).get('Content-Type')).toBe('application/json')
  const raw = new Uint8Array([80, 75, 0, 255])
  document.cookie = 'dtvp_csrf=new-token; path=/'
  await knowledgeApi('/archive', { method: 'POST', headers: { 'Content-Type': 'application/zip' }, body: raw })
  const zip = fetch.mock.calls[1]![1] as RequestInit
  expect(new Headers(zip.headers).get('Content-Type')).toBe('application/zip')
  expect(new Headers(zip.headers).get('X-CSRF-Token')).toBe('new-token')
  expect(zip.body).toBe(raw)
  expect(zip.credentials).toBe('same-origin')
})
