import { afterEach, expect, it, vi } from 'vitest'
import { knowledgeUpload } from './knowledgeUpload'

class Request {
  static last: Request
  upload: { onprogress?: (event: ProgressEvent) => void; onload?: () => void } = {}
  onload?: () => void
  onerror?: () => void
  onabort?: () => void
  ontimeout?: () => void
  status = 201
  response: unknown = { committed: true }
  headers: Record<string, string> = {}
  method = ''; url = ''; body?: FormData; responseType = ''; withCredentials = false
  constructor() { Request.last = this }
  open(method: string, url: string) { this.method = method; this.url = url }
  setRequestHeader(name: string, value: string) { this.headers[name] = value }
  send(body: FormData) { this.body = body }
}
afterEach(() => { vi.unstubAllGlobals(); document.cookie = 'dtvp_csrf=; Max-Age=0; path=/' })
function start() { vi.stubGlobal('XMLHttpRequest', Request); const progress = vi.fn(); const body = new FormData(); body.append('metadata', '{"request_id":"fixed"}'); const pending = knowledgeUpload('/projects/p/versions/1/files', body, progress); return { request: Request.last, pending, progress, body } }
it('measures transfer separately from commit and preserves authenticated multipart bytes', async () => {
  document.cookie = 'dtvp_csrf=token%2Fvalue; path=/'
  const { request, pending, progress, body } = start()
  let settled = false; void pending.then(() => { settled = true })
  expect(request.method).toBe('POST'); expect(request.url).toBe('/api/v1/projects/p/versions/1/files')
  expect(request.body).toBe(body); expect(request.headers).toEqual({ 'X-CSRF-Token': 'token/value' })
  expect(request.withCredentials).toBe(true)
  request.upload.onprogress?.(new ProgressEvent('progress', { lengthComputable: true, loaded: 100, total: 100 }))
  expect(progress).toHaveBeenLastCalledWith(100, false)
  request.upload.onload?.(); await Promise.resolve()
  expect(progress).toHaveBeenLastCalledWith(null, true); expect(settled).toBe(false)
  request.status = 202; request.response = { committed: true, projection: 'pending' }; request.onload?.()
  await expect(pending).resolves.toEqual({ committed: true, projection: 'pending' })
})
it('keeps unknown transfer size indeterminate and preserves HTTP conflict details', async () => {
  const { request, pending, progress } = start()
  request.upload.onprogress?.(new ProgressEvent('progress'))
  expect(progress).toHaveBeenLastCalledWith(null, false)
  request.status = 409; request.response = { detail: 'Baseline changed' }; request.onload?.()
  await expect(pending).rejects.toMatchObject({ status: 409, message: 'Baseline changed' })
})
for (const failure of ['onerror', 'onabort', 'ontimeout'] as const) it(`${failure} never confirms publication`, async () => {
  const { request, pending } = start()
  request[failure]?.()
  await expect(pending).rejects.toThrow('not confirmed')
})
