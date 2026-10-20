import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, reactive, type App } from 'vue'
import KnowledgeProductAccess from './KnowledgeProductAccess.vue'
import { api } from '../api'
import type { Me } from '../types'
vi.mock('../api', () => ({ api: vi.fn() }))
const request = vi.mocked(api)
const me: Me = { id: 'actor', name: 'Actor', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, vscorer_url: '', workspaces: [{ id: 'owner', name: 'Owner', capabilities: ['read'] }, { id: 'team', name: 'Other team', capabilities: ['read'] }] }
const access = { owner: { id: 'owner', name: 'Owner' }, grants: [{ workspace_id: 'team', workspace_name: 'Other team', capabilities: ['read'] }], capabilities: ['manage'] }
let app: App | undefined
function mount() { const host = document.createElement('div'); document.body.append(host); const props = reactive({ me, project: 'product', disabled: false, onLocked: vi.fn() }); app = createApp(KnowledgeProductAccess, props); app.mount(host); return { host, props } }
function button(host: HTMLElement, text: string) { const value = [...host.querySelectorAll('button')].find(item => item.textContent?.trim() === text); if (!value) throw new Error(`Missing button ${text}`); return value }
afterEach(() => { app?.unmount(); app = undefined; document.body.innerHTML = ''; request.mockReset() })
describe('product access', () => {
  it('shows authorized ownership and grants without reader write controls', async () => {
    request.mockResolvedValue({ ...access, capabilities: [] })
    const { host } = mount()
    await vi.waitFor(() => expect(host.textContent).toContain('Product owner team: Owner'))
    expect(host.textContent).toContain('Other team'); expect(host.querySelector('select')).toBeNull()
    expect(host.textContent).toContain('management permission is required')
    expect(request).toHaveBeenCalledWith('/projects/product/sharing')
  })
  it('shows unavailable reads honestly and never exposes management controls', async () => {
    request.mockRejectedValue(new Error('Resource unavailable in your scope'))
    const { host } = mount()
    await vi.waitFor(() => expect(host.querySelector('[role=alert]')?.textContent).toContain('Resource unavailable'))
    expect(host.querySelector('select')).toBeNull(); expect(host.textContent).not.toContain('No explicit sharing grants.')
  })
  it('reviews before writing, freezes the request and retries exact target/body', async () => {
    request.mockResolvedValueOnce(access).mockRejectedValueOnce(new Error('Response lost')).mockResolvedValueOnce({}).mockResolvedValueOnce(access)
    const { host, props } = mount()
    await vi.waitFor(() => expect(host.querySelector('select')).not.toBeNull())
    const select = host.querySelector('select')!; select.value = 'team'; select.dispatchEvent(new Event('change'))
    await nextTick(); button(host, 'Review sharing update').click(); await nextTick()
    expect(request).toHaveBeenCalledTimes(1); expect(props.onLocked).toHaveBeenLastCalledWith(true)
    expect(host.querySelector('select')).toBeNull(); button(host, 'Confirm sharing update').click()
    await vi.waitFor(() => expect(host.querySelector('[role=alert]')?.textContent).toContain('Response lost'))
    const first = request.mock.calls[1]
    expect(first).toEqual(['/projects/product/sharing', { method: 'PUT', body: JSON.stringify({ workspace_id: 'team', capabilities: ['read'] }) }])
    button(host, 'Retry captured sharing update').click()
    await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(4)); expect(request.mock.calls[2]).toEqual(first)
    await vi.waitFor(() => expect(props.onLocked).toHaveBeenLastCalledWith(false))
  })
  it('cancelled review never writes and old actor responses cannot revive captures', async () => {
    let finish: ((value: unknown) => void) | undefined
    request.mockResolvedValueOnce(access).mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    const { host } = mount()
    await vi.waitFor(() => expect(host.querySelector('select')).not.toBeNull())
    const select = host.querySelector('select')!; select.value = 'team'; select.dispatchEvent(new Event('change')); await nextTick()
    button(host, 'Review sharing update').click(); await nextTick(); button(host, 'Cancel sharing update').click(); await nextTick()
    expect(request).toHaveBeenCalledTimes(1)
    button(host, 'Review sharing update').click(); await nextTick(); button(host, 'Confirm sharing update').click(); await nextTick()
    app?.unmount(); app = undefined; finish?.({}); await nextTick(); await nextTick()
    expect(request).toHaveBeenCalledTimes(2); expect(host.textContent).toBe('')
  })
})
