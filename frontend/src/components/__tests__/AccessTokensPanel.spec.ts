import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import AccessTokensPanel from '../AccessTokensPanel.vue'
import * as api from '../../lib/api'

vi.mock('../../lib/api', () => ({
    createAccessToken: vi.fn(),
    getMcpEndpointUrl: vi.fn(() => 'https://dtvp.example/mcp'),
    listAccessTokenAudit: vi.fn(),
    listAccessTokens: vi.fn(),
    revokeAccessToken: vi.fn(),
}))

const listing = (tokens: any[] = [], enabled = true) => ({
    enabled,
    scopes: ['read', 'write'],
    default_expiry_days: 90,
    max_expiry_days: 365,
    tokens,
})

const activeToken = {
    id: 't1',
    name: 'triage agent',
    scopes: ['read', 'write'],
    created_at: '2026-01-01T00:00:00+00:00',
    expires_at: '2999-01-01T00:00:00+00:00',
    last_used_at: null,
    revoked_at: null,
}

const mountPanel = async (isReviewer = false) => {
    const wrapper = mount(AccessTokensPanel, { props: { isReviewer } })
    await flushPromises()
    return wrapper
}

describe('AccessTokensPanel', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(api.listAccessTokens).mockResolvedValue(listing())
        vi.mocked(api.listAccessTokenAudit).mockResolvedValue([])
    })

    it('explains how to enable tokens when they are turned off', async () => {
        vi.mocked(api.listAccessTokens).mockResolvedValue(listing([], false))
        const wrapper = await mountPanel()

        expect(wrapper.find('[data-testid="access-tokens-disabled"]').text()).toContain('DTVP_ACCESS_TOKENS_ENABLED')
        expect(wrapper.find('[data-testid="token-create"]').exists()).toBe(false)
        expect(api.listAccessTokenAudit).not.toHaveBeenCalled()
    })

    it('shows the endpoint and empty states', async () => {
        const wrapper = await mountPanel()

        expect(wrapper.find('[data-testid="mcp-url"]').text()).toBe('https://dtvp.example/mcp')
        expect(wrapper.find('[data-testid="tokens-empty"]').exists()).toBe(true)
        expect(wrapper.find('[data-testid="audit-empty"]').exists()).toBe(true)
        expect(wrapper.find('[data-testid="token-create"]').attributes('disabled')).toBeDefined()
    })

    it('creates a read-only token by default and shows its value once', async () => {
        vi.mocked(api.createAccessToken).mockResolvedValue({ ...activeToken, scopes: ['read'], token: 'dtvp_pat_secret' })
        const wrapper = await mountPanel()

        await wrapper.find('[data-testid="token-name"]').setValue('  triage agent ')
        await wrapper.find('form').trigger('submit')
        await flushPromises()

        expect(api.createAccessToken).toHaveBeenCalledWith({
            name: 'triage agent',
            scopes: ['read'],
            expires_in_days: 90,
        })
        expect(wrapper.find('[data-testid="created-token"]').text()).toContain('dtvp_pat_secret')
        expect(wrapper.find('[data-testid="created-token"]').text()).toContain('cannot be shown again')
        expect((wrapper.find('[data-testid="token-name"]').element as HTMLInputElement).value).toBe('')
        expect(api.listAccessTokens).toHaveBeenCalledTimes(2)
    })

    it('requests the write scope only when asked', async () => {
        vi.mocked(api.createAccessToken).mockResolvedValue({ ...activeToken, token: 'dtvp_pat_secret' })
        const wrapper = await mountPanel()

        await wrapper.find('[data-testid="token-name"]').setValue('agent')
        await wrapper.find('[data-testid="token-write"]').setValue(true)
        await wrapper.find('[data-testid="token-expiry"]').setValue(30)
        await wrapper.find('form').trigger('submit')
        await flushPromises()

        expect(api.createAccessToken).toHaveBeenCalledWith({
            name: 'agent',
            scopes: ['read', 'write'],
            expires_in_days: 30,
        })
    })

    it('blocks creation for an out-of-range expiry and reports server errors', async () => {
        const wrapper = await mountPanel()
        await wrapper.find('[data-testid="token-name"]').setValue('agent')
        await wrapper.find('[data-testid="token-expiry"]').setValue(400)
        expect(wrapper.find('[data-testid="token-create"]').attributes('disabled')).toBeDefined()

        await wrapper.find('[data-testid="token-expiry"]').setValue(30)
        vi.mocked(api.createAccessToken).mockRejectedValue({ response: { data: { detail: 'At most 20 active tokens per user; revoke one first' } } })
        await wrapper.find('form').trigger('submit')
        await flushPromises()

        expect(wrapper.find('[role="alert"]').text()).toContain('At most 20 active tokens')
        expect(wrapper.find('[data-testid="created-token"]').exists()).toBe(false)
    })

    it('lists tokens and revokes only after confirmation', async () => {
        vi.mocked(api.listAccessTokens).mockResolvedValue(listing([
            activeToken,
            { ...activeToken, id: 't2', name: 'old', scopes: ['read'], revoked_at: '2026-02-01T00:00:00+00:00' },
            { ...activeToken, id: 't3', name: 'lapsed', expires_at: '2020-01-01T00:00:00+00:00' },
        ]))
        vi.mocked(api.revokeAccessToken).mockResolvedValue()
        const wrapper = await mountPanel()

        const rows = wrapper.findAll('[data-testid="token-row"]')
        expect(rows.map((row) => row.text())).toEqual([
            expect.stringContaining('Read and draft'),
            expect.stringContaining('Revoked'),
            expect.stringContaining('Expired'),
        ])
        expect(rows[1]!.text()).toContain('Read only')
        expect(wrapper.findAll('[data-testid="token-revoke"]')).toHaveLength(1)

        const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
        await wrapper.find('[data-testid="token-revoke"]').trigger('click')
        expect(api.revokeAccessToken).not.toHaveBeenCalled()

        confirm.mockReturnValue(true)
        await wrapper.find('[data-testid="token-revoke"]').trigger('click')
        await flushPromises()
        expect(api.revokeAccessToken).toHaveBeenCalledWith('t1')
        confirm.mockRestore()
    })

    it('shows audited changes with the scope that applies to the viewer', async () => {
        vi.mocked(api.listAccessTokenAudit).mockResolvedValue([{
            id: 1,
            occurred_at: '2026-03-01T10:00:00+00:00',
            username: 'alice',
            token_id: 't1',
            agent: 'triage agent',
            action: 'save_assessment',
            outcome: 'success',
            target: { project: 'TestApp', vulnerability: 'CVE-2026-0001', team: 'Team A' },
            detail: '',
        }])

        const own = await mountPanel(false)
        expect(own.text()).toContain('Recent changes made with your tokens')
        expect(own.find('[data-testid="audit-row"]').text()).toContain('TestApp · CVE-2026-0001 · Team A')

        const all = await mountPanel(true)
        expect(all.text()).toContain('all users')
    })

    it('reports a load failure', async () => {
        vi.mocked(api.listAccessTokens).mockRejectedValue(new Error('network down'))
        const wrapper = await mountPanel()
        expect(wrapper.find('[role="alert"]').text()).toContain('network down')
    })
})
