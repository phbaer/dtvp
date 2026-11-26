import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('vue-router', () => ({
    useRouter: () => ({ resolve: (location: { path: string, query?: Record<string, string> }) => ({
        href: `/dtvp${location.path}${location.query?.project ? `?project=${location.query.project}` : ''}`,
    }) }),
}))
vi.mock('../../lib/api', () => ({
    listSavedViews: vi.fn(),
    createSavedView: vi.fn(),
    deleteSavedView: vi.fn(),
    setDefaultView: vi.fn(),
    updateSavedView: vi.fn(),
}))

import SavedViewsMenu from '../SavedViewsMenu.vue'
import * as api from '../../lib/api'

const view = (code: string, overrides: Record<string, unknown> = {}) => ({
    code, scope: 'personal', name: `View ${code}`, project: 'App', query: `q=${code}`,
    owner: 'anna', created_at: '', updated_at: '', updated_by: 'anna', editable: true, ...overrides,
})
const listing = (overrides: Record<string, unknown> = {}) => ({
    views: [view('aaaaaaaa'), view('bbbbbbbb', { scope: 'global', name: 'Release freeze', editable: false, project: null })],
    defaults: {
        user_project: null, user_all: null, role_project: null, role_all: null, roles: {},
        effective: { source: 'builtin', code: null, query: null },
    },
    role: 'ANALYST',
    can_manage_global: false,
    limits: {},
    ...overrides,
})

describe('SavedViewsMenu', () => {
    const writeText = vi.fn(async () => undefined)
    beforeEach(() => {
        vi.mocked(api.listSavedViews).mockResolvedValue(listing() as any)
        Object.assign(navigator, { clipboard: { writeText } })
        writeText.mockClear()
    })
    afterEach(() => {
        document.body.innerHTML = ''
        vi.clearAllMocks()
    })

    const open = async (props: Record<string, unknown> = {}) => {
        const wrapper = mount(SavedViewsMenu, {
            props: { project: 'App', currentQuery: 'q=aaaaaaaa', currentUrl: 'http://dtvp/project/App?q=aaaaaaaa', ...props },
            attachTo: document.body,
        })
        await wrapper.get('[data-testid="saved-views-trigger"]').trigger('click')
        await flushPromises()
        return wrapper
    }
    const el = (testId: string) => document.querySelector(`[data-testid="${testId}"]`) as HTMLElement

    it('lists my and shared views, marks the current one and applies a view', async () => {
        const wrapper = await open()
        expect(wrapper.get('[data-testid="saved-views-trigger"]').text()).toContain('View aaaaaaaa')
        expect(el('saved-views-menu').textContent).toContain('Release freeze')
        expect(el('saved-views-menu').textContent).toContain('all projects')
        // A shared view an analyst cannot change has no edit actions.
        expect(el('saved-view-delete-bbbbbbbb')).toBeNull()
        expect(el('saved-view-share-aaaaaaaa')).toBeNull()
        el('saved-view-bbbbbbbb').click()
        expect(wrapper.emitted('apply')?.[0]).toEqual(['q=bbbbbbbb'])
        wrapper.unmount()
    })

    it('saves the current filters, copies their full link and a view\'s short link', async () => {
        vi.mocked(api.createSavedView).mockResolvedValue(view('cccccccc') as any)
        const wrapper = await open({ currentQuery: 'cutoff=2026-03-01', currentUrl: 'http://dtvp/project/App?cutoff=2026-03-01' })
        const name = el('saved-view-name') as HTMLInputElement
        name.value = 'Release 7.2'
        name.dispatchEvent(new Event('input'))
        ;(el('saved-view-all-projects') as HTMLInputElement).click()
        el('saved-view-save').click()
        await flushPromises()
        expect(api.createSavedView).toHaveBeenCalledWith({
            name: 'Release 7.2', scope: 'personal', project: null, query: 'cutoff=2026-03-01',
        })
        // Unsaved filters: the full link.
        el('copy-link').click()
        await flushPromises()
        expect(writeText).toHaveBeenCalledWith('http://dtvp/project/App?cutoff=2026-03-01')
        expect(el('saved-views-notice').textContent).toContain('Link copied')
        el('saved-view-link-aaaaaaaa').click()
        await flushPromises()
        expect(writeText).toHaveBeenLastCalledWith(`${window.location.origin}/dtvp/v/aaaaaaaa`)
        expect(el('saved-views-notice').textContent).toContain('Short link copied')
        // An any-project view's link names the current project.
        el('saved-view-link-bbbbbbbb').click()
        await flushPromises()
        expect(writeText).toHaveBeenLastCalledWith(`${window.location.origin}/dtvp/v/bbbbbbbb?project=App`)
        wrapper.unmount()
    })

    it('sets my default and asks twice before deleting', async () => {
        vi.mocked(api.setDefaultView).mockResolvedValue({} as any)
        vi.mocked(api.deleteSavedView).mockResolvedValue(undefined)
        const wrapper = await open()
        el('saved-view-default-aaaaaaaa').click()
        await flushPromises()
        expect(api.setDefaultView).toHaveBeenCalledWith({ target: 'user', project: 'App', code: 'aaaaaaaa' })
        expect(wrapper.emitted('defaults-changed')).toHaveLength(1)
        el('saved-view-delete-aaaaaaaa').click()
        await flushPromises()
        expect(api.deleteSavedView).not.toHaveBeenCalled()
        el('saved-view-delete-aaaaaaaa').click()
        await flushPromises()
        expect(api.deleteSavedView).toHaveBeenCalledWith('aaaaaaaa')
        wrapper.unmount()
    })

    it('lets reviewers share views and set role defaults, and shows errors', async () => {
        vi.mocked(api.listSavedViews).mockResolvedValue(listing({ can_manage_global: true, role: 'REVIEWER' }) as any)
        vi.mocked(api.updateSavedView).mockRejectedValue({ response: { data: { detail: 'At most 200 global views' } } })
        vi.mocked(api.setDefaultView).mockResolvedValue({} as any)
        const wrapper = await open()
        expect(el('saved-view-global')).not.toBeNull()
        el('saved-view-share-aaaaaaaa').click()
        await flushPromises()
        expect(el('saved-views-error').textContent).toContain('At most 200 global views')
        const select = el('role-default-ANALYST') as HTMLSelectElement
        select.value = 'bbbbbbbb'
        select.dispatchEvent(new Event('change'))
        await flushPromises()
        expect(api.setDefaultView).toHaveBeenCalledWith({ target: 'role', role: 'ANALYST', project: 'App', code: 'bbbbbbbb' })
        wrapper.unmount()
    })
})
