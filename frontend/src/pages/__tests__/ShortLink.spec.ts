import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

const replace = vi.fn()
const route = { params: { code: 'abcdefgh' }, query: {} as Record<string, string> }
vi.mock('vue-router', () => ({
    useRoute: () => route,
    useRouter: () => ({ replace }),
}))
vi.mock('../../lib/api', () => ({ getSavedView: vi.fn() }))

import ShortLink from '../ShortLink.vue'
import { getSavedView } from '../../lib/api'

const stubs = { 'router-link': { template: '<a><slot /></a>' } }

describe('ShortLink', () => {
    it('opens the project with the stored filters', async () => {
        vi.mocked(getSavedView).mockResolvedValue({ code: 'abcdefgh', project: 'My App', query: 'cutoff=2026-03-01&lifecycle=OPEN&lifecycle=INCOMPLETE' } as any)
        mount(ShortLink, { global: { stubs } })
        await flushPromises()
        expect(replace).toHaveBeenCalledWith({
            path: '/project/My%20App',
            query: { cutoff: '2026-03-01', lifecycle: ['OPEN', 'INCOMPLETE'] },
        })
    })

    it('takes the project of the link for a view of any project, and explains a missing one', async () => {
        replace.mockClear()
        vi.mocked(getSavedView).mockResolvedValue({ code: 'abcdefgh', name: 'Freeze', project: null, query: '' } as any)
        route.query = { project: 'Other' }
        mount(ShortLink, { global: { stubs } })
        await flushPromises()
        expect(replace).toHaveBeenCalledWith({ path: '/project/Other', query: {} })

        route.query = {}
        const wrapper = mount(ShortLink, { global: { stubs } })
        await flushPromises()
        expect(wrapper.text()).toContain('applies to any project')

        vi.mocked(getSavedView).mockRejectedValue({ response: { status: 404 } })
        const missing = mount(ShortLink, { global: { stubs } })
        await flushPromises()
        expect(missing.text()).toContain('does not exist')
    })
})
