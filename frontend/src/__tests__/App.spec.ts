import { flushPromises, mount } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '../App.vue'
import { getUserInfo, getVersion } from '../lib/api'

const mocks = vi.hoisted(() => ({
    route: {
        path: '/',
        fullPath: '/',
        meta: {} as Record<string, unknown>,
    },
    router: {
        push: vi.fn(),
        replace: vi.fn(),
    },
    getVersion: vi.fn(),
    getUserInfo: vi.fn(),
    getChangelog: vi.fn(),
    logout: vi.fn(),
}))

vi.mock('vue-router', () => ({
    useRoute: () => mocks.route,
    useRouter: () => mocks.router,
}))

vi.mock('../lib/api', () => ({
    getVersion: mocks.getVersion,
    getUserInfo: mocks.getUserInfo,
    getChangelog: mocks.getChangelog,
    logout: mocks.logout,
}))

const mountedWrappers: VueWrapper[] = []

const createLocalStorageMock = (): Storage => {
    const store = new Map<string, string>()

    return {
        get length() {
            return store.size
        },
        clear: vi.fn(() => {
            store.clear()
        }),
        getItem: vi.fn((key: string) => store.get(key) ?? null),
        key: vi.fn((index: number) => Array.from(store.keys())[index] ?? null),
        removeItem: vi.fn((key: string) => {
            store.delete(key)
        }),
        setItem: vi.fn((key: string, value: string) => {
            store.set(key, String(value))
        }),
    }
}

const mountApp = () => {
    const wrapper = mount(App, {
        global: {
            stubs: {
                AnalysisQueueIndicator: true,
                ChangelogModal: true,
                RouterLink: {
                    props: ['to'],
                    template: '<a><slot /></a>',
                },
                RouterView: {
                    template: '<div data-testid="router-view"></div>',
                },
            },
        },
    })
    mountedWrappers.push(wrapper)
    return wrapper
}

const flushBootstrapDom = async (wrapper: VueWrapper) => {
    await flushPromises()
    await wrapper.vm.$nextTick()
}

describe('App bootstrap state', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        mocks.route.path = '/'
        mocks.route.fullPath = '/'
        mocks.route.meta = {}
        mocks.router.replace.mockResolvedValue(undefined)
        mocks.getChangelog.mockResolvedValue({ content: '' })
        mocks.getUserInfo.mockResolvedValue({ username: 'reviewer', role: 'REVIEWER' })
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }))
        vi.stubGlobal('localStorage', createLocalStorageMock())
    })

    afterEach(() => {
        for (const wrapper of mountedWrappers.splice(0)) {
            wrapper.unmount()
        }
        vi.unstubAllGlobals()
    })

    it('shows a loading page while the backend bootstrap checks are pending', async () => {
        mocks.getVersion.mockReturnValue(new Promise(() => {}))

        const wrapper = mountApp()
        await wrapper.vm.$nextTick()

        expect(wrapper.get('[data-testid="app-bootstrap-state"]').text()).toContain('DTVP is starting')
        expect(wrapper.find('[data-testid="router-view"]').exists()).toBe(false)
    })

    it('shows a retryable initialization page when the backend is not ready', async () => {
        mocks.getVersion
            .mockRejectedValueOnce({ response: { status: 503 } })
            .mockResolvedValueOnce({ version: '1.2.3', build: 'abc123' })

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        expect(wrapper.get('[data-testid="app-bootstrap-state"]').text()).toContain('DTVP is still starting')
        expect(wrapper.get('[data-testid="app-bootstrap-error"]').text()).toContain('HTTP 503')

        await wrapper.get('button').trigger('click')
        await flushBootstrapDom(wrapper)

        expect(getVersion).toHaveBeenCalledTimes(2)
        expect(getUserInfo).toHaveBeenCalled()
        expect(wrapper.find('[data-testid="app-bootstrap-state"]').exists()).toBe(false)
        expect(wrapper.find('[data-testid="router-view"]').exists()).toBe(true)
    })
})
