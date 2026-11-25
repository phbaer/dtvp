import { flushPromises, mount } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '../App.vue'
import { getUserInfo, getVersion } from '../lib/api'
import { projectHeaderState } from '../lib/projectHeaderStore'
import { AUTH_EXPIRED_EVENT } from '../lib/authSession'

const mocks = vi.hoisted(() => ({
    route: {
        path: '/',
        fullPath: '/',
        query: {} as Record<string, unknown>,
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
    streamStart: vi.fn(),
    streamStop: vi.fn(),
    setInterest: vi.fn(),
}))

vi.mock('../lib/eventStream', async () => {
    const { ref } = await import('vue')
    return {
        eventStream: {
            status: ref('idle'),
            start: mocks.streamStart,
            stop: mocks.streamStop,
            setInterest: mocks.setInterest,
            on: () => () => undefined,
            cursor: null,
        },
        useServerEvents: () => undefined,
    }
})

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
                WhatsNewDialog: {
                    props: ['mode', 'shown', 'releases', 'currentVersion', 'previousVersion'],
                    emits: ['close'],
                    template: '<div data-testid="whats-new-stub" :data-mode="mode" :data-shown="shown.map(r => r.version).join(\',\')"><button data-testid="whats-new-stub-close" @click="$emit(\'close\')">close</button></div>',
                },
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
    it('reports the product a project page shows as this tab\'s interest', async () => {
        mocks.setInterest.mockClear()
        ;(mocks.route as any).path = '/project/App'
        ;(mocks.route as any).params = { name: 'App' }
        const wrapper = mountApp()
        await flushPromises()
        expect(mocks.setInterest).toHaveBeenLastCalledWith(['App'])
        wrapper.unmount()
        delete (mocks.route as any).params
    })

    beforeEach(() => {
        vi.clearAllMocks()
        mocks.route.path = '/'
        mocks.route.fullPath = '/'
        mocks.route.query = {}
        mocks.route.meta = {}
        mocks.router.replace.mockResolvedValue(undefined)
        mocks.router.push.mockResolvedValue(undefined)
        mocks.getChangelog.mockResolvedValue({ content: '', releases: [] })
        mocks.getUserInfo.mockResolvedValue({ username: 'reviewer', role: 'REVIEWER' })
        projectHeaderState.currentProjectName.value = null
        projectHeaderState.lastProjectName.value = null
        projectHeaderState.lastProjectPath.value = null
        projectHeaderState.isAllProjects.value = true
        projectHeaderState.viewMode.value = 'analysis'
        projectHeaderState.bulkWorkflowHandler.value = null
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

        expect(wrapper.get('[data-testid="app-bootstrap-state"]').text()).toContain('River is starting')
        expect(wrapper.find('[data-testid="router-view"]').exists()).toBe(false)
    })

    it('shows a retryable initialization page when the backend is not ready', async () => {
        mocks.getVersion
            .mockRejectedValueOnce({ response: { status: 503 } })
            .mockResolvedValueOnce({ version: '1.2.3', build: 'abc123' })

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        expect(wrapper.get('[data-testid="app-bootstrap-state"]').text()).toContain('River is still starting')
        expect(wrapper.get('[data-testid="app-bootstrap-error"]').text()).toContain('HTTP 503')

        await wrapper.get('button').trigger('click')
        await flushBootstrapDom(wrapper)

        expect(getVersion).toHaveBeenCalledTimes(2)
        expect(getUserInfo).toHaveBeenCalled()
        expect(wrapper.find('[data-testid="app-bootstrap-state"]').exists()).toBe(false)
        expect(wrapper.find('[data-testid="router-view"]').exists()).toBe(true)
    })

    it('moves an expired live session to sign-in and remembers the route', async () => {
        mocks.getVersion.mockResolvedValue({ version: '1.2.3', build: 'abc123' })
        mocks.route.path = '/project/Example'
        mocks.route.fullPath = '/project/Example?vuln=CVE-1'

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT))
        await wrapper.vm.$nextTick()

        expect(mocks.router.replace).toHaveBeenLastCalledWith({
            path: '/login',
            query: { expired: '1' },
        })
        expect(sessionStorage.getItem('dtvp:auth-return-path')).toBe(
            '/project/Example?vuln=CVE-1',
        )
    })

    it('opens the live-update stream once signed in and stops it on expiry and logout', async () => {
        mocks.getVersion.mockResolvedValue({ version: '1.2.3', build: 'abc123' })

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)
        expect(mocks.streamStart).toHaveBeenCalledTimes(1)

        await wrapper.get('button.cursor-pointer.border-gray-600').trigger('click')
        expect(mocks.streamStop).toHaveBeenCalledWith('logout')
        expect(mocks.logout).toHaveBeenCalledTimes(1)
        expect(mocks.streamStop.mock.invocationCallOrder[0]).toBeLessThan(
            mocks.logout.mock.invocationCallOrder[0],
        )

        window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT))
        expect(mocks.streamStop).toHaveBeenLastCalledWith('auth')
    })

    it('does not open the stream without a signed-in user', async () => {
        mocks.getVersion.mockResolvedValue({ version: '1.2.3', build: 'abc123' })
        mocks.getUserInfo.mockRejectedValue({ response: { status: 401 } })

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)
        expect(mocks.streamStart).not.toHaveBeenCalled()
    })

    it('offers a return to the last vulnerability list from code analysis', async () => {
        mocks.getVersion.mockResolvedValue({ version: '1.2.3', build: 'abc123' })
        mocks.route.path = '/code-analysis'
        mocks.route.fullPath = '/code-analysis'
        projectHeaderState.lastProjectName.value = 'Example App'
        projectHeaderState.lastProjectPath.value = '/project/Example%20App?id=CVE-2026-1'

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        const button = wrapper.findAll('button')
            .find(candidate => candidate.text().includes('Vuln List'))
        expect(button).toBeTruthy()

        await button?.trigger('click')

        expect(mocks.router.push).toHaveBeenCalledWith('/project/Example%20App?id=CVE-2026-1')
    })

    it('shows the backend Python and GIL state to reviewers', async () => {
        mocks.getVersion.mockResolvedValue({
            version: '1.2.3',
            build: 'abc123',
            runtime: {
                implementation: 'CPython',
                version: '3.14.4',
                free_threaded_build: true,
                gil_enabled: false,
                free_threading_active: true,
                free_threading_required: true,
            },
        })

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        expect(wrapper.get('[data-testid="backend-runtime-label"]').text())
            .toContain('CPython 3.14.4 · Free-threaded · GIL off')
    })

    it('does not show backend runtime details to analysts', async () => {
        mocks.getUserInfo.mockResolvedValue({ username: 'analyst', role: 'ANALYST' })
        mocks.getVersion.mockResolvedValue({
            version: '1.2.3',
            build: 'abc123',
            runtime: {
                implementation: 'CPython',
                version: '3.14.4',
                free_threaded_build: true,
                gil_enabled: false,
                free_threading_active: true,
                free_threading_required: true,
            },
        })

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        expect(wrapper.find('[data-testid="backend-runtime-label"]').exists()).toBe(false)
    })

    it('labels the project statistics toggle as a vulnerability-list return', async () => {
        mocks.getVersion.mockResolvedValue({ version: '1.2.3', build: 'abc123' })
        mocks.route.path = '/project/ExampleApp'
        mocks.route.fullPath = '/project/ExampleApp'
        projectHeaderState.currentProjectName.value = 'ExampleApp'
        projectHeaderState.isAllProjects.value = false
        projectHeaderState.viewMode.value = 'statistics'

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        const button = wrapper.findAll('button')
            .find(candidate => candidate.text().includes('Vuln List'))
        expect(button).toBeTruthy()

        await button?.trigger('click')

        expect(projectHeaderState.viewMode.value).toBe('analysis')
    })

    it('opens the bulk workflow selector from the project header', async () => {
        mocks.getVersion.mockResolvedValue({ version: '1.2.3', build: 'abc123' })
        mocks.route.path = '/project/ExampleApp'
        mocks.route.fullPath = '/project/ExampleApp'
        const handler = vi.fn()
        projectHeaderState.currentProjectName.value = 'ExampleApp'
        projectHeaderState.isAllProjects.value = false
        projectHeaderState.isReviewer.value = true
        projectHeaderState.bulkWorkflowHandler.value = handler

        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        const button = wrapper.findAll('button')
            .find(candidate => candidate.text().includes('Bulk Changes'))
        expect(button).toBeTruthy()
        await button?.trigger('click')
        expect(handler).toHaveBeenCalledOnce()
    })
})

describe("What's new", () => {
    const release = (version: string, text: string) => ({
        version,
        date: '2026-11-23',
        prerelease: /rc\d+$/.test(version),
        unreleased: false,
        groups: { breaking: [], new: [{ text, scope: null, pr: null, breaking: false, note: null }], faster: [], fixed: [] },
    })
    const releases = [release('2.1.0', 'Minor thing'), release('2.0.0', 'Major thing'), release('1.0.26', 'Old')]

    beforeEach(() => {
        vi.clearAllMocks()
        mocks.route.path = '/'
        mocks.route.fullPath = '/'
        mocks.route.query = {}
        mocks.route.meta = {}
        mocks.router.replace.mockResolvedValue(undefined)
        mocks.getChangelog.mockResolvedValue({ content: '', releases })
        mocks.getUserInfo.mockResolvedValue({ username: 'alice', role: 'ANALYST' })
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }))
        vi.stubGlobal('localStorage', createLocalStorageMock())
    })

    afterEach(() => {
        for (const wrapper of mountedWrappers.splice(0)) wrapper.unmount()
        vi.unstubAllGlobals()
    })

    it('shows nothing on a first visit and remembers the version for the user', async () => {
        mocks.getVersion.mockResolvedValue({ version: '2.0.0', build: 'abc' })
        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        expect(wrapper.find('[data-testid="whats-new-stub"]').exists()).toBe(false)
        expect(JSON.parse(localStorage.getItem('dtvp_whats_new:alice')!)).toEqual({ version: '2.0.0', final: '2.0.0' })
        expect(mocks.getChangelog).not.toHaveBeenCalled()
    })

    it('shows a major upgrade prominently with every release since the last visit', async () => {
        localStorage.setItem('dtvp_last_seen_version', '1.0.26')
        mocks.getVersion.mockResolvedValue({ version: '2.1.0', build: 'abc' })
        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        const dialog = wrapper.get('[data-testid="whats-new-stub"]')
        expect(dialog.attributes('data-mode')).toBe('major')
        expect(dialog.attributes('data-shown')).toBe('2.1.0,2.0.0')

        await wrapper.get('[data-testid="whats-new-stub-close"]').trigger('click')
        expect(wrapper.find('[data-testid="whats-new-stub"]').exists()).toBe(false)
        expect(JSON.parse(localStorage.getItem('dtvp_whats_new:alice')!)).toEqual({ version: '2.1.0', final: '2.1.0' })
    })

    it('shows a minor upgrade compactly', async () => {
        localStorage.setItem('dtvp_whats_new:alice', JSON.stringify({ version: '2.0.0', final: '2.0.0' }))
        mocks.getVersion.mockResolvedValue({ version: '2.1.0', build: 'abc' })
        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)

        expect(wrapper.get('[data-testid="whats-new-stub"]').attributes('data-mode')).toBe('compact')
    })

    it('opens again from the header and the footer', async () => {
        localStorage.setItem('dtvp_whats_new:alice', JSON.stringify({ version: '2.1.0', final: '2.1.0' }))
        mocks.getVersion.mockResolvedValue({ version: '2.1.0', build: 'abc' })
        const wrapper = mountApp()
        await flushBootstrapDom(wrapper)
        expect(wrapper.find('[data-testid="whats-new-stub"]').exists()).toBe(false)

        await wrapper.get('[data-testid="footer-whats-new"]').trigger('click')
        await flushPromises()
        expect(wrapper.get('[data-testid="whats-new-stub"]').attributes('data-mode')).toBe('browse')
        await wrapper.get('[data-testid="whats-new-stub-close"]').trigger('click')

        await wrapper.get('[data-testid="header-whats-new"]').trigger('click')
        await flushPromises()
        expect(wrapper.get('[data-testid="whats-new-stub"]').attributes('data-mode')).toBe('browse')
        // Opening it by hand does not change what was seen.
        expect(JSON.parse(localStorage.getItem('dtvp_whats_new:alice')!)).toEqual({ version: '2.1.0', final: '2.1.0' })
        expect(mocks.getChangelog).toHaveBeenCalledTimes(1)
    })
})

