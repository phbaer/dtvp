import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import SourceSyncMenu from '../SourceSyncMenu.vue'
import * as api from '../../lib/api'
import * as liveEvents from '../../lib/eventStream'

vi.mock('../../lib/api', () => ({
    getProjects: vi.fn(),
    getSyncSource: vi.fn(),
    getSyncVersions: vi.fn(),
    requestSyncRead: vi.fn(),
    requestSourceAnalysis: vi.fn(),
    exportAssessments: vi.fn(),
}))
vi.mock('../../lib/eventStream', async () => {
    const { createFakeEventStreamModule } = await import('../../lib/__tests__/fakeEventStreamTestUtils')
    return createFakeEventStreamModule()
})

const fakeStream = liveEvents as unknown as { emit: (type: string, data?: unknown) => void; reset: () => void }

const open = async (canAnalyse = true, synced: unknown[] = []) => {
    vi.mocked(api.getProjects).mockResolvedValue([
        { uuid: 'p1', name: 'App', version: '1.0' },
        { uuid: 'p2', name: 'App', version: '2.0' },
    ] as any)
    vi.mocked(api.getSyncSource).mockResolvedValue({ name: 'Dependency-Track', can_request_analysis: canAnalyse })
    vi.mocked(api.getSyncVersions).mockResolvedValue(synced as any)
    const wrapper = mount(SourceSyncMenu, { props: { projectName: 'App' } })
    await wrapper.get('[data-testid="source-sync-button"]').trigger('click')
    await flushPromises()
    return wrapper
}

describe('SourceSyncMenu', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        fakeStream.reset()
    })

    it('reads one version again and follows its progress from the events', async () => {
        vi.mocked(api.requestSyncRead).mockResolvedValue({ requested: ['p1'], already_requested: [] })
        const wrapper = await open()

        expect(wrapper.findAll('[data-testid="sync-version"]').map(item => item.text())).toEqual([
            expect.stringContaining('2.0'), expect.stringContaining('1.0'),
        ])
        await wrapper.get('[data-testid="sync-read-p1"]').trigger('click')
        await flushPromises()
        expect(api.requestSyncRead).toHaveBeenCalledWith({ project_uuid: 'p1' })
        expect(wrapper.get('[data-testid="sync-state-p1"]').text()).toBe('requested')

        fakeStream.emit('version.sync_state', { uuid: 'p1', status: 'syncing' })
        await flushPromises()
        expect(wrapper.get('[data-testid="sync-state-p1"]').text()).toBe('reading')
        fakeStream.emit('version.synced', { uuid: 'p1' })
        await flushPromises()
        expect(wrapper.get('[data-testid="sync-state-p1"]').text()).toBe('read')
        wrapper.unmount()
    })

    it('asks the source for an analysis of all versions, and reports a failure', async () => {
        vi.mocked(api.requestSourceAnalysis).mockResolvedValue({ requested: ['p1', 'p2'], already_running: [] })
        const wrapper = await open()

        await wrapper.get('[data-testid="sync-analyse-product"]').trigger('click')
        await flushPromises()
        expect(api.requestSourceAnalysis).toHaveBeenCalledWith({ product: 'App' })
        expect(wrapper.get('[data-testid="sync-state-p2"]').text()).toBe('analysing')

        fakeStream.emit('version.sync_failed', { uuid: 'p2' })
        await flushPromises()
        expect(wrapper.get('[data-testid="sync-state-p2"]').text()).toBe('failed')

        vi.mocked(api.requestSyncRead).mockRejectedValue({ response: { status: 503 } })
        await wrapper.get('[data-testid="sync-read-product"]').trigger('click')
        await flushPromises()
        expect(wrapper.get('[data-testid="sync-message"]').text()).toContain('not reachable')
        wrapper.unmount()
    })

    it('hides the analysis when the source cannot be asked, and exports now', async () => {
        vi.mocked(api.exportAssessments).mockResolvedValue({} as any)
        const wrapper = await open(false)

        expect(wrapper.find('[data-testid="sync-analyse-product"]').exists()).toBe(false)
        expect(wrapper.find('[data-testid="sync-analyse-p1"]').exists()).toBe(false)
        await wrapper.get('[data-testid="sync-export-now"]').trigger('click')
        await flushPromises()
        expect(api.exportAssessments).toHaveBeenCalledWith()
        expect(wrapper.get('[data-testid="sync-message"]').text()).toContain('exported')
        wrapper.unmount()
    })

    it("shows a request's progress as the server keeps it, with why it failed", async () => {
        const wrapper = await open(true, [
            { project_uuid: 'p1', request: { id: 'r1', by: 'rita', at: 't', state: 'failed', error: 'ConnectError: down' } },
            { project_uuid: 'p2', request: { id: 'r2', by: 'rita', at: 't', state: 'running' } },
        ])

        expect(wrapper.get('[data-testid="sync-state-p1"]').text()).toBe('failed')
        expect(wrapper.get('[data-testid="sync-state-p1"]').attributes('title')).toBe('ConnectError: down')
        expect(wrapper.get('[data-testid="sync-state-p2"]').text()).toBe('reading')
        wrapper.unmount()
    })
})
