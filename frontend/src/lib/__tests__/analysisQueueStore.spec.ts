import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', () => ({
    analysisQueueList: vi.fn(),
    analysisQueueSubmit: vi.fn(),
    analysisQueueGet: vi.fn(),
    analysisQueueCancel: vi.fn(),
}))

describe('analysisQueueStore', () => {
    beforeEach(() => {
        vi.resetModules()
        vi.clearAllMocks()
        vi.useRealTimers()
    })

    it('fetchResult caches results and evicts older entries beyond the bounded cache size', async () => {
        const api = await import('../api')
        const { analysisQueueStore } = await import('../analysisQueueStore')

        const getMock = vi.mocked(api.analysisQueueGet)
        getMock.mockImplementation(async (queueId: string) => ({
            queue_id: queueId,
            vuln_id: queueId,
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'completed',
            position: 0,
            result: { summary: queueId } as any,
        }))

        for (let index = 0; index < 51; index += 1) {
            await analysisQueueStore.fetchResult(`queue-${index}`)
        }

        expect(analysisQueueStore.getCachedResult('queue-0')).toBeUndefined()
        expect(analysisQueueStore.getCachedResult('queue-50')).toEqual({ summary: 'queue-50' })
        expect(getMock).toHaveBeenCalledTimes(51)

        await analysisQueueStore.fetchResult('queue-50')
        expect(getMock).toHaveBeenCalledTimes(51)
    })

    it('polling fetches completed results and notifies completion callbacks', async () => {
        vi.useFakeTimers()

        const api = await import('../api')
        const listMock = vi.mocked(api.analysisQueueList)
        const submitMock = vi.mocked(api.analysisQueueSubmit)
        const getMock = vi.mocked(api.analysisQueueGet)

        listMock
            .mockResolvedValueOnce([
                {
                    queue_id: 'queue-1',
                    vuln_id: 'CVE-1',
                    component_name: 'component',
                    submitted_by: 'tester',
                    submitted_at: 'now',
                    status: 'queued',
                    position: 1,
                },
            ] as any)
            .mockResolvedValueOnce([
                {
                    queue_id: 'queue-1',
                    vuln_id: 'CVE-1',
                    component_name: 'component',
                    submitted_by: 'tester',
                    submitted_at: 'now',
                    status: 'queued',
                    position: 1,
                },
            ] as any)
            .mockResolvedValueOnce([
                {
                    queue_id: 'queue-1',
                    vuln_id: 'CVE-1',
                    component_name: 'component',
                    submitted_by: 'tester',
                    submitted_at: 'now',
                    status: 'completed',
                    position: 0,
                },
            ] as any)

        submitMock.mockResolvedValue({
            queue_id: 'queue-1',
            vuln_id: 'CVE-1',
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'queued',
            position: 1,
        } as any)

        getMock.mockResolvedValue({
            queue_id: 'queue-1',
            vuln_id: 'CVE-1',
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'completed',
            position: 0,
            result: { summary: 'done' } as any,
        } as any)

        const onComplete = vi.fn()
        const { analysisQueueStore } = await import('../analysisQueueStore')

        await analysisQueueStore.submit('CVE-1', 'component', undefined, undefined, onComplete)

        await vi.advanceTimersByTimeAsync(3000)
        vi.runAllTicks()
        await vi.advanceTimersByTimeAsync(3000)
        vi.runAllTicks()

        expect(onComplete).toHaveBeenCalledWith({ summary: 'done' })
        expect(analysisQueueStore.getCachedResult('queue-1')).toEqual({ summary: 'done' })

        analysisQueueStore.stopPolling()
    })

    it('keeps queue items ordered by newest submission first after refresh', async () => {
        const api = await import('../api')
        const listMock = vi.mocked(api.analysisQueueList)

        listMock.mockResolvedValue([
            {
                queue_id: 'older',
                vuln_id: 'CVE-1',
                component_name: 'component-a',
                submitted_by: 'tester',
                submitted_at: '2026-05-01T10:00:00Z',
                status: 'running',
                position: 2,
            },
            {
                queue_id: 'newer',
                vuln_id: 'CVE-2',
                component_name: 'component-b',
                submitted_by: 'tester',
                submitted_at: '2026-05-02T10:00:00Z',
                status: 'queued',
                position: 1,
            },
            {
                queue_id: 'middle',
                vuln_id: 'CVE-3',
                component_name: 'component-c',
                submitted_by: 'tester',
                submitted_at: '2026-05-01T12:00:00Z',
                status: 'completed',
                position: 0,
            },
        ] as any)

        const { analysisQueueStore } = await import('../analysisQueueStore')

        await analysisQueueStore.refresh()

        expect(analysisQueueStore.items.value.map(item => item.queue_id)).toEqual(['newer', 'middle', 'older'])
    })
})