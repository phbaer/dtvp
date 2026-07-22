import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', () => ({
    analysisQueueList: vi.fn(),
    analysisQueueSubmit: vi.fn(),
    analysisQueueSubmitFollowUp: vi.fn(),
    analysisQueueGet: vi.fn(),
    analysisQueueCancel: vi.fn(),
    analysisQueueClear: vi.fn(),
    analysisQueueCancelQueued: vi.fn(),
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

        await analysisQueueStore.submit('CVE-1', 'component', undefined, undefined, undefined, onComplete)

        await vi.advanceTimersByTimeAsync(3000)
        vi.runAllTicks()
        await vi.advanceTimersByTimeAsync(3000)
        vi.runAllTicks()

        expect(onComplete).toHaveBeenCalledWith(
            { summary: 'done' },
            expect.objectContaining({ queue_id: 'queue-1' }),
        )
        expect(analysisQueueStore.getCachedResult('queue-1')).toEqual({ summary: 'done' })

        analysisQueueStore.stopPolling()
    })

    it('notifies completion callbacks when an item is already completed on the first post-submit refresh', async () => {
        const api = await import('../api')
        const listMock = vi.mocked(api.analysisQueueList)
        const submitMock = vi.mocked(api.analysisQueueSubmit)
        const getMock = vi.mocked(api.analysisQueueGet)

        submitMock.mockResolvedValue({
            queue_id: 'queue-fast',
            vuln_id: 'CVE-1',
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'queued',
            position: 1,
        } as any)
        listMock.mockResolvedValue([
            {
                queue_id: 'queue-fast',
                vuln_id: 'CVE-1',
                component_name: 'component',
                submitted_by: 'tester',
                submitted_at: 'now',
                status: 'completed',
                position: 0,
            },
        ] as any)
        getMock.mockResolvedValue({
            queue_id: 'queue-fast',
            vuln_id: 'CVE-1',
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'completed',
            position: 0,
            result: { summary: 'fast result' } as any,
        } as any)

        const onComplete = vi.fn()
        const { analysisQueueStore } = await import('../analysisQueueStore')

        await analysisQueueStore.submit('CVE-1', 'component', undefined, undefined, undefined, onComplete)

        expect(onComplete).toHaveBeenCalledWith(
            { summary: 'fast result' },
            expect.objectContaining({ queue_id: 'queue-fast' }),
        )
        expect(analysisQueueStore.getCachedResult('queue-fast')).toEqual({ summary: 'fast result' })

        analysisQueueStore.stopPolling()
    })

    it('submits follow-up queue items with parent context', async () => {
        const api = await import('../api')
        const listMock = vi.mocked(api.analysisQueueList)
        const followUpMock = vi.mocked(api.analysisQueueSubmitFollowUp)

        listMock.mockResolvedValue([])
        followUpMock.mockResolvedValue({
            queue_id: 'queue-follow',
            vuln_id: 'CVE-1',
            component_name: 'keycloak',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'queued',
            position: 1,
            parent_run_id: 'run-parent',
            follow_up_question: 'Is Keycloak itself vulnerable?',
            source: 'follow-up',
        } as any)

        const { analysisQueueStore } = await import('../analysisQueueStore')

        const item = await analysisQueueStore.submitFollowUp(
            'run-parent',
            'Is Keycloak itself vulnerable?',
            'keycloak',
            'ExampleApp',
        )

        expect(item.queue_id).toBe('queue-follow')
        expect(followUpMock).toHaveBeenCalledWith({
            parent_run_id: 'run-parent',
            question: 'Is Keycloak itself vulnerable?',
            component_name: 'keycloak',
            project_name: 'ExampleApp',
            cvss_vector: undefined,
            user_guidance: undefined,
        })
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

    it.each([
        ['failed', 'Analyzer rejected the request', 'Analyzer rejected the request'],
        ['failed', undefined, 'Analysis failed'],
        ['cancelled', undefined, 'Analysis cancelled'],
    ] as const)('releases callbacks when a submitted item becomes %s', async (status, error, expectedError) => {
        const api = await import('../api')
        vi.mocked(api.analysisQueueSubmit).mockResolvedValue({
            queue_id: `queue-${status}`,
            vuln_id: 'CVE-1',
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: '2026-05-01T10:00:00Z',
            status: 'queued',
            position: 1,
        } as any)
        vi.mocked(api.analysisQueueList).mockResolvedValue([{
            queue_id: `queue-${status}`,
            vuln_id: 'CVE-1',
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: '2026-05-01T10:00:00Z',
            status,
            error,
            position: 0,
        }] as any)

        const onComplete = vi.fn()
        const onError = vi.fn()
        const { analysisQueueStore } = await import('../analysisQueueStore')

        await analysisQueueStore.submit(
            'CVE-1',
            'component',
            undefined,
            undefined,
            undefined,
            onComplete,
            onError,
        )

        expect(onComplete).not.toHaveBeenCalled()
        expect(onError).toHaveBeenCalledOnce()
        expect(onError).toHaveBeenCalledWith(expectedError)
        analysisQueueStore.stopPolling()
    })

    it('retries fetching a completed result after a transient API failure', async () => {
        vi.useFakeTimers()
        const api = await import('../api')
        vi.mocked(api.analysisQueueSubmit).mockResolvedValue({
            queue_id: 'queue-retry',
            vuln_id: 'CVE-1',
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: '2026-05-01T10:00:00Z',
            status: 'queued',
            position: 1,
        } as any)
        vi.mocked(api.analysisQueueList).mockResolvedValue([{
            queue_id: 'queue-retry',
            vuln_id: 'CVE-1',
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: '2026-05-01T10:00:00Z',
            status: 'completed',
            position: 0,
        }] as any)
        vi.mocked(api.analysisQueueGet)
            .mockRejectedValueOnce(new Error('temporary outage'))
            .mockResolvedValue({
                queue_id: 'queue-retry',
                vuln_id: 'CVE-1',
                component_name: 'component',
                submitted_by: 'tester',
                submitted_at: '2026-05-01T10:00:00Z',
                status: 'completed',
                position: 0,
                result: { summary: 'retried result' },
            } as any)

        const onComplete = vi.fn()
        const { analysisQueueStore } = await import('../analysisQueueStore')
        await analysisQueueStore.submit('CVE-1', 'component', undefined, undefined, undefined, onComplete)
        await vi.advanceTimersByTimeAsync(10_000)

        expect(api.analysisQueueGet).toHaveBeenCalledTimes(2)
        expect(onComplete).toHaveBeenCalledWith(
            { summary: 'retried result' },
            expect.objectContaining({ queue_id: 'queue-retry' }),
        )
        analysisQueueStore.stopPolling()
    })

    it('preserves the current queue snapshot when refresh fails', async () => {
        const api = await import('../api')
        vi.mocked(api.analysisQueueList)
            .mockResolvedValueOnce([{
                queue_id: 'existing',
                vuln_id: 'CVE-1',
                component_name: 'component',
                submitted_by: 'tester',
                submitted_at: 'invalid timestamp',
                status: 'running',
                position: 1,
            }] as any)
            .mockRejectedValueOnce(new Error('offline'))
        const { analysisQueueStore } = await import('../analysisQueueStore')

        await analysisQueueStore.refresh()
        await analysisQueueStore.refresh()

        expect(analysisQueueStore.items.value.map(item => item.queue_id)).toEqual(['existing'])
        expect(analysisQueueStore.activeCount.value).toBe(1)
        expect(analysisQueueStore.runningItem.value?.queue_id).toBe('existing')
        expect(analysisQueueStore.hasActivity.value).toBe(true)
    })

    it('dismisses a cached result even when the server-side delete already disappeared', async () => {
        const api = await import('../api')
        vi.mocked(api.analysisQueueGet).mockResolvedValue({
            queue_id: 'finished',
            vuln_id: 'CVE-1',
            component_name: 'component',
            submitted_by: 'tester',
            submitted_at: '2026-05-01T10:00:00Z',
            status: 'completed',
            position: 0,
            result: { summary: 'cached' },
        } as any)
        vi.mocked(api.analysisQueueCancel).mockRejectedValue(new Error('not found'))
        vi.mocked(api.analysisQueueList).mockResolvedValue([])
        const { analysisQueueStore } = await import('../analysisQueueStore')

        await analysisQueueStore.fetchResult('finished')
        await analysisQueueStore.dismiss('finished')

        expect(analysisQueueStore.getCachedResult('finished')).toBeUndefined()
        expect(analysisQueueStore.items.value).toEqual([])
    })
})
