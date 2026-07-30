import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', () => ({
    analysisQueueList: vi.fn(),
    analysisQueueStatus: vi.fn(),
    analysisQueueSubmit: vi.fn(),
    analysisQueueSubmitFollowUp: vi.fn(),
    analysisQueueGet: vi.fn(),
    analysisQueueCancel: vi.fn(),
    analysisQueueClear: vi.fn(),
    analysisQueueCancelQueued: vi.fn(),
}))

const autoSweepStatus = {
    enabled: false,
    code_analysis_configured: false,
    active: false,
    interval_seconds: 900,
    running: false,
}

const queueStatus = (items: any[]) => ({
    updated_at: '2026-07-30T12:00:00Z',
    counts_by_status: items.reduce((counts, item) => ({
        ...counts,
        [item.status]: (counts[item.status] ?? 0) + 1,
    }), {} as Record<string, number>),
    active_count: items.filter(item => item.status === 'queued' || item.status === 'running').length,
    running_count: items.filter(item => item.status === 'running').length,
    items,
    auto_sweep: autoSweepStatus,
})

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
        const statusMock = vi.mocked(api.analysisQueueStatus)
        const submitMock = vi.mocked(api.analysisQueueSubmit)
        const getMock = vi.mocked(api.analysisQueueGet)

        statusMock
            .mockResolvedValueOnce(queueStatus([
                {
                    queue_id: 'queue-1',
                    vuln_id: 'CVE-1',
                    component_name: 'component',
                    submitted_by: 'tester',
                    submitted_at: 'now',
                    status: 'queued',
                    position: 1,
                },
            ] as any))
            .mockResolvedValueOnce(queueStatus([
                {
                    queue_id: 'queue-1',
                    vuln_id: 'CVE-1',
                    component_name: 'component',
                    submitted_by: 'tester',
                    submitted_at: 'now',
                    status: 'queued',
                    position: 1,
                },
            ] as any))
            .mockResolvedValueOnce(queueStatus([
                {
                    queue_id: 'queue-1',
                    vuln_id: 'CVE-1',
                    component_name: 'component',
                    submitted_by: 'tester',
                    submitted_at: 'now',
                    status: 'completed',
                    position: 0,
                },
            ] as any))

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

        vi.spyOn(Math, 'random').mockReturnValue(0.5)
        await vi.advanceTimersByTimeAsync(5000)
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
        const statusMock = vi.mocked(api.analysisQueueStatus)
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
        statusMock.mockResolvedValue(queueStatus([
            {
                queue_id: 'queue-fast',
                vuln_id: 'CVE-1',
                component_name: 'component',
                submitted_by: 'tester',
                submitted_at: 'now',
                status: 'completed',
                position: 0,
            },
        ] as any))
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
        const statusMock = vi.mocked(api.analysisQueueStatus)
        const followUpMock = vi.mocked(api.analysisQueueSubmitFollowUp)

        statusMock.mockResolvedValue(queueStatus([]))
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

    it('uses compact status polling and backs off to 30 seconds while idle', async () => {
        vi.useFakeTimers()
        vi.spyOn(Math, 'random').mockReturnValue(0.5)

        const api = await import('../api')
        const statusMock = vi.mocked(api.analysisQueueStatus)
        statusMock.mockResolvedValue(queueStatus([]))
        const { analysisQueueStore } = await import('../analysisQueueStore')

        await analysisQueueStore.startPolling()
        expect(statusMock).toHaveBeenCalledTimes(1)

        await vi.advanceTimersByTimeAsync(29999)
        expect(statusMock).toHaveBeenCalledTimes(1)

        await vi.advanceTimersByTimeAsync(1)
        expect(statusMock).toHaveBeenCalledTimes(2)
        expect(analysisQueueStore.sweepStatus.value).toEqual(autoSweepStatus)

        analysisQueueStore.stopPolling()
    })
})
