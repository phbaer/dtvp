import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import BulkRestoreAssessmentModal from '../BulkRestoreAssessmentModal.vue'

const mocks = vi.hoisted(() => ({
    drainTaskVulnGroups: vi.fn(),
    previewAssessmentRestore: vi.fn(),
    applyAssessmentRestore: vi.fn(),
}))

vi.mock('../../lib/api', () => ({
    drainTaskVulnGroups: mocks.drainTaskVulnGroups,
    previewAssessmentRestore: mocks.previewAssessmentRestore,
    applyAssessmentRestore: mocks.applyAssessmentRestore,
}))

const previewResponse = {
    task_id: 'task-1',
    items: [
        {
            group_id: 'CVE-2026-RESTORE',
            title: 'Missing rescored vector',
            status: 'recoverable',
            finding_count: 1,
            recoverable_finding_count: 1,
            findings: [
                {
                    status: 'recoverable',
                    reason: 'MISSING_RESCORING_VECTOR',
                    restored_score: 0,
                    restored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
                    candidate_vectors: ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'],
                    source: { timestamp: 1710000000000, commenter: 'reviewer' },
                },
            ],
        },
    ],
    summary: {
        groups: 1,
        findings: 1,
        recoverable_findings: 1,
        ambiguous_findings: 0,
        no_history_findings: 0,
    },
}

describe('BulkRestoreAssessmentModal', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        mocks.drainTaskVulnGroups.mockResolvedValue([{ id: 'CVE-2026-RESTORE' }])
        mocks.previewAssessmentRestore.mockResolvedValue(previewResponse)
    })

    it('shows indeterminate progress and keeps queued 405 details visible after apply', async () => {
        let resolveApply: (value: any) => void = () => undefined
        mocks.applyAssessmentRestore.mockReturnValue(new Promise(resolve => {
            resolveApply = resolve
        }))
        const wrapper = mount(BulkRestoreAssessmentModal, {
            props: { show: false, taskId: 'task-1', query: { q: 'openssl' } },
        })

        await wrapper.setProps({ show: true })
        await flushPromises()
        expect(mocks.drainTaskVulnGroups).toHaveBeenCalledWith('task-1', {
            q: 'openssl',
            sort: 'id',
            order: 'asc',
        }, { limit: 1000 })
        expect(mocks.previewAssessmentRestore).toHaveBeenCalledWith(
            'task-1',
            ['CVE-2026-RESTORE'],
        )
        await wrapper.findAll('button').find(button => button.text().includes('Apply Restore'))?.trigger('click')

        expect(wrapper.get('[data-testid="restore-progress"]').text()).toContain('Restoring CVSS rescoring')
        expect(wrapper.get('[data-testid="restore-progress"]').text()).toContain('Keep this window open')
        expect(mocks.applyAssessmentRestore).toHaveBeenCalledWith('task-1', ['CVE-2026-RESTORE'])

        resolveApply({
            task_id: 'task-1',
            summary: { attempted: 1, succeeded: 0, queued: 1, failed: 0 },
            results: [
                {
                    status: 'error',
                    uuid: 'finding-1',
                    queued: true,
                    error: '405 Method Not Allowed from Dependency-Track',
                },
            ],
        })
        await flushPromises()

        const completion = wrapper.get('[data-testid="restore-completion"]')
        expect(completion.text()).toContain('Restore processing complete')
        expect(completion.text()).toContain('Queued for Retry')
        expect(completion.text()).toContain('405 Method Not Allowed from Dependency-Track')
        expect(wrapper.emitted('applied')).toHaveLength(1)
        expect(wrapper.find('[data-testid="restore-completion"]').exists()).toBe(true)

        await wrapper.findAll('button').find(button => button.text().trim() === 'Close')?.trigger('click')
        expect(wrapper.emitted('close')).toHaveLength(1)
    })

    it('identifies an outer HTTP 405 as a route mismatch rather than missing progress', async () => {
        mocks.previewAssessmentRestore.mockRejectedValue({
            response: { status: 405, data: {} },
            message: 'Method Not Allowed',
        })
        const wrapper = mount(BulkRestoreAssessmentModal, {
            props: { show: false, taskId: 'task-1' },
        })

        await wrapper.setProps({ show: true })
        await flushPromises()

        const error = wrapper.get('[data-testid="restore-error"]').text()
        expect(error).toContain('HTTP 405')
        expect(error).toContain('POST /api/assessments/restore-preview')
        expect(error).toContain('not caused by missing progress updates')
    })
})
