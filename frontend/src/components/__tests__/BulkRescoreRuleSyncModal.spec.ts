import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import BulkRescoreRuleSyncModal from '../BulkRescoreRuleSyncModal.vue'

const mocks = vi.hoisted(() => ({
    previewRescoreRuleSync: vi.fn(),
    applyRescoreRuleSync: vi.fn(),
}))

vi.mock('../../lib/api', () => ({
    previewRescoreRuleSync: mocks.previewRescoreRuleSync,
    applyRescoreRuleSync: mocks.applyRescoreRuleSync,
}))

const previewResponse = {
    task_id: 'task-1',
    items: [
        {
            group_id: 'CVE-2026-RULE',
            title: 'Stale requirement fields',
            finding_count: 1,
            syncable_finding_count: 1,
            review_finding_count: 0,
            findings: [
                {
                    state: 'NOT_AFFECTED',
                    cvss_version: '3.1',
                    status: 'ready',
                    reasons: ['Missing requirements: AR, CR, IR'],
                    current_score: 9.8,
                    proposed_score: 3.1,
                    current_vector: 'CVSS:3.1/AV:N/MC:N',
                    proposed_vector: 'CVSS:3.1/AV:N/CR:L/IR:L/AR:L/MC:N',
                },
            ],
        },
    ],
    summary: {
        groups: 1,
        findings: 1,
        syncable_groups: 1,
        syncable_findings: 1,
        review_findings: 0,
        compliant_findings: 2,
    },
}

describe('BulkRescoreRuleSyncModal', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        mocks.previewRescoreRuleSync.mockResolvedValue(previewResponse)
        mocks.applyRescoreRuleSync.mockResolvedValue({
            task_id: 'task-1',
            summary: { attempted: 1, succeeded: 1, queued: 0, failed: 0 },
            results: [{ status: 'success', uuid: 'finding-1' }],
        })
    })

    it('previews configured changes, selects syncable groups, and applies them', async () => {
        const wrapper = mount(BulkRescoreRuleSyncModal, {
            props: { show: false, taskId: 'task-1' },
        })

        await wrapper.setProps({ show: true })
        await flushPromises()

        expect(mocks.previewRescoreRuleSync).toHaveBeenCalledWith('task-1')
        expect(wrapper.text()).toContain('Missing requirements: AR, CR, IR')
        expect(wrapper.text()).toContain('9.8 → 3.1')

        await wrapper.findAll('button').find(button => button.text().includes('Apply Rule Sync'))?.trigger('click')
        await flushPromises()

        expect(mocks.applyRescoreRuleSync).toHaveBeenCalledWith('task-1', ['CVE-2026-RULE'])
        expect(wrapper.get('[data-testid="rescore-rule-sync-completion"]').text()).toContain('CVSS rule sync complete')
        expect(wrapper.emitted('applied')).toHaveLength(1)
    })

    it('shows configuration errors returned by the preview endpoint', async () => {
        mocks.previewRescoreRuleSync.mockRejectedValue({
            response: { data: { detail: 'metric_rules.3.1.relationships is required' } },
        })
        const wrapper = mount(BulkRescoreRuleSyncModal, {
            props: { show: false, taskId: 'task-1' },
        })

        await wrapper.setProps({ show: true })
        await flushPromises()

        expect(wrapper.get('[data-testid="rescore-rule-sync-error"]').text()).toContain('metric_rules.3.1.relationships')
    })
})
