import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import BulkWorkflowModal from '../BulkWorkflowModal.vue'

const mocks = vi.hoisted(() => ({
    getBulkWorkflowSummary: vi.fn(),
    previewBulkWorkflow: vi.fn(),
    applyBulkWorkflow: vi.fn(),
    buildBulkWorkflowDocument: vi.fn(),
}))

vi.mock('../../lib/api', async importOriginal => {
    const original = await importOriginal<typeof import('../../lib/api')>()
    return {
        ...original,
        getBulkWorkflowSummary: mocks.getBulkWorkflowSummary,
        previewBulkWorkflow: mocks.previewBulkWorkflow,
        applyBulkWorkflow: mocks.applyBulkWorkflow,
        buildBulkWorkflowDocument: mocks.buildBulkWorkflowDocument,
    }
})

vi.mock('../../lib/env', () => ({
    getRuntimeConfig: () => 'https://jira.example/secure/CreateIssue.jspa',
}))

const workflow = {
    id: 'incomplete-sync',
    label: 'Complete assessments',
    description: 'Apply assessment blocks to incomplete findings.',
    supports_apply: true,
    supports_document: false,
    version: 1,
}

describe('BulkWorkflowModal', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        mocks.getBulkWorkflowSummary.mockResolvedValue({
            task_id: 'task-1',
            workflows: [{ ...workflow, candidate_count: 1, summary: { groups: 1 } }],
        })
        mocks.previewBulkWorkflow.mockResolvedValue({
            task_id: 'task-1',
            workflow,
            preview_token: 'preview-1',
            selectable_group_ids: ['CVE-2026-1'],
            items: [{ group_id: 'CVE-2026-1', finding_count: 2, block_count: 1 }],
            summary: { groups: 1 },
        })
        mocks.applyBulkWorkflow.mockResolvedValue({
            task_id: 'task-1',
            workflow,
            summary: { attempted: 2, succeeded: 2, queued: 0, failed: 0 },
            results: [],
        })
        mocks.buildBulkWorkflowDocument.mockResolvedValue('# Ticket drafts\n')
    })

    it('freezes active filters, previews one workflow, and applies its selection', async () => {
        const wrapper = mount(BulkWorkflowModal, {
            props: {
                show: false,
                taskId: 'task-1',
                query: { q: 'openssl', component: 'runtime', sort: 'id', limit: 250 },
            },
        })

        await wrapper.setProps({ show: true })
        await flushPromises()

        const filters = { q: 'openssl', component: 'runtime' }
        expect(mocks.getBulkWorkflowSummary).toHaveBeenCalledWith('task-1', filters)
        expect(mocks.previewBulkWorkflow).not.toHaveBeenCalled()
        expect(wrapper.text()).toContain('Select a bulk workflow')

        await wrapper.get('[data-testid="bulk-workflow-incomplete-sync"]').trigger('click')
        await flushPromises()

        expect(mocks.previewBulkWorkflow).toHaveBeenCalledWith(
            'incomplete-sync',
            'task-1',
            filters,
            expect.any(Function),
        )
        expect(wrapper.text()).toContain('CVE-2026-1')

        await wrapper.get('[data-testid="bulk-workflow-apply"]').trigger('click')
        await flushPromises()

        expect(mocks.applyBulkWorkflow).toHaveBeenCalledWith(
            'incomplete-sync',
            'task-1',
            filters,
            ['CVE-2026-1'],
            'preview-1',
            expect.any(Function),
        )
        expect(wrapper.get('[data-testid="bulk-workflow-completion"]').text()).toContain('2 applied')
        expect(wrapper.emitted('applied')).toHaveLength(1)
    })

    it('shows an empty intersection without enabling apply', async () => {
        mocks.getBulkWorkflowSummary.mockResolvedValue({
            task_id: 'task-1',
            workflows: [{ ...workflow, candidate_count: 0, summary: { groups: 0 } }],
        })
        mocks.previewBulkWorkflow.mockResolvedValue({
            task_id: 'task-1',
            workflow,
            preview_token: 'preview-empty',
            selectable_group_ids: [],
            items: [],
            summary: { groups: 0 },
        })

        const wrapper = mount(BulkWorkflowModal, {
            props: { show: false, taskId: 'task-1', query: { q: 'does-not-match' } },
        })
        await wrapper.setProps({ show: true })
        await flushPromises()

        await wrapper.get('[data-testid="bulk-workflow-incomplete-sync"]').trigger('click')
        await flushPromises()

        expect(wrapper.text()).toContain('No matching changes')
        expect(wrapper.find('[data-testid="bulk-workflow-apply"]').exists()).toBe(true)
        expect(wrapper.get('[data-testid="bulk-workflow-apply"]').attributes('disabled')).toBeDefined()
    })

    it('supports verdict selections, ticket copy, Jira, and Markdown export', async () => {
        const automaticWorkflow = {
            ...workflow,
            id: 'automatic-assessments',
            label: 'Apply Automatic Assessments',
            supports_document: true,
        }
        mocks.getBulkWorkflowSummary.mockResolvedValue({
            task_id: 'task-1',
            workflows: [{ ...automaticWorkflow, candidate_count: 2, summary: { groups: 2 } }],
        })
        mocks.previewBulkWorkflow.mockResolvedValue({
            task_id: 'task-1',
            workflow: automaticWorkflow,
            preview_token: 'preview-auto',
            selectable_group_ids: ['CVE-AFFECTED', 'CVE-SAFE'],
            items: [
                { group_id: 'CVE-AFFECTED', verdict_bucket: 'AFFECTED', eligible_finding_count: 1, run_ids: ['run-1'], ticket_text: 'Title: fix it' },
                { group_id: 'CVE-SAFE', verdict_bucket: 'NOT_AFFECTED', eligible_finding_count: 1, run_ids: ['run-2'], ticket_text: '' },
            ],
            summary: { groups: 2 },
        })
        const clipboard = vi.fn().mockResolvedValue(undefined)
        Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: clipboard } })
        const open = vi.spyOn(window, 'open').mockImplementation(() => null)
        const createObjectURL = vi.fn(() => 'blob:ticket')
        const revokeObjectURL = vi.fn()
        Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL })
        Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL })
        const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

        const wrapper = mount(BulkWorkflowModal, {
            props: { show: false, taskId: 'task-1', query: { q: 'auto' } },
        })
        await wrapper.setProps({ show: true })
        await flushPromises()

        await wrapper.get('[data-testid="bulk-workflow-automatic-assessments"]').trigger('click')
        await flushPromises()

        await wrapper.findAll('[data-testid="automatic-assessment-actions"] button')[2].trigger('click')
        expect(wrapper.get('[data-testid="bulk-workflow-apply"]').text()).toContain('(1)')

        await wrapper.get('[data-testid="copy-ticket-CVE-AFFECTED"]').trigger('click')
        expect(clipboard).toHaveBeenCalledWith('Title: fix it')
        await wrapper.get('[data-testid="jira-ticket-CVE-AFFECTED"]').trigger('click')
        expect(open).toHaveBeenCalledWith('https://jira.example/secure/CreateIssue.jspa', '_blank', 'noopener,noreferrer')

        await wrapper.get('[data-testid="bulk-workflow-document"]').trigger('click')
        await flushPromises()
        expect(mocks.buildBulkWorkflowDocument).toHaveBeenCalledWith(
            'automatic-assessments', 'task-1', { q: 'auto' }, ['CVE-AFFECTED'], 'preview-auto',
            expect.any(Function),
        )
        expect(createObjectURL).toHaveBeenCalled()
        expect(click).toHaveBeenCalled()
        expect(revokeObjectURL).toHaveBeenCalledWith('blob:ticket')
    })

    it('shows automatic-assessment discovery diagnostics for an empty preview', async () => {
        const automaticWorkflow = {
            ...workflow,
            id: 'automatic-assessments',
            label: 'Apply Automatic Assessments',
        }
        mocks.getBulkWorkflowSummary.mockResolvedValue({
            task_id: 'task-1',
            workflows: [{ ...automaticWorkflow, candidate_count: null, summary: {} }],
        })
        mocks.previewBulkWorkflow.mockResolvedValue({
            task_id: 'task-1',
            workflow: automaticWorkflow,
            preview_token: 'preview-empty-auto',
            selectable_group_ids: [],
            items: [],
            summary: {
                groups: 0,
                stored_analysis_results: 7,
                usable_assessment_results: 4,
                matched_analysis_results: 1,
                already_applied_findings: 1,
            },
        })
        const wrapper = mount(BulkWorkflowModal, {
            props: { show: false, taskId: 'task-1' },
        })

        await wrapper.setProps({ show: true })
        await flushPromises()
        await wrapper.get('[data-testid="bulk-workflow-automatic-assessments"]').trigger('click')
        await flushPromises()

        expect(wrapper.get('[data-testid="automatic-assessment-diagnostics"]').text())
            .toContain('7 saved result(s) scanned')
        expect(wrapper.get('[data-testid="automatic-assessment-diagnostics"]').text())
            .toContain('4 usable assessment(s)')
        expect(wrapper.get('[data-testid="automatic-assessment-diagnostics"]').text())
            .toContain('1 matched result(s)')
    })

    it('shows the original and fixed CVSS vector and score for rule sync candidates', async () => {
        const rescoreWorkflow = {
            ...workflow,
            id: 'rescore-rule-sync',
            label: 'Sync CVSS Rules',
        }
        mocks.getBulkWorkflowSummary.mockResolvedValue({
            task_id: 'task-1',
            workflows: [{ ...rescoreWorkflow, candidate_count: 1, summary: { groups: 1 } }],
        })
        mocks.previewBulkWorkflow.mockResolvedValue({
            task_id: 'task-1',
            workflow: rescoreWorkflow,
            preview_token: 'preview-rescore',
            selectable_group_ids: ['CVE-2026-RULE'],
            items: [{
                group_id: 'CVE-2026-RULE',
                syncable_finding_count: 1,
                review_finding_count: 0,
                findings: [{
                    state: 'NOT_AFFECTED',
                    cvss_version: '3.1',
                    status: 'ready',
                    reasons: ['Missing requirements: AR, CR, IR'],
                    current_score: 9.8,
                    proposed_score: 0,
                    current_vector: 'CVSS:3.1/AV:N/MC:N',
                    proposed_vector: 'CVSS:3.1/AV:N/CR:L/IR:L/AR:L/MC:N',
                }],
            }],
            summary: { groups: 1 },
        })
        const wrapper = mount(BulkWorkflowModal, {
            props: { show: false, taskId: 'task-1' },
        })

        await wrapper.setProps({ show: true })
        await flushPromises()
        await wrapper.get('[data-testid="bulk-workflow-rescore-rule-sync"]').trigger('click')
        await flushPromises()

        const change = wrapper.get('[data-testid="rescore-rule-change-CVE-2026-RULE"]')
        expect(change.text()).toContain('Original')
        expect(change.text()).toContain('Score 9.8')
        expect(change.text()).toContain('CVSS:3.1/AV:N/MC:N')
        expect(change.text()).toContain('Fixed')
        expect(change.text()).toContain('Score 0.0')
        expect(change.text()).toContain('CVSS:3.1/AV:N/CR:L/IR:L/AR:L/MC:N')
    })

    it('reuses a prepared preview when returning to a workflow', async () => {
        const secondWorkflow = { ...workflow, id: 'assessment-restore', label: 'Restore CVSS' }
        mocks.getBulkWorkflowSummary.mockResolvedValue({
            task_id: 'task-1',
            workflows: [
                { ...workflow, candidate_count: null, summary: {} },
                { ...secondWorkflow, candidate_count: null, summary: {} },
            ],
        })
        mocks.previewBulkWorkflow.mockImplementation(async workflowId => ({
            task_id: 'task-1',
            workflow: workflowId === workflow.id ? workflow : secondWorkflow,
            preview_token: `preview-${workflowId}`,
            selectable_group_ids: [],
            items: [],
            summary: { groups: 0 },
        }))
        const wrapper = mount(BulkWorkflowModal, {
            props: { show: false, taskId: 'task-1' },
        })
        await wrapper.setProps({ show: true })
        await flushPromises()

        await wrapper.get('[data-testid="bulk-workflow-incomplete-sync"]').trigger('click')
        await flushPromises()
        await wrapper.get('[data-testid="bulk-workflow-assessment-restore"]').trigger('click')
        await flushPromises()
        await wrapper.get('[data-testid="bulk-workflow-incomplete-sync"]').trigger('click')
        await flushPromises()

        expect(mocks.previewBulkWorkflow).toHaveBeenCalledTimes(2)
    })
})
