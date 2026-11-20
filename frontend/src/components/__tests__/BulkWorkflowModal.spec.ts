import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import BulkWorkflowModal from '../BulkWorkflowModal.vue'

const mocks = vi.hoisted(() => ({
    getBulkWorkflowSummary: vi.fn(),
    previewBulkWorkflow: vi.fn(),
    applyBulkWorkflow: vi.fn(),
    buildBulkWorkflowDocument: vi.fn(),
    uploadBulkWorkflowSource: vi.fn(),
}))

vi.mock('../../lib/api', async importOriginal => {
    const original = await importOriginal<typeof import('../../lib/api')>()
    return {
        ...original,
        getBulkWorkflowSummary: mocks.getBulkWorkflowSummary,
        previewBulkWorkflow: mocks.previewBulkWorkflow,
        applyBulkWorkflow: mocks.applyBulkWorkflow,
        buildBulkWorkflowDocument: mocks.buildBulkWorkflowDocument,
        uploadBulkWorkflowSource: mocks.uploadBulkWorkflowSource,
    }
})

vi.mock('../../lib/env', () => ({
    getRuntimeConfig: () => 'https://jira.example/secure/CreateIssue.jspa',
}))

const workflow = {
    id: 'assessment-repair',
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

        await wrapper.get('[data-testid="bulk-workflow-assessment-repair"]').trigger('click')
        await flushPromises()

        expect(mocks.previewBulkWorkflow).toHaveBeenCalledWith(
            'assessment-repair',
            'task-1',
            filters,
            expect.any(Function),
        )
        expect(wrapper.text()).toContain('CVE-2026-1')

        await wrapper.get('[data-testid="bulk-workflow-apply"]').trigger('click')
        await flushPromises()

        expect(mocks.applyBulkWorkflow).toHaveBeenCalledWith(
            'assessment-repair',
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

        await wrapper.get('[data-testid="bulk-workflow-assessment-repair"]').trigger('click')
        await flushPromises()

        expect(wrapper.text()).toContain('No matching changes')
        expect(wrapper.find('[data-testid="bulk-workflow-apply"]').exists()).toBe(true)
        expect(wrapper.get('[data-testid="bulk-workflow-apply"]').attributes('disabled')).toBeDefined()
    })

    it('supports outcome and rescore filters, ticket copy, Jira, and Markdown export', async () => {
        const automaticWorkflow = {
            ...workflow,
            id: 'automatic-assessments',
            label: 'Apply Automatic Assessments',
            supports_document: true,
        }
        mocks.getBulkWorkflowSummary.mockResolvedValue({
            task_id: 'task-1',
            workflows: [{ ...automaticWorkflow, candidate_count: 3, summary: { groups: 3 } }],
        })
        mocks.previewBulkWorkflow.mockResolvedValue({
            task_id: 'task-1',
            workflow: automaticWorkflow,
            preview_token: 'preview-auto',
            selectable_group_ids: ['CVE-AFFECTED', 'CVE-PROBABLE', 'CVE-SAFE'],
            items: [
                {
                    group_id: 'CVE-AFFECTED',
                    verdict_bucket: 'AFFECTED',
                    eligible_finding_count: 1,
                    run_ids: ['run-1', 'run-4'],
                    teams: ['TEAM-API', 'TEAM-WORKER'],
                    unowned_components: ['orphan-lib'],
                    ticket_text: 'Title: fix it',
                    rescore: {
                        current_score: 8.1,
                        current_vector: 'CVSS:3.1/AV:N/AC:L/C:H',
                        proposed_score: 3.2,
                        proposed_vector: 'CVSS:3.1/AV:N/AC:L/C:H/CR:L',
                        proposed_severity: 'LOW',
                    },
                },
                {
                    group_id: 'CVE-PROBABLE',
                    verdict_bucket: 'PROBABLY_AFFECTED',
                    eligible_finding_count: 1,
                    run_ids: ['run-3'],
                    ticket_text: 'Title: investigate it',
                    rescore: {
                        current_score: 8.1,
                        proposed_score: 6.1,
                        proposed_severity: 'MEDIUM',
                    },
                },
                { group_id: 'CVE-SAFE', verdict_bucket: 'NOT_AFFECTED', eligible_finding_count: 1, run_ids: ['run-2'], ticket_text: '' },
            ],
            summary: { groups: 3, rescored_groups: 2, low_rescored_affected_groups: 1 },
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

        const notice = wrapper.get('[data-testid="automatic-assessment-rescore-notice"]').text()
        expect(notice).toContain('one assessment per owning team')
        expect(notice).toContain("takes the worst result's state and its CVSS rescore")
        const rescore = wrapper.get('[data-testid="automatic-assessment-rescore-CVE-AFFECTED"]')
        expect(rescore.text()).toContain('Current')
        expect(rescore.text()).toContain('Score 8.1')
        expect(rescore.text()).toContain('Will apply')
        expect(rescore.text()).toContain('Score 3.2 · LOW')
        expect(rescore.text()).toContain('CVSS:3.1/AV:N/AC:L/C:H/CR:L')

        expect(
            wrapper.findAll('[data-testid="automatic-assessment-outcome-filters"] button')
                .map(button => button.text())
        ).toEqual(['All', 'Affected', 'Probably affected', 'Not affected', 'Uncertain'])
        expect(
            wrapper.findAll('[data-testid="automatic-assessment-rescore-filters"] button')
                .map(button => button.text())
        ).toEqual(['All', 'Critical', 'High', 'Medium', 'Low', 'Info', 'No rescore', 'Unscored'])
        expect(wrapper.get('[data-testid="automatic-assessment-filter-count"]').text())
            .toContain('Showing 3 of 3 candidates')

        const affectedRow = wrapper.get('[data-testid="bulk-workflow-item-CVE-AFFECTED"]').text()
        expect(affectedRow).toContain('2 analysis runs')
        expect(affectedRow).toContain('2 team assessments: TEAM-API, TEAM-WORKER')
        expect(affectedRow).toContain('no team for orphan-lib')
        expect(wrapper.get('[data-testid="bulk-workflow-item-CVE-SAFE"]').text())
            .toContain('global assessment only')

        await wrapper.get('[data-testid="automatic-outcome-filter-probably_affected"]').trigger('click')
        expect(wrapper.find('[data-testid="bulk-workflow-item-CVE-AFFECTED"]').exists()).toBe(false)
        expect(wrapper.find('[data-testid="bulk-workflow-item-CVE-PROBABLE"]').exists()).toBe(true)
        expect(wrapper.get('[data-testid="bulk-workflow-apply"]').text()).toContain('(1)')

        await wrapper.get('[data-testid="automatic-rescore-filter-low"]').trigger('click')
        expect(wrapper.find('[data-testid="automatic-assessment-filter-empty"]').exists()).toBe(true)
        expect(wrapper.get('[data-testid="bulk-workflow-apply"]').attributes('disabled')).toBeDefined()

        await wrapper.get('[data-testid="automatic-outcome-filter-affected"]').trigger('click')
        expect(wrapper.get('[data-testid="automatic-outcome-filter-affected"]').attributes('aria-pressed')).toBe('true')
        expect(wrapper.get('[data-testid="automatic-outcome-filter-probably_affected"]').attributes('aria-pressed')).toBe('true')
        expect(wrapper.find('[data-testid="bulk-workflow-item-CVE-AFFECTED"]').exists()).toBe(true)
        expect(wrapper.find('[data-testid="bulk-workflow-item-CVE-PROBABLE"]').exists()).toBe(false)
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

    it('labels each repair and shows the original and fixed CVSS vector', async () => {
        const repairWorkflow = {
            ...workflow,
            id: 'assessment-repair',
            label: 'Repair Assessments',
        }
        mocks.getBulkWorkflowSummary.mockResolvedValue({
            task_id: 'task-1',
            workflows: [{ ...repairWorkflow, candidate_count: null, summary: {} }],
        })
        mocks.previewBulkWorkflow.mockResolvedValue({
            task_id: 'task-1',
            workflow: repairWorkflow,
            preview_token: 'preview-repair',
            selectable_group_ids: ['CVE-2026-RULE'],
            notes: ['Rescoring repair skipped: invalid rule'],
            items: [{
                group_id: 'CVE-2026-RULE',
                finding_count: 3,
                repairable: true,
                repairs: [
                    { id: 'sync_findings', label: 'Synchronize assessment to 1 finding' },
                    { id: 'former_teams', label: 'Keep former team assessment as historical: TeamA' },
                    { id: 'rescoring', label: 'Repair rescoring on 1 finding' },
                ],
                review: ['CVSS vector not recoverable on 1 finding'],
                rescore_findings: [{
                    state: 'NOT_AFFECTED',
                    cvss_version: '3.1',
                    status: 'ready',
                    reasons: ['Missing requirements: AR, CR, IR'],
                    current_score: 9.8,
                    proposed_score: 0,
                    current_vector: 'CVSS:3.1/AV:N/MC:N',
                    proposed_vector: 'CVSS:3.1/AV:N/CR:L/IR:L/AR:L/MC:N',
                }],
            }, {
                group_id: 'CVE-2026-MANUAL',
                finding_count: 0,
                repairable: false,
                repairs: [],
                review: ['Rescoring needs manual review on 2 findings'],
                rescore_findings: [],
            }],
            summary: { groups: 2 },
        })
        const wrapper = mount(BulkWorkflowModal, {
            props: { show: false, taskId: 'task-1' },
        })

        await wrapper.setProps({ show: true })
        await flushPromises()
        await wrapper.get('[data-testid="bulk-workflow-assessment-repair"]').trigger('click')
        await flushPromises()

        const labels = wrapper.get('[data-testid="repair-labels-CVE-2026-RULE"]').text()
        expect(labels).toContain('Synchronize assessment to 1 finding')
        expect(labels).toContain('Keep former team assessment as historical: TeamA')
        expect(labels).toContain('Repair rescoring on 1 finding')
        expect(labels).toContain('CVSS vector not recoverable on 1 finding')
        const repairable = wrapper.get('[data-testid="bulk-workflow-item-CVE-2026-RULE"]').text()
        expect(repairable).toContain('3 findings will be updated')
        expect(repairable).toContain('Ready')
        const manual = wrapper.get('[data-testid="bulk-workflow-item-CVE-2026-MANUAL"]').text()
        expect(manual).toContain('Rescoring needs manual review on 2 findings')
        expect(manual).toContain('No automatic repair available')
        expect(wrapper.find('[data-testid="rescore-rule-change-CVE-2026-MANUAL"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="bulk-workflow-note"]').text())
            .toContain('Rescoring repair skipped: invalid rule')

        const change = wrapper.get('[data-testid="rescore-rule-change-CVE-2026-RULE"]')
        expect(change.text()).toContain('Original')
        expect(change.text()).toContain('Score 9.8')
        expect(change.text()).toContain('CVSS:3.1/AV:N/MC:N')
        expect(change.text()).toContain('Fixed')
        expect(change.text()).toContain('Score 0.0')
        expect(change.text()).toContain('CVSS:3.1/AV:N/CR:L/IR:L/AR:L/MC:N')
        expect(wrapper.get('[data-testid="rescore-rule-reasons-CVE-2026-RULE"]').text())
            .toContain('Missing requirements: AR, CR, IR')
    })

    it('leaves review-first repairs unselected and toggles selection by topic', async () => {
        const repairWorkflow = { ...workflow, id: 'assessment-repair', label: 'Repair Assessments' }
        const item = (group_id: string, repairId: string, requires_review: boolean) => ({
            group_id,
            finding_count: 1,
            repairable: true,
            requires_review,
            repairs: [{ id: repairId, label: repairId }],
            review: [],
            rescore_findings: [],
        })
        mocks.getBulkWorkflowSummary.mockResolvedValue({
            task_id: 'task-1',
            workflows: [{ ...repairWorkflow, candidate_count: null, summary: {} }],
        })
        mocks.previewBulkWorkflow.mockResolvedValue({
            task_id: 'task-1',
            workflow: repairWorkflow,
            preview_token: 'preview-repair',
            selectable_group_ids: ['CVE-SYNC-1', 'CVE-SYNC-2', 'CVE-CONFLICT'],
            topics: [
                { id: 'sync_findings', label: 'Synchronize', groups: 2 },
                { id: 'combine_conflict', label: 'Combine conflicts', groups: 1 },
            ],
            items: [
                item('CVE-SYNC-1', 'sync_findings', false),
                item('CVE-SYNC-2', 'sync_findings', false),
                item('CVE-CONFLICT', 'combine_conflict', true),
            ],
            summary: { groups: 3 },
        })
        mocks.applyBulkWorkflow.mockResolvedValue({
            task_id: 'task-1', workflow: repairWorkflow, summary: { succeeded: 1 }, results: [],
        })
        const wrapper = mount(BulkWorkflowModal, { props: { show: false, taskId: 'task-1' } })
        await wrapper.setProps({ show: true })
        await flushPromises()
        await wrapper.get('[data-testid="bulk-workflow-assessment-repair"]').trigger('click')
        await flushPromises()

        const button = (id: string) => wrapper.get(`[data-testid="bulk-workflow-select-${id}"]`)
        expect(button('sync_findings').text()).toContain('Synchronize · 2/2')
        expect(button('combine_conflict').text()).toContain('Combine conflicts · 0/1')
        expect(button('review-first').text()).toContain('Needs review · 0/1')
        expect(wrapper.get('[data-testid="bulk-workflow-item-CVE-CONFLICT"]').text()).toContain('Review first')
        expect(wrapper.get('[data-testid="bulk-workflow-item-CVE-SYNC-1"]').text()).toContain('Ready')

        await button('review-first').trigger('click')
        expect(button('review-first').text()).toContain('1/1')
        expect(button('combine_conflict').text()).toContain('1/1')
        await button('sync_findings').trigger('click')
        expect(button('sync_findings').text()).toContain('0/2')

        await wrapper.get('[data-testid="bulk-workflow-apply"]').trigger('click')
        await flushPromises()
        expect(mocks.applyBulkWorkflow.mock.calls[0][3]).toEqual(['CVE-CONFLICT'])
    })

    it('reuses a prepared preview when returning to a workflow', async () => {
        const secondWorkflow = { ...workflow, id: 'automatic-assessments', label: 'Restore CVSS' }
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

        await wrapper.get('[data-testid="bulk-workflow-assessment-repair"]').trigger('click')
        await flushPromises()
        await wrapper.get('[data-testid="bulk-workflow-automatic-assessments"]').trigger('click')
        await flushPromises()
        await wrapper.get('[data-testid="bulk-workflow-assessment-repair"]').trigger('click')
        await flushPromises()

        expect(mocks.previewBulkWorkflow).toHaveBeenCalledTimes(2)
    })

    describe('restore from an export', () => {
        const restoreWorkflow = {
            ...workflow,
            id: 'team-assessment-restore',
            label: 'Restore Team Assessments From Export',
            requires_source: true,
            source_kind: 'dependency-track-vdr',
        }
        const upload = (sourceId: string, sha: string) => ({
            source_id: sourceId,
            entries: 3,
            team_blocks: 5,
            summary: {
                tool: 'Dependency-Track', tool_version: '4.99.0', spec_version: '1.5',
                project_uuid: 'proj-1', project_name: 'App', project_version: '1.0',
                timestamp: '2030-01-03T00:00:00Z', sha256: sha, warnings: ['Not from Dependency-Track.'],
            },
        })
        const restorePreview = (token: string) => ({
            task_id: 'task-1',
            workflow: restoreWorkflow,
            preview_token: token,
            selectable_group_ids: ['CVE-2099-0001', 'CVE-2099-0002'],
            items: [{
                group_id: 'CVE-2099-0001',
                finding_count: 1,
                restore_count: 2,
                status: 'Ready',
                requires_review: false,
                review: [],
                notes: [{ kind: 'present_ticket_missing', team: 'TeamA', tickets: ['ABC-1'] }],
                blocks: [
                    { team: 'TeamB', state: 'NOT_AFFECTED', date: '2030-01-01', assessed_by: 'bob',
                      ticket: 'ABC-2', match: 'uuid', component_name: 'lib-a', component_version: '1.0',
                      project_version: '1.0', text_excerpt: 'Not shipped.' },
                    { team: 'TeamC', state: 'NOT_AFFECTED', date: null, assessed_by: null,
                      ticket: null, match: 'uuid', component_name: 'lib-a', component_version: '1.0',
                      project_version: '1.0', text_excerpt: '' },
                ],
            }, {
                group_id: 'CVE-2099-0002',
                finding_count: 1,
                restore_count: 1,
                status: 'Review first',
                requires_review: true,
                review: ['A restored assessment has a worse state than the finding today'],
                notes: [],
                blocks: [],
            }, {
                // Notes only: listed, never selectable.
                group_id: 'CVE-2099-0003',
                finding_count: 0,
                restore_count: 0,
                status: 'Notes only',
                requires_review: false,
                review: [],
                notes: [{ kind: 'present_ticket_missing', team: 'TeamD', tickets: ['ABC-3'] }],
                blocks: [],
            }],
            summary: {
                groups: 2,
                notes_only_groups: 1,
                unmatched: { no_finding_in_view: 2, ambiguous: 1, other_project: 0 },
                unmatched_samples: [{ id: 'CVE-2099-0009', component_name: 'lib-z', component_version: '9', reason: 'ambiguous' }],
                unmatched_note: 'Entries can be unmatched because the finding is no longer reported or the current filters exclude it.',
            },
        })

        const choose = async (wrapper: any, name: string) => {
            const input = wrapper.get('[data-testid="bulk-workflow-source-input"]')
            Object.defineProperty(input.element, 'files', {
                value: [new File(['{}'], name, { type: 'application/json' })],
                configurable: true,
            })
            await input.trigger('change')
            await flushPromises()
        }

        beforeEach(() => {
            mocks.getBulkWorkflowSummary.mockResolvedValue({
                task_id: 'task-1',
                workflows: [
                    { ...workflow, candidate_count: null, summary: {} },
                    { ...restoreWorkflow, candidate_count: null, summary: {} },
                ],
            })
            mocks.uploadBulkWorkflowSource
                .mockReset()
                .mockResolvedValueOnce(upload('source-1', 'a'.repeat(64)))
                .mockResolvedValueOnce(upload('source-2', 'b'.repeat(64)))
            mocks.previewBulkWorkflow.mockImplementation(async (workflowId: string, _task, _filters, _progress, sourceId?: string) =>
                workflowId === restoreWorkflow.id
                    ? restorePreview(`token-${sourceId}`)
                    : {
                        task_id: 'task-1', workflow, preview_token: 'preview-1',
                        selectable_group_ids: [], items: [], summary: { groups: 0 },
                    })
        })

        it('asks for a file only for a workflow that reads one', async () => {
            const wrapper = mount(BulkWorkflowModal, { props: { show: false, taskId: 'task-1' } })
            await wrapper.setProps({ show: true })
            await flushPromises()

            await wrapper.get('[data-testid="bulk-workflow-assessment-repair"]').trigger('click')
            await flushPromises()
            expect(wrapper.find('[data-testid="bulk-workflow-source-input"]').exists()).toBe(false)

            await wrapper.get('[data-testid="bulk-workflow-team-assessment-restore"]').trigger('click')
            await flushPromises()
            expect(wrapper.find('[data-testid="bulk-workflow-source-input"]').exists()).toBe(true)
            expect(wrapper.find('[data-testid="bulk-workflow-source-empty-state"]').exists()).toBe(true)
            // No preview before a file is there.
            expect(mocks.previewBulkWorkflow).toHaveBeenCalledTimes(1)
            expect(wrapper.find('[data-testid="bulk-workflow-apply"]').exists()).toBe(false)
        })

        it('uploads, previews and applies with the source id', async () => {
            const wrapper = mount(BulkWorkflowModal, { props: { show: false, taskId: 'task-1' } })
            await wrapper.setProps({ show: true })
            await flushPromises()
            await wrapper.get('[data-testid="bulk-workflow-team-assessment-restore"]').trigger('click')
            await flushPromises()
            await choose(wrapper, 'export.json')

            expect(mocks.uploadBulkWorkflowSource).toHaveBeenCalledTimes(1)
            const summary = wrapper.get('[data-testid="bulk-workflow-source-summary"]').text()
            expect(summary).toContain('Dependency-Track 4.99.0')
            expect(summary).toContain('project App 1.0')
            expect(summary).toContain('aaaaaaaaaaaa')
            expect(summary).not.toContain('a'.repeat(13))
            expect(wrapper.get('[data-testid="bulk-workflow-source-warning"]').text()).toContain('Not from Dependency-Track.')
            expect(mocks.previewBulkWorkflow).toHaveBeenLastCalledWith(
                'team-assessment-restore', 'task-1', {}, expect.any(Function), 'source-1',
            )

            const row = wrapper.get('[data-testid="bulk-workflow-item-CVE-2099-0001"]').text()
            expect(row).toContain('2 team assessments on 1 findings')
            const blocks = wrapper.get('[data-testid="restore-blocks-CVE-2099-0001"]').text()
            expect(blocks).toContain('TeamB · NOT_AFFECTED · 2030-01-01 · bob · ABC-2')
            expect(blocks).toContain('TeamC · NOT_AFFECTED · undated')
            expect(blocks).toContain('matched by uuid')
            expect(blocks).toContain('Not shipped.')
            expect(wrapper.get('[data-testid="restore-review-CVE-2099-0002"]').text())
                .toContain('worse state')
            expect(wrapper.get('[data-testid="restore-review-CVE-2099-0001"]').text())
                .toContain('ABC-1 is named nowhere')
            // A vulnerability with notes only is shown but cannot be selected.
            const notesOnly = wrapper.get('[data-testid="bulk-workflow-item-CVE-2099-0003"]')
            expect(notesOnly.text()).toContain('Notes only; nothing to restore')
            expect(wrapper.get('[data-testid="restore-review-CVE-2099-0003"]').text())
                .toContain('ABC-3 is named nowhere')
            expect(notesOnly.classes()).toContain('opacity-60')
            await notesOnly.trigger('click')

            const unmatched = wrapper.get('[data-testid="bulk-workflow-unmatched"]').text()
            expect(unmatched).toContain('Unmatched entries · 3')
            expect(unmatched).toContain('2 no finding in view')
            expect(unmatched).toContain('1 ambiguous')
            expect(unmatched).toContain('CVE-2099-0009')
            expect(unmatched).toContain('no longer reported')

            // Review-first items start unselected.
            expect(wrapper.get('[data-testid="bulk-workflow-apply"]').text()).toContain('Apply selected (1)')
            mocks.applyBulkWorkflow.mockResolvedValueOnce({
                task_id: 'task-1', workflow: restoreWorkflow, results: [],
                summary: { attempted: 1, succeeded: 0, queued: 0, failed: 0, changed_since_preview: 1 },
            })
            await wrapper.get('[data-testid="bulk-workflow-apply"]').trigger('click')
            await flushPromises()
            expect(mocks.applyBulkWorkflow).toHaveBeenCalledWith(
                'team-assessment-restore', 'task-1', {}, ['CVE-2099-0001'], 'token-source-1',
                expect.any(Function), 'source-1',
            )
            // A finding saved after the preview is left as it is, and said so.
            expect(wrapper.get('[data-testid="bulk-workflow-changed-since-preview"]').text())
                .toContain('1 changed since the preview')
        })

        it('keys the preview cache by file and resets the preview for a new file', async () => {
            const wrapper = mount(BulkWorkflowModal, { props: { show: false, taskId: 'task-1' } })
            await wrapper.setProps({ show: true })
            await flushPromises()
            await wrapper.get('[data-testid="bulk-workflow-team-assessment-restore"]').trigger('click')
            await flushPromises()
            await choose(wrapper, 'first.json')
            expect(mocks.previewBulkWorkflow).toHaveBeenCalledTimes(1)

            // Back to the same workflow and file: the preview is reused.
            await wrapper.get('[data-testid="bulk-workflow-assessment-repair"]').trigger('click')
            await flushPromises()
            await wrapper.get('[data-testid="bulk-workflow-team-assessment-restore"]').trigger('click')
            await flushPromises()
            expect(mocks.previewBulkWorkflow).toHaveBeenCalledTimes(2)
            expect(wrapper.find('[data-testid="bulk-workflow-item-CVE-2099-0001"]').exists()).toBe(true)

            let release: (value: unknown) => void = () => {}
            mocks.uploadBulkWorkflowSource.mockReset().mockImplementationOnce(
                () => new Promise(resolve => { release = resolve }),
            )
            const input = wrapper.get('[data-testid="bulk-workflow-source-input"]')
            Object.defineProperty(input.element, 'files', {
                value: [new File(['{}'], 'second.json', { type: 'application/json' })],
                configurable: true,
            })
            await input.trigger('change')
            await flushPromises()
            // The preview of the first file is gone while the second is read.
            expect(wrapper.find('[data-testid="bulk-workflow-item-CVE-2099-0001"]').exists()).toBe(false)
            expect(wrapper.find('[data-testid="bulk-workflow-apply"]').exists()).toBe(false)

            release(upload('source-2', 'b'.repeat(64)))
            await flushPromises()
            expect(mocks.previewBulkWorkflow).toHaveBeenCalledTimes(3)
            expect(mocks.previewBulkWorkflow).toHaveBeenLastCalledWith(
                'team-assessment-restore', 'task-1', {}, expect.any(Function), 'source-2',
            )
        })

        it('shows an upload error', async () => {
            mocks.uploadBulkWorkflowSource.mockReset().mockRejectedValueOnce({
                response: { data: { detail: 'This is a DTVP export; restoring needs a Dependency-Track export.' } },
            })
            const wrapper = mount(BulkWorkflowModal, { props: { show: false, taskId: 'task-1' } })
            await wrapper.setProps({ show: true })
            await flushPromises()
            await wrapper.get('[data-testid="bulk-workflow-team-assessment-restore"]').trigger('click')
            await flushPromises()
            await choose(wrapper, 'dtvp.json')
            expect(wrapper.get('[data-testid="bulk-workflow-error"]').text()).toContain('This is a DTVP export')
            expect(mocks.previewBulkWorkflow).not.toHaveBeenCalled()
        })
    })
})
