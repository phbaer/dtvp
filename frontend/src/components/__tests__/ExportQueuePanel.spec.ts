import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ExportQueuePanel from '../ExportQueuePanel.vue'
import * as api from '../../lib/api'

vi.mock('../../lib/api', () => ({
    discardExports: vi.fn(),
    exportAssessments: vi.fn(),
    getExportQueue: vi.fn(),
    getExportTexts: vi.fn(),
}))

const item = (overrides: Record<string, unknown> = {}) => ({
    update_id: 'u1',
    project_uuid: 'p1',
    component_uuid: 'c1',
    vulnerability_uuid: 'v1',
    project_known: true,
    project_name: 'TestApp',
    project_version: '1.0',
    component_name: 'library-a',
    component_version: '2.0',
    vulnerability_id: 'CVE-2026-0001',
    revision: 1,
    status: 'pending',
    queued_at: '2026-11-17T08:00:00+00:00',
    updated_at: '2026-11-17T08:00:00+00:00',
    attempts: 0,
    last_error: null,
    author: 'rita',
    origin: 'individual-assessment',
    // The list carries no texts; they are loaded when an entry is opened.
    local: { analysisState: 'NOT_AFFECTED', isSuppressed: false },
    source: { analysisState: 'IN_TRIAGE', isSuppressed: false },
    ...overrides,
})

const queue = (pending: any[], mode: 'auto' | 'manual' = 'manual') => ({
    mode,
    pending,
})

const mountPanel = async () => {
    const wrapper = mount(ExportQueuePanel)
    await flushPromises()
    return wrapper
}

describe('ExportQueuePanel', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('says so when nothing is waiting and explains the mode', async () => {
        vi.mocked(api.getExportQueue).mockResolvedValue(queue([], 'auto'))
        const wrapper = await mountPanel()

        expect(wrapper.get('[data-testid="export-empty"]').text()).toContain('Nothing is waiting')
        expect(wrapper.get('[data-testid="export-mode"]').text()).toContain('exported automatically')
        expect(wrapper.get('[data-testid="export-all"]').attributes('disabled')).toBeDefined()
    })

    it('lists each change with what it replaces', async () => {
        vi.mocked(api.getExportQueue).mockResolvedValue(queue([item()]))
        const wrapper = await mountPanel()

        expect(wrapper.get('[data-testid="export-mode"]').text()).toContain('Manual export is on')
        const row = wrapper.get('[data-testid="export-row"]')
        expect(row.text()).toContain('CVE-2026-0001')
        expect(row.text()).toContain('TestApp 1.0 · library-a@2.0')
        expect(row.text()).toContain('IN_TRIAGE')
        expect(row.text()).toContain('NOT_AFFECTED')
        expect(row.text()).toContain('rita')
        expect(wrapper.find('[data-testid="export-detail"]').exists()).toBe(false)

        expect(api.getExportTexts).not.toHaveBeenCalled()
        vi.mocked(api.getExportTexts).mockResolvedValue({
            update_id: 'u1',
            local: { analysisState: 'NOT_AFFECTED', analysisDetails: 'Local text', isSuppressed: false },
            source: { analysisState: 'IN_TRIAGE', analysisDetails: 'Source text', isSuppressed: false },
        })
        await wrapper.get('[data-testid="export-toggle"]').trigger('click')
        await flushPromises()
        const detail = wrapper.get('[data-testid="export-detail"]')
        expect(api.getExportTexts).toHaveBeenCalledWith('u1')
        expect(detail.text()).toContain('Source text')
        expect(detail.text()).toContain('Local text')
    })

    it('says so when an entry has no known previous value or its texts cannot be loaded', async () => {
        vi.mocked(api.getExportQueue).mockResolvedValue(queue([item({ source: null }), item({ update_id: 'u2' })]))
        vi.mocked(api.getExportTexts).mockImplementation(async (id: string) => {
            if (id === 'u2') throw new Error('down')
            return { update_id: id, local: { analysisState: 'NOT_AFFECTED', analysisDetails: '', isSuppressed: false }, source: null }
        })
        const wrapper = await mountPanel()

        const toggles = wrapper.findAll('[data-testid="export-toggle"]')
        await toggles[0].trigger('click')
        await toggles[1].trigger('click')
        await flushPromises()

        const details = wrapper.findAll('[data-testid="export-detail"]')
        expect(details[0].text()).toContain('Not known')
        expect(details[0].text()).toContain('(No details)')
        expect(details[1].text()).toContain('The text could not be loaded.')
    })

    it('exports one change or all of them and reports the outcome', async () => {
        vi.mocked(api.getExportQueue).mockResolvedValue(queue([item(), item({ update_id: 'u2' })]))
        vi.mocked(api.exportAssessments).mockResolvedValue({ exported: 1, dropped: 0, remaining: 1, failed: [] })
        const wrapper = await mountPanel()

        await wrapper.findAll('[data-testid="export-one"]')[1]!.trigger('click')
        await flushPromises()
        expect(api.exportAssessments).toHaveBeenLastCalledWith(['u2'])
        expect(wrapper.get('[data-testid="export-notice"]').text()).toBe('1 exported.')
        expect(api.getExportQueue).toHaveBeenCalledTimes(2)

        expect(wrapper.get('[data-testid="export-all"]').text()).toContain('Export all (2)')
        await wrapper.get('[data-testid="export-all"]').trigger('click')
        await flushPromises()
        expect(api.exportAssessments).toHaveBeenLastCalledWith(undefined)
    })

    it('offers every entry for export, also when Dependency-Track holds a different value', async () => {
        vi.mocked(api.getExportQueue).mockResolvedValue(queue([item({ status: 'error', last_error: 'not kept' }), item({ update_id: 'u2' })]))
        const wrapper = await mountPanel()

        expect(wrapper.find('[data-testid="export-conflicts"]').exists()).toBe(false)
        expect(wrapper.findAll('[data-testid="export-one"]')).toHaveLength(2)
        expect(wrapper.get('[data-testid="export-all"]').text()).toContain('Export all (2)')
        expect(wrapper.findAll('[data-testid="export-row"]')[0]!.text()).not.toContain('Conflict')
    })

    it('shows why an export is stuck and lets a reviewer discard it', async () => {
        const stuck = item({
            update_id: 'gone',
            status: 'error',
            attempts: 15441,
            project_known: false,
            project_name: 'Imaging Suite',
            project_version: '4.2',
            project_last_seen_at: '2026-11-01T10:00:00+00:00',
            queued_at: '2026-11-02T04:31:29+00:00',
            last_error: "Client error '404 Not Found' for url 'http://dt/api/v1/analysis'",
        })
        const retrying = item({ update_id: 'retry', status: 'error', attempts: 2, last_error: 'timeout' })
        vi.mocked(api.getExportQueue).mockResolvedValue(queue([stuck, retrying, item({ update_id: 'ok' })]))
        vi.mocked(api.discardExports).mockResolvedValue({ discarded: 1, remaining: 2 })
        const wrapper = await mountPanel()

        const rows = wrapper.findAll('[data-testid="export-row"]')
        expect(rows[0]!.text()).toContain('Stuck')
        // The product and version stay known after the project is deleted.
        expect(rows[0]!.text()).toContain('Imaging Suite 4.2 · library-a@2.0')
        expect(rows[0]!.get('[data-testid="export-project-gone"]').text()).toMatch(/Project deleted in Dependency-Track, last seen .*2026/)
        expect(rows[1]!.find('[data-testid="export-project-gone"]').exists()).toBe(false)
        expect(rows[0]!.text()).toContain('15441 attempts')
        expect(rows[0]!.text()).toMatch(/waiting \d+ days/)
        expect(rows[1]!.text()).toContain('Failed, will retry')
        const failures = wrapper.findAll('[data-testid="export-failure"]')
        expect(failures[0]!.text()).toContain('no longer in Dependency-Track')
        expect(failures[0]!.text()).toContain("404 Not Found")
        expect(failures[1]!.text()).toContain('timeout')
        expect(failures[1]!.text()).not.toContain('discard it')

        const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
        await wrapper.findAll('[data-testid="export-discard"]')[0]!.trigger('click')
        expect(api.discardExports).not.toHaveBeenCalled()

        confirm.mockReturnValue(true)
        await wrapper.findAll('[data-testid="export-discard"]')[0]!.trigger('click')
        await flushPromises()
        expect(api.discardExports).toHaveBeenLastCalledWith(['gone'])
        expect(wrapper.get('[data-testid="export-notice"]').text()).toBe('1 discarded.')

        expect(wrapper.get('[data-testid="export-discard-failing"]').text()).toContain('Discard failing (2)')
        await wrapper.get('[data-testid="export-discard-failing"]').trigger('click')
        await flushPromises()
        expect(api.discardExports).toHaveBeenLastCalledWith(['gone', 'retry'])
        confirm.mockRestore()
    })

    it('reports failures from the export and from loading', async () => {
        vi.mocked(api.getExportQueue).mockResolvedValue(queue([item({ status: 'error', last_error: 'timeout' })]))
        vi.mocked(api.exportAssessments).mockResolvedValue({
            exported: 0, dropped: 1, remaining: 1,
            failed: [{ update_id: 'u1', status: 'error', error: 'Dependency-Track answered 503' }],
        })
        const wrapper = await mountPanel()
        expect(wrapper.get('[data-testid="export-row"]').text()).toContain('Failed, will retry')

        await wrapper.get('[data-testid="export-all"]').trigger('click')
        await flushPromises()
        expect(wrapper.get('[data-testid="export-notice"]').text()).toBe('0 exported, 1 no longer in Dependency-Track, 1 failed.')
        expect(wrapper.get('[role="alert"]').text()).toContain('Dependency-Track answered 503')

        vi.mocked(api.getExportQueue).mockRejectedValue({ response: { data: { detail: 'Only reviewers' } } })
        const failing = await mountPanel()
        expect(failing.get('[role="alert"]').text()).toContain('Only reviewers')
    })
})
