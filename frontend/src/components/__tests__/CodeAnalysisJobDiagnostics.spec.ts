import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import CodeAnalysisJobDiagnostics from '../CodeAnalysisJobDiagnostics.vue'
import { codeAnalysisDownloadDiagnostics, codeAnalysisDownloadReport, codeAnalysisGetResult } from '../../lib/api'
vi.mock('../../lib/api', () => ({ codeAnalysisDownloadDiagnostics: vi.fn(), codeAnalysisDownloadReport: vi.fn(), codeAnalysisGetResult: vi.fn() }))
describe('analyzer diagnostics', () => {
    beforeEach(() => vi.clearAllMocks())
    it('shows and copies the assigned ID with saved safe error details', async () => {
        const copy = vi.fn().mockResolvedValue(undefined)
        Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: copy } })
        const wrapper = mount(CodeAnalysisJobDiagnostics, { props: { jobId: 'job1', errorDetails: { code: 'llm_unavailable', retryable: true } } })
        await wrapper.findAll('button')[0]!.trigger('click')
        expect(copy).toHaveBeenCalledWith('job1')
        expect(wrapper.text()).toContain('llm_unavailable')
    })
    it('explains missing remote jobs while retaining saved details', async () => {
        vi.mocked(codeAnalysisDownloadDiagnostics).mockRejectedValue({ response: { status: 404 } })
        const wrapper = mount(CodeAnalysisJobDiagnostics, { props: { jobId: 'job1', errorDetails: { code: 'llm_timeout' } } })
        await wrapper.findAll('button')[1]!.trigger('click'); await flushPromises()
        expect(wrapper.text()).toContain('another analyzer instance')
        expect(wrapper.text()).toContain('llm_timeout')
    })
    it('downloads the authenticated response as an attachment', async () => {
        vi.mocked(codeAnalysisDownloadDiagnostics).mockResolvedValue(new Blob(['{}']))
        URL.createObjectURL = vi.fn().mockReturnValue('blob:test')
        URL.revokeObjectURL = vi.fn()
        vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
        const wrapper = mount(CodeAnalysisJobDiagnostics, { props: { jobId: 'job1' } })
        await wrapper.findAll('button')[1]!.trigger('click'); await flushPromises()
        expect(codeAnalysisDownloadDiagnostics).toHaveBeenCalledWith('job1')
        expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:test')
    })
    it('downloads saved history reports without contacting an expired analyzer job', async () => {
        vi.mocked(codeAnalysisGetResult).mockResolvedValue({ result: { assessment: { report_markdown: '# Saved assessment' } } } as any)
        URL.createObjectURL = vi.fn().mockReturnValue('blob:report')
        URL.revokeObjectURL = vi.fn()
        vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
        const wrapper = mount(CodeAnalysisJobDiagnostics, { props: { jobId: 'oldjob', analysisRunId: 'run1', status: 'completed' } })
        await wrapper.get('[data-testid="download-assessment-report"]').trigger('click')
        await flushPromises()
        expect(codeAnalysisGetResult).toHaveBeenCalledWith('run1')
        expect(codeAnalysisDownloadReport).not.toHaveBeenCalled()
        expect(wrapper.text()).toContain('Assessment report downloaded')
    })
    it('explains reports missing from older analyzers', async () => {
        vi.mocked(codeAnalysisDownloadReport).mockRejectedValue({ response: { status: 409 } })
        const wrapper = mount(CodeAnalysisJobDiagnostics, { props: { jobId: 'job1', status: 'completed' } })
        await wrapper.get('[data-testid="download-assessment-report"]').trigger('click')
        await flushPromises()
        expect(wrapper.text()).toContain('predate Markdown reports')
    })

})
