import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import CodeAnalysisJobDiagnostics from '../CodeAnalysisJobDiagnostics.vue'
import { codeAnalysisDownloadDiagnostics } from '../../lib/api'
vi.mock('../../lib/api', () => ({ codeAnalysisDownloadDiagnostics: vi.fn() }))
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
})
