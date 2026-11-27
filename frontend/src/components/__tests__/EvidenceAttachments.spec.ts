import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import EvidenceAttachments from '../EvidenceAttachments.vue'
const api = vi.hoisted(() => ({ upload: vi.fn(), download: vi.fn() }))
vi.mock('../../lib/api', () => ({ uploadCodeEvidenceAttachment: api.upload, downloadCodeEvidenceMaterial: api.download }))
const file = { attachment_id:'att_1', filename:'report.md', version:1, size:4, sha256:'abc', uploaded_by:'alice', uploaded_at:'2026-11-26T10:00:00Z' }
const evidence = { evidence_id:'ev_1', attachments:[file] } as any
beforeEach(() => { vi.resetAllMocks(); api.upload.mockResolvedValue({}); api.download.mockResolvedValue(undefined) })
describe('EvidenceAttachments', () => {
    it('downloads file versions and packages without exposing file paths', async () => {
        const wrapper = mount(EvidenceAttachments, { props:{ evidence, canUpload:false } })
        await wrapper.findAll('button')[0]!.trigger('click')
        expect(api.download).toHaveBeenCalledWith('ev_1', undefined)
        await wrapper.findAll('button')[1]!.trigger('click')
        expect(api.download).toHaveBeenCalledWith('ev_1', file)
        expect(wrapper.find('input[type=file]').exists()).toBe(false)
    })
    it('uploads a replacement as a new version and refreshes the reader', async () => {
        const wrapper = mount(EvidenceAttachments, { props:{ evidence, canUpload:true } })
        const input = wrapper.get('input[type=file]')
        const upload = new File(['updated'], 'report.md', { type:'text/markdown' })
        Object.defineProperty(input.element, 'files', { value:[upload] })
        await wrapper.get('input[maxlength]').setValue('Updated test observation')
        await input.trigger('change'); await flushPromises()
        expect(api.upload).toHaveBeenCalledWith('ev_1', upload, 'Updated test observation', 'att_1')
        expect(wrapper.emitted('changed')).toHaveLength(1)
    })
    it('keeps an upload error visible and does not claim a successful refresh', async () => {
        api.upload.mockRejectedValue({ response:{ data:{ detail:'Evidence is withdrawn' } } })
        const wrapper = mount(EvidenceAttachments, { props:{ evidence, canUpload:true } })
        const input = wrapper.get('input[type=file]')
        Object.defineProperty(input.element, 'files', { value:[new File(['data'], 'new.txt')] })
        await input.trigger('change'); await flushPromises()
        expect(wrapper.get('[role=alert]').text()).toContain('Evidence is withdrawn')
        expect(wrapper.emitted('changed')).toBeUndefined()
    })
})
