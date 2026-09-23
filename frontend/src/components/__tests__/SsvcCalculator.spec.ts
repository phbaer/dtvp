import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import model from '../../../../dtvp/resources/ssvc/deployer-1.0.0.json'
import SsvcCalculator from '../SsvcCalculator.vue'
import { getSsvcExploitation, getSsvcModels } from '../../lib/api'
import type { SsvcEnrichment, SsvcSelection } from '../../lib/ssvc'

vi.mock('../../lib/api', () => ({ getSsvcModels: vi.fn(), getSsvcExploitation: vi.fn() }))

const evidence: SsvcEnrichment = {
    enabled: true, auto_fill: true, retry_after: 60,
    suggestion: { value: 'A', source: 'CISA KEV', cve: 'CVE-2024-25522', url: 'https://www.cisa.gov/',
        assessed_at: '2024-05-24', checked_at: '2026-09-21', stale: false, token: 'signed-evidence' },
    sources: [{ source: 'CISA KEV', cve: 'CVE-2024-25522', url: 'https://www.cisa.gov/', status: 'ok', checked_at: '2026-09-21', assessed_at: '2024-05-24' }],
}
const selected: SsvcSelection = { model: 'ssvc:DT_DP', version: '1.0.0', answers: { 'ssvc:E:1.1.0': 'N' }, rationale: '' }
const wrappers: ReturnType<typeof mount>[] = []
afterEach(() => { wrappers.splice(0).forEach(wrapper => wrapper.unmount()); vi.useRealTimers() })

describe('SsvcCalculator', () => {
    it('renders bundled definitions and calculates locally, without prefilled answers', async () => {
        vi.mocked(getSsvcModels).mockResolvedValue([model])
        const wrapper = mount(SsvcCalculator, { props: { modelValue: null } })
        wrappers.push(wrapper)
        await flushPromises()
        expect(wrapper.findAll('select')).toHaveLength(4)
        expect(wrapper.get('[role="status"]').text()).toContain('Incomplete')
        expect(wrapper.text()).toContain('credible public reporting')
        const values = ['A', 'O', 'Y', 'VH']
        for (const [index, select] of wrapper.findAll('select').entries()) {
            await select.setValue(values[index])
            const value = wrapper.emitted('update:modelValue')!.at(-1)![0] as SsvcSelection
            await wrapper.setProps({ modelValue: value })
        }
        expect(wrapper.get('[role="status"]').text()).toBe('Priority: Immediate')
        await wrapper.get('textarea').setValue('Deployment rationale')
        expect(wrapper.emitted('update:modelValue')!.at(-1)![0]).toMatchObject({ rationale: 'Deployment rationale' })
        expect(getSsvcModels).toHaveBeenCalledTimes(1)
        expect(wrapper.findAll('a').at(-1)!.attributes('href')).toBe(model.calculator)
        await wrapper.get('button').trigger('click')
        expect(wrapper.emitted('update:modelValue')!.at(-1)).toEqual([null])
    })

    it('handles unavailable rules and retry', async () => {
        vi.mocked(getSsvcModels).mockRejectedValueOnce(new Error('offline')).mockResolvedValue([model])
        const wrapper = mount(SsvcCalculator, { props: { modelValue: null } })
        wrappers.push(wrapper)
        await flushPromises()
        expect(wrapper.get('[role="alert"]').text()).toContain('Could not load')
        await wrapper.get('button').trigger('click')
        await flushPromises()
        expect(wrapper.findAll('select')).toHaveLength(4)
    })

    it('fetches only on opening, prefills once, and enforces refresh cooldown', async () => {
        vi.useFakeTimers()
        vi.mocked(getSsvcModels).mockResolvedValue([model])
        vi.mocked(getSsvcExploitation).mockResolvedValue(evidence)
        const wrapper = mount(SsvcCalculator, { props: { modelValue: null, cves: ['GHSA-abcd', 'CVE-2024-25522'], active: false } })
        wrappers.push(wrapper)
        await flushPromises()
        expect(getSsvcExploitation).not.toHaveBeenCalled()
        await wrapper.setProps({ active: true })
        await flushPromises()
        expect(getSsvcExploitation).toHaveBeenCalledWith(['CVE-2024-25522'], false)
        const selection = wrapper.emitted('update:modelValue')!.at(-1)![0] as SsvcSelection
        expect(selection).toMatchObject({ answers: { 'ssvc:E:1.1.0': 'A' }, exploitation_evidence: 'signed-evidence' })
        await wrapper.setProps({ modelValue: selection })
        expect(wrapper.get('[data-testid="ssvc-refresh"]').attributes('disabled')).toBeDefined()
        await wrapper.findAll('select')[1]!.setValue('O')
        expect(wrapper.emitted('update:modelValue')!.at(-1)![0]).toMatchObject({ exploitation_evidence: 'signed-evidence' })
        await wrapper.get('textarea').setValue('Context')
        expect(wrapper.emitted('update:modelValue')!.at(-1)![0]).toMatchObject({ exploitation_evidence: 'signed-evidence' })
        await vi.advanceTimersByTimeAsync(60000)
        await wrapper.get('[data-testid="ssvc-refresh"]').trigger('click')
        await flushPromises()
        expect(getSsvcExploitation).toHaveBeenLastCalledWith(['CVE-2024-25522'], true)
        await wrapper.findAll('select')[0]!.setValue('P')
        expect(wrapper.emitted('update:modelValue')!.at(-1)![0]).toMatchObject({ exploitation_evidence: null })
    })

    it('never overwrites an existing answer and requires explicit acceptance', async () => {
        vi.mocked(getSsvcModels).mockResolvedValue([model])
        vi.mocked(getSsvcExploitation).mockResolvedValue(evidence)
        const wrapper = mount(SsvcCalculator, { props: { modelValue: selected, cves: ['CVE-2024-25522'] } })
        wrappers.push(wrapper)
        await flushPromises()
        expect(wrapper.emitted('update:modelValue')).toBeUndefined()
        await wrapper.get('[data-testid="ssvc-use-suggestion"]').trigger('click')
        expect(wrapper.emitted('update:modelValue')!.at(-1)![0]).toMatchObject({ answers: { 'ssvc:E:1.1.0': 'A' } })
        expect(wrapper.text()).toContain('source assessment 2024-05-24')
    })

    it('does not refill a manual clear while the fetch is in flight', async () => {
        vi.mocked(getSsvcModels).mockResolvedValue([model])
        let resolve!: (value: SsvcEnrichment) => void
        vi.mocked(getSsvcExploitation).mockReturnValue(new Promise(done => { resolve = done }))
        const wrapper = mount(SsvcCalculator, { props: { modelValue: selected, cves: ['CVE-2024-25522'] } })
        wrappers.push(wrapper)
        await flushPromises()
        await wrapper.get('button').trigger('click')
        await wrapper.setProps({ modelValue: null })
        resolve(evidence)
        await flushPromises()
        expect(wrapper.emitted('update:modelValue')).toEqual([[null]])
    })

    it('requires manual acceptance of stale evidence and respects parent draft guards', async () => {
        vi.mocked(getSsvcModels).mockResolvedValue([model])
        vi.mocked(getSsvcExploitation).mockResolvedValue({ ...evidence, auto_fill: false, suggestion: { ...evidence.suggestion!, stale: true } })
        const wrapper = mount(SsvcCalculator, { props: { modelValue: null, cves: ['CVE-2024-25522'] } })
        wrappers.push(wrapper)
        await flushPromises()
        expect(wrapper.emitted('update:modelValue')).toBeUndefined()
        expect(wrapper.text()).toContain('stale evidence')
        vi.mocked(getSsvcExploitation).mockResolvedValue(evidence)
        const guarded = mount(SsvcCalculator, { props: { modelValue: null, cves: ['CVE-2024-25522'], allowAutofill: false } })
        wrappers.push(guarded)
        await flushPromises()
        expect(guarded.emitted('update:modelValue')).toBeUndefined()
    })

    it('ignores responses for a previous vulnerability', async () => {
        vi.mocked(getSsvcModels).mockResolvedValue([model])
        let resolve!: (value: SsvcEnrichment) => void
        vi.mocked(getSsvcExploitation).mockReturnValueOnce(new Promise(done => { resolve = done }))
        const wrapper = mount(SsvcCalculator, { props: { modelValue: null, cves: ['CVE-2024-25522'] } })
        wrappers.push(wrapper)
        await flushPromises()
        await wrapper.setProps({ cves: [] })
        resolve(evidence)
        await flushPromises()
        expect(wrapper.emitted('update:modelValue')).toBeUndefined()
        expect(wrapper.text()).toContain('No CVE identifier')
    })

    it('shows fetch errors without changing answers', async () => {
        vi.mocked(getSsvcModels).mockResolvedValue([model])
        vi.mocked(getSsvcExploitation).mockRejectedValue(new Error('offline'))
        const wrapper = mount(SsvcCalculator, { props: { modelValue: null, cves: ['CVE-2024-25522'] } })
        wrappers.push(wrapper)
        await flushPromises()
        expect(wrapper.get('[role="alert"]').text()).toContain('Exploitation is unchanged')
        expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    })

    it('does not silently drop aliases to fit the lookup limit', async () => {
        vi.mocked(getSsvcModels).mockResolvedValue([model])
        const wrapper = mount(SsvcCalculator, { props: { modelValue: null,
            cves: Array.from({ length: 21 }, (_, index) => `CVE-2024-${1000 + index}`) } })
        wrappers.push(wrapper)
        await flushPromises()
        expect(getSsvcExploitation).not.toHaveBeenCalled()
        expect(wrapper.text()).toContain('More than 20 CVE aliases')
        expect(wrapper.find('[data-testid="ssvc-refresh"]').exists()).toBe(false)
    })
})
