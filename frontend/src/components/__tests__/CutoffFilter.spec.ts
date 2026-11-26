import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import CutoffFilter from '../CutoffFilter.vue'

describe('CutoffFilter', () => {
    it('sets a date, a rolling preset and the mode, and shows the unknown count', async () => {
        const wrapper = mount(CutoffFilter, { props: { cutoff: '', mode: 'before' } })
        expect(wrapper.find('[data-testid="cutoff-clear"]').exists()).toBe(false)
        await wrapper.get('[data-testid="cutoff-date"]').setValue('2026-03-01')
        expect(wrapper.emitted('update:cutoff')?.[0]).toEqual(['2026-03-01'])
        await wrapper.get('[data-testid="cutoff-preset-14d"]').trigger('click')
        expect(wrapper.emitted('update:cutoff')?.[1]).toEqual(['14d'])
        await wrapper.get('[data-testid="cutoff-mode"]').setValue('after')
        expect(wrapper.emitted('update:mode')?.[0]).toEqual(['after'])

        await wrapper.setProps({ cutoff: '14d', count: 12, unknownCount: 3 })
        expect(wrapper.get('[data-testid="cutoff-preset-14d"]').attributes('aria-pressed')).toBe('true')
        expect(wrapper.text()).toContain('14 days before today')
        expect(wrapper.get('[data-testid="cutoff-count"]').text()).toBe('12')
        expect(wrapper.get('[data-testid="cutoff-unknown"]').text()).toContain('3 listed without a published date')
        await wrapper.get('[data-testid="cutoff-clear"]').trigger('click')
        expect(wrapper.emitted('update:cutoff')?.[2]).toEqual([''])
    })

    it('names the FDA purpose of each date and explains it on request', async () => {
        const wrapper = mount(CutoffFilter, { props: { cutoff: '2026-03-01', mode: 'before', basis: 'published' } })
        const options = wrapper.get('[data-testid="cutoff-basis"]').findAll('option').map(option => option.text())
        expect(options).toEqual(['Published (premarket)', 'First attributed (postmarket)'])
        await wrapper.get('[data-testid="cutoff-basis"]').setValue('attributed')
        expect(wrapper.emitted('update:basis')?.[0]).toEqual(['attributed'])

        const toggle = wrapper.get('[data-testid="cutoff-help-toggle"]')
        expect(toggle.attributes('title')).toContain('FDA premarket guidance (Feb 2026, §V.A.4)')
        expect(toggle.attributes('aria-expanded')).toBe('false')
        await toggle.trigger('click')
        expect(toggle.attributes('aria-expanded')).toBe('true')
        const help = wrapper.get('[data-testid="cutoff-help"]')
        expect(wrapper.get('[data-testid="cutoff-help-published"]').text()).toContain(
            'a submission should identify all known vulnerabilities of the device and its software components',
        )
        expect(wrapper.get('[data-testid="cutoff-help-attributed"]').text()).toContain(
            'FDA postmarket guidance (Dec 2016, §VI.B): for uncontrolled risk, communicate within 30 days and fix within 60 days',
        )
        expect(help.text()).toContain('A cutoff is a planning aid, not a compliance boundary')
        expect(help.text()).toContain('it is not regulatory advice')
        expect(wrapper.get('[data-testid="cutoff-help-docs"]').attributes('href')).toContain('review-workflows.md#cutoff-and-the-fda-guidance')
    })
})
