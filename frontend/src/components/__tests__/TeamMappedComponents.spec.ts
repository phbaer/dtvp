import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import TeamMappedComponents from '../TeamMappedComponents.vue'

describe('team-mapped component previews', () => {
    it('limits components and versions initially and exposes every value on demand', async () => {
        const components = Array.from({ length: 12 }, (_, index) => ({
            name: `library-${index}`, tag: 'Security',
            versions: Array.from({ length: 30 }, (_, version) => `${version + 1}.0`),
            under: Array.from({ length: 20 }, (_, version) => `Product ${version + 1}`),
        }))
        const wrapper = mount(TeamMappedComponents, { props: { components } })
        expect(wrapper.findAll('[data-testid="triggering-team-component"]')).toHaveLength(4)
        expect(wrapper.text()).not.toContain('30.0')
        expect(wrapper.text()).not.toContain('Product 20')
        await wrapper.findAll('button')[0]!.trigger('click')
        expect(wrapper.text()).toContain('30.0')
        expect(wrapper.text()).toContain('Product 20')
        await wrapper.findAll('button').at(-1)!.trigger('click')
        expect(wrapper.findAll('[data-testid="triggering-team-component"]')).toHaveLength(12)
        await wrapper.findAll('button').at(-1)!.trigger('click')
        expect(wrapper.findAll('[data-testid="triggering-team-component"]')).toHaveLength(4)
    })

    it('does not carry expanded details into a different finding', async () => {
        const component = { name: 'one', tag: 'Unknown', catchAll: true, versions: ['1', '2', '3', '4'] }
        const wrapper = mount(TeamMappedComponents, { props: { components: [component] } })
        await wrapper.get('button').trigger('click')
        expect(wrapper.text()).toContain('Component versions: 1, 2, 3, 4')
        await wrapper.setProps({ components: [{ ...component, name: 'another' }] })
        expect(wrapper.text()).not.toContain('Component versions:')
        expect(wrapper.get('[data-testid="triggering-team-component"]').attributes('data-catch-all')).toBe('true')
    })
})
