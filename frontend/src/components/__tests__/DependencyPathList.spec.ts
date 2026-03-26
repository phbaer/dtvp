import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import DependencyPathList from '../DependencyPathList.vue'

describe('DependencyPathList', () => {
    it('renders a chain grouped by direct dependency', () => {
        // Chain: Root -> Parent -> Child  (Root is project, Parent is direct dep, Child is affected)
        const paths = ['Root -> Parent -> Child']
        const wrapper = mount(DependencyPathList, {
            props: { paths }
        })

        const text = wrapper.text()
        // Should show direct dep 'Parent' (intermediates only, affected component is omitted as redundant)
        expect(text).toContain('Parent')
        // Should NOT show stripped project root
        expect(text).not.toContain('Root')
    })

    it('renders multiple chains grouped by direct dependency', () => {
        const paths = [
            'App -> Vuln1',
            'App -> Lib -> Vuln2'
        ]
        const wrapper = mount(DependencyPathList, { props: { paths } })

        const text = wrapper.text()

        // Vuln1 is a direct dependency (chain length 1 after stripping root)
        expect(text).toContain('Vuln1')
        expect(text).toContain('(direct)')

        // Lib is a direct dep leading to Vuln2 (Vuln2 is the affected component, omitted from chain)
        expect(text).toContain('Lib')
    })

    it('shows empty state when no paths', () => {
        const wrapper = mount(DependencyPathList, { props: { paths: [] } })
        expect(wrapper.text()).toContain('No dependency chains found')
    })

    it('shows all intermediates in long chains', () => {
        const paths = ['Root -> A -> B -> C -> D -> E -> F -> G -> H -> I -> J']
        const wrapper = mount(DependencyPathList, { props: { paths } })

        const text = wrapper.text()
        expect(text).toContain('A')
        expect(text).toContain('B')
        expect(text).toContain('E')
        expect(text).toContain('H')
        expect(text).toContain('I')
    })
})
