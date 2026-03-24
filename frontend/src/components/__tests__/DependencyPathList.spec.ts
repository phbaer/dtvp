import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import DependencyPathList from '../DependencyPathList.vue'

describe('DependencyPathList', () => {
    it('renders paths as a sparse tree and hides root', () => {
        const paths = ['Child -> Parent -> Root']
        const wrapper = mount(DependencyPathList, {
            props: { paths }
        })

        // Should show minimal tree nodes: Parent and Child
        const items = wrapper.findAll('li')

        expect(items.length).toBe(2)
        expect(items[0].text()).toBe('Parent')
        expect(items[1].text()).toBe('Child')
    })

    it('renders multiple merged paths in sparse tree structure', () => {
        const paths = [
            'Vuln1 -> App',
            'Vuln2 -> Lib -> App'
        ]
        const wrapper = mount(DependencyPathList, { props: { paths } })

        const listItems = wrapper.findAll('li')
        // Vuln1 (depth 0), Lib (depth 0), Vuln2 (depth 1)
        const texts = listItems.map(i => i.text())

        expect(texts).toContain('Vuln1')
        expect(texts).toContain('Lib')
        expect(texts).toContain('Vuln2')

        expect(listItems[0].attributes('style')).toContain('padding-left: 0rem')
        // child should have indent
        expect(listItems[2].attributes('style')).toContain('padding-left: 1rem')
    })


})
