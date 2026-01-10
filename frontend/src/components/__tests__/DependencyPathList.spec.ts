import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import DependencyPathList from '../DependencyPathList.vue'

describe('DependencyPathList', () => {
    it('renders paths correctly in reverse order', () => {
        const paths = ['Child -> Parent -> Root']
        const wrapper = mount(DependencyPathList, {
            props: { paths }
        })

        // Should appear as Parent -> Child (Root hidden)
        // The list elements:
        const items = wrapper.findAll('.truncate')

        expect(items.length).toBe(2)
        expect(items[0]?.text()).toBe('Parent')
        expect(items[1]?.text()).toBe('Child')
    })

    it('renders chevron classes correctly', () => {
        const paths = ['Child -> Parent -> Root']
        const wrapper = mount(DependencyPathList, {
            props: { paths }
        })

        const segments = wrapper.findAll('.relative.flex.items-center')
        // First item should be clip-start
        expect(segments[0]?.classes()).toContain('clip-start')
        expect(segments[0]?.classes()).not.toContain('clip-middle')

        // Others should be clip-middle
        expect(segments[1]?.classes()).toContain('clip-middle')
        expect(segments[2]?.classes()).toContain('clip-middle')
    })


    it('renders multiple paths', () => {
        const paths = [
            'Vuln1 -> App',
            'Vuln2 -> Lib -> App'
        ]
        const wrapper = mount(DependencyPathList, { props: { paths } })

        // We look for the path containers (flex flex-1)
        const pathContainers = wrapper.findAll('.group')

        expect(pathContainers.length).toBe(2)

        // Path 1: App -> Vuln1. Only 'Vuln1' shown.
        expect(pathContainers[0]?.text()).not.toContain('App')
        expect(pathContainers[0]?.text()).toContain('Vuln1')

        // Path 2: App -> Lib -> Vuln2. 'Lib' -> 'Vuln2' shown.
        expect(pathContainers[1]?.text()).not.toContain('App')
        expect(pathContainers[1]?.text()).toContain('Lib')
        expect(pathContainers[1]?.text()).toContain('Vuln2')
    })
})
