import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { ref } from 'vue'
import VulnGroupCardDependencies from '../VulnGroupCardDependencies.vue'
import { updateTeamMapping } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    updateTeamMapping: vi.fn()
}))

describe('VulnGroupCardDependencies.vue', () => {
    const instances = [
        {
            component_name: 'log4j-core',
            component_version: '2.17.0',
            component_uuid: 'comp-1',
            project_uuid: 'project-1',
            project_name: 'Test Project',
            dependency_chains: ['log4j-core -> some-dep -> Test Project'],
            is_direct_dependency: true,
        },
    ]

    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('renders current main team tag and shows edit controls for reviewers', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: { instances },
            global: {
                provide: {
                    user: { role: 'REVIEWER' },
                    teamMapping: ref({ 'log4j-core': ['TEAM-A', 'legacy-team'] }),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        expect(wrapper.text()).toContain('TEAM-A')
        expect(wrapper.findAll('button').some((btn) => btn.text() === 'Edit tag')).toBe(true)
    })

    it('does not show edit controls for non-reviewers', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: { instances },
            global: {
                provide: {
                    user: { role: 'ANALYST' },
                    teamMapping: ref({ 'log4j-core': ['TEAM-A', 'legacy-team'] }),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        expect(wrapper.findAll('button').some((btn) => btn.text() === 'Edit tag')).toBe(false)
    })

    it('shows vuln-scoped mapping controls when reviewer user is provided as a ref', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: { instances },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER' }),
                    teamMapping: ref({}),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        expect(wrapper.text()).toContain('Add Component Team Tag')
        expect(wrapper.findAll('button').some((btn) => btn.text() === 'Add tag')).toBe(true)
    })

    it('shows a mapped team from dependency paths when the direct component is not mapped', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                instances: [
                    {
                        component_name: 'unmapped-comp',
                        component_version: '1.0.0',
                        component_uuid: 'comp-2',
                        project_uuid: 'project-1',
                        project_name: 'Test Project',
                        dependency_chains: ['unmapped-comp -> some-dep -> Test Project'],
                        is_direct_dependency: true,
                    },
                ],
            },
            global: {
                provide: {
                    user: { role: 'REVIEWER' },
                    teamMapping: ref({ 'some-dep': ['TEAM-B'] }),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        expect(wrapper.text()).toContain('TEAM-B')
        expect(wrapper.text()).not.toContain('none')
    })

    it('shows only the first mapped team from each dependency chain', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                instances: [
                    {
                        component_name: 'unmapped-comp',
                        component_version: '1.0.0',
                        component_uuid: 'comp-2',
                        project_uuid: 'project-1',
                        project_name: 'Test Project',
                        dependency_chains: ['unmapped-comp -> dep-a -> dep-b -> Test Project'],
                        is_direct_dependency: true,
                    },
                ],
            },
            global: {
                provide: {
                    user: { role: 'REVIEWER' },
                    teamMapping: ref({ 'dep-a': ['TEAM-A'], 'dep-b': ['TEAM-B'] }),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        expect(wrapper.text()).toContain('TEAM-A')
        expect(wrapper.text()).not.toContain('TEAM-B')
        expect(wrapper.text()).not.toContain('TEAM-A, TEAM-B')
    })

    it('saves a new main team tag while preserving existing aliases', async () => {
        vi.mocked(updateTeamMapping).mockResolvedValue({ status: 'success', message: 'saved' })

        const wrapper = mount(VulnGroupCardDependencies, {
            props: { instances },
            global: {
                provide: {
                    user: { role: 'REVIEWER' },
                    teamMapping: ref({ 'log4j-core': ['TEAM-A', 'legacy-team'] }),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        const editButton = wrapper.findAll('button').find((btn) => btn.text() === 'Edit tag')
        expect(editButton).toBeDefined()
        await editButton?.trigger('click')

        const inputs = wrapper.findAll('input[placeholder="Primary tag"]')
        const input = inputs[inputs.length - 1]
        expect(input.exists()).toBe(true)
        await input.setValue('TEAM-X')

        const saveButton = wrapper.findAll('button').find((btn) => btn.text() === 'Save')
        expect(saveButton).toBeDefined()
        await saveButton?.trigger('click')

        expect(updateTeamMapping).toHaveBeenCalledWith({
            'log4j-core': ['TEAM-X', 'legacy-team'],
        })
    })

    it('offers only unmapped vuln components in the add-mapping dropdown', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                instances: [
                    {
                        component_name: 'mapped-lib',
                        component_version: '1.0.0',
                        component_uuid: 'comp-1',
                        project_uuid: 'project-1',
                        project_name: 'Test Project',
                        dependency_chains: ['mapped-lib -> Test Project'],
                        is_direct_dependency: true,
                    },
                    {
                        component_name: 'unmapped-lib',
                        component_version: '2.0.0',
                        component_uuid: 'comp-2',
                        project_uuid: 'project-1',
                        project_name: 'Test Project',
                        dependency_chains: ['unmapped-lib -> Test Project'],
                        is_direct_dependency: false,
                    },
                    {
                        component_name: 'unmapped-lib',
                        component_version: '2.0.0',
                        component_uuid: 'comp-3',
                        project_uuid: 'project-2',
                        project_name: 'Test Project',
                        dependency_chains: ['unmapped-lib -> Other Project'],
                        is_direct_dependency: true,
                    },
                ],
            },
            global: {
                provide: {
                    user: { role: 'REVIEWER' },
                    teamMapping: ref({ 'mapped-lib': ['TEAM-A'] }),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        const options = wrapper.findAll('select option').map(option => option.text())
        expect(options).toContain('Select an unmapped component')
        expect(options).toContain('unmapped-lib')
        expect(options).not.toContain('mapped-lib')
    })

    it('includes intermediate dependency-chain components in the add-mapping dropdown', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                instances: [
                    {
                        component_name: 'log4j-core',
                        component_version: '2.14.0',
                        component_uuid: 'comp-1',
                        project_uuid: 'project-1',
                        project_name: 'Test Project',
                        dependency_chains: ['log4j-core -> internal-lib-b -> internal-lib-a -> Test Project'],
                        is_direct_dependency: true,
                    },
                ],
            },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER' }),
                    teamMapping: ref({ 'internal-lib-b': ['TEAM-B'] }),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        const options = wrapper.findAll('select option').map(option => option.text())
        expect(options).toContain('log4j-core')
        expect(options).toContain('internal-lib-a')
        expect(options).not.toContain('internal-lib-b')
        expect(options).not.toContain('Test Project')
    })

    it('creates a new component team tag from the vuln-scoped add form', async () => {
        vi.mocked(updateTeamMapping).mockResolvedValue({ status: 'success', message: 'saved' })

        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                instances: [
                    {
                        component_name: 'unmapped-lib',
                        component_version: '1.0.0',
                        component_uuid: 'comp-2',
                        project_uuid: 'project-1',
                        project_name: 'Test Project',
                        dependency_chains: ['unmapped-lib -> dep-a -> Test Project'],
                        is_direct_dependency: true,
                    },
                ],
            },
            global: {
                provide: {
                    user: { role: 'REVIEWER' },
                    teamMapping: ref({}),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        await wrapper.find('select').setValue('unmapped-lib')

        const inputs = wrapper.findAll('input[placeholder="Primary tag"]')
        expect(inputs.length).toBeGreaterThan(0)
        await inputs[0].setValue('TEAM-Z')

        const addButton = wrapper.findAll('button').find((btn) => btn.text() === 'Add tag')
        expect(addButton).toBeDefined()
        await addButton?.trigger('click')

        expect(updateTeamMapping).toHaveBeenCalledWith({
            'unmapped-lib': 'TEAM-Z',
        })
        expect(wrapper.text()).toContain('Component team tag saved.')
    })

    it('combines matching component instances into a single chain viewer', async () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                instances: [
                    {
                        component_name: 'shared-lib',
                        component_version: '1.0.0',
                        component_uuid: 'comp-1',
                        project_uuid: 'project-1',
                        project_name: 'Project One',
                        dependency_chains: ['shared-lib -> dep-a -> Project One'],
                        is_direct_dependency: true,
                    },
                    {
                        component_name: 'shared-lib',
                        component_version: '1.0.0',
                        component_uuid: 'comp-2',
                        project_uuid: 'project-2',
                        project_name: 'Project Two',
                        dependency_chains: ['shared-lib -> dep-b -> Project Two'],
                        is_direct_dependency: true,
                    },
                ],
            },
            global: {
                provide: {
                    user: { role: 'ANALYST' },
                    teamMapping: ref({}),
                },
                stubs: {
                    DependencyChainViewer: {
                        props: ['sources'],
                        template: '<div data-testid="chain-viewer">{{ sources.length }}</div>',
                    },
                },
            },
        })

        const chainsButton = wrapper.findAll('button').find((btn) => btn.text().includes('chains'))
        expect(chainsButton).toBeDefined()
        await chainsButton?.trigger('click')

        const viewers = wrapper.findAll('[data-testid="chain-viewer"]')
        expect(viewers).toHaveLength(1)
        expect(viewers[0].text()).toBe('2')
    })
})
