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

    it('renders current main team tag without edit controls in dependency mode', () => {
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
        expect(wrapper.findAll('button').some((btn) => btn.text() === 'Edit tag')).toBe(false)
        expect(wrapper.text()).not.toContain('Add Component Team Tag')
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

    it('hides mapping edit controls for non-reviewers', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: { instances, mode: 'mapping' },
            global: {
                provide: {
                    user: { role: 'ANALYST' },
                    teamMapping: ref({}),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        expect(wrapper.text()).not.toContain('Add Component Team Tag')
        expect(wrapper.findAll('button').some((btn) => btn.text() === 'Add tag')).toBe(false)
        expect(wrapper.findAll('button').some((btn) => btn.text() === 'Edit tag')).toBe(false)
    })

    it('shows vuln-scoped mapping controls when reviewer user is provided as a ref', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: { instances, mode: 'mapping' },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER' }),
                    teamMapping: ref({}),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        expect(wrapper.text()).toContain('Component Team Mapping')
        expect(wrapper.text()).not.toContain('Add Component Team Tag')
        expect(wrapper.findAll('button').some((btn) => btn.text() === 'Add tag')).toBe(false)
        expect(wrapper.findAll('button').some((btn) => btn.text() === 'Edit tag')).toBe(true)
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
            props: { instances, mode: 'mapping' },
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

    it('creates group-qualified mappings when editing grouped components', async () => {
        vi.mocked(updateTeamMapping).mockResolvedValue({ status: 'success', message: 'saved' })

        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                mode: 'mapping',
                instances: [
                    {
                        component_name: 'core',
                        component_group: '@angular',
                        component_version: '18.0.0',
                        component_uuid: 'comp-1',
                        project_uuid: 'project-1',
                        project_name: 'Test Project',
                        dependency_chains: ['core -> Test Project'],
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

        const editButton = wrapper.findAll('button').find((btn) => btn.text() === 'Edit tag')
        await editButton?.trigger('click')

        const input = wrapper.findAll('input[placeholder="Primary tag"]').at(-1)
        expect(input?.exists()).toBe(true)
        await input?.setValue('FRONTEND')

        const saveButton = wrapper.findAll('button').find((btn) => btn.text() === 'Save')
        await saveButton?.trigger('click')

        expect(updateTeamMapping).toHaveBeenCalledWith({
            '@angular:core': 'FRONTEND',
        })
    })

    it('shows mapped and unmapped vulnerability components in one editable list', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                mode: 'mapping',
                instances: [
                    {
                        component_name: 'owned-lib',
                        component_version: '1.0.0',
                        component_uuid: 'comp-1',
                        project_uuid: 'project-1',
                        project_name: 'Test Project',
                        dependency_chains: ['owned-lib -> Test Project'],
                        is_direct_dependency: true,
                    },
                    {
                        component_name: 'unowned-lib',
                        component_version: '2.0.0',
                        component_uuid: 'comp-2',
                        project_uuid: 'project-1',
                        project_name: 'Test Project',
                        dependency_chains: ['unowned-lib -> Test Project'],
                        is_direct_dependency: false,
                    },
                    {
                        component_name: 'unowned-lib',
                        component_version: '2.0.0',
                        component_uuid: 'comp-3',
                        project_uuid: 'project-2',
                        project_name: 'Test Project',
                        dependency_chains: ['unowned-lib -> Other Project'],
                        is_direct_dependency: true,
                    },
                ],
            },
            global: {
                provide: {
                    user: { role: 'REVIEWER' },
                    teamMapping: ref({ 'owned-lib': ['TEAM-A'] }),
                },
                stubs: { DependencyChainViewer: true },
            },
        })

        const rows = wrapper.findAll('[data-testid="component-team-mapping-row"]').map(row => row.text())
        expect(rows).toHaveLength(2)
        expect(rows.some(row => row.includes('owned-lib') && row.includes('TEAM-A'))).toBe(true)
        expect(rows.some(row => row.includes('unowned-lib') && row.includes('none'))).toBe(true)
        expect(wrapper.findAll('[role="option"]')).toHaveLength(0)
    })

    it('includes intermediate dependency-chain components in the editable list', () => {
        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                mode: 'mapping',
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

        const rows = wrapper.findAll('[data-testid="component-team-mapping-row"]').map(row => row.text())
        expect(rows.some(row => row.includes('log4j-core'))).toBe(true)
        expect(rows.some(row => row.includes('internal-lib-a'))).toBe(true)
        expect(rows.some(row => row.includes('internal-lib-b') && row.includes('TEAM-B'))).toBe(true)
        expect(rows.some(row => row.includes('Test Project'))).toBe(false)
    })

    it('creates a new component team tag from the component row editor', async () => {
        vi.mocked(updateTeamMapping).mockResolvedValue({ status: 'success', message: 'saved' })

        const wrapper = mount(VulnGroupCardDependencies, {
            props: {
                mode: 'mapping',
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

        const row = wrapper.findAll('[data-testid="component-team-mapping-row"]').find((candidate) => candidate.text().includes('unmapped-lib'))
        expect(row).toBeDefined()
        if (!row) throw new Error('Expected unmapped-lib mapping row')

        const editButton = row.findAll('button').find((btn) => btn.text() === 'Edit tag')
        expect(editButton).toBeDefined()
        await editButton?.trigger('click')

        const input = row.find('input[placeholder="Primary tag"]')
        expect(input.exists()).toBe(true)
        await input.setValue('TEAM-Z')

        const saveButton = row.findAll('button').find((btn) => btn.text() === 'Save')
        expect(saveButton).toBeDefined()
        await saveButton?.trigger('click')

        expect(updateTeamMapping).toHaveBeenCalledWith({
            'unmapped-lib': 'TEAM-Z',
        })
        expect(wrapper.text()).toContain('Team tag saved.')
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
