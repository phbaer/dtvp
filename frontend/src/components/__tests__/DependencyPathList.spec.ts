import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import DependencyPathList from '../DependencyPathList.vue'

describe('DependencyPathList', () => {
  it('renders a compact dependency tree for shared prefixes', () => {
    const paths = ['Vuln -> Shared -> A', 'Vuln -> Shared -> B']
    const wrapper = mount(DependencyPathList, { props: { paths } })

    const text = wrapper.text()
    // Root 'Vuln' is not rendered (parent shows affected component)
    expect(text).toContain('Shared')
    expect(text).toContain('A')
    expect(text).toContain('B')
    expect(text.match(/Shared/g)?.length).toBe(1)
  })

  it('marks primary team, other teams, and root correctly', () => {
    const paths = ['log4j-core -> team-a-comp -> team-b-comp -> Vulnerable Project']
    const teamMappedNames = new Map<string, string[]>([
      ['team-a-comp', ['TEAM-A']],
      ['team-b-comp', ['TEAM-B']],
    ])

    const wrapper = mount(DependencyPathList, {
      props: { paths, teamMappedNames },
    })

    const text = wrapper.text()
    // Root 'log4j-core' is not rendered (parent shows affected component)
    expect(text).not.toContain('log4j-core')
    expect(text).toContain('team-a-comp')
    expect(text).toContain('TEAM-A')
    expect(text).toContain('team-b-comp')
    expect(text).toContain('TEAM-B')
    expect(text).toContain('Vulnerable Project')
    expect(text).toContain('root')
  })

  it('renders direct leaf paths without duplicate nodes', () => {
    const paths = ['VulnComp -> RootProject']
    const wrapper = mount(DependencyPathList, { props: { paths } })

    const text = wrapper.text()
    // Root 'VulnComp' is not rendered (parent shows affected component)
    expect(text).toContain('RootProject')
    expect(text.match(/RootProject/g)?.length).toBe(1)
  })

  it('matches team mapping keys case-insensitively', () => {
    const paths = ['log4j-core -> Team-A-Comp -> Impacted-Project']
    const teamMappedNames = new Map<string, string[]>([['team-a-comp', ['TEAM-A']]])

    const wrapper = mount(DependencyPathList, {
      props: { paths, teamMappedNames },
    })

    expect(wrapper.text()).toContain('TEAM-A')
  })

  it('collapses consecutive duplicate nodes', () => {
    const paths = ['VulnComp -> VulnComp -> Intermediate -> Root']
    const wrapper = mount(DependencyPathList, { props: { paths } })

    const text = wrapper.text()
    // Root 'VulnComp' is not rendered; consecutive dup removed
    expect(text).not.toContain('VulnComp')
    expect(text).toContain('Intermediate')
    expect(text).toContain('Root')
  })

  it('shows empty state when no paths exist', () => {
    const wrapper = mount(DependencyPathList, { props: { paths: [] } })
    expect(wrapper.text()).toContain('No dependency chains found')
  })

  it('hides single-node paths', () => {
    const wrapper = mount(DependencyPathList, { props: { paths: ['OnlyComponent'] } })
    expect(wrapper.text()).toContain('No dependency chains found')
  })
})
