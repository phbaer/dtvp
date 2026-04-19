import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import DependencyPathList from '../DependencyPathList.vue'

const getGraphSource = (wrapper: ReturnType<typeof mount>) => {
  return wrapper.get('[data-testid="graph-source"]').text()
}

const getGraphLabels = (wrapper: ReturnType<typeof mount>) => {
  return wrapper.get('[data-testid="graph-labels"]').text()
}

describe('DependencyPathList', () => {
  it('renders a compact dependency tree for shared prefixes', () => {
    const paths = ['Vuln -> Shared -> A', 'Vuln -> Shared -> B']
    const wrapper = mount(DependencyPathList, { props: { paths } })

    const source = getGraphSource(wrapper)
    expect(source).toContain('Vuln -> Shared -> A')
    expect(source).toContain('Vuln -> Shared -> B')
    expect(source).toContain('A')
    expect(source).toContain('B')
  })

  it('renders the full dependency sequence once in the tree', () => {
    const paths = ['log4j-core -> team-a-comp -> team-b-comp -> Vulnerable Project']
    const teamMappedNames = new Map<string, string[]>([
      ['team-a-comp', ['TEAM-A']],
      ['team-b-comp', ['TEAM-B']],
    ])

    const wrapper = mount(DependencyPathList, {
      props: { paths, teamMappedNames },
    })

    const source = getGraphSource(wrapper)
    const labels = getGraphLabels(wrapper)
    expect(source).toContain('log4j-core')
    expect(labels).toContain('log4j-core | SOURCE')
    expect(labels).toContain('team-a-comp | TEAM-A | PRIMARY')
    expect(labels).toContain('team-b-comp | TEAM-B')
    expect(labels).toContain('Vulnerable Project | ROOT')
  })

  it('renders direct leaf paths without duplicate nodes', () => {
    const paths = ['VulnComp -> RootProject']
    const wrapper = mount(DependencyPathList, { props: { paths } })

    const source = getGraphSource(wrapper)
    expect(source).toContain('VulnComp -> RootProject')
  })

  it('renders duplicate dependency paths only once', () => {
    const paths = [
      'internal-lib-b -> internal-lib-a -> Vulnerable Project',
      'internal-lib-b -> internal-lib-a -> Vulnerable Project',
    ]
    const wrapper = mount(DependencyPathList, { props: { paths } })

    const source = getGraphSource(wrapper)
    expect(source).toBe('internal-lib-b -> internal-lib-a -> Vulnerable Project')
  })

  it('selects the shortest path for each affected team', () => {
    const paths = [
      'log4j-core -> team-a-comp -> long-lib -> Vulnerable Project',
      'log4j-core -> team-a-comp -> Vulnerable Project',
      'log4j-core -> team-b-comp -> other-lib -> Vulnerable Project',
    ]
    const teamMappedNames = new Map<string, string[]>([
      ['team-a-comp', ['TEAM-A']],
      ['team-b-comp', ['TEAM-B']],
    ])

    const wrapper = mount(DependencyPathList, {
      props: { paths, teamMappedNames },
    })

    const source = getGraphSource(wrapper)
    const labels = getGraphLabels(wrapper)
    expect(source).not.toContain('long-lib')
    expect(source).toContain('team-a-comp')
    expect(source).toContain('team-b-comp')
    expect(source).toContain('other-lib')
    expect(labels).toContain('team-a-comp | TEAM-A | PRIMARY')
  })

  it('shows only the representative path for the closest affected team', () => {
    const paths = [
      'log4j-core -> team-a-comp -> RootProject',
      'log4j-core -> team-b-comp -> team-a-comp -> RootProject',
    ]
    const teamMappedNames = new Map<string, string[]>([
      ['team-a-comp', ['TEAM-A']],
      ['team-b-comp', ['TEAM-B']],
    ])

    const wrapper = mount(DependencyPathList, {
      props: { paths, teamMappedNames },
    })

    const source = getGraphSource(wrapper)
    const labels = getGraphLabels(wrapper)
    expect(labels).toContain('team-a-comp | TEAM-A | PRIMARY')
    expect(labels).toContain('team-b-comp | TEAM-B | PRIMARY')
    expect(source.match(/team-a-comp/g)?.length).toBe(2)
  })

  it('matches team mapping keys case-insensitively', () => {
    const paths = ['log4j-core -> Team-A-Comp -> Impacted-Project']
    const teamMappedNames = new Map<string, string[]>([['team-a-comp', ['TEAM-A']]])

    const wrapper = mount(DependencyPathList, {
      props: { paths, teamMappedNames },
    })

    expect(getGraphLabels(wrapper)).toContain('Team-A-Comp | TEAM-A | PRIMARY')
  })

  it('collapses consecutive duplicate nodes', () => {
    const paths = ['VulnComp -> VulnComp -> Intermediate -> Root']
    const wrapper = mount(DependencyPathList, { props: { paths } })

    const source = getGraphSource(wrapper)
    expect(source).toContain('VulnComp -> Intermediate -> Root')
  })

  it('replaces non-team intermediate dependencies with an ellipsis bubble', () => {
    const paths = ['source-lib -> hidden-a -> hidden-b -> hidden-c -> hidden-d -> root-app']
    const wrapper = mount(DependencyPathList, { props: { paths } })

    expect(getGraphSource(wrapper)).toContain('source-lib -> hidden-a -> ... -> hidden-d -> root-app')
    expect(getGraphLabels(wrapper)).toContain('...')
  })

  it('keeps short paths fully expanded when they fit within five bubbles', () => {
    const paths = ['source-lib -> dep-a -> dep-b -> dep-c -> root-app']
    const wrapper = mount(DependencyPathList, { props: { paths } })

    expect(getGraphSource(wrapper)).toBe('source-lib -> dep-a -> dep-b -> dep-c -> root-app')
    expect(getGraphLabels(wrapper)).not.toContain('...')
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
