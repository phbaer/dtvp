import { describe, expect, it } from 'vitest'
import { selectorMappingFromTeams, type Team } from '../team-config'
import {
    assignEntries,
    buildInventory,
    canonicalSelector,
    componentCompletions,
    entryFromKey,
    entryInsights,
    insightKey,
    looseToken,
    previewSelector,
    suggestEntry,
    type MappingReport,
} from '../team-mapping-insights'

const report = (components: MappingReport['inventory']['components'], projects: string[]): MappingReport => ({
    totals: { versions: 1, projects: projects.length, findings: 0, owned_by_component: 0, owned_by_project: 0, unmapped: 0 },
    projects: [],
    entries: {},
    unmapped: [],
    unmapped_total: 0,
    near_duplicates: [],
    missing_versions: [],
    inventory: { projects, components, total: components.length, truncated: false },
})

const PROJECTS = ['A', 'B', 'C', 'D', 'E', 'ViewPoint_Product']
const VP = 5
const inventory = buildInventory(report([
    ['core', '', '', [[VP, 40, 30, 2], [0, 5, 5, 2]]],
    ['libtiff', '', 'pkg:generic/libtiff', [[VP, 12, 12, 2]]],
    ['stats-app', '', 'pkg:npm/vp-stats-app', [[1, 9, 9, 1]]],
    ['util', '', 'pkg:npm/util', [[0, 1, 0, 0], [1, 1, 0, 0], [2, 1, 0, 0]]],
    ['util', '', 'pkg:pypi/util', [[3, 1, 0, 0], [4, 1, 0, 0]]],
], PROJECTS))

const teams = (): Team[] => [
    { name: 'Core', aliases: [], projects: [], components: ['project:ViewPoint_Product::core', 'vp-stats-app', 'gone-lib'] },
    { name: 'Generic', aliases: [], projects: [], components: ['core', 'util'] },
    { name: 'Phoenix', aliases: [], projects: [], components: ['VPStatsApp'] },
    { name: 'Dup', aliases: [], projects: [], components: ['Gone-Lib'] },
]

describe('team mapping insights', () => {
    it('previews what a selector matches and who wins', () => {
        const mapping = selectorMappingFromTeams(teams())
        const scoped = previewSelector('project:ViewPoint_Product::core', inventory, mapping)
        expect(scoped.matched).toHaveLength(1)
        expect(scoped.projects).toEqual(['ViewPoint_Product'])
        expect(scoped.findingsBelow).toBe(40)
        expect(scoped.wins).toBe(1)

        const plain = previewSelector('core', inventory, mapping)
        expect(plain.matched).toHaveLength(2)
        expect(plain.wins).toBe(1)
        expect(plain.overriddenBy.get('project:ViewPoint_Product::core')).toBe(1)

        // The purl names the package: vp-stats-app matches stats-app.
        expect(previewSelector('vp-stats-app', inventory, mapping).matched[0].name).toBe('stats-app')
    })

    it('flags stale, broad, shadowed, duplicate and disagreeing entries', () => {
        const list = teams()
        const insights = entryInsights(list, inventory, selectorMappingFromTeams(list), true)
        const kinds = (team: string, key: string) => insights.get(insightKey(team, key))!.flags.map(flag => flag.kind)
        expect(kinds('Core', 'gone-lib')).toEqual(['stale', 'duplicate'])
        expect(kinds('Dup', 'Gone-Lib')).toEqual(['stale', 'duplicate'])
        expect(kinds('Generic', 'util')).toEqual(['broad'])
        expect(kinds('Core', 'vp-stats-app')).toEqual(['disagreement'])
        expect(kinds('Phoenix', 'VPStatsApp')).toEqual(['stale', 'disagreement'])
        expect(kinds('Core', 'project:ViewPoint_Product::core')).toEqual([])

        const shadowedTeams: Team[] = [
            { name: 'A', aliases: [], projects: [], components: ['libtiff'] },
            { name: 'B', aliases: [], projects: [], components: ['purl::pkg:generic/libtiff'] },
        ]
        const shadowed = entryInsights(shadowedTeams, inventory, selectorMappingFromTeams(shadowedTeams), true)
        expect(shadowed.get(insightKey('A', 'libtiff'))!.flags.map(flag => flag.kind)).toEqual(['shadowed', 'disagreement'])
    })

    it('reads selectors loosely and canonically', () => {
        expect(canonicalSelector('Group/Name')).toBe(canonicalSelector('group:name'))
        expect(canonicalSelector('cs::Name')).not.toBe(canonicalSelector('cs::name'))
        expect(canonicalSelector('ci::Name')).toBe(canonicalSelector('name'))
        expect(looseToken('purl::pkg:npm/vp-stats-app')).toBe('vpstatsapp')
        expect(looseToken('VPStatsApp')).toBe('vpstatsapp')
    })

    it('suggests entries like the server', () => {
        expect(suggestEntry({ name: 'X', group: '', purl: '', root: true }, 'eventserver')).toEqual({ kind: 'project', value: 'eventserver' })
        expect(suggestEntry({ name: 'netty', group: 'io.netty', purl: 'pkg:maven/io.netty/netty-codec' }, 'P'))
            .toEqual({ kind: 'component', value: 'io.netty:netty-codec' })
        expect(suggestEntry({ name: 'libtiff', group: '', purl: 'pkg:generic/libtiff' }, 'P')).toEqual({ kind: 'component', value: 'libtiff' })
        expect(suggestEntry({ name: 'core', group: '', purl: '' }, 'ViewPoint_Product'))
            .toEqual({ kind: 'component', value: 'project:ViewPoint_Product::core' })
        expect(entryFromKey('project::eventserver')).toEqual({ kind: 'project', value: 'eventserver' })
    })

    it('assigns entries to an existing or a new team', () => {
        const next = assignEntries(teams(), 'core', [{ kind: 'project', value: 'eventserver' }, { kind: 'component', value: 'gone-lib' }])
        expect(next[0].projects).toEqual(['eventserver'])
        expect(next[0].components).toEqual(['project:ViewPoint_Product::core', 'vp-stats-app', 'gone-lib'])
        const created = assignEntries([], '3P', [{ kind: 'component', value: 'libtiff' }])
        expect(created).toEqual([{ name: '3P', aliases: [], projects: [], components: ['libtiff'] }])
    })

    it('completes selectors from stored components', () => {
        expect(componentCompletions('tiff', inventory)).toEqual(['libtiff', 'purl::pkg:generic/libtiff'])
        expect(componentCompletions('project:ViewPoint_Product::co', inventory)).toEqual(['project:ViewPoint_Product::core'])
    })
})
