import { describe, expect, it } from 'vitest'
import { documentFromTeams, selectorMappingFromTeams, teamConfigErrors, type Team } from '../team-config'
import {
    applyEdits,
    buildChecks,
    checkCounts,
    describeChange,
    describeEntry,
    diffTeams,
    plural,
} from '../team-mapping-editing'
import { buildInventory, entryInsights, type MappingReport } from '../team-mapping-insights'

const team = (name: string, components: string[] = [], projects: string[] = [], aliases: string[] = []): Team =>
    ({ name, aliases, projects, components })

const report = (): MappingReport => ({
    totals: { versions: 2, projects: 2, findings: 2400, owned_by_component: 1180, owned_by_project: 0, unmapped: 1220 },
    projects: [
        { name: 'ViewPoint_Product', versions: [], findings: 1188, unmapped: 18, owned_by: {}, fallback_key: null, root: { name: 'ViewPoint_Product', group: '', purl: '' } },
        { name: 'eventserver', versions: [], findings: 1212, unmapped: 1202, owned_by: {}, fallback_key: null, root: { name: 'eventserver', group: '', purl: '' } },
    ],
    entries: { 'vp-stats-app': { findings: 993, projects: [] }, libtiff: { findings: 187, projects: [] } },
    unmapped: [],
    unmapped_total: 0,
    near_duplicates: [],
    missing_versions: [],
    inventory: {
        projects: ['ViewPoint_Product', 'eventserver'],
        components: [
            ['stats-app', '', 'pkg:npm/vp-stats-app', [[0, 993, 0, 2]]],
            ['libtiff', '', 'pkg:generic/libtiff', [[0, 187, 0, 2]]],
        ],
        total: 2,
        truncated: false,
    },
})

const checksFor = (teams: Team[], data: MappingReport | null = report()) => {
    const inventory = buildInventory(data)
    return buildChecks({
        teams,
        errors: teamConfigErrors(documentFromTeams(teams)),
        insights: entryInsights(teams, inventory, selectorMappingFromTeams(teams), Boolean(data)),
        report: data,
        conversionWarnings: [],
    })
}

describe('describeEntry', () => {
    it('says in words what an entry owns', () => {
        expect(describeEntry('project::eventserver')).toEqual({
            kind: 'project',
            text: 'The project eventserver: its findings no component entry owns',
        })
        expect(describeEntry('project:ViewPoint_Product::core').text)
            .toBe('Components named core, or whose package URL names it, only in ViewPoint_Product, and what they contain')
        expect(describeEntry('com.vp:app').text).toContain('named app in group com.vp, in every project')
        expect(describeEntry('purl::pkg:npm/vp-stats-app').text).toContain('package URL pkg:npm/vp-stats-app')
        expect(describeEntry('nogroup::core').text).toContain('without a group')
        expect(describeEntry('cs::Core').text).toContain('(exact case)')
        expect(describeEntry('*').kind).toBe('catch-all')
        expect(describeEntry('project::').error).toBeTruthy()
    })
})

describe('plural', () => {
    it('counts', () => {
        expect(plural(1, 'finding')).toBe('1 finding')
        expect(plural(0, 'entry', 'entries')).toBe('0 entries')
    })
})

describe('diffTeams', () => {
    it('lists teams added, removed and renamed and entries added and removed', () => {
        const saved = [team('Core', ['vp-stats-app', 'gone-lib'], [], ['DE-Core']), team('Old', ['x']), team('3P', ['libtiff'])]
        const draft = [
            team('Core', ['vp-stats-app', 'project:ViewPoint_Product::core'], ['eventserver'], ['DE-Core']),
            team('Third Party', ['libtiff']),
            team('New', ['zlib']),
            team('', ['ignored']),
        ]
        const changes = diffTeams(saved, draft)
        expect(changes.map(describeChange)).toEqual([
            'Team 3P renamed to Third Party',
            'New team New',
            'New: added entry zlib',
            'Team Old removed',
            'Core: added project eventserver',
            'Core: added entry project:ViewPoint_Product::core',
            'Core: removed entry gone-lib',
        ])
        expect(diffTeams(saved, saved)).toEqual([])
    })
})

describe('applyEdits', () => {
    it('adds and removes, creating a team on demand, without touching the input', () => {
        const teams = [team('Core', ['a']), team('Phoenix', ['b'], ['P'])]
        const next = applyEdits(teams, [
            { type: 'remove', team: 'Phoenix', field: 'components', value: 'b' },
            { type: 'add', team: 'core', field: 'components', value: 'b' },
            { type: 'add', team: 'Core', field: 'components', value: 'a' },
            { type: 'remove', team: 'Phoenix', field: 'projects', value: 'p' },
            { type: 'add', team: 'Events', field: 'projects', value: 'eventserver' },
        ])
        expect(next).toEqual([
            team('Core', ['a', 'b']),
            team('Phoenix', [], []),
            team('Events', [], ['eventserver']),
        ])
        expect(teams[1].components).toEqual(['b'])
    })
})

describe('buildChecks', () => {
    it('groups errors first, then warnings by the findings concerned, with fixes', () => {
        const teams = [
            team('Core', ['vp-stats-app', 'gone-lib']),
            team('Phoenix', ['VPStatsApp', 'libtiff']),
            team('3P', ['libtiff']),
            team('Unknown', ['*']),
        ]
        const groups = checksFor(teams)
        expect(groups.map(group => group.kind)).toEqual(['conflict', 'coverage', 'disagreement', 'stale'])
        expect(checkCounts(groups)).toEqual({ errors: 1, warnings: 5 })

        const [conflict] = groups[0].items
        expect(conflict.message).toBe('Entry libtiff is listed under Phoenix and 3P')
        expect(conflict.impact).toBe(187)
        expect(conflict.fixes.map(fix => fix.label)).toEqual(['Keep in Phoenix', 'Keep in 3P'])
        const kept = applyEdits(teams, conflict.fixes[1].actions)
        expect(kept.find(item => item.name === 'Phoenix')!.components).toEqual(['VPStatsApp'])
        expect(kept.find(item => item.name === '3P')!.components).toEqual(['libtiff'])

        // Projects by unowned findings, offering to assign the project.
        expect(groups[1].items.map(item => [item.message, item.assignProject])).toEqual([
            ['eventserver: 1202 findings of 1212 unowned', 'eventserver'],
            ['ViewPoint_Product: 18 findings of 1188 unowned', 'ViewPoint_Product'],
        ])

        // A near-duplicate pair is one item; a fix gives both entries to one team.
        expect(groups[2].items).toHaveLength(1)
        const disagreement = groups[2].items[0]
        expect(disagreement.message).toBe('vp-stats-app (Core) and VPStatsApp (Phoenix)')
        expect(disagreement.fixes.map(fix => fix.label)).toEqual(['Core owns all', 'Phoenix owns all'])
        const moved = applyEdits(teams, disagreement.fixes[0].actions)
        expect(moved.find(item => item.name === 'Core')!.components).toEqual(['vp-stats-app', 'gone-lib', 'VPStatsApp'])
        expect(moved.find(item => item.name === 'Phoenix')!.components).toEqual(['libtiff'])

        // Stale entries: removing them is the fix.
        expect(groups[3].items.map(item => item.message)).toEqual([
            'Core: gone-lib — Matches no stored component',
            'Phoenix: VPStatsApp — Matches no stored component',
        ])
        const removed = applyEdits(teams, groups[3].items[0].fixes[0].actions)
        expect(removed[0].components).toEqual(['vp-stats-app'])
    })

    it('treats a project under two teams and the catch-all owned twice as conflicts', () => {
        const groups = checksFor([
            team('Core', ['*'], ['eventserver']),
            team('Events', ['project::EventServer', '*']),
        ], null)
        const messages = groups[0].items.map(item => item.message)
        expect(messages).toContain('Project eventserver is listed under Core and Events')
        expect(messages).toContain('The catch-all * is listed under Core and Events')
        const project = groups[0].items.find(item => item.message.startsWith('Project'))!
        const keepCore = applyEdits([team('Core', ['*'], ['eventserver']), team('Events', ['project::EventServer', '*'])],
            project.fixes[0].actions)
        expect(keepCore[1].components).toEqual(['*'])
    })

    it('keeps one of two duplicates of a team and offers removing invalid entries', () => {
        const groups = checksFor([team('Core', ['com.vp:app', 'com.vp/app', 'project::'])])
        const duplicate = groups.find(group => group.kind === 'duplicate')!.items
        expect(duplicate).toHaveLength(1)
        expect(duplicate[0].fixes.map(fix => fix.label)).toEqual(['Keep com.vp/app', 'Keep com.vp:app'])
        const invalid = groups.find(group => group.kind === 'invalid')!.items[0]
        expect(invalid.fixes[0].actions).toEqual([{ type: 'remove', team: 'Core', field: 'components', value: 'project::' }])
    })
})
