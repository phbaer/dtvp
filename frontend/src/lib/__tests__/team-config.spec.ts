// The cases of tests/fixtures/team_config_cases.json, shared with
// tests/test_team_config.py: errors and the derived selector mapping must
// be the same in the browser and on the server.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
    documentFromTeams,
    isTeamFormat,
    selectorMappingFromDocument,
    teamConfigErrors,
    teamRosterFromDocument,
    teamsFromDocument,
} from '../team-config'
import { buildTeamAliasGroups, resolveCanonicalTeamName } from '../team-mapping'

interface Case { name: string; document: Record<string, unknown>; errors: string[]; mapping?: Record<string, unknown> }

const { cases } = JSON.parse(readFileSync(
    resolve(__dirname, '../../../../tests/fixtures/team_config_cases.json'),
    'utf8',
)) as { cases: Case[] }

describe('team config shared cases', () => {
    it.each(cases.map(item => [item.name, item] as const))('%s', (_name, item) => {
        expect(teamConfigErrors(item.document)).toEqual(item.errors)
        if (item.mapping) expect(selectorMappingFromDocument(item.document)).toEqual(item.mapping)
    })
})

describe('team config', () => {
    it('tells the team format from selector keys', () => {
        expect(isTeamFormat({ Unknown: '*' })).toBe(true)
        expect(isTeamFormat({ Core: { components: ['x'] } })).toBe(true)
        expect(isTeamFormat({ '*': 'Unknown', core: 'Core' })).toBe(false)
        expect(selectorMappingFromDocument({ core: 'Core' })).toEqual({ core: 'Core' })
    })

    it('writes objects and leaves empty fields out', () => {
        const teams = teamsFromDocument({ Core: ['a', 'a', ' b '], Unknown: '*' })
        expect(documentFromTeams([...teams, { name: ' ', aliases: [], projects: [], components: [] }])).toEqual({
            Core: { components: ['a', 'b'] },
            Unknown: { components: ['*'] },
        })
    })
})

describe('the team roster', () => {
    const document = {
        Core: { aliases: ['DE-Core'], components: ['core'] },
        Events: { projects: ['eventserver'], aliases: ['Ops-Events'] },
        Newcomers: { aliases: ['Old-Newcomers'] },
        Unknown: '*',
    }

    it('lists every team, also those owning only projects or nothing', () => {
        expect(teamRosterFromDocument(document)).toEqual([
            { name: 'Core', aliases: ['DE-Core'] },
            { name: 'Events', aliases: ['Ops-Events'] },
            { name: 'Newcomers', aliases: ['Old-Newcomers'] },
            { name: 'Unknown', aliases: [] },
        ])
    })

    it('resolves aliases and groups teams the selector mapping does not name', () => {
        const roster = teamRosterFromDocument(document)
        const mapping = selectorMappingFromDocument(document)
        // The selector mapping has no entry for Newcomers.
        expect(Object.values(mapping).flat()).not.toContain('Newcomers')
        expect(resolveCanonicalTeamName(mapping, 'old-newcomers')).toBe('old-newcomers')
        expect(resolveCanonicalTeamName(mapping, 'old-newcomers', roster)).toBe('Newcomers')
        expect(resolveCanonicalTeamName(mapping, 'de-core', roster)).toBe('Core')
        expect(buildTeamAliasGroups(mapping, roster)).toEqual({
            Core: ['DE-Core'],
            Events: ['Ops-Events'],
            Newcomers: ['Old-Newcomers'],
            Unknown: [],
        })
    })
})
