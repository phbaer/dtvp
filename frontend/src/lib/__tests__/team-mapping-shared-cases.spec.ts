// The cases of tests/fixtures/team_mapping_cases.json, shared with the
// server's tests (tests/test_team_mapping_project_selectors.py): both
// matchers must agree on every one.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { findTeamMappingMatch, parseTeamMappingKey, type TeamMapping } from '../team-mapping'

interface ParseCase { key: string; expect?: Record<string, unknown>; error?: string }
interface MatchCase {
    identity: { name?: string; group?: string; purl?: string; groupKnown?: boolean }
    project: string | null
    wildcard: boolean
    expect: string | null
}
interface MatchGroup { name: string; mapping: TeamMapping; cases: MatchCase[] }

const cases = JSON.parse(readFileSync(
    resolve(__dirname, '../../../../tests/fixtures/team_mapping_cases.json'),
    'utf8',
)) as { parse: ParseCase[]; match: MatchGroup[] }

describe('team mapping shared parse cases', () => {
    it.each(cases.parse.map(item => [item.key || '<empty>', item] as const))('%s', (_label, item) => {
        const selector = parseTeamMappingKey(item.key)
        if (item.error !== undefined) {
            expect(selector.error).toBe(item.error)
            return
        }
        expect(selector.error).toBeUndefined()
        const actual: Record<string, unknown> = {
            name: selector.name,
            group: selector.group ?? null,
            purl: selector.purl ?? null,
            project: selector.project ?? null,
            projectFallback: Boolean(selector.projectFallback),
            caseSensitive: selector.caseSensitive,
            requireNoGroup: selector.requireNoGroup,
            wildcard: selector.wildcard,
        }
        for (const [field, value] of Object.entries(item.expect || {})) {
            expect(actual[field], field).toEqual(value)
        }
    })
})

describe('team mapping shared match cases', () => {
    for (const group of cases.match) {
        it.each(group.cases.map(item => [JSON.stringify(item.identity), item.project, item] as const))(
            `${group.name}: %s in %s`,
            (_identity, _project, item) => {
                const match = findTeamMappingMatch(group.mapping, item.identity, item.wildcard, item.project)
                expect(match?.key ?? null).toBe(item.expect)
            },
        )
    }
})
