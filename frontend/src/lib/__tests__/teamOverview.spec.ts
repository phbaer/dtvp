import { describe, expect, it } from 'vitest'
import type { AssessmentBlock } from '../assessment-helpers'
import {
    buildTeamOverview,
    resolveTeamAlias,
    stateLabel,
    TEAM_OVERVIEW_COLLAPSE_LIMIT,
    visibleTeamOverviewRows,
    type TeamOverviewInput,
} from '../teamOverview'

const block = (team: string, state: string, extra: Partial<AssessmentBlock> = {}): AssessmentBlock => ({
    team,
    state,
    user: 'alice',
    details: `${team} rationale.`,
    justification: state === 'NOT_AFFECTED' ? 'CODE_NOT_REACHABLE' : 'NOT_SET',
    timestamp: 1_700_000_000_000,
    ...extra,
})

const saved = (team: string, state: string): TeamOverviewInput => ({
    team,
    state,
    justification: state === 'NOT_AFFECTED' ? 'CODE_NOT_REACHABLE' : 'NOT_SET',
    details: `${team} rationale.`,
    source: 'team',
})
const missing = (team: string): TeamOverviewInput => ({ team, state: 'NOT_SET', justification: 'NOT_SET', details: '', source: 'missing' })

describe('buildTeamOverview', () => {
    it('sums up agreeing teams without highlighting', () => {
        const overview = buildTeamOverview({
            teams: [saved('A-Core', 'NOT_AFFECTED'), saved('B-Core', 'NOT_AFFECTED')],
            blocks: [block('A-Core', 'NOT_AFFECTED'), block('B-Core', 'NOT_AFFECTED')],
            pendingReview: true,
        })
        expect(overview.summary).toBe('2 teams: 2 Not affected')
        expect(overview.hasDisagreement).toBe(false)
        expect(overview.rows.map(row => [row.team, row.status, row.disagrees])).toEqual([
            ['A-Core', 'pending', false],
            ['B-Core', 'pending', false],
        ])
        expect(overview.rows[0]).toMatchObject({
            state: 'NOT_AFFECTED',
            justification: 'CODE_NOT_REACHABLE',
            user: 'alice',
            timestamp: 1_700_000_000_000,
            rationaleFirstLine: 'A-Core rationale.',
            required: true,
            source: 'saved',
        })
    })

    it('names the minority and the missing teams and sorts disagreeing, missing, agreeing', () => {
        const overview = buildTeamOverview({
            teams: [
                saved('A-Core', 'NOT_AFFECTED'),
                missing('K-Core'),
                saved('B-Core', 'NOT_AFFECTED'),
                saved('H-Core', 'EXPLOITABLE'),
                saved('C-Core', 'NOT_AFFECTED'),
            ],
            blocks: ['A-Core', 'B-Core', 'C-Core'].map(team => block(team, 'NOT_AFFECTED')).concat(block('H-Core', 'EXPLOITABLE')),
            pendingReview: true,
        })
        expect(overview.summary).toBe('5 teams: 3 Not affected, 1 Exploitable (H-Core) · 1 missing (K-Core)')
        expect(overview.rows.map(row => row.team)).toEqual(['H-Core', 'K-Core', 'A-Core', 'B-Core', 'C-Core'])
        expect(overview.rows[0]!.disagrees).toBe(true)
        expect(overview.rows[1]!.status).toBe('missing')
        expect(overview.missingTeams).toEqual(['K-Core'])
        expect(overview.hasDisagreement).toBe(true)
    })

    it('highlights every team when states tie', () => {
        const overview = buildTeamOverview({
            teams: [saved('A', 'NOT_AFFECTED'), saved('B', 'EXPLOITABLE')],
            blocks: [block('A', 'NOT_AFFECTED'), block('B', 'EXPLOITABLE')],
        })
        expect(overview.rows.every(row => row.disagrees)).toBe(true)
        expect(overview.summary).toBe('2 teams: 1 Exploitable (B), 1 Not affected (A)')
    })

    it('highlights teams that differ from the Global decision', () => {
        const overview = buildTeamOverview({
            teams: [saved('A', 'NOT_AFFECTED'), saved('B', 'NOT_AFFECTED')],
            blocks: [block('A', 'NOT_AFFECTED'), block('B', 'NOT_AFFECTED'), block('General', 'EXPLOITABLE')],
            globalState: 'EXPLOITABLE',
        })
        expect(overview.rows.every(row => row.disagrees && row.disagreesWithGlobal)).toBe(true)
        expect(overview.summary).toBe('2 teams: 2 Not affected · 2 differ from Global Exploitable')
        expect(overview.rows[0]!.status).toBe('approved')
    })

    it('resolves aliases to the team and finds its block under an alias', () => {
        const aliasGroups = { 'H-Core': ['HCore', 'hcore-legacy'] }
        expect(resolveTeamAlias('hcore-legacy', aliasGroups)).toBe('H-Core')
        expect(resolveTeamAlias('Other', aliasGroups)).toBe('Other')
        const overview = buildTeamOverview({
            teams: [missing('H-Core')],
            blocks: [block('HCore', 'EXPLOITABLE', { user: 'bob' })],
            aliasGroups,
            componentsByTeam: new Map([['h-core', ['libxml2', 'zlib']]]),
            pendingReview: true,
        })
        expect(overview.rows).toHaveLength(1)
        expect(overview.rows[0]).toMatchObject({
            team: 'H-Core',
            state: 'EXPLOITABLE',
            status: 'pending',
            user: 'bob',
            components: ['libxml2', 'zlib'],
            required: true,
        })
    })

    it('adds a team with a current block that is no longer required', () => {
        const overview = buildTeamOverview({
            teams: [saved('A', 'NOT_AFFECTED')],
            blocks: [block('A', 'NOT_AFFECTED'), block('Gone-Team', 'NOT_AFFECTED')],
        })
        expect(overview.rows.map(row => [row.team, row.required])).toEqual([['A', true], ['Gone-Team', false]])
    })

    it('leaves historical blocks out of the rows and counts them', () => {
        const overview = buildTeamOverview({
            teams: [saved('A', 'NOT_AFFECTED')],
            blocks: [
                block('A', 'NOT_AFFECTED'),
                block('Former', 'EXPLOITABLE', { historical: true }),
                block('A', 'EXPLOITABLE', { historical: true }),
            ],
        })
        expect(overview.rows.map(row => row.team)).toEqual(['A'])
        expect(overview.formerCount).toBe(2)
        expect(overview.hasDisagreement).toBe(false)
    })

    it('derives the status from the review marker, the reviewer and the Global decision', () => {
        const teams = [saved('A', 'NOT_AFFECTED'), saved('B', 'NOT_AFFECTED')]
        const blocks = [block('A', 'NOT_AFFECTED', { reviewer: 'rita' }), block('B', 'NOT_AFFECTED')]
        expect(buildTeamOverview({ teams, blocks, pendingReview: true }).rows.map(row => row.status))
            .toEqual(['approved', 'pending'])
        expect(buildTeamOverview({ teams, blocks }).rows.map(row => row.status))
            .toEqual(['approved', 'submitted'])
        expect(buildTeamOverview({ teams, blocks: [...blocks, block('General', 'NOT_AFFECTED')] }).rows.map(row => row.status))
            .toEqual(['approved', 'approved'])
    })

    it('shows an analyzer proposal or an unsaved draft but counts the team as missing', () => {
        const overview = buildTeamOverview({
            teams: [
                { team: 'A', state: 'EXPLOITABLE', justification: 'NOT_SET', details: 'Reachable.', source: 'automatic' },
                { team: 'B', state: 'NOT_AFFECTED', justification: 'NOT_SET', details: 'Draft.', source: 'team' },
                saved('C', 'NOT_AFFECTED'),
            ],
            blocks: [block('C', 'NOT_AFFECTED')],
        })
        expect(overview.rows.map(row => [row.team, row.status, row.source, row.state])).toEqual([
            ['A', 'missing', 'automatic', 'EXPLOITABLE'],
            ['B', 'missing', 'draft', 'NOT_AFFECTED'],
            ['C', 'submitted', 'saved', 'NOT_AFFECTED'],
        ])
        expect(overview.summary).toBe('3 teams: 1 Not affected · 2 missing (A, B)')
        expect(overview.hasDisagreement).toBe(false)
    })

    it('shows the unsaved edit of a saved team and compares it', () => {
        const overview = buildTeamOverview({
            teams: [saved('A', 'EXPLOITABLE'), saved('B', 'NOT_AFFECTED'), saved('C', 'NOT_AFFECTED')],
            blocks: [block('A', 'NOT_AFFECTED'), block('B', 'NOT_AFFECTED'), block('C', 'NOT_AFFECTED')],
        })
        expect(overview.rows[0]).toMatchObject({ team: 'A', source: 'draft', state: 'EXPLOITABLE', status: 'submitted', disagrees: true })
    })

    it('strips the review marker and SSVC documentation from the rationale', () => {
        const details = '\nFirst line.\nSecond line.\n\n[Status: Pending Review]'
        const overview = buildTeamOverview({
            teams: [{ ...saved('A', 'NOT_AFFECTED'), details }],
            blocks: [block('A', 'NOT_AFFECTED', { details })],
        })
        expect(overview.rows[0]!.source).toBe('saved')
        expect(overview.rows[0]!.rationaleFirstLine).toBe('First line.')
        expect(overview.rows[0]!.rationale).toBe('First line.\nSecond line.')
    })

    it('skips a General entry in the inputs', () => {
        const overview = buildTeamOverview({ teams: [saved('General', 'NOT_AFFECTED')], blocks: [] })
        expect(overview.rows).toEqual([])
        expect(overview.summary).toBe('0 teams')
    })
})

describe('visibleTeamOverviewRows', () => {
    const many = (count: number, disagreeing: number[] = [], missingAt: number[] = []) => buildTeamOverview({
        teams: Array.from({ length: count }, (_, index) => missingAt.includes(index)
            ? missing(`T${index}`)
            : saved(`T${index}`, disagreeing.includes(index) ? 'EXPLOITABLE' : 'NOT_AFFECTED')),
        blocks: Array.from({ length: count }, (_, index) => index)
            .filter(index => !missingAt.includes(index))
            .map(index => block(`T${index}`, disagreeing.includes(index) ? 'EXPLOITABLE' : 'NOT_AFFECTED')),
    }).rows

    it('shows every row up to the limit', () => {
        const rows = many(TEAM_OVERVIEW_COLLAPSE_LIMIT)
        expect(visibleTeamOverviewRows(rows, false)).toHaveLength(TEAM_OVERVIEW_COLLAPSE_LIMIT)
    })

    it('collapses to the disagreeing and missing rows above the limit, and shows all on request', () => {
        const rows = many(8, [3], [6])
        expect(visibleTeamOverviewRows(rows, false).map(row => row.team)).toEqual(['T3', 'T6'])
        expect(visibleTeamOverviewRows(rows, true)).toHaveLength(8)
    })
})

describe('stateLabel', () => {
    it('writes states in sentence case', () => {
        expect(stateLabel('NOT_AFFECTED')).toBe('Not affected')
        expect(stateLabel('EXPLOITABLE')).toBe('Exploitable')
    })
})
