/**
 * The team overview on the Global assessment: one row per team that is
 * required for the vulnerability or has a current assessment block, so a
 * reviewer sees what every team decided without opening each team tab.
 * Pure functions; the card passes what it already loaded.
 */
import type { AssessmentBlock } from './assessment-helpers'
import { stripPendingReviewStatus } from './assessmentFormState'
import { stripSsvcDocumentation } from './ssvc'

/** What the card already resolves per required team (saved, draft or analyzer fallback). */
export interface TeamOverviewInput {
    team: string
    state: string
    justification: string
    details: string
    source: 'team' | 'automatic' | 'missing'
}

export type TeamOverviewStatus = 'approved' | 'pending' | 'changes-requested' | 'submitted' | 'missing'

export interface TeamOverviewRow {
    team: string
    /** False for a team with a current block that the vulnerability no longer requires. */
    required: boolean
    /** The state shown: the team's decision, its unsaved draft or the analyzer proposal. */
    state: string
    justification: string
    status: TeamOverviewStatus
    /** Where the shown state comes from. */
    source: 'saved' | 'draft' | 'automatic' | 'missing'
    user: string
    timestamp?: number
    reviewer?: string
    reviewedAt?: number
    components: string[]
    rationale: string
    rationaleFirstLine: string
    /** Differs from the other teams or from the Global decision. */
    disagrees: boolean
    disagreesWithGlobal: boolean
}

export interface TeamOverview {
    rows: TeamOverviewRow[]
    summary: string
    missingTeams: string[]
    formerCount: number
    /** At least two teams or a team and the Global decision disagree. */
    hasDisagreement: boolean
}

export interface TeamOverviewOptions {
    teams: TeamOverviewInput[]
    /** All merged blocks of the vulnerability, historical ones included. */
    blocks: AssessmentBlock[]
    /** Primary team name → aliases, from the team mapping. */
    aliasGroups?: Record<string, string[]>
    /** Lower-case team name → the team's components. */
    componentsByTeam?: Map<string, string[]>
    /** The vulnerability carries [Status: Pending Review]. */
    pendingReview?: boolean
    changesRequestedTeams?: string[]
    /** The state in the Global form; NOT_SET for none. */
    globalState?: string
}

/** Above this many rows the overview shows only the rows that need a look. */
export const TEAM_OVERVIEW_COLLAPSE_LIMIT = 5

const key = (value: string) => value.trim().toLocaleLowerCase()
const hasState = (state?: string) => !!state && state !== 'NOT_SET'

/** "NOT_AFFECTED" → "Not affected". */
export const stateLabel = (state: string): string => {
    const words = (state || 'NOT_SET').replaceAll('_', ' ').toLowerCase()
    return words.charAt(0).toUpperCase() + words.slice(1)
}

export const statusLabel = (status: TeamOverviewStatus): string => ({
    approved: 'approved',
    pending: 'pending review',
    'changes-requested': 'changes requested',
    submitted: 'submitted',
    missing: 'no assessment',
})[status]

/** Maps a team name or one of its aliases to the primary team name. */
export const resolveTeamAlias = (name: string, aliasGroups: Record<string, string[]> = {}): string => {
    const wanted = key(name)
    for (const [primary, aliases] of Object.entries(aliasGroups)) {
        if (key(primary) === wanted || aliases.some(alias => key(alias) === wanted)) return primary
    }
    return name
}

const cleanRationale = (details: string) => stripPendingReviewStatus(stripSsvcDocumentation(details || '')).trim()

const newest = (blocks: AssessmentBlock[]) => blocks
    .slice()
    .sort((left, right) => (right.timestamp || 0) - (left.timestamp || 0))[0]

const statusOf = (block: AssessmentBlock | undefined, pendingReview: boolean, globalDecided: boolean): TeamOverviewStatus => {
    if (!block || !hasState(block.state)) return 'missing'
    if (block.reviewer?.trim()) return 'approved'
    if (pendingReview) return 'pending'
    return globalDecided ? 'approved' : 'submitted'
}

/** The state most teams share, or '' when two or more states tie. */
const majorityState = (states: string[]): string => {
    const counts = new Map<string, number>()
    for (const state of states) counts.set(state, (counts.get(state) || 0) + 1)
    const ranked = [...counts.entries()].sort((left, right) => right[1] - left[1])
    if (!ranked.length) return ''
    if (ranked.length > 1 && ranked[0]![1] === ranked[1]![1]) return ''
    return ranked[0]![0]
}

const rank = (row: TeamOverviewRow) => (
    row.status === 'changes-requested' || row.disagrees ? 0 : row.status === 'missing' ? 1 : 2
)

export const buildTeamOverview = (options: TeamOverviewOptions): TeamOverview => {
    const aliasGroups = options.aliasGroups || {}
    const changesRequested = new Set((options.changesRequestedTeams || [])
        .map(team => key(resolveTeamAlias(team, aliasGroups))))
    const pendingReview = !!options.pendingReview
    const globalState = hasState(options.globalState) ? options.globalState! : ''
    const active = options.blocks.filter(block => !block.historical)
    const globalDecided = active.some(block => key(block.team) === 'general' && hasState(block.state))
    const teamBlocks = new Map<string, AssessmentBlock[]>()
    for (const block of active) {
        if (key(block.team) === 'general') continue
        const team = key(resolveTeamAlias(block.team, aliasGroups))
        teamBlocks.set(team, [...(teamBlocks.get(team) || []), block])
    }

    const rows: TeamOverviewRow[] = []
    const seen = new Set<string>()
    const addRow = (input: TeamOverviewInput, required: boolean) => {
        const teamKey = key(resolveTeamAlias(input.team, aliasGroups))
        if (seen.has(teamKey)) return
        seen.add(teamKey)
        const block = newest((teamBlocks.get(teamKey) || []).filter(candidate => hasState(candidate.state)))
        const status = changesRequested.has(teamKey)
            ? 'changes-requested'
            : statusOf(block, pendingReview, globalDecided)
        const draft = input.source === 'team' && hasState(input.state) && (
            !block
            || block.state !== input.state
            || (block.justification || 'NOT_SET') !== (input.justification || 'NOT_SET')
            || cleanRationale(block.details) !== cleanRationale(input.details)
        )
        const shown = draft || input.source === 'automatic'
            ? input
            : block
                ? { state: block.state, justification: block.justification, details: block.details }
                : input
        const rationale = cleanRationale(shown.details)
        rows.push({
            team: input.team,
            required,
            state: hasState(shown.state) ? shown.state : 'NOT_SET',
            justification: shown.justification || 'NOT_SET',
            status,
            source: draft ? 'draft' : block ? 'saved' : input.source === 'automatic' && hasState(input.state) ? 'automatic' : 'missing',
            user: block?.user && key(block.user) !== 'unknown' ? block.user : '',
            timestamp: block?.timestamp,
            reviewer: block?.reviewer,
            reviewedAt: block?.reviewedAt,
            components: options.componentsByTeam?.get(key(input.team)) || options.componentsByTeam?.get(teamKey) || [],
            rationale,
            rationaleFirstLine: rationale.split('\n').map(line => line.trim()).find(Boolean) || '',
            disagrees: false,
            disagreesWithGlobal: false,
        })
    }

    for (const input of options.teams) {
        if (key(input.team) === 'general') continue
        addRow(input, true)
    }
    for (const [teamKey, blocks] of teamBlocks) {
        if (seen.has(teamKey)) continue
        const block = newest(blocks)!
        addRow({
            team: resolveTeamAlias(block.team, aliasGroups),
            state: block.state,
            justification: block.justification,
            details: block.details,
            source: 'missing',
        }, false)
    }

    // Only teams with a saved decision take part (with their unsaved edits);
    // a draft or analyzer proposal for a missing team is a hint, not a decision.
    const decided = rows.filter(row => row.status !== 'missing')
    const majority = majorityState(decided.map(row => row.state))
    const teamsDisagree = new Set(decided.map(row => row.state)).size > 1
    for (const row of decided) {
        row.disagreesWithGlobal = !!globalState && row.state !== globalState
        row.disagrees = (teamsDisagree && row.state !== majority) || row.disagreesWithGlobal
    }

    const sorted = rows
        .map((row, index) => ({ row, index }))
        .sort((left, right) => rank(left.row) - rank(right.row) || left.index - right.index)
        .map(entry => entry.row)

    const missingTeams = rows.filter(row => row.status === 'missing').map(row => row.team)
    const counts = new Map<string, string[]>()
    for (const row of decided) counts.set(row.state, [...(counts.get(row.state) || []), row.team])
    const stateParts = [...counts.entries()]
        .sort((left, right) => right[1].length - left[1].length || left[0].localeCompare(right[0]))
        .map(([state, teams]) => {
            const named = teamsDisagree && state !== majority ? ` (${teams.join(', ')})` : ''
            return `${teams.length} ${stateLabel(state)}${named}`
        })
    const differFromGlobal = decided.filter(row => row.disagreesWithGlobal).length
    const parts = [
        `${rows.length} ${rows.length === 1 ? 'team' : 'teams'}${stateParts.length ? `: ${stateParts.join(', ')}` : ''}`,
        ...(missingTeams.length ? [`${missingTeams.length} missing (${missingTeams.join(', ')})`] : []),
        ...(differFromGlobal ? [`${differFromGlobal} differ${differFromGlobal === 1 ? 's' : ''} from Global ${stateLabel(globalState)}`] : []),
    ]

    return {
        rows: sorted,
        summary: parts.join(' · '),
        missingTeams,
        formerCount: options.blocks.filter(block => block.historical && key(block.team) !== 'general').length,
        hasDisagreement: sorted.some(row => row.disagrees),
    }
}

/**
 * The rows to show: all of them up to the limit or when asked for, otherwise
 * only the disagreeing and missing ones.
 */
export const visibleTeamOverviewRows = (
    rows: TeamOverviewRow[],
    showAll: boolean,
    limit = TEAM_OVERVIEW_COLLAPSE_LIMIT,
): TeamOverviewRow[] => (
    showAll || rows.length <= limit
        ? rows
        : rows.filter(row => row.disagrees || row.status === 'missing' || row.status === 'changes-requested')
)
