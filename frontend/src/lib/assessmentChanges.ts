import type { GroupedVuln, Instance } from '../types'

export interface TeamChangesRequest {
    team: string
    rationale: string
    reviewer: string
    requested_at_ms: number
}

// The server owns these records. They are stored as complete lines in the
// shared assessment text and never copied into editable prose.
const changesMarker = () => /^\[Team Changes Requested: ([A-Za-z0-9_-]{1,8000})\]\r?$/gm

export const stripTeamChangesRequests = (details: string): string =>
    details.includes('Team Changes Requested') ? details.replace(changesMarker(), '').trim() : details

export function readTeamChangesRequests(details: string): TeamChangesRequest[] {
    if (!details.includes('[Team Changes Requested:')) return []
    const requests = new Map<string, TeamChangesRequest>()
    for (const line of details.split(/\r?\n/)) {
        if (!line.trim()) continue
        const match = changesMarker().exec(line)
        if (!match) break
        try {
            const base64 = match[1]!.replaceAll('-', '+').replaceAll('_', '/')
            const bytes = Uint8Array.from(atob(base64), character => character.charCodeAt(0))
            const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Partial<TeamChangesRequest> | null
            if (!value || typeof value.team !== 'string' || !value.team.trim() || [...value.team].length > 200
                || typeof value.rationale !== 'string' || !value.rationale.trim() || [...value.rationale].length > 1000
                || typeof value.reviewer !== 'string' || !value.reviewer.trim() || [...value.reviewer].length > 200
                || typeof value.requested_at_ms !== 'number' || !Number.isInteger(value.requested_at_ms)
                || value.requested_at_ms <= 0
                || /[\p{Cc}\p{Cs}]/u.test([value.team, value.rationale, value.reviewer].join('').replace(/[\n\t]/g, ''))) continue
            const team = value.team.trim()
            const teamKey = team.toLowerCase()
            if (teamKey === 'general') continue
            requests.set(teamKey, {
                team,
                rationale: value.rationale.trim(),
                reviewer: value.reviewer.trim(),
                requested_at_ms: value.requested_at_ms,
            })
        } catch {
            // A malformed marker does not supply a review record.
        }
    }
    return [...requests.values()]
}

const detailsOf = (instance: Instance): string | undefined =>
    instance.analysis_details ?? instance.analysisDetails

export function teamChangesRequestsForFindings(instances: Instance[]): TeamChangesRequest[] {
    const requests = instances.flatMap(instance => readTeamChangesRequests(detailsOf(instance) || ''))
    return [...new Map(requests.map(request => [JSON.stringify(request), request])).values()]
        .sort((left, right) => right.requested_at_ms - left.requested_at_ms)
}

export function getGroupChangesRequestedTeams(group: GroupedVuln): string[] {
    const instances = (group.affected_versions || []).flatMap(version => version.components || [])
    if (!instances.some(instance => typeof detailsOf(instance) === 'string')) {
        return group.list_metadata?.changes_requested_teams || []
    }
    return [...new Set(teamChangesRequestsForFindings(instances).map(request => request.team))]
}
