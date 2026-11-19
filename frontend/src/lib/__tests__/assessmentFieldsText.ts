import type { AssessmentFields } from '../assessment-helpers'

/**
 * Test double for the server: the text it renders for an assessment sent as
 * fields (header, newline, body; blocks separated by a blank line; the
 * pending marker last). Mirrors `render_assessment` in the backend's
 * `dtvp/assessment_model.py`; a spec there pins the exact format.
 */
export const renderAssessmentFields = (fields: AssessmentFields | undefined | null): string => {
    if (!fields) return ''
    const general = fields.teams.find(team => team.team === 'General')
    const parts: string[] = []
    const shared: string[] = []
    if (fields.rescored_score !== null && fields.rescored_score !== general?.rescored_score) {
        shared.push(`[Rescored: ${fields.rescored_score.toFixed(1)}]`)
    }
    if (fields.rescored_vector && fields.rescored_vector !== general?.rescored_vector) {
        shared.push(`[Rescored Vector: ${fields.rescored_vector}]`)
    }
    if (fields.response) shared.push(`[Response: ${fields.response}]`)
    if (shared.length) parts.push(shared.join(' '))
    if (fields.free_text) parts.push(fields.free_text)
    for (const team of fields.teams) {
        const tags = [
            `[Team: ${team.team}]`,
            `[State: ${team.state}]`,
            `[Assessed By: ${team.assessed_by || 'unknown'}]`,
        ]
        if (team.reviewed_by) tags.push(`[Reviewed By: ${team.reviewed_by}]`)
        if (team.assessed_at_ms) tags.push(`[Date: ${team.assessed_at_ms}]`)
        tags.push(`[Justification: ${team.justification || 'NOT_SET'}]`)
        if (team.assigned.length) tags.push(`[Assigned: ${team.assigned.join(', ')}]`)
        if (team.evidence_reviewed) tags.push(`[Evidence Reviewed: ${team.evidence_reviewed}]`)
        if (team.version_coverage) tags.push(`[Version Coverage: ${team.version_coverage}]`)
        if (team.ticket) tags.push(`[Ticket: ${team.ticket}]`)
        if (team.rescored_score !== null) tags.push(`[Rescored: ${team.rescored_score.toFixed(1)}]`)
        if (team.rescored_vector) tags.push(`[Rescored Vector: ${team.rescored_vector}]`)
        if (team.ssvc) tags.push(`[SSVC: ${team.ssvc}]`)
        if (team.historical) tags.push('[Historical: yes]')
        if (team.copied_from) tags.push(`[Copied From: ${team.copied_from}]`)
        const body = [team.details, team.ssvc_details].filter(Boolean).join('\n\n')
        parts.push(`--- ${tags.join(' ')} ---\n${body}`.trimEnd())
    }
    if (fields.pending_review) parts.push('[Status: Pending Review]')
    return parts.join('\n\n')
}
