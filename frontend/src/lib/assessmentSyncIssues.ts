import type { GroupedVuln, InconsistencyReason, Tags } from '../types'
import {
    assessedTeamKeys,
    assessmentTeamKey,
    getAssessedTeams,
    getGroupInconsistencyReasons,
    getGroupLifecycle,
    hasGlobalAssessmentForGroup,
    isPendingReview,
    normalizeTags,
} from './assessment-helpers'
import { INCONSISTENCY_REASON_OPTIONS } from './inconsistency'
import { getGroupChangesRequestedTeams } from './assessmentChanges'

export interface AssessmentSyncIssue {
    code: string
    kind: 'incomplete' | 'inconsistent' | 'approval'
    label: string
    detail: string
}

interface AssessmentSyncIssueOptions {
    lifecycle?: string
    requiredTeamsOrTags?: Tags
    teamMapping?: Record<string, string | string[]>
}

const humanizeState = (state: string) => state
    .toLowerCase()
    .replace(/_/g, ' ')
    .replace(/\b\w/g, character => character.toUpperCase())

const inconsistencyOption = (reason: InconsistencyReason) =>
    INCONSISTENCY_REASON_OPTIONS.find(option => option.value === reason)

const missingTeamsOf = (
    group: GroupedVuln,
    requiredTeamsOrTags: Tags,
    teamMapping: Record<string, string | string[]>,
): string[] => {
    const requiredTeams = normalizeTags(requiredTeamsOrTags, teamMapping)
    const assessedTeams = group.list_metadata?.assessed_teams
        ? new Set(group.list_metadata.assessed_teams)
        : getAssessedTeams(group)
    const assessedKeys = assessedTeamKeys(assessedTeams, teamMapping)
    return requiredTeams.filter(team =>
        assessmentTeamKey(team) !== 'unassigned' && !assessedKeys.has(assessmentTeamKey(team))
    )
}

/** A General block decides and is pending review: approving it completes
 * the teams without a block of their own
 * (docs/assessment-model.md#lifecycle-decision-table). */
const globalAwaitsApproval = (group: GroupedVuln): boolean =>
    isPendingReview(group) && hasGlobalAssessmentForGroup(group)

const APPROVE_GLOBAL = 'Approve the Global assessment to complete it.'
const changesRequestedIssue = (group: GroupedVuln): AssessmentSyncIssue | undefined => {
    const teams = getGroupChangesRequestedTeams(group)
    if (!teams.length) return
    return {
        code: 'CHANGES_REQUESTED',
        kind: 'incomplete',
        label: 'Changes requested',
        detail: `Waiting for ${teams.join(', ')} to resubmit for review.`,
    }
}

const incompleteIssues = (
    group: GroupedVuln,
    requiredTeamsOrTags: Tags,
    teamMapping: Record<string, string | string[]>,
): AssessmentSyncIssue[] => {
    const issues: AssessmentSyncIssue[] = []
    const changes = changesRequestedIssue(group)
    if (changes) issues.push(changes)
    const allInstances = (group.affected_versions || []).flatMap(version => version.components || [])
    const missingInstances = allInstances.filter(instance =>
        (instance.analysis_state || instance.analysisState || 'NOT_SET') === 'NOT_SET'
    )
    // An approved General decision covers every team (ADR 0014).
    const missingTeams = hasGlobalAssessmentForGroup(group) && !isPendingReview(group)
        ? []
        : missingTeamsOf(group, requiredTeamsOrTags, teamMapping)

    if (missingTeams.length > 0) {
        issues.push({
            code: 'MISSING_TEAM_ASSESSMENTS',
            kind: 'incomplete',
            label: 'Missing team assessments',
            detail: globalAwaitsApproval(group)
                ? `No assessment of their own for ${missingTeams.join(', ')}; the pending Global assessment covers them once approved.`
                : `No completed assessment for ${missingTeams.join(', ')}.`,
        })
    }

    if (missingInstances.length > 0) {
        const scopes = Array.from(new Set(missingInstances.map(instance => {
            const version = String(instance.project_version || '').trim()
            const component = String(instance.component_name || '').trim()
            return [version, component].filter(Boolean).join(' / ')
        }).filter(Boolean)))
        const scopeSummary = scopes.length > 0
            ? ` Affected: ${scopes.slice(0, 3).join(', ')}${scopes.length > 3 ? ` +${scopes.length - 3} more` : ''}.`
            : ''

        issues.push({
            code: 'UNASSESSED_FINDINGS',
            kind: 'incomplete',
            label: 'Unassessed findings',
            detail: `${missingInstances.length} of ${allInstances.length} finding instances have no analysis state.${scopeSummary}`,
        })
    }

    if (issues.length === 0) {
        issues.push({
            code: 'PARTIAL_ASSESSMENT_COVERAGE',
            kind: 'incomplete',
            label: 'Partial assessment coverage',
            detail: 'Assessment coverage is incomplete across the grouped findings.',
        })
    }

    return issues
}

const inconsistentIssues = (group: GroupedVuln): AssessmentSyncIssue[] => {
    const reasons = getGroupInconsistencyReasons(group)
    const allInstances = (group.affected_versions || []).flatMap(version => version.components || [])

    const issues = reasons.map((reason): AssessmentSyncIssue => {
        const option = inconsistencyOption(reason)
        let detail = option?.description || 'Grouped findings contain conflicting assessment data.'

        if (reason === 'ANALYSIS_STATE_MISMATCH') {
            const states = Array.from(new Set(allInstances
                .map(instance => instance.analysis_state || instance.analysisState || 'NOT_SET')
                .filter(state => state !== 'NOT_SET')))
            if (states.length > 0) {
                detail = `Current analysis states: ${states.map(humanizeState).join(', ')}.`
            }
        } else if (reason === 'MISSING_RESCORING_VECTOR') {
            const count = group.assessment_restore_count
                || group.list_metadata?.assessment_restore_count
                || 0
            if (count > 0) {
                detail = `${count} assessed finding${count === 1 ? '' : 's'} have rescoring evidence but no explicit rescored vector.`
            }
        }

        return {
            code: reason,
            kind: 'inconsistent',
            label: option?.label || reason.replace(/_/g, ' '),
            detail,
        }
    })

    if (issues.length === 0) {
        issues.push({
            code: 'ASSESSMENT_CONFLICT',
            kind: 'inconsistent',
            label: 'Assessment conflict',
            detail: 'Assessment data differs across the grouped findings.',
        })
    }

    return issues
}

export const getGroupAssessmentSyncIssues = (
    group: GroupedVuln,
    options: AssessmentSyncIssueOptions = {},
): AssessmentSyncIssue[] => {
    const teamMapping = options.teamMapping || {}
    const requiredTeamsOrTags = options.requiredTeamsOrTags || group.tags || []
    const lifecycle = options.lifecycle
        || group.list_metadata?.lifecycle
        || getGroupLifecycle(group, requiredTeamsOrTags, teamMapping)

    if (lifecycle === 'INCONSISTENT') return inconsistentIssues(group)
    if (lifecycle === 'INCOMPLETE') {
        return incompleteIssues(group, requiredTeamsOrTags, teamMapping)
    }
    if (lifecycle === 'NEEDS_APPROVAL' && globalAwaitsApproval(group)) {
        // Ready for approval although teams have no block of their own.
        const missingTeams = missingTeamsOf(group, requiredTeamsOrTags, teamMapping)
        if (missingTeams.length > 0) {
            return [{
                code: 'GLOBAL_AWAITS_APPROVAL',
                kind: 'approval',
                label: 'Covered by the pending Global assessment',
                detail: `No assessment of their own for ${missingTeams.join(', ')}. ${APPROVE_GLOBAL}`,
            }]
        }
    }
    return []
}

/**
 * Why a pending vulnerability cannot be approved now, or '' when it can or
 * nothing waits. Approval is for Ready for approval only
 * (docs/assessment-model.md#lifecycle-decision-table); the server refuses
 * it otherwise (assessment_use_cases.approval_blocker).
 */
export const getApprovalUnavailableReason = (
    group: GroupedVuln,
    options: AssessmentSyncIssueOptions = {},
): string => {
    const changes = changesRequestedIssue(group)
    if (changes) return changes.detail
    if (!isPendingReview(group)) return ''
    const teamMapping = options.teamMapping || {}
    const requiredTeamsOrTags = options.requiredTeamsOrTags || group.tags || []
    const lifecycle = options.lifecycle
        || group.list_metadata?.lifecycle
        || getGroupLifecycle(group, requiredTeamsOrTags, teamMapping)
    if (lifecycle === 'NEEDS_APPROVAL') return ''
    if (lifecycle === 'OPEN') return 'Approval is possible once it is ready for approval: nothing is decided yet.'
    if (lifecycle === 'INCONSISTENT') {
        return 'Approval is possible once it is ready for approval: the findings disagree; resolve the conflict first.'
    }
    if (lifecycle === 'INCOMPLETE') {
        const details = incompleteIssues(group, requiredTeamsOrTags, teamMapping).map(issue => issue.detail).join(' ')
        const missingTeams = !hasGlobalAssessmentForGroup(group)
            && missingTeamsOf(group, requiredTeamsOrTags, teamMapping).length > 0
        return `Approval is possible once it is ready for approval. ${details}`
            + (missingTeams ? ' Record the Global decision, or the missing team assessments, first.' : '')
    }
    return ''
}
