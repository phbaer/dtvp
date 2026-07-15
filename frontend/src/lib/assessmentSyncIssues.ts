import type { GroupedVuln, InconsistencyReason, Tags } from '../types'
import {
    getAssessedTeams,
    getGroupInconsistencyReasons,
    getGroupLifecycle,
    hasGlobalAssessmentForGroup,
    normalizeTags,
} from './assessment-helpers'
import { INCONSISTENCY_REASON_OPTIONS } from './inconsistency'

export interface AssessmentSyncIssue {
    code: string
    kind: 'incomplete' | 'inconsistent'
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

const incompleteIssues = (
    group: GroupedVuln,
    requiredTeamsOrTags: Tags,
    teamMapping: Record<string, string | string[]>,
): AssessmentSyncIssue[] => {
    const issues: AssessmentSyncIssue[] = []
    const allInstances = (group.affected_versions || []).flatMap(version => version.components || [])
    const missingInstances = allInstances.filter(instance =>
        (instance.analysis_state || instance.analysisState || 'NOT_SET') === 'NOT_SET'
    )
    const requiredTeams = normalizeTags(requiredTeamsOrTags, teamMapping)
    const assessedTeams = getAssessedTeams(group)
    const missingTeams = requiredTeams.filter(team => !assessedTeams.has(team))

    if (missingTeams.length > 0) {
        issues.push({
            code: 'MISSING_TEAM_ASSESSMENTS',
            kind: 'incomplete',
            label: 'Missing team assessments',
            detail: `No completed assessment for ${missingTeams.join(', ')}.`,
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

    if (!hasGlobalAssessmentForGroup(group)) {
        issues.push({
            code: 'MISSING_GLOBAL_ASSESSMENT',
            kind: 'incomplete',
            label: 'Missing global assessment',
            detail: 'No completed General assessment provides a group-wide result.',
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
    return []
}
