import type { AffectedVersion, GroupedVuln, Instance } from '../types'
import {
    getAssessedTeams,
    getGroupInconsistencyReasons,
    hasGlobalAssessmentForGroup,
    normalizeTags,
} from './assessment-helpers'
import { classifyGroup } from './group-classifier'

export const isSummaryGroupedVuln = (group: GroupedVuln | null | undefined) =>
    !!group?.list_metadata

const normalizeAssessedTeams = (
    teams: Iterable<string>,
    teamMapping: Record<string, any>,
) => Array.from(new Set(normalizeTags(Array.from(teams), teamMapping))).sort()

const summarizeComponent = (component: Instance): Instance => ({
    project_name: component.project_name,
    project_version: component.project_version,
    project_uuid: component.project_uuid,
    component_name: component.component_name,
    component_version: component.component_version,
    component_uuid: component.component_uuid,
    vulnerability_uuid: component.vulnerability_uuid,
    finding_uuid: component.finding_uuid,
    attributed_on: component.attributed_on,
    analysis_state: component.analysis_state,
    analysisState: component.analysisState,
    justification: component.justification,
    is_suppressed: component.is_suppressed,
    is_direct_dependency: component.is_direct_dependency,
    tags: component.tags ? [...component.tags] : undefined,
    assessment_restore: component.assessment_restore ? { ...component.assessment_restore } : undefined,
})

const summarizeAffectedVersion = (version: AffectedVersion): AffectedVersion => ({
    project_name: version.project_name,
    project_version: version.project_version,
    project_uuid: version.project_uuid,
    components: (version.components || []).map(summarizeComponent),
})

export const summarizeGroupForList = (
    group: GroupedVuln,
    teamMapping: Record<string, any>,
): GroupedVuln => {
    const classification = classifyGroup(group, teamMapping)
    const isAssessed = (
        hasGlobalAssessmentForGroup(group) &&
        !classification.isPending
    ) || classification.lifecycle === 'ASSESSED_LEGACY'
    const inconsistencyReasons = getGroupInconsistencyReasons(group)

    return {
        id: group.id,
        title: group.title,
        description: group.description,
        severity: group.severity,
        cvss: group.cvss,
        cvss_score: group.cvss_score,
        cvss_vector: group.cvss_vector,
        rescored_cvss: group.rescored_cvss ?? null,
        rescored_vector: group.rescored_vector ?? null,
        rescored_vector_adjusted: group.rescored_vector_adjusted,
        tags: group.tags ? [...group.tags] : undefined,
        assignees: group.assignees ? [...group.assignees] : undefined,
        aliases: group.aliases ? [...group.aliases] : undefined,
        assessment_restore_count: group.assessment_restore_count ?? 0,
        assessment_restore_recoverable_count: group.assessment_restore_recoverable_count ?? 0,
        assessment_restore_reasons: group.assessment_restore_reasons ? [...group.assessment_restore_reasons] : [],
        assessment_restore_status: group.assessment_restore_status ?? null,
        list_metadata: {
            lifecycle: classification.lifecycle,
            inconsistency_reasons: inconsistencyReasons,
            is_pending: classification.isPending,
            is_open: classification.isOpen,
            is_assessed: isAssessed,
            technical_state: classification.technicalState,
            assessed_teams: normalizeAssessedTeams(getAssessedTeams(group), teamMapping),
            assessment_restore_count: group.assessment_restore_count ?? 0,
            assessment_restore_recoverable_count: group.assessment_restore_recoverable_count ?? 0,
            assessment_restore_reasons: group.assessment_restore_reasons ? [...group.assessment_restore_reasons] : [],
            assessment_restore_status: group.assessment_restore_status ?? null,
        },
        affected_versions: (group.affected_versions || []).map(summarizeAffectedVersion),
    }
}
