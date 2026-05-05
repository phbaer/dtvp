import type { GroupedVuln } from '../types'
import { analysisQueueStore } from './analysisQueueStore'
import { hasCodeAnalysisInAssessmentText } from './assessment-helpers'

export type GroupCodeAnalysisStatus = 'used-in-assessment' | 'available' | 'not-available'

const normalizeId = (value: string | null | undefined) => String(value || '').trim().toUpperCase()

const getCandidateIds = (group: GroupedVuln) => {
    return new Set([group.id, ...(group.aliases || [])].map(normalizeId).filter(Boolean))
}

export function isCodeAnalysisUsedInAssessment(group: GroupedVuln): boolean {
    const allInstances = (group.affected_versions || []).flatMap(version => version.components || [])
    return allInstances.some(instance => hasCodeAnalysisInAssessmentText(instance.analysis_details || instance.analysisDetails || ''))
}

export function hasCodeAnalysisAvailable(group: GroupedVuln): boolean {
    if (isCodeAnalysisUsedInAssessment(group)) {
        return true
    }

    const candidateIds = getCandidateIds(group)
    return analysisQueueStore.items.value.some(item => item.status === 'completed' && candidateIds.has(normalizeId(item.vuln_id)))
}

export function getGroupCodeAnalysisStatus(group: GroupedVuln): GroupCodeAnalysisStatus {
    if (isCodeAnalysisUsedInAssessment(group)) {
        return 'used-in-assessment'
    }

    if (hasCodeAnalysisAvailable(group)) {
        return 'available'
    }

    return 'not-available'
}