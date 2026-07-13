import type { InconsistencyReason } from '../types'

export const INCONSISTENCY_REASON_OPTIONS: ReadonlyArray<{
    value: InconsistencyReason
    label: string
    description: string
}> = [
    {
        value: 'MISSING_RESCORING_VECTOR',
        label: 'Missing CVSS metadata',
        description: 'The assessment has rescoring evidence but no explicit rescored vector.',
    },
    {
        value: 'ANALYSIS_STATE_MISMATCH',
        label: 'Analysis states differ',
        description: 'Affected components or project versions have different technical states.',
    },
    {
        value: 'TEAM_ASSESSMENT_MISMATCH',
        label: 'Team assessments differ',
        description: 'Structured team assessment blocks differ within or across findings.',
    },
    {
        value: 'ASSESSMENT_DETAILS_MISMATCH',
        label: 'Assessment details differ',
        description: 'Assessed findings have different substantive assessment text.',
    },
]

const inconsistencyReasonSet = new Set<string>(
    INCONSISTENCY_REASON_OPTIONS.map(option => option.value),
)

export const normalizeInconsistencyReasons = (values: unknown): InconsistencyReason[] => {
    if (!Array.isArray(values)) return []
    return Array.from(new Set(values
        .map(value => String(value || '').trim().toUpperCase())
        .filter(value => inconsistencyReasonSet.has(value)))) as InconsistencyReason[]
}

export const inconsistencyReasonLabel = (reason: InconsistencyReason): string =>
    INCONSISTENCY_REASON_OPTIONS.find(option => option.value === reason)?.label
    || reason.replace(/_/g, ' ')
