export type AutomaticAssessmentOutcome =
    | 'AFFECTED'
    | 'PROBABLY_AFFECTED'
    | 'NOT_AFFECTED'
    | 'INCONCLUSIVE'

export type AutomaticAssessmentRescoreState =
    | 'CRITICAL'
    | 'HIGH'
    | 'MEDIUM'
    | 'LOW'
    | 'INFO'
    | 'NO_RESCORE'
    | 'UNSCORED'

export const AUTOMATIC_ASSESSMENT_OUTCOME_OPTIONS = [
    { value: 'AFFECTED', label: 'Affected' },
    { value: 'PROBABLY_AFFECTED', label: 'Probably affected' },
    { value: 'NOT_AFFECTED', label: 'Not affected' },
    { value: 'INCONCLUSIVE', label: 'Uncertain' },
] as const satisfies ReadonlyArray<{
    value: AutomaticAssessmentOutcome
    label: string
}>

export const AUTOMATIC_ASSESSMENT_RESCORE_OPTIONS = [
    { value: 'CRITICAL', label: 'Critical' },
    { value: 'HIGH', label: 'High' },
    { value: 'MEDIUM', label: 'Medium' },
    { value: 'LOW', label: 'Low' },
    { value: 'INFO', label: 'Info' },
    { value: 'NO_RESCORE', label: 'No rescore' },
    { value: 'UNSCORED', label: 'Unscored' },
] as const satisfies ReadonlyArray<{
    value: AutomaticAssessmentRescoreState
    label: string
}>

export const automaticAssessmentRescoreState = (
    rescore: Record<string, unknown> | null | undefined,
): AutomaticAssessmentRescoreState => {
    if (!rescore) return 'NO_RESCORE'
    const severity = String(rescore.proposed_severity || '').toUpperCase()
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity)) {
        return severity as AutomaticAssessmentRescoreState
    }
    const rawScore = rescore.proposed_score
    const score = Number(rawScore)
    if (rawScore !== null && rawScore !== undefined && rawScore !== '' && Number.isFinite(score)) {
        if (score >= 9) return 'CRITICAL'
        if (score >= 7) return 'HIGH'
        if (score >= 4) return 'MEDIUM'
        if (score > 0) return 'LOW'
        return 'INFO'
    }
    return 'UNSCORED'
}
