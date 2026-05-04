import type { AssessmentBlock } from './assessment-helpers'
import { parseAssessmentBlocks, parseJustificationFromText, STATE_PRIORITY } from './assessment-helpers'

export interface AssessmentInstanceState {
    analysis_state?: string
    analysisState?: string
    analysis_details?: string
    analysisDetails?: string
    justification?: string
    analysisJustification?: string
}

export interface AssessmentFormValues {
    state: string
    details: string
    justification: string
}

interface DtCandidate {
    state: string
    details: string
    justification: string
}

export interface DependencyTrackConsensusInput {
    dtStates: string[]
    dtJustification?: string
}

const DEFAULT_FORM_VALUES: AssessmentFormValues = {
    state: 'NOT_SET',
    details: '',
    justification: 'NOT_SET',
}

export const stripPendingReviewStatus = (details: string): string => {
    return details
        .replaceAll(/\n\n\[Status: Pending Review\]/g, '')
        .replaceAll(/\[Status: Pending Review\]/g, '')
}

export const cleanStructuredAssessmentDetails = (details: string): string => {
    return stripPendingReviewStatus(details)
        .replaceAll(/---\s*\[Team:[^\n]*---\s*/g, '')
        .replaceAll(/\[Rescored:\s*[\d.]+\]/g, '')
        .replaceAll(/\[Rescored Vector:\s*[^\]]+\]/g, '')
        .trim()
}

const extractDtCandidates = (instances: AssessmentInstanceState[]): DtCandidate[] => {
    return instances
        .map(instance => {
            const rawState = instance.analysis_state || instance.analysisState || 'NOT_SET'
            const rawDetails = instance.analysis_details || instance.analysisDetails || ''
            const rawJustification = instance.justification || instance.analysisJustification
            const parsedJustification = parseJustificationFromText(rawDetails)

            return {
                state: rawState,
                details: rawDetails,
                justification: rawJustification || parsedJustification || 'NOT_SET',
            }
        })
        .filter(candidate => candidate.state && candidate.state !== 'NOT_SET')
}

const getWorstDtCandidate = (instances: AssessmentInstanceState[]): DtCandidate | undefined => {
    return extractDtCandidates(instances)
        .sort((left, right) => (STATE_PRIORITY[left.state] ?? 10) - (STATE_PRIORITY[right.state] ?? 10))[0]
}

const resolveDtJustification = (
    dtCandidates: DtCandidate[],
    dtWorstCandidate?: DtCandidate,
): string | undefined => {
    let dtJustification = dtWorstCandidate ? dtWorstCandidate.justification : undefined

    if (dtWorstCandidate && (!dtJustification || dtJustification === 'NOT_SET')) {
        const sameStateCandidateJustification = dtCandidates.find(
            candidate => candidate.state === dtWorstCandidate.state && candidate.justification && candidate.justification !== 'NOT_SET',
        )?.justification

        if (sameStateCandidateJustification) {
            dtJustification = sameStateCandidateJustification
        } else {
            const blocks = parseAssessmentBlocks(dtWorstCandidate.details)
            const matching = blocks.find(
                block => block.state === dtWorstCandidate.state && block.justification && block.justification !== 'NOT_SET',
            )

            if (matching) {
                dtJustification = matching.justification
            } else {
                const parsed = parseJustificationFromText(dtWorstCandidate.details)
                if (parsed) {
                    dtJustification = parsed
                }
            }

            if (!dtJustification || dtJustification === 'NOT_SET') {
                const fallbackCandidate = dtCandidates.find(
                    candidate => candidate.state === dtWorstCandidate.state && candidate.justification && candidate.justification !== 'NOT_SET',
                )
                if (fallbackCandidate) {
                    dtJustification = fallbackCandidate.justification
                }
            }
        }
    }

    return dtJustification
}

const resolveDtFallbackFormValues = (instances: AssessmentInstanceState[]): AssessmentFormValues | null => {
    const dtCandidates = extractDtCandidates(instances)
    const dtWorstCandidate = getWorstDtCandidate(instances)

    if (!dtWorstCandidate) {
        return null
    }

    const dtParsedBlocks = parseAssessmentBlocks(dtWorstCandidate.details)
    const dtGeneralBlock = dtParsedBlocks.find(block => block.team === 'General')

    const resolvedJustification = resolveDtJustification(dtCandidates, dtWorstCandidate)

    return {
        state: dtWorstCandidate.state,
        details: stripPendingReviewStatus(dtGeneralBlock?.details || ''),
        justification: resolvedJustification || 'NOT_SET',
    }
}

export const resolveDependencyTrackConsensusInput = (
    instances: AssessmentInstanceState[],
): DependencyTrackConsensusInput => {
    const dtCandidates = extractDtCandidates(instances)
    const dtWorstCandidate = dtCandidates
        .slice()
        .sort((left, right) => (STATE_PRIORITY[left.state] ?? 10) - (STATE_PRIORITY[right.state] ?? 10))[0]

    return {
        dtStates: dtCandidates.map(candidate => candidate.state),
        dtJustification: resolveDtJustification(dtCandidates, dtWorstCandidate),
    }
}

const blockToFormValues = (block?: AssessmentBlock): AssessmentFormValues => {
    return {
        state: block?.state || 'NOT_SET',
        details: stripPendingReviewStatus(block?.details || ''),
        justification: block?.justification || 'NOT_SET',
    }
}

export const resolveAssessmentFormValues = ({
    selectedTeam,
    isReviewer,
    teamBlocks,
    instances,
}: {
    selectedTeam: string
    isReviewer: boolean
    teamBlocks: AssessmentBlock[]
    instances: AssessmentInstanceState[]
}): AssessmentFormValues => {
    if (selectedTeam) {
        return blockToFormValues(teamBlocks.find(block => block.team === selectedTeam))
    }

    if (!isReviewer) {
        return DEFAULT_FORM_VALUES
    }

    const generalBlock = teamBlocks.find(block => block.team === 'General')
    if (generalBlock && generalBlock.state !== 'NOT_SET') {
        return blockToFormValues(generalBlock)
    }

    const dtFallback = resolveDtFallbackFormValues(instances)
    if (dtFallback) {
        return dtFallback
    }

    if (generalBlock) {
        return blockToFormValues(generalBlock)
    }

    return DEFAULT_FORM_VALUES
}