import { constructAssessmentDetails, mergeTeamAssessment, parseAssessmentBlocks, sanitizeAssessmentDetails, type AssessmentBlock } from './assessment-helpers'
import { cleanStructuredAssessmentDetails } from './assessmentFormState'
import type { AssessmentPayload, Instance } from '../types'

const RESCORED_TAG_REGEX = /\[Rescored:\s*[\d.]+\]/
const RESCORED_VECTOR_TAG_REGEX = /\[Rescored Vector:\s*[^\]]+\]/
const RESCORED_TAG_VALUE_REGEX = /\[Rescored:\s*([\d.]+)\]/
const RESCORED_VECTOR_VALUE_REGEX = /\[Rescored Vector:\s*([^\]]+)\]/

export interface AssessmentDraft {
    state: string
    details: string
    justification: string
    assigned: string[]
    evidenceReviewed: boolean
    versionCoverageChecked: boolean
    ticket: string
}

interface PrepareAssessmentSubmissionInput {
    allInstances: Instance[]
    originalAnalysis: Record<string, any>
    selectedTeam: string
    state: string
    details: string
    justification: string
    currentAssigned: string[]
    evidenceReviewed: boolean
    versionCoverageChecked: boolean
    ticket: string
    teamDrafts: Map<string, AssessmentDraft>
    isReviewer: boolean
    pendingVector: string
    pendingScore: number | null
    initialVector: string
    initialScore: number | null
    originalVector?: string
    originalScore?: number | null
    currentUser: string
    isApprove: boolean
    showRawEdit: boolean
    rawDetailsTouched: boolean
    rawDetails: string
    mergedAssessmentFullText: string
    suppressed: boolean
    force: boolean
}

export interface PreparedAssessmentSubmission {
    targetTeam: string
    nextDrafts: Map<string, AssessmentDraft>
    reviewText: string
    finalText: string
    finalState: string
    payload: AssessmentPayload
}

export interface AssessmentUpdateSuccessResult {
    new_state: string
    new_details: string
}

export interface EmittedAssessmentUpdate {
    rescored_cvss: number | null
    rescored_vector: string | null
    analysis_state: string
    analysis_details: string
    is_suppressed: boolean
    assignees: string[]
}

export interface SavedAssessmentResultState {
    emittedAssessment: EmittedAssessmentUpdate
    nextPendingVector: string
    nextInitialVector: string
    nextInitialScore: number | null
    nextLastRescoredScore: number | null
}

const upsertLatestBlock = (
    allBlocks: AssessmentBlock[],
    teamToIndex: Map<string, number>,
    block: AssessmentBlock,
) => {
    const existingIndex = teamToIndex.get(block.team)
    if (existingIndex === undefined) {
        teamToIndex.set(block.team, allBlocks.length)
        allBlocks.push(block)
        return
    }

    const existingBlock = allBlocks[existingIndex]
    if (!existingBlock) return

    const currentTimestamp = existingBlock.timestamp || 0
    const newTimestamp = block.timestamp || 0
    if (newTimestamp > currentTimestamp || (newTimestamp === currentTimestamp && (block.details?.length || 0) > (existingBlock.details?.length || 0))) {
        allBlocks[existingIndex] = block
    }
}

const collectRescoredTags = (detailsToParse: string, allTags: Set<string>) => {
    const rescoredMatch = RESCORED_TAG_REGEX.exec(detailsToParse)
    if (rescoredMatch) {
        allTags.add(rescoredMatch[0])
    }

    const vectorMatch = RESCORED_VECTOR_TAG_REGEX.exec(detailsToParse)
    if (vectorMatch) {
        allTags.add(vectorMatch[0])
    }
}

const getInstanceAssessmentDetails = (instance: Instance, originalAnalysis: Record<string, any>): string => {
    if (instance.finding_uuid && originalAnalysis[instance.finding_uuid]) {
        const original = originalAnalysis[instance.finding_uuid]
        return original.analysisDetails || original.analysis_details || ''
    }

    return instance.analysis_details || instance.analysisDetails || ''
}

const collectCurrentFullDetails = (
    allInstances: Instance[],
    originalAnalysis: Record<string, any>,
): string => {
    const allBlocks: AssessmentBlock[] = []
    const teamToIndex = new Map<string, number>()
    const allTags = new Set<string>()
    let isPending = false

    for (const instance of allInstances) {
        const detailsToParse = getInstanceAssessmentDetails(instance, originalAnalysis)
        if (!detailsToParse) continue

        if (detailsToParse.includes('[Status: Pending Review]')) {
            isPending = true
        }

        const blocks = parseAssessmentBlocks(detailsToParse)
        for (const block of blocks) {
            upsertLatestBlock(allBlocks, teamToIndex, block)
        }
        collectRescoredTags(detailsToParse, allTags)
    }

    return allBlocks.length > 0
        ? constructAssessmentDetails(allBlocks, Array.from(allTags), isPending).text
        : ''
}

const buildRescoredTags = ({
    isReviewer,
    pendingVector,
    pendingScore,
    initialVector,
    initialScore,
    originalVector,
    originalScore,
}: {
    isReviewer: boolean
    pendingVector: string
    pendingScore: number | null
    initialVector: string
    initialScore: number | null
    originalVector?: string
    originalScore?: number | null
}): string[] | undefined => {
    if (!isReviewer) {
        return undefined
    }

    const touched = pendingVector !== initialVector || pendingScore !== initialScore
    if (!touched) {
        return undefined
    }

    const matchesOriginal = pendingVector === originalVector && pendingScore === originalScore
    if (matchesOriginal) {
        return []
    }

    const tags: string[] = []
    if (pendingScore !== null && pendingScore !== undefined) {
        tags.push(`[Rescored: ${pendingScore}]`)
    }
    if (pendingVector) {
        tags.push(`[Rescored Vector: ${pendingVector}]`)
    }
    return tags
}

export const prepareAssessmentSubmission = (
    input: PrepareAssessmentSubmissionInput,
): PreparedAssessmentSubmission => {
    const targetTeam = input.selectedTeam || 'General'
    const nextDrafts = new Map(input.teamDrafts)
    nextDrafts.set(targetTeam, {
        state: input.state,
        details: input.details,
        justification: input.justification,
        assigned: [...input.currentAssigned],
        evidenceReviewed: input.evidenceReviewed,
        versionCoverageChecked: input.versionCoverageChecked,
        ticket: input.ticket.trim(),
    })

    const currentFullDetails = collectCurrentFullDetails(input.allInstances, input.originalAnalysis)
    const rescoredTags = buildRescoredTags({
        isReviewer: input.isReviewer,
        pendingVector: input.pendingVector,
        pendingScore: input.pendingScore,
        initialVector: input.initialVector,
        initialScore: input.initialScore,
        originalVector: input.originalVector,
        originalScore: input.originalScore,
    })

    let reviewText: string
    let aggregatedState: string

    if (input.showRawEdit && input.rawDetailsTouched && input.rawDetails !== input.mergedAssessmentFullText) {
        const sanitized = sanitizeAssessmentDetails(input.rawDetails)
        reviewText = sanitized.text
        aggregatedState = sanitized.aggregatedState
    } else {
        let mergedText = currentFullDetails
        let mergedState = ''
        for (const [teamName, draft] of nextDrafts.entries()) {
            const result = mergeTeamAssessment(
                mergedText,
                teamName,
                draft.state,
                cleanStructuredAssessmentDetails(draft.details),
                input.currentUser,
                draft.justification,
                teamName === targetTeam ? rescoredTags : undefined,
                !input.isApprove,
                draft.assigned,
                {
                    evidenceReviewed: draft.evidenceReviewed,
                    versionCoverageChecked: draft.versionCoverageChecked,
                    ticket: draft.ticket,
                },
            )
            mergedText = result.text
            mergedState = result.aggregatedState
        }
        reviewText = mergedText
        aggregatedState = mergedState || 'NOT_SET'
    }

    const sanitized = sanitizeAssessmentDetails(reviewText)
    const finalText = sanitized.text
    const finalState = sanitized.aggregatedState || aggregatedState

    return {
        targetTeam,
        nextDrafts,
        reviewText,
        finalText,
        finalState,
        payload: {
            instances: input.allInstances,
            state: finalState,
            details: finalText,
            justification: input.justification && input.justification !== 'NOT_SET' ? input.justification : undefined,
            suppressed: input.suppressed,
            team: input.selectedTeam || undefined,
            comparison_mode: 'REPLACE',
            original_analysis: input.force ? {} : { ...input.originalAnalysis },
            force: input.force,
        },
    }
}

export const buildSavedAssessmentResultState = ({
    success,
    isReviewer,
    pendingVector,
    pendingScore,
    baseVector,
    existingRescoredVector,
    existingRescoredCvss,
    suppressed,
    currentAssigned,
}: {
    success: AssessmentUpdateSuccessResult
    isReviewer: boolean
    pendingVector: string
    pendingScore: number | null
    baseVector?: string | null
    existingRescoredVector?: string | null
    existingRescoredCvss?: number | null
    suppressed: boolean
    currentAssigned: string[]
}): SavedAssessmentResultState => {
    const rescoredScoreMatch = RESCORED_TAG_VALUE_REGEX.exec(success.new_details)
    const rescoredVectorMatch = RESCORED_VECTOR_VALUE_REGEX.exec(success.new_details)

    let rescoredCvss: number | null = rescoredScoreMatch ? Number(rescoredScoreMatch[1]) : null
    let rescoredVector: string | null = rescoredVectorMatch?.[1] || null

    if (rescoredCvss == null && rescoredVector == null) {
        const hasVectorChange = isReviewer
            ? pendingVector !== (baseVector || '')
            : Boolean(existingRescoredVector)

        if (hasVectorChange) {
            rescoredCvss = isReviewer ? pendingScore : existingRescoredCvss ?? null
            rescoredVector = isReviewer ? pendingVector : existingRescoredVector ?? null
        }
    }

    const nextPendingVector = rescoredVector || baseVector || ''
    const nextInitialScore = rescoredCvss ?? null

    return {
        emittedAssessment: {
            rescored_cvss: rescoredCvss,
            rescored_vector: rescoredVector,
            analysis_state: success.new_state,
            analysis_details: success.new_details,
            is_suppressed: suppressed,
            assignees: [...currentAssigned],
        },
        nextPendingVector,
        nextInitialVector: nextPendingVector,
        nextInitialScore,
        nextLastRescoredScore: nextInitialScore,
    }
}

export const buildSavedOriginalAnalysis = ({
    allInstances,
    finalState,
    finalText,
    suppressed,
}: {
    allInstances: Instance[]
    finalState: string
    finalText: string
    suppressed: boolean
}): Record<string, { analysisState: string; analysisDetails: string; isSuppressed: boolean }> => {
    const nextOriginalAnalysis: Record<string, { analysisState: string; analysisDetails: string; isSuppressed: boolean }> = {}

    for (const instance of allInstances) {
        if (!instance.finding_uuid) continue

        nextOriginalAnalysis[instance.finding_uuid] = {
            analysisState: finalState,
            analysisDetails: finalText,
            isSuppressed: suppressed,
        }
    }

    return nextOriginalAnalysis
}
