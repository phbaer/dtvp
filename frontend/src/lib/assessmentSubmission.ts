import { assessmentBlockKey, assessmentTeamKey, assessmentTextToFields, constructAssessmentDetails, markAssessmentBlocksHistorical, mergeTeamAssessment, parseAssessmentBlocks, parseAssessmentResponse, sanitizeAssessmentDetails, setAssessmentResponse, withoutHistoricalBlocks, type AssessmentBlock } from './assessment-helpers'
import { stripSsvcDetails } from './ssvc'
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
    /**
     * The response chosen in the Global form ("NOT_SET" for none), given
     * when the Global assessment is saved. Only a reviewer's save sends it;
     * left out, the server keeps what each finding has.
     */
    response?: string
    teamDrafts: Map<string, AssessmentDraft>
    takeoverSources?: Map<string, string>
    isReviewer: boolean
    pendingVector: string
    pendingScore: number | null
    initialVector: string
    initialScore: number | null
    originalVector?: string
    originalScore?: number | null
    currentUser: string
    isApprove: boolean
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
    uuid?: string
    new_state: string
    new_details: string
    queued?: boolean
    sync_status?: string
    update_id?: string
    revision?: number
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

// One active block per team, the newest; a historical block is a record of
// its own and never stands in for the team's active one (as in
// mergedAssessmentData.ts).
const upsertLatestBlock = (
    allBlocks: AssessmentBlock[],
    teamToIndex: Map<string, number>,
    block: AssessmentBlock,
) => {
    const teamKey = assessmentBlockKey(block)
    const existingIndex = teamToIndex.get(teamKey)
    if (existingIndex === undefined) {
        teamToIndex.set(teamKey, allBlocks.length)
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

// The finding's rescoring: a historical block's rescoring is a record and
// does not rescore the finding (as sanitizeAssessmentDetails reads it).
const collectRescoredTags = (fullText: string, allTags: Set<string>) => {
    const detailsToParse = stripSsvcDetails(withoutHistoricalBlocks(fullText))
    const rescoredMatch = RESCORED_TAG_REGEX.exec(detailsToParse)
    if (rescoredMatch) {
        allTags.add(rescoredMatch[0])
    }

    const vectorMatch = RESCORED_VECTOR_TAG_REGEX.exec(detailsToParse)
    if (vectorMatch) {
        allTags.add(vectorMatch[0])
    }
}

/**
 * What each finding's assessment was when this edit started. The server
 * compares it with Dependency-Track before exporting, so an edit made on an
 * outdated view becomes a conflict instead of overwriting a newer value.
 *
 * A reload or save records the exact server state; for findings without
 * one, the value shown in the open view is what the edit was based on.
 * Findings whose text is not loaded (list rows) are left out.
 */
export const seenAnalysis = (
    instances: Instance[],
    originalAnalysis: Record<string, any>,
): Record<string, any> => {
    const seen: Record<string, any> = { ...originalAnalysis }
    for (const instance of instances) {
        const findingId = instance.finding_uuid
        if (!findingId || seen[findingId]) continue
        const details = instance.analysis_details ?? (instance as any).analysisDetails
        if (typeof details !== 'string') continue
        seen[findingId] = {
            analysisState: instance.analysis_state || (instance as any).analysisState || 'NOT_SET',
            analysisDetails: details,
            isSuppressed: Boolean(instance.is_suppressed),
        }
    }
    return seen
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
    let response: string | null = null

    for (const instance of allInstances) {
        const detailsToParse = getInstanceAssessmentDetails(instance, originalAnalysis)
        if (!detailsToParse) continue
        response = response ?? parseAssessmentResponse(detailsToParse)

        if (detailsToParse.includes('[Status: Pending Review]')) {
            isPending = true
        }

        const blocks = parseAssessmentBlocks(detailsToParse)
        for (const block of blocks) {
            upsertLatestBlock(allBlocks, teamToIndex, block)
        }
        collectRescoredTags(detailsToParse, allTags)
    }

    const sharedTags = [...allTags, ...(response ? [`[Response: ${response}]`] : [])]
    return allBlocks.length > 0
        ? constructAssessmentDetails(allBlocks, sharedTags, isPending).text
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
        tags.push(`[Rescored: ${pendingScore.toFixed(1)}]`)
    }
    if (pendingVector) {
        tags.push(`[Rescored Vector: ${pendingVector}]`)
    }
    return tags
}

const sameText = (left: string | undefined, right: string | undefined) =>
    (left || '').replace(/\s+/g, ' ').trim() === (right || '').replace(/\s+/g, ' ').trim()

/**
 * Whether the draft of a team other than the one being saved says something
 * new. Such a draft is what the form held when its tab was left. An unchanged
 * one must not be written again under the saving user's name and time, and an
 * empty one must not remove the assessment of a team nobody was editing:
 * removing an assessment is done on that team's own tab.
 */
const changesOtherTeam = (
    currentText: string,
    teamName: string,
    draft: AssessmentDraft,
    takeoverSources?: Map<string, string>,
): boolean => {
    const state = draft.state || 'NOT_SET'
    const justification = draft.justification || 'NOT_SET'
    const details = cleanStructuredAssessmentDetails(draft.details)
    if (state === 'NOT_SET' && !details.trim() && justification === 'NOT_SET') return false
    if (takeoverSources?.has(teamName)) return true
    const existing = parseAssessmentBlocks(currentText)
        .find(block => !block.historical && assessmentTeamKey(block.team) === assessmentTeamKey(teamName))
    if (!existing) return true
    return !(
        (existing.state || 'NOT_SET') === state
        && (existing.justification || 'NOT_SET') === justification
        && sameText(existing.details, details)
        && sameText(existing.ticket, draft.ticket)
        && Boolean(existing.evidenceReviewed) === Boolean(draft.evidenceReviewed)
        && Boolean(existing.versionCoverageChecked) === Boolean(draft.versionCoverageChecked)
        && [...(existing.assigned || [])].sort().join(',') === [...(draft.assigned || [])].sort().join(',')
    )
}

export const prepareAssessmentSubmission = (
    input: PrepareAssessmentSubmissionInput,
): PreparedAssessmentSubmission => {
    const requestedTargetTeam = input.selectedTeam || 'General'
    const targetTeam = assessmentTeamKey(requestedTargetTeam) === 'general'
        ? 'General'
        : requestedTargetTeam.trim()
    const nextDrafts = new Map<string, AssessmentDraft>()
    for (const [teamName, draft] of input.teamDrafts.entries()) {
        const duplicateKey = [...nextDrafts.keys()]
            .find(existingTeam => assessmentTeamKey(existingTeam) === assessmentTeamKey(teamName))
        if (duplicateKey) nextDrafts.delete(duplicateKey)
        nextDrafts.set(assessmentTeamKey(teamName) === 'general' ? 'General' : teamName.trim(), draft)
    }
    const duplicateTargetKey = [...nextDrafts.keys()]
        .find(existingTeam => assessmentTeamKey(existingTeam) === assessmentTeamKey(targetTeam))
    if (duplicateTargetKey) nextDrafts.delete(duplicateTargetKey)
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

    // Whether this save decides the response: a reviewer's Global save.
    const sendsResponse = input.isReviewer && input.response !== undefined

    let mergedText = currentFullDetails
    let mergedState = ''
    for (const [teamName, draft] of nextDrafts.entries()) {
        if (teamName !== targetTeam && !changesOtherTeam(mergedText, teamName, draft, input.takeoverSources)) {
            continue
        }
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
                copiedFrom: input.takeoverSources?.get(teamName),
            },
        )
        mergedText = result.text
        mergedState = result.aggregatedState
    }
    if (sendsResponse) {
        mergedText = setAssessmentResponse(mergedText, input.response)
    }
    let reviewText = mergedText
    const aggregatedState = mergedState || 'NOT_SET'

    reviewText = markAssessmentBlocksHistorical(reviewText, input.takeoverSources?.values() || [])
    const sanitized = sanitizeAssessmentDetails(reviewText)
    const finalText = sanitized.text
    const finalState = sanitized.aggregatedState || aggregatedState
    const fields = assessmentTextToFields(finalText)
    // The response is the Global assessment's, which reviewers save. Every
    // other save leaves it out and the server keeps what each finding has.
    if (!sendsResponse) delete fields.response

    return {
        targetTeam,
        nextDrafts,
        reviewText,
        finalText,
        finalState,
        payload: {
            instances: input.allInstances,
            state: finalState,
            // The assessment goes out as fields. The text above is only what
            // the review dialog shows; the server renders the stored text.
            fields,
            justification: input.justification && input.justification !== 'NOT_SET' ? input.justification : undefined,
            suppressed: input.suppressed,
            team: input.selectedTeam || undefined,
            original_analysis: input.force ? {} : seenAnalysis(input.allInstances, input.originalAnalysis),
            force: input.force,
            // Said in so many words: the server removes the pending status
            // for nothing less, whatever the fields say.
            ...(input.isApprove && input.isReviewer ? { approve: true } : {}),
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
    // The finding's own rescoring; a historical record's tags do not count.
    const ownText = stripSsvcDetails(withoutHistoricalBlocks(success.new_details || ''))
    const rescoredScoreMatch = RESCORED_TAG_VALUE_REGEX.exec(ownText)
    const rescoredVectorMatch = RESCORED_VECTOR_VALUE_REGEX.exec(ownText)

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
    results = [],
}: {
    allInstances: Instance[]
    finalState: string
    finalText: string
    suppressed: boolean
    results?: AssessmentUpdateSuccessResult[]
}): Record<string, {
    analysisState: string
    analysisDetails: string
    isSuppressed: boolean
    dtvpRevision?: number
    dtvpSyncStatus?: string
    dtvpUpdateId?: string
}> => {
    const resultsByFinding = new Map(
        results
            .filter(result => result.uuid)
            .map(result => [result.uuid as string, result]),
    )
    const nextOriginalAnalysis: Record<string, {
        analysisState: string
        analysisDetails: string
        isSuppressed: boolean
        dtvpRevision?: number
        dtvpSyncStatus?: string
        dtvpUpdateId?: string
    }> = {}

    for (const instance of allInstances) {
        if (!instance.finding_uuid) continue

        const result = resultsByFinding.get(instance.finding_uuid)
        nextOriginalAnalysis[instance.finding_uuid] = {
            analysisState: result?.new_state || finalState,
            analysisDetails: result?.new_details || finalText,
            isSuppressed: suppressed,
            ...(result?.revision !== undefined ? { dtvpRevision: result.revision } : {}),
            ...((result?.sync_status || result?.queued) ? {
                dtvpSyncStatus: result.sync_status || 'pending',
            } : {}),
            ...(result?.update_id ? { dtvpUpdateId: result.update_id } : {}),
        }
    }

    return nextOriginalAnalysis
}
