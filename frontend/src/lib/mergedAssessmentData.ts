import { assessmentTeamKey, constructAssessmentDetails, parseAssessmentBlocks, type AssessmentBlock } from './assessment-helpers'
import type { Instance } from '../types'

const RESCORED_TAG_REGEX = /\[Rescored:\s*[\d.]+\]/

export interface MergedAssessmentData {
    blocks: AssessmentBlock[]
    fullText: string
    isPending: boolean
}

const upsertLatestBlock = (
    allBlocks: AssessmentBlock[],
    teamToIndex: Map<string, number>,
    block: AssessmentBlock,
) => {
    const teamKey = assessmentTeamKey(block.team)
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

export const buildMergedAssessmentData = (allInstances: Instance[], _refreshTick?: number): MergedAssessmentData => {
    const allBlocks: AssessmentBlock[] = []
    const teamToIndex = new Map<string, number>()
    const allTags = new Set<string>()
    let isPendingValue = false

    for (const instance of allInstances) {
        const instDetails = instance.analysis_details || instance.analysisDetails || ''
        if (!instDetails) continue

        if (instDetails.includes('[Status: Pending Review]')) {
            isPendingValue = true
        }

        const blocks = parseAssessmentBlocks(instDetails)
        for (const block of blocks) {
            upsertLatestBlock(allBlocks, teamToIndex, block)
        }

        const rescoredMatch = RESCORED_TAG_REGEX.exec(instDetails)
        if (rescoredMatch) {
            allTags.add(rescoredMatch[0])
        }
    }

    return {
        blocks: allBlocks,
        fullText: allBlocks.length > 0 ? constructAssessmentDetails(allBlocks, Array.from(allTags), isPendingValue).text : '',
        isPending: isPendingValue,
    }
}
