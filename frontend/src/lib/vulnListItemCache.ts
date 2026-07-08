import type { GroupedVuln, TMRescoreProposal } from '../types'
import { buildVulnListItem, type VulnListItem } from './vulnListIndex'

const EMPTY_AUTOMATIC_ASSESSMENT_IDS: ReadonlySet<string> = new Set()

interface CacheEntry {
    teamMapping: Record<string, any>
    proposals: Record<string, TMRescoreProposal>
    automaticAssessmentIds: ReadonlySet<string>
    item: VulnListItem
}

export interface VulnListItemCache {
    build: (
        groups: readonly GroupedVuln[],
        teamMapping: Record<string, any>,
        proposals: Record<string, TMRescoreProposal>,
        automaticAssessmentIds?: ReadonlySet<string>,
    ) => VulnListItem[]
    clear: () => void
}

export const createVulnListItemCache = (): VulnListItemCache => {
    let byGroup = new WeakMap<GroupedVuln, CacheEntry>()

    return {
        build(groups, teamMapping, proposals, automaticAssessmentIds = EMPTY_AUTOMATIC_ASSESSMENT_IDS) {
            return groups.map((group) => {
                const cached = byGroup.get(group)
                if (
                    cached &&
                    cached.teamMapping === teamMapping &&
                    cached.proposals === proposals &&
                    cached.automaticAssessmentIds === automaticAssessmentIds
                ) {
                    return cached.item
                }

                const item = buildVulnListItem(group, teamMapping, proposals, automaticAssessmentIds)
                byGroup.set(group, { teamMapping, proposals, automaticAssessmentIds, item })
                return item
            })
        },
        clear() {
            byGroup = new WeakMap<GroupedVuln, CacheEntry>()
        },
    }
}
