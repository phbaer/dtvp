import type { GroupedVuln, TMRescoreProposal } from '../types'
import {
    buildVulnListItem,
    type AutomaticAssessmentLookup,
    type VulnListItem,
} from './vulnListIndex'

const EMPTY_AUTOMATIC_ASSESSMENT_IDS: ReadonlySet<string> = new Set()

interface CacheEntry {
    teamMapping: Record<string, any>
    proposals: Record<string, TMRescoreProposal>
    automaticAssessments: AutomaticAssessmentLookup
    item: VulnListItem
}

export interface VulnListItemCache {
    build: (
        groups: readonly GroupedVuln[],
        teamMapping: Record<string, any>,
        proposals: Record<string, TMRescoreProposal>,
        automaticAssessments?: AutomaticAssessmentLookup,
    ) => VulnListItem[]
    clear: () => void
}

export const createVulnListItemCache = (): VulnListItemCache => {
    let byGroup = new WeakMap<GroupedVuln, CacheEntry>()

    return {
        build(groups, teamMapping, proposals, automaticAssessments = EMPTY_AUTOMATIC_ASSESSMENT_IDS) {
            return groups.map((group) => {
                const cached = byGroup.get(group)
                if (
                    cached &&
                    cached.teamMapping === teamMapping &&
                    cached.proposals === proposals &&
                    cached.automaticAssessments === automaticAssessments
                ) {
                    return cached.item
                }

                const item = buildVulnListItem(group, teamMapping, proposals, automaticAssessments)
                byGroup.set(group, { teamMapping, proposals, automaticAssessments, item })
                return item
            })
        },
        clear() {
            byGroup = new WeakMap<GroupedVuln, CacheEntry>()
        },
    }
}
