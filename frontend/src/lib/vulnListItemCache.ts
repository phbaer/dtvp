import type { GroupedVuln, TMRescoreProposal } from '../types'
import { buildVulnListItem, type VulnListItem } from './vulnListIndex'

interface CacheEntry {
    teamMapping: Record<string, any>
    proposals: Record<string, TMRescoreProposal>
    item: VulnListItem
}

export interface VulnListItemCache {
    build: (
        groups: readonly GroupedVuln[],
        teamMapping: Record<string, any>,
        proposals: Record<string, TMRescoreProposal>,
    ) => VulnListItem[]
    clear: () => void
}

export const createVulnListItemCache = (): VulnListItemCache => {
    let byGroup = new WeakMap<GroupedVuln, CacheEntry>()

    return {
        build(groups, teamMapping, proposals) {
            return groups.map((group) => {
                const cached = byGroup.get(group)
                if (
                    cached &&
                    cached.teamMapping === teamMapping &&
                    cached.proposals === proposals
                ) {
                    return cached.item
                }

                const item = buildVulnListItem(group, teamMapping, proposals)
                byGroup.set(group, { teamMapping, proposals, item })
                return item
            })
        },
        clear() {
            byGroup = new WeakMap<GroupedVuln, CacheEntry>()
        },
    }
}
