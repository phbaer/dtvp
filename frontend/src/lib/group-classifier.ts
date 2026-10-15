/**
 * Group lifecycle classification and counters for recorded team assessments.
 */

import type { GroupedVuln } from '../types'
import {
    getGroupLifecycle,
    isPendingReview,
    getGroupTechnicalState,
    normalizeTags,
    getAssessedTeams,
    matchesFilters,
} from './assessment-helpers'

export interface GroupClassification {
    /** The lifecycle state returned by getGroupLifecycle (OPEN, ASSESSED, INCOMPLETE, etc.) */
    lifecycle: string
    /** Whether the group is pending review */
    isPending: boolean
    /** Whether all required assessments are documented and approval is pending */
    isApprovalReady: boolean
    /** Whether this group is open/not done for the open/assessed counters. */
    isOpen: boolean
    /** The technical analysis state (EXPLOITABLE, IN_TRIAGE, NOT_SET, etc.) */
    technicalState: string
}

/**
 * Single authoritative classification of a vulnerability group.
 * Lifecycle filter counts use this function.
 */
export function classifyGroup(
    group: GroupedVuln,
    teamMapping: Record<string, any>
): GroupClassification {
    const tags = group.tags || []
    const lifecycle = getGroupLifecycle(group, tags, teamMapping)
    const isPending = isPendingReview(group)
    const isApprovalReady = isPending && lifecycle === 'NEEDS_APPROVAL'
    // Pending review is not done even when no individual team currently has
    // an open block. Keep the existing separate semantics for incomplete and
    // inconsistent lifecycle counters.
    const isOpen = lifecycle === 'OPEN' || isPending

    return {
        lifecycle,
        isPending,
        isApprovalReady,
        isOpen,
        technicalState: getGroupTechnicalState(group),
    }
}

export interface FilterCounts {
    OPEN: number
    ASSESSED: number
    ASSESSED_LEGACY: number
    INCOMPLETE: number
    INCONSISTENT: number
    NOT_SET: number
    EXPLOITABLE: number
    IN_TRIAGE: number
    RESOLVED: number
    FALSE_POSITIVE: number
    NOT_AFFECTED: number
    NEEDS_APPROVAL: number
    READY_FOR_APPROVAL: number
    [key: string]: number
}

/**
 * Compute lifecycle and analysis filter counts from the full (unfiltered) group list.
 */
export function computeFilterCounts(
    groups: GroupedVuln[],
    teamMapping: Record<string, any>,
    activeLifecycleFilters: string[]
): FilterCounts {
    const counts: FilterCounts = {
        OPEN: 0,
        ASSESSED: 0,
        ASSESSED_LEGACY: 0,
        INCOMPLETE: 0,
        INCONSISTENT: 0,
        NOT_SET: 0,
        EXPLOITABLE: 0,
        IN_TRIAGE: 0,
        RESOLVED: 0,
        FALSE_POSITIVE: 0,
        NOT_AFFECTED: 0,
        NEEDS_APPROVAL: 0,
        READY_FOR_APPROVAL: 0,
    }

    for (const g of groups) {
        const c = classifyGroup(g, teamMapping)

        // Lifecycle counts
        if (c.lifecycle === 'OPEN') counts.OPEN++
        if (['ASSESSED', 'ASSESSED_LEGACY'].includes(c.lifecycle)) counts.ASSESSED++
        if (c.lifecycle === 'ASSESSED_LEGACY') counts.ASSESSED_LEGACY++
        if (c.lifecycle === 'INCOMPLETE') counts.INCOMPLETE++
        if (c.lifecycle === 'INCONSISTENT') counts.INCONSISTENT++
        if (c.isPending) counts.NEEDS_APPROVAL++
        if (c.isApprovalReady) counts.READY_FOR_APPROVAL++

        // Analysis counts: only count when the group matches the active lifecycle filters
        const lifecycleActiveMatch =
            activeLifecycleFilters.length === 0 ||
            activeLifecycleFilters.includes(c.lifecycle) ||
            (activeLifecycleFilters.includes('ASSESSED') && c.lifecycle === 'ASSESSED_LEGACY') ||
            (activeLifecycleFilters.includes('NEEDS_APPROVAL') && c.isPending) ||
            (activeLifecycleFilters.includes('READY_FOR_APPROVAL') && c.isApprovalReady)

        if (lifecycleActiveMatch) {
            counts[c.technicalState]++
        }
    }

    return counts
}

export interface TeamCounts {
    open: number
    assessed: number
}

export function addTeamCounts(
    counts: Record<string, TeamCounts>,
    teams: readonly string[],
    assessedTeams: Iterable<string>,
    closed = false,
): void {
    const assessed = new Set(Array.from(assessedTeams, team => team.toLowerCase()))
    for (const team of new Set(teams)) {
        const entry = counts[team] ||= { open: 0, assessed: 0 }
        if (closed || assessed.has(team.toLowerCase())) entry.assessed++
        else entry.open++
    }
}

/**
 * Compute per-team counts from the supplied groups, using recorded team coverage.
 */
export function computeTeamCounts(
    groups: GroupedVuln[],
    teamMapping: Record<string, any>
): Record<string, TeamCounts> {
    const counts: Record<string, TeamCounts> = {}

    for (const g of groups) {
        const teams = normalizeTags(g.tags || [], teamMapping)
        if (!teams.length) continue

        const assessed = g.list_metadata?.assessed_teams ?? Array.from(getAssessedTeams(g))
        const lifecycle = g.list_metadata?.lifecycle ?? classifyGroup(g, teamMapping).lifecycle
        const closed = ['ASSESSED', 'ASSESSED_LEGACY'].includes(lifecycle)
            && !(g.list_metadata?.is_pending ?? isPendingReview(g))
        addTeamCounts(counts, teams, normalizeTags(assessed, teamMapping), closed)
    }

    return counts
}

export { matchesFilters, normalizeTags, getGroupTechnicalState }
