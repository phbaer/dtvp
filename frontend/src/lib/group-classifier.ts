/**
 * Centralized group classification for lifecycle state, filter counts, and team statistics.
 *
 * This module is the single source of truth for determining whether a vulnerability
 * group counts as "open" or "assessed" for both lifecycle filter chips and per-team
 * statistics. All classification decisions flow through classifyGroup().
 */

import type { GroupedVuln } from '../types'
import {
    getGroupLifecycle,
    isPendingReview,
    hasOpenTeamAssessment,
    getGroupTechnicalState,
    normalizeTags,
} from './assessment-helpers'

export interface GroupClassification {
    /** The lifecycle state returned by getGroupLifecycle (OPEN, ASSESSED, INCOMPLETE, etc.) */
    lifecycle: string
    /** Whether the group is pending review */
    isPending: boolean
    /** Whether this group qualifies as OPEN for filter/stats purposes.
     *  True when lifecycle is OPEN, or when it's a pending group with open team assessments. */
    isOpen: boolean
    /** The technical analysis state (EXPLOITABLE, IN_TRIAGE, NOT_SET, etc.) */
    technicalState: string
}

type TeamMapping = Record<string, any>

interface CachedClassificationEntry {
    teamMapping: TeamMapping
    classification: GroupClassification
}

const classificationCache = new WeakMap<GroupedVuln, CachedClassificationEntry>()

/**
 * Single authoritative classification of a vulnerability group.
 * Both filter counts and team statistics MUST use this function.
 */
export function classifyGroup(
    group: GroupedVuln,
    teamMapping: TeamMapping
): GroupClassification {
    const cached = classificationCache.get(group)
    if (cached && cached.teamMapping === teamMapping) {
        return cached.classification
    }

    const tags = group.tags || []
    const lifecycle = getGroupLifecycle(group, tags, teamMapping)
    const isPending = isPendingReview(group)
    const openPendingWithOpenTeam = isPending && hasOpenTeamAssessment(group, tags, teamMapping)
    const isOpen = lifecycle === 'OPEN' || openPendingWithOpenTeam

    const classification = {
        lifecycle,
        isPending,
        isOpen,
        technicalState: getGroupTechnicalState(group),
    }

    classificationCache.set(group, { teamMapping, classification })
    return classification
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
    }

    for (const g of groups) {
        const c = classifyGroup(g, teamMapping)

        // Lifecycle counts
        if (c.isOpen) counts.OPEN++
        if (c.lifecycle === 'ASSESSED') counts.ASSESSED++
        if (c.lifecycle === 'ASSESSED_LEGACY') counts.ASSESSED_LEGACY++
        if (c.lifecycle === 'INCOMPLETE') counts.INCOMPLETE++
        if (c.lifecycle === 'INCONSISTENT') counts.INCONSISTENT++
        if (c.isPending) counts.NEEDS_APPROVAL++

        // Analysis counts: only count when the group matches the active lifecycle filters
        const lifecycleActiveMatch =
            activeLifecycleFilters.length === 0 ||
            activeLifecycleFilters.includes(c.lifecycle) ||
            (activeLifecycleFilters.includes('OPEN') && c.isOpen) ||
            (activeLifecycleFilters.includes('NEEDS_APPROVAL') && c.isPending)

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

/**
 * Compute per-team open/assessed counts from the full (unfiltered) group list.
 * Uses the same isOpen classification as the lifecycle OPEN filter.
 */
export function computeTeamCounts(
    groups: GroupedVuln[],
    teamMapping: TeamMapping
): Record<string, TeamCounts> {
    const counts: Record<string, TeamCounts> = {}

    for (const g of groups) {
        const teams = normalizeTags(g.tags || [], teamMapping)
        if (!teams.length) continue

        const c = classifyGroup(g, teamMapping)

        for (const team of teams) {
            if (!counts[team]) counts[team] = { open: 0, assessed: 0 }
            if (c.isOpen) {
                counts[team].open++
            } else {
                counts[team].assessed++
            }
        }
    }

    return counts
}

export function matchesFilters(
    group: GroupedVuln,
    lifecycleFilters: string[],
    analysisFilters: string[],
    teamMapping: TeamMapping
): boolean {
    if (lifecycleFilters.length === 0 || analysisFilters.length === 0) return false

    const classification = classifyGroup(group, teamMapping)
    const lifecycleMatch =
        (lifecycleFilters.includes('OPEN') && classification.isOpen) ||
        (lifecycleFilters.includes('ASSESSED') && classification.lifecycle === 'ASSESSED') ||
        (lifecycleFilters.includes('ASSESSED_LEGACY') && classification.lifecycle === 'ASSESSED_LEGACY') ||
        (lifecycleFilters.includes('INCOMPLETE') && classification.lifecycle === 'INCOMPLETE') ||
        (lifecycleFilters.includes('INCONSISTENT') && classification.lifecycle === 'INCONSISTENT') ||
        (lifecycleFilters.includes('NEEDS_APPROVAL') && classification.isPending)

    if (!lifecycleMatch) return false

    if (classification.technicalState === 'NOT_SET') {
        return analysisFilters.includes('NOT_SET')
    }

    return analysisFilters.includes(classification.technicalState)
}

export { normalizeTags, getGroupTechnicalState }
