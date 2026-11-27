import { assessmentTextToFields, parseAssessmentBlocks } from './assessment-helpers'
import { stripTeamChangesRequests } from './assessmentChanges'
import { buildFindingMatrix, compareVariants, type MatrixInstance, type MatrixVariant } from './findingMatrix'
import type { AssessmentCleanupValue } from './api'

/**
 * The assessment cleanup: the versions of a vulnerability's assessment,
 * which findings carry which, and what a cleanup would change. The versions
 * are those of the finding matrix, compared as the server compares them.
 */

/** A finding's identity as the server keys revisions: `project|component|vulnerability`. */
export const cleanupFindingKey = (instance: { project_uuid?: unknown; component_uuid?: unknown; vulnerability_uuid?: unknown }) =>
    [instance.project_uuid, instance.component_uuid, instance.vulnerability_uuid].map(value => String(value ?? '')).join('|')

/** The teams with a current (not historical) block in a text, as written. */
export const activeTeams = (details: string | null | undefined): string[] => {
    const teams = new Map<string, string>()
    for (const block of parseAssessmentBlocks(String(details || ''))) {
        if (block.historical) continue
        const key = block.team.toLocaleLowerCase()
        if (!teams.has(key)) teams.set(key, block.team)
    }
    return [...teams.values()]
}

export const isGeneral = (team: string | null | undefined) => String(team || '').toLocaleLowerCase() === 'general'

/** Shared Global fields can exist without a saved General block. */
export const hasGlobalAssessmentData = (instances: readonly MatrixInstance[]): boolean => instances.some(instance => {
    const fields = assessmentTextToFields(stripTeamChangesRequests(String(instance.analysis_details || '')))
    return Boolean(instance.is_suppressed || fields.pending_review || fields.response
        || fields.rescored_score != null || fields.rescored_vector || fields.free_text?.trim()
        || fields.teams.some(team => isGeneral(team.team) && !team.historical))
})

export interface CleanupDifference {
    key: string
    label: string
    value: string
}

export interface CleanupVersion<T extends MatrixInstance = MatrixInstance> {
    variant: MatrixVariant<T>
    teams: string[]
    /** This version's value of every field in which the versions differ. */
    differences: CleanupDifference[]
}

// Who assessed when does not make two versions different (the server does
// not compare it); listing it would only hide what does.
const ATTRIBUTION = /:(assessed_by|assessed_at|reviewed_by)$/

export const cleanupVersions = <T extends MatrixInstance>(instances: readonly T[]): CleanupVersion<T>[] => {
    const { variants } = buildFindingMatrix(instances)
    const differing = compareVariants(variants).filter(row => row.differs && !ATTRIBUTION.test(row.key))
    return variants.map((variant, index) => {
        const teams = activeTeams(variant.details)
        const has = new Set(teams.map(team => team.toLocaleLowerCase()))
        const differences: CleanupDifference[] = []
        const absent = new Set<string>()
        for (const row of differing) {
            const value = row.values[index] ?? ''
            const team = row.key.startsWith('team:') ? row.key.split(':')[1]! : ''
            if (team) {
                if (absent.has(team)) continue
                if (!has.has(team.toLocaleLowerCase())) {
                    // A team this version has no assessment of: one line.
                    absent.add(team)
                    differences.push({ key: `team:${team}`, label: row.label.split(' · ')[0]!, value: '' })
                    continue
                }
            }
            differences.push({ key: row.key, label: row.label, value })
        }
        return { variant, teams, differences }
    })
}

/** Every team with a current block on any finding, General first. */
export const assessedTeamsOf = (instances: readonly MatrixInstance[]): string[] => {
    const teams = new Map<string, string>()
    for (const instance of instances) {
        for (const team of activeTeams(instance.analysis_details)) {
            if (!teams.has(team.toLocaleLowerCase())) teams.set(team.toLocaleLowerCase(), team)
        }
    }
    return [...teams.values()].sort((left, right) => (
        Number(isGeneral(right)) - Number(isGeneral(left)) || left.localeCompare(right)
    ))
}

export type TeamStatus = 'unknown' | 'alias'

/**
 * Why a team's block may be stale: the team mapping names no such team, or
 * names it only as an alias of another. Nothing is said without a mapping.
 */
export const teamStatus = (team: string, mapping: Record<string, string | string[]> | null | undefined): TeamStatus | null => {
    if (isGeneral(team) || !mapping || Object.keys(mapping).length === 0) return null
    const wanted = team.trim().toLocaleLowerCase()
    let alias = false
    for (const value of Object.values(mapping)) {
        const names = (Array.isArray(value) ? value : [value]).map(name => String(name || '').trim().toLocaleLowerCase())
        if (names[0] === wanted) return null
        if (names.slice(1).includes(wanted)) alias = true
    }
    return alias ? 'alias' : 'unknown'
}

/** The fields a cleanup changes on one finding, in words. */
export const cleanupChanges = (before: AssessmentCleanupValue, after: AssessmentCleanupValue | null): string[] => {
    if (!after) return []
    if (!after.details.trim() && before.details.trim()) return ['Whole assessment removed']
    const variant = (value: AssessmentCleanupValue, label: string): MatrixVariant => ({
        label,
        state: value.state || 'NOT_SET',
        details: value.details,
        suppressed: value.suppressed,
        instances: [],
    })
    const rows = compareVariants([variant(before, 'before'), variant(after, 'after')]).filter(row => row.differs)
    const labels = rows.map(row => row.label)
    const teamsBefore = activeTeams(before.details).map(team => team.toLocaleLowerCase())
    const teamsAfter = activeTeams(after.details).map(team => team.toLocaleLowerCase())
    const removed = activeTeams(before.details).filter(team => !teamsAfter.includes(team.toLocaleLowerCase()))
    const added = activeTeams(after.details).filter(team => !teamsBefore.includes(team.toLocaleLowerCase()))
    const named = [
        ...added.map(team => `${isGeneral(team) ? 'Global' : team} assessment added`),
        ...removed.map(team => `${isGeneral(team) ? 'Global' : team} assessment removed`),
    ]
    // Rows of a team that is added or removed as a whole say nothing more.
    const whole = new Set([...added, ...removed].map(team => (isGeneral(team) ? 'Global' : team).toLocaleLowerCase()))
    const rest = labels.filter(label => !whole.has(label.split(' · ')[0]!.toLocaleLowerCase()))
    const result = [...named, ...rest]
    return result.length ? result : ['Text of the assessment']
}
