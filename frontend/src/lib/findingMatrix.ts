import {
    assessmentTextKey,
    assessmentTextToFields,
    STATE_PRIORITY,
    type AssessmentTeamFields,
} from './assessment-helpers'

/** What the matrix needs of one finding (a component in a project version). */
export interface MatrixInstance {
    project_version?: string | null
    component_name?: string | null
    component_version?: string | null
    analysis_state?: string | null
    analysis_details?: string | null
    is_suppressed?: boolean | null
    is_new_finding?: boolean | null
    [key: string]: unknown
}

/** Findings that carry the same assessment. */
export interface MatrixVariant<T extends MatrixInstance = MatrixInstance> {
    /** A, B, C … by number of findings; A is the most common one. */
    label: string
    state: string
    details: string
    suppressed: boolean
    instances: T[]
}

export interface MatrixCell<T extends MatrixInstance = MatrixInstance> {
    instances: T[]
    /** The worst state among the findings of the cell. */
    state: string
    variantLabels: string[]
    /** True when a finding of the cell is not in the most common variant. */
    differs: boolean
    isNew: boolean
    suppressed: boolean
    componentVersions: string[]
}

export interface MatrixRow<T extends MatrixInstance = MatrixInstance> {
    key: string
    name: string
    /** The component version when it is the same in every project version. */
    version: string
    instances: T[]
    cells: Record<string, MatrixCell<T> | undefined>
}

export interface FindingMatrix<T extends MatrixInstance = MatrixInstance> {
    versions: string[]
    rows: MatrixRow<T>[]
    variants: MatrixVariant<T>[]
    /** Findings whose assessment is not the most common one. */
    differingCount: number
    total: number
}

const UNKNOWN_VERSION = '(unknown)'

const byNumericText = (left: string, right: string) =>
    left.localeCompare(right, undefined, { numeric: true })

const stateOf = (instance: MatrixInstance) => String(instance.analysis_state || 'NOT_SET')

const variantKey = (instance: MatrixInstance) =>
    `${stateOf(instance)}|${assessmentTextKey(instance.analysis_details)}|${Boolean(instance.is_suppressed)}`

const variantLabel = (index: number) => {
    let label = ''
    let rest = index
    do {
        label = String.fromCharCode(65 + (rest % 26)) + label
        rest = Math.floor(rest / 26) - 1
    } while (rest >= 0)
    return label
}

/**
 * Where a vulnerability was found: components by project versions, with the
 * assessment of each finding and the variants the assessments fall into.
 */
export const buildFindingMatrix = <T extends MatrixInstance>(instances: readonly T[]): FindingMatrix<T> => {
    const grouped = new Map<string, T[]>()
    for (const instance of instances) {
        const key = variantKey(instance)
        const list = grouped.get(key)
        if (list) list.push(instance)
        else grouped.set(key, [instance])
    }
    // Most findings first; among equals the worse state first, so the order
    // does not depend on the order of the findings.
    const variants: MatrixVariant<T>[] = [...grouped.values()]
        .sort((left, right) => (
            right.length - left.length
            || (STATE_PRIORITY[stateOf(left[0]!)] ?? 10) - (STATE_PRIORITY[stateOf(right[0]!)] ?? 10)
            || variantKey(left[0]!).localeCompare(variantKey(right[0]!))
        ))
        .map((list, index) => ({
            label: variantLabel(index),
            state: stateOf(list[0]!),
            details: String(list[0]!.analysis_details || ''),
            suppressed: Boolean(list[0]!.is_suppressed),
            instances: list,
        }))
    const labelOf = new Map<T, string>()
    for (const variant of variants) {
        for (const instance of variant.instances) labelOf.set(instance, variant.label)
    }
    const commonLabel = variants[0]?.label ?? ''

    const versions = new Set<string>()
    const rowInstances = new Map<string, T[]>()
    for (const instance of instances) {
        versions.add(String(instance.project_version || '').trim() || UNKNOWN_VERSION)
        const name = String(instance.component_name || '').trim() || '(unnamed component)'
        const list = rowInstances.get(name)
        if (list) list.push(instance)
        else rowInstances.set(name, [instance])
    }

    const rows: MatrixRow<T>[] = [...rowInstances.entries()]
        .sort(([left], [right]) => byNumericText(left, right))
        .map(([name, list]) => {
            const componentVersions = new Set(list.map(instance => String(instance.component_version || '').trim()))
            const cells: Record<string, MatrixCell<T> | undefined> = {}
            for (const instance of list) {
                const version = String(instance.project_version || '').trim() || UNKNOWN_VERSION
                const cell = cells[version] ?? (cells[version] = {
                    instances: [],
                    state: 'NOT_SET',
                    variantLabels: [],
                    differs: false,
                    isNew: false,
                    suppressed: false,
                    componentVersions: [],
                })
                const label = labelOf.get(instance) ?? ''
                const state = stateOf(instance)
                if (cell.instances.length === 0 || (STATE_PRIORITY[state] ?? 10) < (STATE_PRIORITY[cell.state] ?? 10)) {
                    cell.state = state
                }
                cell.instances.push(instance)
                if (!cell.variantLabels.includes(label)) cell.variantLabels.push(label)
                cell.differs = cell.differs || label !== commonLabel
                cell.isNew = cell.isNew || Boolean(instance.is_new_finding)
                cell.suppressed = cell.suppressed || Boolean(instance.is_suppressed)
                const componentVersion = String(instance.component_version || '').trim()
                if (componentVersion && !cell.componentVersions.includes(componentVersion)) {
                    cell.componentVersions.push(componentVersion)
                }
            }
            for (const cell of Object.values(cells)) {
                cell?.variantLabels.sort()
                cell?.componentVersions.sort(byNumericText)
            }
            return {
                key: name,
                name,
                version: componentVersions.size === 1 ? [...componentVersions][0]! : '',
                instances: list,
                cells,
            }
        })

    return {
        versions: [...versions].sort(byNumericText),
        rows,
        variants,
        differingCount: instances.length - (variants[0]?.instances.length ?? 0),
        total: instances.length,
    }
}

export interface ComparisonRow {
    /** Stable identifier of the field, e.g. `state` or `team:Security:details`. */
    key: string
    label: string
    /** The value per variant, in the order of the variants. */
    values: string[]
    differs: boolean
}

const humanState = (state: string) => state.replaceAll('_', ' ')

const teamValue = (team: AssessmentTeamFields | undefined, pick: (team: AssessmentTeamFields) => string) =>
    team ? pick(team) : ''

/**
 * The variants field by field. Only rows with a value in at least one
 * variant are returned; `differs` marks the rows that explain the mismatch.
 */
export const compareVariants = (variants: readonly MatrixVariant[]): ComparisonRow[] => {
    const fields = variants.map(variant => assessmentTextToFields(variant.details))
    const rows: ComparisonRow[] = []
    const add = (key: string, label: string, values: string[]) => {
        if (values.every(value => !value)) return
        const normalized = values.map(value => value.replace(/\s+/g, ' ').trim())
        rows.push({ key, label, values, differs: new Set(normalized).size > 1 })
    }

    add('state', 'State', variants.map(variant => humanState(variant.state)))
    add('suppressed', 'Suppressed', variants.some(variant => variant.suppressed)
        ? variants.map(variant => (variant.suppressed ? 'Yes' : 'No'))
        : variants.map(() => ''))
    add('pending', 'Pending review', fields.some(field => field.pending_review)
        ? fields.map(field => (field.pending_review ? 'Yes' : 'No'))
        : fields.map(() => ''))
    add('rescored_score', 'Rescored score', fields.map(field => (
        field.rescored_score == null ? '' : String(field.rescored_score)
    )))
    add('rescored_vector', 'Rescored vector', fields.map(field => field.rescored_vector || ''))
    add('free_text', 'Text outside the team assessments', fields.map(field => (field.free_text || '').trim()))

    const teamNames: string[] = []
    for (const field of fields) {
        for (const team of field.teams) {
            if (team.historical) continue
            if (!teamNames.some(name => name.toLocaleLowerCase() === team.team.toLocaleLowerCase())) {
                teamNames.push(team.team)
            }
        }
    }
    // The General assessment first: it is the one that decides.
    teamNames.sort((left, right) => (
        Number(right.toLocaleLowerCase() === 'general') - Number(left.toLocaleLowerCase() === 'general')
        || byNumericText(left, right)
    ))
    for (const name of teamNames) {
        const teams = fields.map(field => field.teams.find(team => (
            !team.historical && team.team.toLocaleLowerCase() === name.toLocaleLowerCase()
        )))
        const title = name.toLocaleLowerCase() === 'general' ? 'Global' : name
        add(`team:${name}:state`, `${title} · state`, teams.map(team => teamValue(team, value => humanState(value.state))))
        add(`team:${name}:justification`, `${title} · justification`, teams.map(team => teamValue(team, value => (
            value.justification && value.justification !== 'NOT_SET' ? humanState(value.justification) : ''
        ))))
        add(`team:${name}:details`, `${title} · rationale`, teams.map(team => teamValue(team, value => value.details.trim())))
        add(`team:${name}:ticket`, `${title} · ticket`, teams.map(team => teamValue(team, value => value.ticket || '')))
        add(`team:${name}:assessed_by`, `${title} · assessed by`, teams.map(team => teamValue(team, value => value.assessed_by || '')))
        add(`team:${name}:reviewed_by`, `${title} · reviewed by`, teams.map(team => teamValue(team, value => value.reviewed_by || '')))
        add(`team:${name}:assessed_at`, `${title} · date`, teams.map(team => teamValue(team, value => (
            value.assessed_at_ms ? new Date(value.assessed_at_ms).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : ''
        ))))
    }
    return rows
}
