// Labels and grouping for findings Dependency-Track no longer reports
// (GET /api/gone-findings), shared by the gone findings view and statistics.
import type { GoneFinding, GoneFindingsOfVersion } from '../types'

export const REASONS: Record<string, string> = {
    replaced: 'Replaced',
    recreated: 'Recreated by Dependency-Track',
    component_removed: 'Component removed',
    no_longer_matched: 'No longer matched',
    undetermined: 'Not yet determined',
    missing_at_export: 'Missing at export',
}

export const CARRY_OVER: Record<string, string> = {
    carried: 'Carried over, pending review',
    conflict: 'Assessments differ, not carried',
    own_assessment: 'Successor has its own assessment',
    undetermined: 'Component unknown, not carried',
    kept: 'Assessment kept on the gone finding',
    no_assessment: 'No assessment',
}

/** Same name and version under a new ID: Dependency-Track recreated the
 * component (a BOM uploaded again), nothing was replaced. */
export const isRecreated = (finding: GoneFinding) => {
    if (typeof finding.recreated === 'boolean') return finding.recreated
    const successor = finding.successor
    return Boolean(
        finding.reason === 'replaced'
        && successor?.component_version
        && successor.component_version === finding.component_version
        && successor.component_name === finding.component_name,
    )
}

/** The reason a finding went, with recreated components apart. */
export const reasonKey = (finding: GoneFinding) => (isRecreated(finding) ? 'recreated' : String(finding.reason))

export const reasonLabel = (finding: GoneFinding) => {
    if (isRecreated(finding)) return 'Recreated by Dependency-Track (same version, new component ID)'
    if (finding.reason === 'replaced' && finding.successor) {
        const name = finding.successor.component_name || finding.successor.component_uuid
        const version = finding.successor.component_version
        return `Replaced by ${name}${version ? `@${version}` : ''}`
    }
    return REASONS[finding.reason] || finding.reason
}

export const carryOverLabel = (finding: GoneFinding) => {
    const carryOver = finding.carry_over || ''
    if (carryOver === 'carried' && isRecreated(finding)) return 'Carried over to the recreated component'
    return CARRY_OVER[carryOver] || carryOver
}

export const componentLabel = (finding: GoneFinding) =>
    finding.component_name
        ? `${finding.component_name}${finding.component_version ? `@${finding.component_version}` : ''}`
        // Known only by its Dependency-Track UUID; no local source names it.
        : `Unknown component (${finding.component_uuid.slice(0, 8)})`

export const needsAttention = (finding: GoneFinding) => Boolean(finding.needs_attention)

/** Gone findings that need attention, over all versions. */
export const attentionCount = (versions: GoneFindingsOfVersion[]) =>
    versions.reduce((sum, version) => sum + version.findings.filter(needsAttention).length, 0)

export const goneCount = (versions: GoneFindingsOfVersion[]) =>
    versions.reduce(
        (sum, version) => sum + Object.values(version.gone || {}).reduce((a, b) => a + b, 0),
        0,
    )

export const byVersionDescending = (left: GoneFindingsOfVersion, right: GoneFindingsOfVersion) =>
    right.version.localeCompare(left.version, undefined, { numeric: true, sensitivity: 'base' })

export interface ComponentGroup {
    key: string
    label: string
    findings: GoneFinding[]
}

export interface ReasonGroup {
    key: string
    label: string
    components: ComponentGroup[]
    count: number
}

/** Findings of one version grouped by reason, then by component. */
export const groupFindings = (findings: GoneFinding[]): ReasonGroup[] => {
    const reasons = new Map<string, Map<string, ComponentGroup>>()
    for (const finding of findings) {
        const reason = reasonKey(finding)
        let components = reasons.get(reason)
        if (!components) {
            components = new Map()
            reasons.set(reason, components)
        }
        const key = finding.component_uuid
        let group = components.get(key)
        if (!group) {
            group = { key, label: componentLabel(finding), findings: [] }
            components.set(key, group)
        }
        group.findings.push(finding)
    }
    return [...reasons.entries()]
        .map(([key, components]) => {
            const list = [...components.values()].sort((a, b) => a.label.localeCompare(b.label))
            return {
                key,
                label: REASONS[key] || key,
                components: list,
                count: list.reduce((sum, group) => sum + group.findings.length, 0),
            }
        })
        .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
}
