import type { GroupedVuln } from '../types'
import { parseVersionOverride } from './assessment-helpers'
import { stripSsvcDetails } from './ssvc'

// Assessment scopes of a vulnerability (ADR 0010). A port of the server's
// dtvp/assessment_scopes.py; both are tested against
// __tests__/fixtures/assessment_scope_cases.json.

export const BASE_SCOPE = 'base'
export const AMBIGUOUS_SCOPE = 'ambiguous'

type Finding = Record<string, any>

export interface AssessmentScope {
    name: string
    label: string | null
    /** The reason the tagged findings agree on; null without one. */
    reason: string | null
    reasonMismatch: boolean
    versions: Array<{ project_uuid: string; version: string | null }>
    instances: Finding[]
    /** Assessed findings without the marker in an overridden version. */
    partial: string[]
    /** Untouched findings without the marker in an overridden version. */
    gaps: string[]
    pending: boolean
}

export interface AssessmentScopeView {
    scopes: AssessmentScope[]
    ambiguous: Finding[]
    versionScopes: Record<string, string>
    hasOverrides: boolean
    primary: AssessmentScope | null
}

const stateOf = (instance: Finding): string => instance.analysis_state || instance.analysisState || 'NOT_SET'
const detailsOf = (instance: Finding): string => instance.analysis_details || instance.analysisDetails || ''

const PENDING_REVIEW_MARKER = '[Status: Pending Review]'

/** Whether an assessment text waits for review: the marker outside the SSVC
 * details. As the server's has_pending_review_marker (assessment_scopes.py). */
export const hasPendingReviewMarker = (details: string | undefined | null): boolean => {
    const text = String(details || '')
    return text.includes(PENDING_REVIEW_MARKER) && stripSsvcDetails(text).includes(PENDING_REVIEW_MARKER)
}

const IGNORED_FOR_UNTOUCHED = /\[(?:Version Override|Override Reason|Status: Pending Review)[^\]]*\]/g

/** No state and no text other than the override and pending tags. */
export const isUntouched = (instance: Finding): boolean =>
    stateOf(instance) === 'NOT_SET' && !detailsOf(instance).replace(IGNORED_FOR_UNTOUCHED, '').trim()

export const scopeFindingKey = (instance: Finding): string =>
    ['project_uuid', 'component_uuid', 'vulnerability_uuid'].map(name => String(instance[name] || '')).join(':')

const versionKey = (version: Finding, instance: Finding): string =>
    String(instance.project_uuid || version.project_uuid || version.project_version || version.version || '')

const labelKey = (label: string): string => label.toLowerCase()

const compareLabels = (left: AssessmentScope, right: AssessmentScope) => {
    const a = labelKey(left.label || '')
    const b = labelKey(right.label || '')
    return a < b ? -1 : a > b ? 1 : 0
}

export function getAssessmentScopes(group: GroupedVuln): AssessmentScopeView {
    const byVersion = new Map<string, { version: Finding; findings: Array<[Finding, ReturnType<typeof parseVersionOverride>]> }>()
    for (const version of (group.affected_versions || []) as Finding[]) {
        for (const instance of (version.components || []) as Finding[]) {
            const key = versionKey(version, instance)
            if (!byVersion.has(key)) byVersion.set(key, { version, findings: [] })
            byVersion.get(key)!.findings.push([instance, parseVersionOverride(detailsOf(instance))])
        }
    }

    const newScope = (name: string, label: string | null): AssessmentScope => ({
        name, label, reason: null, reasonMismatch: false, versions: [], instances: [], partial: [], gaps: [], pending: false,
    })
    const base = newScope(BASE_SCOPE, null)
    const overrides = new Map<string, AssessmentScope>()
    const reasons = new Map<AssessmentScope, string[]>()
    const ambiguous: Finding[] = []
    const versionScopes: Record<string, string> = {}

    for (const [key, { version, findings }] of byVersion) {
        const labels = new Map<string, string>()
        for (const [, marker] of findings) {
            if (marker?.label && !labels.has(labelKey(marker.label))) labels.set(labelKey(marker.label), marker.label)
        }
        if (labels.size > 1) {
            versionScopes[key] = AMBIGUOUS_SCOPE
            ambiguous.push(...findings.map(([instance]) => instance))
            continue
        }
        let scope = base
        if (labels.size === 1) {
            const [[lk, label]] = [...labels]
            if (!overrides.has(lk)) overrides.set(lk, newScope(label, label))
            scope = overrides.get(lk)!
        }
        versionScopes[key] = scope.name
        scope.versions.push({ project_uuid: key, version: version.project_version || version.version || null })
        for (const [instance, marker] of findings) {
            scope.instances.push(instance)
            if (scope === base) continue
            if (marker) {
                if (!reasons.has(scope)) reasons.set(scope, [])
                reasons.get(scope)!.push(marker.reason || '')
            } else if (isUntouched(instance)) {
                scope.gaps.push(scopeFindingKey(instance))
            } else {
                scope.partial.push(scopeFindingKey(instance))
            }
        }
    }

    const scopes = [base, ...[...overrides.values()].sort(compareLabels)]
    for (const scope of scopes) {
        const agreed = new Set(reasons.get(scope) || [])
        scope.reasonMismatch = agreed.size > 1
        scope.reason = agreed.size === 1 ? ([...agreed][0] || null) : null
        scope.pending = scope.instances.some(instance => hasPendingReviewMarker(detailsOf(instance)))
    }
    const withFindings = scopes.filter(scope => scope.instances.length > 0)
    const primary = base.instances.length > 0
        ? base
        : [...withFindings].sort((left, right) => right.instances.length - left.instances.length || compareLabels(left, right))[0] || null

    return {
        scopes,
        ambiguous,
        versionScopes,
        hasOverrides: ambiguous.length > 0 || overrides.size > 0,
        primary,
    }
}

/** ``group`` with only ``instances``, for rules that run per scope. */
export function scopedGroup(group: GroupedVuln, instances: Finding[]): GroupedVuln {
    const wanted = new Set(instances)
    const affected_versions = (group.affected_versions || [])
        .map(version => ({ ...version, components: (version.components || []).filter(component => wanted.has(component as Finding)) }))
        .filter(version => version.components.length > 0)
    // A scope's own lifecycle is derived from its findings, never from the
    // whole group's list metadata.
    const { list_metadata: _metadata, ...rest } = group as GroupedVuln & { list_metadata?: unknown }
    return { ...rest, affected_versions } as GroupedVuln
}

/** Combined in this order (ADR 0010 section 5). */
export function combineLifecycles(lifecycles: string[], ambiguous = false): string {
    if (ambiguous || lifecycles.includes('INCONSISTENT')) return 'INCONSISTENT'
    if (lifecycles.includes('INCOMPLETE') || (lifecycles.includes('OPEN') && lifecycles.some(value => value !== 'OPEN'))) {
        return 'INCOMPLETE'
    }
    if (lifecycles.includes('NEEDS_APPROVAL')) return 'NEEDS_APPROVAL'
    if (lifecycles.every(value => value === 'OPEN')) return 'OPEN'
    if (lifecycles.includes('ASSESSED_LEGACY')) return 'ASSESSED_LEGACY'
    return 'ASSESSED'
}
