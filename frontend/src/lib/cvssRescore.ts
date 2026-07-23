import {
    createCvssInstance,
    detectCvssVersion,
    type CvssInstanceLike,
    type CvssVersion,
} from './cvss'

export type { CvssVersion } from './cvss'

export interface CvssMetricRelationship {
    base: string
    modified?: string
    requirement?: string
}

export interface CvssMetricRule {
    undefined_values: string[]
    base_metrics: string[]
    metric_order: string[]
    relationships: CvssMetricRelationship[]
}

export type CvssMetricRules = Partial<Record<CvssVersion, CvssMetricRule>>

const getComponentSafe = (instance: CvssInstanceLike, name: string) => {
    if (typeof instance.getComponentByStringOpt === 'function') {
        return instance.getComponentByStringOpt(name)
    }
    try {
        return instance.getComponent?.(name) ?? null
    } catch {
        return null
    }
}

const undefinedValues = (metricRule?: CvssMetricRule) =>
    new Set(metricRule?.undefined_values?.length ? metricRule.undefined_values : ['X', 'ND'])

const isDefinedMetricValue = (value?: string | null, metricRule?: CvssMetricRule) =>
    Boolean(value && !undefinedValues(metricRule).has(value))

const getComponentValue = (instance: CvssInstanceLike, key: string) =>
    getComponentSafe(instance, key)?.shortName ?? null

const applyComponent = (instance: CvssInstanceLike, key: string, value: string) => {
    try {
        instance.applyComponentString(key, value)
    } catch (error) {
        console.error('Failed to apply component string:', key, value, error)
    }
}

const applyModifiedAction = (
    instance: CvssInstanceLike,
    relationship: CvssMetricRelationship,
    value: string,
    metricRule?: CvssMetricRule,
) => {
    if (!relationship.modified) return
    const baseValue = getComponentValue(instance, relationship.base)
    if (!isDefinedMetricValue(baseValue, metricRule)) return

    // A modified value equal to its base value is redundant. Clearing an old
    // override here also lets the same rule repair already-rescored vectors.
    applyComponent(
        instance,
        relationship.modified,
        baseValue === value ? (metricRule?.undefined_values?.[0] || 'X') : value,
    )
}

const applyRequirementAction = (
    instance: CvssInstanceLike,
    relationship: CvssMetricRelationship,
    value: string,
    metricRule?: CvssMetricRule,
) => {
    if (!relationship.requirement) return
    const baseValue = getComponentValue(instance, relationship.base)

    // A relationship without a modified metric (CVSS v2 in the default
    // configuration) applies its requirement to the base metric. Otherwise,
    // a requirement is retained only while the configured modified metric is
    // an effective override.
    const hasApplicableMetric = !relationship.modified
        ? isDefinedMetricValue(baseValue, metricRule)
        : Boolean(
            isDefinedMetricValue(baseValue, metricRule) &&
            isDefinedMetricValue(getComponentValue(instance, relationship.modified), metricRule) &&
            getComponentValue(instance, relationship.modified) !== baseValue,
        )

    applyComponent(
        instance,
        relationship.requirement,
        hasApplicableMetric ? value : (metricRule?.undefined_values?.[0] || 'X'),
    )
}

const toDefinedVector = (instance: CvssInstanceLike, metricRule?: CvssMetricRule) => {
    const unresolved = undefinedValues(metricRule)
    return instance.toString()
    .split('/')
    .filter((part: string) => {
        const value = part.includes(':') ? part.slice(part.lastIndexOf(':') + 1) : ''
        return !unresolved.has(value)
    })
    .join('/')
}

const getTransitionActions = (
    rules: Array<Record<string, any>>,
    targetState: string,
    vectorVersion: CvssVersion,
) => {
    const triggerMatch = rules.find(rule => {
        const triggerState = rule?.trigger?.state ?? rule?.from
        return triggerState === targetState
    })

    if (!triggerMatch) {
        return null
    }

    return (triggerMatch.actions?.[vectorVersion] || {}) as Record<string, string>
}

export const buildRescoredVectorForState = ({
    rules,
    metricRules,
    targetState,
    currentVector,
    fallbackVersion,
}: {
    rules: Array<Record<string, any>>
    metricRules?: CvssMetricRules
    targetState: string
    currentVector: string
    fallbackVersion: CvssVersion
}): { vector: string; version: CvssVersion } | null => {
    const vectorVersion = detectCvssVersion(currentVector) ?? fallbackVersion
    const actions = getTransitionActions(rules, targetState, vectorVersion)

    if (!actions || Object.keys(actions).length === 0) {
        return null
    }

    const { instance, version } = createCvssInstance(currentVector, fallbackVersion)
    const metricRule = metricRules?.[version]
    const relationships = metricRule?.relationships || []
    const requirementRelationships = new Map(
        relationships
            .filter(relationship => relationship.requirement)
            .map(relationship => [relationship.requirement as string, relationship]),
    )
    const modifiedRelationships = new Map(
        relationships
            .filter(relationship => relationship.modified)
            .map(relationship => [relationship.modified as string, relationship]),
    )

    const requirementActions: Array<[string, string]> = []
    for (const [key, value] of Object.entries(actions)) {
        if (requirementRelationships.has(key)) {
            requirementActions.push([key, value])
        } else if (modifiedRelationships.has(key)) {
            applyModifiedAction(instance, modifiedRelationships.get(key)!, value, metricRule)
        } else {
            applyComponent(instance, key, value)
        }
    }
    for (const [key, value] of requirementActions) {
        applyRequirementAction(instance, requirementRelationships.get(key)!, value, metricRule)
    }

    const vector = toDefinedVector(instance, metricRule)
    return { vector, version }
}

export const normalizeCvssVectorInstance = (
    instance: CvssInstanceLike,
    metricRule?: CvssMetricRule,
) => {
    const relationships = metricRule?.relationships || []
    for (const relationship of relationships) {
        const modifiedKey = relationship.modified
        if (!modifiedKey) continue
        const baseKey = relationship.base
        const modifiedComponent = getComponentSafe(instance, modifiedKey)
        const baseComponent = getComponentSafe(instance, baseKey)
        if (!modifiedComponent || !baseComponent) continue

        const modifiedValue = modifiedComponent.shortName
        const baseValue = baseComponent.shortName
        if (!isDefinedMetricValue(modifiedValue, metricRule) || !isDefinedMetricValue(baseValue, metricRule)) continue
        if (modifiedValue === baseValue) {
            instance.applyComponentString(modifiedKey, metricRule?.undefined_values?.[0] || 'X')
        }
    }

    for (const relationship of relationships) {
        const requirementKey = relationship.requirement
        if (!requirementKey) continue
        const requirementComponent = getComponentSafe(instance, requirementKey)
        if (!requirementComponent || !isDefinedMetricValue(requirementComponent.shortName, metricRule)) continue

        const baseComponent = getComponentSafe(instance, relationship.base)
        if (!baseComponent) continue

        const modifiedComponent = relationship.modified
            ? getComponentSafe(instance, relationship.modified)
            : null

        if (modifiedComponent) {
            const hasEffectiveModifiedMetric = isDefinedMetricValue(baseComponent.shortName, metricRule) &&
                isDefinedMetricValue(modifiedComponent.shortName, metricRule) &&
                modifiedComponent.shortName !== baseComponent.shortName
            if (!hasEffectiveModifiedMetric) {
                instance.applyComponentString(requirementKey, metricRule?.undefined_values?.[0] || 'X')
            }
        } else if (!isDefinedMetricValue(baseComponent.shortName, metricRule)) {
            instance.applyComponentString(requirementKey, metricRule?.undefined_values?.[0] || 'X')
        }
    }

    return toDefinedVector(instance, metricRule)
}
