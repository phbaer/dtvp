import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

export type CvssVersion = '4.0' | '3.1' | '3.0' | '2.0'

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

interface CvssComponentLike {
    shortName: string
}

interface CvssInstanceLike {
    applyComponentString: (key: string, value: string) => void
    getComponentByStringOpt?: (name: string) => CvssComponentLike | null
    getComponent?: (name: any) => CvssComponentLike | null
    toString: () => string
}

const DEFAULT_VECTOR_BY_VERSION: Record<CvssVersion, string> = {
    '4.0': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
    '3.1': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    '3.0': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    '2.0': 'AV:N/AC:L/Au:N/C:N/I:N/A:N',
}

const detectCvssVersion = (vector: string, fallbackVersion: CvssVersion): CvssVersion => {
    const trimmed = vector.trim()
    if (trimmed.startsWith('CVSS:4.0')) return '4.0'
    if (trimmed.startsWith('CVSS:3.0')) return '3.0'
    if (trimmed.startsWith('CVSS:3.')) return '3.1'
    if (trimmed.startsWith('CVSS:2.0') || (trimmed.includes('/') && !trimmed.startsWith('CVSS:'))) return '2.0'
    return fallbackVersion
}

const createCvssInstance = (vector: string, fallbackVersion: CvssVersion) => {
    const version = detectCvssVersion(vector, fallbackVersion)
    const normalizedVector = vector.trim()
    const hasRecognizedVector = normalizedVector.startsWith('CVSS:4.0') ||
        normalizedVector.startsWith('CVSS:3.') ||
        normalizedVector.startsWith('CVSS:2.0') ||
        (normalizedVector.includes('/') && !normalizedVector.startsWith('CVSS:'))

    if (hasRecognizedVector) {
        try {
            if (version === '4.0') return { version, instance: new Cvss4P0(normalizedVector) }
            if (version === '3.1') return { version, instance: new Cvss3P1(normalizedVector) }
            if (version === '3.0') return { version, instance: new Cvss3P0(normalizedVector) }
            if (version === '2.0') return { version, instance: new Cvss2(normalizedVector) }
        } catch {
            // fall through to default vector
        }
    }

    const defaultVector = DEFAULT_VECTOR_BY_VERSION[version]
    if (version === '4.0') return { version, instance: new Cvss4P0(defaultVector) }
    if (version === '3.1') return { version, instance: new Cvss3P1(defaultVector) }
    if (version === '3.0') return { version, instance: new Cvss3P0(defaultVector) }
    return { version, instance: new Cvss2(defaultVector) }
}

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
    const vectorVersion = detectCvssVersion(currentVector, fallbackVersion)
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
