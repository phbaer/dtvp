import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

export type CvssVersion = '4.0' | '3.1' | '3.0' | '2.0'

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

const REQUIREMENT_KEYS = new Set(['CR', 'IR', 'AR'])

const isDefinedMetricValue = (value?: string | null) => Boolean(value && value !== 'X' && value !== 'ND')

const getComponentValue = (instance: CvssInstanceLike, key: string) =>
    getComponentSafe(instance, key)?.shortName ?? null

const requirementMetricKeys = (version: CvssVersion, requirementKey: string) => {
    const impactKey = requirementKey.charAt(0)
    if (version === '4.0') {
        return { baseKey: `V${impactKey}`, modifiedKey: `MV${impactKey}` }
    }
    if (version === '2.0') {
        return { baseKey: impactKey, modifiedKey: null }
    }
    return { baseKey: impactKey, modifiedKey: `M${impactKey}` }
}

const applyComponent = (instance: CvssInstanceLike, key: string, value: string) => {
    try {
        instance.applyComponentString(key, value)
    } catch (error) {
        console.error('Failed to apply component string:', key, value, error)
    }
}

const applyModifiedAction = (
    instance: CvssInstanceLike,
    key: string,
    value: string,
) => {
    const baseValue = getComponentValue(instance, key.slice(1))
    if (!isDefinedMetricValue(baseValue)) return

    // A modified value equal to its base value is redundant. Clearing an old
    // override here also lets the same rule repair already-rescored vectors.
    applyComponent(instance, key, baseValue === value ? 'X' : value)
}

const applyRequirementAction = (
    instance: CvssInstanceLike,
    version: CvssVersion,
    key: string,
    value: string,
) => {
    const { baseKey, modifiedKey } = requirementMetricKeys(version, key)
    const baseValue = getComponentValue(instance, baseKey)

    // CVSS v2 requirements weight the base CIA metrics directly. CVSS v3/v4
    // requirements are kept only when the corresponding modified impact is
    // effective, so rescored vectors never retain an orphaned requirement.
    const hasApplicableMetric = version === '2.0'
        ? isDefinedMetricValue(baseValue)
        : Boolean(
            isDefinedMetricValue(baseValue) &&
            modifiedKey &&
            isDefinedMetricValue(getComponentValue(instance, modifiedKey)) &&
            getComponentValue(instance, modifiedKey) !== baseValue,
        )

    applyComponent(instance, key, hasApplicableMetric ? value : (version === '2.0' ? 'ND' : 'X'))
}

const toDefinedVector = (instance: CvssInstanceLike) => instance.toString()
    .split('/')
    .filter((part: string) => !part.endsWith(':X') && !part.endsWith(':ND'))
    .join('/')

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
    targetState,
    currentVector,
    fallbackVersion,
}: {
    rules: Array<Record<string, any>>
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

    const requirementActions: Array<[string, string]> = []
    for (const [key, value] of Object.entries(actions)) {
        if (REQUIREMENT_KEYS.has(key)) {
            requirementActions.push([key, value])
        } else if (key.startsWith('M') && key.length > 1) {
            applyModifiedAction(instance, key, value)
        } else {
            applyComponent(instance, key, value)
        }
    }
    for (const [key, value] of requirementActions) {
        applyRequirementAction(instance, version, key, value)
    }

    const vector = toDefinedVector(instance)
    return { vector, version }
}

export const normalizeCvssVectorInstance = (instance: CvssInstanceLike) => {
    const modifiedPairs: Array<[string, string]> = [
        ['MAV', 'AV'], ['MAC', 'AC'], ['MAT', 'AT'], ['MPR', 'PR'], ['MUI', 'UI'],
        ['MVC', 'VC'], ['MVI', 'VI'], ['MVA', 'VA'], ['MSC', 'SC'], ['MSI', 'SI'], ['MSA', 'SA'],
        ['MC', 'C'], ['MI', 'I'], ['MA', 'A'],
    ]

    for (const [modifiedKey, baseKey] of modifiedPairs) {
        const modifiedComponent = getComponentSafe(instance, modifiedKey)
        const baseComponent = getComponentSafe(instance, baseKey)
        if (!modifiedComponent || !baseComponent) continue

        const modifiedValue = modifiedComponent.shortName
        const baseValue = baseComponent.shortName
        if (modifiedValue === 'X' || baseValue === 'X') continue
        if (modifiedValue === baseValue) {
            instance.applyComponentString(modifiedKey, 'X')
        }
    }

    const requirementMap: Record<string, { baseKeys: string[], modifiedKeys: string[] }> = {
        CR: { baseKeys: ['C', 'VC'], modifiedKeys: ['MC', 'MVC'] },
        IR: { baseKeys: ['I', 'VI'], modifiedKeys: ['MI', 'MVI'] },
        AR: { baseKeys: ['A', 'VA'], modifiedKeys: ['MA', 'MVA'] },
    }

    for (const [requirementKey, metricKeys] of Object.entries(requirementMap)) {
        const requirementComponent = getComponentSafe(instance, requirementKey)
        if (!requirementComponent || !isDefinedMetricValue(requirementComponent.shortName)) continue

        const baseComponent = metricKeys.baseKeys
            .map(baseKey => getComponentSafe(instance, baseKey))
            .find(component => component !== null)
        if (!baseComponent) continue

        const modifiedComponent = metricKeys.modifiedKeys
            .map(modifiedKey => getComponentSafe(instance, modifiedKey))
            .find(component => component !== null)

        if (modifiedComponent) {
            const hasEffectiveModifiedMetric = isDefinedMetricValue(baseComponent.shortName) &&
                isDefinedMetricValue(modifiedComponent.shortName) &&
                modifiedComponent.shortName !== baseComponent.shortName
            if (!hasEffectiveModifiedMetric) {
                instance.applyComponentString(requirementKey, 'X')
            }
        } else if (!isDefinedMetricValue(baseComponent.shortName)) {
            // CVSS v2 has no modified CIA metrics; its requirements apply to
            // the corresponding base metric and use ND as the undefined value.
            instance.applyComponentString(requirementKey, 'ND')
        }
    }

    return toDefinedVector(instance)
}
