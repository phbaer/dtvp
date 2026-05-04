import { Cvss2, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

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
    let normalizedVector = vector.trim()

    try {
        if (normalizedVector.startsWith('CVSS:4.0')) {
            return { version, instance: new Cvss4P0(normalizedVector) }
        }
        if (normalizedVector.startsWith('CVSS:3.')) {
            if (normalizedVector.startsWith('CVSS:3.0')) {
                normalizedVector = normalizedVector.replace('CVSS:3.0', 'CVSS:3.1')
            }
            return { version, instance: new Cvss3P1(normalizedVector) }
        }
        if (normalizedVector.startsWith('CVSS:2.0') || (normalizedVector.includes('/') && !normalizedVector.startsWith('CVSS:'))) {
            return { version, instance: new Cvss2(normalizedVector) }
        }
    } catch {
        // fall through to default vector
    }

    const defaultVersion = version === '3.0' ? '3.1' : version
    const defaultVector = DEFAULT_VECTOR_BY_VERSION[defaultVersion]
    if (defaultVersion === '4.0') {
        return { version: defaultVersion, instance: new Cvss4P0(defaultVector) }
    }
    if (defaultVersion === '2.0') {
        return { version: defaultVersion, instance: new Cvss2(defaultVector) }
    }
    return { version: defaultVersion, instance: new Cvss3P1(defaultVector) }
}

const getMetricValue = (vectorParts: string[], key: string) => {
    const part = vectorParts.find(vectorPart => vectorPart.startsWith(`${key}:`))
    return part ? part.split(':')[1] : null
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

const shouldApplyAction = (
    key: string,
    value: string,
    currentVector: string,
    actions: Record<string, string>,
) => {
    const vectorParts = currentVector.split('/')
    const isV4 = currentVector.startsWith('CVSS:4.0')
    const isModifiedMetric = key.startsWith('M') && key.length > 1
    const isRequirementMetric = key === 'CR' || key === 'IR' || key === 'AR'

    let baseKey = key
    if (isModifiedMetric) {
        baseKey = key.slice(1)
    } else if (isRequirementMetric) {
        baseKey = isV4 ? `V${key.charAt(0)}` : key.charAt(0)
    }

    const baseValue = getMetricValue(vectorParts, baseKey)
    const isDefined = Boolean(baseValue && baseValue !== 'X')

    if (isModifiedMetric) {
        return isDefined && baseValue !== value
    }

    if (isRequirementMetric) {
        const modKey = `M${baseKey}`
        const currentModValue = actions[modKey] ?? getMetricValue(vectorParts, modKey)
        const finalModValue = currentModValue && currentModValue !== 'X' ? currentModValue : baseValue
        return isDefined && baseValue !== finalModValue
    }

    return true
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

    for (const [key, value] of Object.entries(actions)) {
        if (!shouldApplyAction(key, value, currentVector.trim(), actions)) {
            continue
        }

        try {
            instance.applyComponentString(key, value)
        } catch (error) {
            console.error('Failed to apply component string:', key, value, error)
        }
    }

    const vector = instance.toString().split('/').filter((part: string) => !part.endsWith(':X')).join('/')
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

    const requirementMap: Record<string, string[]> = {
        CR: ['C', 'VC'],
        IR: ['I', 'VI'],
        AR: ['A', 'VA'],
    }

    for (const [requirementKey, baseKeys] of Object.entries(requirementMap)) {
        const requirementComponent = getComponentSafe(instance, requirementKey)
        if (!requirementComponent || requirementComponent.shortName === 'X') continue

        const baseComponent = baseKeys.map(baseKey => getComponentSafe(instance, baseKey)).find(Boolean)
        if (!baseComponent || baseComponent.shortName === 'X') continue

        if (requirementComponent.shortName === baseComponent.shortName) {
            instance.applyComponentString(requirementKey, 'X')
        }
    }

    return instance.toString().split('/').filter((part: string) => !part.endsWith(':X')).join('/')
}