import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

export type CvssVersion = '4.0' | '3.1' | '3.0' | '2.0'

export interface CvssComponentLike {
    shortName: string
}

export interface CvssInstanceLike {
    applyComponentString: (key: string, value: string) => void
    getComponentByStringOpt?: (name: string) => CvssComponentLike | null
    getComponent?: (name: any) => CvssComponentLike | null
    toString: () => string
}

export const CVSS_VERSIONS: readonly CvssVersion[] = ['4.0', '3.1', '3.0', '2.0']

export const DEFAULT_CVSS_VECTOR_BY_VERSION: Record<CvssVersion, string> = {
    '4.0': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
    '3.1': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    '3.0': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    '2.0': 'AV:N/AC:L/Au:N/C:N/I:N/A:N',
}

export function detectCvssVersion(vector: string): CvssVersion | null {
    const trimmed = vector.trim()
    if (trimmed.startsWith('CVSS:4.0')) return '4.0'
    if (trimmed.startsWith('CVSS:3.0')) return '3.0'
    if (trimmed.startsWith('CVSS:3.')) return '3.1'
    if (trimmed.startsWith('CVSS:2.0') || (trimmed.includes('/') && !trimmed.startsWith('CVSS:'))) {
        return '2.0'
    }
    return null
}

export function createDefaultCvssInstance(version: CvssVersion): CvssInstanceLike {
    const vector = DEFAULT_CVSS_VECTOR_BY_VERSION[version]
    if (version === '4.0') return new Cvss4P0(vector)
    if (version === '3.1') return new Cvss3P1(vector)
    if (version === '3.0') return new Cvss3P0(vector)
    return new Cvss2(vector)
}

export function createCvssInstance(
    vector: string,
    fallbackVersion: CvssVersion = '3.1',
): { version: CvssVersion; instance: CvssInstanceLike } {
    const normalizedVector = vector.trim()
    const version = detectCvssVersion(normalizedVector) ?? fallbackVersion

    if (detectCvssVersion(normalizedVector)) {
        try {
            if (version === '4.0') return { version, instance: new Cvss4P0(normalizedVector) }
            if (version === '3.1') return { version, instance: new Cvss3P1(normalizedVector) }
            if (version === '3.0') return { version, instance: new Cvss3P0(normalizedVector) }
            return { version, instance: new Cvss2(normalizedVector) }
        } catch {
            // Use a valid empty vector for the detected version.
        }
    }

    return { version, instance: createDefaultCvssInstance(version) }
}

export function cvssVersionsForVector(vector: string): CvssVersion[] {
    const detected = detectCvssVersion(vector)
    return detected ? [detected] : [...CVSS_VERSIONS]
}

/**
 * Calculates a CVSS score from a vector string.
 * Supports CVSS v2, v3.0, v3.1, and v4.0.
 */
export function calculateScoreFromVector(vector: string): number | null {
    if (!vector || vector.trim().length <= 5) return null

    try {
        let v = vector.trim()
        let score: number | null = null

        if (v.startsWith('CVSS:4.0')) {
            const cvss = new Cvss4P0(v)
            const s = cvss.calculateScores()
            score = s.overall ?? null
        } else if (v.startsWith('CVSS:3.0')) {
            const cvss = new Cvss3P0(v)
            const s = cvss.calculateScores(false)
            score = s.overall ?? s.base ?? null
        } else if (v.startsWith('CVSS:3.')) {
            const cvss = new Cvss3P1(v)
            const s = cvss.calculateScores(false)
            score = s.overall ?? s.base ?? null
        } else {
            // Try CVSS v2
            const cvss = new Cvss2(v)
            const s = cvss.calculateScores()
            score = s.overall ?? s.base ?? null
        }

        if (score !== null && !isNaN(score)) {
            return parseFloat(score.toFixed(1))
        }
    } catch (e) {
        // Invalid vector
    }

    return null
}

export function scoreToSeverity(score: number): string {
    if (score >= 9) return 'CRITICAL'
    if (score >= 7) return 'HIGH'
    if (score >= 4) return 'MEDIUM'
    if (score >= 0.1) return 'LOW'
    return 'INFO'
}
