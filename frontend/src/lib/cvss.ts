import { Cvss2, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

type MetricMap = Record<string, string>

function parseVectorMetrics(vector: string): MetricMap {
    const metrics: MetricMap = {}
    if (!vector) return metrics

    for (const part of vector.trim().split('/')) {
        if (!part.includes(':')) continue
        const [key, value] = part.split(':', 2)
        if (!key || !value || key === 'CVSS') continue
        metrics[key] = value
    }

    return metrics
}

function formatCvss31Vector(metrics: MetricMap): string {
    const orderedKeys = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
    return `CVSS:3.1/${orderedKeys.map(key => `${key}:${metrics[key]}`).join('/')}`
}

function mapCvss2ToCvss31(metrics: MetricMap): MetricMap | null {
    const mapped: MetricMap = {
        AV: metrics.AV,
        AC: metrics.AC === 'L' ? 'L' : 'H',
        PR: ({ N: 'N', S: 'L', M: 'H' } as Record<string, string | undefined>)[metrics.Au] || '',
        UI: 'N',
        S: 'U',
        C: ({ N: 'N', P: 'L', C: 'H' } as Record<string, string | undefined>)[metrics.C] || '',
        I: ({ N: 'N', P: 'L', C: 'H' } as Record<string, string | undefined>)[metrics.I] || '',
        A: ({ N: 'N', P: 'L', C: 'H' } as Record<string, string | undefined>)[metrics.A] || ''
    }

    return Object.values(mapped).every(Boolean) ? mapped : null
}

function mapCvss4ToCvss31(metrics: MetricMap): MetricMap | null {
    const mapped: MetricMap = {
        AV: metrics.AV || '',
        AC: metrics.AT && metrics.AT !== 'N' ? 'H' : (metrics.AC || ''),
        PR: metrics.PR || '',
        UI: ({ N: 'N', P: 'R', A: 'R' } as Record<string, string | undefined>)[metrics.UI] || metrics.UI || '',
        S: ['SC', 'SI', 'SA'].some(key => (metrics[key] || 'N') !== 'N') ? 'C' : 'U',
        C: ['VC', 'SC'].some(key => metrics[key] === 'H') ? 'H' : ['VC', 'SC'].some(key => metrics[key] === 'L') ? 'L' : 'N',
        I: ['VI', 'SI'].some(key => metrics[key] === 'H') ? 'H' : ['VI', 'SI'].some(key => metrics[key] === 'L') ? 'L' : 'N',
        A: ['VA', 'SA'].some(key => metrics[key] === 'H') ? 'H' : ['VA', 'SA'].some(key => metrics[key] === 'L') ? 'L' : 'N'
    }

    return Object.values(mapped).every(Boolean) ? mapped : null
}

export function calculateVirtualCvss31Vector(vector: string): string | null {
    if (!vector || vector.trim().length <= 5) return null

    const normalized = vector.trim()
    const metrics = parseVectorMetrics(normalized)
    if (!Object.keys(metrics).length) return null

    if (normalized.startsWith('CVSS:3.1/')) return normalized

    let mapped: MetricMap | null = null
    if (normalized.startsWith('CVSS:4.0/')) {
        mapped = mapCvss4ToCvss31(metrics)
    } else if (normalized.startsWith('CVSS:3.')) {
        mapped = {
            AV: metrics.AV || '',
            AC: metrics.AC || '',
            PR: metrics.PR || '',
            UI: metrics.UI || '',
            S: metrics.S || '',
            C: metrics.C || '',
            I: metrics.I || '',
            A: metrics.A || ''
        }
    } else {
        mapped = mapCvss2ToCvss31(metrics)
    }

    return mapped && Object.values(mapped).every(Boolean) ? formatCvss31Vector(mapped) : null
}

/**
 * Calculates a CVSS score from a vector string.
 * Supports CVSS v2, v3.x (as 3.1), and v4.0.
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
        } else if (v.startsWith('CVSS:3.')) {
            // Treat all 3.x as 3.1
            if (v.startsWith('CVSS:3.0')) v = v.replace('CVSS:3.0', 'CVSS:3.1')
            const cvss = new Cvss3P1(v)
            const s = cvss.calculateScores(false)
            score = s.overall ?? s.base ?? null
        } else {
            const virtualVector = calculateVirtualCvss31Vector(v)
            if (virtualVector) {
                const cvss = new Cvss3P1(virtualVector)
                const s = cvss.calculateScores(false)
                score = s.overall ?? s.base ?? null
            } else {
                const cvss = new Cvss2(v)
                const s = cvss.calculateScores()
                score = s.overall ?? s.base ?? null
            }
        }

        if (score !== null && !isNaN(score)) {
            return parseFloat(score.toFixed(1))
        }
    } catch (e) {
        // Invalid vector
    }

    return null
}
