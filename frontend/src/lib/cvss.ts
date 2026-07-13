import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

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
