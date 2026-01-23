import { Cvss2, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

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
