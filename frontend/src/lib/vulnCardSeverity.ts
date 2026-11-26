import type { GroupedVuln } from '../types'
import { calculateScoreFromVector } from './cvss'

export const savedRescoredScore = (group: GroupedVuln) =>
    group.rescored_cvss ?? (group.rescored_vector ? calculateScoreFromVector(group.rescored_vector) : null)

const severityColours: Record<string, { text: string; tint?: string }> = {
    CRITICAL: { text: 'text-red-300', tint: '0.028 25' },
    HIGH: { text: 'text-orange-300', tint: '0.025 55' },
    MEDIUM: { text: 'text-amber-300', tint: '0.024 88' },
    LOW: { text: 'text-blue-300', tint: '0.044 242' },
    INFO: { text: 'text-slate-300' },
}

export const severityTextColour = (severity: string | null) =>
    severityColours[severity || '']?.text || 'text-gray-400'

export const cardSeverityTint = (original: string, rescored: string | null) => {
    const tint = severityColours[rescored || original]?.tint
    // Keep the card's perceptual lightness while changing its chroma and hue.
    return tint ? `oklch(from var(--color-gray-800) l ${tint})` : undefined
}
