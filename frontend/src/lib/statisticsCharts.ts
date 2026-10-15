export interface ChartSegment {
    label: string
    value: number
    color: string
}

export const SEVERITY_CHART_COLORS: Record<string, string> = {
    CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308',
    LOW: '#22c55e', INFO: '#3b82f6', UNKNOWN: '#6b7280',
}

export const ANALYSIS_CHART_COLORS: Record<string, string> = {
    EXPLOITABLE: '#ef4444', IN_TRIAGE: '#fbbf24', FALSE_POSITIVE: '#6b7280',
    NOT_AFFECTED: '#16a34a', RESOLVED: '#3b82f6', NOT_SET: '#a855f7', MIXED: '#fb923c',
}

export function distributionSegments(
    counts: Record<string, number>, colors: Record<string, string>,
): ChartSegment[] {
    const keys = [...new Set([...Object.keys(colors), ...Object.keys(counts)])]
    return keys.map(label => ({ label: label.replaceAll('_', ' '), value: counts[label] || 0, color: colors[label] || '#6b7280' }))
}
