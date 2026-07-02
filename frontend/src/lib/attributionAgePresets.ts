import { getRuntimeConfig } from './env'

export const DEFAULT_ATTRIBUTION_AGE_FILTER_DAYS = [7, 14, 28]
export const ATTRIBUTION_AGE_FILTER_DAYS_CONFIG_KEY = 'DTVP_ATTRIBUTION_AGE_FILTER_DAYS'

const DEFAULT_ATTRIBUTION_AGE_FILTER_DAYS_VALUE = DEFAULT_ATTRIBUTION_AGE_FILTER_DAYS
    .map(day => `${day}d`)
    .join(',')

export const parseAttributionAgeFilterDays = (value: string): number[] => {
    const seen = new Set<number>()
    const days: number[] = []

    for (const token of value.split(',')) {
        const trimmed = token.trim().toLowerCase()
        const numericText = trimmed.endsWith('d') ? trimmed.slice(0, -1).trim() : trimmed
        if (!/^\d+$/.test(numericText)) continue

        const day = Number(numericText)
        if (!Number.isSafeInteger(day) || day < 1 || seen.has(day)) continue

        seen.add(day)
        days.push(day)
    }

    return days.length ? days : [...DEFAULT_ATTRIBUTION_AGE_FILTER_DAYS]
}

export const getAttributionAgeFilterDays = (): number[] =>
    parseAttributionAgeFilterDays(
        getRuntimeConfig(
            ATTRIBUTION_AGE_FILTER_DAYS_CONFIG_KEY,
            DEFAULT_ATTRIBUTION_AGE_FILTER_DAYS_VALUE,
        ),
    )
