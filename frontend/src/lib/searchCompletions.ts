export interface SearchCompletionOption {
    value: string
    label: string
    detail: string
    valueLower: string
    labelLower: string
}

const cleanCompletionValue = (value: unknown) => String(value || '').trim()

const sortCompletionValues = (values: string[]) =>
    values.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }))

export const createSearchCompletionOption = (
    value: string,
    label: string,
    detail: string,
): SearchCompletionOption => ({
    value,
    label,
    detail,
    valueLower: value.toLowerCase(),
    labelLower: label.toLowerCase(),
})

export const buildSearchCompletionOptions = (
    values: readonly unknown[],
    detail: string,
    labelForValue: (value: string) => string = value => value,
): SearchCompletionOption[] => {
    return sortCompletionValues(Array.from(new Set(values.map(cleanCompletionValue).filter(Boolean))))
        .map(value => createSearchCompletionOption(value, labelForValue(value), detail))
}

const matchesCompletionQuery = (option: SearchCompletionOption, query: string) =>
    option.valueLower.includes(query) || option.labelLower.includes(query)

const startsWithCompletionQuery = (option: SearchCompletionOption, query: string) =>
    option.valueLower.startsWith(query) || option.labelLower.startsWith(query)

export const getSearchCompletionMatches = (
    options: readonly SearchCompletionOption[],
    query: string,
    limit = 8,
): SearchCompletionOption[] => {
    if (limit <= 0) return []

    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return options.slice(0, limit)

    const matches: SearchCompletionOption[] = []
    const seen = new Set<SearchCompletionOption>()

    for (const option of options) {
        if (!startsWithCompletionQuery(option, normalizedQuery)) continue
        matches.push(option)
        seen.add(option)
        if (matches.length >= limit) return matches
    }

    for (const option of options) {
        if (seen.has(option) || !matchesCompletionQuery(option, normalizedQuery)) continue
        matches.push(option)
        if (matches.length >= limit) return matches
    }

    return matches
}
