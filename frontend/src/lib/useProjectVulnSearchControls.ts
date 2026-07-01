import { computed, nextTick, ref, watch, type ComponentPublicInstance, type ComputedRef, type Ref } from 'vue'
import type { VulnListFacets } from './vulnListFacets'
import type { ParsedVulnSearchQuery } from './vulnListIndex'
import type { ProjectVulnFilterOption } from './projectVulnFilterChips'
import {
    buildSearchCompletionOptions,
    createSearchCompletionOption,
    getSearchCompletionMatches,
    type SearchCompletionOption,
} from './searchCompletions'

export const SEARCH_TOKEN_SHORTCUTS = [
    { label: 'CVE', value: 'cve:' },
    { label: 'Component', value: 'component:' },
    { label: 'Team', value: 'team:' },
    { label: 'Assignee', value: 'assignee:' },
    { label: 'Version', value: 'version:' },
] as const

export interface SearchCompletionToken {
    prefix: string
    typedPrefix: string
    value: string
    start: number
    end: number
}

interface UseProjectVulnSearchControlsOptions {
    smartSearchInput: Ref<string>
    liveParsedSmartSearch: ComputedRef<ParsedVulnSearchQuery>
    flushSmartSearchFilter: () => void
    facets: ComputedRef<VulnListFacets>
    lifecycleOptions: readonly ProjectVulnFilterOption[]
    analysisOptions: readonly ProjectVulnFilterOption[]
    dependencyOptions: readonly ProjectVulnFilterOption[]
}

export const quoteSearchValue = (value: string) => {
    if (!/\s/.test(value)) return value
    return `"${value.replace(/"/g, '\\"')}"`
}

export const formatSearchChipRaw = (raw: string) => {
    const separatorIndex = raw.indexOf(':')
    if (separatorIndex > 0) {
        const prefix = raw.slice(0, separatorIndex)
        const value = raw.slice(separatorIndex + 1)
        return /\s/.test(value) ? `${prefix}:${quoteSearchValue(value)}` : raw
    }
    return raw.includes(' ') ? quoteSearchValue(raw) : raw
}

export const buildProjectVulnSearchCompletionOptions = ({
    facets,
    lifecycleOptions,
    analysisOptions,
    dependencyOptions,
}: {
    facets: VulnListFacets
    lifecycleOptions: readonly ProjectVulnFilterOption[]
    analysisOptions: readonly ProjectVulnFilterOption[]
    dependencyOptions: readonly ProjectVulnFilterOption[]
}): Record<string, SearchCompletionOption[]> => {
    const idOptions = buildSearchCompletionOptions(facets.ids, 'ID')
    const componentOptions = buildSearchCompletionOptions(facets.components, 'Component')
    const teamOptions = buildSearchCompletionOptions(facets.teams, 'Team')
    const assigneeOptions = buildSearchCompletionOptions(facets.assignees, 'Assignee')
    const versionOptions = buildSearchCompletionOptions(facets.availableVersions, 'Version')
    const lifecycleCompletionOptions = lifecycleOptions.map(option =>
        createSearchCompletionOption(option.value.toLowerCase(), option.label, 'Lifecycle'),
    )
    const analysisCompletionOptions = analysisOptions.map(option =>
        createSearchCompletionOption(option.value.toLowerCase(), option.label, 'State'),
    )
    const dependencyCompletionOptions = dependencyOptions.map(option =>
        createSearchCompletionOption(option.value.toLowerCase(), option.label, 'Dependency'),
    )
    const tmrescoreOptions = [
        createSearchCompletionOption('with', 'With proposal', 'TM'),
        createSearchCompletionOption('without', 'Without proposal', 'TM'),
    ]
    const hasOptions = [
        createSearchCompletionOption('tmrescore', 'TM proposal', 'Has'),
        createSearchCompletionOption('no_tmrescore', 'No TM proposal', 'Has'),
        createSearchCompletionOption('cvss_mismatch', 'CVSS mismatch', 'Has'),
    ]
    const cvssOptions = [
        createSearchCompletionOption('mismatch', 'Mismatch', 'CVSS'),
    ]

    return {
        id: idOptions,
        cve: idOptions,
        alias: idOptions,
        vuln: idOptions,
        component: componentOptions,
        comp: componentOptions,
        pkg: componentOptions,
        package: componentOptions,
        team: teamOptions,
        tag: teamOptions,
        assignee: assigneeOptions,
        assigned: assigneeOptions,
        owner: assigneeOptions,
        version: versionOptions,
        ver: versionOptions,
        v: versionOptions,
        lifecycle: lifecycleCompletionOptions,
        analysis: analysisCompletionOptions,
        state: [...lifecycleCompletionOptions, ...analysisCompletionOptions],
        dep: dependencyCompletionOptions,
        dependency: dependencyCompletionOptions,
        tm: tmrescoreOptions,
        tmrescore: tmrescoreOptions,
        proposal: tmrescoreOptions,
        has: hasOptions,
        cvss: cvssOptions,
    }
}

export function useProjectVulnSearchControls({
    smartSearchInput,
    liveParsedSmartSearch,
    flushSmartSearchFilter,
    facets,
    lifecycleOptions,
    analysisOptions,
    dependencyOptions,
}: UseProjectVulnSearchControlsOptions) {
    const showSearchTokenMenu = ref(false)
    const searchInput = ref<HTMLInputElement | null>(null)
    const searchFocused = ref(false)
    const searchCursorPosition = ref(0)
    const activeCompletionIndex = ref(0)

    const smartSearchChips = computed(() => liveParsedSmartSearch.value.chips)

    const setSearchInput = (element: Element | ComponentPublicInstance | null) => {
        searchInput.value = element as HTMLInputElement | null
    }

    const searchCompletionOptionsByPrefix = computed<Record<string, SearchCompletionOption[]>>(() =>
        buildProjectVulnSearchCompletionOptions({
            facets: facets.value,
            lifecycleOptions,
            analysisOptions,
            dependencyOptions,
        }),
    )

    const currentSearchCompletionToken = computed<SearchCompletionToken | null>(() => {
        const input = smartSearchInput.value
        const cursor = Math.min(searchCursorPosition.value, input.length)
        const beforeCursor = input.slice(0, cursor)
        const tokenMatch = beforeCursor.match(/(?:^|\s)([^\s]*)$/)
        const tokenUntilCursor = tokenMatch?.[1] || ''
        const tokenStart = cursor - tokenUntilCursor.length
        const separatorIndex = tokenUntilCursor.indexOf(':')

        if (separatorIndex <= 0) return null

        const typedPrefix = tokenUntilCursor.slice(0, separatorIndex)
        const prefix = typedPrefix.toLowerCase()
        if (!searchCompletionOptionsByPrefix.value[prefix]) return null

        const rawValue = tokenUntilCursor.slice(separatorIndex + 1).replace(/^["']/, '')
        const afterCursor = input.slice(cursor)
        const tokenEndOffset = afterCursor.search(/\s/)
        const tokenEnd = tokenEndOffset === -1 ? input.length : cursor + tokenEndOffset

        return {
            prefix,
            typedPrefix,
            value: rawValue.toLowerCase(),
            start: tokenStart,
            end: tokenEnd,
        }
    })

    const currentSearchCompletions = computed(() => {
        const token = currentSearchCompletionToken.value
        if (!token) return []

        const query = token.value
        const options = searchCompletionOptionsByPrefix.value[token.prefix] || []

        return getSearchCompletionMatches(options, query, 8)
    })

    const showSearchCompletions = computed(() =>
        searchFocused.value
        && !!currentSearchCompletionToken.value
        && currentSearchCompletions.value.length > 0
    )

    const updateSearchCursorPosition = (event?: Event) => {
        const target = event?.target as HTMLInputElement | null
        searchCursorPosition.value = target?.selectionStart
            ?? searchInput.value?.selectionStart
            ?? smartSearchInput.value.length
    }

    const handleSearchFocus = (event: FocusEvent) => {
        searchFocused.value = true
        updateSearchCursorPosition(event)
    }

    const handleSearchBlur = () => {
        setTimeout(() => {
            searchFocused.value = false
        }, 120)
    }

    const selectSearchCompletion = async (completion: SearchCompletionOption) => {
        const token = currentSearchCompletionToken.value
        if (!token) return

        const before = smartSearchInput.value.slice(0, token.start)
        const after = smartSearchInput.value.slice(token.end).replace(/^\s+/, '')
        const replacement = `${token.typedPrefix}:${quoteSearchValue(completion.value)}`
        smartSearchInput.value = `${before}${replacement}${after ? ` ${after}` : ' '}`
        flushSmartSearchFilter()

        const cursor = `${before}${replacement} `.length
        searchCursorPosition.value = cursor
        activeCompletionIndex.value = 0
        await nextTick()
        searchInput.value?.focus()
        searchInput.value?.setSelectionRange(cursor, cursor)
    }

    const handleSearchKeydown = (event: KeyboardEvent) => {
        if (!showSearchCompletions.value) {
            return
        }

        if (event.key === 'ArrowDown') {
            event.preventDefault()
            activeCompletionIndex.value = (activeCompletionIndex.value + 1) % currentSearchCompletions.value.length
        } else if (event.key === 'ArrowUp') {
            event.preventDefault()
            activeCompletionIndex.value = (activeCompletionIndex.value - 1 + currentSearchCompletions.value.length) % currentSearchCompletions.value.length
        } else if (event.key === 'Enter' || event.key === 'Tab') {
            const selected = currentSearchCompletions.value[activeCompletionIndex.value]
            if (selected) {
                event.preventDefault()
                void selectSearchCompletion(selected)
            }
        }
    }

    const appendSearchToken = async (token: string) => {
        const current = smartSearchInput.value.trim()
        const hasToken = !token.endsWith(':') && current.split(/\s+/).filter(Boolean).includes(token)
        smartSearchInput.value = hasToken ? current : `${current}${current && !hasToken ? ' ' : ''}${hasToken ? '' : token}`.trim()
        showSearchTokenMenu.value = false
        await nextTick()
        searchInput.value?.focus()

        if (token.endsWith(':')) {
            const end = smartSearchInput.value.length
            searchCursorPosition.value = end
            searchInput.value?.setSelectionRange(end, end)
        }
    }

    const removeSmartSearchChip = (indexToRemove: number) => {
        smartSearchInput.value = smartSearchChips.value
            .filter((_, index) => index !== indexToRemove)
            .map(chip => formatSearchChipRaw(chip.raw))
            .join(' ')
        flushSmartSearchFilter()
    }

    const clearSmartSearch = () => {
        smartSearchInput.value = ''
        flushSmartSearchFilter()
        searchCursorPosition.value = 0
    }

    watch(() => `${currentSearchCompletionToken.value?.prefix || ''}:${currentSearchCompletionToken.value?.value || ''}`, () => {
        activeCompletionIndex.value = 0
    })

    return {
        showSearchTokenMenu,
        searchInput,
        setSearchInput,
        searchFocused,
        searchCursorPosition,
        activeCompletionIndex,
        smartSearchChips,
        currentSearchCompletionToken,
        currentSearchCompletions,
        showSearchCompletions,
        updateSearchCursorPosition,
        handleSearchFocus,
        handleSearchBlur,
        handleSearchKeydown,
        selectSearchCompletion,
        appendSearchToken,
        removeSmartSearchChip,
        clearSmartSearch,
    }
}
