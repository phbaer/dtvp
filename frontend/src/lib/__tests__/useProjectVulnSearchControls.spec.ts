import { computed, effectScope, ref } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
    buildProjectVulnSearchCompletionOptions,
    formatSearchChipRaw,
    quoteSearchValue,
    useProjectVulnSearchControls,
} from '../useProjectVulnSearchControls'
import { parseVulnSearchQuery } from '../vulnListIndex'
import type { VulnListFacets } from '../vulnListFacets'

const lifecycleOptions = [
    { value: 'OPEN', label: 'Open' },
    { value: 'ASSESSED', label: 'Assessed' },
]

const analysisOptions = [
    { value: 'NOT_SET', label: 'Not Set' },
    { value: 'RESOLVED', label: 'Resolved' },
]

const dependencyOptions = [
    { value: 'DIRECT', label: 'Direct' },
    { value: 'TRANSITIVE', label: 'Transitive' },
    { value: 'UNKNOWN', label: 'Unknown' },
]

const defaultFacets: VulnListFacets = {
    ids: ['CVE-2026-0001'],
    components: ['Spring Core', 'spring-web'],
    teams: ['Platform'],
    assignees: ['alice'],
    availableVersions: ['1.0.0'],
}

const createControls = (initialSearch = '') => {
    const scope = effectScope()
    const smartSearchInput = ref(initialSearch)
    const facets = ref(defaultFacets)
    const flushSmartSearchFilter = vi.fn()
    let controls!: ReturnType<typeof useProjectVulnSearchControls>

    scope.run(() => {
        controls = useProjectVulnSearchControls({
            smartSearchInput,
            liveParsedSmartSearch: computed(() => parseVulnSearchQuery(smartSearchInput.value)),
            flushSmartSearchFilter,
            facets: computed(() => facets.value),
            lifecycleOptions,
            analysisOptions,
            dependencyOptions,
        })
    })

    return {
        scope,
        smartSearchInput,
        facets,
        flushSmartSearchFilter,
        controls,
    }
}

describe('useProjectVulnSearchControls', () => {
    afterEach(() => {
        vi.clearAllMocks()
    })

    it('builds completion options for search-token aliases', () => {
        const options = buildProjectVulnSearchCompletionOptions({
            facets: defaultFacets,
            lifecycleOptions,
            analysisOptions,
            dependencyOptions,
        })

        expect(options.cve).toBe(options.id)
        expect(options.pkg).toBe(options.component)
        expect(options.tag).toBe(options.team)
        expect(options.state.map(option => option.detail)).toEqual(['Lifecycle', 'Lifecycle', 'State', 'State'])
        expect(options.component.map(option => option.value)).toEqual(['Spring Core', 'spring-web'])
    })

    it('matches completions from the token under the cursor and navigates them by keyboard', () => {
        const { scope, controls, smartSearchInput } = createControls('component:spr')
        controls.handleSearchFocus({
            target: { selectionStart: smartSearchInput.value.length },
        } as unknown as FocusEvent)

        expect(controls.currentSearchCompletionToken.value).toMatchObject({
            prefix: 'component',
            typedPrefix: 'component',
            value: 'spr',
        })
        expect(controls.currentSearchCompletions.value.map(option => option.value)).toEqual(['Spring Core', 'spring-web'])
        expect(controls.showSearchCompletions.value).toBe(true)

        const event = { key: 'ArrowDown', preventDefault: vi.fn() } as unknown as KeyboardEvent
        controls.handleSearchKeydown(event)

        expect(event.preventDefault).toHaveBeenCalled()
        expect(controls.activeCompletionIndex.value).toBe(1)

        scope.stop()
    })

    it('selects a completion with quoting and preserves the remaining search text', async () => {
        const { scope, controls, smartSearchInput, flushSmartSearchFilter } = createControls('component:spr team:Platform')
        controls.handleSearchFocus({
            target: { selectionStart: 'component:spr'.length },
        } as unknown as FocusEvent)

        await controls.selectSearchCompletion({
            value: 'Spring Core',
            label: 'Spring Core',
            detail: 'Component',
            valueLower: 'spring core',
            labelLower: 'spring core',
        })

        expect(smartSearchInput.value).toBe('component:"Spring Core" team:Platform')
        expect(flushSmartSearchFilter).toHaveBeenCalledTimes(1)
        expect(controls.searchCursorPosition.value).toBe('component:"Spring Core" '.length)

        scope.stop()
    })

    it('appends token shortcuts, removes chips with quoting, and clears search', async () => {
        const { scope, controls, smartSearchInput, flushSmartSearchFilter } = createControls('urgent component:"Spring Core"')

        controls.showSearchTokenMenu.value = true
        await controls.appendSearchToken('team:')

        expect(smartSearchInput.value).toBe('urgent component:"Spring Core" team:')
        expect(controls.showSearchTokenMenu.value).toBe(false)
        expect(controls.searchCursorPosition.value).toBe(smartSearchInput.value.length)

        controls.removeSmartSearchChip(0)

        expect(smartSearchInput.value).toBe('component:"Spring Core"')
        expect(flushSmartSearchFilter).toHaveBeenCalledTimes(1)

        controls.clearSmartSearch()

        expect(smartSearchInput.value).toBe('')
        expect(controls.searchCursorPosition.value).toBe(0)
        expect(flushSmartSearchFilter).toHaveBeenCalledTimes(2)

        scope.stop()
    })

    it('quotes only values that need quoting', () => {
        expect(quoteSearchValue('single')).toBe('single')
        expect(quoteSearchValue('two words')).toBe('"two words"')
        expect(formatSearchChipRaw('component:Spring Core')).toBe('component:"Spring Core"')
        expect(formatSearchChipRaw('plain text')).toBe('"plain text"')
    })
})
