import { describe, expect, it } from 'vitest'
import {
    buildSearchCompletionOptions,
    createSearchCompletionOption,
    getSearchCompletionMatches,
} from '../searchCompletions'

describe('searchCompletions', () => {
    it('builds unique sorted options with precomputed lowercase fields', () => {
        const options = buildSearchCompletionOptions(['zeta', 'Alpha', '', 'alpha'], 'ID')

        expect(options.map(option => option.value)).toEqual(['Alpha', 'alpha', 'zeta'])
        expect(options[0]).toMatchObject({
            value: 'Alpha',
            label: 'Alpha',
            detail: 'ID',
            valueLower: 'alpha',
            labelLower: 'alpha',
        })
    })

    it('returns bounded matches with prefix matches before contains matches', () => {
        const options = [
            createSearchCompletionOption('alpha', 'Alpha', 'ID'),
            createSearchCompletionOption('apricot', 'Apricot', 'ID'),
            createSearchCompletionOption('grape', 'Grape', 'ID'),
            createSearchCompletionOption('pineapple', 'Pineapple', 'ID'),
        ]

        expect(getSearchCompletionMatches(options, 'ap', 3).map(option => option.value)).toEqual([
            'apricot',
            'grape',
            'pineapple',
        ])
    })

    it('returns the first options for empty queries and respects non-positive limits', () => {
        const options = [
            createSearchCompletionOption('one', 'One', 'ID'),
            createSearchCompletionOption('two', 'Two', 'ID'),
        ]

        expect(getSearchCompletionMatches(options, '', 1).map(option => option.value)).toEqual(['one'])
        expect(getSearchCompletionMatches(options, 'o', 0)).toEqual([])
    })
})
