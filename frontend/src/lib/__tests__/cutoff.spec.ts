import { describe, expect, it } from 'vitest'
import {
    cutoffDate,
    cutoffEndMs,
    cutoffLabel,
    cutoffMatch,
    findingCutoffDate,
    normalizeCutoffBasis,
    isAfterCutoff,
    legacyCutoff,
    normalizeCutoff,
    normalizeCutoffMode,
} from '../cutoff'

const NOW = Date.UTC(2026, 10, 25, 15)
const day = (text: string) => Date.parse(`${text}T12:00:00Z`)

describe('cutoff', () => {
    it('accepts a date or a number of days and nothing else', () => {
        expect(normalizeCutoff(' 2026-03-01 ')).toBe('2026-03-01')
        expect(normalizeCutoff('030D')).toBe('30d')
        for (const bad of ['2026-02-30', 'soon', '-3d', '2026/03/01', '']) expect(normalizeCutoff(bad)).toBe('')
        expect(normalizeCutoffMode('AFTER')).toBe('after')
        expect(normalizeCutoffMode('later')).toBe('before')
    })

    it('reads the retired attribution-age parameters as a relative cutoff', () => {
        expect(legacyCutoff('14', 'younger')).toEqual({ cutoff: '14d', cutoffMode: 'after', cutoffBasis: 'attributed' })
        expect(legacyCutoff(30, 'older')).toEqual({ cutoff: '30d', cutoffMode: 'before', cutoffBasis: 'attributed' })
        expect(legacyCutoff('x', 'older')).toBeNull()
    })

    it('includes the whole cutoff day, in UTC', () => {
        expect(cutoffDate('3d', NOW)).toBe('2026-11-22')
        expect(cutoffEndMs('2026-11-22')).toBe(Date.UTC(2026, 10, 23))
        expect(cutoffEndMs('3d', NOW)).toBe(Date.UTC(2026, 10, 23))
        expect(isAfterCutoff(day('2026-11-22'), '2026-11-22')).toBe(false)
        expect(isAfterCutoff(day('2026-11-23'), '2026-11-22')).toBe(true)
        expect(isAfterCutoff(null, '2026-11-22')).toBe(false)
        expect(cutoffLabel('2026-03-01', 'before')).toBe('Published by 2026-03-01')
        expect(cutoffLabel('2026-03-01', 'after', 'attributed')).toBe('First attributed after 2026-03-01')
        expect(cutoffLabel('7d', 'after')).toBe('Published after 7 days ago')
        expect(findingCutoffDate({ published_ms: 1, first_seen_ms: 2 }, 'published')).toBe(1)
        expect(findingCutoffDate({ published_ms: 1, first_seen_ms: 2 }, 'attributed')).toBe(2)
        expect(findingCutoffDate({}, 'published')).toBeNull()
        expect(normalizeCutoffBasis('ATTRIBUTED')).toBe('attributed')
        expect(normalizeCutoffBasis('attributed_version')).toBe('published')
    })

    it('lists a vulnerability with a finding in scope on the right side, or one without a date', () => {
        const byVersion = { '7.1.0': [day('2026-01-10'), day('2026-01-10')], '7.1.1': [day('2026-06-01'), day('2026-06-01')] }
        expect(cutoffMatch(byVersion, [], '2026-03-01', 'before')).toBe('known')
        expect(cutoffMatch(byVersion, [], '2026-03-01', 'before', ['7.1.1'])).toBeNull()
        expect(cutoffMatch(byVersion, ['7.1.1'], '2026-03-01', 'before', ['7.1.1'])).toBe('unknown')
        expect(cutoffMatch(byVersion, [], '2026-03-01', 'after')).toBe('known')
        expect(cutoffMatch(byVersion, [], '2026-07-01', 'after')).toBeNull()
        expect(cutoffMatch(byVersion, [], '', 'before')).toBe('known')
    })
})
