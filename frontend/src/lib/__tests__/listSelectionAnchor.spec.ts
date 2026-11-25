import { describe, expect, it } from 'vitest'
import { captureListAnchor, estimatedScrollTop, resolveListAnchor } from '../listSelectionAnchor'

const ids = ['A', 'B', 'C', 'D', 'E']
const anchorOn = (id: string, neighbours?: number) =>
    captureListAnchor(ids, id, { selected: true, offset: 120, neighbours })!

describe('list selection anchor', () => {
    it('remembers the neighbours in visible order, nearest first', () => {
        expect(anchorOn('C')).toEqual({
            id: 'C', selected: true, next: ['D', 'E'], previous: ['B', 'A'], offset: 120,
        })
        expect(anchorOn('C', 1)).toMatchObject({ next: ['D'], previous: ['B'] })
        expect(captureListAnchor(ids, null, { selected: false, offset: 0 })).toBeNull()
    })

    it('keeps the item when it is still listed, even when it moved', () => {
        expect(resolveListAnchor(anchorOn('C'), ['C', 'A', 'B', 'D', 'E'])).toEqual({ id: 'C', reason: 'kept' })
    })

    it('selects the next item when the item left the list', () => {
        expect(resolveListAnchor(anchorOn('C'), ['A', 'B', 'D', 'E'])).toEqual({ id: 'D', reason: 'next' })
    })

    it('selects the previous item when the last item left the list', () => {
        expect(resolveListAnchor(anchorOn('E'), ['A', 'B', 'C', 'D'])).toEqual({ id: 'D', reason: 'previous' })
    })

    it('skips a neighbour that is gone as well', () => {
        expect(resolveListAnchor(anchorOn('B'), ['A', 'D', 'E'])).toEqual({ id: 'D', reason: 'next' })
        expect(resolveListAnchor(anchorOn('D'), ['A', 'B'])).toEqual({ id: 'B', reason: 'previous' })
    })

    it('selects nothing when the list became empty or no neighbour is left', () => {
        expect(resolveListAnchor(anchorOn('C'), [])).toEqual({ id: null, reason: 'empty' })
        expect(resolveListAnchor(anchorOn('C'), ['X', 'Y'])).toEqual({ id: null, reason: 'none' })
    })

    it('estimates a scroll position for a row that is not rendered', () => {
        expect(estimatedScrollTop(10, 120, 88)).toBe(760)
        expect(estimatedScrollTop(0, 120, 88)).toBe(0)
    })
})

describe('evidence flags of a lookup', () => {
    it('match the flags the server gives a listed vulnerability', async () => {
        const { evidenceSourcesFromLookup, groupCves } = await import('../evidence')
        expect(evidenceSourcesFromLookup([
            { source: 'CISA KEV', status: 'ok', value: 'A' },
            { source: 'CISA Vulnrichment', status: 'ok', value: 'P' },
        ])).toEqual(['KEV', 'CISA_SSVC'])
        expect(evidenceSourcesFromLookup([
            { source: 'CISA KEV', status: 'not_found' },
            { source: 'CISA Vulnrichment', status: 'not_found' },
        ])).toEqual(['NO_DATA'])
        expect(evidenceSourcesFromLookup([
            { source: 'CISA KEV', status: 'unavailable' },
            { source: 'CISA Vulnrichment', status: 'stale', error: 'timeout' },
        ])).toEqual(['NOT_CHECKED', 'STALE', 'UNAVAILABLE'])
        expect(groupCves({ id: 'cve-2026-1', aliases: ['GHSA-xxxx', 'CVE-2025-0002'] }))
            .toEqual(['CVE-2025-0002'])
        expect(groupCves({ id: 'CVE-2026-1234', aliases: ['GHSA-x'] })).toEqual(['CVE-2026-1234'])
    })
})
