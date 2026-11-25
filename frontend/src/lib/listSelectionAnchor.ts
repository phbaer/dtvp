/**
 * Keeps the vulnerability list steady across a refresh.
 *
 * Before the list is refreshed, the anchor records the selected row (or,
 * without a selection, the first visible row), the rows after and before it
 * in the visible order, and how far the row is from the top of the list
 * viewport. After the refresh the same row is kept when it is still listed;
 * otherwise the nearest following row that is still listed takes its place,
 * else the nearest preceding one. The chosen row goes back to the same
 * distance from the top, so a reviewer approving through a list that the
 * approval leaves goes from item to item without scrolling.
 */
export interface ListAnchor {
    id: string
    /** The anchor is the selected row (true) or only the first visible one. */
    selected: boolean
    /** Rows after the anchor, nearest first. */
    next: string[]
    /** Rows before the anchor, nearest first. */
    previous: string[]
    /** Distance of the row's top from the top of the list viewport, in px. */
    offset: number | null
}

export type AnchorResolution =
    | { id: string; reason: 'kept' | 'next' | 'previous' }
    | { id: null; reason: 'empty' | 'none' }

/** How many neighbours on each side are remembered. */
export const ANCHOR_NEIGHBOURS = 25

export function captureListAnchor(
    ids: readonly string[],
    anchorId: string | null,
    options: { selected: boolean; offset: number | null; neighbours?: number },
): ListAnchor | null {
    if (!anchorId) return null
    const index = ids.indexOf(anchorId)
    const span = options.neighbours ?? ANCHOR_NEIGHBOURS
    return {
        id: anchorId,
        selected: options.selected,
        next: index < 0 ? [] : ids.slice(index + 1, index + 1 + span),
        previous: index < 0 ? [] : ids.slice(Math.max(0, index - span), index).reverse(),
        offset: options.offset,
    }
}

export function resolveListAnchor(
    anchor: ListAnchor,
    ids: readonly string[],
): AnchorResolution {
    if (ids.length === 0) return { id: null, reason: 'empty' }
    const present = new Set(ids)
    if (present.has(anchor.id)) return { id: anchor.id, reason: 'kept' }
    const next = anchor.next.find(id => present.has(id))
    if (next) return { id: next, reason: 'next' }
    const previous = anchor.previous.find(id => present.has(id))
    if (previous) return { id: previous, reason: 'previous' }
    return { id: null, reason: 'none' }
}

/**
 * The scrollTop that puts the row at ``index`` at ``offset`` from the top,
 * when its rendered position is unknown (estimated row height).
 */
export const estimatedScrollTop = (index: number, offset: number, rowHeight: number) =>
    Math.max(0, index * rowHeight - offset)
