// The River logo: the triple tilde. The canonical files are in data/
// (standalone mark, full wordmark, inline wordmark); Docker copies all three
// for the frontend build.
import markIconUrl from '../../../data/river-mark.svg'
import wordmarkUrl from '../../../data/river-wordmark.svg'
import inlineWordmarkUrl from '../../../data/river-wordmark-inline.svg'

export { markIconUrl, wordmarkUrl, inlineWordmarkUrl }

/** Point the page's icon at the River mark. */
export const applyFavicon = (doc: Document = document) => {
    let link = doc.querySelector<HTMLLinkElement>('link[rel="icon"]')
    if (!link) {
        link = doc.createElement('link')
        link.rel = 'icon'
        doc.head.appendChild(link)
    }
    link.type = 'image/svg+xml'
    link.href = markIconUrl
}
