// The River logo: the triple tilde. The canonical files are in data/
// (river-mark.svg, river-wordmark.svg); the Docker image copies the icon for the
// frontend build.
import markIconUrl from '../../../data/river-mark.svg'

export { markIconUrl }

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
