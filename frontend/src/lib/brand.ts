// The DTVP logo. The canonical files are in data/ (dtvp-lucide-radar.svg,
// dtvp-wordmark.svg); the Docker image copies the icon for the frontend build.
import radarIconUrl from '../../../data/dtvp-lucide-radar.svg'

export { radarIconUrl }

/** Point the page's icon at the DTVP radar. */
export const applyFavicon = (doc: Document = document) => {
    let link = doc.querySelector<HTMLLinkElement>('link[rel="icon"]')
    if (!link) {
        link = doc.createElement('link')
        link.rel = 'icon'
        doc.head.appendChild(link)
    }
    link.type = 'image/svg+xml'
    link.href = radarIconUrl
}
