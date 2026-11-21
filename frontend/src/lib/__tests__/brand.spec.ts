import { describe, expect, it } from 'vitest'
import { applyFavicon, radarIconUrl } from '../brand'

describe('brand', () => {
    it('points the page icon at the DTVP radar', () => {
        document.head.innerHTML = '<link rel="icon" href="data:," />'
        applyFavicon()
        const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')!
        // Small enough for Vite to embed in the bundle.
        expect(radarIconUrl).toMatch(/^data:image\/svg\+xml|dtvp-lucide-radar/)
        expect(link.getAttribute('href')).toBe(radarIconUrl)
        expect(link.type).toBe('image/svg+xml')
    })

    it('adds the icon link when the page has none', () => {
        document.head.innerHTML = ''
        applyFavicon()
        expect(document.querySelectorAll('link[rel="icon"]')).toHaveLength(1)
    })
})
