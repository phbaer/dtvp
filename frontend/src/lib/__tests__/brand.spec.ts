import { describe, expect, it } from 'vitest'
import { applyFavicon, markIconUrl } from '../brand'

describe('brand', () => {
    it('points the page icon at the River mark', () => {
        document.head.innerHTML = '<link rel="icon" href="data:," />'
        applyFavicon()
        const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')!
        // Small enough for Vite to embed in the bundle.
        expect(markIconUrl).toMatch(/^data:image\/svg\+xml|river-mark/)
        expect(link.getAttribute('href')).toBe(markIconUrl)
        expect(link.type).toBe('image/svg+xml')
    })

    it('adds the icon link when the page has none', () => {
        document.head.innerHTML = ''
        applyFavicon()
        expect(document.querySelectorAll('link[rel="icon"]')).toHaveLength(1)
    })
})
