import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

// The project toolbar's popups (Filter, Gone findings, CycloneDX, Archive)
// must open over the assessment cards, whose sticky header bars come later
// in the page. Stacking is decided by the z-index classes, so compare them.
const source = (path: string) => readFileSync(resolve(__dirname, path), 'utf8')
// The z-index class of the element whose opening tag carries ``marker``.
const zOf = (markup: string, marker: string) => {
    const at = markup.indexOf(marker)
    const tag = markup.slice(markup.lastIndexOf('<', at), markup.indexOf('>', at))
    return Number(/\bz-(\d+)\b/.exec(tag)?.[1])
}

describe('project toolbar layering', () => {
    it('stacks the toolbar above the cards\' sticky header bars and below full-screen dialogs', () => {
        const toolbar = zOf(source('../ProjectView.vue'), 'data-testid="project-toolbar"')
        const cardBar = zOf(source('../../components/VulnGroupCard.vue'), 'data-vuln-card-sticky-nav')

        expect(toolbar).toBeGreaterThan(cardBar)
        expect(toolbar).toBeLessThan(60)
    })
})
