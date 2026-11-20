import { describe, expect, it } from 'vitest'
import { renderSafeMarkdown, safeLinkUrl } from '../safeMarkdown'

const render = (markdown: string) => {
    const host = document.createElement('div')
    host.innerHTML = renderSafeMarkdown(markdown)
    return host
}

describe('safe Markdown', () => {
    it('removes scripts, images, frames and raw HTML handlers', () => {
        const html = render('Text<script>alert(1)</script><img src=x onerror=alert(1)><iframe src="https://x"></iframe><b onclick="x()">bold</b>')
        expect(html.querySelector('script,img,iframe,b')).toBeNull()
        expect(html.querySelector('[onclick],[onerror]')).toBeNull()
        expect(html.textContent).toContain('Text')
    })

    it('links only http(s) URLs without credentials', () => {
        const html = render([
            '[ok](https://example.org/a)',
            '[js](javascript:alert(1))',
            '[data](data:text/html;base64,PHNjcmlwdD4=)',
            '[creds](https://user:secret@example.org/)',
            '[mail](mailto:a@example.org)',
        ].join(' '))
        // Unsafe links stay as text: the element keeps no href.
        const links = [...html.querySelectorAll('a[href]')]
        expect(links.map(link => link.getAttribute('href'))).toEqual(['https://example.org/a'])
        expect(html.querySelectorAll('a:not([href])')).toHaveLength(4)
        expect(links[0].getAttribute('rel')).toBe('noopener noreferrer')
        expect(links[0].getAttribute('target')).toBe('_blank')
        expect(html.textContent).toContain('js')
        expect(safeLinkUrl('javascript:alert(1)')).toBeNull()
        expect(safeLinkUrl('https://user:pw@example.org')).toBeNull()
        expect(safeLinkUrl('http://example.org/x')).toBe('http://example.org/x')
    })

    it('keeps tables, code and lists', () => {
        const html = render('| a | b |\n|---|---|\n| 1 | 2 |\n\n```\ncode()\n```\n\n- item\n\n`inline`')
        expect(html.querySelector('table td')?.textContent).toBe('1')
        expect(html.querySelector('pre code')?.textContent).toContain('code()')
        expect(html.querySelector('ul li')?.textContent).toBe('item')
        expect(html.querySelector('p code')?.textContent).toBe('inline')
    })
})
