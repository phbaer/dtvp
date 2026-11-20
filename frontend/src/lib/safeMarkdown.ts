import { marked } from 'marked'

/**
 * Renders Markdown to HTML through an allow-list: anything not listed is
 * removed with its content, every attribute is dropped, and links survive
 * only as plain http(s) URLs without credentials. Used for analyzer reports
 * and for code evidence written by agents, both untrusted text.
 */
const ALLOWED_TAGS = new Set([
    'P', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'UL', 'OL', 'LI', 'TABLE', 'THEAD',
    'TBODY', 'TR', 'TH', 'TD', 'STRONG', 'EM', 'CODE', 'PRE', 'BLOCKQUOTE', 'HR',
    'BR', 'A', 'DEL',
])

/** The URL when it is safe to link: http(s) and no user name or password. */
export const safeLinkUrl = (value: string | null | undefined): string | null => {
    if (!value) return null
    try {
        const url = new URL(value)
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null
        return url.href
    } catch {
        return null
    }
}

export const renderSafeMarkdown = (markdown: string): string => {
    const template = document.createElement('template')
    template.innerHTML = marked.parse(String(markdown || ''), { async: false }) as string
    for (const element of Array.from(template.content.querySelectorAll('*'))) {
        if (!ALLOWED_TAGS.has(element.tagName)) {
            element.remove()
            continue
        }
        const href = element.tagName === 'A' ? element.getAttribute('href') : null
        for (const attribute of Array.from(element.attributes)) element.removeAttribute(attribute.name)
        const safe = safeLinkUrl(href)
        if (safe) {
            element.setAttribute('href', safe)
            element.setAttribute('target', '_blank')
            element.setAttribute('rel', 'noopener noreferrer')
        }
        // Unsafe or unsupported links remain plain text.
    }
    return template.innerHTML
}
