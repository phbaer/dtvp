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

const BLOCK_TAGS = new Set(['P', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'LI', 'TR', 'PRE', 'BLOCKQUOTE', 'HR', 'BR'])

/**
 * The text of Markdown, for a summary shown as plain text: rendered through
 * the same allow-list as renderSafeMarkdown, then reduced to its text, one
 * line per block. Never returns markup; callers interpolate it as text.
 */
export const markdownToPlainText = (markdown: string): string => {
    const template = document.createElement('template')
    template.innerHTML = renderSafeMarkdown(markdown)
    // Line breaks inside a block are soft: only blocks start a new line.
    const walker = document.createTreeWalker(template.content, NodeFilter.SHOW_TEXT)
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        node.textContent = (node.textContent || '').replace(/\s+/g, ' ')
    }
    for (const element of Array.from(template.content.querySelectorAll('*'))) {
        if (BLOCK_TAGS.has(element.tagName)) element.after('\n')
    }
    return (template.content.textContent || '')
        .split('\n')
        .map(line => line.replace(/\s+/g, ' ').trim())
        .filter(Boolean)
        .join('\n')
}
