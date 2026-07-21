import DOMPurify from 'dompurify'
import { marked } from 'marked'

const MARKDOWN_TAGS = [
  'a',
  'blockquote',
  'br',
  'code',
  'del',
  'em',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'hr',
  'li',
  'ol',
  'p',
  'pre',
  'strong',
  'table',
  'tbody',
  'td',
  'th',
  'thead',
  'tr',
  'ul',
]

export const sanitizeHtml = (html: string): string => DOMPurify.sanitize(html, {
  ALLOWED_TAGS: MARKDOWN_TAGS,
  ALLOWED_ATTR: ['class', 'href', 'title'],
  ALLOW_DATA_ATTR: false,
  ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto):|[#/])/i,
})

export const renderSafeMarkdown = (markdown: string, fallback = ''): string => {
  const source = markdown.trim() || fallback
  const rendered = marked.parse(source, { async: false }) as string
  return sanitizeHtml(rendered)
}
