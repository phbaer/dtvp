import { describe, expect, it } from 'vitest'

import { renderSafeMarkdown, sanitizeHtml } from '../sanitizeMarkdown'

describe('sanitizeMarkdown', () => {
  it('keeps ordinary markdown formatting', () => {
    const html = renderSafeMarkdown('## Advisory\n\nUse **patched** versions.')

    expect(html).toContain('<h2>Advisory</h2>')
    expect(html).toContain('<strong>patched</strong>')
  })

  it('removes active HTML and event handlers', () => {
    const html = renderSafeMarkdown(
      '<img src=x onerror=alert(1)><svg onload=alert(2)></svg>' +
      '<script>alert(3)</script><a href="javascript:alert(4)">unsafe</a>',
    )

    expect(html).not.toMatch(/img|svg|script|onerror|onload|javascript:/i)
    expect(html).toContain('unsafe')
  })

  it('allows safe absolute and same-origin links only', () => {
    const html = sanitizeHtml(
      '<a href="https://example.com/advisory">external</a>' +
      '<a href="/local">local</a><a href="data:text/html,bad">data</a>',
    )

    expect(html).toContain('href="https://example.com/advisory"')
    expect(html).toContain('href="/local"')
    expect(html).not.toContain('data:text/html')
  })
})
