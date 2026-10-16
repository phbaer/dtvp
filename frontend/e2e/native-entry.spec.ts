import { expect, test, type Page } from '@playwright/test'

async function fixture(page: Page, location = '/', legacyReview = true) {
  const requests: string[] = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    requests.push(path)
    let data: unknown = { items: [], next_offset: null, next_cursor: null }
    if (path === '/api/v2/me') data = { id: 'reader', name: 'Reader', playground: false, legacy_review_enabled: legacyReview, org_admin: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path.endsWith('/playground/personas')) data = []
    else if (path === '/api/v2/jobs') data = []
    await route.fulfill({ json: data })
  })
  await page.goto(location)
  return requests
}

for (const location of ['/', '/?page=Knowledge', '/?page=unknown']) {
  test(`native entry ${location} avoids legacy finding and inventory reads`, async ({ page }) => {
    const requests = await fixture(page, location)
    await expect(page.getByRole('button', { name: 'Knowledge', exact: true })).toHaveClass(/current/)
    await expect(page.getByRole('button', { name: 'Knowledge product', exact: false })).toBeVisible()
    expect(requests.some(path => path === '/api/v2/findings' || path.includes('/releases'))).toBe(false)
    await page.getByRole('button', { name: 'Review', exact: true }).click()
    await expect.poll(() => requests.filter(path => path === '/api/v2/findings').length).toBe(1)
    await page.getByRole('button', { name: 'Knowledge', exact: true }).click()
    await expect(page.getByRole('button', { name: 'Knowledge product', exact: false })).toBeVisible()
    expect(requests.filter(path => path === '/api/v2/findings')).toHaveLength(1)
  })
}

for (const location of ['/?page=Review', '/?q=CVE-2099-20001']) {
  test(`explicit compatibility link ${location} keeps legacy review`, async ({ page }) => {
    const requests = await fixture(page, location)
    await expect(page.getByRole('button', { name: 'Review', exact: true })).toHaveClass(/current/)
    await expect.poll(() => requests.filter(path => path === '/api/v2/findings').length).toBe(1)
    expect(requests.some(path => path.includes('/releases'))).toBe(false)
  })
}

for (const location of ['/?page=Review', '/?page=Statistics', '/?page=Products', '/?q=CVE-2099-20001']) {
  test(`native-only deployment normalizes compatibility link ${location}`, async ({ page }) => {
    const requests = await fixture(page, location, false)
    await expect(page.getByRole('button', { name: 'Knowledge', exact: true })).toHaveClass(/current/)
    for (const name of ['Review', 'Statistics', 'Products']) await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Knowledge product', exact: false })).toBeVisible()
    expect(requests.some(path => path === '/api/v2/findings' || path.includes('/releases') || path === '/api/v2/statistics')).toBe(false)
    await page.evaluate(() => { history.pushState({}, '', '/?page=Review'); dispatchEvent(new PopStateEvent('popstate')) })
    await expect(page.getByRole('button', { name: 'Knowledge', exact: true })).toHaveClass(/current/)
    await page.getByRole('button', { name: 'Activity', exact: true }).click()
    await expect.poll(() => requests.includes('/api/v2/jobs')).toBe(true)
    expect(requests.includes('/api/v2/findings')).toBe(false)
  })
}
