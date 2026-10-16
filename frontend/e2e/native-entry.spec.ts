import { expect, test, type Page } from '@playwright/test'

async function fixture(page: Page, location = '/') {
  const requests: string[] = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    requests.push(path)
    let data: unknown = { items: [], next_offset: null, next_cursor: null }
    if (path === '/api/v2/me') data = { id: 'reader', name: 'Reader', playground: false, org_admin: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
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
