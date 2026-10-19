import { expect, test } from '@playwright/test'
for (const location of ['/', '/?page=Knowledge', '/?page=Statistics', '/?page=Products', '/?q=CVE-2099-20001']) {
  test(`single native Review workspace normalizes ${location}`, async ({ page }) => {
    const requests: string[] = []
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname; requests.push(path)
      let data: unknown = { items: [], next_cursor: null }
      if (path.endsWith('/me')) data = { id: 'reader', name: 'Reader', playground: false, org_admin: false, agentyzer: { enabled: false }, workspaces: [] }
      if (path.endsWith('/playground/personas') || path.endsWith('/jobs')) data = []
      await route.fulfill({ json: data })
    })
    await page.goto(location)
    await expect(page.getByRole('button', { name: 'Review', exact: true })).toHaveClass(/current/)
    await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeVisible()
    for (const name of ['Knowledge', 'Statistics', 'Products']) await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0)
    expect(requests.every(path => path.startsWith('/api/v1/'))).toBe(true)
    expect(requests.some(path => /\/(findings|releases|statistics)$/.test(path))).toBe(false)
    await page.getByRole('button', { name: 'Activity', exact: true }).click()
    await expect.poll(() => requests.includes('/api/v1/jobs')).toBe(true)
    await expect(page.getByRole('button', { name: /retry|cancel/i })).toHaveCount(0)
  })
}
