import { expect, test, type Page } from '@playwright/test'

async function fixture(page: Page, teams: string[], query = '') {
  const queries: URLSearchParams[] = []
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    let value: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') value = { id: 'analyst', name: 'Analyst', playground: false, org_admin: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: teams.map(id => ({ id, name: id, capabilities: ['read', 'assess'] })) }
    else if (path === '/api/v2/catalog/projects') value = { items: [{ id: 'product', name: 'Product', capabilities: ['read'] }], next_cursor: null }
    else if (path === '/api/v2/projects/product') value = { id: 'product', name: 'Product' }
    else if (path.endsWith('/versions')) value = { items: [{ version: '1', state: 'state' }] }
    else if (path.endsWith('/workspace')) {
      queries.push(url.searchParams)
      value = { state: 'state', version: '1', items: [], statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    }
    await route.fulfill({ json: value })
  })
  await page.goto('/?page=Knowledge' + query)
  if (!query.includes('k_project')) {
    await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
    await page.getByRole('option', { name: 'Product', exact: true }).click()
  }
  await expect(page.getByLabel('Filtered workspace statistics')).toBeVisible()
  return queries
}

test('single analyst team is the initial scope and explicit all-team scope survives reload', async ({ page }) => {
  const queries = await fixture(page, ['Platform'])
  await expect(page.getByRole('combobox', { name: /^Responsible team/ })).toHaveValue('Platform')
  expect(queries.at(-1)!.get('team_id')).toBe('Platform')
  await page.getByRole('combobox', { name: /^Responsible team/ }).selectOption('')
  await expect(page.getByRole('combobox', { name: /^Responsible team/ })).toHaveValue('')
  await expect.poll(() => new URL(page.url()).searchParams.get('k_team')).toBe('')
  await page.reload()
  await expect(page.getByLabel('Filtered workspace statistics')).toBeVisible()
  await expect(page.getByRole('combobox', { name: /^Responsible team/ })).toHaveValue('')
  expect(queries.at(-1)!.get('team_id')).toBeNull()
})

test('multiple analyst teams require explicit scope instead of guessing one', async ({ page }) => {
  const queries = await fixture(page, ['Platform', 'Operations'])
  await expect(page.getByRole('combobox', { name: /^Responsible team/ })).toHaveValue('')
  expect(queries.at(-1)!.get('team_id')).toBeNull()
})

test('an explicit shared view overrides the single-team default', async ({ page }) => {
  const queries = await fixture(page, ['Platform'], '&k_project=product&k_version=1&k_team=')
  await expect(page.getByRole('combobox', { name: /^Responsible team/ })).toHaveValue('')
  expect(queries.at(-1)!.get('team_id')).toBeNull()
})
