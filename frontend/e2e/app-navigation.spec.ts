import { expect, test, type Page } from '@playwright/test'

async function fixture(page: Page, admin = false) {
  const catalogSearches: string[] = []
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    let data: unknown = { items: [], next_cursor: null }
    if (path.endsWith('/me')) data = { id: 'reader', name: 'Reader', playground: false, org_admin: admin, agentyzer: { enabled: false, mode: 'disabled' }, vscorer_url: '', workspaces: [{ id: 'team', name: 'Platform', capabilities: admin ? ['read', 'manage'] : ['read'] }] }
    else if (path.endsWith('/playground/personas') || path.endsWith('/jobs')) data = []
    else if (path.endsWith('/catalog/projects')) {
      const query = url.searchParams.get('q') || ''; catalogSearches.push(query)
      data = { items: query === 'Missing' ? [] : [{ id: 'p', name: 'Gateway', workspace_id: 'team', workspace: 'Platform', version_count: 2, capabilities: ['read'] }], next_cursor: null }
    } else if (path.endsWith('/projects/p')) data = { id: 'p', name: 'Gateway', workspace_id: 'team', capabilities: ['read'] }
    else if (path.endsWith('/versions')) data = { items: [] }
    await route.fulfill({ json: data })
  })
  return catalogSearches
}

test('global navigation, legacy aliases and catalog search', async ({ page }) => {
  const searches = await fixture(page)
  await page.goto('/?page=Review')
  const nav = page.getByRole('navigation', { name: 'Main navigation' })
  await expect(nav.getByRole('button', { name: 'Products', exact: true })).toHaveAttribute('aria-current', 'page')
  await expect(nav.getByRole('button', { name: 'Administration' })).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Product catalog' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Products', exact: true })).toHaveCount(1)
  await expect(page.getByRole('combobox', { name: 'Review status', exact: true })).toBeHidden()
  await page.getByRole('searchbox', { name: 'Search products' }).fill('Missing')
  await expect.poll(() => searches.includes('Missing')).toBe(true)
  await expect(page.getByText('No products match this search.')).toBeVisible()
  await nav.getByRole('button', { name: 'Activity', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Activity', exact: true })).toBeVisible()
  await nav.getByRole('button', { name: 'Products', exact: true }).click()
  await expect(page.getByRole('searchbox', { name: 'Search products' })).toHaveValue('Missing')
  await nav.getByRole('button', { name: 'My work', exact: true }).click()
  await expect(nav.getByRole('button', { name: 'My work', exact: true })).toHaveAttribute('aria-current', 'page')
})

test('legacy Access link opens authorized administration', async ({ page }) => {
  await fixture(page, true)
  await page.goto('/?page=Access')
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Member mapping' })).toBeVisible()
  await page.getByRole('button', { name: 'Product maintenance', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Member mapping' })).toBeHidden()
})

test('mobile menu supports escape, focus return and selection', async ({ page }) => {
  await fixture(page)
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')
  const menu = page.getByRole('button', { name: 'Menu', exact: true })
  const nav = page.getByRole('navigation', { name: 'Main navigation' })
  await expect(nav).toBeHidden()
  await menu.click()
  await expect(page.getByRole('button', { name: 'Close menu' })).toHaveAttribute('aria-expanded', 'true')
  await nav.getByRole('button', { name: 'My work' }).focus()
  await page.keyboard.press('Escape')
  await expect(menu).toBeFocused()
  await expect(nav).toBeHidden()
  await menu.click()
  await nav.getByRole('button', { name: 'Activity', exact: true }).click()
  await expect(nav).toBeHidden()
  await expect(page.getByRole('heading', { name: 'Activity', exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})

test('Activity resolves accessible product names and retains explicit ID fallback', async ({ page }) => {
  await fixture(page)
  await page.route('**/api/v1/jobs', route => route.fulfill({ json: [{ id: 'job-1', kind: 'advisory_refresh', status: 'failed', project_id: 'p', version: '1.0', error: 'Provider unavailable', result: {}, attempts: 1 }, { id: 'job-2', kind: 'import', status: 'queued', project_id: 'unavailable', error: '', result: {}, attempts: 0 }] }))
  await page.route('**/api/v1/projects/unavailable', route => route.fulfill({ status: 403, json: { detail: 'No access' } }))
  await page.goto('/?page=Activity')
  const activity = page.getByRole('region', { name: 'Operational activity' })
  await expect(activity.getByText('Gateway · 1.0')).toBeVisible()
  await expect(activity.getByText('Product ID: unavailable')).toBeVisible()
  await expect(activity.getByText('Provider unavailable')).toBeVisible()
})

test('selected product and version survive Activity navigation', async ({ page }) => {
  await fixture(page)
  await page.route('**/api/v1/projects/p/versions', route => route.fulfill({ json: { items: [{ version: '1.0', state: 'state-one' }, { version: '2.0', state: 'state-two' }] } }))
  await page.route('**/api/v1/projects/p/versions/*/workspace?*', route => route.fulfill({ json: { state: 'state-two', project_id: 'p', version: '2.0', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {} } } }))
  await page.goto('/?page=Products&k_project=p&k_version=2.0')
  const product = page.getByRole('button', { name: /Product scope/ })
  const version = page.getByRole('button', { name: /^Version / })
  await expect(product).toContainText('Gateway')
  await expect(version).toContainText('2.0')
  const nav = page.getByRole('navigation', { name: 'Main navigation' })
  await expect(nav.getByRole('button', { name: 'Activity', exact: true })).toBeEnabled()
  await nav.getByRole('button', { name: 'Activity', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Activity', exact: true })).toBeVisible()
  await nav.getByRole('button', { name: 'Products', exact: true }).click()
  await expect(product).toContainText('Gateway'); await expect(version).toContainText('2.0')
  await expect(page).toHaveURL(/k_version=2.0/)
})

test('Product access exposes grants to readers and reviews exact management retries', async ({ page }) => {
  await fixture(page, true)
  const captured: unknown[] = []
  let attempts = 0
  await page.route('**/api/v1/projects/p/sharing', async route => {
    if (route.request().method() === 'PUT') {
      captured.push(route.request().postDataJSON()); attempts++
      return route.fulfill({ status: attempts === 1 ? 503 : 200, json: attempts === 1 ? { detail: 'Response uncertain' } : { workspace_id: 'other', capabilities: ['read'] } })
    }
    await route.fulfill({ json: { owner: { id: 'owner', name: 'Owner' }, grants: [{ workspace_id: 'team', workspace_name: 'Platform', capabilities: ['read'] }], capabilities: ['manage'] } })
  })
  await page.goto('/?page=Products&k_project=p&k_view=Settings&k_setting=Sharing')
  const access = page.getByRole('region', { name: 'Product access and sharing' })
  await expect(access.getByText('Product owner team: Owner')).toBeVisible()
  await access.getByLabel('Share with team').selectOption('team')
  await access.getByRole('button', { name: 'Review sharing update' }).click()
  expect(captured).toEqual([])
  await expect(page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Activity', exact: true })).toBeDisabled()
  await access.getByRole('button', { name: 'Confirm sharing update', exact: true }).click()
  await expect(access.getByRole('alert')).toHaveText('Response uncertain')
  await access.getByRole('button', { name: 'Retry captured sharing update' }).click()
  await expect(access.getByText('Product sharing updated.')).toBeVisible()
  expect(captured).toEqual([{ workspace_id: 'team', capabilities: ['read'] }, { workspace_id: 'team', capabilities: ['read'] }])
})


test('searchable dropdown hover keeps a thin border and keyboard focus remains visible', async ({ page }) => {
  await fixture(page)
  await page.goto('/?page=Products')
  const control = page.getByRole('button', { name: /Product scope/ })
  const borders = () => control.evaluate(element => { const css = getComputedStyle(element); return [css.borderWidth, css.borderColor, css.boxShadow, css.outlineWidth] })
  await page.mouse.move(0, 0)
  const before = await borders()
  expect(before[0]).toBe('1px')
  await control.hover()
  expect(await borders()).toEqual(before)
  await control.focus()
  await page.keyboard.press('Tab')
  await page.keyboard.press('Shift+Tab')
  await expect(control).toBeFocused()
  await expect(control).toHaveCSS('outline-style', 'solid')
  await expect(control).toHaveCSS('outline-width', '2px')
})
