import { expect, test, type Page } from '@playwright/test'
const pin = 'a'.repeat(64)
const cards = (toolbar: ReturnType<Page['getByRole']>) => toolbar.locator(':scope > details, :scope > .knowledge-tool-group > details, :scope > .knowledge-composition-tools > details')
async function fixture(page: Page, inventory = true) {
  const reads: string[] = [], writes: string[] = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    reads.push(path); if (route.request().method() !== 'GET') writes.push(path)
    let data: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') data = { id: 'manager', name: 'Manager', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'product', name: 'Tools product', capabilities: ['read', 'manage'] }], next_cursor: null }
    else if (path.endsWith('/versions')) data = { items: inventory ? [{ version: '7.1.1', state: pin }] : [], next_offset: null }
    else if (path.endsWith('/workspace')) data = { state: pin, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0, retained_absent_assessments: 1 } }
    else if (path.endsWith('/cpe/editor')) data = { policy_state: pin, configuration: { algorithm_version: 'dtvp.cpe-discovery/1', catalog: [], rules: {} }, capabilities: ['configure'], limitations: ['Supplied claims remain unverified'] }
    else if (path.endsWith('/pipeline-config')) data = { configuration_state: pin, configuration: { models: [], mappings: [] }, capabilities: [] }
    else if (path.endsWith('/synchronization-policy')) data = { state: pin, relationships: [], capabilities: [] }
    else if (path.endsWith('/ownership/editor')) data = { policy_state: pin, policy: { rules: [], context_roots: {} }, versions: { '7.1.1': pin }, selectors: [], capabilities: [], available_teams: [] }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Review')
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Tools product', exact: true }).click()
  const product = page.locator('[data-tool-group=composition]'), state = page.locator('[data-tool-group=reports]')
  expect(reads.filter(path => path.startsWith('/api/v1/projects//'))).toEqual([])
  return { product, state, reads, writes }
}
test('review queue precedes three collapsed tool groups and drafts survive closing', async ({ page }) => {
  const { writes } = await fixture(page)
  const groups = page.locator('details[data-tool-group]')
  await expect(groups).toHaveCount(3)
  for (const item of await groups.all()) await expect(item).not.toHaveAttribute('open', '')
  const intelligence = page.locator('[data-tool-group=intelligence]')
  await intelligence.locator(':scope > summary').click()
  await intelligence.getByText('CPE discovery policy and reviewed mappings', { exact: true }).click()
  const policy = intelligence.getByLabel('CPE discovery policy', { exact: true })
  await policy.getByRole('button', { name: 'Prepare complete policy replacement', exact: true }).click()
  await policy.getByLabel('Reviewed mapping rules JSON', { exact: true }).fill('{"draft":"preserved"}')
  await intelligence.locator(':scope > summary').click()
  await intelligence.locator(':scope > summary').click()
  await expect(policy.getByLabel('Reviewed mapping rules JSON', { exact: true })).toHaveValue('{"draft":"preserved"}')
  expect(writes).toHaveLength(0)
})
test('tool menus fit mobile width and composition remains available without a baseline', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { product, writes } = await fixture(page, false)
  await product.locator(':scope > summary').click()
  await product.getByText('Component ownership', { exact: true }).click()
  await expect(product.getByRole('region', { name: 'Component ownership editor' })).toBeVisible()
  expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(390)
  expect(writes).toHaveLength(0)
})
