import { expect, test, type Page } from '@playwright/test'
const pin = 'a'.repeat(64)
const cards = (toolbar: ReturnType<Page['getByRole']>) => toolbar.locator(':scope > details, :scope > .knowledge-tool-group > details, :scope > .knowledge-composition-tools > details')
async function fixture(page: Page, inventory = true) {
  const reads: string[] = [], writes: string[] = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    reads.push(path); if (route.request().method() !== 'GET') writes.push(path)
    let data: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') data = { id: 'manager', name: 'Manager', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v2/catalog/projects') data = { items: [{ id: 'product', name: 'Tools product', capabilities: ['read', 'manage'] }], next_cursor: null }
    else if (path.endsWith('/versions')) data = { items: inventory ? [{ version: '7.1.1', state: pin }] : [], next_offset: null }
    else if (path.endsWith('/workspace')) data = { state: pin, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0, retained_absent_assessments: 1 } }
    else if (path.endsWith('/cpe/editor')) data = { policy_state: pin, configuration: { algorithm_version: 'dtvp.cpe-discovery/1', catalog: [], rules: {} }, capabilities: ['configure'], limitations: ['Supplied claims remain unverified'] }
    else if (path.endsWith('/pipeline-config')) data = { configuration_state: pin, configuration: { models: [], mappings: [] }, capabilities: [] }
    else if (path.endsWith('/synchronization-policy')) data = { state: pin, relationships: [], capabilities: [] }
    else if (path.endsWith('/ownership/editor')) data = { policy_state: pin, policy: { rules: [], context_roots: {} }, versions: { '7.1.1': pin }, selectors: [], capabilities: [], available_teams: [] }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'Tools product', exact: true }).click()
  const product = page.getByRole('group', { name: 'Product tools', exact: true }), state = page.getByRole('group', { name: 'Pinned state tools', exact: true })
  await expect(cards(product)).toHaveCount(inventory ? 11 : 10)
  expect(reads.filter(path => path.startsWith('/api/v3/projects//'))).toEqual([])
  return { product, state, reads, writes }
}
test('closed utilities form compact rows; open panels span width and retain their existing inputs', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 })
  const { product, state, reads, writes } = await fixture(page)
  await expect(state.locator(':scope > details')).toHaveCount(7)
  await expect(state.locator(':scope > .knowledge-composition-tools > details')).toHaveCount(2)
  const productCards = cards(product), first = (await productCards.nth(0).boundingBox())!, second = (await productCards.nth(1).boundingBox())!
  expect(first.y).toBe(second.y); expect(second.x).toBeGreaterThan(first.x)
  expect((await product.boundingBox())!.height).toBeLessThan(160)
  await product.getByText('CPE discovery policy and reviewed mappings', { exact: true }).click()
  const policy = product.getByLabel('CPE discovery policy', { exact: true })
  await policy.getByRole('button', { name: 'Prepare complete policy replacement', exact: true }).click()
  await policy.getByLabel('Reviewed mapping rules JSON', { exact: true }).fill('{"draft":"preserved"}')
  expect((await policy.boundingBox())!.width).toBeCloseTo((await product.boundingBox())!.width, 0)
  await product.getByText('Component ownership', { exact: true }).click()
  await expect(product.getByRole('region', { name: 'Component ownership editor' })).toBeVisible()
  await product.getByText('CPE discovery policy and reviewed mappings', { exact: true }).click()
  await product.getByText('CPE discovery policy and reviewed mappings', { exact: true }).click()
  await expect(policy.getByLabel('Reviewed mapping rules JSON', { exact: true })).toHaveValue('{"draft":"preserved"}')
  expect(reads.filter(path => path.endsWith('/cpe/editor'))).toHaveLength(1)
  expect(writes).toHaveLength(0)
})
test('narrow utility panels stay directly accessible and do not overflow the review workspace', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { product, state, writes } = await fixture(page)
  for (const toolbar of [product, state]) {
    for (const card of await cards(toolbar).all()) {
      await expect(card.locator(':scope > summary')).toBeVisible()
      expect((await card.boundingBox())!.width).toBeLessThanOrEqual(390)
    }
  }
  await product.getByText('CPE discovery policy and reviewed mappings', { exact: true }).click()
  await expect(product.getByRole('button', { name: 'Prepare complete policy replacement', exact: true })).toBeVisible()
  expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(390)
  expect(writes).toHaveLength(0)
})
test('product tools remain available before a first baseline without requiring another disclosure layer', async ({ page }) => {
  const { product, state, writes } = await fixture(page, false)
  await expect(state).toHaveCount(0)
  await product.getByText('Component ownership', { exact: true }).click()
  await expect(product.getByRole('region', { name: 'Component ownership editor' })).toBeVisible()
  await expect(page.getByText('No journal-backed versions. Import a baseline to start.', { exact: true })).toBeVisible()
  expect(writes).toHaveLength(0)
})

test('pipeline and synchronization disclosures use compact cells and expand to the full workspace width', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 })
  const { product, writes } = await fixture(page)
  for (const title of ['Pipeline source roles and threat-model mappings', 'Automatic synchronization relationships', 'Automatic synchronization proposals']) {
    const summary = product.getByText(title, { exact: true })
    const disclosure = summary.locator('..')
    const closed = (await disclosure.boundingBox())!
    expect(closed.width).toBeLessThan((await product.boundingBox())!.width)
    await summary.click()
    await expect(disclosure).toHaveAttribute('open', '')
    expect((await disclosure.boundingBox())!.width).toBeCloseTo((await product.boundingBox())!.width, 0)
    await summary.click()
  }
  expect(writes).toHaveLength(0)
})
