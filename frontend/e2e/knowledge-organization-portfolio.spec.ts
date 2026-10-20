import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const pin = 'a'.repeat(64), changed = 'b'.repeat(64)
const counts = (total = 79) => ({ context_findings: total, unique_vulnerabilities: 31, unique_latest_logical_assessments: 12, unique_approved_logical_assessments: 8, reviewed_covered_targets: 50, pending_revision_targets: 2, by_status: { approved: 50, submitted: 29 }, source_severity: { critical: 60, unknown: 19 }, current_published_severity: { low: 40, unknown: 39 }, scoring_status: { published: 40, outdated: 39 }, required_context_review_workload: { required_targets: 79, approved_targets: 50, remaining_targets: 29, unresolved_targets: 2, not_assessable_targets: 2 } })
async function fixture(page: Page, personas = false) {
  let digest = pin, actor = 'person', hold = false, tooMany = false
  let release: (() => void) | undefined
  const reads: URL[] = [], catalog: URL[] = [], writes: string[] = []
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (path === '/api/v1/playground/login') { actor = route.request().postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (route.request().method() !== 'GET') writes.push(path)
    let data: unknown = { items: [], capabilities: [], next_cursor: null }
    if (path === '/api/v1/me') data = { id: actor, name: actor, org_admin: false, playground: personas, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'oversight', name: 'Oversight', capabilities: ['read', 'manage'] }] }
    else if (path === '/api/v1/playground/personas') data = personas ? [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v1/catalog/projects') { catalog.push(url); data = { items: [{ id: 'alpha', name: 'Alpha' }, { id: 'beta', name: 'Beta' }], next_cursor: 'next-catalog-page' } }
    else if (path === '/api/v1/portfolio') {
      reads.push(url)
      if (hold) { hold = false; await new Promise<void>(resolve => { release = resolve }) }
      if (tooMany && !url.searchParams.has('project')) return route.fulfill({ status: 422, json: { detail: 'Portfolio exceeds 100 projects; select projects explicitly' } })
      if (url.searchParams.has('expected_heads') && url.searchParams.get('expected_heads') !== digest) return route.fulfill({ status: 409, json: { detail: 'Product/version heads changed' } })
      const later = url.searchParams.get('offset') === '20'
      data = { format: 'dtvp.organization-portfolio/1', heads: { alpha: { '7.1.1': pin }, beta: { '7.1.2': pin } }, heads_digest: digest, statistics: counts(digest === pin ? 79 : 25), by_team: { platform: counts(70), operations: counts(30) }, team_labels: { platform: 'Platform', operations: 'Operations' }, team_counts_overlap: true, project_count: 21, version_count: 42, total: 21, next_offset: later ? null : 20, items: [{ project_id: later ? 'beta' : 'alpha', name: later ? 'Beta' : 'Alpha', heads: { '7.1.1': pin }, statistics: counts(later ? 36 : 43), by_version: { '7.1.1': counts(43) }, state_evidence: { '7.1.1': { collection_coverage: { package_coverage: 'unknown' }, coverage_verification: 'not_verified' } } }], limitations: ['Only selected currently authorized products are counted.'] }
    }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=My%20work'); await openNativeTools(page)
  await expect(page.getByRole('region', { name: 'My work across products' }).getByRole('button', { name: 'Refresh workload' })).toBeEnabled()
  const panel = page.getByRole('region', { name: 'Statistics across products', exact: true })
  return { panel, reads, catalog, writes, advance: () => { digest = changed }, tooMany: () => { tooMany = true }, hold: () => { hold = true }, release: () => { release?.() } }
}
async function open(page: Page) { await openDisclosure(page.getByText('Statistics across products', { exact: true })) }
test('global detailed statistics are lazy within My work', async ({ page }) => {
  const f = await fixture(page)
  await expect(f.panel.getByLabel('Cross-product portfolio totals')).toHaveCount(0)
  await open(page)
  await expect(f.panel.getByLabel('Cross-product portfolio totals')).toContainText('Context findings79')
  await expect(f.panel.getByLabel('Cross-product portfolio totals')).toContainText('Latest logical assessments12')
  await expect(f.panel).toContainText('21 selected products · 42 current product versions')
  await expect(f.panel.getByRole('table', { name: 'Cross-product review workload by team', exact: true })).toContainText('Platform')
  await expect(f.panel).toContainText('Source severity: critical 60 · unknown 19')
  await expect(f.panel).toContainText('Current published severity: low 40 · unknown 39')
  await expect(f.panel).toContainText('Team counts can overlap')
  await f.panel.getByRole('button', { name: 'Next portfolio products', exact: true }).click()
  await expect(f.panel.getByRole('table', { name: 'Review workload across products', exact: true })).toContainText('Beta')
  expect(f.reads.at(-1)!.searchParams.get('expected_heads')).toBe(pin)
  await expect(f.panel.getByLabel('Cross-product portfolio totals')).toContainText('Context findings79')
  expect(f.writes).toHaveLength(0)
})
test('bounded explicit project selection and applied team/filter snapshot survive draft edits and paging', async ({ page }) => {
  const f = await fixture(page)
  await open(page)
  await f.panel.getByRole('combobox', { name: 'Portfolio products', exact: true }).selectOption('selected')
  await f.panel.getByRole('button', { name: 'Add portfolio product', exact: false }).click()
  await page.getByRole('option', { name: 'Alpha', exact: true }).click()
  await f.panel.getByRole('combobox', { name: 'Cross-product team', exact: true }).selectOption('platform')
  await page.getByRole('searchbox', { name: 'Search', exact: true }).fill('openssl')
  await expect(page.getByRole('region', { name: 'My work across products' }).getByLabel('Displayed workload scope')).toContainText('openssl')
  await f.panel.getByRole('button', { name: 'Refresh cross-product statistics', exact: true }).click()
  expect(f.reads.at(-1)!.searchParams.getAll('project')).toEqual(['alpha'])
  expect(f.reads.at(-1)!.searchParams.get('team_id')).toBe('platform')
  expect(f.reads.at(-1)!.searchParams.get('q')).toBe('openssl')
  await expect(f.panel.getByLabel('Displayed cross-product scope')).toContainText('Products: Alpha · All responsible teams · Team: Platform · q: openssl')
  expect(f.catalog.some(url => url.searchParams.get('limit') === '25')).toBe(true)
  await f.panel.getByRole('combobox', { name: 'Portfolio products', exact: true }).selectOption('all')
  await f.panel.getByRole('combobox', { name: 'Cross-product team', exact: true }).selectOption('operations')
  await page.getByRole('searchbox', { name: 'Search', exact: true }).fill('edited search')
  await expect(page.getByRole('region', { name: 'My work across products' }).getByLabel('Displayed workload scope')).toContainText('edited search')
  await f.panel.getByRole('button', { name: 'Next portfolio products', exact: true }).click()
  expect(f.reads.at(-1)!.searchParams.getAll('project')).toEqual(['alpha'])
  expect(f.reads.at(-1)!.searchParams.get('team_id')).toBe('platform')
  expect(f.reads.at(-1)!.searchParams.get('q')).toBe('openssl')
  expect(f.reads.at(-1)!.searchParams.get('expected_heads')).toBe(pin)
  await expect(f.panel.getByLabel('Displayed cross-product scope')).toContainText('Products: Alpha · All responsible teams · Team: Platform · q: openssl')
  await expect(f.panel.getByLabel('Displayed cross-product scope')).not.toContainText('edited search')
  expect(f.writes).toHaveLength(0)
})
test('head conflicts retain old complete statistics until an explicit refresh and stay readable on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const f = await fixture(page)
  await open(page); f.advance()
  await f.panel.getByRole('button', { name: 'Next portfolio products', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Previous statistics and pins remain')
  await expect(f.panel.getByLabel('Cross-product portfolio totals')).toContainText('Context findings79')
  await expect(f.panel.getByRole('table', { name: 'Review workload across products', exact: true })).toContainText('Alpha')
  await f.panel.getByRole('button', { name: 'Refresh cross-product statistics', exact: true }).click()
  await expect(f.panel.getByLabel('Cross-product portfolio totals')).toContainText('Context findings25')
  expect(f.reads.at(-1)!.searchParams.has('expected_heads')).toBe(false)
  expect((await f.panel.boundingBox())!.width).toBeLessThanOrEqual(390)
  expect(await page.locator('body').evaluate(item => item.scrollWidth)).toBeLessThanOrEqual(390)
})
test('an oversized all-products selection remains an error and can be narrowed explicitly', async ({ page }) => {
  const f = await fixture(page); f.tooMany()
  await open(page)
  await expect(f.panel.getByRole('alert')).toContainText('100 projects; select projects explicitly')
  await f.panel.getByRole('combobox', { name: 'Portfolio products', exact: true }).selectOption('selected')
  await f.panel.getByRole('button', { name: 'Add portfolio product', exact: false }).click()
  await page.getByRole('option', { name: 'Alpha', exact: true }).click()
  await f.panel.getByRole('button', { name: 'Load cross-product statistics', exact: true }).click()
  await expect(f.panel.getByLabel('Cross-product portfolio totals')).toContainText('Context findings79')
  expect(f.reads.at(-1)!.searchParams.getAll('project')).toEqual(['alpha'])
})
test('actor remount invalidates a late portfolio response through an actor roundtrip', async ({ page }) => {
  const f = await fixture(page, true); f.hold(); await open(page)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('person')
  const response = page.waitForResponse(item => item.url().includes('/api/v1/portfolio?'))
  f.release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByLabel('Cross-product portfolio totals')).toHaveCount(0)
})


test('a selected product overview excludes cross-product statistics and global reads', async ({ page }) => {
  const f = await fixture(page)
  const reads = f.reads.length
  const navigation = page.getByRole('navigation', { name: 'Main navigation' })
  await navigation.getByRole('button', { name: 'Products', exact: true }).click()
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Alpha', exact: true }).click()
  await openProductView(page, 'Overview')
  await expect(page.locator('[data-product-view="Overview"]')).toHaveAttribute('aria-current', 'page')
  await expect(page.getByRole('region', { name: 'Composition required', exact: true })).toBeVisible()
  await expect(f.panel).toBeHidden()
  expect(f.reads).toHaveLength(reads)
  await navigation.getByRole('button', { name: 'My work', exact: true }).click()
  await expect(page.locator('.organization-portfolio > summary')).toBeVisible()
})
