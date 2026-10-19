import { expect, test, type Page } from '@playwright/test'
const first = 'a'.repeat(64), second = 'b'.repeat(64)
const row = (ref: string, parent: string | null, depth: number, extra = {}) => ({ component_ref: ref, parent_ref: parent, depth, component: { name: ref, version: '1.0', group: '', purl: `pkg:generic/${ref}@1.0`, type: 'library' }, child_count: 0, vulnerability_count: 2, cycle: false, shared: false, missing: false, path: parent ? ['application', ref] : [ref], ...extra })
async function fixture(page: Page, graph = 'reported') {
  const reads: URL[] = [], writes: string[] = []
  let fail = false, wrongPin = false, hold = false, release: (() => void) | undefined
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (route.request().method() !== 'GET') writes.push(path)
    if (path.endsWith('/dependency-paths')) {
      const component = url.searchParams.get('component_ref')!, pin = path.includes(second) ? second : first
      return route.fulfill({ json: { state: pin, component_ref: component, root_ref: null, paths: [
        ['application', 'parser', component].map(ref => ({ component_ref: ref, component: { name: ref, version: '1.0' }, missing: false })),
        ['application', 'alternative-parent', component].map(ref => ({ component_ref: ref, component: { name: ref }, missing: false })),
      ], truncated: false, dependency_graph: 'reported', limitations: ['Shortest declared paths only.'] } })
    }
    if (path.endsWith('/dependency-tree')) {
      reads.push(url)
      if (hold && url.searchParams.get('offset') === '100') await new Promise<void>(resolve => { release = resolve })
      if (fail) return route.fulfill({ status: 503, json: { detail: 'Tree unavailable; retry explicitly' } })
      const pin = path.includes(second) ? second : first, depth = Number(url.searchParams.get('max_depth')), root = url.searchParams.get('root_ref') || '', later = url.searchParams.get('offset') === '100'
      const items = later ? [row(pin === second ? 'new-page' : 'later-child', 'off-page-parent', 3)] : root ? [row(root, null, 0), row('subtree-child', root, 1, { path: [root, 'subtree-child'] })] : [row('application', null, 0, { child_count: 5, vulnerability_count: 5000 }), row('parser', 'application', 1, { child_count: 1 }), row('shared-lib', 'application', 1, { shared: true, child_count: 4 }), row('cycle-ref', 'application', 1, { cycle: true, child_count: 1 }), row('missing-ref', 'application', 1, { missing: true, child_count: 1 }), row('missing-child', 'missing-ref', 2, { path: ['application', 'missing-ref', 'missing-child'] }), row('<script>untrusted</script>', 'application', 1)]
      return route.fulfill({ json: { state: wrongPin ? 'c'.repeat(64) : pin, offset: later ? 100 : 0, root_ref: root || null, truncated: !root, row_limit: 10000, component_count: 5000, dependency_graph: graph, version: pin === first ? '7.1.1' : '7.1.2', items, total: 5001, next_offset: later || root ? null : 100, max_depth: depth, depth_limited: true, limitations: ['Imported dependency evidence; disconnected roots included.'] } })
    }
    let data: unknown = { items: [], next_cursor: null, next_offset: null }
    if (path.endsWith('/me')) data = { id: 'reader', name: 'Reader', playground: false, org_admin: false, workspaces: [], agentyzer: { enabled: false } }
    else if (path.endsWith('/playground/personas')) data = []
    else if (path.endsWith('/catalog/projects')) data = { items: [{ id: 'product', name: 'Tree product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.1', state: first }, { version: '7.1.2', state: second }], next_offset: null }
    else if (path.endsWith('/workspace')) data = { state: path.includes('7.1.2') ? second : first, version: path.includes('7.1.2') ? '7.1.2' : '7.1.1', project_id: 'product', items: [], next_offset: null, statistics: { totals: { context_findings: 5000, unique_vulnerabilities: 5000 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    await route.fulfill({ json: data })
  })
  await page.goto('/?page=Review')
  await page.getByRole('button', { name: 'Product scope', exact: false }).click(); await page.getByRole('option', { name: 'Tree product', exact: true }).click()
  await expect(page.getByLabel('Filtered workspace statistics')).toContainText('5000')
  return { panel: page.getByLabel('Dependency tree', { exact: true }), reads, writes, fail: (value: boolean) => { fail = value }, wrongPin: (value: boolean) => { wrongPin = value }, hold: () => { hold = true }, release: () => { hold = false; release?.() } }
}
test('tree is lazy, bounded and hierarchical with honest shared/cycle/missing markers', async ({ page }) => {
  const f = await fixture(page)
  expect(f.reads).toHaveLength(0)
  await f.panel.locator(':scope > summary').click()
  await expect(f.panel.getByRole('table', { name: 'Dependency hierarchy' })).toBeVisible()
  expect(f.reads[0]!.pathname).toBe(`/api/v1/projects/product/states/${first}/dependency-tree`)
  expect(f.reads[0]!.searchParams.get('limit')).toBe('100'); expect(f.reads[0]!.searchParams.get('max_depth')).toBe('3')
  for (const marker of ['Shared', 'Cycle', 'Missing reference']) await expect(f.panel.getByText(marker, { exact: true })).toBeVisible()
  await expect(f.panel.getByRole('button', { name: 'Browse subtree shared-lib', exact: true })).toBeVisible()
  await expect(f.panel.getByText(/Traversal capped at 10000 entries/)).toBeVisible()
  await f.panel.getByRole('button', { name: 'Collapse application', exact: true }).click()
  await expect(f.panel.locator('strong').filter({ hasText: /^parser$/ })).toHaveCount(0)
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  await expect(f.panel.locator('strong').filter({ hasText: /^parser$/ })).toBeVisible()
  await expect(f.panel.locator('strong').filter({ hasText: /^<script>untrusted<\/script>$/ })).toBeVisible()
  await f.panel.getByRole('button', { name: 'Collapse missing-ref', exact: true }).click()
  await expect(f.panel.locator('strong').filter({ hasText: /^missing-child$/ })).toHaveCount(0)
  await f.panel.getByRole('button', { name: 'Expand missing-ref', exact: true }).click()
  await expect(f.panel.locator('strong').filter({ hasText: /^missing-child$/ })).toBeVisible()
  expect(f.writes).toHaveLength(0); expect(f.reads).toHaveLength(1)
})
test('page scope stays pinned despite depth draft; failed and mismatched reads retain prior rows', async ({ page }) => {
  const f = await fixture(page); await f.panel.locator(':scope > summary').click()
  await expect(f.panel).toContainText('5001 traversal entries')
  await f.panel.getByRole('combobox', { name: 'Dependency depth', exact: true }).selectOption('7')
  await f.panel.getByRole('button', { name: 'Next tree page', exact: true }).click()
  await expect(f.panel.locator('strong').filter({ hasText: /^later-child$/ })).toBeVisible()
  expect(f.reads.at(-1)!.searchParams.get('max_depth')).toBe('3')
  await expect(f.panel).toContainText('Parent off-page-parent')
  f.fail(true); await f.panel.getByRole('button', { name: 'Previous tree page', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Tree unavailable'); await expect(f.panel.locator('strong').filter({ hasText: /^later-child$/ })).toBeVisible()
  f.fail(false); f.wrongPin(true); await f.panel.getByRole('button', { name: 'Previous tree page', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('changed its requested state'); await expect(f.panel.locator('strong').filter({ hasText: /^later-child$/ })).toBeVisible()
  f.wrongPin(false); await f.panel.getByRole('button', { name: 'Apply depth', exact: true }).click()
  await expect(f.panel).toContainText('at depth 7'); expect(f.reads.at(-1)!.searchParams.get('offset')).toBe('0')
})
test('subtree browsing is explicit and mobile tree scroll stays within the workspace', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const f = await fixture(page); await f.panel.locator(':scope > summary').click()
  await f.panel.getByRole('button', { name: 'Browse subtree parser', exact: true }).click()
  await expect(f.panel.locator('strong').filter({ hasText: /^subtree-child$/ })).toBeVisible()
  expect(f.reads.at(-1)!.searchParams.get('root_ref')).toBe('parser')
  await f.panel.getByRole('button', { name: 'View product roots', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Collapse application', exact: true })).toBeVisible()
  expect(f.reads.at(-1)!.searchParams.has('root_ref')).toBe(false)
  await f.panel.getByRole('combobox', { name: 'Dependency depth', exact: true }).selectOption('0')
  await f.panel.getByRole('button', { name: 'Apply depth', exact: true }).click()
  await expect(f.panel).toContainText('at depth 0')
  await f.panel.getByRole('button', { name: 'Browse subtree application', exact: true }).click()
  await expect.poll(() => f.reads.at(-1)!.searchParams.get('root_ref')).toBe('application')
  expect(f.reads.at(-1)!.searchParams.get('max_depth')).toBe('0')
  expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(390)
  expect(f.writes).toHaveLength(0)
})
test('late old-state pages cannot restore a previous version tree', async ({ page }) => {
  const f = await fixture(page); await f.panel.locator(':scope > summary').click()
  await expect(f.panel).toContainText('7.1.1')
  f.hold(); const next = f.panel.getByRole('button', { name: 'Next tree page', exact: true }).click()
  await expect.poll(() => f.reads.length).toBe(2)
  await page.getByRole('button', { name: 'Version', exact: false }).click(); await page.getByRole('option', { name: '7.1.2', exact: true }).click()
  await expect(f.panel).toContainText('7.1.2')
  f.release(); await next
  await expect(f.panel.locator('strong').filter({ hasText: /^later-child$/ })).toHaveCount(0)
  await expect(f.panel).toContainText('7.1.2')
})

test('unknown dependency declarations never imply isolated components have no dependencies', async ({ page }) => {
  const f = await fixture(page, 'unknown'); await f.panel.locator(':scope > summary').click()
  await expect(f.panel.getByText(/Components shown as isolated roots do not prove they have no dependencies/)).toBeVisible()
  expect(f.writes).toHaveLength(0)
})

test('path-only view removes siblings and compares alternative routes without losing the tree', async ({ page }) => {
  const f = await fixture(page); await f.panel.locator(':scope > summary').click()
  await f.panel.getByRole('button', { name: 'Show paths to shared-lib', exact: true }).click()
  const location = f.panel.getByRole('region', { name: 'Location in dependency tree', exact: true })
  await expect(location.getByRole('list', { name: 'Dependency path components' })).toContainText('shared-lib')
  await expect(location).toContainText('parser')
  await expect(f.panel.getByRole('table', { name: 'Dependency hierarchy' })).not.toBeVisible()
  await location.getByRole('combobox', { name: 'Dependency path', exact: true }).selectOption('1')
  await expect(location).toContainText('alternative-parent')
  await expect(location.getByRole('list')).not.toContainText('parser')
  await f.panel.getByRole('button', { name: 'Back to dependency tree', exact: true }).click()
  await expect(f.panel.getByRole('table', { name: 'Dependency hierarchy' })).toBeVisible()
  await expect(f.panel.getByRole('button', { name: 'Collapse application', exact: true })).toBeVisible()
  expect(f.writes).toHaveLength(0)
})
