import { openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const first = 'a'.repeat(64), second = 'b'.repeat(64)
async function fixture(page: Page, options: { paged?: boolean; roots?: boolean; graph?: string } = {}) {
  const reads: URL[] = [], writes: string[] = []
  let fail = false, wrongPin = false, hold = false, release: (() => void) | undefined
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (route.request().method() !== 'GET') writes.push(path)
    const pin = path.includes(second) ? second : first
    if (path.endsWith('/dependency-paths')) return route.fulfill({ json: { state: pin, component_ref: url.searchParams.get('component_ref'), root_ref: null, paths: [
      ['application', 'parser', 'shared-lib'].map(ref => ({ component_ref: ref, component: { name: ref, version: '1.0' }, missing: false })),
      ['application', 'alternative-parent', 'shared-lib'].map(ref => ({ component_ref: ref, component: { name: ref }, missing: false })),
    ], truncated: false, dependency_graph: 'reported', limitations: ['Shortest declared paths only.'] } })
    if (path.endsWith('/dependency-children')) {
      reads.push(url)
      const parent = url.searchParams.get('parent_ref'), root = url.searchParams.get('root_ref'), ancestors = url.searchParams.getAll('path'), offset = Number(url.searchParams.get('offset'))
      if (hold && parent === 'parser') await new Promise<void>(resolve => { release = resolve })
      if (fail) return route.fulfill({ status: 503, json: { detail: 'Dependencies unavailable; retry explicitly' } })
      const row = (ref: string, count = 0, extra = {}) => ({ component_ref: ref, parent_ref: parent, depth: ancestors.length, path: [...ancestors, ref], component: { name: ref, version: '1.0', purl: `pkg:generic/${ref}@1.0` }, child_count: count, vulnerability_count: 2, shared: false, cycle: false, missing: false, ...extra })
      const siblings = !parent ? root ? [row(root, 1)] : options.roots ? [row('application', 5), row('island')] : [row('application', 5)]
        : parent === 'application' ? [row('parser', 1), row('shared-lib', 1, { shared: true }), row('cycle-ref', 1, { cycle: true }), row('missing-ref', 1, { missing: true }), row('<script>untrusted</script>')]
        : parent === 'missing-ref' ? [row('missing-child')]
        : [row(pin === second ? 'new-leaf' : 'leaf')]
      const size = !parent && options.roots && !root ? 1 : parent === 'application' && options.paged ? 2 : 100
      return route.fulfill({ json: { state: wrongPin ? 'c'.repeat(64) : pin, version: pin === second ? '7.1.2' : '7.1.1', root_ref: root, parent_ref: parent, ancestor_path: ancestors, offset, items: siblings.slice(offset, offset + size), total: siblings.length, next_offset: offset + size < siblings.length ? offset + size : null, component_count: 5000, dependency_graph: options.graph || 'reported', limitations: ['Imported dependencies do not establish runtime reachability.'] } })
    }
    let data: unknown = { items: [], capabilities: [], next_cursor: null, next_offset: null }
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
  await openProductView(page, 'Components')
  const panel = page.getByLabel('Dependency tree', { exact: true })
  return { panel, reads, writes, fail: (value: boolean) => { fail = value }, wrongPin: (value: boolean) => { wrongPin = value }, hold: () => { hold = true }, release: () => { hold = false; release?.() } }
}
test('collapsed tree loads roots then immediate children with shared, cycle and missing markers', async ({ page }) => {
  const f = await fixture(page)
  expect(f.reads).toHaveLength(0)
  await expect(f.panel).not.toHaveAttribute('open', '')
  await openDisclosure(f.panel.locator(':scope > h2'))
  await expect(f.panel.getByRole('button', { name: 'Expand application', exact: true })).toBeVisible()
  expect(f.reads).toHaveLength(1)
  await expect(f.panel.getByRole('button', { name: /^(Next|Previous) tree page$/ })).toHaveCount(0)
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  for (const marker of ['Shared', 'Cycle', 'Missing reference']) await expect(f.panel.getByText(marker, { exact: true })).toBeVisible()
  expect(f.reads.at(-1)!.searchParams.get('parent_ref')).toBe('application')
  expect(f.reads.at(-1)!.searchParams.getAll('path')).toEqual(['application'])
  await expect(f.panel.getByRole('button', { name: 'Expand cycle-ref', exact: true })).toHaveCount(0)
  await expect(f.panel.getByRole('button', { name: 'Expand shared-lib', exact: true })).toBeVisible()
  await expect(f.panel.getByRole('button', { name: 'Select <script>untrusted</script>', exact: true })).toBeVisible()
  await f.panel.getByRole('button', { name: 'Expand missing-ref', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Select missing-child', exact: true })).toBeVisible()
  expect(f.writes).toHaveLength(0)
})
test('loading more siblings preserves expanded descendants and selected component', async ({ page }) => {
  const f = await fixture(page, { paged: true }); await openDisclosure(f.panel.locator(':scope > h2'))
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  await f.panel.getByRole('button', { name: 'Expand parser', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Select leaf', exact: true })).toBeVisible()
  await f.panel.getByRole('button', { name: 'Select parser', exact: true }).click()
  await f.panel.getByRole('button', { name: /Load more children of application/ }).click()
  await expect(f.panel.getByText('Missing reference', { exact: true })).toBeVisible()
  expect(f.reads.at(-1)!.searchParams.get('offset')).toBe('2')
  await expect(f.panel.getByRole('button', { name: 'Collapse parser', exact: true })).toBeVisible()
  await expect(f.panel.getByRole('button', { name: 'Select leaf', exact: true })).toBeVisible()
  await expect(f.panel.getByLabel('Selected dependency')).toContainText('parser')
  const requests = f.reads.length
  await f.panel.getByRole('button', { name: 'Collapse application', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: /Load more children of application/ })).toHaveCount(0)
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Select leaf', exact: true })).toBeVisible()
  expect(f.reads).toHaveLength(requests)
})
test('failed or mismatched branch reads retain ancestors and retry in place', async ({ page }) => {
  const f = await fixture(page); await openDisclosure(f.panel.locator(':scope > h2'))
  f.fail(true); await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Dependencies unavailable')
  await expect(f.panel.getByRole('button', { name: 'Select application', exact: true })).toBeVisible()
  f.fail(false); f.wrongPin(true); await f.panel.getByRole('button', { name: /Retry.*application/ }).click()
  await expect(f.panel.getByRole('alert')).toContainText('changed its requested state or branch')
  f.wrongPin(false); await f.panel.getByRole('button', { name: /Retry.*application/ }).click()
  await expect(f.panel.getByRole('button', { name: 'Select parser', exact: true })).toBeVisible()
  f.fail(true); await f.panel.getByRole('button', { name: 'Refresh tree', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Dependencies unavailable')
  await expect(f.panel.getByRole('button', { name: 'Select parser', exact: true })).toBeVisible()
})
test('subtree back navigation and compact mobile rows stay within workspace', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const f = await fixture(page); await openDisclosure(f.panel.locator(':scope > h2'))
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  await f.panel.getByRole('button', { name: 'Select parser', exact: true }).click()
  const row = f.panel.getByRole('table').locator('tbody tr').filter({ hasText: 'parser' }).first()
  expect((await row.boundingBox())!.height).toBeLessThan(36)
  await f.panel.getByRole('button', { name: 'Browse subtree parser', exact: true }).click()
  await f.panel.getByRole('button', { name: 'Expand parser', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Select leaf', exact: true })).toBeVisible()
  expect(f.reads.at(-1)!.searchParams.get('root_ref')).toBe('parser')
  await f.panel.getByRole('button', { name: 'Back', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Expand application', exact: true })).toBeVisible()
  expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(390)
})
test('late old-state branch responses cannot restore previous version descendants', async ({ page }) => {
  const f = await fixture(page); await openDisclosure(f.panel.locator(':scope > h2'))
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  f.hold(); await f.panel.getByRole('button', { name: 'Expand parser', exact: true }).click()
  await expect.poll(() => f.reads.length).toBe(3)
  await page.getByRole('button', { name: /^Version / }).click(); await page.getByRole('option', { name: '7.1.2', exact: true }).click()
  await expect(f.panel).toContainText('7.1.2')
  f.release()
  await expect(f.panel.getByRole('button', { name: 'Select leaf', exact: true })).toHaveCount(0)
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  await f.panel.getByRole('button', { name: 'Expand parser', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Select new-leaf', exact: true })).toBeVisible()
})
test('path-only mode preserves the expanded tree on return', async ({ page }) => {
  const f = await fixture(page); await openDisclosure(f.panel.locator(':scope > h2'))
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  await f.panel.getByRole('button', { name: 'Select shared-lib', exact: true }).click()
  await f.panel.getByRole('button', { name: 'Show paths to shared-lib', exact: true }).click()
  const location = f.panel.getByRole('region', { name: 'Location in dependency tree', exact: true })
  await expect(location.getByRole('list')).toContainText('shared-lib')
  await expect(f.panel.getByRole('table')).not.toBeVisible()
  await location.getByRole('combobox', { name: 'Dependency path', exact: true }).selectOption('1')
  await expect(location.getByRole('list')).toContainText('alternative-parent')
  await f.panel.getByRole('button', { name: 'Back to dependency tree', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Collapse application', exact: true })).toBeVisible()
  expect(f.reads).toHaveLength(2)
})
test('additional roots append without replacing expanded branches; collapse all uses cache', async ({ page }) => {
  const f = await fixture(page, { roots: true }); await openDisclosure(f.panel.locator(':scope > h2'))
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  await f.panel.getByRole('button', { name: /Load more roots/ }).click()
  await expect(f.panel.getByRole('button', { name: 'Select island', exact: true })).toBeVisible()
  await expect(f.panel.getByRole('button', { name: 'Collapse application', exact: true })).toBeVisible()
  await f.panel.getByRole('button', { name: 'Collapse all', exact: true }).click()
  await expect(f.panel.getByRole('table').locator('tbody tr')).toHaveCount(2)
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Select parser', exact: true })).toBeVisible()
  expect(f.reads).toHaveLength(3)
})
test('closing a loading branch does not reopen it when its response arrives', async ({ page }) => {
  const f = await fixture(page); await openDisclosure(f.panel.locator(':scope > h2'))
  await f.panel.getByRole('button', { name: 'Expand application', exact: true }).click()
  f.hold(); await f.panel.getByRole('button', { name: 'Expand parser', exact: true }).click()
  await expect.poll(() => f.reads.length).toBe(3)
  await f.panel.getByRole('button', { name: 'Collapse parser', exact: true }).click(); f.release()
  await expect(f.panel.getByRole('button', { name: 'Select leaf', exact: true })).toHaveCount(0)
  await f.panel.getByRole('button', { name: 'Expand parser', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Select leaf', exact: true })).toBeVisible()
  expect(f.reads).toHaveLength(3)
})
test('unknown graph coverage does not imply isolated components have no dependencies', async ({ page }) => {
  const f = await fixture(page, { graph: 'unknown' }); await openDisclosure(f.panel.locator(':scope > h2'))
  await expect(f.panel.getByText(/Components shown as isolated roots do not prove they have no dependencies/)).toBeVisible()
  expect(f.writes).toHaveLength(0)
})

test('initial root loading can be retried without closing the tree', async ({ page }) => {
  const f = await fixture(page); f.fail(true)
  await openDisclosure(f.panel.locator(':scope > h2'))
  await expect(f.panel.getByRole('alert')).toContainText('Dependencies unavailable')
  f.fail(false); await f.panel.getByRole('button', { name: 'Refresh tree', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Expand application', exact: true })).toBeVisible()
})
