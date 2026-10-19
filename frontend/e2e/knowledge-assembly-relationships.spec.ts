import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const a = 'a'.repeat(64), b = 'b'.repeat(64), head = 'c'.repeat(64)
const declarations = [{ relationship_id: 'application-container', kind: 'DEPENDS_ON', from: { part_id: 'application', state: a, ref: 'root-a' }, to: { part_id: 'container', state: b, ref: 'root-b' }, rationale: 'Explicit integration relationship' }]
async function fixture(page: Page, hold?: 'preview' | 'apply') {
  let actor = 'analyst', release: (() => void) | undefined, applications = 0
  const writes: { path: string; body: Record<string, any> }[] = []
  await page.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname
    if (path.endsWith('/playground/login')) { actor = request.postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (request.method() === 'POST') {
      const body = request.postDataJSON(); writes.push({ path, body })
      if (path.endsWith(`/assembly-${hold}`)) await new Promise<void>(resolve => { release = resolve })
      if (path.endsWith('/assembly-preview')) return route.fulfill({ json: { preview_digest: 'd'.repeat(64), readiness: 'unverified', missing_required_parts: [], selected_part_count: 2, counts: {}, changes: {}, relationship_diagnostics: { declared: body.cross_part_relationships?.length || 0, identity_merges: 0 }, limitations: [] } })
      applications++
      if (hold === 'apply') return route.fulfill({ status: 201, json: { committed: true } })
      return route.fulfill(applications < 3 ? { status: applications === 1 ? 503 : 409, json: { detail: 'Exact input retained' } } : { status: 201, json: { committed: true } })
    }
    let value: unknown = { items: [], next_cursor: null, next_offset: null }
    if (path === '/api/v1/me') value = { id: actor, name: actor, org_admin: false, playground: true, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path.endsWith('/playground/personas')) value = [{ id: 'analyst', name: 'Analyst' }, { id: 'other', name: 'Other' }]
    else if (path === '/api/v1/catalog/projects') value = { items: [{ id: 'product', name: 'Assembly product' }], next_cursor: null }
    else if (path.endsWith('/versions')) value = { items: [{ version: '7.2', state: head }], next_offset: null }
    else if (path.endsWith('/workspace')) value = { state: head, project_id: 'product', version: '7.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/assembly-target')) value = { state: head, predecessor: null, previous_kind: 'assembly', parts: [{ part_id: 'application', state: a, required: true, role: 'delivery' }, { part_id: 'container', state: b, required: true, role: 'delivery' }], cross_part_relationships: declarations, capabilities: ['assemble'], limitations: [] }
    return route.fulfill({ json: value })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click(); await page.getByRole('option', { name: 'Assembly product', exact: true }).click()
  await page.locator('.knowledge-assembly > summary').click()
  const panel = page.getByRole('region', { name: 'Product assembly editor' })
  await panel.getByRole('button', { name: 'Inspect assembly target', exact: true }).click()
  return { panel, writes, release: () => release?.() }
}
test('existing exact mappings stay hidden by default and survive frozen503/409 retries', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const f = await fixture(page)
  await expect(f.panel.getByLabel('Cross-part relationships JSON', { exact: true })).not.toBeVisible()
  await f.panel.getByText('Explicit cross-part relationships', { exact: true }).click()
  expect(JSON.parse(await f.panel.getByLabel('Cross-part relationships JSON', { exact: true }).inputValue())).toEqual(declarations)
  await expect(f.panel).toContainText('CONTAINS records containment only')
  await f.panel.getByRole('button', { name: 'Preview exact assembly', exact: true }).click()
  const publish = f.panel.getByRole('button', { name: 'Publish selected assembly', exact: true })
  await publish.click(); await expect(f.panel.getByRole('alert')).toContainText('Exact selection')
  await publish.click(); await expect(f.panel.getByRole('alert')).toContainText('Exact selection')
  await publish.click()
  const posts = f.writes.filter(row => row.path.endsWith('/assembly-apply'))
  expect(posts).toHaveLength(3); expect(posts[0]).toEqual(posts[1]); expect(posts[0]).toEqual(posts[2])
  expect(posts[0]!.body.assembly.cross_part_relationships).toEqual(declarations)
  expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(390)
})
test('invalid mapping JSON releases the workspace lock and explicit removal captures its reason', async ({ page }) => {
  const f = await fixture(page)
  await f.panel.getByText('Explicit cross-part relationships', { exact: true }).click()
  const json = f.panel.getByLabel('Cross-part relationships JSON', { exact: true })
  await json.fill('not JSON')
  await f.panel.getByRole('button', { name: 'Preview exact assembly', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Correct the input')
  expect(f.writes).toHaveLength(0)
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
  await json.fill('[]'); await f.panel.getByLabel('Relationship change reason', { exact: true }).fill('Explicit relationship retirement')
  await f.panel.getByRole('button', { name: 'Preview exact assembly', exact: true }).click()
  expect(f.writes[0]!.body.relationship_change_reason).toBe('Explicit relationship retirement')
  expect(f.writes[0]!.body.cross_part_relationships).toBeUndefined()
})
for (const hold of ['preview', 'apply'] as const) test(`actor roundtrip discards late assembly ${hold} completion`, async ({ page }) => {
  const f = await fixture(page, hold)
  await f.panel.getByRole('button', { name: 'Preview exact assembly', exact: true }).click()
  if (hold === 'apply') await f.panel.getByRole('button', { name: 'Publish selected assembly', exact: true }).click()
  await expect.poll(() => f.writes.some(row => row.path.endsWith(`/assembly-${hold}`))).toBe(true)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('analyst')
  const response = page.waitForResponse(item => item.url().endsWith(`/assembly-${hold}`)); f.release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByRole('region', { name: 'Frozen assembly selection' })).toHaveCount(0)
  await expect(page.getByText('Product assembly published.', { exact: false })).toHaveCount(0)
})
