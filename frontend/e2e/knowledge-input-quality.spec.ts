import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const first = 'a'.repeat(64), second = 'b'.repeat(64), digest = 'c'.repeat(64)
async function fixture(page: Page) {
  const reads: URL[] = [], writes: string[] = []
  let changedDigest = false, hold = false, release: (() => void) | null = null
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (request.method() !== 'GET') writes.push(path)
    if (path.endsWith('/input-quality')) {
      reads.push(url)
      if (hold && url.searchParams.get('offset') === '20') await new Promise<void>(resolve => { release = resolve })
      const state = path.includes(second) ? second : first, q = url.searchParams.get('q') || '', code = url.searchParams.get('code') || '', offset = Number(url.searchParams.get('offset') || 0)
      const items = Array.from({ length: offset ? 2 : 20 }, (_, index) => ({ id: `issue-${offset + index}`, code: code || 'license_noassertion_reported', component_ref: `${state === first ? 'old' : 'new'}-component-${offset + index}`, source_id: 'part:supplier', roles: ['inventory_component'], details: { declared: 'NOASSERTION', limits: 'A source claim, not a legal conclusion' } }))
      return route.fulfill({ json: { format: 'dtvp.input-quality/1', state, project_id: 'product', version: state === first ? '7.1.1' : '7.1.2', baseline_status: 'assembly', report_digest: changedDigest ? 'd'.repeat(64) : digest, sources: [{ id: 'part:supplier', part_id: 'supplier', state: first, availability: 'selected', required: true, collection: { package_coverage: 'reported_complete', dependency_coverage: 'unknown', license_coverage: 'partial' }, dependency_graph: 'not_reported', coverage_verification: 'not_verified', source: { source: 'Supplier nightly', artifact_sha: second, format: 'spdx-2.3-json' } }], statistics: { occurrences: 101, by_role: { inventory_component: 100, constituent_root: 1 }, inventory_components: { components: 100 }, by_source: { 'part:supplier': { occurrences: 101, inventory_components: 100, license_evidence: { reported: 50, unknown: 50 }, by_code: { license_noassertion_reported: 40 } } }, unique_dependency_edges: 0, unresolved_dependency_refs: 2, issues: 250, by_code: { license_noassertion_reported: 40, package_identifier_not_reported: 30 } }, selection: { q, code }, items, total: q || code ? 22 : 80, next_offset: offset ? null : 20, limitations: ['Producer claims remain unverified.', 'Missing packages cannot be discovered from the imported model.'] } })
    }
    let result: unknown = { items: [], capabilities: [], next_offset: null, next_cursor: null }
    if (path === '/api/v1/me') result = { id: 'reader', name: 'Reader', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Quality product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state: first }, { version: '7.1.2', state: second }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state: path.includes('7.1.2') ? second : first, project_id: 'product', version: path.includes('7.1.2') ? '7.1.2' : '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/connectors/dependency-track')) result = { project_id: null, configured: false, capabilities: [] }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click(); await page.getByRole('option', { name: 'Quality product', exact: true }).click()
  const panel = page.getByLabel('Composition input observations', { exact: true })
  return { panel, reads, writes, change: () => { changedDigest = true }, hold: () => { hold = true }, release: () => { hold = false; release?.() } }
}
test('lazy read shows full role/source counts while server filters and pages stay pinned', async ({ page }) => {
  const { panel, reads, writes } = await fixture(page)
  expect(reads).toHaveLength(0)
  await openProductView(page, 'Imports')
  await openDisclosure(panel.locator(':scope > summary'))
  await expect(panel).toContainText('250 observations in the full model')
  expect((await panel.boundingBox())!.width).toBeCloseTo((await panel.locator('..').boundingBox())!.width, 0)
  await panel.getByText('Source and constituent coverage claims', { exact: true }).click()
  await expect(panel).toContainText('Producer-declared; not verified')
  await expect(panel).toContainText('reported complete')
  await expect(panel).toContainText('Dependency coverageunknown')
  await panel.getByRole('combobox', { name: 'Observation class', exact: true }).selectOption('license_noassertion_reported')
  await panel.getByLabel('Search input observations').fill('supplier')
  await panel.getByRole('button', { name: 'Apply input observation filters' }).click()
  await expect(panel).toContainText('22 matching observations')
  await expect(panel).toContainText('250 observations in the full model')
  await panel.getByLabel('Search input observations').fill('unapplied edit')
  await panel.getByRole('button', { name: 'Next input observations' }).click()
  await expect(panel).toContainText('showing 21–22')
  expect(reads.at(-1)!.searchParams.get('q')).toBe('supplier')
  expect(reads.at(-1)!.searchParams.get('offset')).toBe('20')
  expect(reads.at(-1)!.pathname).toContain(first)
  await expect(panel.getByLabel('Search input observations')).toHaveValue('unapplied edit')
  expect(writes).toHaveLength(0)
})
test('a changed derived digest retains the old result until explicit pinned reload', async ({ page }) => {
  const { panel, change } = await fixture(page)
  await openProductView(page, 'Imports')
  await openDisclosure(panel.locator(':scope > summary')); await expect(panel).toContainText('showing 1–20')
  change(); await panel.getByRole('button', { name: 'Next input observations' }).click()
  await expect(panel.getByRole('alert')).toContainText('Retained results were not replaced')
  await expect(panel).toContainText('showing 1–20')
  await panel.getByRole('button', { name: 'Reload pinned input report' }).click()
  await expect(panel.getByRole('alert')).toHaveCount(0)
  await panel.getByText('Input report pins and limitations', { exact: true }).click()
  await expect(panel).toContainText('d'.repeat(64))
})
test('late old-state page cannot restore old filters or replace the new version report', async ({ page }) => {
  const { panel, hold, release, reads } = await fixture(page)
  await openProductView(page, 'Imports')
  await openDisclosure(panel.locator(':scope > summary')); await expect(panel).toContainText('7.1.1')
  await panel.getByLabel('Search input observations').fill('old draft'); hold()
  await panel.getByRole('button', { name: 'Next input observations' }).click()
  await expect.poll(() => reads.some(url => url.searchParams.get('offset') === '20')).toBeTruthy()
  await page.getByRole('button', { name: 'Version 7.1.1' }).click(); await page.getByRole('option', { name: '7.1.2', exact: true }).click()
  await expect(panel).toContainText('7.1.2')
  release(); await expect(panel.getByLabel('Search input observations')).toHaveValue('')
  await expect(panel).toContainText('new-component-0')
  await expect(panel).not.toContainText('old-component-20')
})
test('readonly report and long reference pins fit a narrow viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes } = await fixture(page)
  await openProductView(page, 'Imports')
  await openDisclosure(panel.locator(':scope > summary'))
  await expect(panel).toContainText('No quality score, license conclusion or automatic release gate')
  await panel.getByText('Input report pins and limitations', { exact: true }).click()
  await expect(panel).toContainText(first)
  expect((await panel.boundingBox())!.width).toBeLessThanOrEqual(390)
  expect(writes).toHaveLength(0)
})
