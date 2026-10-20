import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const pin = 'a'.repeat(64), newer = 'b'.repeat(64)
const counts = (total = 79) => ({ context_findings: total, unique_vulnerabilities: 31, unique_latest_logical_assessments: 12, unique_approved_logical_assessments: 8, reviewed_covered_targets: 50, pending_revision_targets: 2, by_status: { approved: 50, submitted: 29 }, source_severity: { critical: 60, unknown: 19 }, current_published_severity: { low: 40, unknown: 39 }, scoring_status: { published: 40, outdated: 39 }, required_context_review_workload: { required_targets: 79, approved_targets: 50, remaining_targets: 29, unresolved_targets: 2, not_assessable_targets: 2 } })
const result = (digest = pin, total = 79) => ({ heads: { '7.1.1': pin, '7.1.2': newer }, heads_digest: digest, statistics: counts(total), by_version: { '7.1.1': counts(43), '7.1.2': counts(36) }, by_team: { platform: counts(70) }, team_labels: { platform: 'Platform' }, team_counts_overlap: true, state_evidence: { '7.1.1': { baseline_status: 'active', collection_coverage: { package_coverage: 'unknown', dependency_coverage: 'partial', license_coverage: 'unknown' }, coverage_verification: 'not_verified', uncontextualized_source_findings: 4 } }, limitations: ['Counts do not verify complete software coverage.'] })
async function fixture(page: Page) {
  const reads: URL[] = [], mutations: string[] = []
  let digest = pin, hold = false, release: (() => Promise<void>) | undefined
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (route.request().method() !== 'GET') mutations.push(path)
    let data: unknown = { items: [], capabilities: [], next_cursor: null }
    if (path === '/api/v1/me') data = { id: 'reader', name: 'Reader', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'product', name: 'Portfolio product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.1', state: pin }, { version: '7.1.2', state: newer }], next_offset: null }
    else if (path.endsWith('/workspace')) data = { state: pin, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path === '/api/v1/portfolio') data = { ...result(pin, 0), heads: {}, project_count: 0, version_count: 0, items: [], total: 0, next_offset: null }
    else if (path === '/api/v1/projects/product/portfolio') {
      reads.push(url)
      if (hold) { hold = false; release = () => route.fulfill({ json: result(pin, 888) }); return }
      if (url.searchParams.has('expected_heads') && url.searchParams.get('expected_heads') !== digest) return route.fulfill({ status: 409, json: { detail: 'Heads changed' } })
      data = result(digest, digest === pin ? 79 : 25)
    }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Portfolio product' }).click()
  return { reads, mutations, advance: () => { digest = newer }, hold: () => { hold = true }, release: async () => { if (!release) throw new Error('No held request'); await release() } }
}
async function open(page: Page) { await openProductView(page, 'Overview');
  await openDisclosure(page.getByText('Project statistics across versions', { exact: true }))
  const panel = page.getByRole('region', { name: 'Project statistics across versions' })
  await expect(panel.getByLabel('Portfolio totals')).toContainText('79')
  return panel
}
test('lazy server counts, explicit versions, inherited filters and compact layout', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const state = await fixture(page)
  expect(state.reads).toHaveLength(0)
  const panel = await open(page)
  await expect(panel.getByLabel('Portfolio totals')).toContainText('Latest logical assessments12')
  await expect(panel.getByLabel('Portfolio totals')).toContainText('Approved logical assessments8')
  await expect(panel.getByRole('table', { name: 'Review workload by version' })).toContainText('43')
  await expect(panel).toContainText('Current published severity: low 40 · unknown 39')
  await expect(panel).toContainText('outdated 39')
  await panel.getByText('Teams and workflow states', { exact: true }).click()
  await expect(panel.getByRole('table', { name: 'Review workload by team' })).toContainText('Platform')
  await panel.getByRole('combobox', { name: 'Portfolio versions', exact: true }).selectOption('selected')
  await panel.getByRole('listbox', { name: 'Selected portfolio versions', exact: true }).selectOption(['7.1.2'])
  await panel.getByRole('combobox', { name: 'Portfolio team', exact: true }).selectOption('platform')
  await panel.getByRole('button', { name: 'Load statistics', exact: true }).click()
  await expect.poll(() => state.reads.length).toBe(2)
  expect(state.reads[1]!.searchParams.getAll('version')).toEqual(['7.1.2'])
  expect(state.reads[1]!.searchParams.get('team_id')).toBe('platform')
  await openProductView(page, 'Vulnerabilities')
  await page.getByLabel('Search', { exact: true }).fill('tls')
  await openProductView(page, 'Overview')
  await expect.poll(() => state.reads.some(url => url.searchParams.get('q') === 'tls')).toBe(true)
  await expect(panel.getByRole('combobox', { name: 'Portfolio team', exact: true })).toHaveValue('platform')
  await panel.getByText('Input coverage and pinned heads', { exact: true }).click()
  await expect(panel).toContainText('package coverage unknown')
  await expect(panel).toContainText('Zero findings do not establish complete input coverage')
  expect(state.mutations).toHaveLength(0)
  expect((await panel.boundingBox())!.width).toBeLessThanOrEqual(390)
})
test('409 retains previous pins until explicit refresh', async ({ page }) => {
  const state = await fixture(page), panel = await open(page)
  state.advance()
  await panel.getByRole('button', { name: 'Check selected heads', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Version heads changed')
  await expect(panel.getByLabel('Portfolio totals')).toContainText('79')
  expect(state.reads[1]!.searchParams.get('expected_heads')).toBe(pin)
  await panel.getByRole('button', { name: 'Refresh statistics', exact: true }).click()
  await expect(panel.getByLabel('Portfolio totals')).toContainText('25')
  expect(state.reads[2]!.searchParams.has('expected_heads')).toBe(false)
  await expect(panel.getByRole('alert')).toHaveCount(0)
})
test('late responses cannot overwrite changed selection', async ({ page }) => {
  const state = await fixture(page), panel = await open(page)
  state.hold()
  await panel.getByRole('button', { name: 'Check selected heads', exact: true }).click()
  await expect.poll(() => state.reads.length).toBe(2)
  await panel.getByRole('combobox', { name: 'Portfolio team', exact: true }).selectOption('platform')
  await panel.getByRole('button', { name: 'Load statistics', exact: true }).click()
  await expect(panel.getByLabel('Portfolio totals')).toContainText('79')
  await state.release()
  await expect(panel.getByLabel('Portfolio totals')).not.toContainText('888')
  await expect(panel.getByRole('combobox', { name: 'Portfolio team', exact: true })).toHaveValue('platform')
})
