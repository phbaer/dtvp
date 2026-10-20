import { openNativeTools, openProductView } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const pin = 'a'.repeat(64)
const counts = { context_findings: 0, unique_vulnerabilities: 0, unique_latest_logical_assessments: 0, unique_approved_logical_assessments: 0, reviewed_covered_targets: 0, pending_revision_targets: 0, by_status: {}, source_severity: {}, current_published_severity: {}, scoring_status: {}, required_context_review_workload: { required_targets: 0, approved_targets: 0, remaining_targets: 0, unresolved_targets: 0, not_assessable_targets: 0 } }
async function fixture(page: Page, query = '') {
  const reads: URL[] = [], writes: string[] = []
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (route.request().method() !== 'GET') writes.push(path)
    let data: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') data = { id: 'analyst', name: 'Analyst', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/playground/personas') data = []
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'p', name: 'Product' }], next_cursor: null }
    else if (path === '/api/v1/projects/p') data = { id: 'p', name: 'Product' }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.2', state: pin }], next_offset: null }
    else if (path.endsWith('/workspace')) { reads.push(url); data = { state: pin, project_id: 'p', version: '7.1.2', items: [], next_offset: null, statistics: { totals: counts, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } } }
    else if (path.endsWith('/portfolio')) {
      reads.push(url)
      data = path === '/api/v1/portfolio'
        ? { heads: { p: { '7.1.2': pin } }, heads_digest: pin, statistics: counts, by_team: {}, team_labels: {}, team_counts_overlap: true, project_count: 1, version_count: 1, total: 1, next_offset: null, items: [], limitations: [] }
        : { heads: { '7.1.2': pin }, heads_digest: pin, statistics: counts, by_version: { '7.1.2': counts }, by_team: {}, team_labels: {}, team_counts_overlap: true, state_evidence: {}, limitations: [] }
    }
    return route.fulfill({ json: data })
  })
  await page.goto(`/?page=Review${query}`); await openNativeTools(page)
  if (!query) {
    await page.getByRole('button', { name: 'Product scope', exact: false }).click()
    await page.getByRole('option', { name: 'Product', exact: true }).click()
  }
  await expect(page.getByLabel('Filtered workspace statistics')).toBeVisible()
  return { reads, writes }
}
test('received evidence draft filters share applied scope with statistics and saved views', async ({ page }) => {
  const f = await fixture(page)
  const agentyzer = page.getByRole('combobox', { name: 'Agentyzer evidence', exact: true }), vscorer = page.getByRole('combobox', { name: 'VScorer evidence', exact: true })
  await expect(agentyzer).not.toBeVisible()
  await page.getByText('More filters', { exact: true }).click()
  await expect(page.locator('.knowledge-advanced')).toContainText('not queued jobs or human approval')
  await page.getByRole('combobox', { name: 'Source severity', exact: true }).selectOption('high')
  const before = f.reads.length
  await agentyzer.selectOption('current'); await vscorer.selectOption('eligible')
  expect(f.reads).toHaveLength(before)
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click()
  await expect.poll(() => f.reads.at(-1)?.searchParams.get('agentyzer_evidence')).toBe('current')
  await openProductView(page, 'Overview')
  await expect(page.getByRole('heading', { name: 'Project statistics across versions', exact: true })).toBeVisible()
  await page.getByRole('navigation', { name: 'Main navigation', exact: true }).getByRole('button', { name: 'My work', exact: true }).click()
  await page.getByText('Statistics across products', { exact: true }).click()
  await expect.poll(() => [...new Set(f.reads.filter(url => url.pathname.endsWith('/portfolio')).map(url => url.pathname))].sort()).toEqual(['/api/v1/portfolio', '/api/v1/projects/p/portfolio'])
  for (const url of f.reads.slice(before)) expect(Object.fromEntries(url.searchParams)).toMatchObject({ agentyzer_evidence: 'current', vscorer_evidence: 'eligible', source_severity: 'high' })
  await page.getByText('Saved views and sharing', { exact: true }).click()
  await page.getByLabel('View name', { exact: true }).fill('Received analysis')
  await page.getByRole('button', { name: 'Save view', exact: true }).click()
  await page.getByRole('button', { name: 'Reset advanced filters', exact: true }).click()
  await expect.poll(() => f.reads.filter(url => url.pathname.endsWith('/workspace')).at(-1)?.searchParams.has('agentyzer_evidence')).toBe(false)
  await page.getByRole('button', { name: 'Received analysis', exact: true }).click()
  await expect(agentyzer).toHaveValue('current'); await expect(vscorer).toHaveValue('eligible')
  await expect(page).toHaveURL(/k_vscorer_evidence=eligible/)
  expect(f.writes).toHaveLength(0)
})
test('shared URL restores missing and historical evidence separately from human assessment on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const f = await fixture(page, '&k_project=p&k_version=7.1.2&k_agentyzer_evidence=missing&k_vscorer_evidence=historical_only&k_team_review=pending')
  expect(Object.fromEntries(f.reads.at(-1)!.searchParams)).toMatchObject({ agentyzer_evidence: 'missing', vscorer_evidence: 'historical_only', team_review: 'pending' })
  await page.getByText('More filters', { exact: false }).first().click()
  await expect(page.getByRole('combobox', { name: 'Agentyzer evidence', exact: true })).toHaveValue('missing')
  await expect(page.getByRole('combobox', { name: 'VScorer evidence', exact: true })).toHaveValue('historical_only')
  await expect(page.getByRole('combobox', { name: 'Team assessment', exact: true })).toHaveValue('pending')
  await expect(page.locator('.knowledge-advanced')).toContainText('Current evidence may still be ineligible')
  expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(390)
  expect(f.writes).toHaveLength(0)
})
