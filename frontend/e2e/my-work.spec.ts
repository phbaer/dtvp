import { expect, test, type Page } from '@playwright/test'

function counts(cases: number, unique = cases) {
  return { context_findings: cases, unique_vulnerabilities: unique, by_status: { unassessed: cases }, required_context_review_workload: { required_targets: cases, approved_targets: 0, remaining_targets: cases, not_assessable_targets: 0 } }
}
async function fixture(page: Page, stalePage = false) {
  const requests: URL[] = []
  let firstPageLoads = 0
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    let data: unknown = { items: [], next_cursor: null, next_offset: null }
    if (path.endsWith('/me')) data = { id: 'analyst', name: 'Analyst', playground: false, org_admin: false, agentyzer: { enabled: false, mode: 'disabled' }, vscorer_url: '', workspaces: [{ id: 'a', name: 'Platform', capabilities: ['read', 'assess'] }, { id: 'b', name: 'Operations', capabilities: ['read', 'approve'] }] }
    else if (path.endsWith('/playground/personas') || path.endsWith('/jobs')) data = []
    else if (path === '/api/v1/portfolio') {
      requests.push(url)
      if (url.searchParams.get('offset') === '20' && stalePage) { await route.fulfill({ status: 409, json: { detail: 'Heads changed' } }); return }
      const nextPage = url.searchParams.get('offset') === '20'
      if (!nextPage) firstPageLoads++
      const version = nextPage ? '2.0' : '1.0', id = nextPage ? 'worker' : 'gateway', name = nextPage ? 'Worker' : 'Gateway'
      data = { heads: { gateway: { '1.0': 'a'.repeat(64) }, worker: { '2.0': 'b'.repeat(64) } }, heads_digest: 'c'.repeat(64), statistics: counts(7, 3), by_team: { a: counts(4), b: counts(4) }, team_labels: { a: 'Platform', b: 'Operations' }, team_counts_overlap: true, project_count: 2, version_count: 2, total: 2, next_offset: nextPage ? null : 20, items: [{ project_id: id, name, statistics: counts(nextPage ? 3 : 4), by_version: { [version]: counts(nextPage ? 3 : 4) } }] }
    } else if (path.endsWith('/catalog/projects')) data = { items: [{ id: 'gateway', name: 'Gateway', workspace_id: 'a', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/projects/gateway')) data = { id: 'gateway', name: 'Gateway', workspace_id: 'a', capabilities: ['read', 'assess'] }
    else if (path.endsWith('/versions')) data = { items: [{ version: '1.0', state: 'a'.repeat(64) }], next_offset: null }
    else if (path.endsWith('/workspace')) data = { state: 'a'.repeat(64), project_id: 'gateway', version: '1.0', items: [], next_offset: null, team_labels: {}, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    await route.fulfill({ json: data })
  })
  return { requests, firstPageLoads: () => firstPageLoads }
}

test('My work loads real cross-product scope on demand and opens a named version', async ({ page }) => {
  const api = await fixture(page)
  await page.goto('/?page=Products')
  await expect(page.getByRole('region', { name: 'Product catalog' })).toBeVisible()
  expect(api.requests).toHaveLength(0)
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'My work', exact: true }).click()
  const work = page.getByRole('region', { name: 'My work across products' })
  await expect(work).toBeVisible()
  await expect(work.getByLabel('My work totals')).toContainText('Assessment cases7')
  await expect(work.getByLabel('My work totals')).toContainText('Unique vulnerabilities3')
  expect(api.requests[0]!.searchParams.get('work_scope')).toBe('my_teams')
  await expect(work.getByText('4 cases · 0 / 4 approved · 4 remaining')).toBeVisible()
  await work.getByText('Workload by responsible team').click()
  await expect(work.getByText('Team counts can overlap when ownership is disputed; do not add them together.')).toBeVisible()
  await work.getByRole('button', { name: 'Open Gateway 1.0 cases' }).click()
  await expect.poll(() => new URL(page.url()).searchParams.get('k_project')).toBe('gateway')
  await expect.poll(() => new URL(page.url()).searchParams.get('k_version')).toBe('1.0')
})

test('My work pins page requests and retains prior workload on stale heads', async ({ page }) => {
  const api = await fixture(page, true)
  await page.goto('/?page=My%20work')
  const work = page.getByRole('region', { name: 'My work across products' })
  await expect(work.getByRole('button', { name: 'Open Gateway 1.0 cases' })).toBeVisible()
  await work.getByRole('button', { name: 'Next products', exact: true }).click()
  await expect(work.getByRole('alert')).toContainText('Refresh workload to continue.')
  expect(api.requests.at(-1)!.searchParams.get('expected_heads')).toBe('c'.repeat(64))
  expect(api.requests.at(-1)!.searchParams.get('work_scope')).toBe('my_teams')
  await expect(work.getByRole('button', { name: 'Open Gateway 1.0 cases' })).toBeVisible()
  await expect(work.getByRole('button', { name: 'Next products', exact: true })).toBeDisabled()
  await expect(work.getByLabel('Displayed workload scope')).toContainText('Previous captured scope: My teams')
  await work.getByRole('button', { name: 'Refresh workload' }).click()
  await expect(work.getByRole('alert')).toHaveCount(0)
  expect(api.firstPageLoads()).toBe(2)
  expect(api.requests.at(-1)!.searchParams.has('expected_heads')).toBe(false)
})

test('My work refetches explicit scope and queue changes and fits mobile', async ({ page }) => {
  const api = await fixture(page)
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/?page=My%20work')
  const work = page.getByRole('region', { name: 'My work across products' })
  await expect(work.getByRole('button', { name: 'Open Gateway 1.0 cases' })).toBeVisible()
  await page.getByRole('combobox', { name: 'Work scope', exact: true }).selectOption('unassigned')
  await expect.poll(() => api.requests.at(-1)?.searchParams.get('work_scope')).toBe('unassigned')
  await expect(work.getByLabel('Displayed workload scope')).toContainText('Unassigned ownership')
  await page.getByRole('button', { name: 'Awaiting review', exact: true }).click()
  await expect.poll(() => api.requests.at(-1)?.searchParams.get('lifecycle')).toBe('submitted')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})


test('Activity preserves My work scope, queue filters and captured workload', async ({ page }) => {
  const api = await fixture(page)
  await page.goto('/?page=My%20work')
  const scope = page.getByRole('combobox', { name: 'Work scope', exact: true })
  await scope.selectOption('unassigned')
  await page.getByRole('button', { name: 'Awaiting review', exact: true }).click()
  await expect.poll(() => api.requests.at(-1)?.searchParams.get('lifecycle')).toBe('submitted')
  const nav = page.getByRole('navigation', { name: 'Main navigation' })
  await nav.getByRole('button', { name: 'Activity', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Activity', exact: true })).toBeVisible()
  await nav.getByRole('button', { name: 'My work', exact: true }).click()
  await expect(scope).toHaveValue('unassigned')
  await expect(page.getByRole('combobox', { name: 'Review status', exact: true })).toHaveValue('submitted')
  await expect(page.getByLabel('Displayed workload scope')).toContainText('Unassigned ownership')
})
