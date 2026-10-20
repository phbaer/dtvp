import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const sha = (char: string) => char.repeat(64), first = sha('a'), evidence = sha('b'), packages = Array.from({ length: 23 }, (_, n) => `pkg:pypi/library-${String(n).padStart(2, '0')}@1.0`)
async function fixture(page: Page, readonly = false, personas = false) {
  let head = first, actor = 'person', failure = 0, hold = false, mismatch = '', release: (() => void) | undefined, jobReads = 0
  const requests: { path: string; body: Record<string, unknown> }[] = [], plans: URL[] = []
  const saved = { id: 'saved-job', kind: 'match-osv-native', status: 'failed', purls: [packages[0]], expected_versions: { '7.1.2': first }, expected_evidence: evidence, revision: 1, attempts: 1, error: 'Provider unavailable; unqueried coverage unknown', result: { selected_queries: 1, completed_queries: 0, unqueried_coverage: 'unknown', capture_sha256: sha('c'), raw_artifact_shas: [sha('d')] }, capabilities: readonly ? [] : ['retry'] }
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (path.endsWith('/playground/login')) { actor = request.postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (request.method() === 'POST') {
      const body = request.postDataJSON(); requests.push({ path, body })
      if (hold) { hold = false; await new Promise<void>(resolve => { release = resolve }) }
      if (failure) return route.fulfill({ status: failure, json: { detail: failure === 503 ? 'Recording uncertain' : 'Product heads changed' } })
      if (path.endsWith('/osv-jobs')) return route.fulfill({ status: 202, json: { ...saved, id: 'queued-job', status: 'queued', purls: body.purls, expected_versions: body.expected_versions, expected_evidence: body.expected_evidence, revision: body.revision, capabilities: ['cancel'] } })
      return route.fulfill({ json: { ...saved, status: 'queued', capabilities: ['cancel'] } })
    }
    let data: unknown = { items: [], capabilities: [], next_cursor: null, next_offset: null }
    if (path === '/api/v1/me') data = { id: actor, name: actor, org_admin: false, playground: personas, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path.endsWith('/playground/personas')) data = personas ? [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'product', name: 'Product' }], next_cursor: null }
    else if (path === '/api/v1/projects/product') data = { id: 'product', name: 'Product' }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.2', state: head }] }
    else if (path.endsWith('/workspace')) data = { state: head, project_id: 'product', version: '7.1.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/advisory-refresh')) data = { expected_versions: { '7.1.2': head }, expected_evidence: evidence, providers: [], identifiers: [], total: 0, next_offset: null, capabilities: [], limitations: [] }
    else if (path.endsWith('/osv-matching')) { plans.push(url); const later = url.searchParams.get('offset') === '20'; data = { expected_versions: { '7.1.2': head }, expected_evidence: evidence, enabled: !readonly, next_revision: 2, purls: packages.slice(later ? 20 : 0, later ? 23 : 20), total: 23, next_offset: later ? null : 20, selection_digest: head, coverage: { eligible_purls: 23, eligible_occurrences: 30, unsupported_occurrences: { qualified_or_subpath_purl: 4 }, unqueried_coverage: 'unknown' }, capabilities: readonly ? [] : ['query'], limitations: ['Provider matching does not establish applicability.'] } }
    else if (path.endsWith('/osv-jobs')) { jobReads++; data = { items: [saved], next_offset: null } }
    else if (path.endsWith('/osv-jobs/saved-job')) { jobReads++; data = { ...saved, ...(mismatch === 'id' ? { id: 'unrelated-job' } : mismatch === 'kind' ? { kind: 'agentyzer-native' } : mismatch === 'scope' ? { expected_evidence: sha('f') } : {}), status: mismatch ? 'succeeded' : saved.status } }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Review'); await openNativeTools(page); await page.getByRole('button', { name: 'Product scope', exact: false }).click(); await page.getByRole('option', { name: 'Product', exact: true }).click()
  await openProductView(page, 'Vulnerabilities'); await page.getByRole('button', { name: 'Discover and enrich', exact: true }).click()
  await openDisclosure(page.getByText('Advisory intelligence refresh', { exact: true }))
  return { panel: page.getByRole('region', { name: 'OSV package matching', exact: true }), requests, plans, jobReads: () => jobReads, fail: (status: number) => { failure = status }, advance: () => { head = sha('9') }, hold: () => { hold = true }, mismatch: (mode: string) => { mismatch = mode }, release: () => release?.() }
}
async function open(page: Page) { await page.getByText('External OSV package matching', { exact: true }).click() }
test('explicit20package cap and pinned pages retain exact request across503/409 and workspace advance', async ({ page }) => {
  const f = await fixture(page); expect(f.plans).toHaveLength(0); await open(page)
  await expect(f.panel.getByRole('checkbox', { checked: true })).toHaveCount(0)
  for (const box of await f.panel.getByRole('checkbox').all()) await box.check()
  await f.panel.getByRole('button', { name: 'Next OSV packages', exact: true }).click()
  await expect(f.panel.getByLabel('Explicitly selected OSV packages')).toContainText(packages[0]!)
  for (const box of await f.panel.getByRole('checkbox').all()) await expect(box).toBeDisabled()
  f.fail(503); await f.panel.getByRole('button', { name: 'Queue selected OSV queries', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Exact package selection, heads, evidence, revision and request ID are retained')
  f.advance(); await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click(); await expect(f.panel).toContainText('Workspace state changed')
  f.fail(409); await f.panel.getByRole('button', { name: 'Resend identical OSV request', exact: true }).click(); await expect(f.panel.getByRole('alert')).toContainText('Product heads changed')
  f.fail(0); await f.panel.getByRole('button', { name: 'Resend identical OSV request', exact: true }).click(); await expect(f.panel.getByRole('status').filter({ hasText: 'OSV job recorded' })).toBeVisible()
  expect(f.requests).toHaveLength(3); expect(f.requests[0]).toEqual(f.requests[1]); expect(f.requests[0]).toEqual(f.requests[2])
  expect(f.requests[0]!.body).toMatchObject({ expected_versions: { '7.1.2': first }, expected_evidence: evidence, purls: packages.slice(0, 20), revision: 2 })
  expect(f.requests[0]!.body.request_id).toMatch(/^[0-9a-f-]{36}$/)
})
test('changed plan retains earlier selection until explicit refresh and unknown coverage stays readable on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 }); const f = await fixture(page); await open(page)
  await f.panel.getByRole('checkbox').first().check(); f.advance(); await f.panel.getByRole('button', { name: 'Next OSV packages', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('OSV package plan changed'); await expect(f.panel.getByLabel('Explicitly selected OSV packages')).toContainText(packages[0]!)
  await f.panel.getByText('OSV coverage limits and source pins', { exact: true }).click(); await expect(f.panel).toContainText('qualified or subpath purl: 4 · coverage unknown')
  await expect(f.panel).toContainText('no-match response does not prove absence or remediation')
  await f.panel.getByRole('button', { name: 'Refresh OSV package plan', exact: true }).click(); await expect(f.panel.getByLabel('Explicitly selected OSV packages')).toHaveCount(0)
  expect(await page.locator('body').evaluate(row => row.scrollWidth)).toBeLessThanOrEqual(390); expect(f.requests).toHaveLength(0)
})
test('server job capabilities and exact action retry expose raw capture links without polling', async ({ page }) => {
  const f = await fixture(page); await open(page)
  const job = f.panel.getByRole('article', { name: 'OSV job saved-job', exact: true })
  await job.getByText('OSV job pins, capture and source bytes', { exact: true }).click(); await expect(job.getByRole('link').first()).toHaveAttribute('href', /\/osv-jobs\/saved-job\/artifacts\/[a-f0-9]{64}$/)
  expect(f.jobReads()).toBe(1); f.fail(503); await job.getByRole('button', { name: 'Retry OSV job', exact: true }).click(); await expect(f.panel.getByRole('alert')).toContainText('Captured job action is retained')
  f.fail(0); await f.panel.getByRole('button', { name: 'Resend captured OSV job action', exact: true }).click(); expect(f.requests[0]).toEqual(f.requests[1]); await expect(job.getByRole('button', { name: 'Cancel OSV job', exact: true })).toBeVisible(); expect(f.jobReads()).toBe(1)
})
test('disabled provider and readonly capabilities withhold queries and job mutations', async ({ page }) => {
  const f = await fixture(page, true); await open(page); await expect(f.panel).toContainText('OSV provider disabled')
  await expect(f.panel.getByRole('button', { name: 'Queue selected OSV queries', exact: true })).toHaveCount(0); await expect(f.panel.getByRole('button', { name: 'Retry OSV job', exact: true })).toHaveCount(0); expect(f.requests).toHaveLength(0)
})
test('actor roundtrip cannot revive a late enqueue or its frozen capture', async ({ page }) => {
  const f = await fixture(page, false, true); await open(page); await f.panel.getByRole('checkbox').first().check(); f.hold(); await f.panel.getByRole('button', { name: 'Queue selected OSV queries', exact: true }).click(); await expect.poll(() => f.requests.length).toBe(1)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other'); await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled(); await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  const response = page.waitForResponse(row => row.url().endsWith('/osv-jobs') && row.request().method() === 'POST'); f.release(); await response; await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByText('OSV job recorded.', { exact: false })).toHaveCount(0); await expect(page.getByText('Frozen OSV matching request', { exact: true })).toHaveCount(0)
})

test('selected draft blocks first enqueue after workspace head advances until an explicit fresh plan', async ({ page }) => {
  const f = await fixture(page); await open(page); await f.panel.getByRole('checkbox').first().check(); f.advance()
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(f.panel.getByRole('button', { name: 'Queue selected OSV queries', exact: true })).toBeDisabled()
  await expect(f.panel.getByLabel('Explicitly selected OSV packages')).toContainText(packages[0]!)
  expect(f.requests).toHaveLength(0)
  await f.panel.getByRole('button', { name: 'Refresh OSV package plan', exact: true }).click(); await f.panel.getByRole('checkbox').first().check()
  await f.panel.getByRole('button', { name: 'Queue selected OSV queries', exact: true }).click()
  await expect.poll(() => f.requests.length).toBe(1); expect(f.requests[0]!.body.expected_versions).toEqual({ '7.1.2': sha('9') })
})


test('uncertain enqueue and job actions block product and application navigation until explicit discard', async ({ page }) => {
  const f = await fixture(page); await open(page); await f.panel.getByRole('checkbox').first().check(); f.fail(503)
  await f.panel.getByRole('button', { name: 'Queue selected OSV queries', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Recording uncertain')
  const product = page.getByRole('button', { name: 'Product scope', exact: false })
  const applicationNav = page.getByRole('navigation', { name: 'Main navigation', exact: true }).getByRole('button', { name: 'Products', exact: true })
  await expect(product).toBeDisabled(); await expect(applicationNav).toBeDisabled()
  await f.panel.getByRole('button', { name: 'Discard OSV request capture', exact: true }).click()
  await expect(product).toBeEnabled(); await expect(applicationNav).toBeEnabled()
  await f.panel.getByRole('button', { name: 'Retry OSV job', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Captured job action is retained')
  await expect(product).toBeDisabled(); await expect(applicationNav).toBeDisabled()
  await f.panel.getByRole('button', { name: 'Discard captured OSV job action', exact: true }).click()
  await expect(product).toBeEnabled(); await expect(applicationNav).toBeEnabled()
})

test('status refresh rejects a different job id, kind or frozen scope without replacing the requested job', async ({ page }) => {
  const f = await fixture(page); await open(page)
  const job = f.panel.getByRole('article', { name: 'OSV job saved-job', exact: true })
  for (const mode of ['id', 'kind', 'scope']) {
    f.mismatch(mode); await job.getByRole('button', { name: 'Refresh OSV job status', exact: true }).click()
    await expect(f.panel.getByRole('alert')).toContainText('OSV status response differs from the requested job or its frozen scope')
    await expect(job.locator('strong')).toContainText('failed')
  }
  expect(f.requests).toHaveLength(0)
})
