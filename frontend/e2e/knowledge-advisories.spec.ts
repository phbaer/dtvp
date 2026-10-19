import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'

async function fixture(page: Page, readonly = false) {
  let changed = false, status = 0
  const writes: { path: string; body: Record<string, unknown> }[] = [], queries: URL[] = []
  const job = { id: 'existing', status: 'import_pending', provider: 'circl', identifiers: ['CVE-2099-0001'], revision: 3, expected_versions: { '7.1.1': 'old-head' }, expected_evidence: 'old-evidence', attempts: 1, error: 'Frozen publication pending', result: { capture_sha256: 'capture-sha', provider: 'circl', publisher: 'CVE Project mirror', not_found: ['CVE-2099-0001'] }, capabilities: readonly ? [] : ['retry'] }
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname; queries.push(url)
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON(); writes.push({ path, body })
      if (path.endsWith('/advisory-jobs') && status) return route.fulfill({ status, json: { detail: 'Uncertain enqueue; resend the identical request.' } })
      return route.fulfill({ status: 202, json: { ...job, id: path.endsWith('/advisory-jobs') ? 'new-job' : 'existing', status: path.endsWith('/cancel') ? 'cancelled' : 'queued', capabilities: readonly ? [] : ['cancel'] } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: 'person', name: 'Person', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read'] }] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state: 'old-head' }] }
    else if (path.endsWith('/workspace')) result = { state: 'old-head', project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/advisory-refresh')) result = { expected_versions: { '7.1.1': changed ? 'new-head' : 'old-head', '7.1.2': 'parallel-head' }, expected_evidence: changed ? 'new-evidence' : 'old-evidence', providers: [{ id: 'circl', publisher: 'CVE Project mirror', enabled: true, next_revision: changed ? 4 : 3 }, { id: 'nvd', publisher: 'NVD', enabled: false, next_revision: 0 }, { id: 'jvn', publisher: 'MyJVN API', enabled: true, next_revision: 0, identifier_formats: ['JVNDB'] }], unsupported_total: url.searchParams.get('provider') === 'jvn' ? 21 : 0, identifiers: url.searchParams.get('provider') === 'jvn' ? ['JVNDB-2099-000001'] : url.searchParams.get('offset') === '20' ? ['CVE-2099-0021'] : Array.from({ length: 20 }, (_, i) => `CVE-2099-${String(i + 1).padStart(4, '0')}`), total: 21, next_offset: url.searchParams.get('offset') === '20' ? null : 20, capabilities: readonly ? [] : ['refresh'], limitations: ['Publisher identity is unverified; no automatic approval.'] }
    else if (path.endsWith('/advisory-jobs')) result = { items: [job], next_offset: url.searchParams.get('offset') === '20' ? null : 20 }
    else if (path.includes('/advisory-jobs/')) result = { ...job, status: 'succeeded', capabilities: [] }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Product', exact: true }).click()
  expect(queries.some(url => url.pathname.endsWith('/advisory-refresh'))).toBeFalsy()
  await page.getByText('Advisory intelligence refresh', { exact: true }).click()
  const panel = page.getByLabel('Advisory intelligence refresh', { exact: true })
  await expect(panel).toContainText('21 matching baseline IDs')
  await expect(panel.getByLabel('Advisory job existing')).toBeVisible()
  return { panel, writes, queries, change: () => { changed = true }, fail: (code: number) => { status = code } }
}

test('refresh is explicit, bounded to20 exact selected IDs and provider availability', async ({ page }) => {
  const { panel, writes } = await fixture(page)
  const queue = panel.getByLabel('Queue advisory refresh', { exact: true })
  await expect(queue.getByRole('button', { name: 'Queue advisory refresh', exact: true })).toBeDisabled()
  await expect(queue.getByLabel('Advisory provider')).toHaveValue('')
  await expect(queue.getByRole('option', { name: /nvd.*disabled/ })).toHaveJSProperty('disabled', true)
  await queue.getByLabel('Advisory provider').selectOption('circl')
  for (const checkbox of await panel.locator('.identifiers input').all()) await checkbox.check()
  await panel.getByRole('button', { name: 'Next advisory identifiers', exact: true }).click()
  await expect(panel.getByRole('checkbox', { name: 'CVE-2099-0021', exact: true })).toBeDisabled()
  await queue.getByRole('button', { name: 'Queue advisory refresh', exact: true }).click()
  await expect.poll(() => writes.length).toBe(1)
  expect(writes[0]!.body).toMatchObject({ provider: 'circl', expected_evidence: 'old-evidence', expected_versions: { '7.1.1': 'old-head', '7.1.2': 'parallel-head' }, revision: 3 })
  expect(writes[0]!.body.identifiers).toHaveLength(20)
  await expect(panel.getByRole('status')).toContainText('job recorded')
})

test('503 retries identical request despite explicit plan refresh changing heads and provider ordinal', async ({ page }) => {
  const { panel, writes, change, fail } = await fixture(page)
  const queue = panel.getByLabel('Queue advisory refresh', { exact: true })
  await queue.getByLabel('Advisory provider').selectOption('circl')
  await panel.getByRole('checkbox', { name: 'CVE-2099-0001', exact: true }).check()
  fail(503)
  await queue.getByRole('button', { name: 'Queue advisory refresh', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Uncertain enqueue')
  change()
  await panel.getByRole('button', { name: 'Refresh advisory plan', exact: true }).click()
  await queue.getByRole('button', { name: 'Resend identical advisory request', exact: true }).click()
  await expect.poll(() => writes.length).toBe(2)
  expect(writes[1]!.body).toEqual(writes[0]!.body)
  expect(writes[1]!.body).toMatchObject({ expected_evidence: 'old-evidence', revision: 3 })
  await queue.getByText('Frozen pending advisory request', { exact: true }).click()
  await expect(queue).toContainText('old-head')
  await queue.getByRole('button', { name: 'Start new advisory request', exact: true }).click()
  await expect(queue.getByRole('button', { name: 'Queue advisory refresh', exact: true })).toBeDisabled()
  expect(writes).toHaveLength(2)
})

test('page pin changes retain selected identifiers and require an explicit new plan', async ({ page }) => {
  const { panel, writes, change } = await fixture(page)
  await panel.getByRole('checkbox', { name: 'CVE-2099-0001', exact: true }).check()
  change()
  await panel.getByRole('button', { name: 'Next advisory identifiers', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('plan changed')
  await expect(panel.getByRole('checkbox', { name: 'CVE-2099-0001', exact: true })).toBeChecked()
  await panel.getByRole('button', { name: 'Refresh advisory plan', exact: true }).click()
  await expect(panel.getByRole('checkbox', { name: 'CVE-2099-0001', exact: true })).not.toBeChecked()
  expect(writes).toHaveLength(0)
})

test('job actions follow server capabilities and only explicit GET refreshes status', async ({ page }) => {
  const { panel, writes, queries } = await fixture(page)
  const job = panel.getByLabel('Advisory job existing', { exact: true })
  await expect(job.getByRole('button', { name: 'Cancel DTVP advisory job', exact: true })).toHaveCount(0)
  await job.getByRole('button', { name: 'Retry advisory job', exact: true }).click()
  await expect(job.getByRole('button', { name: 'Cancel DTVP advisory job', exact: true })).toBeVisible()
  await job.getByRole('button', { name: 'Cancel DTVP advisory job', exact: true }).click()
  await expect.poll(() => writes.length).toBe(2)
  expect(writes.map(item => item.path)).toEqual(['/api/v1/projects/product/advisory-jobs/existing/retry', '/api/v1/projects/product/advisory-jobs/existing/cancel'])
  await job.getByRole('button', { name: 'Refresh advisory status', exact: true }).click()
  await expect(job).toContainText('succeeded')
  await job.getByText('Advisory job pins and capture result', { exact: true }).click()
  await expect(job).toContainText('not_found')
  await expect(panel).toContainText('not-found response never proves remediation')
  await panel.getByRole('button', { name: 'Next advisory jobs', exact: true }).click()
  await expect(panel.getByRole('button', { name: 'Next advisory jobs', exact: true })).toBeDisabled()
  expect(queries.some(url => url.search === '?offset=20&limit=20' && url.pathname.endsWith('/advisory-jobs'))).toBeTruthy()
})

test('readonly role sees provenance and jobs with no enqueue or retry controls in narrow layout', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes } = await fixture(page, true)
  await expect(panel.getByLabel('Queue advisory refresh', { exact: true })).toHaveCount(0)
  await expect(panel.getByRole('button', { name: 'Retry advisory job', exact: true })).toHaveCount(0)
  await expect(panel.getByRole('checkbox', { name: 'CVE-2099-0001', exact: true })).toBeDisabled()
  await panel.getByText('Provider availability and plan pins', { exact: true }).click()
  await expect(panel).toContainText('publisher CVE Project mirror')
  await expect(page.locator('body')).toHaveJSProperty('scrollWidth', 390)
  expect(writes).toHaveLength(0)
})


test('provider switches clear prior selections and explain unsupported baseline IDs', async ({ page }) => {
  const { panel, writes, queries } = await fixture(page)
  const queue = panel.getByLabel('Queue advisory refresh', { exact: true })
  await queue.getByLabel('Advisory provider').selectOption('circl')
  await panel.getByRole('checkbox', { name: 'CVE-2099-0001', exact: true }).check()
  await queue.getByLabel('Advisory provider').selectOption('jvn')
  await expect(panel).toContainText('21 baseline IDs unsupported by jvn; these have not been looked up.')
  await expect(panel).toContainText('Supported exact IDs: JVNDB')
  await expect(panel.getByRole('checkbox', { name: 'CVE-2099-0001', exact: true })).toHaveCount(0)
  await expect(queue.getByRole('button', { name: 'Queue advisory refresh', exact: true })).toBeDisabled()
  await panel.getByRole('checkbox', { name: 'JVNDB-2099-000001', exact: true }).check()
  await queue.getByRole('button', { name: 'Queue advisory refresh', exact: true }).click()
  await expect.poll(() => writes.length).toBe(1)
  expect(writes[0]!.body).toMatchObject({ provider: 'jvn', identifiers: ['JVNDB-2099-000001'] })
  expect(queries.some(url => url.pathname.endsWith('/advisory-refresh') && url.searchParams.get('provider') === 'jvn')).toBeTruthy()
})
