import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'

const stateSha = 'a'.repeat(64), updatedState = 'b'.repeat(64)
const externalA = '11111111-1111-4111-8111-111111111111', externalB = '22222222-2222-4222-8222-222222222222', externalC = '33333333-3333-4333-8333-333333333333'
const sourceJob = (id = 'source-job', status = 'failed', capabilities: string[] = ['retry']) => ({ id, status, version: '7.1.2', expected: stateSha, external_project_id: externalA, build_number: 41, attempts: 1, created_at: '2026-10-15T12:00:00Z', error: '', result: { capture_sha256: 'c'.repeat(64), remote_snapshot_consistent: false }, capabilities })
async function fixture(page: Page, options: { readonly?: boolean; configured?: boolean; enqueueResponses?: number[] } = {}) {
  const reads: { path: string; query: URLSearchParams }[] = [], writes: { method: string; path: string; body: Record<string, unknown> }[] = []
  let state = stateSha, external = externalA, enqueues = 0
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (request.method() !== 'GET') {
      const body = request.postDataJSON()
      writes.push({ method: request.method(), path, body })
      if (path.endsWith('/connectors/dependency-track')) {
        if (body.expected_external_project_id !== external) return route.fulfill({ status: 409, json: { detail: 'DT version binding changed; reload before replacing it' } })
        external = body.external_project_id
        return route.fulfill({ json: { project_id: external } })
      }
      if (path.endsWith('/imports/dependency-track/jobs')) {
        const status = options.enqueueResponses?.[enqueues++] || 202
        if (status !== 202) return route.fulfill({ status, json: { detail: status === 409 ? 'Source baseline changed; refresh before a new request' : 'Enqueue response uncertain; retry the same request ID' } })
        return route.fulfill({ status, json: sourceJob('requested-source', 'queued', ['cancel']) })
      }
      if (path.endsWith('/retry')) return route.fulfill({ status: 202, json: sourceJob('source-job', 'queued', ['cancel']) })
      if (path.endsWith('/cancel')) return route.fulfill({ json: sourceJob('source-job', 'cancelled', []) })
      return route.fulfill({ status: 403, json: { detail: 'Unexpected mutation' } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path.endsWith('/connectors/dependency-track')) { reads.push({ path, query: new URLSearchParams(url.search) }); result = { project_id: external, configured: options.configured !== false, capabilities: options.readonly ? [] : ['bind', 'import'] } }
    else if (path.endsWith('/source-jobs')) { reads.push({ path, query: new URLSearchParams(url.search) }); const later = url.searchParams.get('offset') === '20'; result = { items: [sourceJob(later ? 'older-source' : 'source-job', 'failed', options.readonly ? [] : ['retry'])], next_offset: later ? null : 20 } }
    else if (path.includes('/source-jobs/')) { reads.push({ path, query: new URLSearchParams(url.search) }); result = sourceJob(path.split('/').at(-1)!, 'failed', options.readonly ? [] : ['retry']) }
    else if (path === '/api/v1/me') result = { id: 'reader', name: 'Reader', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Source product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.2', state }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state, project_id: 'product', version: '7.1.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Source product', exact: true }).click()
  return { reads, writes, panel: page.getByRole('region', { name: 'Dependency-Track source imports', exact: true }), rebind: () => { external = externalB }, advance: () => { state = updatedState } }
}

async function open(page: Page) { await page.locator('.knowledge-sources > summary').click() }
async function inputImport(page: Page) {
  const form = page.getByRole('form', { name: 'Request DT source import', exact: true })
  await form.getByLabel('Source build number', { exact: true }).fill('42')
  await form.getByLabel('Observed at (ISO 8601 with timezone)', { exact: true }).fill('2026-10-15T14:30:00+02:00')
  return form
}

test('readers see explicit version binding and bounded retained captures without write actions', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const state = await fixture(page, { readonly: true })
  expect(state.reads).toHaveLength(0)
  await open(page)
  await expect(state.panel).toContainText(externalA)
  await expect(state.panel).toContainText('accepted source authority cannot be switched here')
  await expect(state.panel).toContainText('without automatic writeback')
  await expect(state.panel).toContainText('does not guarantee one consistent remote snapshot')
  await expect(state.panel.getByRole('form')).toHaveCount(0)
  await expect(state.panel.getByRole('button', { name: /retry|cancel|queue/i })).toHaveCount(0)
  await state.panel.getByRole('button', { name: 'Next source jobs', exact: true }).click()
  expect(state.reads.at(-1)?.query.get('offset')).toBe('20')
  expect(state.reads.at(-1)?.query.get('limit')).toBe('20')
  await state.panel.getByRole('button', { name: 'Refresh import status', exact: true }).click()
  expect(state.reads.at(-1)?.path).toBe('/api/v1/projects/product/source-jobs/older-source')
  expect(state.writes).toHaveLength(0)
  expect(await state.panel.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
})

test('binding replacement uses exact previous UUID and retains proposed UUID across conflicts', async ({ page }) => {
  const state = await fixture(page)
  await open(page)
  await state.panel.getByText('Edit version-specific DT binding', { exact: true }).click()
  const form = state.panel.getByRole('form', { name: 'DT project binding', exact: true })
  await form.getByLabel('External DT project UUID', { exact: true }).fill(externalC)
  state.rebind()
  await form.getByRole('button', { name: 'Save DT binding', exact: true }).click()
  await expect(state.panel.getByRole('alert')).toContainText('binding changed')
  await expect(form.getByLabel('External DT project UUID', { exact: true })).toHaveValue(externalC)
  await state.panel.getByRole('button', { name: 'Refresh source configuration and jobs', exact: true }).click()
  await expect(state.panel).toContainText(externalB)
  await expect(form.getByLabel('External DT project UUID', { exact: true })).toHaveValue(externalC)
  await form.getByRole('button', { name: 'Save DT binding', exact: true }).click()
  await expect(state.panel.getByRole('status')).toContainText('No source data was imported.')
  expect(state.writes.map(write => [write.method, write.body])).toEqual([['PUT', { external_project_id: externalC, expected_external_project_id: externalA }], ['PUT', { external_project_id: externalC, expected_external_project_id: externalB }]])
})

for (const status of [409, 503]) {
  test(`DT enqueue ${status} retains explicit build/time and retries exactly the same request identity`, async ({ page }) => {
    const state = await fixture(page, { enqueueResponses: [status, 202] })
    await open(page)
    const form = await inputImport(page)
    await form.getByRole('button', { name: 'Queue DT import', exact: true }).click()
    await expect(form.getByRole('alert')).toContainText(status === 409 ? 'Source baseline changed' : 'Enqueue response uncertain')
    await expect(form.getByLabel('Source build number', { exact: true })).toHaveValue('42')
    await expect(form.getByLabel('Observed at (ISO 8601 with timezone)', { exact: true })).toHaveValue('2026-10-15T14:30:00+02:00')
    expect(state.writes).toHaveLength(1)
    await form.getByRole('button', { name: 'Queue DT import', exact: true }).click()
    await expect(state.panel.getByRole('status')).toContainText('DT import request recorded.')
    expect(state.writes[1]?.body).toEqual(state.writes[0]?.body)
    expect(state.writes[0]?.body).toEqual({ expected: stateSha, build_number: 42, occurred_at: '2026-10-15T14:30:00+02:00', request_id: expect.stringMatching(/^[0-9a-f-]{36}$/) })
    await expect(state.panel.getByRole('article', { name: 'DT import job requested-source', exact: true })).toContainText('Requested import')
  })
}

test('missing timezone prevents enqueue and deployment availability remains separate from permissions', async ({ page }) => {
  const state = await fixture(page)
  await open(page)
  const form = await inputImport(page)
  await form.getByLabel('Observed at (ISO 8601 with timezone)', { exact: true }).fill('2026-10-15T14:30:00')
  await form.getByRole('button', { name: 'Queue DT import', exact: true }).click()
  await expect(form.getByRole('alert')).toContainText('explicit timezone')
  expect(state.writes).toHaveLength(0)
})

test('unconfigured DT deployment exposes no endpoint or credential and cannot enqueue', async ({ page }) => {
  const state = await fixture(page, { configured: false })
  await open(page)
  const form = await inputImport(page)
  await expect(state.panel).toContainText('Their values are not exposed here.')
  await expect(form.getByRole('button', { name: 'Queue DT import', exact: true })).toBeDisabled()
  expect(state.writes).toHaveLength(0)
})

test('source retry/cancel actions require server capabilities and a new state clears import inputs', async ({ page }) => {
  const state = await fixture(page)
  await open(page)
  await state.panel.getByRole('button', { name: 'Retry DT import', exact: true }).click()
  await expect(state.panel.getByRole('article')).toContainText('queued')
  await state.panel.getByRole('button', { name: 'Cancel DTVP import job', exact: true }).click()
  await expect(state.panel.getByRole('article')).toContainText('cancelled')
  expect(state.writes.map(write => write.path)).toEqual(['/api/v1/projects/product/source-jobs/source-job/retry', '/api/v1/projects/product/source-jobs/source-job/cancel'])
  await inputImport(page)
  state.advance()
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(state.panel).toContainText(updatedState)
  await expect(state.panel.getByLabel('Source build number', { exact: true })).toBeEmpty()
  await expect(state.panel.getByLabel('Observed at (ISO 8601 with timezone)', { exact: true })).toBeEmpty()
  expect(state.writes).toHaveLength(2)
})
