import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const sha = (char: string) => char.repeat(64), state = sha('a'), policy = sha('b')
async function fixture(page: Page, writable = true) {
  let actor = 'person', fail = false, held = false, wrongContext = false, release: (() => void) | undefined
  const writes: { method: string; path: string; body: unknown }[] = []
  const job = (status = 'succeeded') => ({ id: 'job-one', kind: 'propose-sync-native', status, stale: false, inputs: { source: sha('c'), target: state, relationship: { relationship_id: 'patches' } }, capabilities: writable && status === 'failed' ? ['retry'] : [], error: '', result: {} })
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (path.endsWith('/playground/login')) { actor = request.postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (request.method() === 'PUT' || request.method() === 'POST') {
      writes.push({ method: request.method(), path, body: request.postData() ? request.postDataJSON() : null })
      if (held) { held = false; await new Promise<void>(resolve => { release = resolve }) }
      if (fail) return route.fulfill({ status: 503, json: { detail: 'Uncertain operation' } })
      return route.fulfill({ json: request.method() === 'PUT' ? { committed: true } : job('queued') })
    }
    let data: unknown = { items: [], capabilities: [], next_offset: null }
    if (path === '/api/v1/me') data = { id: actor, name: actor, playground: true, org_admin: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path.endsWith('/playground/personas')) data = [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }]
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'product', name: 'Product' }], next_cursor: null }
    else if (path === '/api/v1/projects/product') data = { id: 'product', name: 'Product' }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.2', state }] }
    else if (path.endsWith('/workspace')) data = { state, project_id: 'product', version: '7.1.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/pipeline-config')) data = { configuration_state: policy, expected_versions: { '7.1.2': state }, configuration: { format: 'dtvp.pipeline-configuration/1', parts: [], models: [], mappings: [] }, capabilities: writable ? ['configure'] : [] }
    else if (path.endsWith('/pipeline-context')) data = { inventory_state: wrongContext ? sha('9') : state, configuration_state: policy, digest: sha('e'), total: 21, unmapped: 0, next_offset: url.searchParams.get('offset') === '20' ? null : 20, rows: [{ component_ref: url.searchParams.get('offset') === '20' ? 'second-component' : 'first-component', context_id: 'context', status: 'mapped', mappings: [{ mapping_id: 'map', model_id: 'device', model_revision: 'revision-1', entity_ids: ['engine'] }] }] }
    else if (path.endsWith('/synchronization-policy')) data = { state: policy, relationships: [], capabilities: writable ? ['configure'] : [], limitations: [] }
    else if (path.endsWith('/synchronization-jobs')) data = { items: [job(url.searchParams.get('offset') === '20' ? 'failed' : 'succeeded')], next_offset: url.searchParams.get('offset') === '20' ? null : 20 }
    else if (path.endsWith('/proposal')) data = { job_id: 'job-one', source: sha('c'), target: state, stale: false, preview_digest: sha('d'), total: 1, next_offset: null, items: [{ id: 'row', vulnerability_id: 'CVE-2099-10', category: 'needs_review', reasons: ['Independent review required'] }] }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click(); await page.getByRole('option', { name: 'Product', exact: true }).click()
  await openProductView(page, 'Settings', 'Pipeline & threat models')
  return { writes, wrongContext: () => { wrongContext = true }, fail: (value: boolean) => { fail = value }, hold: () => { held = true }, release: () => release?.() }
}
async function pipeline(page: Page) { await openDisclosure(page.getByText('Pipeline source roles and threat-model mappings', { exact: true })); return page.getByRole('region', { name: 'Pipeline source roles and threat-model mappings', exact: true }) }
test('readonly pipeline configuration exposes declarations without a write control', async ({ page }) => {
  const f = await fixture(page, false), panel = await pipeline(page)
  await expect(panel).toContainText('dtvp.pipeline-configuration/1')
  await expect(panel.getByRole('textbox')).toHaveCount(0)
  await expect(panel.getByRole('button', { name: 'Review configuration replacement' })).toHaveCount(0)
  expect(f.writes).toHaveLength(0)
})
test('configuration publication retains exact failed request and pins until explicit retry', async ({ page }) => {
  const f = await fixture(page), panel = await pipeline(page)
  await panel.getByLabel('Pipeline configuration JSON', { exact: true }).fill(JSON.stringify({ format: 'dtvp.pipeline-configuration/1', parts: [{ part_id: null, authority_source: 'build', observation_sources: ['scanner'] }], models: [], mappings: [] }))
  await panel.getByLabel('Configuration replacement reason').fill('CI owner binds nightly source roles')
  await panel.getByRole('button', { name: 'Review configuration replacement' }).click()
  await panel.getByLabel('I reviewed this configuration replacement').check()
  f.fail(true); await panel.getByRole('button', { name: 'Publish captured configuration' }).click()
  await expect(panel.getByRole('alert')).toContainText('Captured request retained')
  await expect(panel.getByLabel('Pipeline configuration JSON', { exact: true })).toBeDisabled()
  await expect(panel.getByRole('button', { name: 'Refresh configuration' })).toBeDisabled()
  f.fail(false); await panel.getByRole('button', { name: 'Publish captured configuration' }).click()
  await expect(panel.getByRole('status')).toContainText('Configuration committed')
  expect(f.writes).toHaveLength(2); expect(f.writes[1]).toEqual(f.writes[0])
  expect(f.writes[0]!.body).toMatchObject({ expected_policy: policy, expected_versions: { '7.1.2': state } })
})
test('automatic proposals are read-only and job actions require explicit captured retries', async ({ page }) => {
  const f = await fixture(page)
  await openProductView(page, 'Settings', 'Automation schedules')
  await openDisclosure(page.getByText('Automatic synchronization proposals', { exact: true }))
  const panel = page.getByRole('region', { name: 'Automatic synchronization', exact: true })
  await panel.getByRole('button', { name: 'Inspect proposal job-one', exact: true }).click()
  await expect(panel.getByRole('region', { name: 'Frozen automatic proposal' })).toContainText('CVE-2099-10')
  expect(f.writes).toHaveLength(0)
  await panel.getByRole('button', { name: 'Next synchronization jobs' }).click()
  f.fail(true); await panel.getByRole('button', { name: 'retry job-one', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Captured action retained')
  f.fail(false); await panel.getByRole('button', { name: 'Retry captured action job-one', exact: true }).click()
  expect(f.writes).toHaveLength(2); expect(f.writes[1]).toEqual(f.writes[0])
  await expect(panel).toContainText('queued')
})
test('actor roundtrip cannot restore a late configuration receipt', async ({ page }) => {
  const f = await fixture(page), panel = await pipeline(page)
  await panel.getByLabel('Configuration replacement reason').fill('Reviewed CI metadata')
  await panel.getByRole('button', { name: 'Review configuration replacement' }).click(); await panel.getByLabel('I reviewed this configuration replacement').check()
  f.hold(); await panel.getByRole('button', { name: 'Publish captured configuration' }).click()
  await expect.poll(() => f.writes.length).toBe(1)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other'); await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  const response = page.waitForResponse(row => row.request().method() === 'PUT'); f.release(); await response
  await expect(page.getByRole('region', { name: 'Captured configuration replacement' })).toHaveCount(0)
  await expect(page.getByText('Configuration committed. No assessment or approval was applied.', { exact: true })).toHaveCount(0)
})

test('resolved model mappings retain exact pins, reject mismatched pages and fit mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const f = await fixture(page); await pipeline(page)
  await page.getByText('Resolved threat-model mappings', { exact: true }).click()
  await page.getByRole('button', { name: 'Inspect pinned model mappings', exact: true }).click()
  const context = page.getByRole('region', { name: 'Resolved pipeline context', exact: true })
  await expect(context).toContainText('first-component'); await expect(context).toContainText('device · revision-1 · engine')
  f.wrongContext(); await context.getByRole('button', { name: 'Next resolved model mappings', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('changed its requested inventory/configuration pins')
  await expect(context).toContainText('first-component'); await expect(context).not.toContainText('second-component')
  expect(f.writes).toHaveLength(0)
  expect(await page.locator('body').evaluate(row => row.scrollWidth)).toBeLessThanOrEqual(390)
})
