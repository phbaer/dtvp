import { openNativeTools, openProductTask } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const sha = (value: string) => value.repeat(64)
async function fixture(page: Page, options: { readonly?: boolean; personas?: boolean; hold?: boolean } = {}) {
  let actor = 'person', pin = sha('a'), failure = 0, projection = 'current', release: (() => void) | undefined
  let schedules: unknown[] = options.readonly ? [{ provider: 'circl', versions: ['7.1.1'], interval_seconds: 3600, batch_size: 10 }] : []
  const writes: Record<string, unknown>[] = [], reads: string[] = []
  await page.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname
    if (path.endsWith('/playground/login')) { actor = request.postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (path.endsWith('/advisory-schedule') && request.method() === 'PUT') {
      const body = request.postDataJSON(); writes.push(body)
      if (options.hold) await new Promise<void>(resolve => { release = resolve })
      if (failure) return route.fulfill({ status: failure, json: { detail: 'Schedule request uncertain; retained.' } })
      pin = sha('b'); schedules = body.providers
      return route.fulfill({ json: { committed: true, projection } })
    }
    reads.push(path)
    let result: unknown = { items: [], capabilities: [], next_cursor: null, next_offset: null }
    if (path === '/api/v1/me') result = { id: actor, name: actor, playground: !!options.personas, org_admin: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path.endsWith('/playground/personas')) result = options.personas ? [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state: sha('f') }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state: sha('f'), project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/advisory-refresh')) result = { expected_versions: { '7.1.1': sha('f') }, expected_evidence: null, providers: [{ id: 'circl', publisher: 'CVE mirror', enabled: true, next_revision: 0 }, { id: 'nvd', publisher: 'NVD', enabled: false, next_revision: 0 }], identifiers: [], total: 0, next_offset: null, capabilities: [], limitations: [] }
    else if (path.endsWith('/advisory-schedule')) result = { state: pin, providers: schedules, actor_id: 'policy-author', capabilities: options.readonly ? [] : ['configure'], provider_minimum_seconds: { nvd: 6, circl: 1 }, limitations: ['Only exact known identifiers; no approval.'] }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Product', exact: true }).click()
  await openProductTask(page, 'Settings', 'Advisories')
  const panel = page.getByLabel('Automatic advisory refresh schedule', { exact: true })
  await expect(panel).toContainText('configured providers')
  return { panel, writes, reads, fail: (status: number) => { failure = status }, advance: () => { pin = sha('c') }, pending: () => { projection = 'pending' }, current: () => { projection = 'current' }, release: () => release?.() }
}
async function prepare(panel: ReturnType<Page['getByLabel']>) {
  await panel.getByRole('combobox', { name: 'Schedule provider', exact: true }).selectOption('circl')
  await panel.getByRole('button', { name: 'Add scheduled provider', exact: true }).click()
  await panel.getByLabel('Versions (one per line)', { exact: true }).fill('7.1.1\n7.1.2')
  await panel.getByLabel('Refresh interval (seconds)', { exact: true }).fill('3600')
  await panel.getByLabel('Maximum IDs per batch', { exact: true }).fill('10')
  await panel.getByRole('button', { name: 'Review schedule changes', exact: true }).click()
}
test('policy capture is local; publishing requires confirmation and exact retries survive changed heads', async ({ page }) => {
  const { panel, writes, fail, advance } = await fixture(page)
  await expect(panel.getByRole('combobox', { name: 'Schedule provider', exact: true }).getByRole('option')).toHaveCount(2)
  await prepare(panel)
  expect(writes).toHaveLength(0)
  await expect(panel.getByRole('button', { name: 'Publish advisory schedule', exact: true })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  await expect(page.locator('[data-product-view="Vulnerabilities"]')).toBeDisabled()
  await panel.getByRole('checkbox').check(); fail(503)
  await panel.getByRole('button', { name: 'Publish advisory schedule', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('uncertain')
  advance(); await panel.getByRole('button', { name: 'Refresh schedule configuration', exact: true }).click()
  await expect(panel).toContainText('original pin')
  fail(0); await panel.getByRole('button', { name: 'Retry identical schedule publication', exact: true }).click()
  await expect(panel.getByRole('status')).toContainText('schedule saved')
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1])
  expect(writes[0]).toMatchObject({ expected_policy: sha('a'), providers: [{ provider: 'circl', versions: ['7.1.1', '7.1.2'], interval_seconds: 3600, batch_size: 10 }] })
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
})
test('empty replacement explicitly stops scheduling and pending projection retains exact receipt', async ({ page }) => {
  const { panel, writes, pending, current } = await fixture(page)
  await panel.getByRole('button', { name: 'Review schedule changes', exact: true }).click()
  await expect(panel).toContainText('New scheduling stops')
  await panel.getByRole('checkbox').check(); pending()
  await panel.getByRole('button', { name: 'Publish advisory schedule', exact: true }).click()
  await expect(panel.getByRole('status')).toContainText('projection pending')
  current(); await panel.getByRole('button', { name: 'Refresh committed schedule receipt', exact: true }).click()
  await expect(panel.getByRole('status')).toContainText('schedule saved')
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1]); expect(writes[0]!.providers).toEqual([])
})
test('reader sees scoped policy without editing controls and narrow layout stays bounded', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes } = await fixture(page, { readonly: true })
  await expect(panel).toContainText('circl · 7.1.1 · every 3600 seconds')
  await expect(panel.getByRole('button', { name: 'Review schedule changes', exact: true })).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy()
  expect(writes).toHaveLength(0)
})
test('discard releases the captured schedule and restores current policy fields', async ({ page }) => {
  const { panel, writes } = await fixture(page)
  await prepare(panel)
  await panel.getByRole('button', { name: 'Discard schedule draft', exact: true }).click()
  await expect(panel.getByLabel('Captured advisory schedule', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
  expect(writes).toHaveLength(0)
})
test('actor roundtrip invalidates a late schedule response', async ({ page }) => {
  const { panel, writes, release } = await fixture(page, { personas: true, hold: true })
  await prepare(panel); await panel.getByRole('checkbox').check()
  await panel.getByRole('button', { name: 'Publish advisory schedule', exact: true }).click()
  await expect.poll(() => writes.length).toBe(1)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  const response = page.waitForResponse(item => item.url().endsWith('/advisory-schedule') && item.request().method() === 'PUT')
  release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByText('Advisory schedule saved.', { exact: false })).toHaveCount(0)
  await expect(page.getByLabel('Captured advisory schedule', { exact: true })).toHaveCount(0)
})
