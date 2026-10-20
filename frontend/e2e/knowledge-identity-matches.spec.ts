import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const sha = (char: string) => char.repeat(64), source = sha('a'), target = sha('b'), digest = sha('c')
async function fixture(page: Page, personas = false) {
  let actor = 'person', responseDigest = digest, failure = 0, hold = false, release: (() => void) | undefined
  const reads: URL[] = [], mutations: string[] = []
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (path.endsWith('/playground/login')) { actor = request.postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (request.method() !== 'GET') { mutations.push(path); return route.fulfill({ status: 400, json: { detail: 'Unexpected mutation' } }) }
    let data: unknown = { items: [], capabilities: [], next_cursor: null, next_offset: null }
    if (path === '/api/v1/me') data = { id: actor, name: actor, playground: personas, org_admin: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path.endsWith('/playground/personas')) data = personas ? [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'product', name: 'Product' }], next_cursor: null }
    else if (path === '/api/v1/projects/product') data = { id: 'product', name: 'Product' }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.2', state: target }] }
    else if (path.endsWith('/workspace')) data = { state: target, project_id: 'product', version: '7.1.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/reconciliations')) data = { items: [], total: 0, next_offset: null, capabilities: [] }
    else if (path.endsWith('/refs')) data = { items: [{ kind: 'tag', name: '7.1.1', version: '7.1.1', state: source }], next_offset: null }
    else if (path.endsWith('/identity-matches')) {
      reads.push(url)
      if (hold) { hold = false; await new Promise<void>(resolve => { release = resolve }) }
      if (failure) return route.fulfill({ status: failure, json: { detail: 'Identity comparison unavailable' } })
      const later = url.searchParams.get('offset') === '20'
      data = { format: 'dtvp.identity-matches/1', source: url.searchParams.get('source'), target, report_digest: responseDigest, summary: { matched: 21, unresolved: 101, scope_compatible: true }, items: [{ kind: 'component', source_id: later ? 'old-two' : 'old-one', target_id: later ? 'new-two' : '<script>window.identityInjected=true</script>', basis: later ? 'scoped_strong_digest' : 'exact_purl', scope: { part_id: null, role: 'component' } }], total: 21, next_offset: later ? null : 20, unresolved: [{ current_ref: 'legacy-common', reason: 'insufficient_identity', candidate_count: 0 }], diagnostics_truncated: true, limitations: ['No context or assessment equivalence is established.'] }
    }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click(); await page.getByRole('option', { name: 'Product', exact: true }).click()
  await openProductView(page, 'Imports')
  await openDisclosure(page.getByText('Occurrence correspondence across imports', { exact: true }))
  await page.getByText('Component identity continuity', { exact: true }).click()
  const panel = page.getByRole('region', { name: 'Component identity comparison', exact: true })
  return { panel, reads, mutations, select: () => page.getByRole('combobox', { name: 'Source branch or tag', exact: true }).selectOption(source), digest: (value: string) => { responseDigest = value }, fail: (value: number) => { failure = value }, hold: () => { hold = true }, release: () => release?.() }
}
test('identity report is manual, readonly, paged, escaped and distinguishes bounded diagnostics on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 }); const f = await fixture(page)
  expect(f.reads).toHaveLength(0); await expect(f.panel.getByRole('button', { name: 'Inspect component identity matches', exact: true })).toBeDisabled()
  await f.select(); expect(f.reads).toHaveLength(0)
  await f.panel.getByRole('button', { name: 'Inspect component identity matches', exact: true }).click()
  await expect(f.panel).toContainText('21 uniquely matched occurrences'); await expect(f.panel).toContainText('<script>window.identityInjected=true</script>')
  await f.panel.getByText('Unresolved component markers (bounded sample)', { exact: true }).click()
  await expect(f.panel).toContainText('Only the first 100 unresolved diagnostics'); await expect(f.panel).toContainText('insufficient identity')
  await f.panel.getByRole('button', { name: 'Next identity matches', exact: true }).click(); await expect(f.panel).toContainText('scoped strong digest')
  await f.panel.getByRole('button', { name: 'Previous identity matches', exact: true }).click(); await expect(f.panel).toContainText('old-one')
  expect(f.reads.map(url => url.searchParams.get('offset'))).toEqual(['0', '20', '0']); expect(f.mutations).toEqual([])
  expect(await page.evaluate(() => (window as unknown as { identityInjected?: boolean }).identityInjected)).toBeUndefined()
  expect(await page.locator('body').evaluate(row => row.scrollWidth)).toBeLessThanOrEqual(390)
})
test('changed report digest keeps original page until explicit refresh', async ({ page }) => {
  const f = await fixture(page); await f.select(); await f.panel.getByRole('button', { name: 'Inspect component identity matches', exact: true }).click()
  await expect(f.panel).toContainText('old-one'); f.digest(sha('d'))
  await f.panel.getByRole('button', { name: 'Next identity matches', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('changed between pages'); await expect(f.panel).toContainText('old-one'); await expect(f.panel).not.toContainText('old-two')
  await f.panel.getByRole('button', { name: 'Inspect component identity matches', exact: true }).click(); await expect(f.panel.getByRole('alert')).toHaveCount(0)
  await f.panel.getByRole('button', { name: 'Next identity matches', exact: true }).click(); await expect(f.panel).toContainText('old-two')
})
test('source change drops a held response without eager refetch', async ({ page }) => {
  const f = await fixture(page); await f.select(); f.hold(); await f.panel.getByRole('button', { name: 'Inspect component identity matches', exact: true }).click()
  await expect.poll(() => f.reads.length).toBe(1)
  await page.getByRole('combobox', { name: 'Source branch or tag', exact: true }).selectOption('')
  const response = page.waitForResponse(row => row.url().includes('/identity-matches')); f.release(); await response
  await expect(f.panel).not.toContainText('old-one'); expect(f.reads).toHaveLength(1)
  await expect(f.panel.getByRole('button', { name: 'Inspect component identity matches', exact: true })).toBeDisabled()
})
test('failed read is retryable without creating assertions', async ({ page }) => {
  const f = await fixture(page); await f.select(); f.fail(503)
  await f.panel.getByRole('button', { name: 'Inspect component identity matches', exact: true }).click(); await expect(f.panel.getByRole('alert')).toContainText('unavailable')
  f.fail(0); await f.panel.getByRole('button', { name: 'Inspect component identity matches', exact: true }).click(); await expect(f.panel).toContainText('old-one'); expect(f.mutations).toEqual([])
})
test('actor roundtrip discards a late identity response', async ({ page }) => {
  const f = await fixture(page, true); await f.select(); f.hold(); await f.panel.getByRole('button', { name: 'Inspect component identity matches', exact: true }).click()
  await expect.poll(() => f.reads.length).toBe(1)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other'); await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  const response = page.waitForResponse(row => row.url().includes('/identity-matches')); f.release(); await response
  await expect(page.getByText('old-one', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Component identity comparison', exact: true })).toHaveCount(0)
})
