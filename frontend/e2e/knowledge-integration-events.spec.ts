import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const sha = (char: string) => char.repeat(64), target = sha('b'), source = sha('a'), eventId = sha('c'), digest = sha('d')
async function fixture(page: Page, personas = false) {
  let head = target, actor = 'person', failure = 0, hold = false, release: (() => void) | undefined
  const reads: URL[] = [], posts: { path: string; body: Record<string, unknown> }[] = []
  const event = (id = eventId, proof = true) => ({ event_id: id, source, target, source_version: '7.1.1', target_version: '7.1.2', source_pin: { repository: 'gateway', commit: '1'.repeat(40) }, target_pin: { repository: 'gateway', commit: '2'.repeat(40), subject_digest: `sha256:${sha('e')}`, pipeline_run: 'nightly-1' }, declaration: { integration_kind: 'merge', occurred_at: '2026-10-16T12:00:00Z', rationale: '<script>window.integrationInjected=true</script>' }, git_ancestry: { status: proof ? 'verified_commit_object_ancestry' : 'not_provided', verification: proof ? 'git_sha1_object_hash_and_explicit_parent_path_consistency_only' : 'producer_declaration_only', limitations: ['No repository membership, signatures or patch equivalence verification.'] }, software_integration_verified: false, limitations: ['Target inventory remains authoritative.'] })
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (path.endsWith('/playground/login')) { actor = request.postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (request.method() === 'POST') {
      const body = request.postDataJSON(); posts.push({ path, body })
      if (!path.endsWith('/synchronization-preview')) return route.fulfill({ status: 400, json: { detail: 'Unexpected mutation' } })
      if (hold) { hold = false; await new Promise<void>(resolve => { release = resolve }) }
      if (failure || body.target !== head) return route.fulfill({ status: failure || 409, json: { detail: failure === 503 ? 'Preview temporarily unavailable' : 'Target branch changed' } })
      const later = url.searchParams.get('offset') === '20'
      return route.fulfill({ json: { integration_event: event(), basis_selection: body.basis ? 'explicit' : 'none_no_inferred_common_basis', apply_supported: false, limitations: ['No automatic draft or approval transfer.'], proposals: { source, target: body.target, basis: body.basis, preview_digest: digest, total: 21, next_offset: later ? null : 20, summary: { by_category: { needs_review: 21 } }, items: [{ id: later ? 'second' : 'first', category: 'needs_review', vulnerability_id: later ? 'CVE-2099-43' : 'CVE-2099-42', source_context_id: sha('1'), target_context_id: sha('2'), reasons: ['material_context_or_source_evidence_differs'], requires_new_target_review: true }], limitations: ['New target review is required.'] } } })
    }
    let data: unknown = { items: [], capabilities: [], next_cursor: null, next_offset: null }
    if (path === '/api/v1/me') data = { id: actor, name: actor, playground: personas, org_admin: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path.endsWith('/playground/personas')) data = personas ? [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'product', name: 'Product' }], next_cursor: null }
    else if (path === '/api/v1/projects/product') data = { id: 'product', name: 'Product' }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.2', state: head }] }
    else if (path.endsWith('/workspace')) data = { state: head, project_id: 'product', version: '7.1.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/reconciliations')) data = { items: [], total: 0, next_offset: null, capabilities: [] }
    else if (path.endsWith('/integration-events')) { reads.push(url); const state = path.split('/states/')[1]!.split('/')[0]; data = { state, items: url.searchParams.get('offset') === '20' ? [event(sha('f'), false)] : [event()], total: 21, next_offset: url.searchParams.get('offset') === '20' ? null : 20, limitations: [] } }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click(); await page.getByRole('option', { name: 'Product', exact: true }).click()
  await openProductView(page, 'Imports')
  await openDisclosure(page.getByText('Occurrence correspondence across imports', { exact: true }))
  const panel = page.getByRole('region', { name: 'Pipeline integration evidence', exact: true })
  return { panel, reads, posts, fail: (code: number) => { failure = code }, advance: () => { head = sha('9') }, hold: () => { hold = true }, release: () => release?.() }
}
async function open(page: Page) { await page.getByText('Pipeline integration observations', { exact: true }).click(); await page.getByRole('region', { name: 'Pipeline integration evidence', exact: true }).getByRole('radio').first().check() }
test('lazy event observation distinguishes commit consistency and freezes event-bound readonly comparison through retries and pages', async ({ page }) => {
  const f = await fixture(page); expect(f.reads).toHaveLength(0); await open(page)
  await expect(f.panel).toContainText('Integration: producer declared, not verified')
  await expect(f.panel).toContainText('verified commit object ancestry')
  await f.panel.getByText('Explicit synchronization basis and context mapping', { exact: true }).click()
  await f.panel.getByLabel('Integration comparison basis (optional state SHA)', { exact: true }).fill(sha('7'))
  await f.panel.getByLabel('Integration context mapping JSON', { exact: true }).fill(JSON.stringify({ [sha('1')]: sha('2') }))
  f.fail(503); await f.panel.getByRole('button', { name: 'Preview event-bound assessment comparison', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Captured event, target, basis and mapping stay unchanged')
  await expect(f.panel.getByLabel('Integration comparison basis (optional state SHA)', { exact: true })).toBeDisabled()
  f.fail(0); await f.panel.getByRole('button', { name: 'Retry captured integration preview', exact: true }).click()
  await expect(f.panel.getByRole('region', { name: 'Integration assessment comparison' })).toContainText('CVE-2099-42')
  await f.panel.getByRole('button', { name: 'Next integration proposals', exact: true }).click()
  await expect(f.panel.getByRole('region', { name: 'Integration assessment comparison' })).toContainText('CVE-2099-43')
  expect(f.posts).toHaveLength(3); expect(f.posts[0]).toEqual(f.posts[1]); expect(f.posts[2]!.body).toEqual(f.posts[0]!.body)
  expect(f.posts[0]!.body).toEqual({ target, basis: sha('7'), context_mapping: { [sha('1')]: sha('2') } })
  await f.panel.getByRole('button', { name: 'Next integration events', exact: true }).click()
  await expect(f.panel.getByRole('region', { name: 'Selected pipeline integration observation' })).toContainText(eventId)
  expect(f.reads[1]!.pathname).toContain(target)
  await expect(f.panel.getByRole('button', { name: /apply|approve|draft|publish/i })).toHaveCount(0)
  expect(await page.evaluate(() => (window as unknown as { integrationInjected?: boolean }).integrationInjected)).toBeUndefined()
})
test('state advance invalidates a held response and keeps old captured target through409 until explicit refresh', async ({ page }) => {
  const f = await fixture(page); await open(page); f.hold()
  await f.panel.getByRole('button', { name: 'Preview event-bound assessment comparison', exact: true }).click()
  await expect.poll(() => f.posts.length).toBe(1)
  f.advance(); await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(f.panel).toContainText('Workspace state changed')
  const response = page.waitForResponse(row => row.url().includes('/synchronization-preview')); f.release(); await response
  await f.panel.getByRole('button', { name: 'Retry captured integration preview', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Target branch changed')
  expect(f.posts[1]).toEqual(f.posts[0])
  await expect(f.panel.getByRole('region', { name: 'Integration assessment comparison' })).toHaveCount(0)
  await f.panel.getByRole('button', { name: 'Refresh integration events for workspace state', exact: true }).click()
  expect(f.reads.at(-1)!.pathname).toContain(sha('9'))
  await expect(f.panel.getByRole('region', { name: 'Selected pipeline integration observation' })).toHaveCount(0)
})
test('unprovided proof stays a declaration and invalid context mapping is editable on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 }); const f = await fixture(page); await open(page)
  await f.panel.getByRole('button', { name: 'Next integration events', exact: true }).click()
  await f.panel.getByRole('radio').check(); await expect(f.panel).toContainText('Commit proof: not provided')
  await f.panel.getByText('Explicit synchronization basis and context mapping', { exact: true }).click()
  await f.panel.getByLabel('Integration context mapping JSON', { exact: true }).fill('[]')
  await f.panel.getByRole('button', { name: 'Preview event-bound assessment comparison', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Context mapping requires a JSON object')
  await expect(f.panel.getByLabel('Integration context mapping JSON', { exact: true })).toBeEnabled(); expect(f.posts).toHaveLength(0)
  expect(await page.locator('body').evaluate(row => row.scrollWidth)).toBeLessThanOrEqual(390)
})
test('actor roundtrip cannot restore a late event-bound preview', async ({ page }) => {
  const f = await fixture(page, true); await open(page); f.hold()
  await f.panel.getByRole('button', { name: 'Preview event-bound assessment comparison', exact: true }).click()
  await expect.poll(() => f.posts.length).toBe(1)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other'); await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  const response = page.waitForResponse(row => row.url().includes('/synchronization-preview')); f.release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByRole('region', { name: 'Integration assessment comparison' })).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Selected pipeline integration observation' })).toHaveCount(0)
})
