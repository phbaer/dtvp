import { expect, test, type Page } from '@playwright/test'
const sha = (char: string) => char.repeat(64), raw = Buffer.from([80,75,3,4,0,255,10,13,42]), archive = sha('a'), entry = sha('b'), digest = sha('c'), policy = sha('d'), evidence = sha('e')
async function fixture(page: Page, options: { statuses?: number[]; previewStatuses?: number[]; total?: number; pending?: boolean; personas?: boolean; hold?: boolean } = {}) {
  let actor = 'author', applied = false, release: (() => void) | undefined
  const posts: { path: string; header?: string; contentType: string; raw: Buffer }[] = []
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (path.endsWith('/playground/login')) { actor = request.postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (request.method() === 'POST') {
      const item = { path, header: request.headers()['x-dtvp-migration'], contentType: request.headers()['content-type']!, raw: request.postDataBuffer()! }; posts.push(item)
      if (path.endsWith('/apply')) {
        if (options.hold) await new Promise<void>(resolve => { release = resolve })
        const index = posts.filter(row => row.path.endsWith('/apply')).length - 1, status = options.statuses?.[index] || 201
        if (status !== 201) return route.fulfill({ status, json: { detail: status === 409 ? 'Selected evidence changed' : 'Publication uncertain' } })
        applied = true; return route.fulfill({ status: 201, json: { committed: true, projection: options.pending ? 'pending' : 'current' } })
      }
      if (item.header) {
        const status = options.previewStatuses?.[posts.filter(row => row.header && row.path.endsWith('/preview')).length - 1]
        if (status && status !== 200) return route.fulfill({ status, json: { detail: 'Preview temporarily unavailable' } })
      }
      if (item.header) return route.fulfill({ json: { preview_digest: digest, archive_sha256: archive, source_entry_id: entry, target: { project_id: 'product', version: 'migrated', source: 'Legacy reviewed', build_number: 1 }, statistics: { native_source_observations: 2, unresolved_source_records: 1, native_assessments: 0, native_reviews: 0, native_scoring_records: 0, inventory_components: 3 }, coverage: { findings: { exact_source_uuid_refs: 1, unresolved: 1, ambiguous: 0 } }, losses: ['source_authorship_team_and_approval_unverified'], disclosure: { audience: 'project_readers', retains_submitted_sanitized_zip: true, retained_member_count: 5 }, limitations: ['Historical evidence is not a native approval.'] } })
      return route.fulfill({ json: { archive_sha256: archive, preview_digest: sha('f'), items: [{ source_entry_id: entry, entry_index: 1, counts: { findings: 2, assessments: 1 }, normalization: { status: 'supported' }, losses: ['assessment_comments_may_have_been_stripped'], member_pins: { bom: { sha256: sha('9'), bytes: 100 } } }], total: options.total || 1, next_offset: null, limitations: [] } })
    }
    let data: unknown = { items: [], next_cursor: null, next_offset: null }
    if (path === '/api/v2/me') data = { id: actor, name: actor, org_admin: false, playground: !!options.personas, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path.endsWith('/playground/personas')) data = options.personas ? [{ id: 'author', name: 'author' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v2/catalog/projects') data = { items: [{ id: 'product', name: 'Product' }], next_cursor: null }
    else if (path === '/api/v2/projects/product') data = { id: 'product', name: 'Product' }
    else if (path.endsWith('/versions')) data = { items: [{ version: applied ? 'migrated' : 'old', state: sha('8') }], next_offset: null }
    else if (path.endsWith('/ownership')) data = { policy_state: policy }
    else if (path.endsWith('/evidence')) data = { evidence_state: evidence, items: [] }
    else if (path.endsWith('/workspace')) data = { state: sha('8'), project_id: 'product', version: 'old', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click(); await page.getByRole('option', { name: 'Product', exact: true }).click()
  await page.locator('.knowledge-intake > summary').click(); await page.getByText('Reviewed v1 archive', { exact: true }).click()
  const panel = page.getByRole('region', { name: 'Reviewed v1 archive intake' })
  await panel.getByLabel('Sanitized v1 ZIP', { exact: true }).setInputFiles({ name: 'reviewed.zip', mimeType: 'application/zip', buffer: raw })
  await panel.getByRole('button', { name: 'Inspect sanitized archive', exact: true }).click()
  await expect(panel).toContainText('source versions')
  return { panel, posts, release: () => release?.() }
}
async function prepare(page: Page) {
  const panel = page.getByRole('region', { name: 'Reviewed v1 archive intake' })
  await panel.getByRole('radio').check()
  await panel.getByLabel('New archive target version', { exact: true }).fill('migrated')
  await panel.getByLabel('Archive source identity', { exact: true }).fill('Legacy reviewed')
  await panel.getByLabel('Archive source sequence', { exact: true }).fill('1')
  await panel.getByLabel('Archive observed time', { exact: true }).fill('2026-10-16T12:00:00Z')
  await panel.getByLabel('Operator review reason', { exact: true }).fill('Reviewed sanitized ä export')
  await expect(panel.getByRole('button', { name: 'Preview reviewed publication', exact: true })).toBeDisabled()
  for (const checkbox of await panel.getByRole('checkbox').all()) await checkbox.check()
}
test('reviewed preview and explicit publication retain byte-exact ZIP, ASCII header and pins across503/409', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const f = await fixture(page, { statuses: [503, 409, 201], pending: true }); await prepare(page)
  await expect(page.getByRole('button', { name: 'Knowledge product', exact: false })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Inspect target', exact: true })).toBeDisabled()
  await f.panel.getByRole('button', { name: 'Preview reviewed publication', exact: true }).click()
  const preview = f.panel.getByRole('region', { name: 'Archive publication preview' })
  await expect(preview).toContainText('native assessments0'); await expect(preview).toContainText('project readers')
  expect(f.posts.filter(row => row.path.endsWith('/apply'))).toHaveLength(0)
  const commit = f.panel.getByRole('button', { name: 'Publish captured reviewed archive', exact: true })
  await commit.click(); await expect(f.panel.getByRole('alert')).toContainText('Publication uncertain')
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await commit.click(); await expect(f.panel.getByRole('alert')).toContainText('Selected evidence changed')
  await commit.click(); await expect(f.panel).toContainText('Projection pending; publication is committed')
  const writes = f.posts.filter(row => row.path.endsWith('/apply')); expect(writes).toHaveLength(3); expect(writes[0]).toEqual(writes[1]); expect(writes[0]).toEqual(writes[2])
  for (const row of f.posts) { expect(row.raw).toEqual(raw); expect(row.contentType).toBe('application/zip') }
  const preflight = f.posts.find(row => row.header && row.path.endsWith('/preview'))!, fields = JSON.parse(preflight.header!)
  expect(preflight.header).toMatch(/\\u00e4/); expect(preflight.header).toMatch(/^[\x00-\x7f]+$/)
  expect(fields).toMatchObject({ expected: null, expected_policy: policy, expected_evidence: evidence, source_entry_id: entry, archive_sha256: archive, acknowledge_sanitized_export: true, acknowledge_operator_review: true, acknowledge_project_reader_disclosure: true })
  expect(JSON.parse(writes[0]!.header!)).toEqual({ ...fields, preview_digest: digest })
  await expect(page.getByRole('button', { name: 'Knowledge product', exact: false })).toBeEnabled()
  expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(390)
})
test('multi-version archive is inspectable but cannot be prepared for publication', async ({ page }) => {
  const f = await fixture(page, { total: 2 }); await prepare(page)
  await expect(f.panel.getByRole('alert')).toContainText('requires a single-version export')
  await expect(f.panel.getByRole('button', { name: 'Preview reviewed publication', exact: true })).toBeDisabled()
  expect(f.posts).toHaveLength(1)
  await f.panel.getByRole('button', { name: 'Discard archive capture', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Knowledge product', exact: false })).toBeEnabled()
})
test('actor roundtrip invalidates a late archive publication response and clears retained capture', async ({ page }) => {
  const f = await fixture(page, { personas: true, hold: true }); await prepare(page)
  await f.panel.getByRole('button', { name: 'Preview reviewed publication', exact: true }).click()
  await f.panel.getByRole('button', { name: 'Publish captured reviewed archive', exact: true }).click()
  await expect.poll(() => f.posts.some(row => row.path.endsWith('/apply'))).toBe(true)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('author')
  const response = page.waitForResponse(row => row.url().endsWith('/apply')); f.release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByRole('region', { name: 'Archive publication preview' })).toHaveCount(0)
  await expect(page.getByText('Reviewed archive published as historical source evidence.', { exact: false })).toHaveCount(0)
})

test('failed first publication preview freezes its exact declaration until retry or explicit discard', async ({ page }) => {
  const f = await fixture(page, { previewStatuses: [503, 200] }); await prepare(page)
  await f.panel.getByRole('button', { name: 'Preview reviewed publication', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('Captured bytes and metadata remain unchanged')
  await expect(f.panel.getByLabel('Operator review reason', { exact: true })).toBeDisabled()
  await f.panel.getByRole('button', { name: 'Retry captured publication preview', exact: true }).click()
  await expect(f.panel.getByRole('region', { name: 'Archive publication preview' })).toBeVisible()
  const requests = f.posts.filter(row => row.header); expect(requests).toHaveLength(2); expect(requests[0]).toEqual(requests[1])
  expect(f.posts.some(row => row.path.endsWith('/apply'))).toBe(false)
  await f.panel.getByRole('button', { name: 'Discard archive capture', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Knowledge product', exact: false })).toBeEnabled()
})
