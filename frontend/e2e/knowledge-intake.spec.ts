import { expect, test, type Page } from '@playwright/test'

const first = 'a'.repeat(64), next = 'b'.repeat(64)
const raw = '{\r\n  "bomFormat": "CycloneDX", "note": "synthetic ä", "components": []\r\n}\r\n'
async function fixture(page: Page, options: { existing?: boolean; connector?: boolean; readonly?: boolean; statuses?: number[] } = {}) {
  const writes: { path: string; metadata: Record<string, unknown>; raw: string }[] = [], reads: string[] = []
  let imported = false
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (request.method() !== 'GET') {
      const form = await new Response(request.postData()!, { headers: { 'Content-Type': request.headers()['content-type']! } }).formData()
      const file = form.get('file') as File
      writes.push({ path, metadata: JSON.parse(form.get('metadata') as string), raw: await file.text() })
      const status = options.statuses?.[writes.length - 1] || 201
      if (status !== 201) return route.fulfill({ status, json: { detail: status === 409 ? 'Source baseline changed' : 'Publication uncertain; retry identical input' } })
      if (!path.includes('/parts/')) imported = true
      return route.fulfill({ status, json: { committed: true, projection: 'current', updates: [{ target: next }] } })
    }
    reads.push(url.pathname + url.search)
    let result: unknown = { items: [], next_cursor: null, next_offset: null }
    if (path === '/api/v2/me') result = { id: 'author', name: 'Author', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v2/catalog/projects') result = { items: [{ id: 'product', name: 'Empty native product', workspace_id: 'team', capabilities: ['read', 'write'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: options.existing || imported ? [{ version: imported ? 'new-version' : '7.1.1', state: imported ? next : first }] : [], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state: imported ? next : first, project_id: 'product', version: imported ? 'new-version' : '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/intake-parts')) result = { items: [{ part_id: 'container', state: first }], total: 1, next_offset: null }
    else if (path.endsWith('/intake-target')) result = { project_id: 'product', version: url.searchParams.get('version'), part_id: url.searchParams.get('part_id'), kind: url.searchParams.has('part_id') ? 'part' : 'product', state: options.existing ? first : null, scope_template: options.existing ? { subject_kind: 'build', target: 'delivery', platform: 'linux', configuration: 'prod' } : {}, source_authority: options.connector ? 'connector' : options.existing ? 'file' : 'unassigned', blocked_reasons: options.connector ? ['connector_owned_source_requires_explicit_authority_policy_to_replace_with_file'] : [], baseline: { source: options.existing ? 'CI:files' : null, build_number: options.existing ? 1 : null, occurred_at: null, collection: null }, capabilities: options.readonly || options.connector ? [] : ['import'], max_upload_bytes: 100000, formats: ['CycloneDX 1.5/1.6 JSON/XML', 'SPDX 2.3 JSON'] }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'Empty native product', exact: true }).click()
  await page.locator('.knowledge-intake > summary').click()
  return { writes, reads, panel: page.getByRole('region', { name: 'Native composition intake' }) }
}
async function target(page: Page, version = 'new-version', part = false) {
  const panel = page.getByRole('region', { name: 'Native composition intake' })
  await panel.getByLabel('Product version (existing or new)', { exact: true }).fill(version)
  if (part) { await panel.getByRole('combobox', { name: 'Import target', exact: true }).selectOption('part'); await panel.getByLabel('Source part ID', { exact: true }).fill('container') }
  await panel.getByRole('button', { name: 'Inspect target', exact: true }).click()
  return panel
}
async function prepare(page: Page, existing = false) {
  const panel = page.getByRole('region', { name: 'Native composition intake' })
  await panel.getByLabel('Original SBOM file', { exact: true }).setInputFiles({ name: 'fixture.cdx.json', mimeType: 'application/json', buffer: Buffer.from(raw) })
  if (!existing) await panel.getByLabel('Source identity', { exact: true }).fill('CI:files')
  await panel.getByLabel('Source sequence', { exact: true }).fill('2')
  await panel.getByLabel('Observed at (ISO 8601 with timezone)', { exact: true }).fill('2026-10-16T12:00:00+02:00')
  await panel.getByRole('checkbox', { name: 'Replace this exact source baseline with the complete document.' }).check()
  await panel.getByRole('button', { name: 'Review captured import', exact: true }).click()
}

test('empty project bootstraps original bytes with identical frozen UUID and metadata after uncertainty', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const state = await fixture(page, { statuses: [503, 201] })
  await target(page)
  await prepare(page)
  await expect(page.getByRole('button', { name: 'Knowledge product', exact: false })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Review', exact: true })).toBeDisabled()
  const commit = state.panel.getByRole('button', { name: 'Commit captured import', exact: true })
  await commit.click()
  await expect(state.panel.getByRole('alert')).toContainText('Captured bytes, metadata and request ID are retained')
  await commit.click()
  await expect(state.panel).toContainText('Product baseline imported')
  expect(state.writes).toHaveLength(2)
  expect(state.writes[0]).toEqual(state.writes[1])
  expect(state.writes[0]!.raw).toBe(raw)
  expect(state.writes[0]!.metadata).toMatchObject({ expected: null, source: 'CI:files', build_number: 2, occurred_at: '2026-10-16T12:00:00+02:00', completeness: 'complete' })
  expect(state.writes[0]!.metadata.request_id).toMatch(/^[0-9a-f-]{36}$/)
  await expect(page.getByRole('button', { name: 'Knowledge product', exact: false })).toBeEnabled()
  await expect(page.getByRole('button', { name: 'Review', exact: true })).toBeEnabled()
  expect(await state.panel.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
})

test('conflict retains existing source pin until explicit new target review', async ({ page }) => {
  const state = await fixture(page, { existing: true, statuses: [409] })
  await target(page, '7.1.1')
  await expect(state.panel.getByLabel('Source identity', { exact: true })).toHaveAttribute('readonly', '')
  await prepare(page, true)
  await state.panel.getByRole('button', { name: 'Commit captured import', exact: true }).click()
  await expect(state.panel.getByRole('alert')).toContainText('Source baseline changed')
  expect(state.writes[0]!.metadata.expected).toBe(first)
  expect(state.writes[0]!.metadata.context).toEqual({ subject_kind: 'build', target: 'delivery', platform: 'linux', configuration: 'prod' })
  await expect(state.panel.getByRole('button', { name: 'Inspect target', exact: true })).toBeDisabled()
  await state.panel.getByRole('button', { name: 'Discard capture and start a new import', exact: true }).click()
  await expect(state.panel.getByRole('button', { name: 'Inspect target', exact: true })).toBeEnabled()
  expect(state.writes).toHaveLength(1)
})

test('isolated part import preserves empty product and exposes explicit assembly next step', async ({ page }) => {
  const state = await fixture(page)
  await target(page, 'new-version', true)
  await prepare(page)
  await state.panel.getByRole('button', { name: 'Commit captured import', exact: true }).click()
  await expect(state.panel).toContainText('The assembled product is unchanged')
  expect(state.writes[0]!.path).toContain('/versions/new-version/parts/container/files')
  expect(state.reads.some(path => path.includes('/workspace'))).toBe(false)
})

test('connector ownership and read permissions withhold manual file mutation', async ({ page }) => {
  const state = await fixture(page, { existing: true, connector: true })
  await target(page, '7.1.1')
  await expect(state.panel).toContainText('File replacement requires an explicit authority policy')
  await expect(state.panel.getByLabel('Original SBOM file', { exact: true })).toHaveCount(0)
  expect(state.writes).toHaveLength(0)
})
