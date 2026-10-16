import { expect, test, type Page } from '@playwright/test'
const sha = (value: string) => value.repeat(64), state = sha('a'), configuration = sha('b'), observation = sha('c')
async function fixture(page: Page, writable = true) {
  let actor = 'person', failed = false, wrongPreview = false, changedListing = false, held = false, release: (() => void) | undefined
  const writes: { path: string; body: unknown; raw: string }[] = []
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (path.endsWith('/playground/login')) { actor = request.postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (request.method() === 'POST') {
      const raw = request.postDataBuffer()?.toString() || '', multipart = request.headers()['content-type']?.includes('multipart/form-data')
      const body = multipart ? JSON.parse(raw.match(/name="metadata"\r\n\r\n([\s\S]*?)\r\n--/)?.[1] || '{}') : request.postDataJSON()
      writes.push({ path, body, raw })
      if (held) { held = false; await new Promise<void>(resolve => { release = resolve }) }
      if (failed) return route.fulfill({ status: 503, json: { detail: 'Uncertain operation' } })
      if (path.endsWith('/preview')) return route.fulfill({ json: { project_id: 'product', version: '7.1.2', expected: wrongPreview ? sha('9') : state, configuration, preview_digest: sha('e'), human_decisions_changed: false, reports: [{ source: 'scanner', part_id: null, bounded_sample: true, report: { summary: { matched_occurrences: 5, field_conflicts: 1, topology_proposals: 2 }, component_proposals: [{ ref: 'extra-library' }], topology_proposals: [] } }] } })
      return route.fulfill({ json: { committed: true, projection: 'current' } })
    }
    let data: unknown = { items: [], next_offset: null }
    if (path === '/api/v2/me') data = { id: actor, name: actor, playground: true, org_admin: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path.endsWith('/playground/personas')) data = [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }]
    else if (path === '/api/v2/catalog/projects') data = { items: [{ id: 'product', name: 'Product' }], next_cursor: null }
    else if (path === '/api/v2/projects/product') data = { id: 'product', name: 'Product' }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.2', state }] }
    else if (path.endsWith('/workspace')) data = { state, project_id: 'product', version: '7.1.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/pipeline-config')) data = { configuration_state: configuration, expected_versions: { '7.1.2': state }, configuration: { format: 'dtvp.pipeline-configuration/1', parts: [], models: [], mappings: [] }, capabilities: [] }
    else if (path.endsWith('/observation-selection')) data = { state, selection: { sources: {} } }
    else if (path.endsWith('/observation-sources')) data = { head: state, digest: changedListing ? sha('9') : sha('d'), total: 21, offset: Number(url.searchParams.get('offset') || 0), limit: 20, next_offset: url.searchParams.get('offset') === '20' ? null : 20, capabilities: writable ? ['write'] : [], items: [{ source: url.searchParams.get('offset') === '20' ? 'second-scanner' : 'scanner', part_id: null, state: observation, build_number: 4, subject_declaration: { assurance: 'producer_declared' }, baseline: { source: 'scanner' } }] }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click(); await page.getByRole('option', { name: 'Product', exact: true }).click()
  return { writes, fail: (value: boolean) => { failed = value }, wrongPreview: () => { wrongPreview = true }, changeListing: () => { changedListing = true }, hold: () => { held = true }, release: () => release?.() }
}
async function panel(page: Page) { await page.getByText('SBOM observations and reconciliation', { exact: true }).click(); const result = page.getByRole('region', { name: 'SBOM observations and reconciliation', exact: true }); await expect(result).toContainText('21 source bindings'); return result }
test('read-only observations show retained source provenance and consistent paging', async ({ page }) => {
  const f = await fixture(page, false), view = await panel(page)
  await expect(view.getByLabel('Observation selection JSON')).toHaveCount(0)
  await view.getByText('Source provenance and pins', { exact: true }).click(); await expect(view).toContainText('producer_declared')
  await view.getByRole('button', { name: 'Next observation sources' }).click(); await expect(view).toContainText('second-scanner')
  expect(f.writes).toHaveLength(0)
})
test('observation selection requires server preview and explicit reviewed publication', async ({ page }) => {
  const f = await fixture(page), view = await panel(page)
  await view.getByRole('button', { name: 'Select source scanner', exact: true }).click()
  await view.getByRole('button', { name: 'Preview observation selection', exact: true }).click()
  await expect(view.getByRole('region', { name: 'Observation reconciliation preview' })).toContainText('field_conflicts')
  await expect(view.getByRole('button', { name: 'Publish observation selection', exact: true })).toBeDisabled()
  expect(f.writes).toHaveLength(1)
  await view.getByLabel('I reviewed the observation selection and adoption reasons').check()
  await view.getByRole('button', { name: 'Publish observation selection', exact: true }).click()
  await expect(view.getByRole('status')).toContainText('No human assessment or approval was applied')
  expect(f.writes[1]!.body).toMatchObject({ expected: state, expected_configuration: configuration, preview_digest: sha('e'), sources: [{ source: 'scanner', state: observation, accepted_components: [] }] })
})
test('uncertain selection publication retries exact captured request and preview', async ({ page }) => {
  const f = await fixture(page), view = await panel(page)
  await view.getByRole('button', { name: 'Select source scanner', exact: true }).click()
  await view.getByRole('button', { name: 'Preview observation selection', exact: true }).click()
  await view.getByLabel('I reviewed the observation selection and adoption reasons').check()
  f.fail(true); await view.getByRole('button', { name: 'Publish observation selection', exact: true }).click()
  await expect(view.getByRole('alert')).toContainText('Exact apply request and preview retained')
  await expect(view.getByLabel('Observation selection JSON')).toBeDisabled()
  await expect(view.getByRole('button', { name: 'Refresh observation sources' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Review', exact: true })).toBeDisabled()
  f.fail(false); await view.getByRole('button', { name: 'Retry identical observation publication', exact: true }).click()
  expect(f.writes[2]!.body).toEqual(f.writes[1]!.body)
})
test('uncertain raw upload retains exact file and metadata until retry', async ({ page }) => {
  const f = await fixture(page), view = await panel(page)
  await view.getByText('Import an observation file', { exact: true }).click()
  const metadata = JSON.parse(await view.getByLabel('Observation import metadata JSON').inputValue()); metadata.source = 'scanner'; metadata.expected = observation
  await view.getByLabel('Observation import metadata JSON').fill(JSON.stringify(metadata))
  await view.getByLabel('Observation SBOM file').setInputFiles({ name: 'observation.json', mimeType: 'application/json', buffer: Buffer.from('{"component":"exact-source-bytes"}\n') })
  f.fail(true); await view.getByRole('button', { name: 'Import observation file', exact: true }).click()
  await expect(view.getByRole('alert')).toContainText('Captured upload retained')
  await expect(view.getByLabel('Observation import metadata JSON')).toBeDisabled()
  f.fail(false); await view.getByRole('button', { name: 'Retry identical observation upload', exact: true }).click()
  expect(f.writes[1]!.body).toEqual(f.writes[0]!.body)
  expect(f.writes[0]!.raw).toContain('{"component":"exact-source-bytes"}\n'); expect(f.writes[1]!.raw).toContain('{"component":"exact-source-bytes"}\n')
  await expect(view.getByRole('status')).toContainText('Product inventory and approvals were not changed')
})
test('wrong preview pins and changed source listing fail closed', async ({ page }) => {
  const f = await fixture(page), view = await panel(page)
  f.changeListing(); await view.getByRole('button', { name: 'Next observation sources' }).click()
  await expect(view.getByRole('alert')).toContainText('listing changed')
  await view.getByRole('button', { name: 'Select source scanner', exact: true }).click()
  f.wrongPreview(); await view.getByRole('button', { name: 'Preview observation selection', exact: true }).click()
  await expect(view.getByRole('alert')).toContainText('Preview does not describe')
  await expect(view.getByRole('button', { name: 'Publish observation selection', exact: true })).toHaveCount(0)
})
test('actor roundtrip cannot restore a late observation preview', async ({ page }) => {
  const f = await fixture(page), view = await panel(page)
  await view.getByRole('button', { name: 'Select source scanner', exact: true }).click()
  f.hold(); await view.getByRole('button', { name: 'Preview observation selection', exact: true }).click()
  await expect.poll(() => f.writes.length).toBe(1)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other'); await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  const response = page.waitForResponse(row => row.url().endsWith('/observation-selection/preview')); f.release(); await response
  await expect(page.getByRole('region', { name: 'Observation reconciliation preview' })).toHaveCount(0)
})
test('one observation draft cannot silently replace another unfinished draft', async ({ page }) => {
  const f = await fixture(page), view = await panel(page)
  await view.getByText('Import an observation file', { exact: true }).click()
  await view.getByRole('button', { name: 'Select source scanner', exact: true }).click()
  await expect(view.getByLabel('Observation SBOM file')).toBeDisabled()
  await expect(view.getByLabel('Observation import metadata JSON')).toBeDisabled()
  await expect(view.getByRole('button', { name: 'Import observation file', exact: true })).toBeDisabled()
  await view.getByRole('button', { name: 'Discard observation changes' }).click()
  await view.getByLabel('Observation SBOM file').setInputFiles({ name: 'observation.json', mimeType: 'application/json', buffer: Buffer.from('{}') })
  await expect(view.getByLabel('Observation selection JSON')).toBeDisabled()
  await expect(view.getByRole('button', { name: 'Preview observation selection', exact: true })).toBeDisabled()
  expect(f.writes).toHaveLength(0)
})
test('selection draft preserves exact source pins while paging to another source', async ({ page }) => {
  const f = await fixture(page), view = await panel(page)
  await view.getByRole('button', { name: 'Select source scanner', exact: true }).click()
  await view.getByRole('button', { name: 'Next observation sources' }).click()
  await view.getByRole('button', { name: 'Select source second-scanner', exact: true }).click()
  const draft = JSON.parse(await view.getByLabel('Observation selection JSON').inputValue())
  expect(draft.sources.map((item: { source: string }) => item.source)).toEqual(['scanner', 'second-scanner'])
  expect(draft.sources.every((item: { state: string }) => item.state === observation)).toBe(true)
  expect(f.writes).toHaveLength(0)
})
