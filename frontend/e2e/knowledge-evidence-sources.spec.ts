import { expect, test, type Page } from '@playwright/test'
import { createHash } from 'node:crypto'
const sha = (value: string) => value.repeat(64)
const raw = Buffer.from(JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'SUPPLIER-1', version: 1, author: 'Supplier', timestamp: '2026-10-16T01:00:00Z', statements: [{ vulnerability: { name: 'CVE-2099-20001' }, products: [{ '@id': 'pkg:npm/demo-http@1.2.0' }, { '@id': 'pkg:generic/unreported@1' }], status: 'affected' }] }, null, 3) + '\n')
const artifact = createHash('sha256').update(raw).digest('hex')
async function fixture(page: Page, readonly = false, empty = false) {
  let head = sha('a'), evidence = sha('b'), failure = 0, wrongHash = false, active = true
  const writes: { path: string; metadata: Record<string, unknown>; raw: Buffer | null }[] = [], previews: Record<string, unknown>[] = [], reads: URL[] = []
  function pins() { return { expected_evidence: evidence, expected_versions: empty ? {} : { '7.1.1': head } } }
  function preview(metadata: Record<string, unknown>, selected = true) { return { ...metadata, source_revision: metadata.revision || 1, committed: false, artifact_sha: wrongHash ? sha('f') : artifact, preview_digest: sha('d'), source: metadata.source || 'supplier', active: selected, trust: 'unverified_publisher_and_signature', document: { format: 'openvex', document_id: 'SUPPLIER-1', publisher: 'Supplier', revision: 1, losses: ['unsupported_signature_not_verified'] }, limitations: ['Semantic scope only: supersession and producer ordering are checked on import.'], application: { [empty ? 'unassigned' : '7.1.1']: { application: { matched: selected && !empty ? 1 : 0, unresolved: selected ? 1 : 0, statements: [], ...(!selected ? { selection: 'inactive' } : {}) }, would_apply: [], unmatched: [{ reason: 'unknown_component' }], contradictions: [] } } } }
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname; reads.push(url)
    if (path.endsWith('/files/preview')) {
      const metadata = JSON.parse(route.request().postDataBuffer()!.toString('utf8').match(/name="metadata"\r\n\r\n([\s\S]*?)\r\n--/)![1]!)
      previews.push(metadata); return route.fulfill({ json: preview(metadata) })
    }
    if (path.endsWith(`/${artifact}/preview`)) { previews.push(route.request().postDataJSON()); return route.fulfill({ json: preview({ ...pins(), source: 'supplier' }, active) }) }
    if (path.includes('/evidence/artifacts/')) return route.fulfill({ body: raw, contentType: 'application/json' })
    if (route.request().method() === 'POST') {
      const bytes = route.request().postDataBuffer(), multipart = route.request().headers()['content-type']?.includes('multipart/form-data')
      const metadata = multipart ? JSON.parse(bytes!.toString('utf8').match(/name="metadata"\r\n\r\n([\s\S]*?)\r\n--/)![1]!) : route.request().postDataJSON()
      writes.push({ path, metadata, raw: bytes })
      if (failure) return route.fulfill({ status: failure, json: { detail: failure === 503 ? 'Publication uncertain; resend identical request.' : 'Evidence or product versions changed' } })
      evidence = sha('e'); head = sha('c'); if (path.endsWith('/withdrawals')) active = false
      return route.fulfill({ status: 201, json: {} })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') result = { id: 'person', name: 'Person', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read'] }] }
    else if (path === '/api/v2/catalog/projects') result = { items: [{ id: 'product', name: 'Product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: empty ? [] : [{ version: '7.1.1', state: head }] }
    else if (path.endsWith('/workspace')) result = { state: head, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/evidence')) result = { evidence_state: evidence, versions: pins().expected_versions, total: 22, documents: [{ artifact_sha: artifact, active, source: 'supplier', source_revision: 1, representation: 'original_bytes', identity_basis: 'publisher_source_document_id', document: { format: 'openvex', document_id: 'SUPPLIER-1', publisher: 'Supplier', revision: 1, losses: ['unsupported_signature_not_verified'] } }, { artifact_sha: sha('0'), active: false, source: 'legacy', source_revision: 0, representation: 'canonical_json', identity_basis: 'content_digest', superseded_by: artifact, document: { format: 'cyclonedx-vex', document_id: null, publisher: null, revision: null, losses: [] } }], next_offset: url.searchParams.get('offset') === '20' ? null : 20, capabilities: readonly ? [] : ['import', 'withdraw'] }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'Product', exact: true }).click()
  await page.getByText('VDR, VEX and advisory evidence files', { exact: true }).click()
  const panel = page.getByLabel('Evidence source files', { exact: true })
  await expect(panel).toContainText('22 retained evidence documents')
  return { panel, writes, previews, reads, fail: (code: number) => { failure = code }, mismatch: () => { wrongHash = true }, advance: () => { head = sha('9'); evidence = sha('8') } }
}
async function previewFile(panel: ReturnType<Page['getByLabel']>) {
  await panel.getByText('Import a source evidence revision', { exact: true }).click()
  const form = panel.getByLabel('Preview evidence file', { exact: true })
  await form.getByLabel('Attributed evidence source', { exact: true }).fill('supplier')
  await form.getByLabel('Producer revision ordinal', { exact: true }).fill('2')
  await form.getByLabel('Evidence JSON file', { exact: true }).setInputFiles({ name: 'supplier-vex.json', mimeType: 'application/json', buffer: raw })
  await form.getByRole('button', { name: 'Preview exact evidence bytes', exact: true }).click()
}

test('exact-byte preview precedes import and503 retry keeps metadata, bytes and UUID despite explicit refresh', async ({ page }) => {
  const { panel, writes, previews, fail, advance } = await fixture(page)
  await previewFile(panel)
  await expect(panel.getByLabel('Candidate evidence preview')).toContainText('Semantic scope preview only')
  expect(writes).toHaveLength(0)
  await expect(panel.getByLabel('Candidate evidence preview')).toContainText('1 unresolved statements')
  fail(503)
  await panel.getByRole('button', { name: 'Import exact previewed evidence', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Publication uncertain')
  advance()
  await panel.getByRole('button', { name: 'Refresh evidence registry and pins', exact: true }).click()
  await panel.getByRole('button', { name: 'Resend identical evidence import', exact: true }).click()
  await expect.poll(() => writes.length).toBe(2)
  expect(writes[1]!.metadata).toEqual(writes[0]!.metadata)
  expect(writes[0]!.metadata).toEqual(previews[0])
  expect(writes[0]!.raw!.includes(raw)).toBeTruthy()
  expect(writes[1]!.raw!.includes(raw)).toBeTruthy()
  expect(writes[0]!.metadata).toMatchObject({ source: 'supplier', revision: 2, expected_evidence: sha('b'), expected_versions: { '7.1.1': sha('a') } })
  fail(0)
  await panel.getByRole('button', { name: 'Resend identical evidence import', exact: true }).click()
  await expect(panel.getByRole('status')).toContainText('No human assessment or approval was created')
})

test('mismatched source-byte digest cannot enable adoption', async ({ page }) => {
  const { panel, writes, mismatch } = await fixture(page)
  mismatch()
  await previewFile(panel)
  await expect(panel.getByRole('alert')).toContainText('differs from the frozen bytes')
  await expect(panel.getByRole('button', { name: 'Import exact previewed evidence', exact: true })).toHaveCount(0)
  expect(writes).toHaveLength(0)
})

test('withdrawal requires reason and retains exact target pins and UUID after409', async ({ page }) => {
  const { panel, writes, fail, advance } = await fixture(page)
  await panel.getByRole('button', { name: 'Prepare evidence withdrawal', exact: true }).click()
  const form = panel.getByLabel('Withdraw evidence selection', { exact: true })
  await expect(form.getByRole('button', { name: 'Withdraw selected evidence', exact: true })).toBeDisabled()
  await form.getByLabel('Evidence withdrawal reason', { exact: true }).fill('Supplier withdrew this claim pending an investigation.')
  fail(409)
  await form.getByRole('button', { name: 'Withdraw selected evidence', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('versions changed')
  advance()
  await panel.getByRole('button', { name: 'Refresh evidence registry and pins', exact: true }).click()
  await form.getByRole('button', { name: 'Resend identical evidence withdrawal', exact: true }).click()
  await expect.poll(() => writes.length).toBe(2)
  expect(writes[1]!.metadata).toEqual(writes[0]!.metadata)
  expect(writes[0]!.metadata).toMatchObject({ artifact_sha: artifact, expected_evidence: sha('b'), expected_versions: { '7.1.1': sha('a') }, reason: 'Supplier withdrew this claim pending an investigation.' })
})

test('readonly inspection preserves active/history distinction, losses and exact source download links', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes } = await fixture(page, true)
  await expect(panel.getByLabel('Preview evidence file', { exact: true })).toHaveCount(0)
  await expect(panel.getByRole('button', { name: 'Prepare evidence withdrawal', exact: true })).toHaveCount(0)
  await expect(panel).toContainText('Inactive historical selection')
  const document = panel.getByLabel(`Evidence document ${artifact}`, { exact: true })
  await document.getByRole('button', { name: 'Inspect application and losses', exact: true }).click()
  await expect(document.getByLabel('Retained evidence application')).toContainText('1 unresolved statements')
  await document.getByText('Matched, unmatched, conflicting statements and losses', { exact: true }).click()
  await expect(document).toContainText('unsupported_signature_not_verified')
  const link = document.getByRole('link', { name: 'Download exact source bytes', exact: true })
  const href = await link.getAttribute('href')
  expect(href).toBe(`/api/v3/projects/product/evidence/artifacts/${artifact}?expected_evidence=${sha('b')}`)
  const bytes = await page.evaluate(async path => Array.from(new Uint8Array(await (await fetch(path!)).arrayBuffer())), href)
  expect(Buffer.from(bytes)).toEqual(raw)
  await expect(page.locator('body')).toHaveJSProperty('scrollWidth', 390)
  expect(writes).toHaveLength(0)
})

test('registry pages pin evidence and every version, retaining old selection on concurrent change', async ({ page }) => {
  const { panel, writes, advance } = await fixture(page)
  advance()
  await panel.getByRole('button', { name: 'Next evidence documents', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('selection changed')
  await panel.getByRole('button', { name: 'Refresh evidence registry and pins', exact: true }).click()
  await panel.getByRole('button', { name: 'Next evidence documents', exact: true }).click()
  await expect(panel.getByRole('button', { name: 'Next evidence documents', exact: true })).toBeDisabled()
  expect(writes).toHaveLength(0)
})

test('empty product can preview and retain evidence before the first inventory', async ({ page }) => {
  const { panel, writes, previews } = await fixture(page, false, true)
  await previewFile(panel)
  await expect(panel.getByLabel('Candidate evidence preview')).toContainText('unassigned')
  expect(previews[0]).toMatchObject({ expected_versions: {} })
  expect(writes).toHaveLength(0)
})
