import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'

const sha = (char: string) => char.repeat(64)
const raw = Buffer.from([0x50, 0x44, 0x46, 0x00, 0xff, 0x0a])
async function fixture(page: Page, role: 'author' | 'reviewer' | 'viewer' = 'author') {
  const writes: { path: string; body: Record<string, unknown>; raw: Buffer | null }[] = [], issued: string[] = [], reads: string[] = []
  let failed = 0, head = sha('a')
  const payload = { document_id: 'architecture', title: 'Architecture report', purpose: 'architecture', rationale: 'Prior rendered artifact rationale', renderer: { name: 'Generator', version: '2.0' }, issued_receipt_sha: sha('b'), artifact_sha256: sha('c'), configuration_sha256: sha('d'), filename: 'architecture.pdf', media_type: 'application/pdf', source_state: sha('e'), bundle_sha256: sha('f'), actor_id: 'author' }
  const row = { document_id: 'architecture', status: 'approved', document: { revision: sha('1'), stage: 'submitted', payload }, approved_document: { revision: sha('2'), stage: 'submitted', payload: { ...payload, artifact_sha256: sha('3'), rationale: 'Previously approved bytes' } }, source_current: false, approved_source_current: false, pending: true, capabilities: role === 'author' ? ['revise'] : role === 'reviewer' ? ['review'] : [], review: { rationale: 'Prior review rationale', action: 'approve', review_revision: sha('4') } }
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (path.endsWith('/exports/bundle')) { issued.push(path); return route.fulfill({ status: 201, json: { receipt_sha256: sha('b'), source_state: head, files: { 'bundle.json': { sha256: sha('f'), url: '/untrusted-provider-url' }, 'manifest.json': { sha256: sha('6'), url: '/untrusted-provider-url' } } } }) }
    if (path.includes('/artifacts/')) return route.fulfill({ body: raw, contentType: 'application/octet-stream', headers: { 'Content-Disposition': 'attachment; filename="artifact.bin"' } })
    if (route.request().method() === 'POST') {
      const data = route.request().postDataBuffer()
      const multipart = route.request().headers()['content-type']?.includes('multipart/form-data')
      const body = multipart ? JSON.parse(data!.toString('utf8').match(/name="metadata"\r\n\r\n([\s\S]*?)\r\n--/)![1]!) : route.request().postDataJSON()
      writes.push({ path, body, raw: data })
      if (failed) return route.fulfill({ status: failed, json: { detail: failed === 503 ? 'Publication uncertain; retry identical input.' : 'Document revision changed' } })
      head = sha('7')
      return route.fulfill({ status: 201, json: {} })
    }
    let result: unknown = { items: [], capabilities: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: role, name: role, org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read'] }] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state: head }] }
    else if (path.endsWith('/workspace')) result = { state: head, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/documents')) { reads.push(url.search); result = { state: head, items: [row], total: 21, next_offset: url.searchParams.get('offset') === '20' ? null : 20, capabilities: role === 'author' ? ['documentary_assess'] : role === 'reviewer' ? ['documentary_approve'] : [] } }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Product', exact: true }).click()
  await openProductView(page, 'Documents')
  await openDisclosure(page.getByText('Controlled documents', { exact: true }))
  const panel = page.getByLabel('Controlled document registry', { exact: true })
  await expect(panel).toContainText('21 documents in this pinned version state')
  return { panel, writes, issued, reads, fail: (status: number) => { failed = status } }
}

async function fillRegistration(panel: ReturnType<Page['getByLabel']>) {
  await panel.getByRole('button', { name: 'Register document', exact: true }).click()
  const form = panel.getByLabel('Document registration', { exact: true })
  await form.getByLabel('Document title', { exact: true }).fill('Reviewed architecture output')
  await form.getByLabel('Renderer name', { exact: true }).fill('Generator')
  await form.getByLabel('Renderer version', { exact: true }).fill('2.1')
  await form.getByLabel('Exact renderer configuration (JSON object)', { exact: true }).fill('{"template":"architecture-v2"}')
  await form.getByLabel('Generated document file', { exact: true }).setInputFiles({ name: 'report.pdf', mimeType: 'application/pdf', buffer: raw })
  await form.getByLabel('Document rationale', { exact: true }).fill('Rendered exact pinned bundle with the reviewed template.')
  return form
}

test('registration explicitly issues input and retains exact multipart metadata and UUID after uncertainty', async ({ page }) => {
  const { panel, writes, issued, fail } = await fixture(page)
  expect(issued).toHaveLength(0)
  const form = await fillRegistration(panel)
  await form.getByRole('button', { name: 'Issue input bundle for this state', exact: true }).click()
  await expect(form.getByLabel('Issued input receipt SHA-256')).toHaveValue(sha('b'))
  expect(issued).toHaveLength(1)
  await expect(form.getByRole('link', { name: 'Download issued bundle.json', exact: true })).toHaveAttribute('href', `/api/v1/projects/product/issued-exports/${sha('b')}/files/bundle.json`)
  fail(503)
  await form.getByRole('button', { name: 'Submit document for review', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Publication uncertain')
  await expect(form.getByLabel('Document rationale', { exact: true })).toHaveValue('Rendered exact pinned bundle with the reviewed template.')
  await form.getByRole('button', { name: 'Submit document for review', exact: true }).click()
  await expect.poll(() => writes.length).toBe(2)
  expect(writes[1]!.body).toEqual(writes[0]!.body)
  expect(writes[0]!.body).toMatchObject({ expected: sha('a'), expected_revision: null, issued_receipt_sha: sha('b'), renderer: { name: 'Generator', version: '2.1', source_revision: null }, configuration: { template: 'architecture-v2' }, purpose: 'architecture', filename: 'report.pdf', media_type: 'application/pdf' })
  expect(writes[0]!.raw!.includes(raw)).toBeTruthy()
  fail(0)
  await form.getByRole('button', { name: 'Submit document for review', exact: true }).click()
  await expect(panel.getByRole('status')).toContainText('submitted for independent review')
  expect(writes[2]!.body).toEqual(writes[0]!.body)
})

test('historical review requires acknowledgment and pins exact current revision while retaining previous approval', async ({ page }) => {
  const { panel, writes } = await fixture(page, 'reviewer')
  await panel.getByRole('button', { name: /Architecture report/, exact: false }).click()
  const detail = panel.getByLabel('Controlled document detail', { exact: true })
  await expect(detail).toContainText('Current recorded revision: submitted')
  await detail.getByText('Retained approved document', { exact: true }).click()
  await expect(detail).toContainText(`Approval is pinned to revision ${sha('2')}`)
  await expect(detail.getByRole('link', { name: 'Download exact approved document', exact: true })).toHaveAttribute('href', `/api/v1/projects/product/states/${sha('a')}/artifacts/${sha('3')}`)
  const review = detail.getByLabel('Independent documentary review', { exact: true })
  await review.getByLabel('Document review rationale', { exact: true }).fill('Reviewed these historical bytes and their exact declared input scope.')
  await expect(review.getByRole('button', { name: 'Approve document revision', exact: true })).toBeDisabled()
  await review.getByRole('checkbox').check()
  await review.getByRole('button', { name: 'Approve document revision', exact: true }).click()
  expect(writes[0]!.body).toMatchObject({ expected: sha('a'), document_id: 'architecture', revision: sha('1'), action: 'approve', acknowledge_historical: true })
})

test('request changes preserves review rationale and UUID after stale publication', async ({ page }) => {
  const { panel, writes, fail } = await fixture(page, 'reviewer')
  await panel.getByRole('button', { name: /Architecture report/ }).click()
  const review = panel.getByLabel('Independent documentary review', { exact: true })
  await review.getByLabel('Document review rationale', { exact: true }).fill('Update the supplier description before this artifact can be approved.')
  await review.getByRole('checkbox').check()
  fail(409)
  await review.getByRole('button', { name: 'Request document changes', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('input is retained')
  await review.getByRole('button', { name: 'Request document changes', exact: true }).click()
  expect(writes[1]!.body).toEqual(writes[0]!.body)
  expect(writes[0]!.body).toMatchObject({ action: 'request_changes', revision: sha('1'), acknowledge_historical: true })
})

test('read-only registry offers exact raw downloads and server-counted bounded pages in narrow layout', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes, reads } = await fixture(page, 'viewer')
  await expect(panel.getByRole('button', { name: 'Register document', exact: true })).toHaveCount(0)
  await panel.getByRole('button', { name: /Architecture report/ }).click()
  await expect(panel.getByLabel('Independent documentary review', { exact: true })).toHaveCount(0)
  const link = panel.getByRole('link', { name: 'Download exact recorded document', exact: true })
  const href = await link.getAttribute('href')
  expect(href).toBe(`/api/v1/projects/product/states/${sha('a')}/artifacts/${sha('c')}`)
  await expect(link).toHaveAttribute('download', '')
  const bytes = await page.evaluate(async path => Array.from(new Uint8Array(await (await fetch(path!)).arrayBuffer())), href)
  expect(Buffer.from(bytes)).toEqual(raw)
  await panel.getByRole('button', { name: 'Next documents', exact: true }).click()
  await expect.poll(() => reads.at(-1)).toBe('?offset=20&limit=20')
  await expect(panel.getByRole('button', { name: 'Next documents', exact: true })).toBeDisabled()
  await expect(page.locator('body')).toHaveJSProperty('scrollWidth', 390)
  expect(writes).toHaveLength(0)
})

test('author replacement pins existing revision without exposing self-approval or guessing configuration', async ({ page }) => {
  const { panel, writes } = await fixture(page)
  await panel.getByRole('button', { name: /Architecture report/ }).click()
  await expect(panel.getByLabel('Independent documentary review', { exact: true })).toHaveCount(0)
  await panel.getByRole('button', { name: 'Register replacement revision', exact: true }).click()
  const form = panel.getByLabel('Document registration', { exact: true })
  await expect(form.getByLabel('Exact renderer configuration (JSON object)', { exact: true })).toHaveValue('')
  await form.getByLabel('Exact renderer configuration (JSON object)', { exact: true }).fill('{}')
  await form.getByLabel('Generated document file', { exact: true }).setInputFiles({ name: 'replacement.pdf', mimeType: 'application/pdf', buffer: raw })
  await form.getByLabel('Document rationale', { exact: true }).fill('Explicit revised external rendering.')
  await form.getByRole('button', { name: 'Save document draft', exact: true }).click()
  await expect.poll(() => writes.length).toBe(1)
  expect(writes[0]!.body).toMatchObject({ expected_revision: sha('1'), document_id: 'architecture', configuration: {}, filename: 'replacement.pdf' })
})
