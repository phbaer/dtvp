import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
import { createHash } from 'node:crypto'
const sha = (value: string) => value.repeat(64)
const bytes = '[{"cpeName":"cpe:2.3:a:vendor:library:*:*:*:*:*:node.js:*:*","source":"fixture"}]'
async function fixture(page: Page, readonly = false) {
  let pin = sha('a'), failure = 0, previewFailure = 0, captureFailure = 0, corruptCapture = false, projection = 'current'
  const captures: Record<string, unknown>[] = [], previews: Record<string, unknown>[] = [], writes: Record<string, unknown>[] = [], reads: string[] = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/cpe/sources/refresh')) {
      const body = route.request().postDataJSON(); captures.push(body)
      if (captureFailure) return route.fulfill({ status: captureFailure, json: { detail: 'NVD provider unavailable; no policy changed' } })
      const artifact = createHash('sha256').update(bytes).digest('hex')
      const sourceInput = { ...body, kind: 'dictionary', source: 'nvd-scoped-query', revision: artifact, occurred_at: '2026-10-16T00:00:00Z', artifact_sha256: corruptCapture ? sha('f') : artifact, content_base64: Buffer.from(bytes).toString('base64'), acquisition: { provider: 'nvd', keyword: body.keyword, captured_at: '2026-10-16T00:00:00Z', artifact_sha256: artifact } }
      return route.fulfill({ json: { format: 'dtvp.cpe-scoped-capture/1', committed: false, source_input: sourceInput, preview: { committed: false, policy_state: body.expected, preview_digest: sha('d'), source: { source: 'nvd-scoped-query', revision: artifact, artifact_sha256: sourceInput.artifact_sha256, records: 1, losses: {} }, replaces: null, limitations: ['Complete scoped keyword subset, not the full dictionary.'] } } })
    }
    if (path.endsWith('/cpe/sources/preview')) {
      const body = route.request().postDataJSON(); previews.push(body)
      if (previewFailure) return route.fulfill({ status: previewFailure, json: { detail: 'temporary preview failure' } })
      return route.fulfill({ json: { committed: false, policy_state: body.expected, preview_digest: sha('d'), source: { source: body.source, revision: body.revision, artifact_sha256: body.artifact_sha256, records: 1, losses: {} }, replaces: null, limitations: ['Offline curated source claims; no approval.'] } })
    }
    if (path.endsWith('/cpe/sources/apply')) {
      writes.push(route.request().postDataJSON())
      if (failure) return route.fulfill({ status: failure, json: { detail: 'retry exact request' } })
      if (projection === 'current') pin = sha('b')
      return route.fulfill({ status: 201, json: { committed: true, projection } })
    }
    if (path.includes('/cpe/sources/') && route.request().method() === 'GET') {
      reads.push(route.request().url())
      const state = path.split('/').at(-2)
      return route.fulfill({ json: { policy_state: state, source: { source: 'Historical source', revision: 'rev-previous' }, items: [{ trust: 'historical_unverified' }], total: 26, next_offset: new URL(route.request().url()).searchParams.get('offset') === '0' ? 25 : null, limitations: [] } })
    }
    let result: unknown = { items: [], capabilities: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: 'person', name: 'Person', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'CPE product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [] }
    else if (path.endsWith('/cpe/editor')) result = { policy_state: pin, configuration: { algorithm_version: 'dtvp.cpe-discovery/1', catalog: [], rules: {}, offline_sources: {} }, capabilities: readonly ? [] : ['configure'], limitations: [] }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'CPE product', exact: true }).click()
  await openProductView(page, 'Settings', 'CPE identity policy')
  await openDisclosure(page.getByText('CPE discovery policy and reviewed mappings', { exact: true }))
  const parent = page.getByLabel('CPE discovery policy', { exact: true })
  await expect(parent).toContainText('0 catalog entries')
  await parent.getByText('Offline curated sources', { exact: true }).click()
  return { parent, panel: page.getByLabel('Offline curated CPE sources', { exact: true }), captures, previews, writes, reads, captureFail: (status: number) => { captureFailure = status }, corrupt: () => { corruptCapture = true }, fail: (status: number) => { failure = status }, previewFail: (status: number) => { previewFailure = status }, advance: () => { pin = sha('c') }, pending: () => { projection = 'pending' }, current: () => { projection = 'current' } }
}
async function prepare(panel: ReturnType<Page['getByLabel']>) {
  await panel.getByLabel('Exact source file').setInputFiles({ name: 'curated.json', mimeType: 'application/json', buffer: Buffer.from(bytes) })
  await panel.getByLabel('Source attribution', { exact: true }).fill('Organization extract')
  await panel.getByLabel('Declared source revision').fill('revision-1')
  await panel.getByLabel('Replacement reason').fill('Reviewed offline input')
  await panel.getByRole('button', { name: 'Preview offline source replacement' }).click()
}
test('exact source capture and CAS pins survive503; confirmation precedes write', async ({ page }) => {
  const { parent, panel, writes, previews, fail } = await fixture(page)
  await prepare(panel)
  await expect(panel.getByRole('button', { name: 'Publish previewed offline source' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  await expect(parent.getByRole('button', { name: 'Prepare complete policy replacement', exact: true })).toBeDisabled()
  expect(writes).toHaveLength(0)
  await panel.getByRole('checkbox').check(); fail(503)
  await panel.getByRole('button', { name: 'Publish previewed offline source' }).click()
  await expect(panel.getByRole('alert')).toContainText('Retry the identical captured request')
  fail(0); await panel.getByRole('button', { name: 'Retry identical source publication' }).click()
  await expect(panel.getByRole('status')).toContainText('Offline source committed')
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1])
  expect(Buffer.from(String(writes[0]!.content_base64), 'base64').toString()).toBe(bytes)
  expect(writes[0]).toMatchObject({ expected: sha('a'), request_id: previews[0]!.request_id, preview_digest: sha('d') })
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
})
test('first preview503 keeps original upload and explicit discard releases context', async ({ page }) => {
  const { panel, previews, previewFail, writes } = await fixture(page)
  previewFail(503); await prepare(panel)
  await expect(panel.getByRole('alert')).toBeVisible()
  await expect(panel.getByLabel('Source attribution', { exact: true })).toBeDisabled()
  previewFail(0); await panel.getByRole('button', { name: 'Retry identical source preview' }).click()
  expect(previews).toHaveLength(2); expect(previews[0]).toEqual(previews[1]); expect(writes).toHaveLength(0)
  await panel.getByRole('button', { name: 'Discard offline source draft' }).click()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
  expect(await panel.getByLabel('Exact source file').evaluate(element => (element as HTMLInputElement).files?.length)).toBe(0)
  await prepare(panel)
  expect(previews).toHaveLength(3)
  expect(previews[2]!.content_base64).toEqual(previews[0]!.content_base64)
  expect(previews[2]!.request_id).not.toEqual(previews[0]!.request_id)
})
test('committed pending retains exact receipt request without pretending failure', async ({ page }) => {
  const { panel, writes, pending, current } = await fixture(page)
  await prepare(panel); await panel.getByRole('checkbox').check(); pending()
  await panel.getByRole('button', { name: 'Publish previewed offline source' }).click()
  await expect(panel.getByRole('status')).toContainText('Source committed; projection is pending')
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
  current(); await panel.getByRole('button', { name: 'Refresh committed source receipt' }).click()
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1])
})
test('reader can browse exact retained policy; paging and download remain on captured source despite edited controls', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, reads, writes } = await fixture(page, true)
  await expect(panel.getByLabel('Import offline CPE source')).toHaveCount(0)
  await panel.getByText('Browse retained source claims', { exact: true }).click()
  await panel.getByLabel('Retained policy SHA (empty uses current)').fill(sha('e'))
  await panel.getByRole('button', { name: 'Read retained source', exact: true }).click()
  await expect(panel).toContainText('Historical source')
  await panel.getByLabel('Retained policy SHA (empty uses current)').fill(sha('f'))
  await panel.getByLabel('Retained source kind', { exact: true }).selectOption('mapping_history')
  await panel.getByRole('button', { name: 'Next source records' }).click()
  expect(reads[1]).toContain(`/${sha('e')}/dictionary?offset=25`)
  await expect(panel.getByRole('link', { name: 'Download exact retained source' })).toHaveAttribute('href', new RegExp(`/${sha('e')}/dictionary/artifact$`))
  expect(writes).toHaveLength(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy()
})

async function prepareRemote(panel: ReturnType<Page['getByLabel']>) {
  await panel.getByLabel('Capture method').selectOption('nvd')
  await panel.getByLabel('NVD query keyword').fill('library')
  await panel.getByLabel('Replacement reason').fill('Refresh scoped evidence')
  await panel.getByRole('button', { name: 'Capture scoped NVD source' }).click()
}
test('scoped capture previews without publishing; exact apply retries retain source bytes and query', async ({ page }) => {
  const { panel, captures, previews, writes, fail } = await fixture(page)
  await prepareRemote(panel)
  await expect(panel.getByRole('button', { name: 'Publish previewed offline source' })).toBeDisabled()
  expect(captures).toHaveLength(1); expect(previews).toHaveLength(0); expect(writes).toHaveLength(0)
  await expect(panel).toContainText('nvd-scoped-query')
  await panel.getByRole('checkbox').check(); fail(503)
  await panel.getByRole('button', { name: 'Publish previewed offline source' }).click()
  await expect(panel.getByRole('alert')).toContainText('Retry the identical captured request')
  fail(0); await panel.getByRole('button', { name: 'Retry identical source publication' }).click()
  await expect(panel.getByRole('status')).toContainText('Offline source committed')
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1]); expect(captures).toHaveLength(1)
  expect(writes[0]).toMatchObject({ expected: sha('a'), acquisition: { provider: 'nvd', keyword: 'library' } })
  expect(Buffer.from(String(writes[0]!.content_base64), 'base64').toString()).toBe(bytes)
})
test('failed remote capture retains original query and policy; explicit retry makes no publication', async ({ page }) => {
  const { panel, captures, writes, captureFail } = await fixture(page)
  captureFail(502); await prepareRemote(panel)
  await expect(panel.getByRole('alert')).toContainText('NVD provider unavailable')
  await expect(panel.getByLabel('NVD query keyword')).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  captureFail(0); await panel.getByRole('button', { name: 'Retry scoped NVD capture' }).click()
  await expect(panel.getByRole('button', { name: 'Publish previewed offline source' })).toBeVisible()
  expect(captures).toHaveLength(2); expect(captures[0]).toEqual(captures[1]); expect(writes).toHaveLength(0)
  await panel.getByRole('button', { name: 'Discard offline source draft' }).click()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
})
test('changed captured bytes fail closed before any publication', async ({ page }) => {
  const { panel, writes, corrupt } = await fixture(page)
  corrupt(); await prepareRemote(panel)
  await expect(panel.getByRole('alert')).toContainText('bytes differ from their digest')
  await expect(panel.getByRole('button', { name: 'Publish previewed offline source' })).toHaveCount(0)
  expect(writes).toHaveLength(0)
})
