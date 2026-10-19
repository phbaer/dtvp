import { openNativeTools } from './nativeTools'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { expect, test, type Page } from '@playwright/test'
const sha = (s: string) => s.repeat(64)
async function fixture(page: Page, available = true) {
  let current = sha('a'), corrupt = false, fail = false
  const requests: URL[] = [], writes: string[] = []
  function result(url: URL) {
    const offset = Number(url.searchParams.get('offset') || 0)
    return { generation: url.searchParams.get('generation') || current, archive_sha256: sha('b'), meta_sha256: sha('c'), query: url.searchParams.get('q'), total: 26, next_offset: offset ? null : 25, limitations: ['META consistency is not publisher authentication.'], items: Array.from({ length: offset ? 1 : 25 }, (_, i) => ({ record_sha256: createHash('sha256').update(String(i + offset)).digest('hex'), member: 'chunk-1.json', record: { cpe: { cpeName: `cpe:2.3:a:vendor:catalog:${i + offset}:*:*:*:*:*:*:*`, cpeNameId: `id-${i + offset}`, deprecated: i === 0, titles: [{ title: `Catalog <script>unsafe()</script> ${i + offset}`, lang: 'en' }] } } })) }
  }
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (route.request().method() !== 'GET') writes.push(path)
    if (path.includes('/cpe/catalog')) {
      requests.push(url)
      if (path.endsWith('/search')) return route.fulfill({ status: fail ? 503 : 200, json: fail ? { detail: 'Rebuild index' } : result(url) })
      if (path.endsWith('/export')) {
        const capture = result(url), dictionary = capture.items.map(item => ({ cpeName: item.record.cpe.cpeName, cpeNameId: item.record.cpe.cpeNameId, source: `nvd-catalog:${capture.generation}` })), raw = JSON.stringify(dictionary)
        return route.fulfill({ json: { capture, content_base64: Buffer.from(raw).toString('base64'), artifact_sha256: corrupt ? sha('f') : createHash('sha256').update(raw).digest('hex'), unprojected_record_fields: ['titles'], selection_scope: 'This page only' } })
      }
      return route.fulfill({ json: { available, generation: available ? current : null, records: 2003, synthetic: true, source: 'Synthetic catalog demonstration', assurance: 'META_consistent_complete_archive', limitations: [] } })
    }
    let json: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') json = { id: 'person', name: 'Person', org_admin: false, playground: false, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') json = { items: [{ id: 'product', name: 'Catalog product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) json = { items: [] }
    else if (path.endsWith('/cpe/editor')) json = { policy_state: sha('d'), configuration: { catalog: [], rules: {}, offline_sources: {} }, capabilities: [], limitations: [] }
    await route.fulfill({ json })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Catalog product', exact: true }).click()
  await page.getByText('CPE discovery policy and reviewed mappings', { exact: true }).click()
  await page.getByText('Offline curated sources', { exact: true }).click()
  expect(requests).toHaveLength(0)
  await page.getByText('Local catalog (optional)', { exact: true }).click()
  const panel = page.getByLabel('Local CPE catalog', { exact: true })
  const search = async () => { await panel.getByLabel('Search local CPE catalog', { exact: true }).fill('catalog'); await panel.getByRole('button', { name: 'Search catalog', exact: true }).click(); await expect(panel).toContainText('26 matches') }
  return { panel, search, requests, writes, advance: () => { current = sha('e') }, corrupt: () => { corrupt = true }, fail: () => { fail = true } }
}
test('optional local catalog is lazy and never imports automatically', async ({ page }) => {
  const { panel, requests, writes } = await fixture(page, false)
  await expect(panel).toContainText('No catalog installed')
  expect(requests).toHaveLength(1); expect(writes).toHaveLength(0)
})
test('paging and exact candidate download retain generation after current catalog advances', async ({ page }) => {
  const { panel, search, requests, writes, advance } = await fixture(page)
  await search(); await expect(panel).toContainText('these records are invented'); advance()
  await panel.getByRole('button', { name: 'Next catalog page', exact: true }).click()
  await expect(panel).toContainText('1 on this page')
  await panel.getByRole('button', { name: 'Prepare this candidate page', exact: true }).click()
  const link = panel.getByRole('link', { name: 'Download candidate dictionary', exact: true })
  await expect(link).toBeVisible()
  const waiting = page.waitForEvent('download'); await link.click(); const download = await waiting
  expect(JSON.parse(await readFile((await download.path())!, 'utf8'))).toMatchObject([{ cpeNameId: 'id-25', source: `nvd-catalog:${sha('a')}` }])
  expect(requests.filter(url => /\/(search|export)$/.test(url.pathname)).every(url => url.searchParams.get('generation') === sha('a'))).toBeTruthy()
  expect(writes).toHaveLength(0)
})
test('corrupt export bytes fail before download', async ({ page }) => {
  const { panel, search, corrupt, writes } = await fixture(page)
  await search(); corrupt()
  await panel.getByRole('button', { name: 'Prepare this candidate page', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('byte hash differs')
  await expect(panel.getByRole('link', { name: 'Download candidate dictionary' })).toHaveCount(0)
  expect(writes).toHaveLength(0)
})
test('readonly mobile results escape source text, expose deprecated status and retain results on failure', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, search, fail, writes } = await fixture(page)
  await search()
  await expect(panel).toContainText('Deprecated'); await expect(panel).toContainText('<script>unsafe()</script>')
  await expect(panel.locator('script')).toHaveCount(0)
  fail(); await panel.getByRole('button', { name: 'Next catalog page', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Rebuild index')
  await expect(panel).toContainText('25 on this page')
  await expect(page.locator('body')).toHaveJSProperty('scrollWidth', 390)
  expect(writes).toHaveLength(0)
})
