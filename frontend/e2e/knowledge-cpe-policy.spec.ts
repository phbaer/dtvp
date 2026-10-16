import { expect, test, type Page } from '@playwright/test'
const sha = (value: string) => value.repeat(64)
const catalog = [{ purl: 'pkg:npm/parser', cpe: 'cpe:2.3:a:example:parser:*:*:*:*:*:*:*:*', source: 'supplied-dictionary', identification_basis: 'community_mapping', reason: 'Supplied explicit identity' }]
const rules = { 'pkg:npm/alias': { target_purl: 'pkg:npm/parser', status: 'internal', source: 'organization', reason: 'Reviewed alias' } }
async function fixture(page: Page, readonly = false) {
  let pin = sha('a'), failure = 0
  const writes: Record<string, unknown>[] = [], previews: Record<string, unknown>[] = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/cpe/preview')) {
      const body = route.request().postDataJSON(); previews.push(body)
      return route.fulfill({ json: { committed: false, policy_state: body.expected, preview_digest: sha('d'), configuration: { algorithm_version: 'dtvp.cpe-discovery/1', catalog: body.catalog, rules: body.rules }, changes: { catalog_added: 1, catalog_removed: 0, rules_added: 0, rules_removed: 1, rules_changed: 0 }, limitations: ['Preview normalizes supplied policy inputs only; no product state or CPE identity is adopted.'] } })
    }
    if (path.endsWith('/cpe') && route.request().method() === 'PUT') {
      writes.push(route.request().postDataJSON())
      if (failure) return route.fulfill({ status: failure, json: { detail: 'Unavailable or conflicting policy' } })
      pin = sha('b'); return route.fulfill({ status: 201, json: { committed: true, projection: 'current' } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') result = { id: 'person', name: 'Person', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v2/catalog/projects') result = { items: [{ id: 'product', name: 'CPE product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [] }
    else if (path.endsWith('/cpe/editor')) result = { policy_state: pin, configuration: { algorithm_version: 'dtvp.cpe-discovery/1', catalog, rules }, capabilities: readonly ? [] : ['configure'], limitations: ['Imported source/basis claims are not independently verified; candidates are not approved mappings.'] }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'CPE product', exact: true }).click()
  await page.getByText('CPE discovery policy and reviewed mappings', { exact: true }).click()
  const panel = page.getByLabel('CPE discovery policy', { exact: true })
  await expect(panel).toContainText('1 catalog entries · 1 mapping rules')
  return { panel, writes, previews, fail: (code: number) => { failure = code }, advance: () => { pin = sha('c') } }
}
async function prepare(panel: ReturnType<Page['getByLabel']>) {
  await panel.getByRole('button', { name: 'Prepare complete policy replacement', exact: true }).click()
  await panel.getByLabel('Supplied CPE catalog JSON', { exact: true }).fill(JSON.stringify([...catalog, { ...catalog[0], purl: 'pkg:npm/other' }]))
  await panel.getByLabel('Reviewed mapping rules JSON', { exact: true }).fill('{}')
  await panel.getByRole('button', { name: 'Preview complete policy replacement', exact: true }).click()
  await expect(panel.getByLabel('CPE policy replacement preview')).toContainText('rules removed')
}
test('preview and explicit full-replacement confirmation precede publication;503 replay keeps exact original pins', async ({ page }) => {
  const { panel, writes, previews, fail, advance } = await fixture(page)
  await prepare(panel)
  expect(writes).toHaveLength(0)
  await expect(panel.getByRole('button', { name: 'Publish previewed CPE policy' })).toBeDisabled()
  await panel.getByRole('checkbox').check(); fail(503)
  await panel.getByRole('button', { name: 'Publish previewed CPE policy' }).click()
  await expect(panel.getByRole('alert')).toContainText('Retry the identical captured request')
  advance(); await panel.getByRole('button', { name: 'Refresh current CPE policy' }).click()
  await expect(panel).toContainText('request still uses its original policy state')
  fail(0); await panel.getByRole('button', { name: 'Retry identical CPE policy publication' }).click()
  await expect(panel.getByRole('status')).toContainText('No component identity, vulnerability assessment or approval was adopted')
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1]); expect(writes[0]).toEqual(previews[0])
  expect(writes[0]).toMatchObject({ expected: sha('a'), rules: {} })
})
test('known policy advancement disables first publication and explicit discard is required to repin', async ({ page }) => {
  const { panel, writes, advance } = await fixture(page)
  await prepare(panel); await panel.getByRole('checkbox').check(); advance()
  await panel.getByRole('button', { name: 'Refresh current CPE policy' }).click()
  await expect(panel.getByRole('button', { name: 'Publish previewed CPE policy' })).toBeDisabled()
  expect(writes).toHaveLength(0)
  await panel.getByRole('button', { name: 'Discard captured request and edit original inputs' }).click()
  await expect(panel.getByLabel('Supplied CPE catalog JSON')).toHaveValue(JSON.stringify([...catalog, { ...catalog[0], purl: 'pkg:npm/other' }]))
  await panel.getByRole('button', { name: 'Discard edits and start from loaded policy' }).click()
  await expect(panel.getByLabel('Supplied CPE catalog JSON')).toHaveValue(JSON.stringify(catalog, null, 2))
})
test('readonly policy attribution and long inputs fit narrow layout before an inventory exists', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes } = await fixture(page, true)
  await expect(panel.getByRole('button', { name: 'Prepare complete policy replacement' })).toHaveCount(0)
  await panel.getByText('Current policy, attribution and limits', { exact: true }).click()
  await expect(panel).toContainText('supplied-dictionary')
  await expect(panel).toContainText('not independently verified')
  expect((await panel.boundingBox())!.width).toBeLessThanOrEqual(390)
  expect(writes).toHaveLength(0)
})
test('invalid editor JSON cannot trigger preview or publication', async ({ page }) => {
  const { panel, previews, writes } = await fixture(page)
  await panel.getByRole('button', { name: 'Prepare complete policy replacement' }).click()
  await panel.getByLabel('Reviewed mapping rules JSON').fill('[]')
  await panel.getByRole('button', { name: 'Preview complete policy replacement' }).click()
  await expect(panel.getByRole('alert')).toContainText('Catalog must be a JSON array and rules a JSON object')
  expect(previews).toHaveLength(0); expect(writes).toHaveLength(0)
})
