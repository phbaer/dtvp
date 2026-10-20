import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const pin = 'a'.repeat(64), revision = 'b'.repeat(64)
async function fixture(page: Page, manage = true) {
  const posts: { path: string; body: Record<string, unknown> }[] = []
  let fail = 0, applied = false
  const fields = { mode: 'component', name: ':literal', namespace_mode: 'exact', namespace: 'legacy', purl: '', case_sensitive: false }
  const original = { selector: 'legacy::literal', team_id: 'platform', aliases: ['legacy-label'], versions: null }
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (route.request().method() !== 'GET') posts.push({ path, body: route.request().postDataJSON() as Record<string, unknown> })
    let data: unknown = { items: [], capabilities: [], next_cursor: null }
    if (path === '/api/v1/me') data = { id: 'reader', name: 'Reader', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'product', name: 'Ownership product', capabilities: manage ? ['read', 'manage'] : ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.1', state: pin }], next_offset: null }
    else if (path.endsWith('/workspace')) data = { state: pin, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/ownership/editor')) data = { policy_state: applied ? revision : pin, policy: { rules: [original], context_roots: { '7.1.1': ['root-a'] } }, versions: { '7.1.1': pin, '7.1.2': revision }, selectors: [{ raw: original.selector, fields, representable: false }], capabilities: manage ? ['manage'] : [], available_teams: [{ id: 'platform', name: 'Platform' }, { id: 'operations', name: 'Operations' }] }
    else if (path.endsWith('/selectors/encode')) data = { raw: 'server-encoded-selector', fields: posts.at(-1)!.body, representable: true }
    else if (path.endsWith('/editor/preview')) data = { preview_digest: revision, versions: { '7.1.1': { before: { contexts: 10 }, after: { contexts: 10, by_status: { resolved: 10 } }, changed_contexts: 4, added_contexts: 0, removed_contexts: 0 }, '7.1.2': { before: { contexts: 9 }, after: { contexts: 9, by_status: { resolved: 9 } }, changed_contexts: 3, added_contexts: 0, removed_contexts: 0 } }, limitations: ['Ownership delegates recursively; aliases are descriptive, not extra owners.'] }
    else if (path.endsWith('/editor/apply')) { if (fail) return route.fulfill({ status: fail, json: { detail: 'Changed or unavailable' } }); applied = true; data = { committed: true, projection: 'current' } }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Ownership product' }).click()
  await openProductView(page, 'Settings', 'Component ownership')
  await openDisclosure(page.getByText('Component ownership', { exact: true }))
  const panel = page.getByRole('region', { name: 'Component ownership editor' })
  await expect(panel).toContainText('legacy::literal')
  return { panel, posts, fail: (value: number) => { fail = value } }
}
test('reader sees raw ownership and recursive responsibility without editing', async ({ page }) => {
  const { panel, posts } = await fixture(page, false)
  await expect(panel).toContainText('Read only')
  await expect(panel.getByRole('button', { name: 'Add ownership rule' })).toHaveCount(0)
  await expect(panel).toContainText('dependencies recursively')
  await panel.getByText('Preserved consuming roots and raw policy', { exact: true }).click()
  await expect(panel.locator('pre')).toContainText('root-a')
  expect(posts).toHaveLength(0)
})
test('builder uses backend encoding, separate namespace and case, keeps full policy and roots', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, posts } = await fixture(page)
  await panel.getByRole('button', { name: 'Add ownership rule' }).click()
  const form = panel.getByRole('form', { name: 'Ownership rule editor' })
  await form.getByLabel('Component name', { exact: true }).fill('Library')
  await form.getByRole('combobox', { name: 'Namespace matching', exact: true }).selectOption('exact')
  await form.getByLabel('Namespace', { exact: true }).fill('acme')
  await form.getByRole('checkbox', { name: 'Case-sensitive matching' }).check()
  await form.getByRole('combobox', { name: 'Primary responsible team' }).selectOption('operations')
  await form.getByText('Descriptive aliases', { exact: true }).click()
  await form.getByLabel('Alias labels (one per line)').fill('display-only')
  await form.getByRole('button', { name: 'Keep rule in draft' }).click()
  await expect(panel).toContainText('server-encoded-selector')
  const encoding = posts.find(row => row.path.endsWith('/selectors/encode'))!
  expect(encoding.body).toMatchObject({ name: 'Library', namespace_mode: 'exact', namespace: 'acme', case_sensitive: true })
  await panel.getByRole('button', { name: 'Preview complete ownership policy' }).click()
  await expect(panel.getByRole('region', { name: 'Prepared ownership policy' })).toContainText('7.1.2')
  const preview = posts.find(row => row.path.endsWith('/editor/preview'))!.body
  expect(preview.context_roots).toEqual({ '7.1.1': ['root-a'] })
  expect(preview.rules).toEqual([{ selector: 'legacy::literal', team_id: 'platform', aliases: ['legacy-label'], versions: null }, { selector: 'server-encoded-selector', team_id: 'operations', aliases: ['display-only'], versions: null }])
  expect((await panel.boundingBox())!.width).toBeLessThanOrEqual(390)
})
test('uncertain retries preserve prepared request and conflicts retain drafts', async ({ page }) => {
  const { panel, posts, fail } = await fixture(page)
  await panel.getByRole('button', { name: 'Preview complete ownership policy' }).click()
  fail(503)
  await panel.getByRole('button', { name: 'Apply reviewed ownership policy' }).click()
  await expect(panel.getByRole('alert')).toContainText('Retry this exact prepared policy')
  fail(409)
  await panel.getByRole('button', { name: 'Apply reviewed ownership policy' }).click()
  await expect(panel.getByRole('alert')).toContainText('Your draft is retained')
  const attempted = posts.filter(row => row.path.endsWith('/editor/apply'))
  expect(attempted[0]!.body).toEqual(attempted[1]!.body)
  fail(0)
  await panel.getByRole('button', { name: 'Apply reviewed ownership policy' }).click()
  await expect(panel.getByRole('status').filter({ hasText: 'Ownership updated' })).toContainText('Ownership updated across the pinned versions')
  expect(posts.filter(row => row.path.endsWith('/editor/apply'))[2]!.body).toEqual(attempted[0]!.body)
})

for (const mode of ['known_empty', 'purl']) {
  test(`optional version scope and ${mode} fields stay explicit backend inputs`, async ({ page }) => {
    const { panel, posts } = await fixture(page)
    await panel.getByRole('button', { name: 'Add ownership rule' }).click()
    const form = panel.getByRole('form', { name: 'Ownership rule editor' })
    if (mode === 'purl') {
      await form.getByRole('combobox', { name: 'Match by', exact: true }).selectOption('purl')
      await form.getByLabel('Package URL', { exact: true }).fill('pkg:generic/acme/library@2')
    } else {
      await form.getByLabel('Component name', { exact: true }).fill('Library')
      await form.getByRole('combobox', { name: 'Namespace matching', exact: true }).selectOption('known_empty')
      await expect(form.getByLabel('Namespace', { exact: true })).toHaveCount(0)
    }
    await form.getByRole('combobox', { name: 'Primary responsible team' }).selectOption('platform')
    await form.getByRole('combobox', { name: 'Product-version scope' }).selectOption('selected')
    await form.getByRole('listbox', { name: 'Scoped versions' }).selectOption(['7.1.2'])
    await form.getByRole('button', { name: 'Keep rule in draft' }).click()
    await panel.getByRole('button', { name: 'Preview complete ownership policy' }).click()
    await expect(panel.getByRole('region', { name: 'Prepared ownership policy' })).toBeVisible()
    const request = posts.find(row => row.path.endsWith('/selectors/encode'))!.body
    expect(mode === 'purl' ? request.purl : request.namespace_mode).toBe(mode === 'purl' ? 'pkg:generic/acme/library@2' : 'known_empty')
    const rules = posts.find(row => row.path.endsWith('/editor/preview'))!.body.rules as { versions: string[] | null }[]
    expect(rules[1]!.versions).toEqual(['7.1.2'])
    expect(rules[0]!.versions).toBeNull()
  })
}
