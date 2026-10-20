import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'

async function fixture(page: Page, options: { readonly?: boolean; failure?: boolean; hold?: boolean; personas?: boolean } = {}) {
  let actor = 'author', release: (() => void) | undefined
  const writes: Record<string, unknown>[] = [], reads: string[] = []
  let created: { id: string; name: string; workspace_id: string } | null = null
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (path.endsWith('/playground/login')) { actor = request.postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (path === '/api/v1/projects' && request.method() === 'POST') {
      const input = request.postDataJSON(); writes.push(input)
      created = { id: 'new-product', name: input.name, workspace_id: input.workspace_id }
      if (options.hold) await new Promise<void>(resolve => { release = resolve })
      if (options.failure) return route.fulfill({ status: 503, json: { detail: 'Unknown creation outcome' } })
      return route.fulfill({ status: 201, json: created })
    }
    reads.push(url.pathname + url.search)
    let result: unknown = { items: [], next_cursor: null, next_offset: null }
    if (path === '/api/v1/me') result = { id: actor, name: actor, org_admin: false, playground: !!options.personas, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'readonly', name: 'Readers', capabilities: ['read'] }, ...options.readonly ? [] : [{ id: 'team', name: 'Builders', capabilities: ['read', 'write'] }]] }
    else if (path.endsWith('/playground/personas')) result = options.personas ? [{ id: 'author', name: 'author' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v1/catalog/projects') result = { items: created ? [created] : [], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [], next_offset: null }
    else if (path === '/api/v1/jobs') result = []
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  return { panel: page.getByLabel('Create native product', { exact: true }), writes, reads, release: () => release?.() }
}
async function prepare(panel: ReturnType<Page['getByLabel']>, name = 'New native product') {
  await panel.getByText('Add product', { exact: true }).click()
  await panel.getByLabel('Product name', { exact: true }).fill(name)
}

test('native-only manager can create a product and proceed directly to composition intake', async ({ page }) => {
  const { panel, writes, reads } = await fixture(page)
  await expect(panel).toBeVisible()
  await prepare(panel)
  await expect(panel.getByLabel('Product owner team').getByRole('option')).toHaveCount(1)
  await expect(panel.getByLabel('Product owner team')).toHaveValue('team')
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Activity', exact: true })).toBeDisabled()
  await panel.getByRole('button', { name: 'Create product', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toContainText('New native product')
  await expect(page.getByText('No journal-backed versions. Import a baseline to start.', { exact: true })).toBeVisible()
  expect(writes).toEqual([{ workspace_id: 'team', name: 'New native product' }])
  expect(reads.some(path => path.includes('/new-product/versions'))).toBe(true)
  expect(reads.some(path => path.includes('/releases') || path.includes('/findings'))).toBe(false)
  await expect(page.getByRole('button', { name: 'Activity', exact: true })).toBeEnabled()
  await openProductView(page, 'Imports')
  await openDisclosure(page.locator('.knowledge-intake > summary'))
  await expect(page.getByRole('button', { name: 'Inspect target', exact: true })).toBeVisible()
})

test('uncertain creation cannot be repeated; inspect and open the existing result', async ({ page }) => {
  const { panel, writes, reads } = await fixture(page, { failure: true })
  await prepare(panel); await panel.getByRole('button', { name: 'Create product', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('may already have succeeded')
  await expect(panel.getByRole('button', { name: 'Create product', exact: true })).toBeDisabled()
  await expect(panel.getByLabel('Product name', { exact: true })).toHaveValue('New native product')
  await panel.getByRole('button', { name: 'Inspect product catalog', exact: true }).click()
  await expect(panel.getByRole('status')).toContainText('1 matching products loaded')
  expect(reads.some(path => path.includes('/catalog/projects?') && path.includes('workspace_id=team') && path.includes('q=New+native+product'))).toBe(true)
  await panel.getByRole('button', { name: 'Open New native product', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toContainText('New native product')
  expect(writes).toHaveLength(1)
})

test('discarding an unsent draft releases navigation; narrow layouts remain usable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes } = await fixture(page)
  await prepare(panel, 'A long product name '.repeat(10))
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy()
  await panel.getByRole('button', { name: 'Discard product draft', exact: true }).click()
  await expect(panel.getByLabel('Product name', { exact: true })).toHaveValue('')
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
  expect(writes).toHaveLength(0)
})

test('read-only users do not receive a product creation action', async ({ page }) => {
  const { panel, writes } = await fixture(page, { readonly: true })
  await expect(panel).toHaveCount(0)
  expect(writes).toHaveLength(0)
})

test('actor roundtrip cannot select the late creation result of another session', async ({ page }) => {
  const { panel, writes, release } = await fixture(page, { hold: true, personas: true })
  await prepare(panel); await panel.getByRole('button', { name: 'Create product', exact: true }).click()
  await expect.poll(() => writes.length).toBe(1)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('author')
  const response = page.waitForResponse(row => row.url().endsWith('/api/v1/projects') && row.request().method() === 'POST')
  release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toContainText('Select…')
  await expect(panel.getByLabel('Product name', { exact: true })).toHaveValue('')
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
  expect(writes).toHaveLength(1)
})
