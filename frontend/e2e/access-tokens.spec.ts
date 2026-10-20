import { expect, test, type Page } from '@playwright/test'

async function fixture(page: Page, uncertain = false) {
  const writes: any[] = [], revoked: string[] = []
  const tokens: any[] = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname, method = route.request().method()
    if (path.endsWith('/me')) return route.fulfill({ json: { id: 'admin', name: 'Admin', org_admin: true, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read','write','manage','evidence'] }] } })
    if (path.endsWith('/credentials') && method === 'POST') {
      const body = route.request().postDataJSON(); writes.push(body)
      tokens.push({ id: 'ci-token', workspace_id: 'team', name: body.name, projects: body.projects, capabilities: body.capabilities, expires_at: '2027-10-20T00:00:00Z', revoked: false })
      return route.fulfill({ status: uncertain ? 503 : 201, json: uncertain ? { detail: 'Response lost' } : { id: 'ci-token', token: 'synthetic-ci-secret', expires_at: '2027-10-20T00:00:00Z' } })
    }
    if (path.endsWith('/credentials')) return route.fulfill({ json: tokens })
    if (method === 'DELETE' && path.includes('/credentials/')) { revoked.push(path.split('/').at(-1)!); tokens[0].revoked = true; return route.fulfill({ status: 204, body: '' }) }
    if (path.endsWith('/playground/personas')) return route.fulfill({ json: [] })
    if (path.endsWith('/catalog/projects')) return route.fulfill({ json: { items: [{ id:'product', name:'Gateway', capabilities:['read','write'] }], next_cursor:null } })
    return route.fulfill({ json: { items: [], capabilities: [], next_cursor: null } })
  })
  await page.goto('/?page=Administration')
  const panel = page.getByRole('region', { name: 'CI and consumer access tokens' })
  await expect(panel.getByRole('button', { name: 'Refresh tokens' })).toBeEnabled()
  return { panel, writes, revoked }
}

test('CI defaults to a year, reveals the token once and supports explicit revocation', async ({ page }) => {
  const f = await fixture(page)
  await f.panel.getByLabel('Token name', { exact: true }).fill('Nightly CI')
  await expect(f.panel.getByLabel('Lifetime (days)')).toHaveValue('365')
  await f.panel.getByRole('button', { name: 'Issue access token' }).click()
  await expect(f.panel.getByLabel('Copy now; shown only once')).toHaveValue('synthetic-ci-secret')
  expect(f.writes).toEqual([{ workspace_id:'team', name:'Nightly CI', projects:[], capabilities:['read','write'], hours:8760 }])
  await expect(f.panel.getByRole('button', { name:'Issue access token' })).toBeDisabled()
  await f.panel.getByRole('button', { name:'Revoke Nightly CI', exact:true }).click()
  expect(f.revoked).toEqual([])
  await f.panel.getByRole('button', { name:'Confirm revoke Nightly CI', exact:true }).click()
  await expect(f.panel.getByRole('button', { name:'Revoke Nightly CI', exact:true })).toBeDisabled()
  await expect(f.panel.getByLabel('Copy now; shown only once')).toHaveCount(0)
  expect(f.revoked).toEqual(['ci-token'])
})

test('product and capability restrictions can be configured independently of lifetime', async ({ page }) => {
  const f = await fixture(page)
  await f.panel.getByLabel('Token name', { exact:true }).fill('Generator')
  await f.panel.getByLabel('Token profile').selectOption('consumer')
  await f.panel.getByLabel('Lifetime (days)').fill('730')
  await f.panel.getByLabel('Product scope').selectOption('selected')
  await f.panel.getByRole('button', { name:/Add token product/ }).click()
  await page.getByRole('option', { name:'Gateway', exact:true }).click()
  await f.panel.getByRole('button', { name:'Issue access token' }).click()
  await expect(f.panel.getByLabel('Copy now; shown only once')).toBeVisible()
  expect(f.writes[0]).toMatchObject({ projects:['product'], capabilities:['read'], hours:17520 })
})

test('uncertain creation retains inspection and revoke access without automatic retry', async ({ page }) => {
  const f = await fixture(page, true)
  await page.setViewportSize({ width:390, height:844 })
  await f.panel.getByLabel('Token name', { exact:true }).fill('Unconfirmed CI')
  await f.panel.getByRole('button', { name:'Issue access token' }).click()
  await expect(f.panel.getByRole('alert')).toContainText('not retried automatically')
  await expect(f.panel.getByRole('button', { name:'Issue access token' })).toBeDisabled()
  await f.panel.getByRole('button', { name:'Refresh tokens' }).click()
  await expect(f.panel.getByRole('button', { name:'Revoke Unconfirmed CI', exact:true })).toBeEnabled()
  expect(f.writes).toHaveLength(1)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})
