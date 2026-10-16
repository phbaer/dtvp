import { expect, test, type Page } from '@playwright/test'
const base = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
const contextual = `${base}/CR:L/IR:L/AR:L`
async function fixture(page: Page, personas = false) {
  let actor = 'coordinator', state = 'source-before', outcome = 'current', holdPreview = false, holdPublish = false
  let releasePreview: (() => void) | undefined, releasePublish: (() => void) | undefined
  const previews: Record<string, unknown>[] = [], publications: Record<string, unknown>[] = [], reads: string[] = []
  function finding(index: number) { return { id: `finding-${index}`, context_id: `context-${index}`, vulnerability_id: `CVE-2099-${index}`, component: { name: `TLS ${index}`, version: '2' }, context: { component_ref: `tls-${index}`, root_ref: `application-${index}`, team_id: 'team', status: 'resolved' }, description: `Source evidence ${index}`, source_ratings: [{ vector: base, score: 9.8, method: 'CVSSv31' }], published_score: null, coverage: { status: 'approved', assessment: null }, capabilities: ['rescore'] } }
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (path === '/api/v2/playground/login') { actor = route.request().postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (path.endsWith('/scoring/preview')) {
      const body = route.request().postDataJSON(); previews.push(body)
      if (holdPreview) { holdPreview = false; await new Promise<void>(resolve => { releasePreview = resolve }) }
      return route.fulfill({ json: { preview: 'exact-preview-token', eligible: true, proposal: { base_score: 9.8, score: 4.2, base_vector: body.base_vector, vector: body.vector, version: '3.1' }, blocked: [] } })
    }
    if (path.endsWith('/scoring/publish')) {
      publications.push(route.request().postDataJSON())
      if (holdPublish) { holdPublish = false; await new Promise<void>(resolve => { releasePublish = resolve }) }
      if (outcome === '503') return route.fulfill({ status: 503, json: { detail: 'Publication uncertain; retry identical input' } })
      if (outcome === '409') return route.fulfill({ status: 409, json: { detail: 'Expected source changed' } })
      if (outcome !== 'uncommitted') state = 'source-after'
      return route.fulfill({ json: { committed: outcome !== 'uncommitted', projection: outcome === 'pending' ? 'pending' : 'current' } })
    }
    reads.push(path)
    let data: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') data = { id: actor, name: actor, org_admin: false, playground: personas, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v2/playground/personas') data = personas ? [{ id: 'coordinator', name: 'coordinator' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v2/catalog/projects') data = { items: [{ id: 'product', name: 'Score product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.1', state }], next_offset: null }
    else if (path.endsWith('/workspace')) data = { state, project_id: 'product', version: '7.1.1', items: [finding(0), finding(1)], next_offset: null, statistics: { totals: { context_findings: 2, unique_vulnerabilities: 2 }, by_status: { approved: 2 }, by_team: { team: 2 }, severity: {}, recorded: 2, submitted: 2, approved: 2 } }
    else if (path.includes('/workspace/')) data = { ...finding(Number(path.split('/').at(-1)!.replace('CVE-2099-', ''))), state }
    await route.fulfill({ json: data })
  })
  await page.goto('/?page=Knowledge')
  async function select() {
    await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
    await page.getByRole('option', { name: 'Score product', exact: true }).click()
    await page.getByRole('button', { name: 'CVE-2099-0', exact: true }).click()
    await page.getByRole('button', { name: 'scoring', exact: true }).click()
  }
  await select()
  const detail = page.getByRole('region', { name: 'Context finding detail', exact: true }), editor = page.getByRole('form', { name: 'Coordinator rescoring' })
  async function prepare() {
    await editor.getByText('Contextual vector', { exact: true }).click()
    await editor.getByLabel('Proposed contextual vector', { exact: true }).fill(contextual)
    await editor.getByLabel('Scoring rationale', { exact: true }).fill('Coordinator reviewed explicit deployment evidence')
    await editor.getByRole('button', { name: 'Preview contextual score', exact: true }).click()
  }
  return { editor, detail, prepare, select, reads, previews, publications, outcome: (value: string) => { outcome = value }, holdPreview: () => { holdPreview = true }, holdPublish: () => { holdPublish = true }, releasePreview: () => { releasePreview?.() }, releasePublish: () => { releasePublish?.() } }
}
test('uncertain and pending score publications retain exact preview, Base, rationale and UUID until current projection', async ({ page }) => {
  const f = await fixture(page); await f.prepare()
  f.outcome('503'); await f.editor.getByRole('button', { name: 'Publish contextual score', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Publication uncertain')
  const pending = page.getByRole('region', { name: 'Pending coordinator score publication' })
  await expect(f.editor.getByLabel('Scoring rationale', { exact: true })).toBeDisabled()
  await expect(f.editor.getByRole('button', { name: 'Preview contextual score', exact: true })).toBeDisabled()
  const readCount = f.reads.length
  for (const outcome of ['uncommitted', 'pending', '409']) {
    f.outcome(outcome); await pending.getByRole('button', { name: 'Retry exact score publication' }).click()
    expect(f.reads).toHaveLength(readCount)
    await expect(pending).toBeVisible()
  }
  f.outcome('current'); await pending.getByRole('button', { name: 'Retry exact score publication' }).click()
  await expect(page.getByRole('status')).toContainText('Contextual score published')
  await expect(pending).toHaveCount(0)
  expect(f.publications).toHaveLength(5)
  for (const body of f.publications) expect(body).toEqual({ ...f.previews[0], preview: 'exact-preview-token' })
  expect(f.publications[0]).toMatchObject({ expected_versions: { '7.1.1': 'source-before' }, base_vector: base, vector: contextual, targets: [{ version: '7.1.1', context_id: 'context-0', vulnerability_id: 'CVE-2099-0' }] })
})
test('navigation keeps frozen score publication visible and never repins or reopens its old context', async ({ page }) => {
  const f = await fixture(page); await f.prepare()
  f.outcome('503'); await f.editor.getByRole('button', { name: 'Publish contextual score', exact: true }).click()
  await expect(page.getByRole('alert')).toBeVisible()
  await f.detail.getByRole('button', { name: 'Next finding', exact: true }).click()
  await expect(f.detail.getByRole('heading', { name: 'CVE-2099-1', exact: true })).toBeVisible()
  f.outcome('current'); await page.getByRole('button', { name: 'Retry exact score publication' }).click()
  await expect(page.getByRole('status')).toContainText('current queue retained')
  await expect(f.detail.getByRole('heading', { name: 'CVE-2099-1', exact: true })).toBeVisible()
  expect(f.publications[1]).toEqual(f.publications[0])
})
for (const operation of ['preview', 'publish']) test(`late scoring ${operation} cannot resume after an actor roundtrip`, async ({ page }) => {
  const f = await fixture(page, true)
  if (operation === 'preview') { f.holdPreview(); await f.prepare() }
  else { await f.prepare(); f.holdPublish(); await f.editor.getByRole('button', { name: 'Publish contextual score', exact: true }).click() }
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('coordinator')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('coordinator')
  await f.select()
  const response = page.waitForResponse(item => item.url().endsWith(`/scoring/${operation}`))
  if (operation === 'preview') f.releasePreview(); else f.releasePublish()
  await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByRole('region', { name: 'Pending coordinator score publication' })).toHaveCount(0)
  await expect(f.editor.getByRole('region', { name: 'Scoring preview' })).toHaveCount(0)
  await expect(f.editor.getByRole('button', { name: 'Publish contextual score', exact: true })).toBeDisabled()
  await expect(page.getByText('Contextual score published.', { exact: true })).toHaveCount(0)
})
test('discard is explicit and editing source rationale requires a fresh preview', async ({ page }) => {
  const f = await fixture(page); await f.prepare()
  f.outcome('503'); await f.editor.getByRole('button', { name: 'Publish contextual score', exact: true }).click()
  await expect(page.getByRole('alert')).toBeVisible()
  await page.getByRole('button', { name: 'Discard captured score publication', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('does not undo an earlier uncertain commit')
  await f.editor.getByLabel('Scoring rationale', { exact: true }).fill('A new explicit rationale')
  await expect(f.editor.getByRole('button', { name: 'Publish contextual score', exact: true })).toBeDisabled()
  expect(f.previews).toHaveLength(1); expect(f.publications).toHaveLength(1)
})
