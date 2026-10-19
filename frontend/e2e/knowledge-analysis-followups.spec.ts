import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const state = 'a'.repeat(64), advanced = 'b'.repeat(64), context = 'c'.repeat(64), report = 'd'.repeat(64), vuln = 'CVE-2099-42'
async function fixture(page: Page, allowed = true, personas = false) {
  let head = state, failure = 0, actor = 'person', hold = false
  let release: (() => void) | undefined
  const posts: { path: string; body: Record<string, unknown> }[] = []
  const finding = { id: 'finding', context_id: context, vulnerability_id: vuln, component: { name: 'Parser', version: '1' }, context: { component_ref: 'parser', root_ref: 'application', team_id: 'team', status: 'resolved' }, description: 'Source evidence', source_ratings: [], coverage: { status: 'unassessed', assessment: null }, published_score: null, capabilities: [] }
  const job = (id = 'parent') => ({ id, status: 'succeeded', version: '7.1.2', context_id: context, vulnerability_id: vuln, state: '9'.repeat(64), attempts: 1, error: '', result: { report_sha256: report }, created_at: '2026-10-16', requires_explicit_reconciliation: false, capabilities: allowed ? ['follow_up'] : [] })
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (path === '/api/v1/playground/login') { actor = route.request().postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (route.request().method() === 'POST' && path.endsWith('/follow-up')) {
      posts.push({ path, body: route.request().postDataJSON() })
      if (hold) { hold = false; await new Promise<void>(resolve => { release = resolve }) }
      if (failure) return route.fulfill({ status: failure, json: { detail: failure === 409 ? 'Product version changed before follow-up' : 'Request recording outcome unknown' } })
      return route.fulfill({ status: 202, json: { ...job('child'), status: 'queued', result: {}, parent_job_id: 'parent', follow_up_question: posts.at(-1)!.body.question, capabilities: ['cancel'] } })
    }
    let data: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') data = { id: actor, name: actor, org_admin: false, playground: personas, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/playground/personas') data = personas ? [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'product', name: 'Follow-up product', capabilities: ['read'] }], next_cursor: null }
    else if (path === '/api/v1/projects/product') data = { id: 'product', name: 'Follow-up product' }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.2', state: head }], next_offset: null }
    else if (path.endsWith('/workspace')) data = { state: head, project_id: 'product', version: '7.1.2', items: [finding], next_offset: null, statistics: { totals: { context_findings: 1, unique_vulnerabilities: 1 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.includes('/workspace/')) data = { ...finding, state: head }
    else if (path.endsWith('/analysis-jobs')) data = { items: [job()], next_offset: null, capabilities: [] }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Follow-up product', exact: true }).click()
  await page.getByRole('button', { name: vuln, exact: true }).click()
  await page.getByText('Agentyzer repository input', { exact: true }).click()
  await page.getByText('Agentyzer analysis jobs', { exact: true }).click()
  await page.getByRole('button', { name: 'Load analysis jobs', exact: true }).click()
  return { panel: page.getByRole('region', { name: 'Bound Agentyzer follow-up', exact: true }), jobs: page.locator('.analysis-jobs'), posts, advance: () => { head = advanced }, fail: (value: number) => { failure = value }, hold: () => { hold = true }, release: () => { release?.() } }
}
async function prepare(page: Page, panel: ReturnType<Page['getByRole']>) {
  await page.getByRole('button', { name: 'Ask a bound follow-up', exact: true }).click()
  await panel.getByLabel('Follow-up question', { exact: true }).fill('Does the configured entry point reach the vulnerable parser?')
  await panel.getByRole('checkbox', { name: 'I selected this exact parent report', exact: false }).check()
}
test('a completed parent and explicit question create only a separate source-bound job', async ({ page }) => {
  const f = await fixture(page)
  expect(f.posts).toHaveLength(0)
  await prepare(page, f.panel)
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Close context finding', exact: true })).toBeDisabled()
  await expect(page.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'Assessment', exact: true })).toBeDisabled()
  await f.panel.getByRole('button', { name: 'Queue bound follow-up', exact: true }).click()
  await expect(f.panel).toContainText('Follow-up job child recorded')
  expect(f.posts).toHaveLength(1)
  expect(f.posts[0]!.path).toBe('/api/v1/projects/product/versions/7.1.2/analysis-jobs/parent/follow-up')
  expect(f.posts[0]!.body).toMatchObject({ expected: state, parent_report_sha256: report, question: 'Does the configured entry point reach the vulnerable parser?', user_guidance: '' })
  expect(Object.keys(f.posts[0]!.body).sort()).toEqual(['expected', 'parent_report_sha256', 'question', 'request_id', 'user_guidance'])
  await expect(f.jobs.getByRole('article', { name: 'Analysis job child', exact: true })).toBeVisible()
})
test('503 and409 retries keep the full question, report, endpoint and UUID through a workspace head advance', async ({ page }) => {
  const f = await fixture(page)
  await prepare(page, f.panel); f.fail(503)
  await f.panel.getByRole('button', { name: 'Queue bound follow-up', exact: true }).click()
  await expect(f.panel.getByRole('alert')).toContainText('request ID remain fixed')
  f.advance(); await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(f.panel).toContainText('workspace head changed')
  await expect(f.panel.getByLabel('Follow-up question', { exact: true })).toHaveValue('Does the configured entry point reach the vulnerable parser?')
  await expect(f.panel.getByLabel('Follow-up question', { exact: true })).toBeDisabled()
  f.fail(409); await f.panel.getByRole('button', { name: 'Retry exact follow-up request', exact: true }).click()
  f.fail(0); await f.panel.getByRole('button', { name: 'Retry exact follow-up request', exact: true }).click()
  await expect(f.panel).toContainText('Follow-up job child recorded')
  expect(f.posts).toHaveLength(3)
  expect(f.posts.every(post => JSON.stringify(post) === JSON.stringify(f.posts[0]))).toBe(true)
})
test('a dirty first question retains its original head and requires explicit discard after source advancement', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const f = await fixture(page)
  await prepare(page, f.panel); f.advance()
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(f.panel).toContainText('retains its original source pin')
  await expect(f.panel.getByRole('button', { name: 'Queue bound follow-up', exact: true })).toBeDisabled()
  expect(f.posts).toHaveLength(0)
  expect((await f.panel.boundingBox())!.width).toBeLessThanOrEqual(390)
  await f.panel.getByRole('button', { name: 'Discard follow-up input', exact: true }).click()
  await expect(f.panel).toHaveCount(0)
  await page.getByRole('button', { name: 'Back to results', exact: false }).click()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
})
test('read-only job capabilities expose no follow-up action', async ({ page }) => {
  const f = await fixture(page, false)
  await expect(page.getByRole('button', { name: 'Ask a bound follow-up', exact: true })).toHaveCount(0)
  expect(f.posts).toHaveLength(0)
})
test('an old actor queued response cannot revive the question after an actor roundtrip', async ({ page }) => {
  const f = await fixture(page, true, true)
  await prepare(page, f.panel); f.hold()
  await f.panel.getByRole('button', { name: 'Queue bound follow-up', exact: true }).click()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('person')
  const response = page.waitForResponse(item => item.url().endsWith('/follow-up'))
  f.release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(f.panel).toHaveCount(0)
  await expect(page.getByText('Follow-up job child recorded', { exact: false })).toHaveCount(0)
  expect(f.posts).toHaveLength(1)
})
