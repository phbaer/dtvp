import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
async function fixture(page: Page, reviewer = false, personas = false) {
  const writes: Record<string, unknown>[] = [], reads: URLSearchParams[] = [], details: string[] = []
  let outcome = 'current', state = 'head-before', detailError = false, actor = reviewer ? 'reviewer' : 'analyst'
  let releasePost: (() => void) | undefined
  function finding(index: number) { return { id: `finding-${index}`, context_id: `context-${index}`, vulnerability_id: `CVE-2099-${index}`, component: { name: `Parser ${index}`, version: '2' }, context: { component_ref: `parser-${index}`, root_ref: `application-${index}`, team_id: 'team', status: 'resolved' }, description: `Evidence for context ${index}`, source_ratings: [{ score: 8.1, method: 'CVSSv3' }], published_score: null, capabilities: reviewer ? ['approve'] : ['assess'], coverage: { status: reviewer ? 'submitted' : 'unassessed', assessment: reviewer ? { revision: `revision-${index}`, stage: 'submitted', payload: { assessment_id: `decision-${index}`, author_id: 'analyst', state: 'affected', rationale: `Reviewed source context ${index}` } } : null } } }
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (path === '/api/v1/playground/login') { actor = route.request().postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (route.request().method() === 'POST') {
      writes.push(route.request().postDataJSON())
      if (outcome === 'hold') await new Promise<void>(resolve => { releasePost = resolve })
      if (outcome === '503') return route.fulfill({ status: 503, json: { detail: 'Publication uncertain; retry identical request' } })
      if (outcome === 'uncertain') return route.fulfill({ status: 503, json: { committed: false } })
      if (outcome !== 'uncommitted') state = 'head-after'
      return route.fulfill({ json: { committed: outcome !== 'uncommitted', projection: outcome === 'pending' ? 'pending' : 'current' } })
    }
    let data: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') data = { id: actor, name: actor, org_admin: false, playground: personas, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/playground/personas') data = personas ? [{ id: 'analyst', name: 'analyst' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v1/catalog/projects') data = { items: [{ id: 'product', name: 'Continuity product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.1', state }], next_offset: null }
    else if (path.endsWith('/workspace')) { reads.push(new URLSearchParams(url.search)); const offset = Number(url.searchParams.get('offset') || 0); data = { state, project_id: 'product', version: '7.1.1', items: [finding(offset), finding(offset + 1)], next_offset: offset === 0 ? 30 : null, statistics: { totals: { context_findings: 32, unique_vulnerabilities: 32 }, by_status: {}, by_team: { team: 32 }, severity: {}, recorded: reviewer ? 32 : 0, submitted: reviewer ? 32 : 0, approved: 0 } } }
    else if (path.includes('/workspace/')) { const index = Number(path.split('/').at(-1)!.replace('CVE-2099-', '')); details.push(`CVE-2099-${index}`); if (detailError) return route.fulfill({ status: 409, json: { detail: 'Detail evidence changed' } }); data = { ...finding(index), state } }
    await route.fulfill({ json: data })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Continuity product', exact: true }).click()
  await page.getByRole('combobox', { name: 'Review status', exact: true }).selectOption(reviewer ? 'submitted' : 'unassessed')
  await page.getByRole('button', { name: 'Next page', exact: true }).click()
  await page.getByRole('button', { name: 'CVE-2099-30', exact: true }).click()
  const detail = page.getByRole('region', { name: 'Context finding detail', exact: true })
  await detail.getByRole('button', { name: reviewer ? 'Independent review' : 'Assessment', exact: true }).click()
  if (reviewer) { await detail.getByLabel('Review rationale', { exact: true }).fill('Reviewed exact evidence and usage'); await detail.getByRole('checkbox', { name: 'I checked the evidence, applicability and context of this assessment.', exact: true }).check() }
  else await detail.getByLabel('Reason and evidence', { exact: true }).fill('Assessed this exact consuming context')
  return { detail, writes, reads, details, outcome: (value: string) => { outcome = value }, detailError: () => { detailError = true }, release: () => { releasePost?.() } }
}
test('submit and next preserves pinned queue filters, pagination and scroll without acting on next finding', async ({ page }) => {
  const { detail, writes, reads } = await fixture(page)
  await detail.getByRole('button', { name: 'Submit and next', exact: true }).click()
  await expect(detail.getByRole('heading', { name: 'CVE-2099-31', exact: true })).toBeVisible()
  await expect(detail.getByRole('button', { name: 'Overview', exact: true })).toHaveAttribute('aria-pressed', 'true')
  expect(writes).toHaveLength(1)
  expect(writes[0]).toMatchObject({ expected_versions: { '7.1.1': 'head-before' }, targets: [{ version: '7.1.1', context_id: 'context-30', vulnerability_id: 'CVE-2099-30' }] })
  expect(reads.at(-1)!.get('offset')).toBe('30'); expect(reads.at(-1)!.get('lifecycle')).toBe('unassessed'); expect(reads.at(-1)!.has('expected')).toBe(false)
  await expect(page.getByRole('button', { name: 'Previous page', exact: true })).toBeEnabled()
})
for (const action of ['Approve', 'Request changes']) test(`${action} and next reviews only the exact current assessment`, async ({ page }) => {
  const { detail, writes } = await fixture(page, true)
  await detail.getByRole('button', { name: `${action} and next`, exact: true }).click()
  await expect(detail.getByRole('heading', { name: 'CVE-2099-31', exact: true })).toBeVisible()
  expect(writes).toHaveLength(1)
  expect(writes[0]).toMatchObject({ assessment_id: 'decision-30', assessment_revision: 'revision-30', action: action === 'Approve' ? 'approve' : 'request_changes', targets: [{ version: '7.1.1', context_id: 'context-30', vulnerability_id: 'CVE-2099-30' }] })
})
test('error, uncommitted and pending projection never advance; exact retries retain scope and UUID', async ({ page }) => {
  const f = await fixture(page)
  f.outcome('503'); await f.detail.getByRole('button', { name: 'Submit and next', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Publication uncertain')
  const pending = page.getByRole('region', { name: 'Pending assessment workflow request' })
  await expect(f.detail.getByLabel('Reason and evidence', { exact: true })).toBeDisabled()
  for (const status of ['uncommitted', 'pending']) {
    f.outcome(status); await pending.getByRole('button', { name: 'Retry exact assessment workflow request' }).click()
    await expect(f.detail.getByRole('heading', { name: 'CVE-2099-30', exact: true })).toBeVisible()
    expect(f.details).toEqual(['CVE-2099-30'])
  }
  f.outcome('current'); await pending.getByRole('button', { name: 'Retry exact assessment workflow request' }).click()
  await expect(f.detail.getByRole('heading', { name: 'CVE-2099-31', exact: true })).toBeVisible()
  expect(f.writes).toHaveLength(4)
  for (const write of f.writes) expect(write).toEqual(f.writes[0])
})
test('failed authoritative next-detail refresh retains current finding and never submits another action', async ({ page }) => {
  const f = await fixture(page)
  f.detailError(); await f.detail.getByRole('button', { name: 'Submit and next', exact: true }).click()
  await expect(page.getByRole('alert')).toBeVisible()
  await expect(f.detail.getByRole('heading', { name: 'CVE-2099-30', exact: true })).toBeVisible()
  expect(f.writes).toHaveLength(1)
})

test('changing queue scope during an uncertain request never resumes automatic next navigation', async ({ page }) => {
  const f = await fixture(page)
  f.outcome('503'); await f.detail.getByRole('button', { name: 'Submit and next', exact: true }).click()
  await expect(page.getByRole('region', { name: 'Pending assessment workflow request' })).toBeVisible()
  await f.detail.getByRole('button', { name: 'Back to results', exact: false }).click()
  await page.getByRole('combobox', { name: 'Review status', exact: true }).selectOption('submitted')
  await expect(page.getByRole('region', { name: 'Context finding detail', exact: true })).toHaveCount(0)
  f.outcome('current'); await page.getByRole('button', { name: 'Retry exact assessment workflow request' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'current queue retained' })).toContainText('current queue retained')
  await expect(page.getByRole('region', { name: 'Context finding detail', exact: true })).toHaveCount(0)
  expect(f.writes[0]).toEqual(f.writes[1])
})

test('the end of the visible queue retains position rather than selecting another page implicitly', async ({ page }) => {
  const f = await fixture(page)
  await f.detail.getByRole('button', { name: 'Next finding', exact: true }).click()
  await f.detail.getByRole('button', { name: 'Assessment', exact: true }).click()
  await f.detail.getByLabel('Reason and evidence', { exact: true }).fill('Last current page context assessed')
  await f.detail.getByRole('button', { name: 'Submit and next', exact: true }).click()
  await expect(f.detail.getByRole('heading', { name: 'CVE-2099-31', exact: true })).toBeVisible()
  await expect(page.getByRole('status').filter({ hasText: 'No next finding remains on this page; queue position retained' })).toContainText('No next finding remains on this page; queue position retained')
  expect(f.writes).toHaveLength(1)
})


test('an old actor response cannot resume navigation after an A to B to A login roundtrip', async ({ page }) => {
  const f = await fixture(page, false, true)
  f.outcome('hold'); await f.detail.getByRole('button', { name: 'Submit and next', exact: true }).click()
  await expect(page.getByRole('region', { name: 'Pending assessment workflow request' })).toBeVisible()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('analyst')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('analyst')
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Continuity product', exact: true }).click()
  await expect(page.getByRole('button', { name: 'CVE-2099-0', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'CVE-2099-0', exact: true }).click()
  const response = page.waitForResponse(item => item.request().method() === 'POST' && item.url().includes('/assessments/'))
  f.release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByRole('region', { name: 'Pending assessment workflow request' })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'CVE-2099-0', exact: true })).toBeVisible()
  await expect(page.getByText('Assessment submitted for independent review.', { exact: true })).toHaveCount(0)
  expect(f.writes).toHaveLength(1)
})
