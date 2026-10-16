import { expect, test, type Page } from '@playwright/test'
const pin = 'a'.repeat(64), revision = 'b'.repeat(64), older = 'c'.repeat(64)
function finding(index: number, status = 'submitted', author = 'analyst') {
  return { id: `row-${index}`, context_id: `context-${index}`, vulnerability_id: `CVE-2099-${index}`, component: { name: `Parser ${index}`, version: '2' }, context: { root_ref: `application-${index}`, team_id: 'team', status: 'resolved' }, description: 'Imported advisory description', source_severity: 'high', source_ratings: [{ score: 8.1, method: 'CVSSv3' }], published_score: { score: 3.2, vector: 'vector', current: index !== 1 }, capabilities: ['approve'], coverage: { status, assessment: { revision, stage: status === 'draft' ? 'draft' : 'submitted', payload: { assessment_id: `decision-${index}`, author_id: author, state: 'not_affected', justification: 'code_not_reachable', rationale: `Exact context rationale ${index}`, conditions: 'Runtime option disabled', evidence: [{ url: 'https://example.test/evidence' }] } }, approved_assessment: index === 0 ? { revision: older, stage: 'submitted', payload: { assessment_id: 'decision-0', rationale: 'Earlier approved revision', state: 'affected' } } : null } }
}
async function fixture(page: Page) {
  const posts: { path: string; body: Record<string, unknown> }[] = []
  let failure = 0, state = pin
  const rows = [finding(0, 'approved'), finding(1), finding(2, 'submitted', 'reviewer'), finding(3, 'draft'), finding(4, 'reassessment_needed')]
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    const body = route.request().method() === 'POST' ? route.request().postDataJSON() as Record<string, unknown> : undefined
    if (body) posts.push({ path, body })
    let data: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') data = { id: 'reviewer', name: 'Reviewer', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v2/catalog/projects') data = { items: [{ id: 'product', name: 'Bulk product', capabilities: ['read', 'approve'] }], next_cursor: null }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.1', state }, { version: '7.1.2', state: older }], next_offset: null }
    else if (path.endsWith('/workspace')) data = { state, project_id: 'product', version: path.includes('7.1.2') ? '7.1.2' : '7.1.1', items: rows, next_offset: null, statistics: { totals: { context_findings: rows.length, unique_vulnerabilities: rows.length }, by_status: { submitted: 3, draft: 1, reassessment_needed: 1 }, by_team: { team: 5 }, severity: { high: 5 }, recorded: 5, submitted: 4, approved: 1 } }
    else if (path.endsWith('/reviews/bulk/preview')) {
      const items = body!.items as Record<string, unknown>[]
      data = { preview_digest: older, total: items.length, next_offset: null, statistics: { total: items.length, ready: Math.min(1, items.length), excluded: Math.max(0, items.length - 1), by_reason: { missing_authority: Math.max(0, items.length - 1) } }, items: items.map((item, index) => ({ ...item, item_id: String(index).repeat(64), ready: index === 0, reason: index === 0 ? 'ready' : 'missing_authority', detail: index ? 'Responsible team permission changed' : '' })) }
    } else if (path.endsWith('/reviews/bulk/apply')) {
      if (failure) return route.fulfill({ status: failure, json: { detail: 'Unavailable or conflicting' } })
      data = { committed: true, projection: 'pending' }; state = older
    }
    await route.fulfill({ json: data })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'Bulk product', exact: true }).click()
  return { posts, fail: (value: number) => { failure = value }, panel: page.getByRole('region', { name: 'Explicit bulk review' }), queue: page.getByRole('region', { name: 'Context finding queue' }) }
}
async function prepare(page: Page, panel: ReturnType<Page['getByRole']>) {
  await page.getByRole('checkbox', { name: 'Select CVE-2099-0 in application-0 for bulk review', exact: true }).check()
  await page.getByRole('checkbox', { name: 'Select CVE-2099-1 in application-1 for bulk review', exact: true }).check()
  await panel.getByLabel('Bulk review rationale').fill('Reviewed exact usage and supporting evidence.')
  await panel.getByRole('button', { name: 'Preview exact review targets' }).click()
  await expect(panel).toContainText('2 candidates · 1 ready · 1 excluded')
}
test('explicit queue selection uses latest submitted revision, excludes self/draft/stale, and requires reviewed ready targets', async ({ page }) => {
  const { panel, posts } = await fixture(page)
  for (const index of [2, 3, 4]) await expect(page.getByRole('checkbox', { name: `Select CVE-2099-${index} in application-${index} for bulk review`, exact: true })).toBeDisabled()
  await prepare(page, panel)
  const preview = posts.find(row => row.path.endsWith('/preview'))!.body
  expect(preview.expected_versions).toEqual({ '7.1.1': pin })
  expect(preview.items).toEqual([0, 1].map(index => ({ target: { version: '7.1.1', context_id: `context-${index}`, vulnerability_id: `CVE-2099-${index}` }, assessment_id: `decision-${index}`, assessment_revision: revision })))
  await expect(panel).toContainText('0 explicitly selected')
  await expect(panel.getByRole('button', { name: 'Approve 0 selected targets' })).toBeDisabled()
  await expect(panel.locator('article').nth(1).getByRole('checkbox')).toBeDisabled()
  await expect(panel).toContainText('Responsible team permission changed')
  await panel.locator('article').first().getByText('Assessment rationale, evidence and scores').click()
  await expect(panel).toContainText('Exact context rationale 0')
  await expect(panel).toContainText('Source severity: high · Published: 3.2')
  await panel.getByRole('button', { name: 'Select all server-ready targets' }).click()
  await expect(panel.getByRole('button', { name: 'Approve 1 selected targets' })).toBeDisabled()
  await panel.getByRole('checkbox', { name: 'I reviewed the evidence', exact: false }).check()
  await panel.getByRole('button', { name: 'Approve 1 selected targets' }).click()
  await expect(panel.getByRole('status').filter({ hasText: '1 exact review targets committed' })).toContainText('1 exact review targets committed')
  expect(posts.find(row => row.path.endsWith('/apply'))!.body.selected).toEqual(['0'.repeat(64)])
})
test('uncertain and conflicting retries keep exact targets, UUID and heads through queue navigation', async ({ page }) => {
  const { panel, posts, fail } = await fixture(page)
  await prepare(page, panel)
  await panel.getByRole('button', { name: 'Select all server-ready targets' }).click()
  await panel.getByRole('checkbox', { name: 'I reviewed the evidence', exact: false }).check()
  fail(503)
  await panel.getByRole('button', { name: 'Approve 1 selected targets' }).click()
  await expect(panel.getByRole('alert')).toContainText('Exact heads, targets, rationale and request ID are retained')
  await page.getByRole('button', { name: 'Version 7.1.1', exact: true }).click()
  await page.getByRole('option', { name: '7.1.2', exact: true }).click()
  await expect(panel).toContainText('current queue has changed')
  await expect(panel).toContainText('Captured scope: product / 7.1.1')
  fail(409)
  await panel.getByRole('button', { name: 'Retry exact captured review' }).click()
  await expect(panel.getByRole('alert')).toContainText('check any earlier uncertain outcome')
  fail(0)
  await panel.getByRole('button', { name: 'Retry exact captured review' }).click()
  await expect(panel.getByRole('status').filter({ hasText: 'committed for product / 7.1.1' })).toContainText('committed for product / 7.1.1')
  const attempts = posts.filter(row => row.path.endsWith('/apply'))
  expect(attempts).toHaveLength(3)
  expect(attempts[0]!.body).toEqual(attempts[1]!.body)
  expect(attempts[1]!.body).toEqual(attempts[2]!.body)
})
test('request-changes action is explicit and narrow layout retains evidence without an approval request', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, posts } = await fixture(page)
  await page.getByRole('checkbox', { name: 'Select CVE-2099-0 in application-0 for bulk review', exact: true }).check()
  await panel.getByLabel('Bulk review action').selectOption('request_changes')
  await panel.getByLabel('Bulk review rationale').fill('Clarify runtime assumption.')
  await panel.getByRole('button', { name: 'Preview exact review targets' }).click()
  await expect(panel).toContainText('request changes')
  expect(posts.find(row => row.path.endsWith('/preview'))!.body.action).toBe('request_changes')
  expect(posts.filter(row => row.path.endsWith('/apply'))).toHaveLength(0)
  expect((await panel.boundingBox())!.width).toBeLessThanOrEqual(390)
  await panel.getByRole('button', { name: 'Discard captured batch and clear selection' }).click()
  await expect(panel).toHaveCount(0)
})

test('unprepared selection clears when queue filters change, captured selection stays visible', async ({ page }) => {
  const { panel, posts } = await fixture(page)
  await page.getByRole('checkbox', { name: 'Select CVE-2099-0 in application-0 for bulk review', exact: true }).check()
  await expect(panel).toContainText('1 explicit context targets selected')
  await page.getByRole('combobox', { name: 'Review status', exact: true }).selectOption('submitted')
  await expect(panel).toHaveCount(0)
  await prepare(page, panel)
  await page.getByRole('combobox', { name: 'Review status', exact: true }).selectOption('approved')
  await expect(panel).toContainText('2 candidates · 1 ready · 1 excluded')
  expect(posts.filter(row => row.path.endsWith('/preview'))).toHaveLength(1)
  expect(posts.filter(row => row.path.endsWith('/apply'))).toHaveLength(0)
})
