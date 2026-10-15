import { expect, test, type Page } from '@playwright/test'

const initial = 'a'.repeat(64), advanced = 'b'.repeat(64), revision = 'c'.repeat(64)
async function fixture(page: Page, capabilities: string[], alreadySubmitted = false) {
  let state = initial, failure = 0, submitted = alreadySubmitted
  const posts: { path: string; body: Record<string, unknown> }[] = [], reads: string[] = []
  const payload = { concluded_expression: 'MIT', disposition: 'restricted', obligations: ['Preserve notice'], conditions: 'Customer deployment only', evidence: [{ reference: 'review:123' }], distribution: 'Binary customer delivery', modification: 'Unmodified', linking: 'Dynamic', rationale: 'Actual delivery and supplier terms checked', provenance: { source: 'license-specialist', reference: 'ticket:123' }, actor_id: 'independent-author' }
  const row = () => ({ component_ref: 'library', component: { name: 'Library', version: '1.0', purl: 'pkg:generic/library@1' }, source: { source: 'supplier', artifact_sha: 'f'.repeat(64) }, evidence: { status: 'reported', facts: [{ source_field: 'licenses', value: { expression: 'Apache-2.0' } }], limitations: [] }, license_review: { status: submitted ? 'submitted' : 'unassessed', assessment: submitted ? { revision, stage: 'submitted', payload } : null, approved: false } })
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (route.request().method() === 'POST') {
      posts.push({ path, body: route.request().postDataJSON() as Record<string, unknown> })
      if (failure) return route.fulfill({ status: failure, json: { detail: failure === 409 ? 'Changed baseline' : 'Temporary unavailable; retry same request' } })
      submitted = path.endsWith('/submit') || submitted; state = advanced
      return route.fulfill({ status: 201, json: { state } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') result = { id: 'reader', name: 'Reader', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Team', capabilities: ['read'] }] }
    else if (path === '/api/v2/catalog/projects') result = { items: [{ id: 'product', name: 'License product', capabilities: ['read', ...capabilities] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/license-worklist')) {
      reads.push(path + url.search)
      const later = url.searchParams.get('offset') === '20'
      result = { items: [later ? { ...row(), component_ref: 'second', component: { name: 'Second library' } } : row()], total: 21, next_offset: later ? null : 20, capabilities, statistics: { components: 21, by_evidence_status: { reported: 21 } } }
    }
    return route.fulfill({ json: result })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'License product' }).click()
  await page.getByText('License evidence and review', { exact: true }).click()
  const panel = page.getByRole('region', { name: 'License evidence and review' })
  await expect(panel.getByLabel('License component total')).toHaveText('21 components in this pinned state')
  await panel.getByRole('button', { name: /^Library / }).click()
  return { panel, posts, reads, fail: (status: number) => { failure = status }, submit: () => { submitted = true } }
}
async function fill(page: Page) {
  await page.getByLabel('Concluded license expression', { exact: true }).fill('MIT')
  await page.getByRole('combobox', { name: 'Disposition', exact: true }).selectOption('restricted')
  await page.getByLabel('Distribution assumptions', { exact: true }).fill('Binary customer delivery')
  await page.getByLabel('Modification assumptions', { exact: true }).fill('Unmodified')
  await page.getByLabel('Linking assumptions', { exact: true }).fill('Dynamic')
  await page.getByLabel('Decision rationale', { exact: true }).fill('Actual delivery and supplier terms checked')
  await page.getByLabel('Evidence source', { exact: true }).fill('license-specialist')
}

test('read-only license evidence is separate, bounded, pinned and mobile readable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, reads, posts } = await fixture(page, [])
  await expect(panel).toContainText('Apache-2.0')
  await expect(panel).toContainText('No automatic license compatibility')
  await expect(panel.getByRole('button', { name: 'Submit license disposition', exact: true })).toHaveCount(0)
  await panel.getByRole('button', { name: 'Next license components', exact: true }).click()
  await expect(panel).toContainText('Second library')
  expect(reads.map(read => [read.includes(initial), new URL('http://test' + read).searchParams.get('offset')])).toEqual([[true, '0'], [true, '20']])
  expect(reads.every(read => read.includes('limit=20'))).toBe(true)
  expect(posts).toHaveLength(0)
  expect((await panel.boundingBox())!.width).toBeLessThanOrEqual(390)
})

test('license draft retains inputs and request identity on unavailable retry', async ({ page }) => {
  const { panel, posts, fail } = await fixture(page, ['license_assess'])
  await fill(page); fail(503)
  await panel.getByRole('button', { name: 'Save license draft', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Temporary unavailable')
  await expect(page.getByLabel('Decision rationale', { exact: true })).toHaveValue('Actual delivery and supplier terms checked')
  fail(0)
  await panel.getByRole('button', { name: 'Save license draft', exact: true }).click()
  await expect(panel).toContainText('License draft saved.')
  expect(posts).toHaveLength(2)
  expect(posts[1]!.body).toEqual(posts[0]!.body)
  expect(posts[0]!.body).toMatchObject({ expected: initial, expected_revision: null, component_ref: 'library', concluded_expression: 'MIT', disposition: 'restricted' })
  expect(posts.every(post => post.path.endsWith('/licenses/draft'))).toBe(true)
})

test('conflicts preserve conclusion and explicit submission never approves automatically', async ({ page }) => {
  const { panel, posts, fail } = await fixture(page, ['license_assess'])
  await fill(page); fail(409)
  await panel.getByRole('button', { name: 'Submit license disposition', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('your input is retained')
  await expect(page.getByLabel('Concluded license expression', { exact: true })).toHaveValue('MIT')
  fail(0)
  await panel.getByRole('button', { name: 'Submit license disposition', exact: true }).click()
  await expect(panel).toContainText('Submitted for independent license review.')
  expect(posts.every(post => post.path.endsWith('/licenses/submit'))).toBe(true)
  await expect(panel).toContainText('Apache-2.0')
  await expect(panel.getByRole('button', { name: 'Approve license disposition', exact: true })).toHaveCount(0)
})

test('independent reviewer sees submitted human assumptions and sends exact revision', async ({ page }) => {
  const { panel, posts } = await fixture(page, ['license_approve'], true)
  await expect(panel.getByRole('button', { name: 'Save license draft', exact: true })).toHaveCount(0)
  await panel.getByText('Recorded human conclusion and usage', { exact: true }).click()
  await expect(panel.locator('pre').last()).toContainText('Binary customer delivery')
  await panel.getByLabel('License review rationale', { exact: true }).fill('Reviewed independent author evidence and exact distribution context')
  await panel.getByRole('button', { name: 'Approve license disposition', exact: true }).click()
  await expect.poll(() => posts.length).toBe(1)
  expect(posts[0]!.path).toContain('/licenses/reviews')
  expect(posts[0]!.body).toMatchObject({ revision, action: 'approve', component_ref: 'library', expected: initial })
})
