import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'

const initial = 'a'.repeat(64), advanced = 'b'.repeat(64), revision = 'c'.repeat(64)
async function fixture(page: Page, capabilities: string[], alreadySubmitted = false, supplemental?: Record<string, unknown>, inventoryRole?: 'adopted_observation') {
  let state = initial, failure = 0, submitted = alreadySubmitted, projection = 'current'
  const posts: { path: string; body: Record<string, unknown> }[] = [], reads: string[] = []
  const payload = { concluded_expression: 'MIT', disposition: 'restricted', obligations: ['Preserve notice'], conditions: 'Customer deployment only', evidence: [{ reference: 'review:123' }], distribution: 'Binary customer delivery', modification: 'Unmodified', linking: 'Dynamic', rationale: 'Actual delivery and supplier terms checked', provenance: { source: 'license-specialist', reference: 'ticket:123' }, actor_id: 'independent-author' }
  const row = () => ({ inventory_role: inventoryRole, supplemental_evidence: supplemental, component_ref: 'library', component: { name: 'Library', version: '1.0', purl: 'pkg:generic/library@1' }, source: { source: 'supplier', artifact_sha: 'f'.repeat(64) }, evidence: inventoryRole ? { status: 'not_reported', facts: [], limitations: [] } : { status: 'reported', facts: [{ source_field: 'licenses', value: { expression: 'Apache-2.0' } }], limitations: [] }, license_review: { status: submitted ? 'submitted' : 'unassessed', assessment: submitted ? { revision, stage: 'submitted', payload } : null, approved: false } })
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (route.request().method() === 'POST') {
      posts.push({ path, body: route.request().postDataJSON() as Record<string, unknown> })
      if (failure) return route.fulfill({ status: failure, json: { detail: failure === 409 ? 'Changed baseline' : 'Temporary unavailable; retry same request' } })
      submitted = path.endsWith('/submit') || submitted; state = advanced
      return route.fulfill({ status: 201, json: { state, committed: true, projection } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: 'reader', name: 'Reader', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Team', capabilities: ['read'] }] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'License product', capabilities: ['read', ...capabilities] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/license-worklist')) {
      reads.push(path + url.search)
      const later = url.searchParams.get('offset') === '20'
      result = { items: [later ? { ...row(), component_ref: 'second', component: { name: 'Second library' } } : row()], total: 21, next_offset: later ? null : 20, capabilities, statistics: { components: 21, by_evidence_status: { reported: 21 } } }
    }
    return route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'License product' }).click()
  await page.getByText('License evidence and review', { exact: true }).click()
  const panel = page.getByRole('region', { name: 'License evidence and review' })
  await expect(panel.getByLabel('License component total')).toHaveText('21 components in this pinned state')
  await panel.getByRole('button', { name: /^Library / }).click()
  return { panel, posts, reads, fail: (status: number) => { failure = status }, submit: () => { submitted = true }, advance: () => { state = advanced }, projection: (value: string) => { projection = value } }
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
  await panel.getByRole('button', { name: 'Retry exact license request', exact: true }).click()
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
  await panel.getByRole('button', { name: 'Retry exact license request', exact: true }).click()
  await expect(panel).toContainText('Submitted for independent license review.')
  expect(posts.every(post => post.path.endsWith('/licenses/submit'))).toBe(true)
  await panel.getByRole('button', { name: /^Library / }).click()
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


test('draft and review buffers block row paging and filters until explicit discard', async ({ page }) => {
  const { panel, reads } = await fixture(page, ['license_assess'])
  await fill(page)
  await expect(panel.getByRole('button', { name: 'Next license components', exact: true })).toBeDisabled()
  await expect(panel.getByRole('button', { name: 'Apply license filters', exact: true })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  await panel.getByRole('button', { name: 'Discard license input', exact: true }).click()
  await panel.getByLabel('Search license evidence', { exact: true }).fill('Apache')
  await panel.getByRole('combobox', { name: 'Authoritative license evidence status', exact: true }).selectOption('reported')
  await panel.getByRole('combobox', { name: 'License review status', exact: true }).selectOption('unassessed')
  await panel.getByRole('combobox', { name: 'Approved license disposition', exact: true }).selectOption('missing')
  expect(reads).toHaveLength(1)
  await panel.getByRole('button', { name: 'Apply license filters', exact: true }).click()
  await expect.poll(() => reads.length).toBe(2)
  const query = new URL('http://test' + reads[1]).searchParams
  expect(Object.fromEntries(query)).toMatchObject({ q: 'Apache', evidence_status: 'reported', review_status: 'unassessed', approved_disposition: 'missing', offset: '0' })
  await panel.getByRole('button', { name: 'Next license components', exact: true }).click()
  await expect.poll(() => reads.length).toBe(3)
  expect(new URL('http://test' + reads[2]).searchParams.get('q')).toBe('Apache')
})

test('review rationale is retained and prevents silent paging', async ({ page }) => {
  const { panel, posts, fail } = await fixture(page, ['license_approve'], true)
  await panel.getByLabel('License review rationale', { exact: true }).fill('Independent review in progress')
  await expect(panel.getByRole('button', { name: 'Next license components', exact: true })).toBeDisabled()
  fail(503)
  await panel.getByRole('button', { name: 'Approve license disposition', exact: true }).click()
  await expect(panel.getByRole('button', { name: 'Retry exact license request', exact: true })).toBeVisible()
  await expect(panel.getByLabel('License review rationale', { exact: true })).toHaveValue('Independent review in progress')
  await expect(panel.getByLabel('License review rationale', { exact: true })).toBeDisabled()
  fail(0)
  await panel.getByRole('button', { name: 'Retry exact license request', exact: true }).click()
  await expect.poll(() => posts.length).toBe(2)
  expect(posts[1]!.body).toEqual(posts[0]!.body)
})


test('a dirty first submission remains pinned after an external workspace refresh', async ({ page }) => {
  const { panel, posts, reads, advance, fail } = await fixture(page, ['license_assess'])
  await fill(page)
  advance()
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(panel).toContainText('retained input stays bound to its original source')
  expect(reads).toHaveLength(1)
  await expect(page.getByLabel('Decision rationale', { exact: true })).toHaveValue('Actual delivery and supplier terms checked')
  fail(409)
  await panel.getByRole('button', { name: 'Submit license disposition', exact: true }).click()
  await expect.poll(() => posts.length).toBe(1)
  expect(posts[0]!.body.expected).toBe(initial)
  await panel.getByRole('button', { name: 'Retry exact license request', exact: true }).click()
  await expect.poll(() => posts.length).toBe(2)
  expect(posts[1]!.body).toEqual(posts[0]!.body)
  await panel.getByRole('button', { name: 'Discard license input', exact: true }).click()
  await expect.poll(() => reads.length).toBe(2)
  expect(reads[1]).toContain(advanced)
})


test('projection-pending publication retains the exact request until confirmed', async ({ page }) => {
  const { panel, posts, projection } = await fixture(page, ['license_assess'])
  await fill(page); projection('pending')
  await panel.getByRole('button', { name: 'Save license draft', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('not confirmed with a current projection')
  await expect(panel.getByLabel('Decision rationale', { exact: true })).toHaveValue('Actual delivery and supplier terms checked')
  projection('current')
  await panel.getByRole('button', { name: 'Retry exact license request', exact: true }).click()
  await expect(panel).toContainText('License draft saved.')
  expect(posts).toHaveLength(2)
  expect(posts[1]!.body).toEqual(posts[0]!.body)
})


type SupplementalFixture = { status: string; source_claims_differ: boolean; claims: { source: string; part_id: string; state: string; ref: string; source_format: string; artifact_sha?: string; evidence: { status: string; facts: { source_field: string; value: unknown }[]; limitations: string[] } }[]; reported_values: { category: string; values: string[] }[]; limitations: string[] }
function supplementalEvidence(): SupplementalFixture {
  return {
    status: 'reported', source_claims_differ: true,
    claims: [
      { source: 'binary-scanner', part_id: 'engine', state: 'd'.repeat(64), ref: 'scan-library', artifact_sha: 'f'.repeat(64), source_format: 'cyclonedx-1.6-json', evidence: { status: 'reported', facts: [{ source_field: 'licenses', value: { expression: '', license: { id: 'MIT', text: { content: 'Long original notice retained in the pinned source.' } } } }], limitations: [] } },
      { source: 'supplier-spdx', part_id: 'engine', state: 'e'.repeat(64), ref: 'SPDXRef-library', artifact_sha: '1'.repeat(64), source_format: 'spdx-2.3-json', evidence: { status: 'unknown', facts: [{ source_field: 'licenseDeclared', value: 'NOASSERTION' }], limitations: ['Supplier did not assert declared terms.'] } },
    ],
    reported_values: [{ category: 'reported', values: ['MIT'] }, { category: 'declared', values: ['NOASSERTION'] }],
    limitations: ['Differences describe source claims, not legal compatibility.'],
  }
}

test('mixed-source license claims expand progressively and never replace authority evidence', async ({ page }) => {
  const { panel, posts } = await fixture(page, [], false, supplementalEvidence())
  await expect(panel.getByRole('heading', { name: 'Authoritative license evidence', exact: true })).toBeVisible()
  await expect(panel).toContainText('Apache-2.0')
  const additional = panel.locator('.supplemental-license-evidence')
  await expect(additional.locator(':scope > summary')).toContainText('2 claims · source claims differ')
  await expect(additional).not.toHaveAttribute('open', '')
  await expect(additional.getByText('binary-scanner · engine · reported', { exact: true })).not.toBeVisible()
  await additional.locator(':scope > summary').click()
  await expect(additional).toContainText('not a legal compatibility decision')
  await expect(additional.locator('.reported-license-values')).toHaveCount(2)
  const scanner = additional.locator('.supplemental-license-claim').first()
  await scanner.locator(':scope > summary').click()
  await expect(scanner).toContainText('licensesMIT')
  await expect(scanner.locator('pre')).not.toBeVisible()
  await scanner.getByText('Source pins and original claim', { exact: true }).click()
  await expect(scanner).toContainText('cyclonedx-1.6-json')
  await expect(scanner).toContainText('d'.repeat(64))
  await expect(scanner).toContainText('Long original notice retained')
  await expect(panel).toContainText('Human disposition: unassessed')
  expect(posts).toHaveLength(0)
})

test('supplemental source text is escaped and fits a narrow license workspace', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const evidence = supplementalEvidence(), text = '<img src=x onerror="window.dtvpInjected=true">' + 'long-source-value'.repeat(45)
  evidence.claims[0]!.source = text
  evidence.reported_values[0]!.values = [text]
  evidence.claims[0]!.evidence.facts[0]!.value = { expression: text }
  const { panel, posts } = await fixture(page, [], false, evidence)
  const additional = panel.locator('.supplemental-license-evidence')
  await additional.locator(':scope > summary').click()
  const scanner = additional.locator('.supplemental-license-claim').first()
  await scanner.locator(':scope > summary').click()
  await scanner.getByText('Source pins and original claim', { exact: true }).click()
  await expect(additional).toContainText(text)
  await expect(additional.locator('img,script')).toHaveCount(0)
  expect(await page.evaluate(() => 'dtvpInjected' in window)).toBe(false)
  expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(390)
  expect(posts).toHaveLength(0)
})

test('legacy license rows stay unchanged and additional evidence does not add approval steps', async ({ page }) => {
  const legacy = await fixture(page, ['license_assess'])
  await expect(legacy.panel.locator('.supplemental-license-evidence')).toHaveCount(0)
  await page.unroute('**/api/**')
  const { panel, posts, fail } = await fixture(page, ['license_assess'], false, supplementalEvidence())
  await panel.locator('.supplemental-license-evidence > summary').click()
  await fill(page); fail(503)
  await panel.getByRole('button', { name: 'Save license draft', exact: true }).click()
  await expect(panel.getByRole('button', { name: 'Next license components', exact: true })).toBeDisabled()
  await expect(panel.locator('.supplemental-license-evidence')).toContainText('source claims differ')
  fail(0); await panel.getByRole('button', { name: 'Retry exact license request', exact: true }).click()
  expect(posts).toHaveLength(2)
  expect(posts[1]!.body).toEqual(posts[0]!.body)
  expect(posts[0]!.body).not.toHaveProperty('supplemental_evidence')
  await expect(panel).toContainText('License draft saved.')
})


test('adopted SPDX occurrence has no authority license claim and retains its own parser attribution', async ({ page }) => {
  const evidence = supplementalEvidence()
  evidence.claims = [evidence.claims[1]!]
  evidence.claims[0]!.evidence.status = 'reported'
  evidence.claims[0]!.evidence.facts = [{ source_field: 'licenseDeclared', value: 'LicenseRef-supplier-terms' }]
  evidence.reported_values = [{ category: 'declared', values: ['LicenseRef-supplier-terms'] }]
  evidence.source_claims_differ = false
  const { panel, posts } = await fixture(page, [], false, evidence, 'adopted_observation')
  await expect(panel).toContainText('Added from a selected observation; no authoritative license claim for this occurrence.')
  await expect(panel).not.toContainText('Apache-2.0')
  await panel.locator('.supplemental-license-evidence > summary').click()
  const claim = panel.locator('.supplemental-license-claim')
  await claim.locator(':scope > summary').click()
  await expect(claim).toContainText('licenseDeclaredLicenseRef-supplier-terms')
  await claim.getByText('Source pins and original claim', { exact: true }).click()
  await expect(claim).toContainText('spdx-2.3-json')
  await expect(claim).toContainText('SPDXRef-library')
  await expect(claim.getByRole('link', { name: 'Open original SBOM', exact: true })).toHaveAttribute('href', `/api/v1/projects/product/states/${initial}/artifacts/${'1'.repeat(64)}`)
  expect(posts).toHaveLength(0)
})


test('original SBOM links stay bound to the retained product state and reject invalid artifact pins', async ({ page }) => {
  const evidence = supplementalEvidence()
  evidence.claims[1]!.artifact_sha = 'javascript:invalid-artifact'
  const { panel, advance, posts } = await fixture(page, ['license_assess'], false, evidence)
  await panel.locator('.supplemental-license-evidence > summary').click()
  const claims = panel.locator('.supplemental-license-claim')
  await claims.nth(0).locator(':scope > summary').click(); await claims.nth(1).locator(':scope > summary').click()
  const link = claims.nth(0).getByRole('link', { name: 'Open original SBOM', exact: true })
  await expect(link).toHaveAttribute('href', `/api/v1/projects/product/states/${initial}/artifacts/${'f'.repeat(64)}`)
  await expect(link).toHaveAttribute('target', '_blank')
  await expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  await expect(claims.nth(1).getByRole('link')).toHaveCount(0)
  await fill(page); advance()
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(panel).toContainText('retained input stays bound to its original source')
  await expect(link).toHaveAttribute('href', `/api/v1/projects/product/states/${initial}/artifacts/${'f'.repeat(64)}`)
  expect(posts).toHaveLength(0)
})
