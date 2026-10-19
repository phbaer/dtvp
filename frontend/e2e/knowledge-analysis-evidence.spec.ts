import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'

const commit = 'a'.repeat(40)
const analysis = (current = true) => ({
  id: current ? 'current-analysis' : 'historical-analysis', provider: 'agentyzer', source_label: current ? 'Nightly code analysis' : 'Earlier code analysis', current,
  application_eligible: current, rescoring_eligible: false, proposal_state: current ? 'not_affected' : null,
  verdict: 'Not affected', confidence: 'High', summary: current ? 'Provider found the parser path unreachable.' : 'Earlier report referenced a different source commit.', rationale: 'A detailed path analysis remains supporting evidence for a human reviewer.',
  ineligibility_reasons: current ? [] : ['source_evidence_changed'], scoring_blockers: ['native_scoring_vectors_unavailable'],
  report_sha256: 'b'.repeat(64), receipt_sha256: 'c'.repeat(64),
  source_receipt: { state: 'd'.repeat(64), context_id: 'context', assessment_fingerprint: 'e'.repeat(64) },
  provider_claim: { llm_provider: 'Example provider', model: 'example-model' },
  source_proof: { target_claim_consistent: true, source_commit_consistent: true, consistency_only: true, source_binding: { status: 'receipt_consistent', expected_commit: commit, requested_commit: commit, resolved_commit: commit, reason: '' } },
})

async function fixture(page: Page, items: ReturnType<typeof analysis>[] = []) {
  const writes: string[] = []
  const row = {
    id: 'finding', context_id: 'context', vulnerability_id: 'CVE-2099-1234',
    component: { name: 'ParserWithALongCorporateComponentName'.repeat(5), version: '2.0', purl: 'pkg:generic/parser@2.0' },
    context: { component_ref: 'parser', root_ref: 'application', team_id: 'team', status: 'resolved' },
    description: 'Imported source advisory description.', source_ratings: [],
    coverage: { status: 'unassessed', assessment: null }, published_score: null,
    capabilities: ['assess'], code_analysis: items,
  }
  const cpeEntry = (id: string, status: string) => ({ id, kind: status, provider: 'Supplier', label: 'Supplier identity evidence', status, current: null, summary: `cpe:2.3:a:example:${id}:2.0:*:*:*:*:*:*:*`, ratings: [], proposal: null, claims: { cpe: `cpe:2.3:a:example:${id}:2.0:*:*:*:*:*:*:*` }, adoption: { status: 'not_recorded', assessment_revisions: [], published_score: false }, provenance: {}, diagnostics: [] })
  ;(row as Record<string, unknown>).contributions = {
    format: 'dtvp.evidence-contributions/1', scope: {},
    vulnerability_sources: [{ id: 'nvd', kind: 'source', provider: 'nvd', label: 'NVD', status: 'current_source_facts', current: true, summary: 'Description and severity rating supplied.', ratings: [{ score: 9.8, method: 'CVSSv31' }], proposal: null, claims: { contributes: ['description', 'ratings'], description: 'Imported source advisory description.' }, adoption: { status: 'not_recorded', assessment_revisions: [], published_score: false }, provenance: { source: 'NVD' }, diagnostics: [] }],
    vulnerability_analyses: items.map(item => ({ id: item.id, kind: 'code_analysis', provider: item.provider, label: item.source_label, status: item.current ? 'eligible' : 'withheld', current: item.current, summary: item.summary, ratings: [], proposal: null, claims: { proposed_applicability: item.proposal_state, verdict: item.verdict, rationale: item.rationale, provider_claim: item.provider_claim }, adoption: { status: 'not_recorded', assessment_revisions: [], published_score: false }, provenance: { source_proof: item.source_proof, report_sha256: item.report_sha256, receipt_sha256: item.receipt_sha256 }, diagnostics: item.ineligibility_reasons })),
    cpe: { declared: [cpeEntry('declared-parser', 'declared')], curated: [cpeEntry('configured-parser', 'curated_mapping')], accepted: [], candidates: [cpeEntry('candidate-parser', 'candidate')], diagnostics: ['No native accepted identity record is available.'] }, limitations: ['Provider claims do not establish human approval.'],
  }
  await page.route('**/api/**' , async route => {
    const path = new URL(route.request().url()).pathname
    if (route.request().method() !== 'GET') { writes.push(path); return route.fulfill({ json: {} }) }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: 'analyst', name: 'Analyst', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read', 'assess'] }] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Analysis product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.2', state: 'state' }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state: 'state', project_id: 'product', version: '7.1.2', items: [row], next_offset: null, statistics: { totals: { context_findings: 1, unique_vulnerabilities: 1 }, by_status: { unassessed: 1 }, by_team: { team: 1 }, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/dependency-paths')) result = { state: 'state', component_ref: 'parser', root_ref: 'application', paths: [['application', 'parser'].map(ref => ({ component_ref: ref, component: { name: ref, version: '2.0' }, missing: false }))], truncated: false, dependency_graph: 'reported', limitations: ['Shortest declared paths only.'] }
    else if (path.includes('/workspace/')) result = { ...row, state: 'state' }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Analysis product', exact: true }).click()
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  return { writes, detail: page.getByLabel('Context finding detail', { exact: true }) }
}

test('sources and analyses show backend contributions without implying missing source data or human adoption', async ({ page }) => {
  const { writes, detail } = await fixture(page)
  const sources = detail.getByRole('region', { name: 'Vulnerability sources', exact: true })
  await expect(sources).toContainText('NVD'); await expect(sources).toContainText('9.8 CVSSv31')
  await expect(sources).toContainText('description · ratings')
  await expect(sources).not.toContainText('Not recorded')
  await expect(detail.getByRole('region', { name: 'Vulnerability analyses', exact: true })).toContainText('No contributions recorded.')
  await expect(detail.getByText('Analysis tools and input files', { exact: true })).toBeVisible()
  await expect(detail.getByText('Specialist inputs and CPE candidates', { exact: true })).toHaveCount(0)
  expect(writes).toHaveLength(0)
})
test('eligible and withheld reports remain distinct supporting proposals and never prefill a human decision', async ({ page }) => {
  const { writes, detail } = await fixture(page, [analysis(), analysis(false)])
  const panel = detail.getByRole('region', { name: 'Vulnerability analyses', exact: true })
  await expect(panel).toContainText('Provider found the parser path unreachable.')
  const current = panel.getByRole('article').filter({ hasText: 'Nightly code analysis' }), historical = panel.getByRole('article').filter({ hasText: 'Earlier code analysis' })
  await expect(current).toContainText('eligible'); await expect(historical).toContainText('withheld · Historical inputs')
  await current.getByText('Evidence, limitations and provenance', { exact: true }).click()
  await expect(current).toContainText('No publication link recorded.')
  await expect(current).toContainText('Applicability proposal: not affected')
  await historical.getByText('Evidence, limitations and provenance', { exact: true }).click()
  await expect(historical).toContainText('source evidence changed')
  await detail.getByRole('button', { name: 'Assess this context', exact: true }).click()
  await expect(detail.getByRole('combobox', { name: 'Applicability', exact: true })).toHaveValue('under_investigation')
  await expect(detail.getByLabel('Reason and evidence', { exact: true })).toBeEmpty()
  await expect(panel).not.toBeVisible()
  await detail.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'evidence', exact: true }).click()
  await expect(panel).toBeVisible(); expect(writes).toHaveLength(0)
})
test('untrusted report text stays escaped and detailed provenance fits a narrow review workspace', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const item = analysis(false); item.summary = '<script>window.analysisInjected=true</script>'
  const { writes, detail } = await fixture(page, [item])
  const panel = detail.getByRole('region', { name: 'Vulnerability analyses', exact: true })
  await expect(panel.getByText(item.summary, { exact: true })).toBeVisible()
  expect(await page.evaluate(() => 'analysisInjected' in window)).toBe(false)
  await panel.getByText('Evidence, limitations and provenance', { exact: true }).click()
  await panel.getByText('Exact claims and provenance', { exact: true }).click()
  await expect(panel).toContainText(item.report_sha256); await expect(panel).toContainText('example-model')
  expect((await panel.boundingBox())!.width).toBeLessThanOrEqual(390)
  expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(390)
  for (const header of await page.locator('.review-queue-table th').all()) expect(await header.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
  expect(writes).toHaveLength(0)
})
test('desktop review detail has sixty percent of space and predictable source/published columns', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 })
  const { detail } = await fixture(page, [analysis()])
  const queue = page.getByRole('region', { name: 'Context finding queue', exact: true })
  const detailWidth = (await detail.boundingBox())!.width, queueWidth = (await queue.boundingBox())!.width
  expect(detailWidth / (detailWidth + queueWidth)).toBeGreaterThan(.58)
  const tabs = detail.getByRole('navigation', { name: 'Assessment workflow' }), sources = detail.getByRole('region', { name: 'Vulnerability sources', exact: true })
  expect((await tabs.boundingBox())!.y).toBeLessThan((await sources.boundingBox())!.y)
  const headers = queue.locator('th'), source = (await headers.nth((await headers.count()) - 2).boundingBox())!, published = (await headers.nth((await headers.count()) - 1).boundingBox())!
  expect(source.width).toBeCloseTo(published.width, 0); expect(source.width).toBeLessThan(85)
  for (const header of await headers.all()) expect(await header.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
  expect(await queue.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
})

test('CPE declarations, configured mappings and candidates remain separate from accepted identities', async ({ page }) => {
  const { detail, writes } = await fixture(page)
  const cpe = detail.getByLabel('CPE identification', { exact: true })
  await expect(cpe.locator(':scope > summary')).toContainText('1 declared · 0 accepted · 1 candidates')
  await cpe.locator(':scope > summary').click()
  await expect(cpe).toContainText('declared-parser'); await expect(cpe).toContainText('configured-parser'); await expect(cpe).toContainText('candidate-parser')
  await expect(cpe.locator('.cpe-groups > section').filter({ hasText: 'Accepted identities' })).toContainText('None recorded')
  await cpe.getByText('Identity limitations', { exact: true }).click()
  await expect(cpe).toContainText('No native accepted identity record is available.')
  expect(writes).toHaveLength(0)
})

test('finding evidence includes only its consuming dependency path', async ({ page }) => {
  const reads: string[] = []
  page.on('request', request => { if (request.url().includes('/dependency-paths?')) reads.push(request.url()) })
  const requested = page.waitForRequest(request => request.url().includes('/dependency-paths?'))
  const { detail, writes } = await fixture(page)
  await expect(detail.getByRole('list', { name: 'Dependency path components' })).toHaveCount(0)
  expect(reads).toHaveLength(0)
  await detail.getByText('Location in dependency tree', { exact: true }).click()
  const location = detail.getByRole('region', { name: 'Location in dependency tree', exact: true })
  await expect(location.getByRole('list', { name: 'Dependency path components' })).toContainText('application')
  await expect(location.getByRole('list')).toContainText('parser')
  await expect(location.getByRole('listitem')).toHaveCount(2)
  expect((await location.boundingBox())!.height).toBeLessThan(120)
  const params = new URL((await requested).url()).searchParams
  expect(params.get('root_ref')).toBe('application'); expect(params.get('component_ref')).toBe('parser')
  expect(reads).toHaveLength(1)
  expect(writes).toHaveLength(0)
})
