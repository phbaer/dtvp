import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'

// Isolated transport/UI contract checks; backend workflow tests cover authority.
async function fixture(page: Page, reviewer = false, coordinator = false, playground = false, displayTeam?: { id: string; labels: Record<string, string> }) {
  const row = {
    id: 'ctx-vuln', context_id: 'ctx', vulnerability_id: 'CVE-2099-1234',
    component: { name: 'Shared TLS', version: '2.0', purl: 'pkg:generic/tls@2.0' },
    context: { root_ref: 'server', team_id: displayTeam?.id || 'security', status: 'assigned', dependencies: ['tls'] },
    description: 'A long vulnerability description. '.repeat(100),
    source_ratings: [{ source: 'Upstream', method: 'CVSSv31', score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    coverage: { status: reviewer ? 'submitted' : 'unassessed', assessment: reviewer ? { revision: 'assessment-sha', stage: 'submitted', payload: { assessment_id: 'assessment-one', author_id: 'analyst', state: 'not_affected', justification: 'code_not_reachable', rationale: 'Reviewed deployment evidence excludes the path.', targets: [{ version: '7.1.2', context_id: 'ctx', vulnerability_id: 'CVE-2099-1234' }], evidence: [] } } : null },
    legacy_evidence: [{ id: 'legacy-one', source: 'Dependency Track', status: 'parsed', legacy_format: 'dtvp-tagged', proposed_applicability: 'not_affected', conflicting: false, raw_text: 'Original historical documentation.', errors: [], current_records: [{ team: 'Platform', state: 'not_affected', rationale: 'Legacy deployment excludes the path.', assessor: 'Alice', reviewer: 'Bob', identity_gaps: [] }], records: [], comments: [], scoring_proposals: [] }],
    curated_metadata: { revision: 'metadata-sha', status: 'current', applicable: true, payload: { rationale: 'Deployment context recorded by component owner.', provenance: { source: 'Component owner', reference: 'DESIGN-42' }, annotations: { cybersecurity: { criticality: 'high', exposure: 'internal', mitigations: ['Input validation'], testing_evidence: ['TEST-42'] }, deployment: { environment: 'Private network', usage: 'Report generation', configuration: '' }, support: { status: 'supported', supplier: 'Example', support_until: null, end_of_life: null }, notes: '', properties: {} } } },
    scoring_proposals: coordinator ? [{ id: 'proposal-one', provider: 'vscorer', source_label: 'Threat model', current: true, eligible: true, ineligibility_reasons: [], report_sha256: 'report-sha', proposal: { base_score: 9.8, score: 0, base_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L' }, score_input: { base_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L' } }] : [],
    published_score: { score: 4.2, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, capabilities: coordinator ? ['rescore'] : reviewer ? ['approve'] : ['assess'], evidence: [{ source: 'build', claim: 'Deployment report' }],
  }
  let conflict = false, uncertain = false, scoreReady = false
  const writes: { path: string; body: Record<string, unknown> }[] = []
  const workspaceQueries: URLSearchParams[] = []
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (route.request().method() === 'POST') {
      writes.push({ path, body: route.request().postDataJSON() })
      if (uncertain) { uncertain = false; return route.fulfill({ status: 503, json: { detail: 'Publication uncertain; retry the same request.' } }) }
      if (path.endsWith('/scoring/preview') || path.endsWith('/scoring/rules/preview')) {
        const body = route.request().postDataJSON()
        return route.fulfill({ json: { preview: 'score-preview-sha', eligible: scoreReady, proposal: { base_vector: body.base_vector, vector: body.vector, base_score: 9.8, score: 0, version: '3.1' }, blocked: scoreReady ? [] : [{ version: '7.1.2', vulnerability_id: 'CVE-2099-1234', missing: [{ context_id: 'other-context', status: 'submitted' }], unresolved_components: [] }] } })
      }
      return route.fulfill({ status: conflict ? 409 : 201, json: conflict ? { detail: 'Baseline changed' } : { committed: true, projection: 'current', assessment_revision: 'new-revision' } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: reviewer ? 'reviewer' : 'analyst', name: 'Test user', org_admin: false, playground, agentyzer: { enabled: false, mode: 'disabled' }, vscorer_url: '', workspaces: [{ id: 'security', name: 'Security', capabilities: ['read', reviewer ? 'approve' : 'assess'] }] }
    else if (path === '/api/v1/playground/personas') result = []
    else if (path.endsWith('/scoring-policy')) result = { state: 'policy-sha', config: {}, digest: 'policy-digest' }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'p', name: 'Test Product', workspace_id: 'security', capabilities: ['read', ...(coordinator ? ['manage'] : [])] }, ...(displayTeam ? [{ id: 'other', name: 'Other Product', workspace_id: 'security', capabilities: ['read'] }] : [])], next_cursor: null }
    else if (path === '/api/v1/projects/p') result = { id: 'p', name: 'Test Product', workspace_id: 'security', capabilities: ['read'] }
    else if (path.endsWith('/versions')) result = { items: [{ version: path.includes('/projects/specialist-demo/') ? '7.2.0' : '7.1.2', state: 'baseline-sha' }] }
    else if (path.endsWith('/workspace')) {
      workspaceQueries.push(new URLSearchParams(url.search))
      const empty = displayTeam && (url.searchParams.get('q') === 'no matching findings' || path.includes('/projects/other/'))
      result = { state: 'baseline-sha', project_id: 'p', version: '7.1.2', items: empty ? [] : [row], team_labels: empty ? {} : displayTeam?.labels, next_offset: url.searchParams.get('offset') === '0' ? 30 : null, statistics: { totals: { context_findings: empty ? 0 : url.searchParams.get('source_severity') ? 79 : 31, unique_vulnerabilities: empty ? 0 : 12 }, by_status: empty ? {} : { submitted: 2 }, by_team: empty ? {} : { [displayTeam?.id || 'security']: 31 }, severity: empty ? {} : { high: 31 }, recorded: 4, submitted: 2, approved: 1 } }
    }
    else if (path.includes('/workspace/')) result = { ...row, state: 'baseline-sha' }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Test Product' }).click()
  await expect(page.getByRole('button', { name: 'CVE-2099-1234', exact: true })).toBeVisible()
  return { row, writes, workspaceQueries, conflict: () => { conflict = true }, uncertain: () => { uncertain = true }, ready: () => { scoreReady = true } }
}

test('knowledge queue shows full-scope statistics and keeps assessment evidence available', async ({ page }) => {
  const { writes } = await fixture(page)
  await expect(page.getByLabel('Filtered workspace statistics')).toContainText('31 context findings')
  await expect(page.getByLabel('Context finding queue')).toContainText('9.8')
  await expect(page.getByLabel('Context finding queue')).toContainText('4.2')
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  const detail = page.getByLabel('Context finding detail')
  await expect(detail.locator('.knowledge-description')).toContainText('A long vulnerability description.')
  await detail.getByText('Additional evidence', { exact: true }).click()
  await expect(detail).toContainText('Deployment report')
  await detail.getByRole('button', { name: 'Assess this context', exact: true }).click()
  await detail.getByRole('combobox', { name: 'Applicability', exact: true }).selectOption('not_affected')
  await expect(detail.getByRole('button', { name: 'Submit assessment', exact: true })).toBeDisabled()
  await detail.getByRole('combobox', { name: 'Why not affected?', exact: true }).selectOption('code_not_reachable')
  await detail.getByLabel('Reason and evidence', { exact: true }).fill('The deployment excludes this vulnerable path.')
  await detail.getByRole('button', { name: 'Submit assessment', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Assessment submitted' })).toContainText('Assessment submitted')
  expect(writes[0]?.body).toMatchObject({ expected_versions: { '7.1.2': 'baseline-sha' }, expected_revision: null, state: 'not_affected', justification: 'code_not_reachable', targets: [{ version: '7.1.2', context_id: 'ctx', vulnerability_id: 'CVE-2099-1234' }] })
  await expect(detail.getByRole('button', { name: /rescor/i })).toHaveCount(0)
})

test('server-scoped team labels display and filter without adding memberships and reset across projects', async ({ page }) => {
  const team = { id: 'outside-membership-team', labels: { 'outside-membership-team': 'Product cybersecurity' } }
  const { writes, workspaceQueries } = await fixture(page, false, false, false, team)
  const queue = page.getByLabel('Context finding queue', { exact: true })
  await expect(queue).toContainText('Product cybersecurity')
  await expect(queue).not.toContainText('outside-membership-team')
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await expect(page.getByLabel('Context finding detail', { exact: true })).toContainText('Product cybersecurity')
  const statistics = page.getByLabel('Filtered workspace statistics', { exact: true })
  await statistics.getByText('Breakdown', { exact: true }).click()
  await expect(statistics).toContainText('Product cybersecurity')
  const teams = page.getByRole('combobox', { name: 'Responsible team', exact: true })
  await teams.selectOption(team.id)
  await expect.poll(() => workspaceQueries.at(-1)?.get('team_id')).toBe(team.id)
  await page.getByRole('searchbox', { name: 'Search', exact: true }).fill('no matching findings')
  await expect(queue).toContainText('No context findings match this scope.')
  await expect(teams).toHaveValue(team.id)
  await expect(teams.getByRole('option', { name: 'Product cybersecurity', exact: true })).toHaveCount(1)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Other Product', exact: true }).click()
  await expect(teams).toHaveValue('security')
  await expect(teams.getByRole('option', { name: 'Product cybersecurity', exact: true })).toHaveCount(0)
  expect(writes).toHaveLength(0)
})

test('independent review pins exact assessment and blocks a stale publication', async ({ page }) => {
  const fixtureState = await fixture(page, true)
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  const detail = page.getByLabel('Context finding detail')
  await detail.getByRole('button', { name: 'review', exact: true }).click()
  await expect(detail.getByRole('button', { name: 'Approve assessment', exact: true })).toBeDisabled()
  await detail.getByLabel('Review rationale', { exact: true }).fill('Independent review confirmed the deployment evidence.')
  await detail.getByRole('checkbox').check()
  fixtureState.conflict()
  await detail.getByRole('button', { name: 'Approve assessment', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('baseline or assessment changed')
  await expect(detail.getByLabel('Review rationale', { exact: true })).toHaveValue('Independent review confirmed the deployment evidence.')
  expect(fixtureState.writes[0]?.body).toMatchObject({ assessment_id: 'assessment-one', assessment_revision: 'assessment-sha', action: 'approve', expected_versions: { '7.1.2': 'baseline-sha' } })
})


test('uncertain assessment publication retries the identical idempotency key', async ({ page }) => {
  const fixtureState = await fixture(page)
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  const detail = page.getByLabel('Context finding detail')
  await detail.getByRole('button', { name: 'Assess this context', exact: true }).click()
  await detail.getByLabel('Reason and evidence', { exact: true }).fill('Working draft pending deployment evidence.')
  fixtureState.uncertain()
  await detail.getByRole('button', { name: 'Save draft', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Publication uncertain')
  await page.getByRole('button', { name: 'Retry exact assessment workflow request', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Draft saved' })).toContainText('Draft saved')
  expect(fixtureState.writes).toHaveLength(2)
  expect(fixtureState.writes[1]?.body).toEqual(fixtureState.writes[0]?.body)
})


test('coordinator previews required-review gate before explicit contextual score publication', async ({ page }) => {
  const fixtureState = await fixture(page, false, true)
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  const detail = page.getByLabel('Context finding detail')
  await detail.getByRole('button', { name: 'scoring', exact: true }).click()
  const editor = detail.getByLabel('Coordinator rescoring')
  await editor.getByText('Advanced vector input', { exact: true }).click()
  const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L'
  await editor.getByLabel('Proposed contextual vector', { exact: true }).fill(vector)
  await editor.getByLabel('Scoring rationale', { exact: true }).fill('Verified contextual protections following the required team reviews.')
  await editor.getByRole('button', { name: 'Preview contextual score', exact: true }).click()
  await expect(editor.getByRole('status').filter({ hasText: 'Waiting for required team reviews' })).toContainText('Waiting for required team reviews')
  await expect(editor.getByRole('button', { name: 'Publish contextual score', exact: true })).toBeDisabled()
  fixtureState.ready()
  await editor.getByRole('button', { name: 'Preview contextual score', exact: true }).click()
  await expect(editor.getByRole('status').filter({ hasText: 'Preview ready' })).toContainText('Preview ready')
  await expect(editor.getByLabel('Scoring preview')).toContainText('Proposed 0.0')
  await editor.getByLabel('Scoring rationale', { exact: true }).fill('Updated rationale explicitly confirms all required independent reviews.')
  await expect(editor.getByRole('button', { name: 'Publish contextual score', exact: true })).toBeDisabled()
  await editor.getByRole('button', { name: 'Preview contextual score', exact: true }).click()
  await expect(editor.getByRole('status').filter({ hasText: 'Preview ready' })).toContainText('Preview ready')
  fixtureState.uncertain()
  await editor.getByRole('button', { name: 'Publish contextual score', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Publication uncertain')
  await page.getByRole('button', { name: 'Retry exact score publication', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Contextual score published' })).toContainText('Contextual score published')
  const previews = fixtureState.writes.filter(item => item.path.endsWith('/scoring/preview'))
  const publications = fixtureState.writes.filter(item => item.path.endsWith('/scoring/publish'))
  expect(previews).toHaveLength(3)
  expect(publications).toHaveLength(2)
  expect(publications[0]?.body).toEqual({ ...previews[2]?.body, preview: 'score-preview-sha' })
  expect(publications[1]?.body).toEqual(publications[0]?.body)
})


test('advanced filters reset pagination and forward the full scope to server statistics', async ({ page }) => {
  const state = await fixture(page)
  await page.getByRole('button', { name: 'Next page', exact: true }).click()
  await expect.poll(() => state.workspaceQueries.at(-1)?.get('offset')).toBe('30')
  await page.getByText('More filters', { exact: true }).click()
  await page.getByRole('combobox', { name: 'Source severity', exact: true }).selectOption('critical')
  await page.getByRole('combobox', { name: 'Published severity', exact: true }).selectOption('none')
  await page.getByRole('combobox', { name: 'Context applicability', exact: true }).selectOption('not_affected')
  await page.getByRole('combobox', { name: 'Scoring status', exact: true }).selectOption('published')
  await page.getByRole('combobox', { name: 'Team assessment', exact: true }).selectOption('pending')
  await page.getByRole('textbox', { name: 'Evidence provider', exact: true }).fill('Upstream')
  await page.getByRole('combobox', { name: 'Source CVSS version', exact: true }).selectOption('3.1')
  await page.getByRole('combobox', { name: 'Dependency relationship', exact: true }).selectOption('transitive')
  await page.getByRole('combobox', { name: 'Source discrepancies', exact: true }).selectOption('no')
  await page.getByRole('textbox', { name: 'Component', exact: true }).fill('Shared TLS')
  await page.getByRole('combobox', { name: 'Cybersecurity criticality', exact: true }).selectOption('critical')
  await page.getByRole('combobox', { name: 'Exposure', exact: true }).selectOption('external')
  await page.getByRole('combobox', { name: 'Support status', exact: true }).selectOption('unsupported')
  await page.getByRole('combobox', { name: 'Annotation status', exact: true }).selectOption('current')
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click()
  await expect(page.getByLabel('Filtered workspace statistics')).toContainText('79 context findings')
  expect(Object.fromEntries(state.workspaceQueries.at(-1)!)).toMatchObject({ offset: '0', source_severity: 'critical', contextual_severity: 'none', applicability: 'not_affected', scoring_status: 'published', team_review: 'pending', provider: 'Upstream', cvss_version: '3.1', dependency: 'transitive', source_conflict: 'no', component: 'Shared TLS', criticality: 'critical', exposure: 'external', support_status: 'unsupported', metadata_status: 'current' })
  await expect(page.getByLabel('Context finding queue').locator('tbody tr')).toHaveCount(1)
  await expect(page).toHaveURL(/k_source_severity=critical/)
  await page.getByText('Saved views and sharing', { exact: true }).click()
  await page.getByRole('textbox', { name: 'View name', exact: true }).fill('Critical shared dependencies')
  await page.getByRole('button', { name: 'Save view', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'View saved' })).toContainText('View saved')
  await page.getByRole('button', { name: 'Reset advanced filters', exact: true }).click()
  await expect(page.getByLabel('Filtered workspace statistics')).toContainText('31 context findings')
  await page.getByRole('button', { name: 'Critical shared dependencies', exact: true }).click()
  await expect(page.getByLabel('Filtered workspace statistics')).toContainText('79 context findings')
  await expect(page.getByRole('combobox', { name: 'Source severity', exact: true })).toHaveValue('critical')
  await expect(page.getByRole('combobox', { name: 'Cybersecurity criticality', exact: true })).toHaveValue('critical')
  await expect(page).toHaveURL(/k_support_status=unsupported/)
})


test('external proposal comparison requires explicit coordinator preview', async ({ page }) => {
  const { writes } = await fixture(page, false, true)
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await page.getByText('External scoring proposals (1)', { exact: true }).click()
  await expect(page.getByRole('table', { name: 'External scoring comparison' })).toContainText('Threat model')
  await page.getByRole('button', { name: 'Use proposal', exact: true }).click()
  expect(writes).toHaveLength(0)
  await expect(page.getByRole('form', { name: 'Coordinator rescoring' })).toBeVisible()
  await expect(page.getByLabel('Scoring rationale', { exact: true })).toHaveValue('')
  await expect(page.getByRole('button', { name: 'Publish contextual score', exact: true })).toBeDisabled()
  await page.getByLabel('Scoring rationale', { exact: true }).fill('Coordinator independently checked the contextual inputs.')
  await page.getByRole('button', { name: 'Preview contextual score', exact: true }).click()
  expect(writes[0]?.body.vector).toContain('/CR:L/IR:L/AR:L')
  await expect(page.getByRole('button', { name: 'Publish contextual score', exact: true })).toBeDisabled()
})


test('curated context remains attributed and available during assessment', async ({ page }) => {
  await fixture(page)
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await page.getByText('Curated component context · current', { exact: true }).click()
  const detail = page.getByLabel('Context finding detail')
  await expect(detail).toContainText('Report generation')
  await expect(detail).toContainText('Component owner · DESIGN-42')
  await detail.getByText('Mitigations, testing and supporting details', { exact: true }).click()
  await expect(detail).toContainText('TEST-42')
  await detail.getByRole('button', { name: 'Assess this context', exact: true }).click()
  await expect(detail).toContainText('Report generation')
})


test('DT legacy documentation stays readable without manufacturing current approval', async ({ page }) => {
  const { writes } = await fixture(page)
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await page.getByText('Imported DT assessment history', { exact: true }).click()
  const detail = page.getByLabel('Context finding detail')
  await expect(detail).toContainText('Legacy deployment excludes the path.')
  await expect(detail).toContainText('Historical assessor: Alice · reviewer: Bob')
  await expect(detail).toContainText('do not establish current DTVP approval')
  await detail.getByRole('button', { name: 'Assess this context', exact: true }).click()
  await expect(detail.getByLabel('Reason and evidence', { exact: true })).toHaveValue('')
  expect(writes).toHaveLength(0)
})

test('coordinator uses readable contextual metrics without changing source Base', async ({ page }) => {
  const f = await fixture(page, false, true)
  await page.route('**/api/v1/cvss/metrics/3.1', route => route.fulfill({ json: { metrics: [
    { key: 'AV', name: 'Attack Vector', base: true, values: [{ value: 'N', name: 'Network' }] },
    { key: 'CR', name: 'Confidentiality Requirement', base: false, values: [{ value: 'L', name: 'Low' }] },
    { key: 'MAV', name: 'Modified Attack Vector', base: false, values: [{ value: 'P', name: 'Physical' }] },
  ] } }))
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await page.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'scoring', exact: true }).click()
  const form = page.getByRole('form', { name: 'Coordinator rescoring' })
  const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
  await form.getByRole('combobox', { name: 'Source Base vector', exact: true }).selectOption(vector)
  await form.getByRole('combobox', { name: 'Confidentiality Requirement', exact: true }).selectOption('L')
  await form.getByRole('button', { name: 'Deployment conditions', exact: true }).click()
  await form.getByRole('combobox', { name: 'Modified Attack Vector', exact: true }).selectOption('P')
  await form.getByLabel('Scoring rationale', { exact: true }).fill('Verified deployment and requirement evidence.')
  await form.getByRole('button', { name: 'Preview contextual score', exact: true }).click()
  expect(f.writes.at(-1)!.body.vector).toBe(`${vector}/CR:L/MAV:P`)
  expect(f.writes.at(-1)!.body.base_vector).toBe(vector)
})

test('rule proposal pins project policy and publishes only an explicit eligible preview', async ({ page }) => {
  const f = await fixture(page, false, true)
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await page.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'scoring', exact: true }).click()
  const form = page.getByRole('form', { name: 'Coordinator rescoring' })
  const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
  await form.getByRole('combobox', { name: 'Source Base vector', exact: true }).selectOption(vector)
  await form.getByRole('combobox', { name: 'Proposal method', exact: true }).selectOption('applicability')
  await form.getByLabel('Scoring rationale', { exact: true }).fill('Apply approved applicability with project rules.')
  await form.getByRole('button', { name: 'Preview contextual score', exact: true }).click()
  expect(f.writes.at(-1)!).toMatchObject({ path: '/api/v1/projects/p/scoring/rules/preview', body: { expected_policy: 'policy-sha', rule_basis: 'applicability' } })
  await expect(form.getByRole('button', { name: 'Publish contextual score', exact: true })).toBeDisabled()
})

test('project scoring policy retains CAS and exact request after an uncertain save', async ({ page }) => {
  await fixture(page, false, true)
  const writes: unknown[] = []
  let first = true
  await page.route('**/api/v1/projects/p/scoring-policy', async route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: { state: 'policy-sha', digest: 'policy-digest', config: { metric_rules: {}, transitions: [] } } })
    writes.push(route.request().postDataJSON())
    if (first) { first = false; return route.fulfill({ status: 503, json: { detail: 'Uncertain publication' } }) }
    await route.fulfill({ json: { committed: true, projection: 'current' } })
  })
  await page.getByText('Contextual scoring rules', { exact: true }).click()
  const policy = page.getByRole('region', { name: 'Project scoring policy', exact: true })
  await policy.getByLabel('Scoring policy JSON', { exact: true }).fill('{"metric_rules":{},"transitions":[],"comment":"reviewed policy"}')
  await policy.getByRole('button', { name: 'Save scoring rules (manage required)', exact: true }).click()
  await expect(policy.getByRole('button', { name: 'Retry exact scoring policy', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Activity', exact: true })).toBeDisabled()
  await policy.getByRole('button', { name: 'Retry exact scoring policy', exact: true }).click()
  await expect(policy.getByText('Scoring rules saved. Existing published scores remain retained.', { exact: true })).toBeVisible()
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1])
  expect(writes[0]).toMatchObject({ expected_policy: 'policy-sha', config: { comment: 'reviewed policy' } })
})

test('optional SSVC records explicit model, answers, rationale and evidence in the same captured assessment', async ({ page }) => {
  const f = await fixture(page)
  const sha = 'a'.repeat(64)
  await page.route('**/api/v1/ssvc/models', route => route.fulfill({ json: { models: [{ id: 'ssvc:DT_DP', version: '1.0.0', sha256: sha, name: 'Deployer priority', outcome: 'action', decision_points: {
    exploitation: { name: 'Exploitation', definition: 'Observed exploitation evidence.', values: [{ key: 'A', name: 'Active', definition: 'Verified activity.' }] },
    action: { name: 'Outcome', values: [{ key: 'I', name: 'Immediate' }] },
  } }] } }))
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await page.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'assessment', exact: true }).click()
  await page.getByText('SSVC prioritization (optional)', { exact: true }).click()
  const panel = page.getByRole('region', { name: 'SSVC assessment', exact: true })
  await panel.getByRole('combobox', { name: 'SSVC decision model', exact: true }).selectOption('ssvc:DT_DP')
  await panel.getByRole('combobox', { name: 'Exploitation', exact: true }).selectOption('A')
  await panel.getByLabel('SSVC rationale', { exact: true }).fill('Verified evidence for prioritization.')
  await panel.getByText('Supporting references (0)', { exact: true }).click()
  await panel.getByRole('button', { name: 'Add SSVC reference', exact: true }).click()
  await panel.getByLabel('SSVC reference 1', { exact: true }).fill('REPORT-42')
  await panel.getByLabel('SSVC evidence description 1', { exact: true }).fill('Reviewed exploitation report.')
  await page.getByLabel('Reason and evidence', { exact: true }).fill('Assessed deployment context.')
  await page.getByRole('button', { name: 'Submit assessment', exact: true }).click()
  expect(f.writes[0]!.body.ssvc).toEqual({ model: 'ssvc:DT_DP', version: '1.0.0', model_sha256: sha, answers: { exploitation: 'A' }, rationale: 'Verified evidence for prioritization.', evidence: [{ reference: 'REPORT-42', description: 'Reviewed exploitation report.' }] })
  expect((f.writes[0]!.body.ssvc as any).outcome).toBeUndefined()
})

test('CVSS4 normalized source Base and contextual controls preserve raw rating evidence', async ({ page }) => {
  const f = await fixture(page, false, true)
  const base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
  ;(f.row as Record<string, unknown>).original_base_vectors = [{ vector: base, version: '4.0', score: 9.3 }]
  await page.route('**/api/v1/cvss/metrics/4.0', route => route.fulfill({ json: { metrics: [
    { key: 'AV', name: 'Attack Vector', base: true, values: [{ value: 'N', name: 'Network' }] },
    { key: 'CR', name: 'Confidentiality Requirement', base: false, values: [{ value: 'L', name: 'Low' }] },
  ] } }))
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await page.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'scoring', exact: true }).click()
  const form = page.getByRole('form', { name: 'Coordinator rescoring' })
  await expect(form.getByRole('combobox', { name: 'Source Base vector', exact: true })).toHaveValue(base)
  await form.getByRole('combobox', { name: 'Confidentiality Requirement', exact: true }).selectOption('L')
  await form.getByLabel('Scoring rationale', { exact: true }).fill('Verified CVSS4 requirement.')
  await form.getByRole('button', { name: 'Preview contextual score', exact: true }).click()
  expect(f.writes.at(-1)!.body.vector).toBe(`${base}/CR:L`)
  expect(f.row.source_ratings[0]!.vector).toContain('CVSS:3.1')
})

test('revising recorded SSVC sends authored selection only and preserves evidence descriptions', async ({ page }) => {
  const f = await fixture(page)
  const sha = 'b'.repeat(64)
  const selection = { model: 'ssvc:DT_DP', version: '1.0.0', model_sha256: sha, answers: { exploitation: 'A' }, rationale: 'Previous prioritization evidence.', evidence: [{ reference: 'REPORT-99', description: 'Original evidence description.' }] }
  ;(f.row.coverage as any).assessment = { revision: 'draft-revision', stage: 'draft', payload: { assessment_id: 'existing', author_id: 'analyst', state: 'affected', rationale: 'Recorded deployment analysis.', ssvc: { selection, outcome: 'I', outcome_label: 'Immediate', complete: true, model_sha256: sha } } }
  await page.route('**/api/v1/ssvc/models', route => route.fulfill({ json: { models: [{ id: 'ssvc:DT_DP', version: '1.0.0', sha256: sha, name: 'Deployer priority', outcome: 'action', decision_points: { exploitation: { name: 'Exploitation', values: [{ key: 'A', name: 'Active' }] }, action: { name: 'Outcome', values: [{ key: 'I', name: 'Immediate' }] } } }] } }))
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await page.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'assessment', exact: true }).click()
  await page.getByText('SSVC prioritization · 1 answers (optional)', { exact: true }).click()
  const panel = page.getByRole('region', { name: 'SSVC assessment', exact: true })
  await expect(panel.getByRole('combobox', { name: 'Exploitation', exact: true })).toHaveValue('A')
  await panel.getByLabel('SSVC rationale', { exact: true }).fill('Updated prioritization rationale.')
  await page.getByRole('button', { name: 'Submit assessment', exact: true }).click()
  expect(f.writes[0]!.body.ssvc).toEqual({ ...selection, rationale: 'Updated prioritization rationale.' })
  expect(selection.rationale).toBe('Previous prioritization evidence.')
})
