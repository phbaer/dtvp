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
    component: { name: 'Parser', version: '2.0', purl: 'pkg:generic/parser@2.0' },
    context: { root_ref: 'application', team_id: 'team', status: 'resolved' },
    description: 'Imported source advisory description.', source_ratings: [],
    coverage: { status: 'unassessed', assessment: null }, published_score: null,
    capabilities: ['assess'], code_analysis: items,
  }
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (route.request().method() !== 'GET') { writes.push(path); return route.fulfill({ json: {} }) }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') result = { id: 'analyst', name: 'Analyst', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read', 'assess'] }] }
    else if (path === '/api/v2/catalog/projects') result = { items: [{ id: 'product', name: 'Analysis product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.2', state: 'state' }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state: 'state', project_id: 'product', version: '7.1.2', items: [row], next_offset: null, statistics: { totals: { context_findings: 1, unique_vulnerabilities: 1 }, by_status: { unassessed: 1 }, by_team: { team: 1 }, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.includes('/workspace/')) result = { ...row, state: 'state' }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'Analysis product', exact: true }).click()
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  return { writes, detail: page.getByLabel('Context finding detail', { exact: true }) }
}

test('empty native code-analysis evidence adds no panel or workflow actions', async ({ page }) => {
  const { writes, detail } = await fixture(page)
  await expect(detail.getByText(/Code analysis evidence/)).toHaveCount(0)
  await expect(detail).toContainText('Imported source advisory description.')
  expect(writes).toHaveLength(0)
})

test('current and historical code-analysis proposals remain progressive and never prefill a human decision', async ({ page }) => {
  const { writes, detail } = await fixture(page, [analysis(), analysis(false)])
  const panel = detail.locator('.analysis-evidence')
  await expect(panel.getByText('Provider found the parser path unreachable.', { exact: true })).not.toBeVisible()
  await detail.getByText('Code analysis evidence (2)', { exact: true }).click()
  await panel.getByText('Nightly code analysis · Not affected · Current inputs', { exact: true }).click()
  await expect(panel.getByText('Provider found the parser path unreachable.', { exact: true })).toBeVisible()
  await expect(panel).toContainText('Applicability proposal: not affected. Available for human assessment.')
  await expect(panel).toContainText('They do not establish DTVP approval.')
  const current = panel.locator('.analysis-result').first()
  await current.getByText('Source consistency and provenance', { exact: true }).click()
  await expect(current).toContainText('do not authenticate the provider or verify the built binary')
  await expect(current).toContainText('job/report association are not verified')
  await expect(current).toContainText('Consistent with pinned inputs')
  await expect(current).toContainText(commit)
  await expect(current).toContainText('Example provider · example-model')
  await panel.getByText('Earlier code analysis · Not affected · Historical inputs', { exact: true }).click()
  const historical = panel.locator('.analysis-result').nth(1)
  await expect(historical).toContainText('source evidence changed')
  await expect(historical).toContainText('Not eligible as a current applicability proposal.')
  await expect(panel.getByRole('button')).toHaveCount(0)
  await detail.getByRole('button', { name: 'Assess this context', exact: true }).click()
  await expect(detail.getByRole('combobox', { name: 'Applicability', exact: true })).toHaveValue('under_investigation')
  await expect(detail.getByLabel('Reason and evidence', { exact: true })).toBeEmpty()
  await expect(detail.getByText('Code analysis evidence (2)', { exact: true })).toBeVisible()
  expect(writes).toHaveLength(0)
})

test('untrusted report text stays escaped and provenance fits a narrow assessment workspace', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const item = analysis(false)
  item.summary = '<script>window.analysisInjected=true</script>'
  const { writes, detail } = await fixture(page, [item])
  const panel = detail.locator('.analysis-evidence')
  await detail.getByText('Code analysis evidence (1)', { exact: true }).click()
  await panel.getByText('Earlier code analysis · Not affected · Historical inputs', { exact: true }).click()
  await expect(panel.getByText(item.summary, { exact: true })).toBeVisible()
  expect(await page.evaluate(() => 'analysisInjected' in window)).toBe(false)
  await panel.getByText('Source consistency and provenance', { exact: true }).click()
  await expect(panel).toContainText('Report SHA-256')
  const bounds = await panel.boundingBox()
  expect(bounds?.width).toBeLessThanOrEqual(390)
  expect(await panel.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
  expect(writes).toHaveLength(0)
})
