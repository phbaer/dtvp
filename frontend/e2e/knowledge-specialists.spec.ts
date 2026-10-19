import { openNativeTools } from './nativeTools'
import { createHash } from 'node:crypto'
import { expect, test, type Page } from '@playwright/test'

const initialState = 'a'.repeat(64), nextState = 'b'.repeat(64), policy = 'c'.repeat(64)
const componentRef = 'package:?scope=' + 'long-reference'.repeat(100) + '&dependency=parser'
const vectorA = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vectorB = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N'
const sbomFile = '{"bomFormat":"CycloneDX","components":[],"specVersion":"1.6","version":1}'
// Preserve the backend's float spelling; reconstructing JSON would lose it.
const cvesFile = '{"cves":[{"base_score":10.0,"cve_id":"CVE-2099-1234"}]}'
const pipelineFile = '{"format":"dtvp.pipeline-context-input/1","declared":true}\n'
const sha = (value: string) => createHash('sha256').update(value).digest('hex')

async function fixture(page: Page, options: { denied?: boolean; wrongHash?: boolean; noVectors?: boolean; pipeline?: 'valid' | 'missing' | 'tampered' | 'unpinned' } = {}) {
  const calls: { path: string; query: URLSearchParams; body: Record<string, unknown> | null }[] = []
  let state = initialState
  const row = { id: 'finding', context_id: 'e'.repeat(64), vulnerability_id: 'CVE-2099-1234', component: { name: 'Parser', version: '2.0', purl: 'pkg:generic/parser@2.0' }, context: { root_ref: 'application', component_ref: componentRef, team_id: 'team', status: 'resolved' }, description: 'Imported advisory.', source_ratings: options.noVectors ? [] : [{ source: 'Vendor', vector: vectorA, score: 9.8 }, { source: 'Advisory', vector: vectorB, score: 3.1 }], coverage: { status: 'unassessed', assessment: null }, published_score: null, capabilities: ['assess'] }
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (path.endsWith('/cpe') || path.endsWith('/vscorer-input') || path.endsWith('/agentyzer-input')) {
      calls.push({ path, query: new URLSearchParams(url.search), body: request.method() === 'POST' ? request.postDataJSON() : null })
      if (path.endsWith('/cpe')) return route.fulfill({ json: { inventory_state: state, policy_state: policy, proposal: { algorithm_version: 'dtvp.cpe/1', content_digest: 'd'.repeat(64), catalog_content_digest: '1'.repeat(64), rules_content_digest: '2'.repeat(64), requested_purl: row.component.purl, resolved_purl: row.component.purl, candidates: [{ cpe: 'cpe:2.3:a:vendor:parser:2.0:*:*:*:*:*:*:*', identification_basis: 'dictionary_supported_identity', basis_verification: 'imported_claim_not_verified', provenance: { source: 'Supplier dictionary extract', kind: 'supplied_catalog' } }], rejected_candidates: [], reviewed_rules: [], limitations: ['CPE identity does not establish vulnerability applicability.'] } } })
      if (options.denied) return route.fulfill({ status: 403, json: { detail: 'Snapshot permission is required to prepare specialist inputs' } })
      if (path.endsWith('/vscorer-input')) {
        const receipt = { format: 'dtvp.vscorer-source/1', state, artifacts: { sbom_sha256: options.wrongHash ? '0'.repeat(64) : sha(sbomFile), cves_sha256: sha(cvesFile), ...(options.pipeline && options.pipeline !== 'unpinned' ? { pipeline_context_sha256: sha(pipelineFile) } : {}) } }
        const pipelineFiles = options.pipeline && options.pipeline !== 'missing' ? { 'pipeline-context.json': options.pipeline === 'tampered' ? pipelineFile + ' ' : pipelineFile } : {}
        return route.fulfill({ json: { eligible: true, sbom: JSON.parse(sbomFile), cves: JSON.parse(cvesFile), dtvp_source: receipt, files: { 'sbom.cdx.json': sbomFile, 'cves.json': cvesFile, 'dtvp-source.json': JSON.stringify(receipt), ...pipelineFiles }, coverage: { included: ['CVE-2099-1234'], excluded: [{ vulnerability_id: 'CVE-2099-5678', reason: 'explicit_base_selection_required' }], verification: 'source_receipt_requires_consumer_artifact_consistency_check', remote_authenticity: 'not_verified' } } })
      }
      return route.fulfill({ json: { format: 'dtvp.agentyzer-input/1', ready_to_submit: false, request: null, receipt: { state, request_sha256: null }, coverage: { reasons: ['qualified_analysis_source_missing_or_invalid'], limitations: ['External orchestrator must authorize the repository.'], source_verification: 'producer_declared_only', repository_authorization: 'not_checked' } } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: 'analyst', name: 'Analyst', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read', 'assess'] }] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Specialist product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.2', state }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state, project_id: 'product', version: '7.1.2', items: [row], next_offset: null, statistics: { totals: { context_findings: 1, unique_vulnerabilities: 1 }, by_status: { unassessed: 1 }, by_team: { team: 1 }, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.includes('/workspace/')) result = { ...row, state }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Specialist product', exact: true }).click()
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  return { calls, advance: () => { state = nextState }, panel: page.locator('.knowledge-specialists') }
}

async function openPanel(page: Page) { await page.getByText('Specialist inputs and CPE candidates', { exact: true }).click() }

test('CPE lookup is explicit, attributed and pinned without changing identity or findings', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { calls, panel } = await fixture(page)
  expect(calls).toHaveLength(0)
  await openPanel(page)
  await panel.getByText('CPE candidate discovery', { exact: true }).click()
  expect(calls).toHaveLength(0)
  await panel.getByRole('button', { name: 'Load CPE candidates', exact: true }).click()
  await expect(panel).toContainText('dictionary supported identity · imported claim not verified')
  await panel.getByText('Candidate attribution', { exact: true }).click()
  await expect(panel).toContainText('Supplier dictionary extract')
  await panel.getByText('CPE input and policy pins', { exact: true }).click()
  await expect(panel).toContainText(policy)
  await expect(panel).toContainText(initialState)
  await expect(panel).toContainText('does not establish vulnerability applicability')
  expect(calls[0]?.query.get('component_ref')).toBe(componentRef)
  expect(calls[0]?.path).toContain(`/states/${initialState}/cpe`)
  await panel.getByRole('button', { name: 'Refresh CPE candidates', exact: true }).click()
  await expect.poll(() => calls.length).toBe(2)
  expect(await panel.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
  await expect(panel.getByRole('button', { name: /adopt|approve|publish/i })).toHaveCount(0)
})

test('VScorer needs an explicit competing Base choice and downloads exact receipt-bound bytes', async ({ page }) => {
  const { calls, panel } = await fixture(page)
  await openPanel(page)
  await panel.getByText('VScorer input files', { exact: true }).click()
  const base = panel.getByRole('combobox', { name: 'Original source Base', exact: true })
  await expect(base).toHaveValue('')
  await expect(panel.getByRole('button', { name: 'Prepare VScorer inputs', exact: true })).toBeDisabled()
  await base.selectOption(vectorB)
  await panel.getByRole('button', { name: 'Prepare VScorer inputs', exact: true }).click()
  await expect(panel.getByRole('button', { name: 'Download CVE list', exact: true })).toBeVisible()
  expect(calls[0]?.body).toEqual({ context_id: 'e'.repeat(64), component_ref: componentRef, base_selections: { 'CVE-2099-1234': vectorB } })
  await expect(panel).toContainText('CVE-2099-5678 · explicit base selection required')
  const pending = page.waitForEvent('download')
  await panel.getByRole('button', { name: 'Download CVE list', exact: true }).click()
  const download = await pending
  const stream = await download.createReadStream()
  const chunks: Buffer[] = []
  for await (const chunk of stream!) chunks.push(Buffer.from(chunk))
  expect(Buffer.concat(chunks).toString()).toBe(cvesFile)
  expect(download.suggestedFilename()).toBe('cves.json')
  await base.selectOption(vectorA)
  await expect(panel.getByRole('button', { name: 'Download CVE list', exact: true })).toHaveCount(0)
  expect(calls).toHaveLength(1)
})

test('receipt hash mismatches withhold native file downloads', async ({ page }) => {
  const { panel } = await fixture(page, { wrongHash: true })
  await openPanel(page)
  await panel.getByText('VScorer input files', { exact: true }).click()
  await panel.getByRole('combobox', { name: 'Original source Base', exact: true }).selectOption(vectorA)
  await panel.getByRole('button', { name: 'Prepare VScorer inputs', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('do not match the source receipt')
  await expect(panel.getByRole('button', { name: 'Download CVE list', exact: true })).toHaveCount(0)
  await expect(panel.getByRole('button', { name: 'Download derivation result JSON', exact: true })).toBeVisible()
})

test('snapshot permission failures are transparent and do not trigger external submission', async ({ page }) => {
  const { calls, panel } = await fixture(page, { denied: true })
  await openPanel(page)
  await panel.getByText('Agentyzer repository input', { exact: true }).click()
  await panel.getByRole('button', { name: 'Prepare Agentyzer input', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Snapshot permission is required')
  await expect(panel.getByRole('button', { name: 'Download Agentyzer input JSON', exact: true })).toHaveCount(0)
  expect(calls.map(call => call.path)).toEqual([`/api/v1/projects/product/states/${initialState}/agentyzer-input`])
})

test('missing source qualification stays explicit and a changed state clears derived inputs', async ({ page }) => {
  const state = await fixture(page, { noVectors: true })
  await openPanel(page)
  await state.panel.getByText('VScorer input files', { exact: true }).click()
  await expect(state.panel).toContainText('No original source vectors are available')
  await state.panel.getByText('Agentyzer repository input', { exact: true }).click()
  await state.panel.getByRole('button', { name: 'Prepare Agentyzer input', exact: true }).click()
  await expect(state.panel).toContainText('Repository input is not ready for submission.')
  await expect(state.panel).toContainText('qualified analysis source missing or invalid')
  await expect(state.panel.getByRole('button', { name: 'Download Agentyzer input JSON', exact: true })).toBeVisible()
  state.advance()
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await page.getByRole('button', { name: 'CVE-2099-1234', exact: true }).click()
  await openPanel(page)
  await state.panel.getByText('Agentyzer repository input', { exact: true }).click()
  await expect(state.panel.getByRole('button', { name: 'Download Agentyzer input JSON', exact: true })).toHaveCount(0)
  await state.panel.getByRole('button', { name: 'Prepare Agentyzer input', exact: true }).click()
  await expect.poll(() => state.calls.at(-1)?.path).toContain(`/states/${nextState}/agentyzer-input`)
})


test('optional pipeline context downloads exact receipt-bound text alongside the existing files', async ({ page }) => {
  const { panel } = await fixture(page, { pipeline: 'valid' })
  await openPanel(page); await panel.getByText('VScorer input files', { exact: true }).click()
  await panel.getByRole('combobox', { name: 'Original source Base', exact: true }).selectOption(vectorA)
  await panel.getByRole('button', { name: 'Prepare VScorer inputs', exact: true }).click()
  await expect(panel.getByRole('button', { name: 'Download CVE list', exact: true })).toBeVisible()
  const pending = page.waitForEvent('download')
  await panel.getByRole('button', { name: 'Download pipeline context', exact: true }).click()
  const result = await pending, stream = await result.createReadStream(), chunks: Buffer[] = []
  for await (const chunk of stream!) chunks.push(Buffer.from(chunk))
  expect(Buffer.concat(chunks).toString()).toBe(pipelineFile)
  expect(result.suggestedFilename()).toBe('pipeline-context.json')
})

for (const kind of ['missing', 'tampered', 'unpinned'] as const) {
  test(`${kind} pipeline metadata withholds every native specialist file`, async ({ page }) => {
    const { panel } = await fixture(page, { pipeline: kind })
    await openPanel(page); await panel.getByText('VScorer input files', { exact: true }).click()
    await panel.getByRole('combobox', { name: 'Original source Base', exact: true }).selectOption(vectorA)
    await panel.getByRole('button', { name: 'Prepare VScorer inputs', exact: true }).click()
    await expect(panel.getByRole('alert')).toContainText('withheld')
    for (const name of ['Download CycloneDX SBOM', 'Download CVE list', 'Download VScorer source receipt', 'Download pipeline context']) await expect(panel.getByRole('button', { name, exact: true })).toHaveCount(0)
    await expect(panel.getByRole('button', { name: 'Download derivation result JSON', exact: true })).toBeVisible()
  })
}
