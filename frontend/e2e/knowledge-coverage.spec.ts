import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'

async function fixture(page: Page, readonly = false, author = 'person') {
  let head = 'source-head', failWrite = 0, failPage = false
  const writes: { path: string; body: Record<string, unknown> }[] = [], previews: Record<string, unknown>[] = []
  const assessment = { revision: 'revision-one', stage: 'submitted', payload: { assessment_id: 'logical-one', author_id: author, state: 'affected', rationale: 'Existing recorded reasoning', conditions: '', evidence: [] } }
  const finding = { id: 'finding', context_id: 'context', vulnerability_id: 'CVE-2099-1234', component: { name: 'TLS', version: '1.0', purl: 'pkg:generic/tls@1.0' }, context: { root_ref: 'app', component_ref: 'tls', team_id: 'team', status: 'resolved' }, description: 'Source description', source_ratings: [{ vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8 }], coverage: { status: 'submitted', assessment }, published_score: null, capabilities: readonly ? [] : ['assess', 'approve'] }
  function row(version: string, extra = {}) { return { id: version, state: `${version}-head`, version, context_id: 'context', vulnerability_id: finding.vulnerability_id, component: { name: 'TLS', version: '1.0' }, context: { root_ref: 'app' }, capabilities: readonly ? [] : ['assess'], assessment_candidate: true, classification: 'matching_material', reasons: [], coverage: { status: 'unassessed' }, comparison: { same_context_references: true, lineage_compatible: true }, ...extra } }
  const rows = [row('7.1.1', { state: 'source-head', coverage: finding.coverage }), row('7.1.2', { classification: 'material_changed', component: { name: 'TLS', version: '1.1' } }), row('7.2.0', { comparison: { same_context_references: false, lineage_compatible: true }, classification: 'different_context', context: { root_ref: 'other-app' } }), row('6.15.6', { capabilities: [] }), row('7.0.0', { coverage: { status: 'submitted', assessment: { ...assessment, revision: 'independent', payload: { ...assessment.payload, assessment_id: 'different' } } } }), row('8.0.0', { context: null, assessment_candidate: false, classification: 'absent' })]
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (path.endsWith('/coverage/candidates')) {
      const body = route.request().postDataJSON(); previews.push(body)
      if (url.searchParams.get('offset') === '20') {
        if (failPage) return route.fulfill({ status: 409, json: { detail: 'Coverage candidate heads changed; refresh the complete preview' } })
        return route.fulfill({ json: { preview_digest: 'preview-one', source: { coverage: finding.coverage }, heads: {}, items: [row('9.0.0')], total: 7, next_offset: null } })
      }
      if (body.version_selection) return route.fulfill({ json: { preview_digest: 'range-one', source: { coverage: finding.coverage }, heads: {}, items: rows.slice(0, 2), total: 2, next_offset: 20, version_selection: { captured_versions: 6, selected_versions: ['7.1.1', '7.1.2'], versions: [{ version: '7.1.1', status: 'selected_numeric_range' }, { version: '7.1.2', status: 'selected_numeric_range' }, { version: '7.2.0', status: 'excluded_explicitly' }, { version: 'main', status: 'unknown_ordering' }], semantics: 'Closed exact current heads only; no future approval.' } } })
      return route.fulfill({ json: { preview_digest: 'preview-one', source: { coverage: finding.coverage }, heads: {}, items: rows, total: 7, next_offset: 20 } })
    }
    if (route.request().method() === 'POST') {
      writes.push({ path, body: route.request().postDataJSON() })
      if (failWrite) return route.fulfill({ status: failWrite, json: { detail: failWrite === 503 ? 'Publication uncertain; retry identical input.' : 'Baseline changed.' } })
      head = 'updated-source-head'
      return route.fulfill({ status: 201, json: { committed: true, projection: 'current' } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: 'person', name: 'Person', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read', ...(readonly ? [] : ['assess', 'approve'])] }] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state: head }] }
    else if (path.endsWith('/workspace')) result = { state: head, project_id: 'product', version: '7.1.1', items: [finding], next_offset: null, statistics: { totals: { context_findings: 1, unique_vulnerabilities: 1 }, by_status: { submitted: 1 }, by_team: { team: 1 }, severity: { critical: 1 }, recorded: 1, submitted: 1, approved: 0 } }
    else if (path.includes('/workspace/')) result = { ...finding, state: head }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Product', exact: true }).click()
  await page.getByRole('button', { name: finding.vulnerability_id, exact: true }).click()
  const detail = page.getByLabel('Context finding detail', { exact: true })
  await detail.getByRole('button', { name: 'assessment', exact: true }).click()
  const matrix = detail.getByLabel('Cross-version assessment scope', { exact: true })
  await matrix.getByText('Coverage across product versions', { exact: true }).click()
  await matrix.getByRole('button', { name: 'Find coverage candidates', exact: true }).click()
  return { detail, matrix, writes, previews, fail: (status: number) => { failWrite = status }, stalePage: () => { failPage = true } }
}

test('explicit multi-version selection blocks other roots, teams and independent decisions', async ({ page }) => {
  const { matrix, writes } = await fixture(page)
  await expect(matrix.getByRole('checkbox', { name: 'Include 7.1.1 app', exact: true })).toBeChecked()
  await expect(matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true })).not.toBeChecked()
  for (const name of ['Include 7.2.0 other-app', 'Include 6.15.6 app', 'Include 7.0.0 app', 'Include 8.0.0 absent context']) await expect(matrix.getByRole('checkbox', { name, exact: true })).toBeDisabled()
  await expect(matrix).toContainText('Different consuming root: assess separately.')
  await expect(matrix).toContainText('Independent target decision: assess separately.')
  await expect(matrix).toContainText('Material/package version changed')
  expect(writes).toHaveLength(0)
})

test('shared assessment requires conditions and retains full scope plus UUID on uncertain response', async ({ page }) => {
  const { detail, matrix, writes, fail } = await fixture(page)
  await matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true }).check()
  await expect(detail.getByRole('button', { name: 'Submit assessment', exact: true })).toBeDisabled()
  await detail.getByLabel('Conditions', { exact: true }).fill('The same deployed configuration applies to these two explicit versions.')
  fail(503)
  await detail.getByRole('button', { name: 'Submit assessment', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Publication uncertain')
  await expect(matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true })).toBeChecked()
  await page.getByRole('button', { name: 'Retry exact assessment workflow request', exact: true }).click()
  expect(writes).toHaveLength(2)
  expect(writes[1]!.body).toEqual(writes[0]!.body)
  expect(writes[0]!.body).toMatchObject({ expected_versions: { '7.1.1': 'source-head', '7.1.2': '7.1.2-head' }, expected_revision: 'revision-one', targets: [{ version: '7.1.1', context_id: 'context', vulnerability_id: 'CVE-2099-1234' }, { version: '7.1.2', context_id: 'context', vulnerability_id: 'CVE-2099-1234' }] })
  fail(0)
  await page.getByRole('button', { name: 'Retry exact assessment workflow request', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Assessment submitted' })).toContainText('Assessment submitted')
  expect(writes[2]!.body).toEqual(writes[0]!.body)
  await detail.getByRole('button', { name: 'assessment', exact: true }).click()
  await expect(detail.getByLabel('Cross-version assessment scope').locator(':scope > summary')).not.toContainText('additional')
})

test('review scope remains current context after choosing assessment targets', async ({ page }) => {
  const { detail, matrix, writes } = await fixture(page)
  await matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true }).check()
  await detail.getByRole('button', { name: 'review', exact: true }).click()
  await detail.getByLabel('Review rationale', { exact: true }).fill('Independent review applies to the selected current context.')
  await detail.getByRole('checkbox').check()
  await detail.getByRole('button', { name: 'Approve assessment', exact: true }).click()
  expect(writes[0]!.body).toMatchObject({ expected_versions: { '7.1.1': 'source-head' }, targets: [{ version: '7.1.1', context_id: 'context', vulnerability_id: 'CVE-2099-1234' }], action: 'approve' })
})

test('candidate paging pins the full preview and stale pages preserve additional selection', async ({ page }) => {
  const { matrix, previews, stalePage } = await fixture(page)
  await matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true }).check()
  stalePage()
  await matrix.getByRole('button', { name: 'Next candidate page', exact: true }).click()
  await expect(matrix.getByRole('alert')).toContainText('heads changed')
  await expect(matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true })).toBeChecked()
  expect(previews[1]).toMatchObject({ source: 'source-head', expected_preview: 'preview-one' })
  await matrix.getByRole('button', { name: 'Refresh coverage candidates', exact: true }).click()
  await expect(matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true })).not.toBeChecked()
  expect(previews[2]).not.toHaveProperty('expected_preview')
})

test('readonly matrix remains accessible and fits narrow layouts without mutation actions', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { matrix, detail, writes } = await fixture(page, true)
  await expect(matrix).toContainText('7 candidate contexts')
  await expect(matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true })).toBeDisabled()
  await expect(detail.getByRole('button', { name: 'Save draft', exact: true })).toHaveCount(0)
  await expect(page.locator('body')).toHaveJSProperty('scrollWidth', 390)
  expect(writes).toHaveLength(0)
})

test('leaving assessment clears extra scope and paginated drafts retain explicit selected targets', async ({ page }) => {
  const { detail, matrix, writes, previews } = await fixture(page)
  await matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true }).check()
  await matrix.getByRole('button', { name: 'Next candidate page', exact: true }).click()
  await matrix.getByRole('checkbox', { name: 'Include 9.0.0 app', exact: true }).check()
  expect(previews[1]).toMatchObject({ expected_preview: 'preview-one' })
  await matrix.getByRole('button', { name: 'Previous candidate page', exact: true }).click()
  await expect(matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true })).toBeChecked()
  await expect(matrix).toContainText('One shared assessment for 3 explicit targets.')
  await detail.getByRole('button', { name: 'review', exact: true }).click()
  await detail.getByRole('button', { name: 'assessment', exact: true }).click()
  await detail.getByRole('button', { name: 'Save draft', exact: true }).click()
  expect(writes[0]!.body).toMatchObject({ expected_versions: { '7.1.1': 'source-head' }, targets: [{ version: '7.1.1', context_id: 'context', vulnerability_id: 'CVE-2099-1234' }] })
})


test('a replacement author starts a separate decision and retains evidence on uncertain retry', async ({ page }) => {
  const { detail, writes, fail } = await fixture(page, false, 'previous-analyst')
  await expect(detail.getByRole('button', { name: 'Save draft', exact: true })).toBeDisabled()
  await expect(detail.getByRole('button', { name: 'Submit assessment', exact: true })).toBeDisabled()
  await detail.getByRole('button', { name: 'Start new assessment', exact: true }).click()
  await expect(detail.getByRole('status')).toHaveCount(0)
  await expect(detail.getByLabel('Reason and evidence', { exact: true })).toHaveValue('Existing recorded reasoning')
  fail(503)
  await detail.getByRole('button', { name: 'Save draft', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Publication uncertain')
  await page.getByRole('button', { name: 'Retry exact assessment workflow request', exact: true }).click()
  expect(writes).toHaveLength(2)
  expect(writes[1]).toEqual(writes[0])
  expect(writes[0]!.path).not.toContain('/logical-one/')
  expect(writes[0]!.body).toMatchObject({ expected_revision: null, rationale: 'Existing recorded reasoning', evidence: [] })
})


test('range narrows finite candidate preview without selecting targets and pages retain the applied selector', async ({ page }) => {
  const { matrix, previews, writes, stalePage } = await fixture(page)
  await matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true }).check()
  await matrix.getByText('Limit additional versions', { exact: true }).click()
  await matrix.getByRole('checkbox', { name: 'Use numeric release range and explicit version names' }).check()
  await matrix.getByLabel('From version (inclusive)').fill('7.1.1')
  await matrix.getByLabel('Through version (inclusive)').fill('7.2.0')
  await matrix.getByLabel('Exclude versions (one per line)').fill('7.2.0')
  await matrix.getByRole('button', { name: 'Refresh coverage candidates', exact: true }).click()
  await expect(matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true })).not.toBeChecked()
  expect(previews.at(-1)).toMatchObject({ version_selection: { lower: '7.1.1', upper: '7.2.0', include: [], exclude: ['7.2.0'] } })
  await matrix.getByText('Captured version selection · 2 of 6 branches', { exact: true }).click()
  await expect(matrix).toContainText('main · unknown ordering')
  await expect(matrix).toContainText('7.2.0 · excluded explicitly')
  await matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true }).check()
  await matrix.getByLabel('Through version (inclusive)').fill('8.0.0')
  stalePage(); await matrix.getByRole('button', { name: 'Next candidate page' }).click()
  await expect(matrix.getByRole('alert')).toContainText('heads changed')
  expect(previews.at(-1)).toMatchObject({ expected_preview: 'range-one', version_selection: { upper: '7.2.0' } })
  await expect(matrix.getByRole('checkbox', { name: 'Include 7.1.2 app', exact: true })).toBeChecked()
  expect(writes).toHaveLength(0)
})
