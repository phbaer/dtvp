import { expect, test, type Page } from '@playwright/test'
const state = 'a'.repeat(64), revision = 'b'.repeat(64), newer = 'c'.repeat(64), context = 'd'.repeat(64)
const annotations = { cybersecurity: { criticality: 'moderate', exposure: 'internal', mitigations: ['Firewall\nseparate note'], testing_evidence: ['TEST-42'] }, deployment: { environment: 'Production', usage: 'Report generation', configuration: 'Default' }, support: { status: 'supported', supplier: 'Supplier', support_until: null, end_of_life: null, references: ['SUPPORT-42'] }, notes: 'Keep this note', properties: { preserved: 'yes' } }
async function fixture(page: Page, options: { manage?: boolean; stale?: boolean; conflict?: boolean; delayedRead?: boolean } = {}) {
  const writes: any[] = []; let attempts = 0, current = state, reads = 0
  let releaseRead!: () => void
  const readGate = new Promise<void>(resolve => { releaseRead = resolve })
  const metadata = { revision, status: options.stale ? 'stale' : 'current', applicable: !options.stale, payload: { annotations, provenance: { source: 'Component owner', reference: 'DESIGN-42', observed_at: '2026-10-15T12:00:00Z' }, rationale: 'Previous evidence', actor_id: 'manager', created_at: '2026-10-15T12:00:00Z' } }
  const finding = { id: 'finding', context_id: context, vulnerability_id: 'CVE-2026-1234', component: { name: 'Runtime library', version: '1.0', purl: 'pkg:generic/runtime@1' }, context: { id: context, root_ref: 'application', component_ref: 'library', team_id: 'team', status: 'resolved' }, description: 'Synthetic vulnerability description', source_ratings: [{ source: 'Provider', score: 7.5 }], coverage: { status: 'unassessed' }, published_score: null, capabilities: ['assess'] }
  const second = { ...finding, id: 'second', context_id: 'e'.repeat(64), vulnerability_id: 'CVE-2026-2345', context: { ...finding.context, id: 'e'.repeat(64), root_ref: 'second-root' } }
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    let result: unknown = { items: [], next_offset: null, next_cursor: null }, status = 200
    if (request.method() === 'PUT') { const body = request.postDataJSON(); writes.push(body); attempts++; status = attempts === 1 ? options.conflict ? 409 : 503 : 201; result = status === 201 ? { committed: true, updates: [{ target: newer }] } : { detail: status === 409 ? 'Product version changed; reload before editing metadata' : 'Publication uncertain' }; if (status === 201) current = newer }
    else if (path === '/api/v2/me') result = { id: 'manager', name: 'Manager', org_admin: options.manage, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v2/catalog/projects') result = { items: [{ id: 'product', name: 'Metadata product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1', state: current }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state: current, project_id: 'product', version: '7.1', items: options.delayedRead ? [finding, second] : [finding], next_offset: null, statistics: { totals: { context_findings: 1, unique_vulnerabilities: 1 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.includes('/workspace/')) result = { ...(path.includes(second.context_id) ? second : finding), state: current }
    else if (path.endsWith('/component-context')) { reads++; if (options.delayedRead && reads === 1) await readGate; result = { state: current, head: current, version: '7.1', component_ref: 'library', component: { name: 'Runtime library', 'bom-ref': 'library' }, metadata, defaults: annotations, capabilities: options.manage ? ['curate'] : [], blocked_reasons: options.manage ? [] : ['component_metadata_requires_management_permission'], limitations: [], topology: { dependency_graph: 'reported', consuming_root: url.searchParams.get('context_id') === second.context_id ? 'second-root' : 'application', incoming: [{ ref: 'application', name: 'Application', version: '7.1', resolved: true }], outgoing: [], incoming_total: 1, outgoing_total: 0, neighbor_limit: 50, limitations: ['Edges do not establish runtime reachability or complete discovery.'] } } }
    await route.fulfill({ status, json: result })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click(); await page.getByRole('option', { name: 'Metadata product', exact: true }).click()
  await page.getByRole('button', { name: 'CVE-2026-1234', exact: true }).click()
  await page.locator('.component-context > summary').click()
  return { writes, releaseRead, panel: page.locator('.component-context') }
}
async function prepare(page: Page) {
  await page.getByRole('button', { name: 'Edit component annotations', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'Component annotations', exact: true })
  await dialog.getByRole('combobox', { name: 'Cybersecurity criticality', exact: true }).selectOption('high')
  await dialog.getByRole('textbox', { name: 'Runtime usage', exact: true }).fill('Used in production export service')
  await dialog.getByRole('textbox', { name: 'Reason for annotation change', exact: true }).fill('Reviewed current deployment evidence')
  await dialog.getByRole('checkbox', { name: 'I reviewed the values and provenance for this exact component/version.', exact: true }).check()
  await dialog.getByRole('button', { name: 'Review captured annotations', exact: true }).click()
  return dialog
}
test('manager annotations preserve extensions and provenance with identical frozen retries', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { writes } = await fixture(page, { manage: true })
  const dialog = await prepare(page)
  await dialog.getByRole('button', { name: 'Save captured annotations', exact: true }).click()
  await expect(dialog.getByRole('alert')).toContainText('Exact annotations, expected state/revision and request ID are retained')
  await page.keyboard.press('Escape'); await expect(dialog).toBeVisible()
  await dialog.getByRole('button', { name: 'Save captured annotations', exact: true }).click()
  await expect(dialog).not.toBeVisible()
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1])
  expect(writes[0]).toMatchObject({ expected: state, expected_revision: revision, component_ref: 'library', annotations: { cybersecurity: { criticality: 'high', mitigations: ['Firewall\nseparate note'] }, support: { references: ['SUPPORT-42'] }, properties: { preserved: 'yes' } }, provenance: { source: 'Component owner', reference: 'DESIGN-42', observed_at: '2026-10-15T12:00:00Z' } })
})
test('readers see declared dependency context and attribution without edit controls', async ({ page }) => {
  const { panel } = await fixture(page)
  await expect(panel.getByRole('button', { name: 'Edit component annotations', exact: true })).toHaveCount(0)
  await panel.getByText('Declared dependency neighborhood', { exact: false }).click()
  await expect(panel).toContainText('Application @ 7.1')
  await expect(panel).toContainText('Edges do not establish runtime reachability')
})
test('stale annotations require explicit review and conflicts keep capture until explicit discard', async ({ page }) => {
  const { writes, panel } = await fixture(page, { manage: true, stale: true, conflict: true })
  await expect(panel).toContainText('Retained annotations are stale and do not currently apply')
  const dialog = await prepare(page)
  await expect(dialog).toContainText('Previous annotations do not currently apply')
  await dialog.getByRole('button', { name: 'Save captured annotations', exact: true }).click()
  await expect(dialog.getByRole('alert')).toContainText('no head was repinned')
  expect(writes[0].expected).toBe(state)
  await dialog.getByRole('button', { name: 'Discard and refresh workspace', exact: true }).click()
  await expect(dialog).not.toBeVisible()
})


test('changing consuming context during a pending read reloads without stale data or a stuck busy state', async ({ page }) => {
  const { panel, releaseRead } = await fixture(page, { delayedRead: true })
  await expect(panel).toContainText('Loading pinned component context')
  await page.getByRole('button', { name: 'CVE-2026-2345', exact: true }).click()
  await panel.getByText('Declared dependency neighborhood', { exact: false }).click()
  await expect(panel).toContainText('Consuming root: second-root')
  releaseRead()
  await expect(panel).toContainText('Consuming root: second-root')
  await expect(panel).not.toContainText('Loading pinned component context')
})
