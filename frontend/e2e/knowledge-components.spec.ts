import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const current = 'a'.repeat(64), old = 'b'.repeat(64), ctx = 'c'.repeat(64)
const defaults = { cybersecurity: { criticality: 'unknown', exposure: 'unknown', mitigations: [], testing_evidence: [] }, deployment: { environment: '', usage: '', configuration: '' }, support: { status: 'unknown', supplier: '', support_until: null, end_of_life: null, references: [] }, notes: '', properties: {} }
async function fixture(page: Page, manage = false) {
  const reads: string[] = [], writes: any[] = []
  await page.route('**/api/**', async route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname, historical = path.includes(old)
    let result: any = { items: [], next_offset: null, next_cursor: null }, status = 200
    if (req.method() === 'PUT') { writes.push(req.postDataJSON()); status = writes.length === 1 ? 503 : 201; result = status === 201 ? { committed: true, updates: [] } : { detail: 'Publication uncertain' } }
    else if (path === '/api/v1/me') result = { id: 'manager', name: 'Manager', org_admin: manage, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Composition product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '1.0', state: current }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state: current, project_id: 'product', version: '1.0', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/components')) { reads.push(path + url.search); result = { state: historical ? old : current, head: current, version: '1.0', items: [{ component_ref: 'quiet', component: { name: 'Quiet package', version: '1' }, context_count: 2, team_ids: ['team'], ownership_statuses: ['resolved'], delegated_contexts: 1, incoming_declared: 2, outgoing_declared: 0 }], next_offset: null, statistics: { component_occurrences: 37, consuming_contexts: 45, all_component_occurrences: 50 }, teams: [{ id: 'team', name: 'Platform' }], limitations: ['No finding does not mean clearance.'] } }
    else if (path.endsWith('/components/contexts')) { reads.push(path); result = { items: [{ id: ctx, root_ref: 'Application', team_id: 'team', status: 'resolved', delegated: true }, { id: 'd'.repeat(64), root_ref: 'Worker', team_id: 'team', status: 'resolved' }], total: 2, next_offset: null } }
    else if (path.endsWith('/component-context')) { reads.push(path + url.search); result = { state: historical ? old : current, head: current, version: '1.0', component_ref: 'quiet', component: { 'bom-ref': 'quiet', name: 'Quiet package' }, metadata: null, defaults, capabilities: manage && !historical ? ['curate'] : [], blocked_reasons: historical ? ['selected_state_is_not_current_head'] : ['component_metadata_requires_management_permission'], limitations: [], topology: { dependency_graph: 'reported', consuming_root: url.searchParams.has('context_id') ? 'Application' : null, incoming: [], outgoing: [], incoming_total: 2, outgoing_total: 0, neighbor_limit: 50, limitations: [] } } }
    await route.fulfill({ status, json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Composition product', exact: true }).click()
  await page.getByText('Component inventory', { exact: true }).click()
  const panel = page.locator('.component-inventory')
  await expect(panel).toContainText('37 component occurrences')
  return { panel, reads, writes }
}
async function detail(panel: ReturnType<Page['locator']>) { await panel.getByRole('button', { name: 'Quiet package @ 1', exact: true }).click(); await panel.getByText('Component context, dependencies and annotations', { exact: true }).click() }

test('no-finding inventory uses backend totals and distinct consuming contexts', async ({ page }) => {
  const { panel, reads } = await fixture(page)
  await panel.getByLabel('Find component', { exact: true }).fill('quiet')
  await panel.getByRole('button', { name: 'Search components', exact: true }).click()
  await expect.poll(() => reads.some(value => value.includes('q=quiet'))).toBe(true)
  await detail(panel)
  await expect(panel).toContainText('Unknown (no current annotations)')
  expect(reads.at(-1)).not.toContain('context_id=')
  await expect(panel.getByLabel('Consuming component context').getByRole('option')).toHaveCount(3)
  await panel.getByLabel('Consuming component context').selectOption(ctx)
  await panel.getByText('Component context, dependencies and annotations', { exact: true }).click()
  await expect.poll(() => reads.at(-1)).toContain('context_id=' + ctx)
  await expect(panel).toContainText('37 component occurrences')
})

test('historical pin is explicit and no-finding annotation edit is read only', async ({ page }) => {
  const { panel, reads } = await fixture(page, true)
  await panel.getByText('Pinned inventory state', { exact: true }).click()
  await panel.getByLabel('Inventory state SHA').fill(old)
  await panel.getByRole('button', { name: 'Quiet package @ 1', exact: true }).click()
  await expect.poll(() => reads.some(value => value.includes(`/states/${current}/components/contexts`))).toBe(true)
  await panel.getByRole('button', { name: 'Load pinned inventory state', exact: true }).click()
  await expect(panel).toContainText('Historical inventory, read only')
  await detail(panel)
  await expect(panel).toContainText('selected state is not current head')
  await expect(panel.getByRole('button', { name: 'Edit component annotations' })).toHaveCount(0)
})

test('no-finding annotation edits retain exact existing capture after uncertainty', async ({ page }) => {
  const { panel, writes } = await fixture(page, true)
  await detail(panel)
  await panel.getByRole('button', { name: 'Edit component annotations', exact: true }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Provenance source', { exact: true }).fill('Team review')
  await dialog.getByLabel('Reason for annotation change', { exact: true }).fill('Runtime evidence')
  await dialog.getByRole('checkbox').check()
  await dialog.getByRole('button', { name: 'Review captured annotations', exact: true }).click()
  await dialog.getByRole('button', { name: 'Save captured annotations', exact: true }).click()
  await expect(dialog).toContainText('Exact annotations, expected state/revision and request ID are retained')
  await dialog.getByRole('button', { name: 'Save captured annotations', exact: true }).click()
  await expect(dialog).not.toBeVisible()
  expect(writes).toHaveLength(2); expect(writes[0]).toEqual(writes[1]); expect(writes[0].component_ref).toBe('quiet'); expect(writes[0].expected).toBe(current)
})
