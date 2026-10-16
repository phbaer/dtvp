import { expect, test, type Page } from '@playwright/test'
const sha = (char: string) => char.repeat(64), inventory = sha('a'), evidence = sha('b'), newerEvidence = sha('c'), digest = sha('d')
async function fixture(page: Page, personas = false) {
  let live = evidence, head = inventory, conflict = false, actor = 'person', hold = false
  let release: (() => void) | undefined
  const reports: Record<string, unknown>[] = [], reads: string[] = []
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (path === '/api/v2/playground/login') { actor = route.request().postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (path.endsWith('/compare/intelligence')) {
      const body = route.request().postDataJSON() as Record<string, unknown>; reports.push(body)
      if (hold) { hold = false; await new Promise<void>(resolve => { release = resolve }) }
      if (conflict) return route.fulfill({ status: 409, json: { detail: 'Intelligence report digest changed' } })
      const later = url.searchParams.get('offset') === '20'
      return route.fulfill({ json: { inventory_state: body.inventory_state, inventory_version: '7.1.1', evidence_state: body.evidence_state, report_digest: digest, currentness: { captured_evidence_head: live, selected_is_current: live === body.evidence_state }, statistics: { baseline_identifiers: 2, claim_groups: 21, by_status: { changed: 20, no_longer_selected: 1 }, excluded_document_formats: { before: {}, after: { vex: 1 } }, nonbaseline_statements: { before: 0, after: 3 } }, total: 21, next_offset: later ? null : 20, items: [{ id: later ? 'second' : 'first', source: 'circl', publisher: 'supplier', document_id: 'advisory-42', vulnerability_id: later ? 'CVE-2099-43' : 'CVE-2099-42', component_refs: ['library'], status: later ? 'no_longer_selected' : 'changed', before: [{ facts: { description: 'Original source statement', rating: 9.8 } }], after: [{ facts: { description: '<script>window.intelligenceInjected=true</script>', rating: 4.2 } }], inactive_selected_records: [] }], limitations: ['Provider statement differences are not remediation or applicability conclusions.'] } })
    }
    reads.push(path)
    let data: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') data = { id: actor, name: actor, org_admin: false, playground: personas, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v2/playground/personas') data = personas ? [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v2/catalog/projects') data = { items: [{ id: 'product', name: 'Product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) data = { items: [{ version: '7.1.1', state: head }] }
    else if (path.endsWith('/workspace')) data = { state: head, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/advisory-refresh')) data = { expected_versions: { '7.1.1': head }, expected_evidence: live, providers: [], identifiers: [], total: 0, next_offset: null, capabilities: [], limitations: [] }
    else if (path.endsWith('/advisory-jobs')) data = { items: [], next_offset: null }
    else if (path.endsWith('/evidence')) data = { evidence_state: live, items: [] }
    return route.fulfill({ json: data })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'Product', exact: true }).click()
  await page.getByText('Advisory intelligence refresh', { exact: true }).click()
  await page.getByText('Compare retained inventory with advisory evidence', { exact: true }).click()
  const panel = page.getByRole('region', { name: 'Pinned advisory intelligence comparison', exact: true })
  return { panel, reports, reads, advanceEvidence: () => { live = newerEvidence }, advanceInventory: () => { head = sha('f') }, conflict: (value: boolean) => { conflict = value }, hold: () => { hold = true }, release: () => { release?.() } }
}
async function compare(panel: ReturnType<Page['getByRole']>, mode = 'captured') {
  await panel.getByRole('button', { name: 'Capture intelligence comparison inputs', exact: true }).click()
  await panel.getByRole('combobox', { name: 'Advisory evidence snapshot', exact: true }).selectOption(mode)
  await panel.getByRole('button', { name: 'Compare pinned advisory evidence', exact: true }).click()
}
test('read-only comparison is explicit and preserves a required null evidence pin', async ({ page }) => {
  const { panel, reports, reads } = await fixture(page)
  expect(reads.filter(path => path.endsWith('/evidence'))).toHaveLength(0)
  expect(reports).toHaveLength(0)
  await compare(panel, 'none')
  await expect(panel.getByLabel('Displayed intelligence comparison pins')).toContainText('none (explicit selection)')
  expect(reports[0]).toEqual({ inventory_state: inventory, evidence_state: null })
  await expect(panel).toContainText('Source ratings and human approvals remain unchanged')
  await expect(panel.getByLabel('Intelligence comparison totals')).toContainText('21 claim groups · 2 baseline identifiers')
})
test('new live heads and edited input drafts never repin report pagination', async ({ page }) => {
  const { panel, reports, reads, advanceEvidence } = await fixture(page)
  await compare(panel); advanceEvidence()
  await panel.getByRole('button', { name: 'Capture intelligence comparison inputs', exact: true }).click()
  await panel.getByRole('combobox', { name: 'Advisory evidence snapshot', exact: true }).selectOption('none')
  await panel.getByRole('button', { name: 'Next intelligence comparison page', exact: true }).click()
  await expect(panel).toContainText('current reference at comparison capture')
  await expect(panel).toContainText('CVE-2099-43 · no longer selected')
  expect(reports[1]).toEqual({ inventory_state: inventory, evidence_state: evidence, expected_digest: digest })
  expect(reads.filter(path => path.endsWith('/evidence'))).toHaveLength(2)
  await panel.getByRole('button', { name: 'Previous intelligence comparison page', exact: true }).click()
  expect(reports[2]).toEqual(reports[1])
})
test('conflicting pages retain exact report pins and facts; explicit inventory refresh stays distinct on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, reports, conflict, advanceInventory } = await fixture(page)
  await compare(panel); conflict(true)
  await panel.getByRole('button', { name: 'Next intelligence comparison page', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('report digest changed')
  await expect(panel).toContainText('CVE-2099-42 · changed')
  advanceInventory(); await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(panel).toContainText('workspace inventory changed')
  await panel.getByText('Before, selected evidence and inactive records', { exact: true }).click()
  await expect(panel.locator('pre').first()).toContainText('<script>window.intelligenceInjected=true</script>')
  expect(await page.evaluate(() => 'intelligenceInjected' in window)).toBe(false)
  conflict(false); await panel.getByRole('button', { name: 'Next intelligence comparison page', exact: true }).click()
  expect(reports[2]).toEqual(reports[1])
  expect((await panel.boundingBox())!.width).toBeLessThanOrEqual(390)
})
test('actor teardown prevents a late report response from restoring the previous session view', async ({ page }) => {
  const f = await fixture(page, true)
  f.hold(); await compare(f.panel)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('person')
  const response = page.waitForResponse(item => item.url().includes('/compare/intelligence'))
  f.release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByText('CVE-2099-42 · changed', { exact: true })).toHaveCount(0)
  expect(f.reports).toHaveLength(1)
})

test('historical inventory is an explicit pin and draft edits do not change its report pages', async ({ page }) => {
  const { panel, reports } = await fixture(page)
  await panel.getByRole('button', { name: 'Capture intelligence comparison inputs', exact: true }).click()
  await panel.getByText('Choose retained inventory state', { exact: true }).click()
  const field = panel.getByRole('textbox', { name: 'Retained inventory SHA-256', exact: true })
  await field.fill('invalid')
  await panel.getByRole('combobox', { name: 'Advisory evidence snapshot', exact: true }).selectOption('captured')
  await expect(panel.getByRole('button', { name: 'Compare pinned advisory evidence', exact: true })).toBeDisabled()
  await field.fill(sha('e'))
  await panel.getByRole('button', { name: 'Compare pinned advisory evidence', exact: true }).click()
  await expect(panel.getByLabel('Displayed intelligence comparison pins')).toContainText(sha('e').slice(0, 12))
  expect(reports[0]).toEqual({ inventory_state: sha('e'), evidence_state: evidence })
  await panel.getByRole('button', { name: 'Use workspace inventory state', exact: true }).click()
  await expect(field).toHaveValue(inventory)
  await panel.getByRole('button', { name: 'Next intelligence comparison page', exact: true }).click()
  expect(reports[1]).toEqual({ inventory_state: sha('e'), evidence_state: evidence, expected_digest: digest })
  await expect(panel.getByLabel('Displayed intelligence comparison pins')).toContainText(sha('e').slice(0, 12))
  await panel.getByRole('button', { name: 'Compare pinned advisory evidence', exact: true }).click()
  expect(reports[2]).toEqual({ inventory_state: inventory, evidence_state: evidence })
})
