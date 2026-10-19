import { openNativeTools } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const sha = (char: string) => char.repeat(64)
const source = sha('a'), target = sha('b'), revision = sha('c'), policy = sha('d'), oldContext = sha('1'), newContext = sha('2')
async function fixture(page: Page, allowed = true, personas = false) {
  let failure = 0, projection = 'current', head = target, candidateChanged = false, actor = 'person', hold = false
  let release: (() => void) | undefined
  const writes: { path: string; body: Record<string, unknown> }[] = [], candidateReads: URL[] = [], contextReads: URL[] = []
  const assessment = { revision, payload: { assessment_id: 'old-decision', state: 'not_affected', justification: 'code_not_reachable', rationale: 'Source analysis considered the imported evidence', conditions: 'Old deployment only', author_id: 'source-author', evidence: [{ reference: 'SOURCE-1' }] } }
  const record = (id: string, char: string) => ({ revision: sha(char), in_version_scope: true, payload: { reconciliation_id: id, source, target, stage: 'active', rationale: `Explicit ${id}`, evidence: [], actor_id: 'curator', preview: { source, target, items: [] } } })
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname
    if (path === '/api/v1/playground/login') { actor = route.request().postDataJSON().persona; return route.fulfill({ json: {} }) }
    if (route.request().method() === 'POST' && path.includes('/correspondence-drafts')) {
      const body = route.request().postDataJSON() as Record<string, unknown>; writes.push({ path, body })
      if (path.endsWith('/preview')) return route.fulfill({ json: { preview_digest: sha('e'), draft_allowed: allowed, source_version: '7.1.1', target_version: '7.1.2', source_assessment: assessment, requires_new_target_review: true, limitations: ['Human correspondence does not verify identity or applicability.'] } })
      if (hold) { hold = false; await new Promise<void>(resolve => { release = resolve }) }
      if (failure) return route.fulfill({ status: failure, json: { detail: failure === 409 ? 'Target product version changed' : 'Publication uncertain' } })
      head = sha('f'); return route.fulfill({ json: { committed: true, projection } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: actor, name: actor, org_admin: false, playground: personas, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/playground/personas') result = personas ? [{ id: 'person', name: 'person' }, { id: 'other', name: 'other' }] : []
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.2', state: head }] }
    else if (path.endsWith('/workspace')) result = { state: head, project_id: 'product', version: '7.1.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/refs')) result = { items: [{ kind: 'tag', name: 'reviewed-source', version: '7.1.1', state: source }], next_offset: null }
    else if (path.endsWith('/correspondence-draft-candidates')) {
      candidateReads.push(url)
      result = { items: url.searchParams.get('offset') === '20' ? [] : [{ context_id: oldContext, vulnerability_id: 'CVE-2099-42', approved_assessment: assessment, component: { name: 'Library', version: '1' } }], total: 21, next_offset: url.searchParams.get('offset') === '20' ? null : 20, current_policy: policy, candidates_digest: sha(candidateChanged ? '9' : '8') }
    } else if (path.endsWith('/reconciliations')) result = { items: [record('component-map', '6'), record('context-map', '7')], total: 2, next_offset: null, capabilities: [] }
    else if (path.endsWith('/reconciliation-candidates')) { contextReads.push(url); result = { items: [{ id: newContext, component_ref: 'new-library', root_ref: 'app', component: { name: 'New library' } }], total: 21, next_offset: url.searchParams.get('offset') === '20' ? null : 20 } }
    return route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Product', exact: true }).click()
  await page.getByText('Occurrence correspondence across imports', { exact: true }).click()
  await page.getByRole('combobox', { name: 'Source branch or tag', exact: true }).selectOption(source)
  await page.getByText('Reuse approved assessment through correspondence', { exact: true }).click()
  const panel = page.getByRole('region', { name: 'Linked target assessment draft', exact: true })
  await panel.getByRole('button', { name: 'Find approved source evidence', exact: true }).click()
  return { panel, writes, candidateReads, contextReads, fail: (value: number) => { failure = value }, projection: (value: string) => { projection = value }, advance: () => { head = sha('f') }, candidateChange: () => { candidateChanged = true }, hold: () => { hold = true }, release: () => { release?.() } }
}
async function preview(panel: ReturnType<Page['getByRole']>) {
  await panel.getByRole('radio', { name: /CVE-2099-42/ }).check()
  await panel.getByRole('button', { name: 'Find linked target contexts', exact: true }).click()
  await panel.getByRole('combobox', { name: 'Linked target context', exact: true }).selectOption(newContext)
  await panel.getByRole('button', { name: 'Load recorded target assertions', exact: true }).click()
  await panel.getByRole('checkbox', { name: 'component-map', exact: false }).check()
  await panel.getByRole('checkbox', { name: 'context-map', exact: false }).check()
  await panel.getByRole('button', { name: 'Preview linked target draft', exact: true }).click()
  await expect(panel.getByLabel('Linked draft preview')).toBeVisible()
}
async function fill(panel: ReturnType<Page['getByRole']>) {
  await panel.getByLabel('Target applicability conditions', { exact: true }).fill('Only the reviewed target deployment and configuration')
  await panel.getByLabel('Reason for adopting this evidence', { exact: true }).fill('Human reviewed both explicit mappings and target usage')
  await panel.getByRole('checkbox', { name: 'I checked the source evidence', exact: false }).check()
}
test('explicit historical source, target context and assertion revisions precede a new unsubmitted target draft', async ({ page }) => {
  const { panel, writes } = await fixture(page)
  await expect(panel.getByRole('radio')).not.toBeChecked()
  await preview(panel)
  await expect(panel.getByRole('button', { name: 'Create new linked target draft', exact: true })).toBeDisabled()
  expect(writes).toHaveLength(1)
  expect(writes[0]!.body).toMatchObject({ source, target, source_context_id: oldContext, target_context_id: newContext, vulnerability_id: 'CVE-2099-42', source_assessment_revision: revision, expected_policy: policy, assertions: { 'component-map': sha('6'), 'context-map': sha('7') } })
  await fill(panel)
  await panel.getByRole('button', { name: 'Create new linked target draft', exact: true }).click()
  await expect(panel).toContainText('Independent target review is still required')
  expect(writes).toHaveLength(2)
  expect(writes[1]!.body.assessment_id).not.toBe('old-decision')
  expect(writes[1]!.body).toMatchObject({ preview_digest: sha('e'), target, conditions: 'Only the reviewed target deployment and configuration' })
  expect(writes[1]!.body).not.toHaveProperty('submit')
})
test('503, advanced target,409 and pending projection retain one exact captured body and request ID', async ({ page }) => {
  const { panel, writes, fail, advance, projection } = await fixture(page)
  await preview(panel); await fill(panel); fail(503)
  await panel.getByRole('button', { name: 'Create new linked target draft', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Retry the identical captured request')
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  advance(); await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(panel).toContainText('The target advanced')
  fail(409); await panel.getByRole('button', { name: 'Retry exact linked draft request', exact: true }).click()
  fail(0); projection('pending'); await panel.getByRole('button', { name: 'Retry exact linked draft request', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('not confirmed current')
  projection('current'); await panel.getByRole('button', { name: 'Retry exact linked draft request', exact: true }).click()
  await expect(panel).toContainText('New target draft created')
  expect(writes).toHaveLength(5)
  expect(writes.slice(1).every(row => JSON.stringify(row.body) === JSON.stringify(writes[1]!.body))).toBe(true)
})
test('changed approved source paging preserves selected evidence and old digest', async ({ page }) => {
  const { panel, writes, candidateChange, candidateReads } = await fixture(page)
  await panel.getByRole('radio', { name: /CVE-2099-42/ }).check(); candidateChange()
  await panel.getByRole('button', { name: 'More approved source assessments', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Source candidates or policy changed')
  await expect(panel.getByRole('radio', { name: /CVE-2099-42/ })).toBeChecked()
  expect(candidateReads[1]!.searchParams.get('offset')).toBe('20')
  expect(writes).toHaveLength(0)
})
test('read-only preview stays attributed and cannot publish; narrow layout retains evidence', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes } = await fixture(page, false)
  await preview(panel); await fill(panel)
  await expect(panel).toContainText('Current permissions do not allow')
  await expect(panel.getByRole('button', { name: 'Create new linked target draft', exact: true })).toBeDisabled()
  expect(writes).toHaveLength(1)
  expect((await panel.boundingBox())!.width).toBeLessThanOrEqual(390)
})


test('an old actor publication response cannot restore captured input after an actor roundtrip', async ({ page }) => {
  const f = await fixture(page, true, true)
  await preview(f.panel); await fill(f.panel); f.hold()
  await f.panel.getByRole('button', { name: 'Create new linked target draft', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('other')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toBeEnabled()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('person')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('person')
  const response = page.waitForResponse(item => item.url().endsWith('/correspondence-drafts'))
  f.release(); await response
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
  await expect(page.getByText('New target draft created with linked historical evidence.', { exact: false })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Retry exact linked draft request', exact: true })).toHaveCount(0)
  expect(f.writes).toHaveLength(2)
})


test('source evidence stays visible across candidate pages and target pages retain the applied search', async ({ page }) => {
  const { panel, contextReads } = await fixture(page)
  await panel.getByRole('radio', { name: /CVE-2099-42/ }).check()
  await panel.getByRole('button', { name: 'More approved source assessments', exact: true }).click()
  await expect(panel.getByRole('radio')).toHaveCount(0)
  await expect(panel.getByLabel('Selected approved source evidence')).toContainText(`CVE-2099-42 · context ${oldContext} · revision ${revision}`)
  await panel.getByLabel('Search linked target contexts', { exact: true }).fill('applied target')
  await panel.getByRole('button', { name: 'Find linked target contexts', exact: true }).click()
  await panel.getByLabel('Search linked target contexts', { exact: true }).fill('unapplied draft')
  await panel.getByRole('button', { name: 'More linked target contexts', exact: true }).click()
  await expect.poll(() => contextReads.length).toBe(2)
  expect(contextReads.map(url => [url.searchParams.get('q'), url.searchParams.get('offset')])).toEqual([['applied target', '0'], ['applied target', '20']])
})
