import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const sha = (value: string) => value.repeat(64)

async function fixture(page: Page, readonly = false) {
  let head = sha('b'), failure = 0, blocked = false
  const writes: { path: string; body: Record<string, unknown> }[] = [], reads: URL[] = []
  const oldPair = { kind: 'component', source_id: 'old-lib', target_id: 'new-lib' }
  const oldPreview = { source: sha('a'), target: sha('b'), preview_digest: sha('d'), eligible: true, items: [{ ...oldPair, classification: 'candidate', reasons: [] }], limitations: [] }
  const record = { revision: sha('e'), in_version_scope: true, payload: { reconciliation_id: 'mapping-one', source: sha('a'), target: sha('b'), stage: 'active', rationale: 'Previous attributed mapping', evidence: [{ ticket: 'REF-1' }], preview: oldPreview, actor_id: 'curator' } }
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname; reads.push(url)
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON(); writes.push({ path, body })
      if (path.endsWith('/reconciliation/preview') && failure === 409) return route.fulfill({ status: 409, json: { detail: 'Correspondence target version changed' } })
      if (path.endsWith('/reconciliation/preview')) return route.fulfill({ json: { ...oldPreview, source: body.source, target: body.target, eligible: !blocked, items: body.pairs.map((pair: object) => ({ ...pair, classification: blocked ? 'conflicting' : 'candidate', reasons: [blocked ? 'same_version_hash_conflict' : 'consuming_context_changed_requires_new_target_review'], source_facts: { component: { name: 'Old library' } }, target_facts: { component: { name: 'Renamed library' } } })), limitations: ['No assessments, approvals or ownership are transferred.'] } })
      if (failure) return route.fulfill({ status: failure, json: { detail: failure === 503 ? 'Publication uncertain; resend identical input.' : 'Correspondence target version changed' } })
      head = sha('c'); return route.fulfill({ status: 201, json: {} })
    }
    let result: unknown = { items: [], capabilities: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: 'person', name: 'Person', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read'] }] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state: head }] }
    else if (path.endsWith('/workspace')) result = { state: head, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/reconciliations')) result = { state: head, items: [record], total: 21, next_offset: url.searchParams.get('offset') === '20' ? null : 20, capabilities: readonly ? [] : ['write'] }
    else if (path.endsWith('/refs')) result = { items: [{ kind: 'tag', name: 'old-release', version: '7.0.0', state: sha('a') }], next_offset: null }
    else if (path.endsWith('/history')) result = { items: [{ state: sha('0'), version: '6.15.6', reason: 'Historical nightly', created_at: '' }], next_offset: null }
    else if (path.endsWith('/reconciliation-candidates')) {
      const source = path.includes(sha('a')) || path.includes(sha('0')), kind = url.searchParams.get('kind') || 'component', name = source ? 'Old library' : 'Renamed library'
      const ref = source ? 'old-lib' : 'new-lib', id = kind === 'context' ? (source ? sha('1') : sha('2')) : ref
      result = { items: [{ id, kind, component_ref: ref, root_ref: kind === 'context' ? 'app' : null, component: { name, version: '1.0', purl: 'pkg:generic/lib@1.0' }, root: kind === 'context' ? { name: 'Application' } : null, team_id: 'team', ownership_status: 'resolved' }], total: 23, next_offset: url.searchParams.get('offset') === '20' ? null : 20 }
    }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Product', exact: true }).click()
  await openProductView(page, 'Imports')
  await openDisclosure(page.getByText('Occurrence correspondence across imports', { exact: true }))
  const panel = page.getByLabel('Occurrence correspondence', { exact: true })
  await expect(panel).toContainText('21 retained assertions')
  return { panel, writes, reads, fail: (status: number) => { failure = status }, block: () => { blocked = true }, advance: () => { head = sha('c') } }
}

async function addPair(panel: ReturnType<Page['getByLabel']>) {
  await panel.getByRole('combobox', { name: 'Source branch or tag', exact: true }).selectOption(sha('a'))
  await panel.getByRole('button', { name: 'Search source occurrences', exact: true }).click()
  await panel.getByRole('radio', { name: /Old library/ }).check()
  await panel.getByRole('button', { name: 'Search target occurrences', exact: true }).click()
  await panel.getByRole('radio', { name: /Renamed library/ }).check()
  await panel.getByRole('button', { name: 'Add explicit correspondence pair', exact: true }).click()
}

test('bounded exact selectors require manual pairs and keep component/context relations distinct', async ({ page }) => {
  const { panel, writes, reads } = await fixture(page)
  await expect(panel.getByRole('button', { name: 'Preview correspondence', exact: true })).toBeDisabled()
  await addPair(panel)
  await panel.getByRole('combobox', { name: 'Relation kind', exact: true }).selectOption('context')
  await panel.getByLabel('Source occurrence search', { exact: true }).fill('lib')
  await panel.getByRole('button', { name: 'Search source occurrences', exact: true }).click()
  await panel.getByRole('radio', { name: /Old library.*via Application/ }).check()
  await panel.getByRole('button', { name: 'Search target occurrences', exact: true }).click()
  await panel.getByRole('radio', { name: /Renamed library.*via Application/ }).check()
  await panel.getByRole('button', { name: 'Add explicit correspondence pair', exact: true }).click()
  await panel.getByRole('button', { name: 'Preview correspondence', exact: true }).click()
  await expect(panel.getByLabel('Correspondence preview')).toContainText('Eligible attributed assertion')
  expect(writes).toHaveLength(1)
  expect(writes[0]!.body).toMatchObject({ source: sha('a'), target: sha('b'), pairs: [{ kind: 'component', source_id: 'old-lib', target_id: 'new-lib' }, { kind: 'context', source_id: sha('1'), target_id: sha('2') }] })
  expect(reads.some(url => url.searchParams.get('q') === 'lib' && url.searchParams.get('limit') === '20')).toBeTruthy()
  await panel.getByRole('button', { name: 'Next source occurrences', exact: true }).click()
  await expect(panel.getByRole('button', { name: 'Next source occurrences', exact: true })).toBeDisabled()
})

test('confirmation preserves exact preview, evidence and UUID across503 and advanced target heads', async ({ page }) => {
  const { panel, writes, fail, advance } = await fixture(page)
  await addPair(panel)
  await panel.getByRole('button', { name: 'Preview correspondence', exact: true }).click()
  const form = panel.getByLabel('Record correspondence', { exact: true })
  await form.getByLabel('Correspondence rationale', { exact: true }).fill('Reviewed producer reference migration against build evidence.')
  await form.getByText('Attributed evidence references', { exact: true }).click()
  await form.getByLabel('Correspondence evidence (JSON array)', { exact: true }).fill('[{"ticket":"MIGRATION-1"}]')
  fail(503)
  await form.getByRole('button', { name: 'Record attributed correspondence', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('Publication uncertain')
  advance()
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect(panel).toContainText('workspace target advanced')
  await expect(panel.getByRole('button', { name: 'Consider retraction mapping-one', exact: true })).toBeDisabled()
  await form.getByRole('button', { name: 'Resend identical correspondence request', exact: true }).click()
  await expect.poll(() => writes.length).toBe(3)
  expect(writes[2]!.body).toEqual(writes[1]!.body)
  expect(writes[1]!.body).toMatchObject({ expected: sha('b'), expected_revision: null, source: sha('a'), preview_digest: sha('d'), evidence: [{ ticket: 'MIGRATION-1' }] })
  fail(0)
  await form.getByRole('button', { name: 'Resend identical correspondence request', exact: true }).click()
  await expect(panel.getByRole('status')).toContainText('No identities, decisions or approvals were transferred')
})

test('blocked server preview prevents confirmation and never turns mapping into approval', async ({ page }) => {
  const { panel, writes, block } = await fixture(page)
  await addPair(panel)
  block()
  await panel.getByRole('button', { name: 'Preview correspondence', exact: true }).click()
  await expect(panel.getByLabel('Correspondence preview')).toContainText('Blocked')
  await panel.getByLabel('Correspondence rationale', { exact: true }).fill('A human explanation does not override the hard conflict.')
  await expect(panel.getByRole('button', { name: 'Record attributed correspondence', exact: true })).toBeDisabled()
  expect(writes).toHaveLength(1)
})

test('supersession requires fresh preview and retraction pins exact existing revision with retry isolation', async ({ page }) => {
  const { panel, writes, fail } = await fixture(page)
  await panel.getByRole('button', { name: 'Supersede assertion mapping-one', exact: true }).click()
  await expect(panel.getByRole('button', { name: 'Record attributed correspondence', exact: true })).toBeDisabled()
  await panel.getByRole('button', { name: 'Preview correspondence', exact: true }).click()
  await panel.getByRole('button', { name: 'Record attributed correspondence', exact: true }).click()
  await expect.poll(() => writes.length).toBe(2)
  expect(writes[1]!.body).toMatchObject({ expected_revision: sha('e') })
  await panel.getByRole('button', { name: 'Consider retraction mapping-one', exact: true }).click()
  await panel.getByLabel('Retraction reason', { exact: true }).fill('Producer withdrew its migration assertion.')
  fail(409)
  await panel.getByRole('button', { name: 'Retract assertion', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('target version changed')
  await expect(panel.getByRole('button', { name: 'Resend identical correspondence request', exact: true })).toBeDisabled()
  await panel.getByRole('button', { name: 'Resend identical retraction request', exact: true }).click()
  await expect.poll(() => writes.length).toBe(4)
  expect(writes[3]!.body).toEqual(writes[2]!.body)
  expect(writes[2]!.body).toMatchObject({ expected_revision: sha('e'), reason: 'Producer withdrew its migration assertion.' })
})

test('readonly historical browsing and selectors fit narrow layout without mutation controls', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes } = await fixture(page, true)
  await expect(panel.getByLabel('Record correspondence', { exact: true })).toHaveCount(0)
  await expect(panel.getByRole('button', { name: 'Retract assertion', exact: true })).toHaveCount(0)
  await panel.getByText('Historical source states', { exact: true }).click()
  await panel.getByRole('button', { name: 'Search source history', exact: true }).click()
  await panel.getByRole('button', { name: /6.15.6.*Historical nightly/ }).click()
  await panel.getByRole('button', { name: 'Search source occurrences', exact: true }).click()
  await expect(panel).toContainText('23 matching component occurrences')
  await panel.getByText('Advanced source state identifier', { exact: true }).click()
  await panel.getByLabel('Historical source SHA-256', { exact: true }).fill('invalid')
  await panel.getByRole('button', { name: 'Use exact historical source', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('complete lowercase SHA-256')
  await expect(page.locator('body')).toHaveJSProperty('scrollWidth', 390)
  expect(writes).toHaveLength(0)
})


test('a stale server preview retains selected pairs but disables unpinned confirmation', async ({ page }) => {
  const { panel, fail } = await fixture(page)
  await addPair(panel)
  await panel.getByRole('button', { name: 'Preview correspondence', exact: true }).click()
  await panel.getByLabel('Correspondence rationale', { exact: true }).fill('Preserve this rationale across a concurrent target build.')
  fail(409)
  await panel.getByRole('button', { name: 'Preview correspondence', exact: true }).click()
  await expect(panel.getByRole('alert')).toContainText('target version changed')
  await expect(panel.getByRole('button', { name: 'Record attributed correspondence', exact: true })).toBeDisabled()
  await expect(panel.getByLabel('Correspondence rationale', { exact: true })).toHaveValue('Preserve this rationale across a concurrent target build.')
  await expect(panel).toContainText('old-lib → new-lib')
})
