import { openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const hash = (char: string) => char.repeat(64)
async function fixture(page: Page, reader = false) {
  let failure = 503, changed = false, pending = false
  const writes: unknown[] = [], reads: string[] = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname, url = new URL(route.request().url())
    let result: unknown = { items: [], capabilities: [], next_cursor: null }
    if (path.includes('/assessment-archive')) reads.push(path)
    if (path.endsWith('/assessment-archive/apply')) {
      writes.push(route.request().postDataJSON())
      if (failure) return route.fulfill({ status: failure, json: { detail: 'Uncertain or changed references' } })
      return route.fulfill({ json: { committed: true, projection: pending ? 'pending' : 'current' } })
    }
    if (path === '/api/v1/me') result = { id: 'person', name: 'Person', org_admin: true, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Archive product', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [] }
    else if (path.endsWith('/assessment-archive')) result = { items: [{ assessment_id: 'retained', reason: 'Past scope removed', actor_id: 'manager', archived_at: '2026-10-16', revision_count: 1 }], total: 1, next_offset: null, capabilities: reader ? [] : ['preview', 'apply'] }
    else if (path.endsWith('/assessment-archive/retained')) result = { manifest: { assessment_id: 'retained', actor_id: 'manager' }, assessments: [{ payload: { rationale: 'Historical reason' } }], current_approval: false, next_offset: null }
    else if (path.endsWith('/assessment-archive/preview')) result = { plan_hash: hash(changed ? 'b' : 'a'), project_refs: { branch: hash('c') }, assessments: [{ assessment_id: url.searchParams.get('offset') === '25' ? 'second' : 'unused', status: 'retention_candidate', candidate: true, revisions: [hash('d')], active_targets: [], tagged_references: [] }, { assessment_id: 'protected', status: 'tag_protected', candidate: false, revisions: [], active_targets: [], tagged_references: ['released'] }], statistics: { retention_candidate: 1, tag_protected: 1 }, total: 2, next_offset: url.searchParams.has('offset') && url.searchParams.get('offset') !== '0' ? null : 25, limitations: ['No physical deletion.'] }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Administration')
  await page.getByRole('navigation', { name: 'Administration', exact: true }).getByRole('button', { name: 'Product maintenance', exact: true }).click()
  await page.getByRole('button', { name: 'Maintenance product', exact: false }).click()
  await page.getByRole('option', { name: 'Archive product', exact: true }).click()
  const panel = page.getByLabel('Assessment archive', { exact: true })
  return { panel, writes, reads, fail: (value: number) => { failure = value }, advance: () => { changed = true }, pending: (value: boolean) => { pending = value } }
}
test('archive list is lazy, readers can inspect retained evidence without management actions', async ({ page }) => {
  const { panel, reads } = await fixture(page, true)
  expect(reads).toHaveLength(0)
  await openDisclosure(panel.getByText('Assessment archive', { exact: true }))
  await expect(panel).toContainText('1 archived assessments')
  await expect(panel.getByRole('button', { name: 'Preview unused assessment retirement' })).toHaveCount(0)
  await panel.getByRole('button', { name: 'retained', exact: true }).click()
  await panel.getByText('Retained assessment and review evidence', { exact: true }).click()
  await expect(panel).toContainText('Historical reason')
  await expect(panel).toContainText('"current_approval": false')
})
test('manual eligible selection and reason confirmation precede exact retry through503,409 and projection pending', async ({ page }) => {
  const { panel, writes, fail, pending } = await fixture(page)
  await openDisclosure(panel.getByText('Assessment archive', { exact: true }))
  await panel.getByRole('button', { name: 'Preview unused assessment retirement' }).click()
  await expect(panel.getByRole('checkbox', { name: 'protected' })).toBeDisabled()
  await expect(panel.getByRole('button', { name: 'Archive selected assessments' })).toBeDisabled()
  await panel.getByRole('checkbox', { name: 'unused' }).check()
  await panel.getByLabel('Archival reason').fill('Wholly absent; preserve history')
  await panel.getByRole('checkbox', { name: 'I checked selected assessments' }).check()
  await panel.getByRole('button', { name: 'Archive selected assessments' }).click()
  await expect(panel.getByRole('alert')).toContainText('identical captured request')
  fail(409); await panel.getByRole('button', { name: 'Retry exact assessment archival' }).click()
  fail(0); pending(true); await panel.getByRole('button', { name: 'Retry exact assessment archival' }).click()
  await expect(panel.getByRole('button', { name: 'Retry exact assessment archival' })).toBeVisible()
  pending(false); await panel.getByRole('button', { name: 'Retry exact assessment archival' }).click()
  await expect(panel.getByRole('status').filter({ hasText: 'Assessments archived' })).toBeVisible()
  expect(writes).toHaveLength(4)
  expect(writes.every(value => JSON.stringify(value) === JSON.stringify(writes[0]))).toBe(true)
  expect(writes[0]).toMatchObject({ assessment_ids: ['unused'], plan_hash: hash('a'), project_refs: { branch: hash('c') } })
})
test('changed preview pagination retains old pins and requires explicit discard', async ({ page }) => {
  const { panel, writes, advance } = await fixture(page)
  await openDisclosure(panel.getByText('Assessment archive', { exact: true }))
  await panel.getByRole('button', { name: 'Preview unused assessment retirement' }).click()
  await panel.getByRole('checkbox', { name: 'unused' }).check()
  advance(); await panel.getByRole('button', { name: 'More retirement candidates' }).click()
  await expect(panel.getByRole('alert')).toContainText('Archive plan changed')
  await expect(panel.getByRole('checkbox', { name: 'unused' })).toBeChecked()
  await expect(panel.getByRole('button', { name: 'Archive selected assessments' })).toBeDisabled()
  expect(writes).toHaveLength(0)
  await panel.getByRole('button', { name: 'Discard archive plan and captured request' }).click()
  await expect(panel.getByLabel('Assessment retirement preview')).toHaveCount(0)
})


test('cross-page selection stays visible and locks product navigation until explicit discard', async ({ page }) => {
  const { panel, writes } = await fixture(page)
  await openDisclosure(panel.getByText('Assessment archive', { exact: true }))
  await panel.getByRole('button', { name: 'Preview unused assessment retirement' }).click()
  await panel.getByRole('checkbox', { name: 'unused' }).check()
  await panel.getByRole('button', { name: 'More retirement candidates' }).click()
  await panel.getByRole('checkbox', { name: 'second' }).check()
  const selected = panel.getByLabel('Selected assessment IDs', { exact: true })
  await expect(selected).toContainText('unused')
  await expect(selected).toContainText('second')
  await expect(page.getByRole('button', { name: 'Maintenance product', exact: false })).toBeDisabled()
  expect(writes).toHaveLength(0)
  await panel.getByRole('button', { name: 'Discard archive plan and captured request' }).click()
  await expect(page.getByRole('button', { name: 'Maintenance product', exact: false })).toBeEnabled()
  await expect(selected).toHaveCount(0)
})
