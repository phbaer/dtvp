import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { expect, test, type Page } from '@playwright/test'
const pin = 'a'.repeat(64), newer = 'b'.repeat(64), head = 'c'.repeat(64)
async function fixture(page: Page, existing = false) {
  const writes: { path: string; body: Record<string, any> }[] = []
  let applied = false, attempts = 0
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    let result: unknown = {}, status = 200
    if (request.method() === 'POST') {
      const body = request.postDataJSON(); writes.push({ path, body })
      if (path.endsWith('/assembly-preview')) result = { preview_digest: 'd'.repeat(64), readiness: body.parts.some((part: any) => part.required && !part.state) ? 'incomplete' : 'selected', missing_required_parts: body.parts.filter((part: any) => part.required && !part.state).map((part: any) => part.part_id), selected_part_count: body.parts.filter((part: any) => part.state).length, counts: { component_occurrences: 4, source_findings: 2, dependency_edges: 1 }, changes: { removed_parts: body.removed_parts, withdrawn_parts: body.withdrawn_parts }, limitations: ['Structural preview only. Ownership, evidence and review status are not previewed.'] }
      else if (path.endsWith('/assembly-apply')) { attempts++; status = attempts === 1 ? 503 : 201; applied = status === 201; result = status === 503 ? { detail: 'Publication uncertain' } : { committed: true, updates: [{ target: head }] } }
    } else if (path === '/api/v1/me') result = { id: 'analyst', name: 'Analyst', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Assembly product', workspace_id: 'team', capabilities: ['read', 'write'] }, { id: 'other', name: 'Other product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: existing || applied ? [{ version: '7.2', state: head }] : [], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state: head, project_id: 'product', version: '7.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/assembly-target')) result = { state: existing ? head : null, predecessor: null, previous_kind: existing ? 'assembly' : 'none', parts: existing ? [{ part_id: 'application', state: pin, required: true, role: 'delivery' }] : [], coherence: existing ? { status: 'producer_declared', build_id: 'old-build' } : null, capabilities: ['assemble'], limitations: [] }
    else if (path.endsWith('/assembly-parts')) result = { items: [{ part_id: 'application', state: newer, source: 'CI' }], total: 1, next_offset: null }
    await route.fulfill({ status, json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Assembly product', exact: true }).click()
  await openProductView(page, 'Imports')
  await openDisclosure(page.locator('.knowledge-assembly > summary'))
  const panel = page.getByRole('region', { name: 'Product assembly editor' })
  await panel.getByLabel('Assembly version (existing or new)', { exact: true }).fill('7.2')
  await panel.getByRole('button', { name: 'Inspect assembly target', exact: true }).click()
  return { panel, writes }
}

test('empty product explicitly selects source parts and retries identical frozen assembly', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { panel, writes } = await fixture(page)
  await expect(panel).toContainText('No parts selected')
  await panel.getByRole('button', { name: 'Add application', exact: true }).click()
  await panel.getByRole('button', { name: 'Preview exact assembly', exact: true }).click()
  await expect(panel).toContainText('review status are not previewed')
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeDisabled()
  const publish = panel.getByRole('button', { name: 'Publish selected assembly', exact: true })
  await publish.click(); await expect(panel.getByRole('alert')).toContainText('Exact selection, preview and request ID retained')
  await publish.click(); await expect(page.getByRole('status').filter({ hasText: 'Product assembly published' })).toContainText('Product assembly published')
  const applications = writes.filter(write => write.path.endsWith('/assembly-apply'))
  expect(applications).toHaveLength(2); expect(applications[0]).toEqual(applications[1])
  expect(applications[0]!.body.assembly).toMatchObject({ expected: null, parts: [{ part_id: 'application', state: newer, required: true, role: 'delivery' }], coherence: { status: 'unverified', build_id: null, rationale: '' } })
  expect(applications[0]!.body.assembly.request_id).toMatch(/^[0-9a-f-]{36}$/)
  expect(await panel.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Other product', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Product assembly published' })).toHaveCount(0)
})

test('existing selected historical pin stays selected and prior coherence is not reused', async ({ page }) => {
  const { panel, writes } = await fixture(page, true)
  await expect(panel.getByRole('button', { name: 'Use inspected head for application', exact: true })).toBeVisible()
  await panel.getByRole('button', { name: 'Preview exact assembly', exact: true }).click()
  const captured = writes.find(write => write.path.endsWith('/assembly-preview'))!.body
  expect(captured.parts[0].state).toBe(pin)
  expect(captured.coherence.status).toBe('unverified')
})

test('withdrawal and changed requirements carry explicit reasons; missing remains incomplete', async ({ page }) => {
  const { panel, writes } = await fixture(page, true)
  await panel.getByRole('combobox', { name: 'Selection for application', exact: true }).selectOption('missing')
  await panel.getByLabel('Withdrawal reason', { exact: true }).fill('Producer withdrew the obsolete input')
  await panel.getByRole('button', { name: 'Preview exact assembly', exact: true }).click()
  await expect(panel).toContainText('Missing required parts: application')
  const body = writes.find(write => write.path.endsWith('/assembly-preview'))!.body
  expect(body).toMatchObject({ withdrawn_parts: ['application'], withdrawal_reason: 'Producer withdrew the obsolete input', parts: [{ part_id: 'application', state: null, required: true }] })
  await panel.getByRole('button', { name: 'Discard plan and inspect again', exact: true }).click()
  await panel.getByRole('button', { name: 'Inspect assembly target', exact: true }).click()
  await panel.getByRole('checkbox', { name: 'Required application', exact: true }).uncheck()
  await panel.getByLabel('Requirement change reason', { exact: true }).fill('No longer part of the required delivery scope')
  await panel.getByRole('button', { name: 'Preview exact assembly', exact: true }).click()
  expect(writes.filter(write => write.path.endsWith('/assembly-preview'))[1]!.body.policy_change_reason).toBe('No longer part of the required delivery scope')
})
