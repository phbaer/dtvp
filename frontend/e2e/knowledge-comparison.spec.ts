import { expect, test, type Page } from '@playwright/test'

const before = 'a'.repeat(64), after = 'b'.repeat(64), historic = 'c'.repeat(64)
async function fixture(page: Page) {
  const requests: URLSearchParams[] = [], historyRequests: URLSearchParams[] = [], mutations: string[] = []
  let fail = false
  await page.route('**/api/**', async route => {
    const request = route.request(), target = new URL(request.url()), path = target.pathname
    if (path.endsWith('/synchronization/preview')) {
      mutations.push(path)
      const body = request.postDataJSON(), next = target.searchParams.get('offset') === '20'
      expect(body).toEqual({ source: before, target: after })
      return route.fulfill({ json: { preview_digest: 'd'.repeat(64), mode: 'two_state', total: 31, next_offset: next ? null : 20, items: [{ id: next ? 'two' : 'one', vulnerability_id: 'CVE-2099-1234', category: 'reusable_content', reasons: ['new_target_review_required'], requires_new_target_review: true }], limitations: ['No software merge is verified.'] } })
    }
    if (request.method() !== 'GET') { mutations.push(path); return route.fulfill({ json: {} }) }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') result = { id: 'reader', name: 'Reader', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [] }
    else if (path === '/api/v2/catalog/projects') result = { items: [{ id: 'comparison-project', name: 'Comparison product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.2', state: after }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state: after, project_id: 'comparison-project', version: '7.1.2', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/refs')) result = { items: [{ kind: 'branch', name: '7.1.1', version: '7.1.1', state: before }, { kind: 'branch', name: '7.1.2', version: '7.1.2', state: after }, { kind: 'tag', name: 'released-7.1.1', version: '7.1.1', state: historic }], next_offset: null }
    else if (path.endsWith('/history')) {
      historyRequests.push(new URLSearchParams(target.search))
      result = { items: [{ state: historic, version: '7.1.1', created_at: '2026-10-14T12:00:00Z', reason: 'Import nightly 41', actor_id: 'pipeline', parents: [] }], next_offset: null }
    } else if (path.endsWith('/compare/details')) {
      requests.push(new URLSearchParams(target.search))
      if (fail) return route.fulfill({ status: 422, json: { detail: 'Comparison states must belong to one product line' } })
      const next = target.searchParams.get('offset') === '25'
      result = {
        project_id: 'comparison-project', before: target.searchParams.get('before'), after: target.searchParams.get('after'), before_version: '7.1.1', after_version: '7.1.2',
        items: next ? [{ category: 'dependency', key: ['server', 'removed-library'], change: 'removed', classifications: ['removed', 'material'], before: { from: 'server', to: 'removed-library' }, after: null }] : [{ category: 'component', key: 'tls', change: 'changed', classifications: ['material'], before: { name: 'TLS library', version: '1.0' }, after: { name: 'TLS library', version: '2.0' } }],
        total: 31, next_offset: next ? null : 25,
        summary: { by_category: { component: 12, dependency: 18, context_finding: 1 }, by_classification: { material: 30, ownership: 1, assessment: 1 } },
        retention: { before: { retained_assessments: 4, retained_absent_assessments: 0 }, after: { retained_assessments: 4, retained_absent_assessments: 2 } },
        limitations: ['Names and PURLs never merge distinct source occurrences.', 'Historical comparison does not change branch heads.'],
      }
    }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'Comparison product' }).click()
  return { requests, historyRequests, mutations, fail: () => { fail = true } }
}

test('comparison stays collapsed and renders backend totals with pinned bounded pages', async ({ page }) => {
  const state = await fixture(page)
  await expect(page.getByLabel('Historical state comparison')).not.toBeVisible()
  expect(state.requests).toHaveLength(0)
  await page.getByText('Compare versions and history', { exact: true }).click()
  const comparison = page.getByLabel('Historical state comparison')
  await expect(comparison.getByRole('combobox', { name: 'Before state', exact: true })).toHaveValue(`branch:7.1.1:${before}`)
  await comparison.getByRole('button', { name: 'Compare states', exact: true }).click()
  await expect(comparison.getByLabel('Comparison totals')).toContainText('31 changes')
  await expect(comparison.getByLabel('Comparison totals')).toContainText('component: 12')
  await expect(comparison.getByLabel('Historical changes')).toContainText('TLS library')
  await expect(comparison.getByText('"version": "1.0"', { exact: false })).not.toBeVisible()
  await comparison.getByText('TLS library', { exact: true }).click()
  await expect(comparison.locator('pre').first()).toContainText('1.0')
  await expect(comparison.locator('pre').nth(1)).toContainText('2.0')
  await comparison.getByRole('button', { name: 'Next changes', exact: true }).click()
  await expect(comparison.getByLabel('Historical changes')).toContainText('server → removed-library')
  await expect(comparison.getByLabel('Comparison totals')).toContainText('31 changes')
  expect(state.requests.map(query => [query.get('before'), query.get('after'), query.get('offset'), query.get('limit')])).toEqual([[before, after, '0', '25'], [before, after, '25', '25']])
  await expect(comparison.getByRole('button', { name: 'Next changes', exact: true })).toBeDisabled()
  await comparison.getByText('Pinned states, classifications and retained assessments', { exact: true }).click()
  await expect(comparison).toContainText('Retained assessments: 4 before → 4 after')
  await expect(comparison).toContainText('Absent targets: 0 before → 2 after')
  await expect(comparison).toContainText('Removed findings do not prove remediation')
  expect(state.mutations).toHaveLength(0)
})

test('release tags and historical imports stay explicit and a changed selection clears results', async ({ page }) => {
  const state = await fixture(page)
  await page.getByText('Compare versions and history', { exact: true }).click()
  const comparison = page.getByLabel('Historical state comparison')
  await comparison.getByRole('combobox', { name: 'Before state', exact: true }).selectOption(`tag:released-7.1.1:${historic}`)
  await comparison.getByRole('button', { name: 'Compare states', exact: true }).click()
  await expect(comparison.getByLabel('Comparison totals')).toBeVisible()
  expect(state.requests[0]?.get('before')).toBe(historic)
  await comparison.getByText('Choose an earlier import or review state', { exact: true }).click()
  await expect(comparison).toContainText('Import nightly 41')
  await comparison.getByLabel('History version (optional)', { exact: true }).fill('7.1.1')
  await comparison.getByRole('button', { name: 'Find history', exact: true }).click()
  await expect.poll(() => state.historyRequests.at(-1)?.get('version')).toBe('7.1.1')
  await comparison.getByRole('button', { name: 'Use 7.1.1 Import nightly 41 as after', exact: true }).click()
  await expect(comparison.getByLabel('Comparison totals')).not.toBeVisible()
  await comparison.getByRole('button', { name: 'Compare states', exact: true }).click()
  await expect(comparison.getByLabel('Comparison totals')).toBeVisible()
  expect(state.requests.at(-1)?.get('after')).toBe(historic)
  expect(state.mutations).toHaveLength(0)
})

test('comparison failures stay visible without inventing changes or overflowing a narrow viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const state = await fixture(page)
  await page.getByText('Compare versions and history', { exact: true }).click()
  const comparison = page.getByLabel('Historical state comparison')
  state.fail()
  await comparison.getByRole('button', { name: 'Compare states', exact: true }).click()
  await expect(comparison.getByRole('alert')).toHaveText('Comparison states must belong to one product line')
  await expect(comparison.getByLabel('Comparison totals')).not.toBeVisible()
  const bounds = await comparison.boundingBox()
  expect(bounds?.width).toBeLessThanOrEqual(390)
  await expect(comparison.getByRole('combobox', { name: 'Before state', exact: true })).toBeVisible()
})


test('assessment reuse is a pinned read-only preview with new target review required', async ({ page }) => {
  const state = await fixture(page)
  await page.getByText('Compare versions and history', { exact: true }).click()
  await page.getByText('Assessment reuse between selected states', { exact: true }).click()
  await page.getByRole('button', { name: 'Preview assessment reuse', exact: true }).click()
  const preview = page.getByRole('region', { name: 'Assessment reuse preview', exact: true })
  await expect(preview).toContainText('31 candidates')
  await preview.getByText('CVE-2099-1234 · reusable content', { exact: true }).click()
  await expect(preview).toContainText('New target coverage requires independent review.')
  await page.getByRole('button', { name: 'Next candidates', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Next candidates', exact: true })).toBeDisabled()
  expect(state.mutations).toEqual(['/api/v3/projects/comparison-project/synchronization/preview', '/api/v3/projects/comparison-project/synchronization/preview'])
  await expect(page.getByRole('button', { name: /apply|merge|approve/i })).toHaveCount(0)
})
