import { expect, test, type Page } from '@playwright/test'

const firstState = 'a'.repeat(64), updatedState = 'b'.repeat(64)
async function fixture(page: Page) {
  const reads: { path: string; query: URLSearchParams }[] = [], mutations: string[] = []
  let state = firstState, fail = false
  const record = (identifier: string) => ({ assessment_id: `assessment-${identifier}`, revision: 'f'.repeat(64), availability: 'absent', targets: [{ version: '7.1.1', context_id: 'context', vulnerability_id: identifier, team_id: 'team-a', lineage: { coordinate: 'pkg:generic/example/library' } }], assessment: { revision: 'f'.repeat(64), stage: 'submitted', payload: { state: 'not_affected', justification: 'code_not_reachable', rationale: 'Deployment evidence excludes this path. Retained after the component disappeared.', author_id: 'historical-author', targets: [{ version: '7.1.1', context_id: 'context', vulnerability_id: identifier, team_id: 'team-a' }] } } })
  await page.route('**/api/**', async route => {
    const target = new URL(route.request().url()), path = target.pathname
    if (route.request().method() !== 'GET') { mutations.push(path); return route.fulfill({ json: {} }) }
    let result: unknown = { items: [], next_cursor: null }
    if (path === '/api/v2/me') result = { id: 'reader', name: 'Reader', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team-a', name: 'Platform', capabilities: ['read'] }] }
    else if (path === '/api/v2/catalog/projects') result = { items: [{ id: 'retained-project', name: 'Retained product', workspace_id: 'team-a', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state, project_id: 'retained-project', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0, retained_absent_assessments: 41 } }
    else if (path.endsWith('/retained-assessments')) {
      reads.push({ path, query: new URLSearchParams(target.search) })
      if (fail) return route.fulfill({ status: 503, json: { detail: 'Historical source temporarily unavailable' } })
      const scoped = target.searchParams.has('team_id'), later = target.searchParams.get('offset') === '20'
      result = { state: path.split('/states/')[1]?.split('/')[0], version: '7.1.1', scope: 'recorded_targets_not_current_approval', items: [record(later ? 'CVE-2099-20002' : 'CVE-2099-20001')], total: scoped ? 1 : 41, next_offset: scoped || later ? null : 20 }
    }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'Retained product' }).click()
  return { reads, mutations, advance: () => { state = updatedState }, fail: (value: boolean) => { fail = value } }
}

test('absent assessments remain collapsed and show recorded reasons without implying current approval', async ({ page }) => {
  const state = await fixture(page)
  const heading = page.getByText('Retained assessments for absent findings', { exact: true })
  await expect(heading).toBeVisible()
  expect(state.reads).toHaveLength(0)
  await heading.click()
  const retained = page.getByLabel('Retained absent assessments')
  await expect(retained.getByLabel('Retained assessment total')).toHaveText('41 retained assessments in this scope')
  await expect(retained).toContainText('CVE-2099-20001')
  await expect(retained).toContainText('Recorded not affected · submitted')
  await expect(retained).toContainText('Vulnerable code cannot be reached')
  await expect(retained).toContainText('Recorded team team-a')
  await expect(retained).toContainText('do not establish a current approval')
  await expect(retained.locator('pre')).not.toBeVisible()
  await retained.getByText('Recorded scope and full assessment', { exact: true }).click()
  await expect(retained.locator('pre')).toContainText('historical-author')
  await expect(retained.getByRole('button', { name: /approve|publish/i })).toHaveCount(0)
  expect(state.reads[0]?.query.get('absent_only')).toBe('true')
  expect(state.reads[0]?.query.get('limit')).toBe('20')
  expect(state.mutations).toHaveLength(0)
})

test('retained pagination stays pinned and team or state changes restart the server scope', async ({ page }) => {
  const state = await fixture(page)
  await page.getByText('Retained assessments for absent findings', { exact: true }).click()
  const retained = page.getByLabel('Retained absent assessments')
  await retained.getByRole('button', { name: 'Next retained assessments', exact: true }).click()
  await expect(retained).toContainText('CVE-2099-20002')
  await expect(retained.getByLabel('Retained assessment total')).toContainText('41')
  expect(state.reads.map(read => [read.path.includes(firstState), read.query.get('offset')])).toEqual([[true, '0'], [true, '20']])
  await page.getByRole('combobox', { name: 'Responsible team', exact: true }).selectOption('team-a')
  await expect(retained.getByLabel('Retained assessment total')).toHaveText('1 retained assessments in this scope')
  expect(state.reads.at(-1)?.query.get('team_id')).toBe('team-a')
  expect(state.reads.at(-1)?.query.get('offset')).toBe('0')
  state.advance()
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await expect.poll(() => state.reads.at(-1)?.path.includes(updatedState)).toBe(true)
  expect(state.reads.at(-1)?.query.get('offset')).toBe('0')
  expect(state.mutations).toHaveLength(0)
})

test('unavailable retained evidence reports an error and supports a bounded retry on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const state = await fixture(page)
  state.fail(true)
  await page.getByText('Retained assessments for absent findings', { exact: true }).click()
  const retained = page.getByLabel('Retained absent assessments')
  await expect(retained.getByRole('alert')).toHaveText('Historical source temporarily unavailable')
  await expect(retained.getByLabel('Retained assessment total')).not.toBeVisible()
  state.fail(false)
  await retained.getByRole('button', { name: 'Retry retained assessments', exact: true }).click()
  await expect(retained).toContainText('CVE-2099-20001')
  const bounds = await retained.boundingBox()
  expect(bounds?.width).toBeLessThanOrEqual(390)
  expect(state.reads).toHaveLength(2)
})
