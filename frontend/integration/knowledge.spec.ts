import { readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { expect, test, type APIResponse, type Page } from '@playwright/test'

async function json(response: APIResponse) {
  expect(response.ok(), await response.text()).toBeTruthy()
  return response.json()
}
async function login(page: Page, persona: string) {
  await json(await page.request.post('/api/v2/playground/login', { data: { persona } }))
  const me = await json(await page.request.get('/api/v2/me'))
  expect(me.playground, 'Native integration tests require an isolated playground').toBe(true)
  const token = (await page.context().cookies()).find(cookie => cookie.name === 'dtvp_csrf')?.value
  expect(token).toBeTruthy()
  return { 'X-CSRF-Token': token! }
}

test('real native intake, assessment, independent review and coordinator publication retain source and version scope', async ({ page }) => {
  test.setTimeout(120_000)
  const headers = await login(page, 'administrator')
  const teams = await json(await page.request.get('/api/v2/workspaces'))
  const team = teams.find((value: { name: string }) => value.name === 'Platform').id
  const project = await json(await page.request.post('/api/v2/projects', {
    headers, data: { workspace_id: team, name: `[SYNTHETIC] Native browser integration ${randomUUID()}` },
  }))
  const base = `/api/v3/projects/${project.id}`
  const original = readFileSync(new URL('../../playground/fixtures/release.cdx.json', import.meta.url))
  const changed = JSON.parse(original.toString())
  changed.components = changed.components.filter((component: { 'bom-ref': string }) => component['bom-ref'] !== 'utility')
  changed.dependencies = changed.dependencies.filter((edge: { ref: string }) => edge.ref !== 'utility').map((edge: { ref: string; dependsOn: string[] }) => ({ ...edge, dependsOn: edge.dependsOn.filter(ref => ref !== 'utility') }))
  const raws = [original, Buffer.from(`${JSON.stringify(changed, null, 2)}\n`)]
  const versions = ['7.1.1', '7.1.2'], states: Record<string, string> = {}
  for (const [index, version] of versions.entries()) {
    const receipt = await json(await page.request.post(`${base}/versions/${version}/files`, {
      headers,
      multipart: {
        metadata: JSON.stringify({ request_id: randomUUID(), expected: null, predecessor: index ? states['7.1.1'] : null, source: 'synthetic:browser-integration', build_number: 1, occurred_at: new Date().toISOString(), completeness: 'complete', context: { collector: 'DTVP browser integration', target: 'synthetic-only', limitations: ['Synthetic test input, not real composition or vulnerability analysis.'] } }),
        file: { name: `synthetic-${version}.cdx.json`, mimeType: 'application/json', buffer: raws[index]! },
      },
    }))
    expect(receipt.committed).toBe(true); expect(receipt.projection).toBe('current')
    states[version] = receipt.updates[0].target
  }
  const ownership = await json(await page.request.get(`${base}/ownership`))
  await json(await page.request.put(`${base}/ownership`, {
    headers, data: { request_id: randomUUID(), expected_policy: ownership.policy_state, expected_versions: ownership.versions, rules: [{ selector: '*', team_id: team }], context_roots: {} },
  }))
  const workspace = async (version = '7.1.1') => json(await page.request.get(`${base}/versions/${version}/workspace`))
  const first = await workspace(), second = await workspace('7.1.2')
  const delta = await json(await page.request.get(`${base}/compare?before=${first.state}&after=${second.state}`))
  expect(delta.changes.inventory.removed).toContain('component:ref:utility')
  const visit = async (persona: string) => {
    await login(page, persona)
    await page.goto(`/?page=Knowledge&k_project=${project.id}&k_version=7.1.1`)
    await expect(page.getByRole('button', { name: 'CVE-2099-20001', exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'CVE-2099-20001', exact: true }).click()
    return page.getByRole('region', { name: 'Context finding detail' })
  }
  let detail = await visit('analyst')
  await detail.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'assessment', exact: true }).click()
  await detail.getByRole('combobox', { name: 'Applicability', exact: true }).selectOption('affected')
  await detail.getByLabel('Reason and evidence', { exact: true }).fill('Synthetic browser integration: reviewed the declared deployment context.')
  await detail.getByRole('button', { name: 'Submit assessment', exact: true }).click()
  await expect.poll(async () => (await workspace()).items.find((row: any) => row.vulnerability_id === 'CVE-2099-20001').coverage.status).toBe('submitted')
  expect((await workspace()).items.find((row: any) => row.vulnerability_id === 'CVE-2099-20001').published_score).toBeNull()

  detail = await visit('reviewer')
  await detail.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'review', exact: true }).click()
  await detail.getByLabel('Review rationale', { exact: true }).fill('Synthetic independent review of the exact assessment and context.')
  await detail.getByRole('checkbox', { name: 'I checked the evidence, applicability and context of this assessment.', exact: true }).check()
  await detail.getByRole('button', { name: 'Approve assessment', exact: true }).click()
  await expect.poll(async () => (await workspace()).items.find((row: any) => row.vulnerability_id === 'CVE-2099-20001').coverage.status).toBe('approved')

  detail = await visit('coordinator')
  await detail.getByRole('navigation', { name: 'Assessment workflow' }).getByRole('button', { name: 'scoring', exact: true }).click()
  const score = detail.getByRole('form', { name: 'Coordinator rescoring' })
  const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
  await score.getByRole('combobox', { name: 'Source Base vector', exact: true }).selectOption(vector)
  await score.getByText('Contextual vector', { exact: true }).click()
  await score.getByLabel('Proposed contextual vector', { exact: true }).fill(`${vector}/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:N/MA:N`)
  await score.getByLabel('Scoring rationale', { exact: true }).fill('Synthetic contextual scoring after independent team review; not a real assessment.')
  await score.getByRole('button', { name: 'Preview contextual score', exact: true }).click()
  await expect(score.getByText('Preview ready. Required reviews are current.', { exact: true })).toBeVisible()
  await score.getByRole('button', { name: 'Publish contextual score', exact: true }).click()
  await expect.poll(async () => (await workspace()).items.find((row: any) => row.vulnerability_id === 'CVE-2099-20001').published_score?.current).toBe(true)
  const current = await workspace(), focal = current.items.find((row: any) => row.vulnerability_id === 'CVE-2099-20001')
  expect(focal.published_score.score).toBe(0)
  expect(focal.source_ratings.some((rating: any) => rating.score === 9.8 && rating.vector === vector)).toBe(true)
  expect(current.items.find((row: any) => row.vulnerability_id === 'CVE-2099-20002').coverage.status).toBe('unassessed')
  const parallel = await workspace('7.1.2')
  expect(parallel.items).toHaveLength(2)
  expect(parallel.items.some((row: any) => row.vulnerability_id === 'CVE-2099-20001')).toBe(true)
  expect(parallel.items.every((row: any) => row.coverage.status === 'unassessed')).toBe(true)
  const retained = await page.request.get(`${base}/states/${current.state}/source`)
  expect(retained.ok()).toBe(true); expect(await retained.body()).toEqual(original)
  const quality = await json(await page.request.get(`${base}/states/${current.state}/input-quality?limit=1`))
  expect(quality.statistics.inventory_components.components).toBe(3)
  expect(quality.sources[0].coverage_verification).toBe('not_verified')
  expect(quality.report_digest).toMatch(/^[a-f0-9]{64}$/)
})
