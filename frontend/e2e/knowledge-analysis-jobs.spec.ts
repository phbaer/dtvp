import { expect, test, type Page } from '@playwright/test'

const stateSha = 'a'.repeat(64), nextState = 'b'.repeat(64), contextId = 'c'.repeat(64)
const vulnerability = 'CVE-2099-1234'
const job = (id: string, status = 'submission_unknown', capabilities: string[] = []) => ({ id, status, version: '7.1.2', context_id: contextId, vulnerability_id: vulnerability, state: stateSha, attempts: 1, error: status === 'submission_unknown' ? 'Remote submission response was lost' : '', result: {}, created_at: '2026-10-15T12:00:00Z', requires_explicit_reconciliation: status === 'submission_unknown', capabilities })

async function fixture(page: Page, options: { readonly?: boolean; createResponses?: number[]; knownFailed?: boolean } = {}) {
  const reads: { path: string; query: URLSearchParams }[] = [], writes: { path: string; body: Record<string, unknown> }[] = []
  let state = stateSha, creates = 0
  const row = { id: 'finding', context_id: contextId, vulnerability_id: vulnerability, component: { name: 'Parser', version: '2.0', purl: 'pkg:generic/parser@2.0' }, context: { root_ref: 'application', component_ref: 'parser', team_id: 'team', status: 'resolved' }, description: 'Advisory.', source_ratings: [], coverage: { status: 'unassessed', assessment: null }, published_score: null, capabilities: options.readonly ? [] : ['assess'] }
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname
    if (request.method() !== 'GET') {
      writes.push({ path, body: request.postDataJSON() })
      if (path.endsWith('/agentyzer-input')) return route.fulfill({ json: { ready_to_submit: true, request: { component_name: 'repository', source_commit: 'd'.repeat(40) }, receipt: { state, request_sha256: 'e'.repeat(64) }, coverage: { reasons: [], limitations: ['Repository authorization is checked separately.'], source_verification: 'producer_declared_only', repository_authorization: 'not_checked' } } })
      if (path.endsWith('/analysis-jobs')) {
        const status = options.createResponses?.[creates++] || 202
        if (status !== 202) return route.fulfill({ status, json: { detail: status === 409 ? 'Baseline changed; retain guidance and reload before a new request' : 'Request outcome uncertain; retry the identical request ID' } })
        return route.fulfill({ status, json: job('requested-job', 'queued', ['cancel']) })
      }
      if (path.endsWith('/retry')) return route.fulfill({ status: 202, json: job('known-job', 'queued', ['cancel']) })
      if (path.endsWith('/cancel')) return route.fulfill({ json: job('known-job', 'cancelled') })
      return route.fulfill({ status: 403, json: { detail: 'Unexpected mutation' } })
    }
    let result: unknown = { items: [], next_cursor: null }
    if (path.endsWith('/analysis-jobs')) {
      reads.push({ path, query: new URLSearchParams(url.search) })
      const later = url.searchParams.get('offset') === '20'
      result = { items: [options.knownFailed ? job('known-job', 'failed', options.readonly ? [] : ['retry']) : job(later ? 'older-job' : 'unknown-job')], next_offset: later ? null : 20, capabilities: options.readonly ? [] : ['submit'] }
    } else if (path.includes('/analysis-jobs/')) { reads.push({ path, query: new URLSearchParams(url.search) }); result = job(path.split('/').at(-1)!) }
    else if (path === '/api/v2/me') result = { id: 'reader', name: 'Reader', org_admin: false, playground: false, agentyzer: { enabled: false, mode: 'disabled' }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read'] }] }
    else if (path === '/api/v2/catalog/projects') result = { items: [{ id: 'product', name: 'Job product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.2', state }], next_offset: null }
    else if (path.endsWith('/workspace')) result = { state, project_id: 'product', version: '7.1.2', items: [row], next_offset: null, statistics: { totals: { context_findings: 1, unique_vulnerabilities: 1 }, by_status: {}, by_team: { team: 1 }, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.includes('/workspace/')) result = { ...row, state }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Knowledge')
  await page.getByRole('button', { name: 'Knowledge product', exact: false }).click()
  await page.getByRole('option', { name: 'Job product', exact: true }).click()
  await page.getByRole('button', { name: vulnerability, exact: true }).click()
  await page.getByText('Specialist inputs and CPE candidates', { exact: true }).click()
  await page.getByText('Agentyzer repository input', { exact: true }).click()
  const jobs = page.locator('.analysis-jobs')
  return { reads, writes, jobs, advance: () => { state = nextState } }
}

async function load(page: Page) {
  await page.getByText('Agentyzer analysis jobs', { exact: true }).click()
  await page.getByRole('button', { name: 'Load analysis jobs', exact: true }).click()
}

test('readers see bounded contextual jobs and unknown submissions never expose an automatic retry', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const state = await fixture(page, { readonly: true })
  expect(state.reads).toHaveLength(0)
  await load(page)
  await expect(state.jobs).toContainText('Submission outcome is unknown.')
  await expect(state.jobs.getByRole('form')).toHaveCount(0)
  await expect(state.jobs.getByRole('button', { name: /retry|cancel/i })).toHaveCount(0)
  expect(state.reads[0]?.query.get('context_id')).toBe(contextId)
  expect(state.reads[0]?.query.get('vulnerability_id')).toBe(vulnerability)
  expect(state.reads[0]?.query.get('limit')).toBe('20')
  await state.jobs.getByRole('button', { name: 'Next jobs', exact: true }).click()
  await expect(state.jobs.getByRole('article', { name: 'Analysis job older-job', exact: true })).toBeVisible()
  expect(state.reads.at(-1)?.query.get('offset')).toBe('20')
  await state.jobs.getByRole('button', { name: 'Refresh job status', exact: true }).click()
  expect(state.reads.at(-1)?.path).toBe('/api/v3/projects/product/analysis-jobs/older-job')
  expect(state.writes).toHaveLength(0)
  expect(await state.jobs.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
})

test('analysis is queued only after explicit qualified input preparation and remains visible on a later jobs page', async ({ page }) => {
  const state = await fixture(page)
  await load(page)
  const form = state.jobs.getByRole('form', { name: 'Request Agentyzer analysis', exact: true })
  await expect(form.getByRole('button', { name: 'Queue Agentyzer analysis', exact: true })).toBeDisabled()
  await page.getByRole('button', { name: 'Prepare Agentyzer input', exact: true }).click()
  await state.jobs.getByRole('button', { name: 'Next jobs', exact: true }).click()
  await form.getByLabel('Analysis guidance (optional)', { exact: true }).fill('Check the parser entry points.')
  await form.getByRole('button', { name: 'Queue Agentyzer analysis', exact: true }).click()
  await expect(state.jobs.getByRole('status')).toContainText('No assessment or approval was created.')
  await expect(state.jobs.getByRole('article', { name: 'Analysis job requested-job', exact: true })).toContainText('Requested job')
  await expect(state.jobs.getByRole('article', { name: 'Analysis job older-job', exact: true })).toBeVisible()
  const create = state.writes.find(write => write.path.endsWith('/analysis-jobs'))!
  expect(create.body).toEqual({ expected: stateSha, context_id: contextId, vulnerability_id: vulnerability, user_guidance: 'Check the parser entry points.', request_id: expect.stringMatching(/^[0-9a-f-]{36}$/) })
  expect(state.writes.map(write => write.path)).toEqual([`/api/v3/projects/product/states/${stateSha}/agentyzer-input`, '/api/v3/projects/product/versions/7.1.2/analysis-jobs'])
  await expect(form.getByRole('button', { name: 'New analysis request', exact: true })).toBeVisible()
})

for (const status of [409, 503]) {
  test(`enqueue ${status} retains guidance and only a manual retry repeats its exact request identity`, async ({ page }) => {
    const state = await fixture(page, { createResponses: [status, 202] })
    await load(page)
    await page.getByRole('button', { name: 'Prepare Agentyzer input', exact: true }).click()
    const form = state.jobs.getByRole('form', { name: 'Request Agentyzer analysis', exact: true })
    await form.getByLabel('Analysis guidance (optional)', { exact: true }).fill('Retain this analysis guidance.')
    await form.getByRole('button', { name: 'Queue Agentyzer analysis', exact: true }).click()
    await expect(form.getByRole('alert')).toContainText(status === 409 ? 'Baseline changed' : 'Request outcome uncertain')
    await expect(form.getByLabel('Analysis guidance (optional)', { exact: true })).toHaveValue('Retain this analysis guidance.')
    expect(state.writes.filter(write => write.path.endsWith('/analysis-jobs'))).toHaveLength(1)
    await form.getByRole('button', { name: 'Queue Agentyzer analysis', exact: true }).click()
    await expect(state.jobs.getByRole('status')).toContainText('Analysis request recorded.')
    const creates = state.writes.filter(write => write.path.endsWith('/analysis-jobs'))
    expect(creates).toHaveLength(2)
    expect(creates[1]?.body).toEqual(creates[0]?.body)
  })
}

test('safe retry and local cancellation appear only through returned job capabilities', async ({ page }) => {
  const state = await fixture(page, { knownFailed: true })
  await load(page)
  await state.jobs.getByRole('button', { name: 'Retry known job', exact: true }).click()
  await expect(state.jobs.getByRole('article')).toContainText('queued')
  await expect(state.jobs).toContainText('does not confirm cancellation at Agentyzer')
  await state.jobs.getByRole('button', { name: 'Cancel DTVP job', exact: true }).click()
  await expect(state.jobs.getByRole('article')).toContainText('cancelled')
  await expect(state.jobs.getByRole('button', { name: /retry|cancel/i })).toHaveCount(0)
  expect(state.writes.map(write => write.path)).toEqual(['/api/v3/projects/product/analysis-jobs/known-job/retry', '/api/v3/projects/product/analysis-jobs/known-job/cancel'])
})

test('a changed input state clears request guidance and requires fresh source preparation', async ({ page }) => {
  const state = await fixture(page)
  await load(page)
  await page.getByRole('button', { name: 'Prepare Agentyzer input', exact: true }).click()
  await state.jobs.getByLabel('Analysis guidance (optional)', { exact: true }).fill('Guidance for the old source state')
  state.advance()
  await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click()
  await page.getByRole('button', { name: vulnerability, exact: true }).click()
  await page.getByText('Specialist inputs and CPE candidates', { exact: true }).click()
  await page.getByText('Agentyzer repository input', { exact: true }).click()
  await load(page)
  await expect(state.jobs.getByLabel('Analysis guidance (optional)', { exact: true })).toBeEmpty()
  await expect(state.jobs.getByRole('button', { name: 'Queue Agentyzer analysis', exact: true })).toBeDisabled()
  expect(state.writes.filter(write => write.path.endsWith('/analysis-jobs'))).toHaveLength(0)
})
