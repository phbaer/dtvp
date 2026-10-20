import { openNativeTools, openProductView, openDisclosure } from './nativeTools'
import { createHash } from 'node:crypto'
import { expect, test, type Page } from '@playwright/test'
const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex')
const source = Buffer.from('{ "bomFormat":"CycloneDX", "specVersion":"1.6", "version":1 }\n')
const signature = Buffer.from('header.payload.signature')
const state = 'a'.repeat(64), policy = 'b'.repeat(64)
async function fixture(page: Page, playground = false) {
  const checks: { path: string; body: Buffer | null }[] = []
  let wrong = false, delay = false, released = () => {}, actor = 'actor'
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/v1/playground/personas') return route.fulfill({ json: playground ? [{ id: 'analyst', name: 'Analyst' }, { id: 'reviewer', name: 'Reviewer' }] : [] })
    if (path === '/api/v1/playground/login') { actor = 'reviewer'; return route.fulfill({ json: {} }) }
    if (path.endsWith('/schema-validation')) {
      checks.push({ path, body: route.request().postDataBuffer() })
      const body = route.request().postDataJSON()
      if (delay) await new Promise<void>(resolve => { released = resolve })
      return route.fulfill({ json: { format: 'dtvp.official-schema-validation/1', committed: false, valid: true, validation_profile: body.validation_profile, document_sha256: sha(JSON.stringify(body.document)), report_digest: 'c'.repeat(64), diagnostics: [], limitations: ['Schema only; signature verification not performed.'] } }).catch(() => {})
    }
    if (path.endsWith('/signature-policy')) {
      checks.push({ path, body: null })
      return route.fulfill({ json: { project_id: 'product', trust_policy_sha256: policy, keys: [{ subject: 'Supplier A', key_id: 'key-1', algorithm: 'ES256', public_key_thumbprint: 'thumbprint' }] } })
    }
    if (path.endsWith('/signature-verification')) {
      checks.push({ path, body: route.request().postDataBuffer() })
      return route.fulfill({ json: { format: 'dtvp.artifact-signature-verification/1', committed: false, project_id: 'product', artifact_sha256: wrong ? 'f'.repeat(64) : sha(source), expected_artifact_sha256: sha(source), compact_jws_sha256: sha(signature), trust_policy_sha256: policy, verified: true, configured_signer_subject: 'Supplier A', report_digest: 'c'.repeat(64), diagnostic: 'signature_verified', limitations: ['Configured key policy only; no applicability or approval.'] } })
    }
    let result: unknown = { items: [], capabilities: [], next_cursor: null }
    if (path === '/api/v1/me') result = { id: actor, name: actor === 'actor' ? 'Analyst' : 'Reviewer', org_admin: false, playground, agentyzer: { enabled: false }, workspaces: [{ id: 'team', name: 'Platform', capabilities: ['read'] }] }
    else if (path === '/api/v1/catalog/projects') result = { items: [{ id: 'product', name: 'Product', workspace_id: 'team', capabilities: ['read'] }], next_cursor: null }
    else if (path.endsWith('/versions')) result = { items: [{ version: '7.1.1', state }] }
    else if (path.endsWith('/workspace')) result = { state, project_id: 'product', version: '7.1.1', items: [], next_offset: null, statistics: { totals: { context_findings: 0, unique_vulnerabilities: 0 }, by_status: {}, by_team: {}, severity: {}, recorded: 0, submitted: 0, approved: 0 } }
    else if (path.endsWith('/evidence')) result = { evidence_state: null, versions: { '7.1.1': state }, total: 0, documents: [], next_offset: null, capabilities: ['import'] }
    await route.fulfill({ json: result })
  })
  await page.goto('/?page=Review'); await openNativeTools(page)
  await page.getByRole('button', { name: 'Product scope', exact: false }).click()
  await page.getByRole('option', { name: 'Product', exact: true }).click()
  await openProductView(page, 'Imports')
  await openDisclosure(page.getByText('VDR, VEX and advisory evidence files', { exact: true }))
  const tool = page.getByLabel('Read-only evidence validation', { exact: true })
  return { tool, checks, mismatch: () => { wrong = true }, delay: () => { delay = true }, release: () => released() }
}
async function open(page: Page) { await page.getByText('Optional schema and signature checks', { exact: true }).click() }
async function chooseSource(tool: ReturnType<Page['getByLabel']>) { await tool.getByLabel('Source artifact for validation', { exact: true }).setInputFiles({ name: 'source.json', mimeType: 'application/json', buffer: source }) }

test('optional schema check stays collapsed, read-only and scoped to captured inputs', async ({ page }) => {
  const { tool, checks } = await fixture(page)
  await expect(tool).toBeHidden(); expect(checks).toHaveLength(0)
  await open(page); await chooseSource(tool)
  await tool.getByRole('button', { name: 'Run read-only validation' }).click()
  await expect(tool.getByLabel('Evidence validation result')).toContainText('Schema check passed')
  await expect(tool.getByLabel('Source artifact for validation', { exact: true })).toBeDisabled()
  await tool.getByText('Captured inputs, scope and complete report', { exact: true }).click()
  await expect(tool).toContainText(sha(source)); await expect(tool).toContainText('server-canonical JSON')
  expect(checks).toHaveLength(1); expect(checks[0]!.path).toMatch(/\/projects\/product\/evidence\/schema-validation$/)
  expect(JSON.parse(checks[0]!.body!.toString()).validation_profile).toBe('cyclonedx-1.6-json-schema/1')
  await tool.getByRole('button', { name: 'Discard validation inputs and report' }).click()
  await expect(tool.getByLabel('Evidence validation result')).toHaveCount(0)
  await expect(tool.getByLabel('Source artifact for validation', { exact: true })).toBeEnabled()
})

test('JWS checks pin exact uploaded bytes, configured subject and policy without publication', async ({ page }) => {
  const { tool, checks } = await fixture(page)
  await open(page); await tool.getByRole('combobox', { name: 'Validation check', exact: true }).selectOption('signature')
  await tool.getByRole('button', { name: 'Load trusted signer policy' }).click()
  await expect(tool.getByLabel('Deployment-trusted signer')).toHaveValue('Supplier A')
  await chooseSource(tool)
  await tool.getByLabel('Compact JWS signature file').setInputFiles({ name: 'source.jws', mimeType: 'text/plain', buffer: signature })
  await tool.getByRole('button', { name: 'Run read-only validation' }).click()
  await expect(tool.getByLabel('Evidence validation result')).toContainText('Signature verified under configured policy')
  await expect(tool).toContainText('no applicability or approval')
  const body = checks.at(-1)!.body!.toString()
  expect(body).toContain(source.toString()); expect(body).toContain(signature.toString()); expect(body).toContain(policy); expect(body).toContain(sha(source))
  expect(checks.map(item => item.path.split('/').at(-1))).toEqual(['signature-policy', 'signature-verification'])
})

test('mismatched signature report is withheld and frozen input must be discarded explicitly', async ({ page }) => {
  const { tool, mismatch } = await fixture(page)
  await open(page); await tool.getByRole('combobox', { name: 'Validation check', exact: true }).selectOption('signature')
  await tool.getByRole('button', { name: 'Load trusted signer policy' }).click()
  await expect(tool.getByLabel('Deployment-trusted signer')).toHaveValue('Supplier A')
  await chooseSource(tool); await tool.getByLabel('Compact JWS signature file').setInputFiles({ name: 'source.jws', buffer: signature })
  mismatch(); await tool.getByRole('button', { name: 'Run read-only validation' }).click()
  await expect(tool.getByRole('alert')).toContainText('differs from the captured bytes')
  await expect(tool.getByLabel('Evidence validation result')).toHaveCount(0)
  await expect(tool.getByRole('button', { name: 'Repeat captured validation' })).toBeEnabled()
})

test('cancel discards late read-only results and releases competing source controls', async ({ page }) => {
  const { tool, checks, delay, release } = await fixture(page)
  await open(page); await chooseSource(tool); delay()
  await tool.getByRole('button', { name: 'Run read-only validation' }).click()
  await expect.poll(() => checks.length).toBe(1)
  await expect(page.getByRole('button', { name: 'Refresh evidence registry and pins' })).toBeDisabled()
  await tool.getByRole('button', { name: 'Cancel and discard validation' }).click(); release()
  await expect(tool.getByLabel('Evidence validation result')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Refresh evidence registry and pins' })).toBeEnabled()
})

test('validation controls fit a narrow screen', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const { tool } = await fixture(page); await open(page)
  await expect(tool).toContainText('Does not import, approve or change evidence trust')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})


test('actor change unmounts captured validation and rejects late prior-actor reports', async ({ page }) => {
  const { tool, checks, delay, release } = await fixture(page, true)
  await open(page); await chooseSource(tool); delay()
  await tool.getByRole('button', { name: 'Run read-only validation' }).click()
  await expect.poll(() => checks.length).toBe(1)
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('reviewer')
  await expect(page.getByRole('combobox', { name: 'Persona', exact: true })).toHaveValue('reviewer')
  release()
  await expect(page.getByLabel('Evidence validation result')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Product scope', exact: false })).toBeEnabled()
})
