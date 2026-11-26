import { test, expect } from '@playwright/test';
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// The browser tests run against mocked API routes, not a backend, so the
// agent evidence is seeded as the response of the evidence list route. The
// MCP tool that writes it is covered by tests/test_mcp_server.py.
const EVIDENCE = {
    kind: 'agent',
    evidence_id: 'ev_e2e',
    project_name: 'TestProject',
    vuln_id: 'CVE-2026-EVID',
    vuln_ids: ['cve-2026-evid'],
    scope: 'vulnerability',
    targets: [{
        component: 'lib-a',
        component_version: '1.0',
        project_version: '1.0',
        finding_uuid: 'f-a',
        vulnerability_uuid: 'v-1',
    }],
    title: 'Parser entry point is not linked',
    body_markdown: '## Call graph\n\n`parse()` is **never** reached from a request handler.\n\n| File | Line |\n|---|---|\n| server.c | 42 |',
    references: ['https://example.org/commit/abc'],
    suggested_state: 'NOT_AFFECTED',
    suggested_justification: 'CODE_NOT_REACHABLE',
    confidence: 'high',
    author: { username: 'alice', agent_label: 'triage-bot', token_id: 'tok_e2e', authority: 'ANALYST' },
    created_at: '2026-07-06T13:00:00Z',
    withdrawn: null,
    applications: [] as any[],
};

test.describe('Code evidence from agents', () => {
    test.beforeEach(async ({ page }) => {
        page.on('dialog', dialog => dialog.accept());
        await page.route('**/auth/me', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ username: 'testuser', role: 'REVIEWER' }),
        }));
        await page.route('**/api/version', route => route.fulfill({
            status: 200,
            body: JSON.stringify({ version: '1.0.0', build: 'test' }),
        }));
        await page.route('**/api/projects?name=TestProject', route => route.fulfill({
            status: 200,
            body: JSON.stringify([{ name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' }]),
        }));
        await page.route('**/api/tasks/group-vulns*', route => route.fulfill({
            status: 200,
            body: JSON.stringify({ task_id: 'task-evidence' }),
        }));
        await mockGroupedVulnTask(page, {
            taskId: 'task-evidence',
            groups: [{
                id: 'CVE-2026-EVID',
                title: 'Parser overflow',
                description: 'Overflow in the parser.',
                severity: 'HIGH',
                cvss: 8.1,
                tags: ['Security'],
                affected_versions: [{
                    project_name: 'TestProject',
                    project_version: '1.0',
                    project_uuid: 'p1',
                    components: [{
                        project_name: 'TestProject',
                        project_version: '1.0',
                        project_uuid: 'p1',
                        component_name: 'lib-a',
                        dependency_chains: ['lib-a -> vp-est-srv -> TestProject'],
                        component_version: '1.0',
                        component_uuid: 'c-a',
                        finding_uuid: 'f-a',
                        vulnerability_uuid: 'v-1',
                        analysis_state: 'NOT_SET',
                        tags: ['Security'],
                    }],
                }],
            }],
        });
        await page.route('**/api/assessments/details', async route => {
            const body = route.request().postDataJSON();
            await route.fulfill({
                status: 200,
                body: JSON.stringify((body.instances || []).map((inst: any) => ({
                    finding_uuid: inst.finding_uuid,
                    project_uuid: inst.project_uuid,
                    component_uuid: inst.component_uuid,
                    vulnerability_uuid: inst.vulnerability_uuid,
                    analysis: { state: 'NOT_SET', analysisState: 'NOT_SET', isSuppressed: false, analysisDetails: '', analysisComments: [] },
                }))),
            });
        });
        await routeMappingTeams(page, { 'lib-a': 'Security' });
        await page.route('**/api/settings/mapping', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ 'vp-est-srv': 'Security' }),
        }));
        await page.route('**/api/settings/rescore-rules', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ transitions: [] }),
        }));
        await page.route('**/api/projects/*/tmrescore/proposals', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ project_name: 'TestProject', session_id: '', scope: 'merged_versions', latest_version: '1.0', analyzed_versions: [], proposals: {} }),
        }));
        await page.route('**/api/projects/*/vulnerabilities/*/analysis-results*', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: '[]',
        }));
        await page.addInitScript(() => {
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
        });
    });

    test('shows finding-scoped dependency evidence when analysis targets its parent application', async ({ page }) => {
        const evidence = { ...EVIDENCE, scope: 'findings' };
        const requests: URL[] = [];
        await page.route('**/api/projects/*/vulnerabilities/*/code-evidence*', async route => {
            const url = new URL(route.request().url());
            requests.push(url);
            const names = url.searchParams.getAll('component_name');
            const items = names.length === 0 || names.includes('lib-a') ? [evidence] : [];
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ items, withdrawn_count: 0 }) });
        });
        await page.goto('/project/TestProject?lifecycle=OPEN');
        const listCard = page.locator('.vuln-card[data-group-id="CVE-2026-EVID"]');
        await expect(listCard).toBeVisible({ timeout: 30000 });
        await listCard.click();
        const card = page.getByTestId('vuln-detail-inspector').locator('.vuln-card').first();
        await card.getByRole('tab', { name: 'Code Evidence' }).click();
        await expect(card.getByTestId('evidence-group')).toHaveAttribute('data-component', 'lib-a');
        const row = card.locator('[data-testid="evidence-row"][data-id="ev_e2e"]');
        await expect(row).toContainText(evidence.title);
        await row.click();
        await expect(card.getByTestId('evidence-reader').getByRole('heading', { name: 'Call graph' })).toBeVisible();
        expect(requests.length).toBeGreaterThan(0);
        expect(requests.every(url => ![...url.searchParams.keys()].some(key => key.startsWith('component_name')))).toBe(true);
    });

    test('reads agent evidence, uses it in the draft, and marks it used after the save', async ({ page }) => {
        const evidence = { ...EVIDENCE, applications: [] as any[] };
        const evidenceRequests: string[] = [];
        await page.route('**/api/projects/*/vulnerabilities/*/code-evidence*', async route => {
            evidenceRequests.push(route.request().url());
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ items: [evidence], withdrawn_count: 0 }),
            });
        });
        let savedPayload: any = null;
        await page.route('**/api/assessment', async route => {
            savedPayload = route.request().postDataJSON();
            // The server records the use beside the evidence.
            evidence.applications = [{ finding_uuid: 'f-a', status: 'queued', applied_by: 'testuser', applied_at: '2026-07-06T14:00:00Z' }];
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(savedPayload.instances.map((instance: any) => ({
                    status: 'success',
                    uuid: instance.finding_uuid,
                    new_state: savedPayload.state,
                    new_details: '',
                    queued: true,
                    revision: 1,
                }))),
            });
        });

        await page.goto('/project/TestProject?lifecycle=OPEN');
        const listCard = page.locator('.vuln-card[data-group-id="CVE-2026-EVID"]');
        await expect(listCard).toBeVisible({ timeout: 30000 });
        await listCard.click();
        const card = page.getByTestId('vuln-detail-inspector').locator('.vuln-card').first();

        const evidenceTab = card.getByRole('tab', { name: 'Code Evidence' });
        await evidenceTab.click();
        await expect(evidenceTab).toHaveAttribute('aria-selected', 'true');

        const row = card.locator('[data-testid="evidence-row"][data-id="ev_e2e"]');
        await expect(row).toContainText('Agent: triage-bot');
        await expect(row).toContainText('NOT_AFFECTED · CODE_NOT_REACHABLE');
        await expect(row).not.toContainText('Used in assessment');
        await row.click();
        await expect(row).toHaveAttribute('aria-expanded', 'true');

        const reader = card.getByTestId('evidence-reader');
        await expect(reader.getByRole('heading', { name: 'Call graph' })).toBeVisible();
        await expect(reader.locator('table')).toContainText('server.c');
        await expect(reader.getByTestId('evidence-added-by')).toHaveText('alice via token triage-bot (id tok_e2e), analyst authority');
        const applyBox = reader.getByTestId('evidence-apply-box');
        await expect(applyBox).toContainText('Nothing is saved until you save the assessment.');
        await applyBox.getByTestId('evidence-use-suggestion').check();
        await applyBox.getByRole('button', { name: 'Use in assessment draft' }).click();

        const details = card.locator('#analysis-details-textarea');
        await expect(details).toHaveValue(/Code evidence ev_e2e from triage-bot \(alice, 2026-07-06\): Parser entry point is not linked/);
        expect(savedPayload).toBeNull();

        const saveButton = card.getByTestId('assessment-submit-button');
        await expect(saveButton).toBeEnabled({ timeout: 10000 });
        await saveButton.click();
        const submit = page.getByRole('button', { name: 'Submit' }).first();
        if (await submit.isVisible({ timeout: 5000 }).catch(() => false)) await submit.click();

        await expect.poll(() => savedPayload?.code_evidence_ids, { timeout: 10000 }).toEqual(['ev_e2e']);
        expect(savedPayload.state).toBe('NOT_AFFECTED');

        const requestsBefore = evidenceRequests.length;
        await evidenceTab.click();
        await expect.poll(() => evidenceRequests.length, { timeout: 10000 }).toBeGreaterThan(requestsBefore);
        await expect(card.locator('[data-testid="evidence-row"][data-id="ev_e2e"]')).toContainText('Used in assessment');
    });
});
