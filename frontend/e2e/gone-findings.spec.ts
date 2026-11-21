import { test, expect } from '@playwright/test';
import { mockGroupedVulnTask } from './helpers/grouped-task';

// Findings Dependency-Track no longer reports, shown on the project view.
// Synthetic data only.

const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

const finding = (overrides: Record<string, unknown>) => ({
    component_uuid: 'c-old', component_name: 'lib-a', component_version: '1.0',
    component_purl: 'pkg:npm/lib-a@1.0', vulnerability_uuid: 'v-1', vuln_id: 'CVE-2026-1',
    reason: 'replaced', gone_at: '2026-11-20T10:00:00+00:00', last_seen_at: '2026-11-19T10:00:00+00:00',
    carry_over: null, successor: null, acknowledged_by: null, acknowledged_at: null, needs_attention: false,
    assessment: { sync_status: 'inactive', state: 'NOT_AFFECTED', revision: 1 },
    ...overrides,
});

// One finding needs attention (its assessments differ, nothing carried);
// the carried-over and the removed one are informational.
const goneFindings = (acknowledgedBy: string | null = null) => ({
    name: 'TestProject',
    versions: [
        {
            version: '1.0',
            project_uuid: 'p1',
            last_read: {
                read_at: '2026-11-20T10:00:00+00:00',
                went: { replaced: 2, component_removed: 1 },
                returned: 0,
                carried_over: 1,
                not_carried: 1,
            },
            gone: { replaced: 2, component_removed: 1 },
            findings: [
                finding({
                    carry_over: 'carried',
                    successor: { component_uuid: 'c-new', component_name: 'lib-a', component_version: '1.1' },
                    assessment: { sync_status: 'superseded', state: 'NOT_AFFECTED', revision: 0 },
                }),
                finding({
                    component_uuid: 'c-gone', component_name: 'lib-b', component_version: '2.0',
                    component_purl: null, vulnerability_uuid: 'v-2', vuln_id: 'CVE-2026-2',
                    reason: 'component_removed', last_seen_at: null,
                    assessment: { sync_status: 'inactive', state: 'EXPLOITABLE', revision: 2 },
                }),
                finding({
                    component_uuid: 'c-twice', component_name: 'lib-c', component_version: '3.0',
                    component_purl: 'pkg:npm/lib-c@3.0', vulnerability_uuid: 'v-3', vuln_id: 'CVE-2026-3',
                    carry_over: 'conflict',
                    successor: { component_uuid: 'c-three', component_name: 'lib-c', component_version: '3.1' },
                    acknowledged_by: acknowledgedBy,
                    acknowledged_at: acknowledgedBy ? '2026-11-21T08:00:00+00:00' : null,
                    needs_attention: !acknowledgedBy,
                }),
            ],
        },
        {
            version: '1.1',
            project_uuid: 'p2',
            last_read: {
                read_at: '2026-11-20T10:05:00+00:00',
                went: {},
                returned: 0,
                carried_over: 0,
                not_carried: 0,
            },
            gone: {},
            findings: [],
        },
    ],
});

test.describe('Gone findings', () => {
    let role = 'ANALYST';
    let acknowledgedBy: string | null = null;
    let acknowledgements: unknown[] = [];

    test.beforeEach(async ({ page }) => {
        role = 'ANALYST';
        acknowledgedBy = null;
        acknowledgements = [];
        await page.route('**/auth/me', route => route.fulfill(json({ username: 'testuser', role })));
        await page.route('**/api/version', route => route.fulfill(json({ version: '1.0.0', build: 'test' })));
        await page.route('**/api/cache-status', route => route.fulfill(json({
            fully_cached: true, last_refreshed_at: new Date().toISOString(), projects: 1, active_projects: 1,
            cached_findings: 1, cached_boms: 1, cached_analyses: 0, pending_updates: 0,
        })));
        await page.route('**/api/projects?name=*', route => route.fulfill(json([
            { name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' },
            { name: 'TestProject', uuid: 'p2', version: '1.1', classifier: 'APPLICATION' },
        ])));
        await page.route('**/api/tasks/group-vulns*', route => route.fulfill(json({ task_id: 'task-gone' })));
        await mockGroupedVulnTask(page, { taskId: 'task-gone', groups: [] });
        await page.route('**/api/settings/mapping', route => route.fulfill(json({})));
        await page.route('**/api/settings/rescore-rules', route => route.fulfill(json({ transitions: [] })));
        await page.route('**/api/projects/*/tmrescore/proposals', route => route.fulfill(json({
            project_name: 'TestProject', session_id: '', scope: 'merged_versions',
            latest_version: '1.1', analyzed_versions: [], proposals: {},
        })));
        await page.route('**/api/gone-findings?*', route => route.fulfill(json(goneFindings(acknowledgedBy))));
        await page.route('**/api/gone-findings/acknowledge', async route => {
            const body = route.request().postDataJSON();
            acknowledgements.push(body);
            acknowledgedBy = body.acknowledged === false ? null : 'testuser';
            await route.fulfill(json({ changed: body.findings.length }));
        });
        await page.addInitScript(() => {
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
        });
    });

    test('counts what needs attention; analysts see everything but cannot acknowledge', async ({ page }) => {
        await page.goto('/project/TestProject');

        const button = page.getByTestId('gone-findings-button');
        await expect(button).toBeEnabled({ timeout: 20000 });
        await expect(page.getByTestId('gone-findings-count')).toHaveText('1');
        await expect(page.getByTestId('gone-findings-panel')).toHaveCount(0);

        await button.click();
        const panel = page.getByTestId('gone-findings-panel');
        await expect(panel).toBeVisible();
        const rows = panel.getByTestId('gone-finding');
        await expect(rows).toHaveCount(1);
        await expect(rows.first()).toContainText('CVE-2026-3');
        await expect(rows.first()).toContainText('Assessments differ, not carried');
        await expect(panel.getByTestId('gone-finding-acknowledge')).toHaveCount(0);
        await expect(panel).toContainText('Last read');

        await panel.getByTestId('gone-findings-view-all').click();
        await expect(rows).toHaveCount(3);
        await expect(rows.filter({ hasText: 'CVE-2026-1' })).toContainText('Replaced by lib-a@1.1');
        await expect(rows.filter({ hasText: 'CVE-2026-2' })).toContainText('Component removed');
        await expect(rows.filter({ hasText: 'CVE-2026-2' })).toContainText('EXPLOITABLE · inactive');

        await page.keyboard.press('Escape');
        await expect(panel).toHaveCount(0);
    });

    test('a reviewer acknowledges for everyone and can withdraw it', async ({ page }) => {
        role = 'REVIEWER';
        await page.goto('/project/TestProject');

        const button = page.getByTestId('gone-findings-button');
        await expect(button).toBeEnabled({ timeout: 20000 });
        await button.click();
        const panel = page.getByTestId('gone-findings-panel');
        await panel.getByTestId('gone-finding-acknowledge').click();

        await expect(page.getByTestId('gone-findings-count')).toHaveText('0');
        await expect(panel.getByTestId('gone-finding')).toHaveCount(0);
        expect(acknowledgements).toEqual([{
            project_uuid: 'p1',
            findings: [{ component_uuid: 'c-twice', vulnerability_uuid: 'v-3' }],
            acknowledged: true,
        }]);

        await panel.getByTestId('gone-findings-view-all').click();
        await panel.getByTestId('gone-findings-show-acknowledged').check();
        await expect(panel.getByTestId('gone-finding-acknowledged')).toBeVisible();
        await panel.getByTestId('gone-finding-withdraw').click();
        await expect(page.getByTestId('gone-findings-count')).toHaveText('1');
    });
});
