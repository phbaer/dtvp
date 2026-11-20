import { test, expect } from '@playwright/test';
import { mockGroupedVulnTask } from './helpers/grouped-task';

// Restore team assessments from a Dependency-Track export, with every API
// call mocked: upload, preview with the source id, apply with it.
test.describe('Bulk Changes: restore team assessments from an export', () => {
    const workflow = {
        id: 'team-assessment-restore',
        label: 'Restore Team Assessments From Export',
        description: 'Adds team assessments a Dependency-Track export has and DTVP has in no form, as historical assessments. Changes no state.',
        supports_apply: true,
        supports_document: false,
        requires_source: true,
        source_kind: 'dependency-track-vdr',
        version: 1,
    };

    test.beforeEach(async ({ page }) => {
        await page.route('**/auth/me', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ username: 'rita', role: 'REVIEWER' }),
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
            body: JSON.stringify({ task_id: 'task-restore' }),
        }));
        await mockGroupedVulnTask(page, {
            taskId: 'task-restore',
            groups: [{
                id: 'CVE-2099-0001',
                title: 'Synthetic vulnerability',
                severity: 'HIGH',
                tags: ['TeamA'],
                affected_versions: [{
                    project_name: 'TestProject',
                    project_version: '1.0',
                    project_uuid: 'p1',
                    components: [{
                        component_name: 'lib-a',
                        component_version: '1.0',
                        component_uuid: 'c-1',
                        finding_uuid: 'f-1',
                        vulnerability_uuid: 'v-1',
                        analysis_state: 'NOT_AFFECTED',
                        tags: ['TeamA'],
                    }],
                }],
                list_metadata: { lifecycle: 'ASSESSED' },
            }],
        });
        await page.route('**/api/settings/mapping', route => route.fulfill({
            status: 200, contentType: 'application/json', body: JSON.stringify({}),
        }));
        await page.route('**/api/settings/rescore-rules', route => route.fulfill({
            status: 200, contentType: 'application/json', body: JSON.stringify({ transitions: [] }),
        }));
        await page.addInitScript(() => {
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
        });

        await page.route('**/api/bulk-workflows/summary', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                task_id: 'task-restore',
                workflows: [{ ...workflow, candidate_count: null, summary: {} }],
            }),
        }));
        await page.route('**/api/bulk-workflows/sources', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                source_id: 'source-1',
                entries: 1,
                team_blocks: 2,
                summary: {
                    tool: 'Dependency-Track', tool_version: '4.99.0', spec_version: '1.5',
                    project_uuid: 'p1', project_name: 'TestProject', project_version: '1.0',
                    timestamp: '2030-01-03T00:00:00Z', sha256: 'c'.repeat(64), warnings: [],
                },
            }),
        }));
    });

    test('uploads an export, previews and applies with its source id', async ({ page }) => {
        const started: Record<string, any>[] = [];
        await page.route('**/api/bulk-workflows/team-assessment-restore/*-task', async route => {
            const body = route.request().postDataJSON();
            started.push(body);
            const operation = route.request().url().endsWith('/apply-task') ? 'op-apply' : 'op-preview';
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ task_id: operation }) });
        });
        await page.route('**/api/bulk-workflows/tasks/op-preview', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                id: 'op-preview', status: 'completed', progress: 100, message: '',
                result: {
                    task_id: 'task-restore',
                    workflow,
                    preview_token: 'token-1',
                    selectable_group_ids: ['CVE-2099-0001'],
                    items: [{
                        group_id: 'CVE-2099-0001',
                        title: 'Synthetic vulnerability',
                        finding_count: 1,
                        restore_count: 1,
                        status: 'Ready',
                        requires_review: false,
                        review: [],
                        notes: [],
                        blocks: [{
                            team: 'TeamB', state: 'NOT_AFFECTED', date: '2030-01-01', assessed_by: 'bob',
                            ticket: 'ABC-1', match: 'uuid', component_name: 'lib-a', component_version: '1.0',
                            project_version: '1.0', text_excerpt: 'Not shipped.',
                        }],
                    }],
                    summary: {
                        groups: 1,
                        unmatched: { no_finding_in_view: 1, ambiguous: 0, other_project: 0 },
                        unmatched_samples: [{ id: 'CVE-2099-0009', component_name: 'lib-z', component_version: '9', reason: 'no_finding_in_view' }],
                        unmatched_note: 'Entries can be unmatched because the finding is no longer reported or the current filters exclude it.',
                    },
                },
            }),
        }));
        await page.route('**/api/bulk-workflows/tasks/op-apply', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                id: 'op-apply', status: 'completed', progress: 100, message: '',
                result: {
                    task_id: 'task-restore', workflow,
                    summary: { attempted: 1, succeeded: 0, queued: 1, failed: 0 },
                    results: [],
                },
            }),
        }));

        await page.goto('/project/TestProject?lifecycle=ASSESSED');
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 30000 });
        await page.getByRole('button', { name: 'Bulk Changes' }).click();
        const modal = page.locator('.fixed.inset-0').filter({ hasText: 'Bulk Changes' }).first();
        await modal.getByTestId('bulk-workflow-team-assessment-restore').click();
        await expect(modal.getByTestId('bulk-workflow-source-empty-state')).toBeVisible();

        await modal.getByTestId('bulk-workflow-source-input').setInputFiles({
            name: 'export.json',
            mimeType: 'application/json',
            buffer: Buffer.from('{"bomFormat": "CycloneDX"}'),
        });
        await expect(modal.getByTestId('bulk-workflow-source-summary')).toContainText('cccccccccccc');
        await expect(modal.getByTestId('bulk-workflow-item-CVE-2099-0001'))
            .toContainText('1 team assessments on 1 findings');
        await expect(modal.getByTestId('bulk-workflow-unmatched')).toContainText('Unmatched entries · 1');

        await modal.getByTestId('restore-blocks-CVE-2099-0001').locator('summary').click();
        await expect(modal.getByTestId('restore-blocks-CVE-2099-0001')).toContainText('TeamB · NOT_AFFECTED · 2030-01-01 · bob · ABC-1');

        await modal.getByTestId('bulk-workflow-apply').click();
        await expect(modal.getByTestId('bulk-workflow-completion')).toContainText('1 queued');
        expect(started.map(body => body.source_id)).toEqual(['source-1', 'source-1']);
        expect(started[1].group_ids).toEqual(['CVE-2099-0001']);
    });
});
