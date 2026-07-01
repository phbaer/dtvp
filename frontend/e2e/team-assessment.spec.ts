import { test, expect } from '@playwright/test';
import { mockGroupedVulnTask } from './helpers/grouped-task';

test.describe('Per-Team Assessment UI Flow', () => {
    test.beforeEach(async ({ page }) => {
        page.on('dialog', dialog => dialog.accept());
        // Mock Session
        await page.route('**/auth/me', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ username: 'testuser', role: 'REVIEWER' }),
            });
        });

        // Mock Version
        await page.route('**/api/version', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({ version: '1.0.0', build: 'test' }),
            });
        });

        // Mock Projects
        await page.route('**/api/projects?name=TestProject', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify([
                    { name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' },
                ]),
            });
        });

        const taskGroups = [
            {
                id: 'CVE-TEAM-TEST',
                title: 'Team Shared Vulnerability',
                description: 'Vulnerability affects both Frontend and Backend teams.',
                severity: 'HIGH',
                cvss: 7.5,
                tags: ['Frontend', 'Backend'],
                affected_versions: [
                    {
                        project_name: 'TestProject',
                        project_version: '1.0',
                        project_uuid: 'p1',
                        components: [
                            {
                                component_name: 'frontend-lib',
                                component_version: '1.0',
                                component_uuid: 'c-front',
                                finding_uuid: 'f-front',
                                vulnerability_uuid: 'v-1',
                                analysis_state: 'NOT_SET',
                                tags: ['Frontend']
                            },
                            {
                                component_name: 'backend-lib',
                                component_version: '1.0',
                                component_uuid: 'c-back',
                                finding_uuid: 'f-back',
                                vulnerability_uuid: 'v-1',
                                analysis_state: 'NOT_SET',
                                tags: ['Backend']
                            }
                        ]
                    }
                ]
            }
        ];

        // Mock Task Start
        await page.route('**/api/tasks/group-vulns*', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({ task_id: 'task-456' }),
            });
        });

        await mockGroupedVulnTask(page, { taskId: 'task-456', groups: taskGroups });

        // Mock Assessment Details
        await page.route('**/api/assessments/details', async (route) => {
            const body = route.request().postDataJSON();
            const results = (body.instances || []).map((inst: any) => ({
                finding_uuid: inst.finding_uuid,
                project_uuid: inst.project_uuid,
                component_uuid: inst.component_uuid,
                vulnerability_uuid: inst.vulnerability_uuid,
                analysis: {
                    state: 'NOT_SET',
                    analysisState: 'NOT_SET',
                    isSuppressed: false,
                    analysisDetails: '',
                    analysisComments: []
                }
            }));
            await route.fulfill({
                status: 200,
                body: JSON.stringify(results),
            });
        });

        // Mock Team Mapping
        await page.route('**/api/settings/mapping', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ 'frontend-lib': 'Frontend', 'backend-lib': 'Backend' }),
            });
        });

        await page.route('**/api/settings/rescore-rules', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ transitions: [] }),
            });
        });

        await page.route('**/api/projects/*/tmrescore/proposals', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    project_name: 'TestProject',
                    session_id: '',
                    scope: 'merged_versions',
                    latest_version: '1.0',
                    analyzed_versions: [],
                    proposals: {},
                }),
            });
        });

        // Bypass ChangelogModal
        await page.addInitScript(() => {
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
        });
    });

    test('should render team-oriented vulnerability row state', async ({ page }) => {
        await page.goto('/project/TestProject');

        // Ensure vulnerability card is visible in compact list
        const vulnCard = page.locator('.vuln-card').filter({ hasText: 'CVE-TEAM-TEST' }).first();
        await expect(vulnCard).toBeVisible({ timeout: 30000 });

        await expect(vulnCard.getByText(/Backend|Frontend/i).first()).toBeVisible();
        await expect(vulnCard.getByTestId('lifecycle-badge')).toHaveText(/Open|Incomplete|Assessed|Inconsistent|Needs Approval/);
        await expect(vulnCard.getByTestId('instance-count')).toBeVisible();
    });
});
