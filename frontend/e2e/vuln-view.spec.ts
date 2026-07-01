
import { test, expect } from '@playwright/test';
import { mockGroupedVulnTask } from './helpers/grouped-task';

test.describe('Vulnerability View and Rescoring', () => {
    test.beforeEach(async ({ page }) => {
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

        // Mock Cache Status
        await page.route('**/api/cache-status', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({ fully_cached: true, last_refreshed_at: new Date().toISOString(), projects: 1, active_projects: 1, cached_findings: 1, cached_boms: 1, cached_analyses: 0, pending_updates: 0 }),
            });
        });

        // Mock Projects
        await page.route('**/api/projects?name=TestProject', async (route) => {
            // Return extended list immediately for search/filter
            await route.fulfill({
                status: 200,
                body: JSON.stringify([
                    { name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' },
                    { name: 'TestProject', uuid: 'p2', version: '1.1', classifier: 'APPLICATION' },
                    { name: 'BackendLib', uuid: 'p3', version: '2.0', classifier: 'LIBRARY' },
                    { name: 'FrontendApp', uuid: 'p4', version: '3.0', classifier: 'APPLICATION' },
                ]),
            });
        });

        // Also mock generic project search if needed
        await page.route('**/api/projects?name=', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify([
                    { name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' },
                    { name: 'TestProject', uuid: 'p2', version: '1.1', classifier: 'APPLICATION' },
                    { name: 'BackendLib', uuid: 'p3', version: '2.0', classifier: 'LIBRARY' },
                    { name: 'FrontendApp', uuid: 'p4', version: '3.0', classifier: 'APPLICATION' },
                ]),
            });
        });

        const taskGroups = [
            {
                id: 'CVE-2023-1234',
                title: 'Test Vulnerability',
                description: 'A bad vulnerability description.',
                severity: 'HIGH',
                cvss: 9.8,
                cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                tags: ['Security'],
                affected_versions: [
                    {
                        project_name: 'TestProject',
                        project_version: '1.0',
                        project_uuid: 'p1',
                        components: [
                            {
                                component_name: 'lib-a',
                                component_version: '1.0',
                                component_uuid: 'c-1',
                                finding_uuid: 'f-1',
                                vulnerability_uuid: 'v-1',
                                analysis_state: 'NOT_SET',
                                analysis_details: '',
                                tags: ['Security']
                            }
                        ]
                    }
                ]
            },
            {
                id: 'CVE-2023-ASSESSED',
                title: 'Already Assessed Vulnerability',
                description: 'A vulnerability with a completed assessment.',
                severity: 'MEDIUM',
                cvss: 5.3,
                cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                tags: ['Security'],
                list_metadata: {
                    lifecycle: 'ASSESSED',
                    is_open: false,
                    is_pending: false,
                    technical_state: 'RESOLVED',
                    component_names: ['lib-b'],
                    versions: ['1.0'],
                    dependency_relationship: 'DIRECT',
                    instance_count: 1,
                    assessed_teams: ['Security'],
                    teams: ['Security'],
                },
                affected_versions: [
                    {
                        project_name: 'TestProject',
                        project_version: '1.0',
                        project_uuid: 'p1',
                        components: [
                            {
                                component_name: 'lib-b',
                                component_version: '1.0',
                                component_uuid: 'c-2',
                                finding_uuid: 'f-2',
                                vulnerability_uuid: 'v-2',
                                analysis_state: 'RESOLVED',
                                analysis_details: '[State: RESOLVED]\nAlready assessed.',
                                tags: ['Security']
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
                body: JSON.stringify({ task_id: 'task-123' }),
            });
        });

        await mockGroupedVulnTask(page, { taskId: 'task-123', groups: taskGroups });

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
                body: JSON.stringify({ 'lib-a': 'Security' }),
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
                    latest_version: '1.1',
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

    test('should render vulnerability row with lifecycle and team context', async ({ page }) => {
        // Go to project view
        await page.goto('/project/TestProject');
        await page.waitForLoadState('networkidle');

        const assessedCard = page.locator('.vuln-card').filter({ hasText: /CVE-2023-ASSESSED/ });
        await expect(assessedCard).toBeVisible({ timeout: 20000 });

        // Deselect "Assessed" and verify backend-windowed filtering removes assessed rows.
        await page.getByRole('button', { name: /^Assessed(?!.*Legacy)/ }).click();
        await expect(assessedCard).toHaveCount(0);

        // Wait for row to appear
        const vulnCard = page.locator('.vuln-card').filter({ hasText: /CVE-2023-1234/ }).first();
        await expect(vulnCard).toBeVisible({ timeout: 20000 });

        await expect(vulnCard.getByText('Security')).toBeVisible();
        await expect(vulnCard.getByTestId('lifecycle-badge')).toHaveText(/Open|Assessed|Incomplete|Inconsistent/);
        await expect(vulnCard.getByTestId('base-score-value')).toBeVisible();
    });
});
