
import { test, expect } from '@playwright/test';

test.describe('Vulnerability View and Rescoring', () => {
    test.beforeEach(async ({ page }) => {
        page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
        // Mock Session
        await page.route('**/auth/me', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ username: 'testuser' }),
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

        // Mock Task Start
        await page.route('**/api/tasks/group-vulns*', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({ task_id: 'task-123' }),
            });
        });

        // Mock Task Status Polling
        await page.route('**/api/tasks/task-123', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({
                    status: 'completed',
                    progress: 100,
                    result: [
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
                        }
                    ]
                }),
            });
        });

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
    });

    test('should allow rescoring a vulnerability', async ({ page }) => {
        // Go to project view
        await page.goto('/project/TestProject');
        await page.waitForLoadState('networkidle');

        // Uncheck "Hide Assessed" and "Hide Mixed"
        await page.locator('label', { hasText: 'Hide Assessed' }).uncheck();
        await page.locator('label', { hasText: 'Hide Mixed' }).uncheck();

        // Wait for CVE to appear
        const cardHeader = page.locator('.border.rounded-lg').filter({ hasText: /CVE-2023-1234/ }).first();
        await expect(cardHeader).toBeVisible({ timeout: 20000 });

        // Expand
        await cardHeader.click();

        // Check description
        await expect(page.locator('text=A bad vulnerability description.')).toBeVisible();

        // Select Team first (required to see rescoring fields)
        const teamSelector = cardHeader.locator('select').first();
        await teamSelector.selectOption('Security');

        // Wait for the team assessment header to appear
        await expect(page.locator('text=Team Assessment: Security')).toBeVisible({ timeout: 10000 });

        // Verify rescoring fields are visible
        await expect(page.locator('input[placeholder^="CVSS"]')).toBeVisible();
        await expect(page.locator('input[type="number"]')).toBeVisible();

        // Change the vector manually
        const vectorInput = page.locator('input[placeholder^="CVSS"]');
        await vectorInput.fill('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H');

        // Change the score manually
        const scoreInput = page.locator('input[type="number"]');
        await scoreInput.fill('9.1');


        // Submit Assessment
        // Mock the submission first
        await page.route('**/api/assessment', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify([{ status: 'success' }]),
            });
        });

        // Click Apply to All
        // We might get a confirm dialog, Playwright handles it if we set up a listener or it might just work if we use page.on('dialog')
        // Click Apply
        const applyBtn = cardHeader.getByRole('button', { name: /Apply to/ });
        await applyBtn.click();

        // Handle Custom Confirm Modal
        await page.getByRole('button', { name: 'Confirm' }).click();

        // Handle Success Modal
        await expect(page.getByText('Assessment updated successfully')).toBeVisible();
        await page.getByRole('button', { name: 'Close' }).click();

        // Check for success alert or indicator that it closed
        await expect(page.locator('text=A bad vulnerability description.')).not.toBeVisible();

        // Verify the new score is in the header
        // We look for the span with title "Rescored Value"
        await expect(page.locator('span[title="Rescored Value"]')).toBeVisible();
    });
});
