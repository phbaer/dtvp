
import { test, expect } from '@playwright/test';

test.describe('Vulnerability View and Rescoring', () => {
    test.beforeEach(async ({ page }) => {
        page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
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

    test('should allow rescoring a vulnerability', async ({ page }) => {
        // Go to project view
        await page.goto('/project/TestProject');
        await page.waitForLoadState('networkidle');

        // Ensure "Assessed" vulnerabilities are visible (avoid matching the similar "Assessed (Legacy)" button)
        await page.getByRole('button', { name: /^Assessed(?!.*Legacy)/ }).click();

        // Wait for CVE to appear
        const cardHeader = page.locator('.border.rounded-lg').filter({ hasText: /CVE-2023-1234/ }).first();
        await expect(cardHeader).toBeVisible({ timeout: 20000 });

        // Expand
        await cardHeader.click();

        // Check description
        await expect(page.locator('text=A bad vulnerability description.')).toBeVisible();

        // Select Team first (required to see rescoring fields)
        const teamDropdown = cardHeader.getByRole('button', { name: 'Global assessment' });
        await teamDropdown.click();
        await page.locator('.absolute.z-50 button', { hasText: 'Security' }).click();

        // Wait for the team assessment header to appear
        await expect(page.locator('text=Team Assessment: Security')).toBeVisible({ timeout: 10000 });

        // Verify rescoring fields are visible
        await expect(cardHeader.locator('input[placeholder^="CVSS"]')).toBeVisible({ timeout: 10000 });
        await expect(cardHeader.locator('input[type="number"]')).toBeVisible({ timeout: 10000 });

        // Change the vector manually
        // First, unlock the fields (new requirement due to read-only by default)
        await page.getByText('Visual Calculator').click();
        await page.getByRole('button', { name: 'Clear' }).click();
        await page.getByRole('button', { name: 'Done' }).click();

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
        const applyBtn = cardHeader.getByRole('button', { name: 'Apply' });
        await applyBtn.click();

        // Handle Custom Confirm Modal
        await page.getByRole('button', { name: 'Confirm' }).click();

        // Check that card remains open and description is still visible
        await expect(page.locator('text=A bad vulnerability description.')).toBeVisible();

        // Verify the new score is in the header
        await expect(page.getByTestId('rescored-value-badge')).toBeVisible();
    });
});
