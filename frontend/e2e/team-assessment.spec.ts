import { test, expect } from '@playwright/test';

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

        // Mock Task Start
        await page.route('**/api/tasks/group-vulns*', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({ task_id: 'task-456' }),
            });
        });

        // Mock Task Status Polling with Team Tags
        await page.route('**/api/tasks/task-456', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({
                    status: 'completed',
                    progress: 100,
                    result: [
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

        // Bypass ChangelogModal
        await page.addInitScript(() => {
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
        });
    });

    test('should allow targeted team assessment and show aggregated result', async ({ page }) => {
        await page.goto('/project/TestProject');

        // Ensure vulnerabilities in the INCOMPLETE lifecycle bucket are visible
        // (this test evaluates a team-level assessment where not all teams have assessed yet)
        await page.getByRole('button', { name: 'Incomplete' }).click();

        // Locate the team vulnerability and click it to expand
        const cardHeader = page.locator('.border.rounded-lg').filter({ hasText: 'CVE-TEAM-TEST' }).first();
        await expect(cardHeader).toBeVisible();
        await cardHeader.click();

        // Wait for the global assessment section to be visible
        const globalHeader = page.getByText(/Global Assessment/i).first();
        await expect(globalHeader).toBeVisible();

        // Verify Team Marker dropdown exists and has options
        const teamSelector = cardHeader.locator('select').first();
        await expect(teamSelector).toBeVisible();

        // selectOption will wait for the option to be present
        await teamSelector.selectOption('Backend');

        // Analysis state selection (Label is now "Team Analysis State")
        const stateSelect = cardHeader.locator('select').nth(1);
        await expect(stateSelect).toBeVisible();
        await stateSelect.selectOption('EXPLOITABLE');

        // Add details
        await page.fill('textarea[placeholder="Technical details..."]', 'Backend confirms this is exploitable in our environment.');

        // Mock the sophisticated server response (Aggregation)
        await page.route('**/api/assessment', async (route) => {
            const request = route.request().postDataJSON();
            await route.fulfill({
                status: 200,
                body: JSON.stringify([
                    {
                        status: 'success',
                        uuid: request.instances[0].finding_uuid,
                        new_state: 'EXPLOITABLE',
                        new_details: `[Rescored: 7.5]\n\n--- [Team: Backend] [State: EXPLOITABLE] [Assessed By: testuser] ---\nBackend confirms this is exploitable in our environment.`
                    }
                ]),
            });
        });

        // Click Apply
        // Use getByRole for better resilience
        const applyBtn = cardHeader.getByRole('button', { name: 'Apply' });
        console.log('E2E: Clickable button found:', await applyBtn.textContent());
        await applyBtn.click();

        // Handle Custom Confirm Modal
        await page.getByRole('button', { name: 'Confirm' }).click();

        // Ensure the card is open (it may re-render/collapse after the update).
        const detailsTextarea = page.locator('textarea[placeholder="Technical details..."]');
        if (await detailsTextarea.count() === 0) {
            await cardHeader.click();
        }

        // Playwright's text selector does not match textarea value, so verify the value directly.
        await expect(detailsTextarea).toHaveValue(/Backend confirms this is exploitable/);

        // Verify the card header now shows the EXPLOITABLE state
        await expect(page.locator('#state-CVE-TEAM-TEST')).toHaveText('EXPLOITABLE', { timeout: 10000 });
    });
});
