
import { test, expect } from '@playwright/test';

test.describe('Team Analysis Persistence', () => {
    test.beforeEach(async ({ page }) => {
        page.on('dialog', dialog => dialog.accept());

        // Mock Session
        await page.route('**/auth/me', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ username: 'testuser', role: 'ANALYST' }),
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
        await page.route('**/api/projects?name=PersistenceTest', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify([{ name: 'PersistenceTest', uuid: 'p1', version: '1.0' }]),
            });
        });

        // Mock Task Start
        await page.route('**/api/tasks/group-vulns*', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({ task_id: 'task-persistence' }),
            });
        });

        // Mock Task Status Polling with Team Tags
        await page.route('**/api/tasks/task-persistence', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({
                    status: 'completed',
                    progress: 100,
                    result: [
                        {
                            id: 'CVE-PERSISTENCE-TEST',
                            title: 'Persistence Test Vulnerability',
                            description: 'Vulnerability for testing persistence.',
                            severity: 'MEDIUM',
                            cvss: 5.0,
                            tags: ['Frontend'],
                            affected_versions: [
                                {
                                    project_name: 'PersistenceTest',
                                    project_version: '1.0',
                                    project_uuid: 'p1',
                                    components: [
                                        {
                                            component_name: 'test-lib',
                                            component_version: '1.0',
                                            component_uuid: 'c-1',
                                            finding_uuid: 'f-1',
                                            vulnerability_uuid: 'v-1',
                                            analysis_state: 'NOT_SET',
                                            tags: ['Frontend']
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }),
            });
        });

        // Mock Assessment Details (Initial empty state)
        await page.route('**/api/assessments/details', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify([{
                    finding_uuid: 'f-1',
                    project_uuid: 'p1',
                    component_uuid: 'c-1',
                    vulnerability_uuid: 'v-1',
                    analysis: {
                        state: 'NOT_SET',
                        analysisState: 'NOT_SET',
                        isSuppressed: false,
                        analysisDetails: '',
                        analysisComments: []
                    }
                }]),
            });
        });
    });

    test('should persist details entered for a team', async ({ page }) => {
        await page.goto('/project/PersistenceTest');

        // Uncheck "Hide Assessed" and "Hide Mixed" to ensure visibility
        await page.locator('label', { hasText: 'Hide Assessed' }).uncheck();
        await page.locator('label', { hasText: 'Hide Mixed' }).uncheck();

        // Expand card
        const cardHeader = page.locator('.border.rounded-lg').filter({ hasText: 'CVE-PERSISTENCE-TEST' }).first();
        await expect(cardHeader).toBeVisible();
        await cardHeader.click();

        // Select Team
        const teamSelector = page.locator('label:has-text("Team assessment (Marker)")').locator('xpath=following-sibling::select').first();
        await expect(teamSelector).toBeVisible();
        await teamSelector.selectOption('Frontend');

        // Enter State and Details
        const stateSelect = page.locator('label:has-text("Team Analysis State")').locator('xpath=following-sibling::select').first();
        await stateSelect.selectOption('IN_TRIAGE');

        const detailsText = 'These are persistent details.';
        await page.fill('textarea[placeholder="Technical details for this team..."]', detailsText);

        // Mock the update response
        // IMPORTANT: We need to update the details route for subsequent calls to simulate persistence on the backend
        let storedDetails = '';

        await page.route('**/api/assessment', async (route) => {
            const request = route.request().postDataJSON();

            // Construct the expected saved format (mocking backend logic)
            storedDetails = `--- [Team: Frontend] [State: IN_TRIAGE] [Assessed By: testuser] ---\n${request.details}\n\n[Status: Pending Review]`;

            await route.fulfill({
                status: 200,
                body: JSON.stringify([
                    {
                        status: 'success',
                        uuid: 'f-1',
                        new_state: 'IN_TRIAGE',
                        new_details: storedDetails
                    }
                ]),
            });
        });

        // Click Apply
        const applyBtn = cardHeader.getByRole('button', { name: /Apply to/ });
        await applyBtn.click();

        // Wait for update to complete (button re-enables or alert)
        // In the real app, it closes the expanded view on success, so let's cycle it.
        // Wait for card to collapse (expanded false)
        await expect(page.locator('text=Technical details for this team...')).not.toBeVisible();

        // Update the mock for details fetching to return the stored data
        await page.route('**/api/assessments/details', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify([{
                    finding_uuid: 'f-1',
                    project_uuid: 'p1',
                    component_uuid: 'c-1',
                    vulnerability_uuid: 'v-1',
                    analysis: {
                        state: 'IN_TRIAGE',
                        analysisState: 'IN_TRIAGE',
                        isSuppressed: false,
                        analysisDetails: storedDetails,
                        analysisComments: []
                    }
                }]),
            });
        });

        // Re-expand card
        await cardHeader.click();

        // Select Team again to view team-specific details
        await teamSelector.selectOption('Frontend');

        // Verify details persist in the textarea
        const textarea = page.locator('textarea[placeholder="Technical details for this team..."]');
        await expect(textarea).toHaveValue(new RegExp(detailsText));
    });
});
