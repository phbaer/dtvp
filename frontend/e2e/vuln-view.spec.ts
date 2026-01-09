
import { test, expect } from '@playwright/test';

test.describe('Vulnerability View and Rescoring', () => {
    test.beforeEach(async ({ page }) => {
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
            await route.fulfill({
                status: 200,
                body: JSON.stringify([{ name: 'TestProject', uuid: 'p1', version: '1.0' }]),
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
                            affected_versions: [
                                {
                                    project_name: 'TestProject',
                                    project_version: '1.0',
                                    project_uuid: 'p1',
                                    components: [
                                        {
                                            component_name: 'lib-a',
                                            component_version: '1.0',
                                            analysis_state: 'NOT_SET',
                                            analysis_details: '',
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }),
            });
        });
    });

    test('should allow rescoring a vulnerability', async ({ page }) => {
        // Go to project view
        await page.goto('/project/TestProject');

        // Wait for CVE to appear
        await expect(page.locator('text=CVE-2023-1234')).toBeVisible();

        // Expand
        await page.locator('text=CVE-2023-1234').click();

        // Check description
        await expect(page.locator('text=A bad vulnerability description.')).toBeVisible();

        // Open calculator
        await page.locator('button:has-text("Visual Calculator")').click();

        // Verify modal is open
        await expect(page.locator('text=CVSS v3.1 Calculator')).toBeVisible();

        // Change a metric (e.g. Attack Complexity)
        await page.locator('#metric-AC').selectOption('H');

        // Check if score updated (9.8 should become something else, e.g. 5.9 for AC:H in 3.1)
        // We look for the score in the modal footer
        const modalFooter = page.locator('.fixed.inset-0 .text-2xl');
        await expect(modalFooter).not.toHaveText('9.8');

        // Click Done
        await page.locator('button:has-text("Done")').click();

        // Verify pending score updated in the main form
        await expect(page.locator('input[type="number"]')).not.toHaveValue('9.8');

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
        page.on('dialog', dialog => dialog.accept());
        await page.locator('button:has-text("Apply to All")').click();

        // Check for success alert or indicator that it closed
        await expect(page.locator('text=A bad vulnerability description.')).not.toBeVisible();

        // Verify the new score is in the header
        // We look for the span with title "Rescored Value"
        await expect(page.locator('span[title="Rescored Value"]')).toBeVisible();
    });
});
