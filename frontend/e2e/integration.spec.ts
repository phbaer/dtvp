import { test, expect } from '@playwright/test';

test.describe('Integration Tests (Real Backend)', () => {

    test('Dashboard loads and displays projects from Mock DT', async ({ page }) => {
        // 1. Go to Dashboard
        await page.goto('/');

        // 2. Perform Search
        await page.getByPlaceholder('Search project name...').fill('Vuln');
        await page.getByRole('button', { name: 'Search' }).click();

        // 3. Wait for projects to load
        // The mock backend returns "Vulnerable Project"
        await expect(page.getByText('Vulnerable Project')).toBeVisible({ timeout: 15000 });

        // Uncheck "Hide Assessed" and "Hide Mixed" to ensure all results are visible


        // 4. Verify version is displayed
        await expect(page.getByText('1.0.0')).toBeVisible({ timeout: 10000 });
    });

    test('Navigate to Project Details and see Vulnerabilities', async ({ page }) => {
        await page.goto('/');

        // 1. Perform Search to find project
        await page.getByPlaceholder('Search project name...').fill('Vuln');
        await page.getByRole('button', { name: 'Search' }).click();

        // 2. Click on the project to navigate
        await page.getByText('Vulnerable Project').click();

        // Uncheck "Hide Assessed" and "Hide Mixed" to ensure vulnerabilities are visible
        await page.locator('label', { hasText: 'Hide Assessed' }).uncheck();
        await page.locator('label', { hasText: 'Hide Mixed' }).uncheck();

        // 3. Check for URL change
        await expect(page).toHaveURL(/.*\/project\/Vulnerable%20Project/);

        // 4. Verify Vulnerabilities from Mock DT are displayed
        // We expect CVE-2021-44228 (Log4Shell)
        await expect(page.getByText('CVE-2021-44228')).toBeVisible({ timeout: 15000 });

        // 4. Verify Analysis State (Mocked as NOT_SET or similar)
        // Wait specifically for the status badge
        await expect(page.locator('.analysis-state-value').first()).toBeVisible();
    });

});
