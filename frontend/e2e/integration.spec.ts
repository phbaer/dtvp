import { test, expect } from '@playwright/test';

test.describe('Integration Tests (Real Backend)', () => {

    test('Dashboard loads and displays projects from Mock DT', async ({ page }) => {
        // 1. Go to Dashboard
        await page.goto('/');

        // 2. Perform Search
        await page.getByPlaceholder('Filter projects...').fill('Vuln');
        // Search button is gone, filtering is instant
        // await page.getByRole('button', { name: 'Search' }).click();

        // 3. Wait for projects to load
        // The mock backend returns "Vulnerable Project"
        await expect(page.getByText('Vulnerable Project')).toBeVisible({ timeout: 15000 });

        // Uncheck "Hide Assessed" and "Hide Mixed" to ensure all results are visible


        // 4. Verify version is displayed
        await expect(page.getByText('v1.0.0')).toBeVisible({ timeout: 10000 });
    });

    test('Navigate to Project Details and see Vulnerabilities', async ({ page }) => {
        await page.goto('/');

        // 1. Perform Search to find project
        await page.getByPlaceholder('Filter projects...').fill('Vuln');
        // await page.getByRole('button', { name: 'Search' }).click();

        // 2. Click on the project name to navigate (pick first if multiple)
        await page.getByText('Vulnerable Project').first().click();

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

        // 5. Verify Dependency Chains
        // Click to expand the card first (click the ID)
        await page.getByText('CVE-2021-44228').click();

        // Click to show dependency chains
        const trackingBtn = page.getByRole('button', { name: 'Show Dependency Chains' }).first();
        await expect(trackingBtn).toBeVisible({ timeout: 5000 });
        await page.waitForTimeout(500); // Small stability wait
        await trackingBtn.click();

        // Expect the chain segments to be visible
        // Note: The root "Vulnerable Project" is hidden by the UI component
        // Use getByTitle because the visualization adds title attributes to the nodes
        await expect(page.getByTitle('internal-lib-a')).toBeVisible();
        await expect(page.getByTitle('internal-lib-b')).toBeVisible();
        await expect(page.getByTitle('log4j-core')).toBeVisible();
    });

});
