import { test, expect } from '@playwright/test';


async function login(page: any, role: 'Analyst' | 'Reviewer' = 'Analyst') {
    await page.goto('/login');
    await page.getByRole('button', { name: 'Sign in with SSO' }).click();

    // Wait for redirect to mock OIDC provider (using regex that handles both localhost and 127.0.0.1)
    await page.waitForURL(/.*:8081\/auth\/authorize/, { timeout: 10000 });

    // Select role
    await page.getByRole('button', { name: `Login as ${role}` }).click();

    // Wait for redirect back to app dashboard
    await page.waitForURL(/\/$/, { timeout: 10000 });
}

test.describe('Integration Tests (Real Backend)', () => {
    test.beforeEach(async ({ page }) => {
        // Bypass ChangelogModal by setting last seen version
        await page.addInitScript(() => {
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.3');
        });
        await login(page);
    });


    test('Dashboard loads and displays projects from Mock DT', async ({ page }) => {
        // 1. Wait for projects to load
        await page.getByPlaceholder('Filter projects...').fill('Vuln');
        // Search button is gone, filtering is instant
        // await page.getByRole('button', { name: 'Search' }).click();

        // 2. Wait for projects to load
        await expect(page.getByText('Vulnerable Project')).toBeVisible({ timeout: 15000 });

        // 3. Verify version 1.0.0 is present
        await expect(page.getByText('v1.0.0')).toBeVisible({ timeout: 10000 });
    });

    test('Navigate to Project Details and see Vulnerabilities', async ({ page }) => {
        // 1. Perform Search to find project
        await page.getByPlaceholder('Filter projects...').fill('Vuln');
        // await page.getByRole('button', { name: 'Search' }).click();

        // 2. Click on the project name to navigate
        const projectLink = page.getByRole('link', { name: 'Vulnerable Project' }).first();
        await projectLink.click();
        // 3. Check for URL change
        await expect(page).toHaveURL(/.*\/project\/Vulnerable%20Project/);

        // 4. Wait for vulnerabilities to be fetched (indicated by loading indicator gone)
        // Use a longer timeout and wait for the vulnerability itself as a better indicator
        await expect(page.getByText('CVE-2021-44228')).toBeVisible({ timeout: 30000 });

        // 5. Uncheck "Hide Assessed" and "Hide Mixed" to ensure vulnerabilities are visible
        // Re-locate to be sure they are on the project page
        const hideAssessedLabel = page.locator('label', { hasText: 'Hide Assessed' });
        const hideMixedLabel = page.locator('label', { hasText: 'Hide Mixed' });

        // Use click on the label wrapper to toggle if checked
        // Note: they are checked by default (well, hideAssessed is true, hideMixed is false)
        // Let's explicitly ensure they are unchecked
        const assessedCheckbox = hideAssessedLabel.locator('input[type="checkbox"]');
        const mixedCheckbox = hideMixedLabel.locator('input[type="checkbox"]');

        if (await assessedCheckbox.isChecked()) await hideAssessedLabel.click();
        if (await mixedCheckbox.isChecked()) await hideMixedLabel.click();

        // 6. Verify Vulnerabilities from Mock DT are displayed
        // We expect CVE-2021-44228 (Log4Shell)
        await expect(page.getByText('CVE-2021-44228')).toBeVisible({ timeout: 20000 });

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
        await expect(page.getByTitle('internal-lib-a').first()).toBeVisible();
        await expect(page.getByTitle('internal-lib-b').first()).toBeVisible();
        await expect(page.getByTitle('log4j-core').first()).toBeVisible();
    });

});
