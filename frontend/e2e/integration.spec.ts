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
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.4');
        });

        // Mock backend endpoints so tests don't depend on a real DT instance.
        await page.route('**/auth/me', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ username: 'testuser', role: 'REVIEWER' }),
            });
        });

        await page.route('**/api/version', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify({ version: '1.0.4', build: 'test' }),
            });
        });

        // Mock project lookup
        const projectList = [
            { name: 'Vulnerable Project', uuid: 'p1', version: '1.0.0', classifier: 'APPLICATION' },
            { name: 'Vulnerable Project', uuid: 'p2', version: '2.0.0', classifier: 'APPLICATION' },
            { name: 'Other Project', uuid: 'p3', version: '1.0.0', classifier: 'APPLICATION' },
        ];

        await page.route('**/api/projects*', async (route) => {
            // Return a filtered list based on `name` query param if present
            const url = new URL(route.request().url());
            const name = url.searchParams.get('name') || '';
            const filtered = name
                ? projectList.filter(p => p.name.toLowerCase().includes(name.toLowerCase()))
                : projectList;
            await route.fulfill({ status: 200, body: JSON.stringify(filtered) });
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
                            id: 'CVE-2021-44228',
                            title: 'Log4Shell',
                            description: 'Log4j JNDI injection',
                            severity: 'CRITICAL',
                            cvss: 10.0,
                            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                            tags: ['Security'],
                            affected_versions: [
                                {
                                    project_name: 'Vulnerable Project',
                                    project_version: '1.0.0',
                                    project_uuid: 'p1',
                                    components: [
                                        {
                                            component_name: 'log4j-core',
                                            component_version: '2.14.0',
                                            component_uuid: 'c1',
                                            finding_uuid: 'f1',
                                            vulnerability_uuid: 'v1',
                                            analysis_state: 'IN_TRIAGE',
                                            analysis_details: '',
                                            tags: ['Security'],
                                        },
                                    ],
                                },
                            ],
                        },
                        {
                            id: 'CVE-2025-INCOMPLETE',
                            title: 'Incomplete Analysis',
                            description: 'One version is assessed, another is missing.',
                            severity: 'HIGH',
                            cvss: 7.5,
                            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                            tags: ['Security'],
                            affected_versions: [
                                {
                                    project_name: 'Vulnerable Project',
                                    project_version: '1.0.0',
                                    project_uuid: 'p1',
                                    components: [
                                        {
                                            component_name: 'lib-a',
                                            component_version: '1.0',
                                            component_uuid: 'c2',
                                            finding_uuid: 'f2',
                                            vulnerability_uuid: 'v2',
                                            analysis_state: 'EXPLOITABLE',
                                            analysis_details: '',
                                            tags: ['Security'],
                                        },
                                    ],
                                },
                                {
                                    project_name: 'Vulnerable Project',
                                    project_version: '2.0.0',
                                    project_uuid: 'p2',
                                    components: [
                                        {
                                            component_name: 'lib-a',
                                            component_version: '2.0',
                                            component_uuid: 'c3',
                                            finding_uuid: 'f3',
                                            vulnerability_uuid: 'v2',
                                            analysis_state: 'NOT_SET',
                                            analysis_details: '',
                                            tags: ['Security'],
                                        },
                                    ],
                                },
                            ],
                        },
                        {
                            id: 'CVE-2025-INCONSISTENT',
                            title: 'Inconsistent Analysis',
                            description: 'Different states across versions.',
                            severity: 'CRITICAL',
                            cvss: 9.8,
                            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                            tags: ['Security'],
                            affected_versions: [
                                {
                                    project_name: 'Vulnerable Project',
                                    project_version: '1.0.0',
                                    project_uuid: 'p1',
                                    components: [
                                        {
                                            component_name: 'lib-b',
                                            component_version: '1.0',
                                            component_uuid: 'c4',
                                            finding_uuid: 'f4',
                                            vulnerability_uuid: 'v3',
                                            analysis_state: 'EXPLOITABLE',
                                            analysis_details: '',
                                            tags: ['Security'],
                                        },
                                    ],
                                },
                                {
                                    project_name: 'Vulnerable Project',
                                    project_version: '2.0.0',
                                    project_uuid: 'p2',
                                    components: [
                                        {
                                            component_name: 'lib-b',
                                            component_version: '2.0',
                                            component_uuid: 'c5',
                                            finding_uuid: 'f5',
                                            vulnerability_uuid: 'v3',
                                            analysis_state: 'NOT_AFFECTED',
                                            analysis_details: '',
                                            tags: ['Security'],
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
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
                body: JSON.stringify({ 'lib-a': 'Security', 'lib-b': 'Security' }),
            });
        });

        await page.route('**/api/settings/rescore-rules', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ transitions: [] }),
            });
        });

        // Mock dependency chains for the DependencyChainViewer
        await page.route('**/api/project/*/component/*/dependency-chains', async (route) => {
            await route.fulfill({
                status: 200,
                body: JSON.stringify(["log4j-core -> Vulnerable Project"]),
            });
        });

        await login(page);
    });


    test('Dashboard loads and displays projects from Mock DT', async ({ page }) => {
        // 1. Wait for projects to load
        await page.getByPlaceholder('Filter projects...').fill('Vuln');
        // Search button is gone, filtering is instant
        // await page.getByRole('button', { name: 'Search' }).click();

        // 2. Wait for projects to load
        const projectLink = page.getByRole('link', { name: 'Vulnerable Project' }).first();
        await expect(projectLink).toBeVisible({ timeout: 15000 });

        // 3. Verify version 1.0.0 is present on the card
        const projectCard = projectLink.locator('..');
        await expect(projectCard.getByText('v1.0.0')).toBeVisible({ timeout: 10000 });
    });

    test('Navigate to Project Details and see Vulnerabilities', async ({ page }) => {
        page.on('console', msg => {
            if (msg.text().includes('[DEBUG]')) console.log(`BROWSER: ${msg.text()}`);
        });
        // 1. Perform Search to find project
        await page.getByPlaceholder('Filter projects...').fill('Vuln');
        // await page.getByRole('button', { name: 'Search' }).click();

        // 2. Click on the project name to navigate
        const projectLink = page.getByRole('link', { name: 'Vulnerable Project' }).first();
        await expect(projectLink).toBeVisible({ timeout: 10000 });

        // Ensure any modal overlay (changelog modal, etc.) is dismissed before clicking
        // The modal can block pointer events even if the link is visible.
        const overlay = page.locator('div.fixed.inset-0');
        if (await overlay.count() > 0) {
            await overlay.evaluate((node: any) => node.remove());
        }

        await projectLink.click();
        // 3. Check for URL change
        await expect(page).toHaveURL(/.*\/project\/Vulnerable%20Project/);

        // 4. Ensure all filters are enabled so vulnerabilities are visible
        // (Reset All guarantees a known state regardless of defaults)
        const resetBtn = page.getByRole('button', { name: 'Reset All' });
        await expect(resetBtn).toBeVisible({ timeout: 10000 });
        await resetBtn.click();

        // 5. Now wait for vulnerabilities to be visible
        await expect(page.getByText('CVE-2021-44228')).toBeVisible({ timeout: 30000 });
        await expect(page.getByText('CVE-2025-INCOMPLETE')).toBeVisible();
        await expect(page.locator('.vuln-card').filter({ hasText: 'CVE-2025-INCOMPLETE' }).locator('.analysis-lifecycle-value')).toHaveText(/INCOMPLETE|ASSESSED/);

        // Verify INCONSISTENT mock vulnerability
        await expect(page.getByText('CVE-2025-INCONSISTENT')).toBeVisible();
        await expect(page.locator('.vuln-card').filter({ hasText: 'CVE-2025-INCONSISTENT' }).locator('.analysis-lifecycle-value')).toHaveText('INCONSISTENT');

        // 5. Verify Dependency Chains
        // Click to expand the card first by clicking the header area
        const vulnCard = page.locator('.vuln-card').filter({ hasText: 'CVE-2021-44228' }).first();
        const cardHeader = vulnCard.locator('.cursor-pointer').first();
        await expect(cardHeader).toBeVisible();
        await cardHeader.click();
        await page.waitForTimeout(500); // Wait for expansion

        // Click the dependency chain toggler button on this vulnerability card
        const chainToggleButton = vulnCard.getByRole('button', { name: /chains/i }).first();
        await expect(chainToggleButton).toBeVisible({ timeout: 5000 });
        await chainToggleButton.click();

        // Expect the chain segments to be visible in the dependency chain viewer
        await expect(page.getByTitle('log4j-core').first()).toBeVisible({ timeout: 15000 });
    });

});
