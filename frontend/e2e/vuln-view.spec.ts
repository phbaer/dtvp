
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

        // Explicit server classifications exercise the mutually exclusive UI filters.
        for (const [id, lifecycle, pending] of [
            ['CVE-READY', 'NEEDS_APPROVAL', true],
            ['CVE-PARTIAL', 'INCOMPLETE', true],
            ['CVE-LEGACY', 'ASSESSED_LEGACY', false],
        ] as const) {
            const fixture = structuredClone(taskGroups[1]!);
            fixture.id = id;
            fixture.list_metadata = {
                ...fixture.list_metadata!, lifecycle,
                is_pending: pending,
                // Pending work remains open in team counters, not in the Open filter.
                is_open: pending,
            };
            if (pending) {
                fixture.affected_versions[0]!.components[0]!.analysis_details =
                    '--- [Team: Security] [State: RESOLVED] ---\n[Status: Pending Review]';
            }
            if (lifecycle === 'INCOMPLETE') fixture.tags = ['Security', 'Other'];
            taskGroups.push(fixture);
        }

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
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=ASSESSED');
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
        await expect(vulnCard.getByTestId('lifecycle-badge')).toHaveText('Open');
        await expect(vulnCard.getByTestId('base-score-value')).toBeVisible();
    });
    test('changing team assessment preserves lifecycle selections and survives reload', async ({ page }) => {
        await page.goto('/project/TestProject?q=team%3ASecurity&lifecycle=READY_FOR_APPROVAL');
        const cards = page.locator('.vuln-card');
        const coverage = page.getByRole('combobox', { name: 'Assessment for selected teams', exact: true });
        await expect(cards.filter({ hasText: 'CVE-READY' })).toBeVisible({ timeout: 15000 });
        await coverage.selectOption('DOCUMENTED');
        await expect(page).toHaveURL(/team_assessment=DOCUMENTED/);
        expect(new URL(page.url()).searchParams.getAll('lifecycle')).toEqual(['READY_FOR_APPROVAL']);
        await expect(cards).toHaveCount(1);
        await expect(cards.filter({ hasText: 'CVE-READY' })).toBeVisible();

        await page.goto('/project/TestProject?q=team%3ASecurity&lifecycle=INCOMPLETE');
        for (const selection of ['DOCUMENTED', 'MISSING', 'ANY', 'DOCUMENTED']) {
            await coverage.selectOption(selection);
            await expect.poll(() => new URL(page.url()).searchParams.get('team_assessment') || 'ANY').toBe(selection);
            if (selection === 'MISSING') await expect(cards).toHaveCount(0);
            else await expect(cards.filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
            await expect(page).toHaveURL(/lifecycle=INCOMPLETE/);
            expect(new URL(page.url()).searchParams.getAll('lifecycle')).toEqual(['INCOMPLETE']);
        }
        await page.reload();
        await expect(coverage).toHaveValue('DOCUMENTED');
        await expect(cards.filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
        await expect(cards).toHaveCount(1);
        expect(new URL(page.url()).searchParams.getAll('lifecycle')).toEqual(['INCOMPLETE']);
    });

    test('Incomplete includes documented teams with Any before and after toggling coverage', async ({ page }) => {
        const cards = page.locator('.vuln-card');
        const coverage = page.getByRole('combobox', { name: 'Assessment for selected teams', exact: true });
        for (const query of ['tag=Security', 'q=team%3ASecurity']) {
            await page.goto('/project/TestProject?lifecycle=INCOMPLETE&' + query);
            await expect(cards.filter({ hasText: 'CVE-PARTIAL' })).toBeVisible({ timeout: 15000 });
            await expect(coverage).toHaveValue('ANY');
            await expect(cards).toHaveCount(1);
            await coverage.selectOption('MISSING');
            await expect(cards).toHaveCount(0);
            await coverage.selectOption('ANY');
            await expect(cards.filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
            await page.reload();
            await expect(cards.filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
        }
    });

    test('plain team search keeps assessment inactive; explicit selection enables it', async ({ page }) => {
        await page.goto('/project/TestProject?q=Security&lifecycle=INCOMPLETE');
        const cards = page.locator('.vuln-card');
        const coverage = page.getByRole('combobox', { name: 'Assessment for selected teams', exact: true });
        await expect(cards.filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
        await expect(coverage).toBeDisabled();
        const teams = page.getByTestId('team-filter-select');
        await teams.locator('summary').focus();
        await page.keyboard.press('Enter');
        await teams.getByRole('checkbox', { name: 'Security', exact: true }).check();
        await expect(coverage).toBeEnabled();
        await coverage.selectOption('MISSING');
        await expect(cards).toHaveCount(0);
        await coverage.selectOption('DOCUMENTED');
        await expect(cards.filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
        await teams.getByRole('checkbox', { name: 'Other', exact: true }).check();
        await expect(coverage).toHaveValue('DOCUMENTED');
        await expect(cards).toHaveCount(0);
        await coverage.selectOption('MISSING');
        await expect(cards.filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
        await teams.getByRole('button', { name: 'Clear teams' }).click();
        await expect(coverage).toBeDisabled();
        await expect(coverage).toHaveValue('ANY');
        await expect(cards.filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
    });

    test('analysts default to not recorded only after selecting a team', async ({ page }) => {
        await page.route('**/auth/me', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ username: 'testuser', role: 'ANALYST' }) }));
        await page.goto('/project/TestProject?q=Security');
        const coverage = page.getByRole('combobox', { name: 'Assessment for selected teams', exact: true });
        await expect(coverage).toBeDisabled();
        await expect(page.locator('.vuln-card')).toHaveCount(2);
        const teams = page.getByTestId('team-filter-select');
        await teams.locator('summary').click();
        await teams.getByRole('checkbox', { name: 'Security', exact: true }).check();
        await expect(coverage).toHaveValue('MISSING');
        await expect(page.locator('.vuln-card')).toHaveCount(1);
        await coverage.selectOption('DOCUMENTED');
        await expect(page.locator('.vuln-card').filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
        await expect(page.locator('.vuln-card')).toHaveCount(1);
        await expect(page).toHaveURL(/team_assessment=DOCUMENTED/);
        await expect.poll(() => new URL(page.url()).searchParams.getAll('teams')).toEqual(['Security']);
        await page.reload();
        await expect(coverage).toHaveValue('DOCUMENTED');
        await expect(page.locator('.vuln-card')).toHaveCount(1);
        await page.getByTestId('workflow-view-all').click();
        await expect(page.locator('.vuln-card')).toHaveCount(4);
    });

    test('ambiguous team tokens require an explicit choice', async ({ page }) => {
        await page.goto('/project/TestProject?q=team%3Ae');
        const choice = page.getByRole('status').filter({ hasText: 'Choose a team for team:e:' });
        await expect(choice).toBeVisible();
        await expect(page.locator('.vuln-card')).toHaveCount(0);
        await choice.getByRole('button', { name: 'Security', exact: true }).click();
        await expect(page.getByTestId('team-filter-select').locator('summary')).toContainText('Security');
        await expect.poll(() => new URL(page.url()).searchParams.getAll('teams')).toEqual(['Security']);
        await expect(choice).toHaveCount(0);
        await expect(page.locator('.vuln-card').filter({ hasText: 'CVE-PARTIAL' })).toBeVisible();
    });

    test('reviewers start with all statuses and can explicitly select approval-ready work', async ({ page }) => {
        await page.goto('/project/TestProject');
        const cards = page.locator('.vuln-card');
        const ready = cards.filter({ hasText: 'CVE-READY' });
        await expect(ready.getByTestId('lifecycle-badge')).toHaveText('Ready for approval');
        await expect(cards).toHaveCount(5);
        await page.getByTestId('workflow-view-approval').click();
        await expect(cards).toHaveCount(1);
        await expect(page.getByRole('button', { name: /^Needs Approval/ })).toHaveCount(0);
        await expect(page.getByRole('button', { name: /^Assessed \(Legacy\)/ })).toHaveCount(0);

        await page.getByRole('button').and(page.getByTitle('Missing assessment coverage or conflicting data that needs repair', { exact: true })).click();
        await expect(cards.filter({ hasText: 'CVE-PARTIAL' }).getByTestId('lifecycle-badge')).toHaveText('Incomplete');
        await expect(cards).toHaveCount(2);
        await page.getByRole('button', { name: /^Ready for Approval\s/ }).click();
        await expect(ready).toHaveCount(0);
        await expect(cards).toHaveCount(1);

        await page.getByRole('button', { name: /^Open\s/ }).click();
        await page.getByRole('button').and(page.getByTitle('Missing assessment coverage or conflicting data that needs repair', { exact: true })).click();
        await expect(cards.filter({ hasText: 'CVE-2023-1234' })).toBeVisible();
        await expect(cards).toHaveCount(1);

        await page.getByRole('button', { name: /^Open\s/ }).click();
        await page.getByRole('button', { name: /^Assessed\s/ }).click();
        await expect(cards.filter({ hasText: 'CVE-2023-ASSESSED' })).toBeVisible();
        const legacy = cards.filter({ hasText: 'CVE-LEGACY' });
        await expect(legacy.getByTestId('lifecycle-badge')).toHaveText('Assessed');
        await expect(legacy.getByTestId('legacy-assessment-badge')).toHaveText('Legacy');
        await expect(cards).toHaveCount(2);
    });

});
