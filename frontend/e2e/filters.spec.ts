import { test, expect, type Page } from '@playwright/test';
import { mockGroupedVulnTask } from './helpers/grouped-task';

const finding = (id: string, team: string) => ({
    project_name: 'TestProject',
    project_version: '1.0',
    project_uuid: 'p1',
    components: [{
        component_name: `${team.toLowerCase()}-lib`,
        component_version: '1.0',
        component_uuid: `c-${id}`,
        finding_uuid: `f-${id}`,
        vulnerability_uuid: `v-${id}`,
        analysis_state: 'NOT_SET',
        tags: [team],
    }],
});

const group = (id: string, lifecycle: string, pending: boolean, cvss: number) => ({
    id,
    title: `${id} title`,
    description: `${id} description`,
    severity: 'HIGH',
    cvss,
    tags: ['Core'],
    list_metadata: {
        lifecycle,
        is_pending: pending,
        is_approval_ready: pending && lifecycle === 'NEEDS_APPROVAL',
        is_open: lifecycle === 'OPEN' || pending,
        technical_state: lifecycle === 'OPEN' ? 'NOT_SET' : 'NOT_AFFECTED',
        dependency_relationship: 'DIRECT',
        assessed_teams: lifecycle === 'OPEN' ? [] : ['Core'],
    },
    affected_versions: [finding(id, 'Core')],
});

// A team's submission while another team is open (Incomplete), one ready for
// approval, one open and one approved.
const groups = [
    group('CVE-2026-0001', 'INCOMPLETE', true, 9.1),
    group('CVE-2026-0002', 'NEEDS_APPROVAL', true, 8.1),
    group('CVE-2026-0003', 'OPEN', false, 7.1),
    group('CVE-2026-0004', 'ASSESSED', false, 6.1),
];

async function mockShell(page: Page) {
    await page.route('**/auth/me', route => route.fulfill({ json: { username: 'reviewer', role: 'REVIEWER' } }));
    await page.route('**/api/version', route => route.fulfill({ json: { version: '1.0.0', build: 'test' } }));
    await page.route('**/api/projects?name=TestProject', route => route.fulfill({
        json: [{ name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' }],
    }));
    await page.route('**/api/tasks/group-vulns*', route => route.fulfill({ json: { task_id: 'task-filters' } }));
    await mockGroupedVulnTask(page, { taskId: 'task-filters', groups });
    await page.route('**/api/settings/mapping', route => route.fulfill({ json: { 'core-lib': 'Core' } }));
    await page.route('**/api/settings/rescore-rules', route => route.fulfill({ json: { transitions: [] } }));
    await page.route('**/api/projects/*/tmrescore/proposals', route => route.fulfill({
        json: { project_name: 'TestProject', session_id: '', scope: 'merged_versions', latest_version: '1.0', analyzed_versions: [], proposals: {} },
    }));
    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
    });
}

const cards = (page: Page) => page.locator('.vuln-card');
const cardIds = async (page: Page) => (await cards(page).allTextContents())
    .map(text => text.match(/CVE-\d{4}-\d{4}/)?.[0])
    .filter(Boolean)
    .sort();

test.describe('Project filters', () => {
    test.beforeEach(async ({ page }) => {
        await mockShell(page);
    });

    test('reviewers start on Awaiting review, which lists every submission not yet approved', async ({ page }) => {
        await page.goto('/project/TestProject');
        const sidebar = page.getByTestId('stats-sidebar');
        const toolbar = page.getByTestId('project-toolbar');
        // The reviewer's default view: Ready for approval and the team
        // submission with another team still open.
        await expect(cards(page)).toHaveCount(2, { timeout: 30000 });
        await expect.poll(() => cardIds(page)).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
        await expect(sidebar.getByTestId('filter-preset-awaiting-review')).toHaveAttribute('aria-pressed', 'true');
        await expect(sidebar.getByTestId('filter-awaiting-review')).toHaveAttribute('aria-pressed', 'true');
        await expect(sidebar.getByTestId('filter-awaiting-review')).toContainText('2');
        await expect(toolbar.getByText('Awaiting review', { exact: true })).toBeVisible();
        // The status chips count the waiting ones.
        await expect(sidebar.getByRole('button', { name: /^Open\s/ })).toContainText('0');
        await expect(sidebar.getByRole('button', { name: /^Incomplete\s/ })).toContainText('1');
        await expect(sidebar.getByRole('button', { name: /^Ready for approval\s/i })).toContainText('1');

        await sidebar.getByTestId('filter-preset-all').click();
        await expect(cards(page)).toHaveCount(4);
        await expect(page).toHaveURL(/awaiting_review=false/);

        const groupRequest = page.waitForRequest(request =>
            request.url().includes('/groups') && new URL(request.url()).searchParams.get('awaiting_review') === 'true');
        await sidebar.getByTestId('filter-preset-awaiting-review').click();
        await groupRequest;
        await expect(cards(page)).toHaveCount(2);
        await expect(page).toHaveURL(/awaiting_review=true/);

        // Narrowed further by status: only the team submission with another team open.
        await sidebar.getByRole('button', { name: /^Ready for approval/i }).click();
        await sidebar.getByRole('button', { name: /^Assessed/i }).click();
        await sidebar.getByRole('button', { name: /^Open/i }).click();
        await expect(cards(page)).toHaveCount(1);
        await expect.poll(() => cardIds(page)).toEqual(['CVE-2026-0001']);
        await expect(sidebar.getByTestId('filter-preset-awaiting-review')).toHaveAttribute('aria-pressed', 'false');

        // The chip removes the filter; the status choice stays.
        await toolbar.getByRole('button', { name: 'Remove Awaiting review' }).click();
        await expect(page).toHaveURL(/awaiting_review=false/);
        await expect(sidebar.getByTestId('filter-awaiting-review')).toHaveAttribute('aria-pressed', 'false');

        // Reset returns to the reviewer's default.
        await sidebar.getByTestId('sidebar-reset-filters').click();
        await expect(cards(page)).toHaveCount(2);
        await expect(sidebar.getByTestId('filter-preset-awaiting-review')).toHaveAttribute('aria-pressed', 'true');
    });

    test('an old needs-approval link opens Awaiting review', async ({ page }) => {
        await page.goto('/project/TestProject?lifecycle=NEEDS_APPROVAL&sort=id&order=asc');
        await expect(cards(page)).toHaveCount(2, { timeout: 30000 });
        await expect(page).toHaveURL(/awaiting_review=true/);
        await expect(page).not.toHaveURL(/NEEDS_APPROVAL/);
    });

    test('a saved link opens Awaiting review, and presets switch the status part', async ({ page }) => {
        await page.goto('/project/TestProject?awaiting_review=true');
        const sidebar = page.getByTestId('stats-sidebar');
        await expect(cards(page)).toHaveCount(2, { timeout: 30000 });
        await expect(sidebar.getByTestId('filter-preset-awaiting-review')).toHaveAttribute('aria-pressed', 'true');

        await sidebar.getByTestId('filter-preset-needs-assessment').click();
        await expect(cards(page)).toHaveCount(2);
        await expect.poll(() => cardIds(page)).toEqual(['CVE-2026-0001', 'CVE-2026-0003']);
        await expect(page).toHaveURL(/awaiting_review=false/);
        await expect(page).toHaveURL(/lifecycle=OPEN&lifecycle=INCOMPLETE/);

        await sidebar.getByTestId('filter-preset-all').click();
        await expect(cards(page)).toHaveCount(4);
        await expect(sidebar.getByTestId('filter-preset-all')).toHaveAttribute('aria-pressed', 'true');
    });
});
