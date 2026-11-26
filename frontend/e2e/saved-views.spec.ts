import { test, expect, type Page } from '@playwright/test';
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// ADR 0015: the cutoff on the published or first-attributed date, saved
// views with their short codes, and defaults.

const DEC_2025 = Date.parse('2025-12-01T00:00:00Z');
const OLD = Date.parse('2024-03-05T00:00:00Z');
const JAN = Date.parse('2026-01-10T08:00:00Z');
const MAY = Date.parse('2026-05-01T00:00:00Z');
const JUN = Date.parse('2026-06-01T08:00:00Z');

const finding = (version: string, name: string, attributed: number | null, published: number | null) => ({
    project_name: 'TestProject',
    project_version: version,
    project_uuid: `p-${version}`,
    components: [{
        component_name: name,
        component_version: '1.0',
        component_uuid: `c-${name}-${version}`,
        finding_uuid: `f-${name}-${version}`,
        vulnerability_uuid: `v-${name}`,
        analysis_state: 'NOT_SET',
        first_seen_ms: attributed,
        published_ms: published,
        tags: ['Core'],
    }],
});

const datesOf = (values: Array<[string, number | null]>) => {
    const by_version: Record<string, number[]> = {};
    const unknown: string[] = [];
    for (const [version, value] of values) {
        if (value == null) unknown.push(version);
        else by_version[version] = [value, value];
    }
    return { by_version, unknown };
};

const group = (id: string, cvss: number, published: number | null, versions: Array<[string, string, number | null]>) => ({
    id,
    title: `${id} title`,
    description: `${id} description`,
    severity: 'HIGH',
    cvss,
    tags: ['Core'],
    list_metadata: {
        lifecycle: 'OPEN',
        is_open: true,
        technical_state: 'NOT_SET',
        dependency_relationship: 'DIRECT',
        assessed_teams: [],
        cutoff_dates: {
            published: datesOf(versions.map(([version]) => [version, published])),
            attributed: datesOf(versions.map(([version, , attributed]) => [version, attributed])),
        },
    },
    affected_versions: versions.map(([version, name, attributed]) => finding(version, name, attributed, published)),
});

// Published and attributed early (7.1.1 was uploaded again and keeps the
// date), published and found late, no dates, and an old advisory on a
// component new in 7.1.1.
const groups = [
    group('CVE-2026-1001', 9.1, DEC_2025, [['7.1.0', 'lib-a', JAN], ['7.1.1', 'lib-a', JAN]]),
    group('CVE-2026-1002', 8.1, MAY, [['7.1.1', 'lib-new', JUN]]),
    group('CVE-2026-1003', 7.1, null, [['7.1.1', 'lib-undated', null]]),
    group('CVE-2026-1004', 6.1, OLD, [['7.1.1', 'lib-legacy', JUN]]),
];

interface StoredView {
    code: string;
    scope: string;
    name: string;
    project: string | null;
    query: string;
}

/** An in-memory /api/views, as the server keeps it. */
async function mockViews(page: Page, options: { defaultQuery?: string } = {}) {
    const views: StoredView[] = [];
    let userDefault: string | null = null;
    if (options.defaultQuery != null) {
        views.push({ code: 'defaultv', scope: 'global', name: 'Release freeze', project: null, query: options.defaultQuery });
    }
    let roleDefault: string | null = options.defaultQuery != null ? 'defaultv' : null;
    const publicView = (view: StoredView) => ({
        ...view, owner: 'reviewer', created_at: '', updated_at: '', updated_by: 'reviewer', editable: true,
    });
    const listing = () => {
        const effectiveCode = userDefault || roleDefault;
        const effective = views.find(view => view.code === effectiveCode);
        return {
            views: views.map(publicView),
            defaults: {
                user_project: userDefault, user_all: null, role_project: null, role_all: roleDefault,
                roles: { REVIEWER: { project: null, all: roleDefault }, ANALYST: { project: null, all: null } },
                effective: effective
                    ? { source: userDefault ? 'user' : 'role', code: effective.code, query: effective.query, name: effective.name }
                    : { source: 'builtin', code: null, query: null },
            },
            role: 'REVIEWER',
            can_manage_global: true,
            limits: {},
        };
    };
    const calls: string[] = [];
    await page.route('**/api/views**', async route => {
        const request = route.request();
        const url = new URL(request.url());
        const path = url.pathname.replace(/^.*\/api\/views/, '');
        calls.push(`${request.method()} ${path}`);
        const body = request.postDataJSON?.() ?? null;
        if (request.method() === 'GET' && path === '') return route.fulfill({ json: listing() });
        if (request.method() === 'POST' && path === '') {
            const view = { code: `view${views.length}abc`.slice(0, 8), scope: body.scope, name: body.name, project: body.project, query: body.query };
            views.push(view);
            return route.fulfill({ status: 201, json: publicView(view) });
        }
        if (request.method() === 'PUT' && path === '/defaults') {
            if (body.target === 'user') userDefault = body.code;
            else roleDefault = body.code;
            return route.fulfill({ json: listing().defaults });
        }
        const code = path.slice(1);
        const view = views.find(item => item.code === code);
        if (request.method() === 'GET' && view) return route.fulfill({ json: publicView(view) });
        return route.fulfill({ status: 404, json: { detail: 'View not found' } });
    });
    return { views, calls };
}

async function mockShell(page: Page) {
    const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    await page.route('**/api/cache-status', route => route.fulfill(json({
        fully_cached: true, last_refreshed_at: new Date().toISOString(), projects: 1, active_projects: 1,
        cached_findings: 4, cached_boms: 2, cached_analyses: 0, pending_updates: 0,
    })));
    await routeMappingTeams(page, { 'lib-a': 'Core' });
    await page.route('**/api/metadata', route => route.fulfill(json({ authors: [], urls: {} })));
    await page.route('**/api/analysis-queue/status', route => route.fulfill(json({ counts_by_status: {}, items: [], auto_sweep: null })));
    await page.route('**/api/gone-findings?*', route => route.fulfill(json({ name: 'TestProject', versions: [] })));
    await page.route(url => url.pathname.endsWith('/api/events'), route => route.fulfill({
        status: 200,
        headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' },
        body: 'id: e2e:1\nevent: hello\ndata: {"boot_id":"e2e","seq":1}\n\n',
    }));
    await page.route('**/api/events/poll*', route => route.fulfill(json({ boot_id: 'e2e', cursor: 'e2e:1', events: [], resync: null, more: false })));
    await page.route('**/api/sync/status', route => route.fulfill(json({ scheduler_state: {
        source: { name: 'Dependency-Track', can_request_analysis: true },
        progress: { pass: null, running: [], queued: 0, requested: 0, ranges: null },
    } })));
    await page.route('**/api/events/interest', route => route.fulfill({ status: 204, body: '' }));
    await page.route('**/auth/me', route => route.fulfill({ json: { username: 'reviewer', role: 'REVIEWER' } }));
    await page.route('**/api/version', route => route.fulfill({ json: { version: '1.0.0', build: 'test' } }));
    await page.route('**/api/projects?name=TestProject', route => route.fulfill({
        json: [{ name: 'TestProject', uuid: 'p-7.1.1', version: '7.1.1', classifier: 'APPLICATION' }],
    }));
    await page.route('**/api/tasks/group-vulns*', route => route.fulfill({ json: { task_id: 'task-views' } }));
    await mockGroupedVulnTask(page, { taskId: 'task-views', groups });
    await page.route('**/api/settings/mapping', route => route.fulfill({ json: { 'lib-a': 'Core' } }));
    await page.route('**/api/settings/rescore-rules', route => route.fulfill({ json: { transitions: [] } }));
    await page.route('**/api/projects/*/tmrescore/proposals', route => route.fulfill({
        json: { project_name: 'TestProject', session_id: '', scope: 'merged_versions', latest_version: '7.1.1', analyzed_versions: [], proposals: {} },
    }));
    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
        // Every browser copies without asking for clipboard permission.
        Object.defineProperty(navigator, 'clipboard', {
            configurable: true,
            value: { writeText: async (text: string) => { (window as any).__copied = text; } },
        });
    });
}

const cards = (page: Page) => page.locator('.vuln-card');
const cardIds = async (page: Page) => (await cards(page).allTextContents())
    .map(text => text.match(/CVE-\d{4}-\d{4}/)?.[0])
    .filter(Boolean)
    .sort();

test.describe('Saved views and the first-seen cutoff', () => {
    let failures: string[] = [];
    test.beforeEach(async ({ page }) => {
        failures = [];
        page.on('response', response => {
            // The missing short link answers 404 on purpose.
            if (response.status() >= 400 && !response.url().endsWith('/api/views/missing1')) {
                failures.push(`${response.status()} ${response.url()}`);
            }
        });
        await mockShell(page);
    });
    test.afterEach(() => {
        expect(failures).toEqual([]);
    });

    test('a cutoff on the published or the first-attributed date, with its FDA purpose', async ({ page }) => {
        await mockViews(page);
        await page.goto('/project/TestProject?awaiting_review=false');
        const sidebar = page.getByTestId('stats-sidebar');
        await expect(cards(page)).toHaveCount(4, { timeout: 30000 });

        const basis = sidebar.getByTestId('cutoff-basis');
        await expect(basis.locator('option')).toHaveText(['Published (premarket)', 'First attributed (postmarket)']);
        await sidebar.getByTestId('cutoff-help-toggle').click();
        const help = sidebar.getByTestId('cutoff-help');
        await expect(help.getByTestId('cutoff-help-published')).toContainText('FDA premarket guidance (Feb 2026, §V.A.4)');
        await expect(help.getByTestId('cutoff-help-attributed')).toContainText('within 30 days and fix within 60 days');
        await expect(help).toContainText('A cutoff is a planning aid, not a compliance boundary');
        await expect(help.getByTestId('cutoff-help-docs')).toHaveAttribute('href', /review-workflows\.md#cutoff-and-the-fda-guidance/);
        await sidebar.getByTestId('cutoff-help-toggle').click();

        // Published (the default): what was publicly known by the date.
        await sidebar.getByTestId('cutoff-date').fill('2026-03-01');
        await sidebar.getByTestId('cutoff-date').dispatchEvent('change');
        await expect(page).toHaveURL(/cutoff=2026-03-01/);
        await expect(page).toHaveURL(/cutoff_basis=published/);
        await expect.poll(() => cardIds(page)).toEqual(['CVE-2026-1001', 'CVE-2026-1003', 'CVE-2026-1004']);
        await expect(sidebar.getByTestId('cutoff-unknown')).toContainText('1 listed without a published date');
        const chip = page.getByTestId('filter-chip-cutoff');
        await expect(chip).toContainText('Published by 2026-03-01');
        await expect(chip).toHaveAttribute('title', /premarket/);

        // First attributed: what monitoring knew of by the date.
        await basis.selectOption('attributed');
        await expect(page).toHaveURL(/cutoff_basis=attributed/);
        await expect.poll(() => cardIds(page)).toEqual(['CVE-2026-1001', 'CVE-2026-1003']);
        await expect(chip).toContainText('First attributed by 2026-03-01');
        await expect(chip).toHaveAttribute('title', /postmarket/);

        // The re-uploaded 7.1.1 keeps the date of 7.1.0.
        await page.goto('/project/TestProject?awaiting_review=false&versions=7.1.1&cutoff=2026-03-01&cutoff_basis=attributed');
        await expect.poll(() => cardIds(page), { timeout: 30000 }).toEqual(['CVE-2026-1001', 'CVE-2026-1003']);

        // After the date: what came in since.
        await sidebar.getByTestId('cutoff-mode').selectOption('after');
        await expect(page).toHaveURL(/cutoff_mode=after/);
        await expect.poll(() => cardIds(page)).toEqual(['CVE-2026-1002', 'CVE-2026-1003', 'CVE-2026-1004']);

        // An old attribution-age link is a rolling cutoff on the attribution.
        await page.goto('/project/TestProject?awaiting_review=false&attributed_before_days=14&attribution_mode=older');
        await expect(page).toHaveURL(/cutoff=14d/, { timeout: 30000 });
        await expect(page).toHaveURL(/cutoff_basis=attributed/);
        await expect(page).not.toHaveURL(/attributed_before_days/);
        await expect(sidebar.getByTestId('cutoff-preset-14d')).toHaveAttribute('aria-pressed', 'true');
    });

    test('save the filters as a view, make it the default, reset to it and open its short link', async ({ page }) => {
        const { calls } = await mockViews(page);
        await page.goto('/project/TestProject?awaiting_review=false&cutoff=2026-03-01');
        const sidebar = page.getByTestId('stats-sidebar');
        await expect.poll(() => cardIds(page), { timeout: 30000 }).toEqual(['CVE-2026-1001', 'CVE-2026-1003', 'CVE-2026-1004']);

        // Unsaved filters: the full link.
        await sidebar.getByTestId('saved-views-trigger').click();
        const menu = page.getByTestId('saved-views-menu');
        const copyNotice = menu.getByTestId('saved-views-notice');
        await expect(menu).toContainText('No views yet');
        const originalBounds = await menu.boundingBox();
        await menu.getByTestId('copy-link').click();
        await expect(copyNotice).toHaveText('Link copied');
        expect(await menu.boundingBox()).toEqual(originalBounds);
        const full = await page.evaluate(() => (window as any).__copied as string);
        expect(full).toMatch(/\/project\/TestProject\?.*cutoff=2026-03-01/);
        expect(full).toContain('cutoff_basis=published');

        // Keep the clipboard request pending long enough to check the menu
        // while a second copy is in progress.
        await page.evaluate(() => {
            const writeText = navigator.clipboard.writeText;
            navigator.clipboard.writeText = text => new Promise<void>(resolve => {
                navigator.clipboard.writeText = writeText;
                window.addEventListener('finish-test-copy', () => resolve(writeText(text)), { once: true });
            });
        });
        await menu.getByTestId('copy-link').click();
        await expect(copyNotice).toHaveText('Link copied');
        expect(await menu.boundingBox()).toEqual(originalBounds);
        await page.evaluate(() => window.dispatchEvent(new Event('finish-test-copy')));

        await menu.getByTestId('saved-view-name').fill('Release 7.2 freeze');
        await menu.getByTestId('saved-view-save').click();
        await expect(menu.getByTestId('saved-views-notice')).toContainText('Saved “Release 7.2 freeze”');
        await expect(sidebar.getByTestId('saved-views-trigger')).toContainText('Release 7.2 freeze');
        const viewButton = menu.getByRole('button', { name: /Release 7\.2 freeze/ });
        const code = (await viewButton.getAttribute('data-testid'))!.replace('saved-view-', '');

        await menu.getByTestId(`saved-view-default-${code}`).click();
        await expect(menu.getByTestId(`saved-view-default-${code}`)).toHaveAttribute('aria-pressed', 'true');
        await expect(menu.getByTestId('saved-views-effective')).toHaveText('Release 7.2 freeze');

        // A saved view has a short link.
        await menu.getByTestId(`saved-view-link-${code}`).click();
        await expect(menu.getByTestId('saved-views-notice')).toContainText('Short link copied');
        const short = await page.evaluate(() => (window as any).__copied as string);
        expect(short).toMatch(new RegExp(`/v/${code}$`));
        expect(calls.some(call => call.includes('/links'))).toBe(false);
        await page.keyboard.press('Escape');
        await expect(menu).toBeHidden();

        // Other filters; Reset returns to the default view, not the built-in one.
        await sidebar.getByTestId('cutoff-clear').click();
        await expect(cards(page)).toHaveCount(4);
        await sidebar.getByTestId('sidebar-reset-filters').click();
        await expect(page).toHaveURL(/cutoff=2026-03-01/);
        await expect.poll(() => cardIds(page)).toEqual(['CVE-2026-1001', 'CVE-2026-1003', 'CVE-2026-1004']);

        await page.goto(`/v/${code}`);
        await expect(page).toHaveURL(/\/project\/TestProject\?.*cutoff=2026-03-01/, { timeout: 30000 });
        await expect.poll(() => cardIds(page), { timeout: 30000 }).toEqual(['CVE-2026-1001', 'CVE-2026-1003', 'CVE-2026-1004']);

        await page.goto('/v/missing1');
        await expect(page.getByTestId('short-link')).toContainText('does not exist');
    });

    test('a project opened without filters shows the default view', async ({ page }) => {
        await mockViews(page, { defaultQuery: 'awaiting_review=false&cutoff=2026-03-01&cutoff_basis=attributed' });
        await page.goto('/project/TestProject');
        await expect(page).toHaveURL(/cutoff=2026-03-01/, { timeout: 30000 });
        await expect.poll(() => cardIds(page), { timeout: 30000 }).toEqual(['CVE-2026-1001', 'CVE-2026-1003']);
        const sidebar = page.getByTestId('stats-sidebar');
        await expect(sidebar.getByTestId('saved-views-trigger')).toContainText('Release freeze');

        // A link with filters wins over the default.
        await page.goto('/project/TestProject?awaiting_review=false&versions=7.1.0');
        await expect.poll(() => cardIds(page), { timeout: 30000 }).toEqual(['CVE-2026-1001']);
        await expect(page).not.toHaveURL(/cutoff=/);
    });
});
