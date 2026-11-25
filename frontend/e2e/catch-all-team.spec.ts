import { test, expect, type Page } from '@playwright/test';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// ViewPoint_Product 6.15.0 (2026-11-23): tar reaches the product through
// stats-app, which the team mapping does not know (only vp-stats-app), so the
// catch-all '*' gives it the team Unknown. The card says so and why.
const LONG = 'com.example.platform.integration.very-long-artifact-name-for-the-viewpoint-statistics-application-bundle';
const component = (overrides: Record<string, unknown>) => ({
    component_name: 'tar',
    component_version: '2.2.2',
    component_uuid: 'c-1',
    finding_uuid: 'f-1',
    vulnerability_uuid: 'v-1',
    analysis_state: 'NOT_SET',
    analysis_details: '',
    tags: ['Unknown'],
    dependency_chains: ['tar -> node-gyp -> node-sass -> stats-app -> ViewPoint_Product'],
    ...overrides,
});

const workspaceGroup = {
    id: 'CVE-2024-28863',
    title: 'node-tar denial of service',
    description: 'A crafted archive makes node-tar exhaust memory.',
    severity: 'MEDIUM',
    cvss: 6.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H',
    tags: ['Unknown', 'S-Web'],
    affected_versions: [
        {
            project_name: 'ViewPoint_Product',
            project_version: '6.15.0',
            project_uuid: 'p1',
            components: [
                component({}),
                component({
                    finding_uuid: 'f-2', component_uuid: 'c-2', component_name: LONG, component_version: '10.20.30-SNAPSHOT',
                    tags: ['S-Web'],
                    dependency_chains: [`${LONG} -> vp-stats-app -> ViewPoint_Product`],
                }),
            ],
        },
    ],
};

const findingsByUuid = new Map(
    workspaceGroup.affected_versions.flatMap(version => version.components.map(entry => [entry.finding_uuid, entry] as const)),
);

async function mockShell(page: Page) {
    const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

    await page.route('**/auth/me', route => route.fulfill(json({ username: 'rita', role: 'REVIEWER' })));
    await page.route('**/api/version', route => route.fulfill(json({ version: '1.0.0', build: 'test' })));
    await page.route('**/api/cache-status', route => route.fulfill(json({
        fully_cached: true, last_refreshed_at: new Date().toISOString(), projects: 1, active_projects: 1,
        cached_findings: 3, cached_boms: 2, cached_analyses: 0, pending_updates: 0,
    })));
    await page.route('**/api/projects?name=*', route => route.fulfill(json([
        { name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' },
        { name: 'TestProject', uuid: 'p2', version: '2.0', classifier: 'APPLICATION' },
    ])));
    await routeMappingTeams(page, { '*': 'Unknown', 'vp-stats-app': 'S-Web' });
    await page.route('**/api/settings/mapping', route => route.fulfill(json({ '*': 'Unknown', 'vp-stats-app': 'S-Web' })));
    await page.route('**/api/settings/rescore-rules', route => route.fulfill(json({ transitions: [] })));
    await page.route('**/api/projects/*/tmrescore/proposals', route => route.fulfill(json({ proposals: {} })));
    await page.route('**/api/ssvc/models', route => route.fulfill(json({ models: [ssvcModel] })));
    await page.route('**/api/ssvc/exploitation**', route => route.fulfill(json({
        enabled: true, auto_fill: false, retry_after: 0, suggestion: null, sources: [],
    })));
    await page.route('**/api/known-users', route => route.fulfill(json(['rita'])));
    await page.route('**/api/metadata', route => route.fulfill(json({ authors: [], urls: {} })));
    await page.route('**/api/analysis-queue/status', route => route.fulfill(json({ counts_by_status: {}, items: [], auto_sweep: null })));
    await page.route('**/api/projects/*/vulnerabilities/*/analysis-results**', route => route.fulfill(json([])));
    await page.route('**/api/gone-findings?*', route => route.fulfill(json({ name: 'TestProject', versions: [] })));
    await page.route('**/api/project/*/earlier-assessments?*', route => {
        const project = new URL(route.request().url()).pathname.split('/').at(-2);
        route.fulfill(json({ earlier: project !== 'p2' ? [] : [{
            component_uuid: '36977e35', component_name: null, component_version: null, component_purl: null,
            vulnerability_uuid: 'v-1', vuln_id: 'CVE-2023-1234', alias: false, gone_at: '2026-11-22T09:42:20Z',
            state: 'NOT_AFFECTED', justification: 'CODE_NOT_PRESENT', response: 'WILL_NOT_FIX', suppressed: false,
            date: '2026-08-11T15:27:11Z',
            teams: [{ team: 'General', state: 'NOT_AFFECTED', justification: 'CODE_NOT_PRESENT', details: 'The parser is not shipped.' }],
            details: 'The parser is not shipped.', preview: 'The parser is not shipped.',
        }] }));
    });
    // The live-update stream: one hello, then the stream ends and is reopened later.
    await page.route(url => url.pathname.endsWith('/api/events'), route => route.fulfill({
        status: 200,
        headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' },
        body: 'id: e2e:1\nevent: hello\ndata: {"boot_id":"e2e","seq":1}\n\n',
    }));
    await page.route('**/api/events/poll*', route => route.fulfill(json({ boot_id: 'e2e', cursor: 'e2e:1', events: [], resync: null, more: false })));
    // The leader tab reports the products the tabs show (ADR 0004 step 4a).
    // The Sync menu reads what the background sync does now.
    await page.route('**/api/sync/status', route => route.fulfill(json({ scheduler_state: {
        source: { name: 'Dependency-Track', can_request_analysis: true },
        progress: { pass: null, running: [], queued: 0, requested: 0, ranges: null },
    } })));
    await page.route('**/api/events/interest', route => route.fulfill({ status: 204, body: '' }));
    await page.route('**/api/projects/*/vulnerabilities/*/code-evidence**', route => route.fulfill(json({ items: [], withdrawn_count: 0 })));

    await page.route('**/api/tasks/group-vulns*', route => route.fulfill(json({ task_id: 'task-ws' })));
    await mockGroupedVulnTask(page, { taskId: 'task-ws', groups: [workspaceGroup] });
    // The inspector loads the full group; registered last, so it wins.
    await page.route('**/api/tasks/task-ws/groups/*', route => route.fulfill(json(workspaceGroup)));

    await page.route('**/api/assessments/details', async (route) => {
        const body = route.request().postDataJSON();
        await route.fulfill(json((body.instances || []).map((instance: any) => {
            const finding = findingsByUuid.get(instance.finding_uuid);
            return {
                finding_uuid: instance.finding_uuid,
                project_uuid: instance.project_uuid,
                component_uuid: instance.component_uuid,
                vulnerability_uuid: instance.vulnerability_uuid,
                analysis: {
                    state: finding?.analysis_state || 'NOT_SET',
                    analysisState: finding?.analysis_state || 'NOT_SET',
                    isSuppressed: false,
                    analysisDetails: finding?.analysis_details || '',
                    analysisComments: [],
                },
            };
        })));
    });

    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
    });
}

const collectConsoleErrors = (page: Page) => {
    const errors: string[] = [];
    page.on('console', message => {
        if (message.type() === 'error') errors.push(message.text());
    });
    page.on('pageerror', error => errors.push(error.message));
    // Name the request behind a "Failed to load resource" message.
    page.on('response', response => {
        if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
    });
    return errors;
};

async function selectVulnerability(page: Page) {
    // A reviewer starts on Awaiting review; this test needs every vulnerability.
    await page.goto('/project/TestProject?awaiting_review=false');
    const row = page.locator(`.vuln-card[data-group-id="${workspaceGroup.id}"]`);
    await expect(row).toBeVisible({ timeout: 20000 });
    await row.click();
    const inspector = page.getByTestId('vuln-detail-inspector');
    await expect(inspector.getByRole('tab', { name: /Context/ })).toBeVisible({ timeout: 10000 });
    return inspector;
}

test.describe('Catch-all team', () => {
    test.beforeEach(async ({ page }) => {
        await mockShell(page);
    });

    test('shows the catch-all team where the vulnerability was found and what triggered it', async ({ page }) => {
        const errors = collectConsoleErrors(page);
        await page.setViewportSize({ width: 1280, height: 900 });
        const inspector = await selectVulnerability(page);

        const whereFound = inspector.getByTestId('where-found');
        const teams = whereFound.getByTestId('finding-matrix-team');
        await expect(teams).toHaveText(['S-Web', 'Unknown · catch-all']);

        const triggering = whereFound.getByTestId('triggering-team-component');
        const catchAll = triggering.filter({ hasText: 'stats-app' }).first();
        await expect(catchAll).toContainText('under ViewPoint_Product 6.15.0');
        await expect(catchAll).toContainText("Unknown; no team mapping, catch-all '*'");
        await expect(triggering.filter({ hasText: 'tar' }).first()).toHaveAttribute('data-catch-all', 'true');

        // One list of mapped components; the matrix carries each component's team.
        await expect(whereFound.getByText('Affected components with team tags')).toHaveCount(0);

        // Long names scroll instead of being cut off.
        const list = whereFound.getByTestId('triggering-team-components').locator('div').first();
        expect(await list.evaluate(element => getComputedStyle(element).overflowX)).toBe('auto');
        expect(errors).toEqual([]);
    });
});
