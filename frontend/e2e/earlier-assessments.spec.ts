import { test, expect, type Page } from '@playwright/test';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// One vulnerability whose findings have no assessment, on components
// Dependency-Track recreated: DTVP still holds an assessment of a gone
// finding of it, offered as a draft (Earlier assessments).
const component = (overrides: Record<string, unknown>) => ({
    component_name: 'lib-a',
    component_version: '1.0',
    component_uuid: 'c-1',
    finding_uuid: 'f-1',
    vulnerability_uuid: 'v-1',
    analysis_state: 'NOT_SET',
    analysis_details: '',
    tags: ['Security'],
    ...overrides,
});

const workspaceGroup = {
    id: 'CVE-2023-1234',
    title: 'Parser vulnerability',
    description: Array.from({ length: 12 }, (_, index) =>
        `Paragraph ${index + 1} of the advisory. A crafted document makes the parser read past its buffer, which can leak memory or crash the process.`,
    ).join('\n\n'),
    severity: 'HIGH',
    cvss: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    tags: ['Security'],
    affected_versions: [
        {
            project_name: 'TestProject',
            project_version: '1.0',
            project_uuid: 'p1',
            components: [component({})],
        },
        {
            project_name: 'TestProject',
            project_version: '2.0',
            project_uuid: 'p2',
            components: [
                component({ project_version: '2.0', finding_uuid: 'f-2', component_uuid: 'c-2' }),
                component({
                    project_version: '2.0',
                    finding_uuid: 'f-3',
                    component_uuid: 'c-3',
                    component_name: 'worker',
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
    await routeMappingTeams(page, { 'lib-a': 'Security', worker: 'Security' });
    await page.route('**/api/settings/mapping', route => route.fulfill(json({ 'lib-a': 'Security', worker: 'Security' })));
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
    await page.goto('/project/TestProject');
    const row = page.locator(`.vuln-card[data-group-id="${workspaceGroup.id}"]`);
    await expect(row).toBeVisible({ timeout: 20000 });
    await row.click();
    const inspector = page.getByTestId('vuln-detail-inspector');
    await expect(inspector.getByRole('tab', { name: /Context/ })).toBeVisible({ timeout: 10000 });
    return inspector;
}

test.describe('Earlier assessments', () => {
    test.beforeEach(async ({ page }) => {
        await mockShell(page);
    });

    test('offers what a gone finding held as a draft for an empty assessment, saving nothing', async ({ page }) => {
        const errors = collectConsoleErrors(page);
        let saved = false;
        await page.route('**/api/assessment', route => { saved = true; return route.fallback(); });
        await page.setViewportSize({ width: 1440, height: 900 });
        const inspector = await selectVulnerability(page);
        await inspector.getByRole('tab', { name: /Assessment/ }).click();

        const earlier = inspector.getByTestId('earlier-assessments');
        await expect(earlier).toBeVisible();
        await expect(earlier.getByTestId('earlier-assessment')).toHaveCount(1);
        await expect(earlier.getByTestId('earlier-assessment')).toContainText('unknown component');
        await expect(earlier.getByTestId('earlier-assessment')).toContainText('2.0');
        await expect(earlier.getByTestId('earlier-assessment')).toContainText('NOT AFFECTED');
        await earlier.getByTestId('use-earlier-assessment').click();

        await expect(inspector.locator('#analysis-details-textarea')).toHaveValue('The parser is not shipped.');
        await expect(inspector.locator('#analysis-state-select')).toContainText(/Not Affected/i);
        expect(saved).toBe(false);
        expect(errors).toEqual([]);
    });
});
