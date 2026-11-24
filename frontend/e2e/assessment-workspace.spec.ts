import { test, expect, type Page } from '@playwright/test';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// One vulnerability, three findings in two versions, two different Global
// assessments: enough context to scroll and a comparison to open.
const component = (overrides: Record<string, unknown>) => ({
    component_name: 'lib-a',
    component_version: '1.0',
    component_uuid: 'c-1',
    finding_uuid: 'f-1',
    vulnerability_uuid: 'v-1',
    analysis_state: 'NOT_AFFECTED',
    analysis_details: '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nThe parser is not shipped.',
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
                    analysis_state: 'EXPLOITABLE',
                    analysis_details: '--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] ---\nReachable in the worker.',
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

test.describe('Assessment workspace', () => {
    test.beforeEach(async ({ page }) => {
        await mockShell(page);
    });

    test('shows the context beside the form, scrolls them apart and keeps edits', async ({ page }) => {
        const errors = collectConsoleErrors(page);
        await page.setViewportSize({ width: 1440, height: 900 });
        const inspector = await selectVulnerability(page);

        await inspector.getByTestId('workspace-toggle').click();
        const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${workspaceGroup.id}` });
        await expect(workspace).toBeVisible();
        await expect(workspace).toHaveAttribute('data-workspace', 'open');
        await expect(workspace.getByTestId('workspace-assessment-heading')).toBeFocused();
        await expect(workspace.getByRole('tab')).toHaveCount(2);

        const description = workspace.getByTestId('vuln-description');
        const decision = workspace.getByTestId('assessment-decision-section');
        await expect(description).toBeInViewport();
        await expect(decision).toBeInViewport();

        // The two panes scroll on their own.
        const contextPane = workspace.getByTestId('workspace-context-pane');
        const assessmentPane = workspace.getByTestId('workspace-assessment-pane');
        await contextPane.evaluate(element => { element.scrollTop = 400; });
        await expect.poll(() => contextPane.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
        expect(await assessmentPane.evaluate(element => element.scrollTop)).toBe(0);

        // The comparison opens on the left; the form stays in view.
        await workspace.getByTestId('card-differences-open').click();
        await expect(workspace.getByTestId('finding-differences')).toBeVisible();
        await expect(decision).toBeInViewport();

        // A menu opens above the workspace, and the first Esc closes only the menu.
        await workspace.locator('#analysis-state-select').click();
        const menu = page.getByTestId('custom-select-menu');
        await expect(menu).toBeVisible();
        const box = (await menu.boundingBox())!;
        const onTop = await page.evaluate(({ x, y }) => {
            const element = document.elementFromPoint(x, y);
            return !!element?.closest('[data-testid="custom-select-menu"]');
        }, { x: box.x + box.width / 2, y: box.y + Math.min(box.height / 2, 20) });
        expect(onTop).toBe(true);

        await page.keyboard.press('Escape');
        await expect(menu).toHaveCount(0);
        await expect(workspace).toBeVisible();

        await page.keyboard.press('Escape');
        await expect(page.getByRole('dialog', { name: /Assessment workspace/ })).toHaveCount(0);
        await expect(inspector).toHaveAttribute('data-workspace', 'closed');
        await expect(inspector.getByRole('tab', { name: /Assessment/ })).toHaveAttribute('aria-selected', 'true');
        await expect(inspector.getByTestId('workspace-toggle')).toBeFocused();

        // Edits survive entering the workspace again.
        const details = inspector.locator('#analysis-details-textarea');
        await details.fill('Reachable only with a crafted document.');
        await inspector.getByTestId('workspace-toggle').click();
        await expect(workspace).toBeVisible();
        await expect(workspace.locator('#analysis-details-textarea')).toHaveValue('Reachable only with a crafted document.');
        // Esc in a text field stays with the field.
        await workspace.locator('#analysis-details-textarea').press('Escape');
        await expect(workspace).toBeVisible();

        // A click on plain text keeps focus in the workspace, so Esc still leaves it.
        await workspace.getByTestId('vuln-description').click();
        await page.keyboard.press('Escape');
        await expect(inspector).toHaveAttribute('data-workspace', 'closed');

        // Esc on a checkbox is not Esc in a text field.
        await inspector.getByTestId('workspace-toggle').click();
        await expect(workspace).toBeVisible();
        const evidenceReviewed = workspace.getByRole('checkbox', { name: 'Evidence reviewed' });
        await evidenceReviewed.focus();
        await evidenceReviewed.press('Space');
        await expect(evidenceReviewed).toBeChecked();
        await page.keyboard.press('Escape');
        await expect(inspector).toHaveAttribute('data-workspace', 'closed');

        expect(errors).toEqual([]);
    });

    test('keeps Tab inside the workspace', async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 });
        const inspector = await selectVulnerability(page);
        await inspector.getByTestId('workspace-toggle').click();
        const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${workspaceGroup.id}` });
        await expect(workspace).toBeVisible();

        const insideAfterTab = async (shift: boolean) => {
            await page.keyboard.press(shift ? 'Shift+Tab' : 'Tab');
            return workspace.evaluate(element => element.contains(document.activeElement));
        };
        // Tab from the last control wraps to the first, Shift+Tab back to the last.
        const lastFocused = await workspace.evaluate(element => {
            const focusable = [...element.querySelectorAll<HTMLElement>(
                'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
            )].filter(candidate => candidate.tabIndex !== -1 && candidate.getClientRects().length > 0);
            const last = focusable[focusable.length - 1];
            last.setAttribute('data-e2e-last', 'true');
            last.focus();
            return document.activeElement === last;
        });
        expect(lastFocused).toBe(true);
        expect(await insideAfterTab(false)).toBe(true);
        expect(await insideAfterTab(true)).toBe(true);
        await expect(workspace.locator('[data-e2e-last]')).toBeFocused();
        // Focus that escaped to the body comes back on the next Tab.
        await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
        expect(await insideAfterTab(false)).toBe(true);
    });

    test('opens from the overlay below the side-panel breakpoint', async ({ page }) => {
        const errors = collectConsoleErrors(page);
        await page.setViewportSize({ width: 1300, height: 800 });
        const inspector = await selectVulnerability(page);

        await inspector.getByTestId('workspace-toggle').click();
        const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${workspaceGroup.id}` });
        await expect(workspace).toBeVisible();
        await expect(workspace.getByTestId('vuln-description')).toBeInViewport();
        await expect(workspace.getByTestId('assessment-decision-section')).toBeInViewport();

        // Shrinking below 1280px ends the workspace; focus moves to the Assessment tab.
        await workspace.locator('#analysis-details-textarea').focus();
        await page.setViewportSize({ width: 1200, height: 800 });
        await expect(inspector).toHaveAttribute('data-workspace', 'closed');
        await expect(inspector.getByRole('tab', { name: /Assessment/ })).toBeFocused();

        expect(errors).toEqual([]);
    });

    test('is not offered below 1280px', async ({ page }) => {
        const errors = collectConsoleErrors(page);
        await page.setViewportSize({ width: 1200, height: 800 });
        const inspector = await selectVulnerability(page);

        await expect(inspector.getByRole('tab', { name: /Assessment/ })).toBeVisible();
        await expect(inspector.getByTestId('workspace-toggle')).toHaveCount(0);

        expect(errors).toEqual([]);
    });
});
