import { test, expect, type Locator, type Page } from '@playwright/test';
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
    cwes: [{ id: 125, name: 'Out-of-bounds Read' }],
    recommendation: 'Upgrade the parser to 3.0.',
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
    // A reviewer starts on Awaiting review; this test needs every vulnerability.
    await page.goto('/project/TestProject?awaiting_review=false');
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

    for (const width of [430, 1440]) {
        test(`keeps team selection and assessment actions reachable at ${width}×560`, async ({ page }) => {
            await page.setViewportSize({ width, height: 560 });
            const inspector = await selectVulnerability(page);
            const nav = inspector.locator('[data-vuln-card-sticky-nav]');
            const lastParagraph = inspector.getByTestId('vuln-description').getByText(/Paragraph 12 of the advisory/);
            await lastParagraph.scrollIntoViewIfNeeded();
            await expect(nav).toBeInViewport({ ratio: 1 });

            await nav.getByRole('tab', { name: /Assessment/ }).click();
            const team = inspector.getByTestId('review-team-tab').filter({ hasText: 'Security' });
            await expect(team).toBeInViewport({ ratio: 1 });
            await team.click();
            await expect(team).toHaveAttribute('aria-pressed', 'true');

            const rationale = inspector.locator('#analysis-details-textarea');
            await rationale.scrollIntoViewIfNeeded();
            await rationale.fill('Reviewed for Security.');
            await expect(rationale).toBeInViewport();
            await expect(nav.getByTestId('assessment-actions')).toBeInViewport({ ratio: 1 });
            await nav.getByRole('tab', { name: /Context/ }).click();
            await nav.getByRole('tab', { name: /Assessment/ }).click();
            await expect(team).toBeInViewport({ ratio: 1 });
            await expect(rationale).toHaveValue('Reviewed for Security.');
        });
    }

    test('shows every team in a compact card before and after opening the desktop inspector', async ({ page }) => {
        const teams = [
            'Application Security', 'Client Platform', 'Database Reliability', 'Embedded Systems',
            'Infrastructure', 'Release Engineering', 'Security', 'System Verification',
        ];
        const group = {
            ...workspaceGroup,
            tags: teams,
            affected_versions: workspaceGroup.affected_versions.map(version => ({
                ...version,
                components: version.components.map(component => ({ ...component, tags: teams })),
            })),
        };
        await mockGroupedVulnTask(page, { taskId: 'task-ws', groups: [group] });
        await page.route('**/api/tasks/task-ws/groups/*', route => route.fulfill(json(group)));

        const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
        const tags = row.getByTestId('team-tag');
        await page.setViewportSize({ width: 430, height: 900 });
        await page.goto('/project/TestProject?awaiting_review=false');
        await expect(tags).toHaveText(teams);
        for (const tag of await tags.all()) await expect(tag).toBeInViewport({ ratio: 1 });

        await page.setViewportSize({ width: 1440, height: 900 });
        await row.click();
        const inspector = page.getByTestId('vuln-detail-inspector');
        await inspector.getByRole('tab', { name: /Assessment/ }).click();
        await expect(inspector.getByTestId('review-team-tab')).toHaveText(teams);
        for (const tag of await tags.all()) await expect(tag).toBeInViewport({ ratio: 1 });
    });

    test('keeps the full ID and the severity comparison readable beside the inspector', async ({ page }) => {
        await page.clock.setFixedTime(new Date('2026-11-26T12:00:00Z'));
        const published = Date.UTC(2024, 4, 20);
        const attributed = Date.UTC(2026, 2, 14);
        const group = {
            ...workspaceGroup,
            original_severity: 'CRITICAL',
            rescored_cvss: 5.4,
            affected_versions: workspaceGroup.affected_versions.map(version => ({
                ...version,
                components: version.components.map(finding => ({ ...finding, published_ms: published, attributed_on: attributed })),
            })),
            list_metadata: {
                assessed_teams: ['Security'], mcp_assessment_teams: ['Security'],
                cutoff_dates: { published: { by_version: { '2.0': [published, published] }, unknown: [] } },
            },
        };
        await mockGroupedVulnTask(page, { taskId: 'task-ws', groups: [group] });
        await page.route('**/api/tasks/task-ws/groups/*', route => route.fulfill(json(group)));
        await page.setViewportSize({ width: 1440, height: 900 });
        const inspector = await selectVulnerability(page);
        const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
        const listCardBounds = await row.boundingBox();
        const detailCardBounds = await inspector.locator('.vuln-card').first().boundingBox();
        expect(listCardBounds?.y).toBeCloseTo(detailCardBounds!.y);

        await expect(row.getByTestId('vuln-primary-id')).toHaveText(group.id);
        await expect(row.getByTestId('vuln-primary-id')).toBeInViewport({ ratio: 1 });
        await expect(row.getByTestId('severity-badge')).toHaveText('Critical');
        await expect(row.getByTestId('rescored-severity-badge')).toHaveText('Medium');
        await expect(row.getByTestId('team-mcp')).toHaveText('MCP');
        const listDates = row.getByTestId('vulnerability-dates');
        await expect(listDates.getByTitle('Published 2024-05-20')).toContainText('Published 2y');
        await expect(listDates.getByTitle('First attributed 2026-03-14')).toContainText('First attributed 8mo');
        await expect(listDates.getByTitle('Published 2024-05-20').locator('svg[aria-hidden="true"]')).toBeVisible();
        await expect(listDates.getByTitle('First attributed 2026-03-14').locator('svg[aria-hidden="true"]')).toBeVisible();
        const detailDates = inspector.getByTestId('vulnerability-dates');
        await expect(detailDates.getByTitle('Published 2024-05-20')).toHaveText('Published 2024-05-20');
        await expect(detailDates.getByTitle('First attributed 2026-03-14')).toHaveText('First attributed 2026-03-14');
        await expect(inspector.getByTestId('team-tag')).toHaveCount(0);
        await expect(inspector.getByTestId('rescored-value-badge')).toHaveText('5.4');

        const labels = row.getByTestId('header-cvss-block').locator('dt');
        const original = await labels.nth(1).boundingBox();
        const rescored = await labels.nth(2).boundingBox();
        expect(original?.y).toBe(rescored?.y);
        expect(rescored?.x).toBeGreaterThan(original!.x);

        const header = inspector.getByTestId('expanded-vulnerability-header');
        for (const surface of [row, header]) {
            const headings = surface.getByTestId('header-cvss-block').locator('dt');
            const originalScore = await surface.getByTestId('base-score-value').boundingBox();
            const rescoredScore = await surface.getByTestId('rescored-value-badge').boundingBox();
            expect(originalScore?.x).toBeCloseTo((await headings.nth(1).boundingBox())!.x);
            expect(rescoredScore?.x).toBeCloseTo((await headings.nth(2).boundingBox())!.x);
        }
        const scores = await header.getByTestId('header-cvss-block').boundingBox();
        const findingSummary = header.getByTestId('instance-count');
        const componentSummary = header.getByTestId('component-summary');
        await expect(findingSummary.locator('svg')).toBeVisible();
        await expect(componentSummary.locator('svg')).toBeVisible();
        const findings = await findingSummary.boundingBox();
        const components = await componentSummary.boundingBox();
        const publicationDate = await detailDates.getByTitle('Published 2024-05-20').boundingBox();
        const attributionDate = await detailDates.getByTitle('First attributed 2026-03-14').boundingBox();
        expect(publicationDate?.x).toBeCloseTo(components!.x);
        expect(attributionDate?.x).toBeCloseTo(findings!.x);
        expect(publicationDate?.y).toBeCloseTo(attributionDate!.y);
        expect(publicationDate!.y).toBeGreaterThan(findings!.y);
        expect(scores).not.toBeNull();
        expect(findings).not.toBeNull();
        expect(findings!.x).toBeGreaterThan(scores!.x + scores!.width);
        expect(findings!.y).toBeLessThan(scores!.y + scores!.height);
        expect(findings!.y + findings!.height).toBeGreaterThan(scores!.y);

        const baseColour = await page.evaluate(() => {
            const swatch = document.createElement('div');
            swatch.style.backgroundColor = 'var(--color-gray-800)';
            document.body.append(swatch);
            const colour = getComputedStyle(swatch).backgroundColor;
            swatch.remove();
            return colour;
        });
        const lightness = (colour: string) => Number(/^oklch\(([\d.]+)/.exec(colour)?.[1]);
        const rowColour = await row.evaluate(el => getComputedStyle(el).backgroundColor);
        expect(rowColour).not.toBe(baseColour);
        expect(lightness(rowColour)).toBeCloseTo(lightness(baseColour), 3);
        await expect(header).toHaveCSS('background-color', rowColour);

        await row.hover();
        await expect(row).toHaveCSS('background-color', rowColour);
        await expect(row).toHaveCSS('filter', 'none');
    });

    test('summarises the vulnerability before the decision, folded in the workspace', async ({ page }) => {
        const errors = collectConsoleErrors(page);
        await page.setViewportSize({ width: 1440, height: 900 });
        const inspector = await selectVulnerability(page);

        // The summary is open in the Assessment tab.
        await inspector.getByRole('tab', { name: /Assessment/ }).click();
        const about = inspector.getByTestId('vuln-about');
        await expect(about).toBeVisible();
        await expect(about.getByTestId('vuln-about-title')).toHaveText('Parser vulnerability');
        const description = about.getByTestId('vuln-about-description');
        await expect(description).toContainText('Paragraph 1 of the advisory.');
        const clamped = await description.evaluate(element => element.scrollHeight > element.clientHeight + 1);
        expect(clamped).toBe(true);
        await about.getByTestId('vuln-about-more').click();
        await expect(about.getByTestId('vuln-about-more')).toHaveText('Show less');
        expect(await description.evaluate(element => element.scrollHeight <= element.clientHeight + 1)).toBe(true);
        await expect(about.getByTestId('vuln-about-cwe')).toContainText('CWE-125 Out-of-bounds Read');
        await expect(about.getByTestId('vuln-about-fix')).toContainText('Upgrade the parser to 3.0.');
        await expect(about.getByTestId('vuln-about-attack')).toContainText('network, low complexity, no privileges, no user interaction');
        await expect(about.getByTestId('vuln-about-affects')).toContainText('in 2 versions');

        // In the workspace the context shows the description; the summary is one line.
        await inspector.getByTestId('workspace-toggle').click();
        const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${workspaceGroup.id}` });
        await expect(workspace).toBeVisible();
        const folded = workspace.getByTestId('vuln-about');
        await expect(folded.getByTestId('vuln-about-toggle')).toHaveAttribute('aria-expanded', 'false');
        await expect(folded).toContainText('Parser vulnerability');
        await expect(folded.getByTestId('vuln-about-description')).toHaveCount(0);
        await expect(workspace.getByTestId('assessment-decision-section')).toBeInViewport();
        await folded.getByTestId('vuln-about-toggle').click();
        await expect(folded.getByTestId('vuln-about-description')).toBeVisible();

        expect(errors).toEqual([]);
    });

    test('a reviewer switches team to Global and back with a team filter and an edited draft', async ({ page }) => {
        const errors = collectConsoleErrors(page);
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('/project/TestProject?teams=Security');
        const row = page.locator(`.vuln-card[data-group-id="${workspaceGroup.id}"]`);
        await expect(row).toBeVisible({ timeout: 20000 });
        await row.click();
        const inspector = page.getByTestId('vuln-detail-inspector');
        await inspector.getByRole('tab', { name: /Assessment/ }).click();

        const scope = inspector.getByTestId('assessment-scope');
        const globalTab = scope.getByRole('button', { name: 'Global', exact: true });
        const teamTab = scope.getByTestId('review-team-tab').filter({ hasText: 'Security' });
        // The team filter preselects its team on first open.
        await expect(teamTab).toHaveAttribute('aria-pressed', 'true');
        const details = inspector.locator('#analysis-details-textarea');
        await details.fill('Security draft.');

        await globalTab.click();
        await expect(globalTab).toHaveAttribute('aria-pressed', 'true');
        await expect(inspector.getByTestId('global-cvss-rescoring')).toBeVisible();
        await expect(details).not.toHaveValue('Security draft.');
        // It stays there: no snap back after a moment, nor after another tab.
        await page.waitForTimeout(300);
        await expect(globalTab).toHaveAttribute('aria-pressed', 'true');
        await inspector.getByRole('tab', { name: /Context/ }).click();
        await inspector.getByRole('tab', { name: /Assessment/ }).click();
        await expect(globalTab).toHaveAttribute('aria-pressed', 'true');

        // In the workspace too.
        await inspector.getByTestId('workspace-toggle').click();
        const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${workspaceGroup.id}` });
        await expect(workspace).toBeVisible();
        await expect(workspace.getByTestId('assessment-scope').getByRole('button', { name: 'Global', exact: true }))
            .toHaveAttribute('aria-pressed', 'true');

        // Back to the team: its draft is kept.
        await workspace.getByTestId('assessment-scope').getByTestId('review-team-tab').filter({ hasText: 'Security' }).click();
        await expect(workspace.locator('#analysis-details-textarea')).toHaveValue('Security draft.');
        expect(errors).toEqual([]);
    });

    for (const width of [1280, 1440, 1920]) {
        test(`shows every CVSS vector and metric without clipping at ${width}px`, async ({ page }, testInfo) => {
            await page.setViewportSize({ width, height: 1000 });
            const inspector = await selectVulnerability(page);
            await inspector.getByRole('tab', { name: /Assessment/ }).click();
            // The stored assessment has loaded into the form before the edit.
            await expect(inspector.locator('#analysis-details-textarea')).toHaveValue('The parser is not shipped.');
            await page.waitForLoadState('networkidle');
            await inspector.locator('#cvss-vector-input')
                .fill('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAC:H/MPR:H/MUI:R/MC:L/MI:L/CR:H/IR:M/AR:L');

            const unclipped = async (scope: Locator, name: string) => {
                const display = scope.getByTestId('cvss-vector-display');
                await expect(display.getByTestId('cvss-vector-row')).toHaveCount(2);
                await display.scrollIntoViewIfNeeded();
                await display.screenshot({ path: testInfo.outputPath(`${name}-${width}.png`) });
                // Nothing overflows the display, and every section lies inside it.
                expect(await display.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
                const box = (await display.boundingBox())!;
                for (const section of await display.getByTestId('cvss-metric-section').all()) {
                    const inner = (await section.boundingBox())!;
                    expect(inner.x).toBeGreaterThanOrEqual(box.x - 1);
                    expect(inner.x + inner.width).toBeLessThanOrEqual(box.x + box.width + 1);
                }
                for (const row of await display.getByTestId('cvss-vector-row').all()) {
                    expect(await row.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
                }
                await expect(display.getByTestId('cvss-metric-section')).toHaveCount(2);
            };
            await unclipped(inspector, 'card');

            await inspector.getByTestId('workspace-toggle').click();
            const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${workspaceGroup.id}` });
            await expect(workspace).toBeVisible();
            await unclipped(workspace, 'workspace');
        });
    }

    test('lines up the CVSS metric groups that sit side by side', async ({ page }) => {
        // One CVSS 4.0 vector: narrow tables under long group titles.
        const group40 = { ...workspaceGroup, cvss_vector: 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' };
        await mockGroupedVulnTask(page, { taskId: 'task-ws', groups: [group40] });
        await page.route('**/api/tasks/task-ws/groups/*', route => route.fulfill(json(group40)));
        await page.setViewportSize({ width: 1280, height: 1000 });
        const inspector = await selectVulnerability(page);
        await inspector.getByRole('tab', { name: /Assessment/ }).click();

        const display = inspector.getByTestId('cvss-vector-display');
        await expect(display.getByTestId('cvss-vector-row')).toHaveCount(1);
        await display.scrollIntoViewIfNeeded();
        const sections = await display.getByTestId('cvss-metric-section').all();
        expect(sections.length).toBe(3);
        // Groups on one line share their header row, so the cells line up.
        const headerTops = new Map<number, number[]>();
        for (const section of sections) {
            const top = Math.round((await section.boundingBox())!.y);
            const header = Math.round((await section.locator('thead').boundingBox())!.y);
            headerTops.set(top, [...(headerTops.get(top) || []), header]);
        }
        for (const headers of headerTops.values()) {
            expect(Math.max(...headers) - Math.min(...headers)).toBeLessThanOrEqual(1);
        }
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

    test('keeps the selected team and unsaved rationale across responsive inspector moves', async ({ page }) => {
        const errors = collectConsoleErrors(page);
        await page.setViewportSize({ width: 1280, height: 900 });
        const inspector = await selectVulnerability(page);
        await inspector.getByRole('tab', { name: /Assessment/ }).click();
        const team = inspector.getByTestId('review-team-tab').filter({ hasText: 'Security' });
        await team.click();
        const details = inspector.locator('#analysis-details-textarea');
        await details.fill('Security rationale survives a viewport change.');
        // DOM identity also catches remounts that restore only a few fields.
        await details.evaluate(element => { element.setAttribute('data-resize-draft', 'original'); });
        for (const width of [1600, 430, 1600]) {
            await page.setViewportSize({ width, height: 900 });
            await expect(team).toHaveAttribute('aria-pressed', 'true');
            await expect(details).toHaveValue('Security rationale survives a viewport change.');
            await expect(details).toHaveAttribute('data-resize-draft', 'original');
        }
        await inspector.getByTestId('workspace-toggle').click();
        const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${workspaceGroup.id}` });
        await expect(workspace.getByTestId('review-team-tab').filter({ hasText: 'Security' })).toHaveAttribute('aria-pressed', 'true');
        await expect(workspace.locator('#analysis-details-textarea')).toHaveValue('Security rationale survives a viewport change.');
        await expect(workspace.locator('#analysis-details-textarea')).toHaveAttribute('data-resize-draft', 'original');
        expect(errors).toEqual([]);
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
