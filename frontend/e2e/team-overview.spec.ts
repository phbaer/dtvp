import { test, expect, type Page } from '@playwright/test';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// One vulnerability with four required teams: three say Not affected (one
// of them under an alias), H-Core says Exploitable, K-Core has nothing yet;
// a former team's assessment is kept as historical. Pending review.
const TEXT = [
    '--- [Team: A-Core] [State: NOT_AFFECTED] [Assessed By: ana] [Date: 1713000000000] [Justification: CODE_NOT_REACHABLE] ---\nThe parser is never called with user input.\nOnly the build tool uses it.',
    '--- [Team: BCore] [State: NOT_AFFECTED] [Assessed By: ben] [Date: 1713100000000] [Justification: CODE_NOT_PRESENT] ---\nThe module is not shipped.',
    '--- [Team: H-Core] [State: EXPLOITABLE] [Assessed By: hana] [Date: 1713200000000] ---\nThe upload endpoint parses documents from users.',
    '--- [Team: Old-Core] [State: NOT_AFFECTED] [Assessed By: olga] [Date: 1700000000000] [Historical: yes] ---\nFormer owner.',
    '[Status: Pending Review]',
].join('\n\n');

const MAPPING = { 'lib-a': 'A-Core', 'lib-b': ['B-Core', 'BCore'], 'lib-h': 'H-Core', 'lib-k': 'K-Core' };

const finding = (name: string, team: string) => ({
    project_name: 'TestProject',
    project_version: '1.0',
    project_uuid: 'p1',
    component_name: name,
    component_version: '1.0',
    component_uuid: `c-${name}`,
    finding_uuid: `f-${name}`,
    vulnerability_uuid: 'v-1',
    analysis_state: 'EXPLOITABLE',
    analysis_details: TEXT,
    tags: [team],
});

const group = {
    id: 'CVE-2023-4242',
    title: 'Parser vulnerability',
    description: 'A crafted document makes the parser read past its buffer.',
    severity: 'HIGH',
    cvss: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    tags: ['A-Core', 'B-Core', 'H-Core', 'K-Core'],
    list_metadata: { lifecycle: 'INCOMPLETE', is_pending: true },
    affected_versions: [{
        project_name: 'TestProject',
        project_version: '1.0',
        project_uuid: 'p1',
        components: [finding('lib-a', 'A-Core'), finding('lib-b', 'B-Core'), finding('lib-h', 'H-Core'), finding('lib-k', 'K-Core')],
    }],
};

async function mockShell(page: Page, saves: unknown[]) {
    const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

    await page.route('**/auth/me', route => route.fulfill(json({ username: 'rita', role: 'REVIEWER' })));
    await page.route('**/api/version', route => route.fulfill(json({ version: '1.0.0', build: 'test' })));
    await page.route('**/api/cache-status', route => route.fulfill(json({
        fully_cached: true, last_refreshed_at: new Date().toISOString(), projects: 1, active_projects: 1,
        cached_findings: 4, cached_boms: 1, cached_analyses: 0, pending_updates: 0,
    })));
    await page.route('**/api/projects?name=*', route => route.fulfill(json([
        { name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' },
    ])));
    await page.route('**/api/settings/mapping', route => route.fulfill(json(MAPPING)));
    await routeMappingTeams(page, MAPPING);
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
    await page.route('**/api/projects/*/vulnerabilities/*/code-evidence**', route => route.fulfill(json({ items: [], withdrawn_count: 0 })));
    await page.route('**/api/gone-findings?*', route => route.fulfill(json({ name: 'TestProject', versions: [] })));
    await page.route('**/api/project/*/earlier-assessments?*', route => route.fulfill(json({ earlier: [] })));
    await page.route('**/api/assessments/history**', route => route.fulfill(json([])));
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

    await page.route('**/api/tasks/group-vulns*', route => route.fulfill(json({ task_id: 'task-overview' })));
    await mockGroupedVulnTask(page, { taskId: 'task-overview', groups: [group] });
    await page.route('**/api/tasks/task-overview/groups/*', route => route.fulfill(json(group)));

    await page.route('**/api/assessments/details', async (route) => {
        const body = route.request().postDataJSON();
        await route.fulfill(json((body.instances || []).map((instance: any) => ({
            finding_uuid: instance.finding_uuid,
            project_uuid: instance.project_uuid,
            component_uuid: instance.component_uuid,
            vulnerability_uuid: instance.vulnerability_uuid,
            analysis: {
                state: 'EXPLOITABLE',
                analysisState: 'EXPLOITABLE',
                isSuppressed: false,
                analysisDetails: TEXT,
                analysisComments: [],
            },
        }))));
    });
    // Nothing in this spec saves; a request here would be a bug.
    await page.route('**/api/assessment', route => {
        saves.push(route.request().postDataJSON());
        return route.fulfill(json([]));
    });

    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
    });
}

const collectErrors = (page: Page) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('response', response => {
        if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
    });
    return errors;
};

async function openGlobalAssessment(page: Page) {
    await page.goto('/project/TestProject?awaiting_review=false');
    const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
    await expect(row).toBeVisible({ timeout: 20000 });
    await row.click();
    const inspector = page.getByTestId('vuln-detail-inspector');
    await inspector.getByRole('tab', { name: /Assessment/ }).click();
    await inspector.getByRole('button', { name: /^Global/ }).click();
    return inspector;
}

test.describe('Team overview on the Global assessment', () => {
    test('sums up the teams, highlights disagreement, opens a team and fills the Global form', async ({ page }) => {
        const errors = collectErrors(page);
        const saves: unknown[] = [];
        await mockShell(page, saves);
        await page.setViewportSize({ width: 1440, height: 1000 });
        const inspector = await openGlobalAssessment(page);

        const overview = inspector.getByTestId('team-assessment-overview');
        await expect(overview.getByTestId('team-overview-summary')).toHaveText(
            '4 teams: 2 Not affected, 1 Exploitable (H-Core) · 1 missing (K-Core) · 2 differ from Global Exploitable',
        );
        const rows = overview.getByTestId('team-overview-row');
        // The Global form holds the findings' state, Exploitable: A-Core and
        // B-Core differ from it, H-Core from the other teams. Disagreeing
        // first, then missing; the alias BCore is B-Core.
        await expect(rows).toHaveCount(4);
        expect(await rows.evaluateAll(items => items.map(item => item.getAttribute('data-team')))).toEqual(['A-Core', 'B-Core', 'H-Core', 'K-Core']);
        for (const team of ['A-Core', 'B-Core', 'H-Core']) {
            await expect(overview.locator(`[data-team="${team}"]`)).toHaveAttribute('data-disagrees', 'true');
        }
        await expect(overview.locator('[data-team="K-Core"]')).toHaveAttribute('data-disagrees', 'false');
        await expect(overview.locator('[data-team="B-Core"] [data-testid="team-overview-state"]')).toHaveText('Not affected · Code not present');
        await expect(overview.locator('[data-team="K-Core"] [data-testid="team-overview-status"]')).toHaveText('no assessment');
        await expect(overview.locator('[data-team="H-Core"] [data-testid="team-overview-status"]')).toHaveText('pending review');
        await expect(overview.locator('[data-team="A-Core"] [data-testid="team-overview-components"]')).toHaveAttribute('title', 'lib-a');
        await expect(overview.getByTestId('team-overview-former')).toHaveText('1 former team assessment');
        // The old one-line summary is gone.
        await expect(inspector.getByTestId('effective-team-assessment-summary')).toHaveCount(0);

        // The rationale expands inline.
        await overview.locator('[data-team="A-Core"] [data-testid="team-overview-expand"]').click();
        await expect(overview.locator('[data-team="A-Core"] [data-testid="team-overview-rationale-full"]')).toContainText('Only the build tool uses it.');

        // A Global draft survives Open → team tab → back to Global.
        const text = inspector.locator('#analysis-details-textarea');
        await text.fill('Global draft: reachable only through uploads.');
        await overview.locator('[data-team="H-Core"] [data-testid="team-overview-open"]').click();
        await expect(inspector.getByTestId('review-team-tab').filter({ hasText: 'H-Core' })).toHaveAttribute('aria-pressed', 'true');
        await expect(text).toHaveValue('The upload endpoint parses documents from users.');
        await expect(inspector.getByTestId('team-assessment-overview')).toHaveCount(0);
        await inspector.getByRole('button', { name: /^Global/ }).click();
        await expect(text).toHaveValue('Global draft: reachable only through uploads.');

        // Use as Global: state and justification, the text stays, nothing saved.
        await overview.locator('[data-team="B-Core"] [data-testid="team-overview-use"]').click();
        await expect(inspector.locator('#analysis-state-select')).toContainText('Not Affected');
        await expect(inspector.locator('#justification-select')).toContainText(/Code not present/i);
        await expect(text).toHaveValue('Global draft: reachable only through uploads.');
        // Now only H-Core differs, from the teams and the Global decision.
        await expect(overview.locator('[data-team="A-Core"]')).toHaveAttribute('data-disagrees', 'false');
        await expect(overview.locator('[data-team="H-Core"]')).toHaveAttribute('data-disagrees', 'true');
        await expect(overview.getByTestId('team-overview-summary')).toContainText('1 differs from Global Not affected');

        expect(saves).toEqual([]);
        expect(errors).toEqual([]);
    });

    test('shows the overview in the assessment workspace', async ({ page }) => {
        const errors = collectErrors(page);
        await mockShell(page, []);
        await page.setViewportSize({ width: 1600, height: 1000 });
        const inspector = await openGlobalAssessment(page);
        await inspector.getByTestId('workspace-toggle').click();
        const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${group.id}` });
        await expect(workspace).toBeVisible();
        const pane = workspace.getByTestId('workspace-assessment-pane');
        await expect(pane.getByTestId('team-assessment-overview')).toBeVisible();
        await expect(pane.getByTestId('team-overview-row')).toHaveCount(4);

        // Former team assessments are shown with the evidence in the context pane.
        await pane.getByTestId('team-overview-former').click();
        await expect(workspace.getByTestId('workspace-context-pane').getByTestId('vulnerability-assessments')).toContainText('Old-Core');
        expect(errors).toEqual([]);
    });
});
