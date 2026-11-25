import { test, expect, type Page } from '@playwright/test';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// One vulnerability in two versions, assessed by the Security team; an
// analyst clears that team's assessment from the More menu.
const TEAM_TEXT = '--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: ana] [Justification: CODE_NOT_PRESENT] ---\nThe parser is not shipped.';

const finding = (version: string, index: number) => ({
    project_name: 'TestProject',
    project_version: version,
    project_uuid: `p${index}`,
    component_name: 'lib-a',
    component_version: '1.0',
    component_uuid: `c-${index}`,
    finding_uuid: `f-${index}`,
    vulnerability_uuid: 'v-1',
    analysis_state: 'NOT_AFFECTED',
    analysis_details: TEAM_TEXT,
    tags: ['Security'],
});

const group = {
    id: 'CVE-2023-7777',
    title: 'Parser vulnerability',
    description: 'A crafted document makes the parser read past its buffer.',
    severity: 'HIGH',
    cvss: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    tags: ['Security'],
    affected_versions: [
        { project_name: 'TestProject', project_version: '1.0', project_uuid: 'p1', components: [finding('1.0', 1)] },
        { project_name: 'TestProject', project_version: '2.0', project_uuid: 'p2', components: [finding('2.0', 2)] },
    ],
};

async function mockShell(page: Page, state: { details: string, clears: unknown[] }) {
    const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

    await page.route('**/auth/me', route => route.fulfill(json({ username: 'ana', role: 'ANALYST' })));
    await page.route('**/api/version', route => route.fulfill(json({ version: '1.0.0', build: 'test' })));
    await page.route('**/api/cache-status', route => route.fulfill(json({
        fully_cached: true, last_refreshed_at: new Date().toISOString(), projects: 1, active_projects: 1,
        cached_findings: 2, cached_boms: 2, cached_analyses: 0, pending_updates: 0,
    })));
    await page.route('**/api/projects?name=*', route => route.fulfill(json([
        { name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' },
        { name: 'TestProject', uuid: 'p2', version: '2.0', classifier: 'APPLICATION' },
    ])));
    await page.route('**/api/settings/mapping', route => route.fulfill(json({ 'lib-a': 'Security' })));
    await routeMappingTeams(page, { 'lib-a': 'Security' });
    await page.route('**/api/settings/rescore-rules', route => route.fulfill(json({ transitions: [] })));
    await page.route('**/api/projects/*/tmrescore/proposals', route => route.fulfill(json({ proposals: {} })));
    await page.route('**/api/ssvc/models', route => route.fulfill(json({ models: [ssvcModel] })));
    await page.route('**/api/ssvc/exploitation**', route => route.fulfill(json({
        enabled: true, auto_fill: false, retry_after: 0, suggestion: null, sources: [],
    })));
    await page.route('**/api/known-users', route => route.fulfill(json(['ana'])));
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

    await page.route('**/api/tasks/group-vulns*', route => route.fulfill(json({ task_id: 'task-clear' })));
    await mockGroupedVulnTask(page, { taskId: 'task-clear', groups: [group] });
    await page.route('**/api/tasks/task-clear/groups/*', route => route.fulfill(json(group)));

    await page.route('**/api/assessments/details', async (route) => {
        const body = route.request().postDataJSON();
        await route.fulfill(json((body.instances || []).map((instance: any) => ({
            finding_uuid: instance.finding_uuid,
            project_uuid: instance.project_uuid,
            component_uuid: instance.component_uuid,
            vulnerability_uuid: instance.vulnerability_uuid,
            analysis: {
                state: state.details ? 'NOT_AFFECTED' : 'NOT_SET',
                analysisState: state.details ? 'NOT_AFFECTED' : 'NOT_SET',
                isSuppressed: false,
                analysisDetails: state.details,
                analysisComments: [],
            },
        }))));
    });
    // The clear: a new revision without the team's block, as the server answers.
    await page.route('**/api/assessment/delete', async (route) => {
        const body = route.request().postDataJSON();
        state.clears.push(body);
        state.details = '';
        await route.fulfill(json((body.instances || []).map((instance: any) => ({
            status: 'success', uuid: instance.finding_uuid, new_state: 'NOT_SET', new_details: '', revision: 2,
        }))));
    });

    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
    });
}

test.describe('Clear assessment', () => {
    test('an analyst clears the team assessment after a confirmation', async ({ page }) => {
        const errors: string[] = [];
        page.on('pageerror', error => errors.push(error.message));
        page.on('response', response => {
            if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
        });
        const state = { details: TEAM_TEXT, clears: [] as any[] };
        await mockShell(page, state);
        await page.setViewportSize({ width: 1440, height: 900 });

        await page.goto('/project/TestProject');
        const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
        await expect(row).toBeVisible({ timeout: 20000 });
        await row.click();
        const inspector = page.getByTestId('vuln-detail-inspector');
        await inspector.getByRole('tab', { name: /Assessment/ }).click();
        await expect(inspector.getByTestId('review-team-tab')).toHaveText(['Security']);
        // Analysts see no generated text and no raw text editor.
        await expect(inspector.getByText('Raw Assessment Text')).toHaveCount(0);

        // Rarely used: in the More menu of the action bar.
        await inspector.getByTestId('assessment-more-button').click();
        await inspector.getByTestId('assessment-clear-button').click();
        const dialog = page.getByRole('dialog', { name: 'Clear assessment' });
        await expect(dialog).toBeVisible();
        await expect(dialog).toContainText('Only the Security assessment');
        await expect(dialog.getByTestId('clear-applies-to')).toContainText('all 2 findings of lib-a in versions 1.0, 2.0');
        // Nothing else remains, so nothing goes to review.
        await expect(dialog).not.toContainText('goes to review');
        await expect(dialog.getByTestId('clear-all')).toHaveCount(0);

        // Cancel changes nothing.
        await dialog.getByRole('button', { name: 'Cancel' }).click();
        await expect(dialog).toHaveCount(0);
        expect(state.clears).toEqual([]);

        await inspector.getByTestId('assessment-more-button').click();
        await inspector.getByTestId('assessment-clear-button').click();
        await page.getByTestId('clear-confirm').click();
        await expect(page.getByRole('dialog', { name: 'Clear assessment' })).toHaveCount(0);

        expect(state.clears).toHaveLength(1);
        expect((state.clears[0] as any).team).toBe('Security');
        expect((state.clears[0] as any).instances.map((instance: any) => instance.finding_uuid).sort()).toEqual(['f-1', 'f-2']);
        // The form shows the cleared assessment.
        await expect(inspector.locator('#analysis-state-select')).toContainText('Not Set');
        expect(errors).toEqual([]);
    });
});
