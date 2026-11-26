import { test, expect, type Page } from '@playwright/test';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// Bulk Changes from a reviewer's default list (Awaiting review): Repair
// Assessments still finds what to synchronize across versions, because the
// dialog looks at the whole project unless the user set list filters.
const ASSESSED = '--- [Team: Identity] [State: NOT_AFFECTED] [Assessed By: ana] [Justification: CODE_NOT_REACHABLE] ---\nThe decoder is not reached.';

interface State {
    details: Record<string, string>;
    states: Record<string, string>;
    repaired: boolean;
    started: any[];
}

const VERSIONS = [['7.1.1', 1], ['7.1.2', 2]] as const;
const finding = (version: string, index: number) => ({
    project_name: 'TestProject',
    project_version: version,
    project_uuid: `p${index}`,
    component_name: 'brotli',
    component_version: '1.1.0',
    component_uuid: `c-${index}`,
    finding_uuid: `f-${index}`,
    vulnerability_uuid: 'v-1',
    analysis_state: index === 1 ? 'NOT_AFFECTED' : 'NOT_SET',
    analysis_details: index === 1 ? ASSESSED : '',
    tags: ['Identity'],
});

const group: any = {
    id: 'CVE-2026-0100',
    title: 'Decoder vulnerability',
    description: 'A crafted compressed stream makes the decoder write past its buffer.',
    severity: 'HIGH',
    cvss: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    tags: ['Identity'],
    list_metadata: { lifecycle: 'INCOMPLETE', inconsistency_reasons: [] },
    affected_versions: VERSIONS.map(([version, index]) => ({
        project_name: 'TestProject', project_version: version, project_uuid: `p${index}`, components: [finding(version, index)],
    })),
};

const INITIAL_GROUP = JSON.stringify(group);

const workflow = { id: 'assessment-repair', label: 'Repair Assessments', description: 'Every safe, rule-based repair.', supports_apply: true, supports_document: false, version: 1 };
// What the server finds for the whole project; the Awaiting review list
// holds no candidate.
const preview = (filters: Record<string, unknown>) => {
    const listed = !filters.awaiting_review;
    return {
        task_id: 'task-bulk', workflow, preview_token: `token-${listed ? 'project' : 'list'}`,
        group_fingerprints: listed ? { [group.id]: 'fp-1' } : {},
        selectable_group_ids: listed ? [group.id] : [],
        items: listed ? [{
            group_id: group.id, title: group.title, severity: 'HIGH',
            repairs: [{ id: 'sync_findings', label: 'Synchronize assessment to 1 finding (7.1.2)' }],
            review: [], finding_count: 1, new_finding_count: 0, repairable: true, requires_review: false,
        }] : [],
        topics: listed ? [{ id: 'sync_findings', label: 'Synchronize', groups: 1 }] : [],
        summary: { groups: listed ? 1 : 0, findings: listed ? 1 : 0 },
    };
};

async function mockShell(page: Page, state: State) {
    const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

    await page.route('**/auth/me', route => route.fulfill(json({ username: 'rita', role: 'REVIEWER' })));
    await page.route('**/api/version', route => route.fulfill(json({ version: '1.0.0', build: 'test' })));
    await page.route('**/api/cache-status', route => route.fulfill(json({
        fully_cached: true, last_refreshed_at: new Date().toISOString(), projects: 1, active_projects: 1,
        cached_findings: 2, cached_boms: 2, cached_analyses: 0, pending_updates: 0,
    })));
    await page.route('**/api/projects?name=*', route => route.fulfill(json([
        { name: 'TestProject', uuid: 'p1', version: '7.1.0', classifier: 'APPLICATION' },
        { name: 'TestProject', uuid: 'p2', version: '7.2.0', classifier: 'APPLICATION' },
        { name: 'TestProject', uuid: 'p3', version: '7.1.1', classifier: 'APPLICATION' },
    ])));
    await page.route('**/api/settings/mapping', route => route.fulfill(json({ brotli: 'Identity' })));
    await routeMappingTeams(page, { brotli: 'Identity' });
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

    await page.route('**/api/tasks/group-vulns*', route => route.fulfill(json({ task_id: 'task-bulk' })));
    await mockGroupedVulnTask(page, { taskId: 'task-bulk', groups: [group] });
    // The server patches its snapshot after a write; so does this mock.
    await page.route('**/api/tasks/task-bulk/groups/*', route => route.fulfill(json({
        ...group,
        affected_versions: group.affected_versions.map(version => ({
            ...version,
            components: version.components.map(component => ({
                ...component,
                analysis_state: state.states[component.finding_uuid],
                analysis_details: state.details[component.finding_uuid],
            })),
        })),
    })));

    await page.route('**/api/assessments/details', async (route) => {
        const body = route.request().postDataJSON();
        await route.fulfill(json((body.instances || []).map((instance: any) => ({
            finding_uuid: instance.finding_uuid,
            project_uuid: instance.project_uuid,
            component_uuid: instance.component_uuid,
            vulnerability_uuid: instance.vulnerability_uuid,
            analysis: {
                state: state.states[instance.finding_uuid],
                analysisState: state.states[instance.finding_uuid],
                isSuppressed: false,
                analysisDetails: state.details[instance.finding_uuid],
                analysisComments: [],
            },
        }))));
    });
    await page.route('**/api/bulk-workflows/summary', route => route.fulfill(json({
        task_id: 'task-bulk', workflows: [{ ...workflow, candidate_count: null, summary: {} }],
    })));
    await page.route('**/api/bulk-workflows/assessment-repair/*-task', async route => {
        const body = route.request().postDataJSON();
        const apply = route.request().url().endsWith('/apply-task');
        state.started.push({ apply, ...body });
        if (apply) {
            state.repaired = true;
            state.details['f-2'] = ASSESSED;
            state.states['f-2'] = 'NOT_AFFECTED';
            // The task's snapshot is patched with the write, as on the server.
            Object.assign(group.affected_versions[1]!.components[0]!, { analysis_state: 'NOT_AFFECTED', analysis_details: ASSESSED });
            group.list_metadata = { lifecycle: 'ASSESSED', inconsistency_reasons: [] };
        }
        await route.fulfill(json({ task_id: apply ? 'op-apply' : 'op-preview' }));
    });
    await page.route('**/api/bulk-workflows/tasks/op-preview', route => route.fulfill(json({
        id: 'op-preview', status: 'completed', progress: 100, message: '',
        result: preview(state.started.filter(entry => !entry.apply).at(-1)?.filters || {}),
    })));
    await page.route('**/api/bulk-workflows/tasks/op-apply', route => route.fulfill(json({
        id: 'op-apply', status: 'completed', progress: 100, message: '',
        result: { task_id: 'task-bulk', workflow, summary: { selected_groups: 1, attempted: 1, succeeded: 1, queued: 0, failed: 0 }, results: [] },
    })));

    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
    });
}

test.describe('Bulk Changes scope', () => {
    test('from the reviewer default list, Repair Assessments synchronizes across versions', async ({ page }) => {
        const errors: string[] = [];
        page.on('pageerror', error => errors.push(error.message));
        page.on('response', response => {
            if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
        });
        Object.assign(group, JSON.parse(INITIAL_GROUP));
        const state: State = {
            details: { 'f-1': ASSESSED, 'f-2': '' },
            states: { 'f-1': 'NOT_AFFECTED', 'f-2': 'NOT_SET' },
            repaired: false,
            started: [],
        };
        await mockShell(page, state);
        await page.setViewportSize({ width: 1440, height: 900 });

        // The reviewer's default list: Awaiting review.
        await page.goto('/project/TestProject');
        await expect(page.getByRole('button', { name: 'Bulk Changes' })).toBeVisible({ timeout: 20000 });
        await page.getByRole('button', { name: 'Bulk Changes' }).click();
        const modal = page.locator('.fixed.inset-0').filter({ hasText: 'Bulk Changes' }).first();
        await expect(modal.getByTestId('bulk-workflow-scope-project')).toHaveAttribute('aria-checked', 'true');
        await expect(modal.getByTestId('bulk-workflow-scope-description')).toHaveText('All versions, no list filters.');

        await modal.getByTestId('bulk-workflow-assessment-repair').click();
        await expect(modal).toContainText(group.id);
        await expect(modal).toContainText('Synchronize assessment to 1 finding (7.1.2)');

        // The current list is the reviewer's Awaiting review: nothing there.
        await modal.getByTestId('bulk-workflow-scope-list').click();
        await expect(modal.getByTestId('bulk-workflow-scope-description')).toContainText('Awaiting review');
        await expect(modal).not.toContainText('Synchronize assessment to 1 finding');
        await modal.getByTestId('bulk-workflow-scope-project').click();
        await expect(modal).toContainText('Synchronize assessment to 1 finding (7.1.2)');

        await modal.getByTestId('bulk-workflow-apply').click();
        await expect(modal.getByTestId('bulk-workflow-completion')).toBeVisible();
        const previews = state.started.filter(entry => !entry.apply).map(entry => entry.filters);
        expect(previews[0]).toEqual({});
        expect(previews[1].awaiting_review).toBe(true);
        expect(state.started.filter(entry => entry.apply).map(entry => [entry.filters, entry.group_ids]))
            .toEqual([[{}, [group.id]]]);
        await modal.getByRole('button').first().click();

        // Both versions carry the assessment now.
        await page.goto('/project/TestProject?awaiting_review=false');
        const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
        await expect(row).toBeVisible({ timeout: 20000 });
        await row.click();
        const cells = page.getByTestId('vuln-detail-inspector').getByTestId('finding-matrix-cell');
        await expect(cells).toHaveCount(2);
        await expect(cells.nth(0)).toContainText('Not affected');
        await expect(cells.nth(1)).toContainText('Not affected');
        expect(errors).toEqual([]);
    });
});
