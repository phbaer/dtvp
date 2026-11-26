import { test, expect, type Page } from '@playwright/test';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// Repair… on the card: the bulk Repair Assessments workflow, scoped to this
// vulnerability. Two findings disagree on the Global decision; the repair
// combines them. A reviewer opens the list with every status.
const CONFLICT = '--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] [Justification: NOT_SET] ---\nReachable through the upload endpoint.';
const AGREED = '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_REACHABLE] ---\nThe decoder is not reached.';

interface State {
    details: Record<string, string>;
    states: Record<string, string>;
    repaired: boolean;
    started: any[];
}

const VERSIONS = [['7.1.0', 1], ['7.1.1', 2]] as const;
const finding = (version: string, index: number) => ({
    project_name: 'TestProject',
    project_version: version,
    project_uuid: `p${index}`,
    component_name: 'brotli',
    component_version: '1.1.0',
    component_uuid: `c-${index}`,
    finding_uuid: `f-${index}`,
    vulnerability_uuid: 'v-1',
    analysis_state: index === 1 ? 'NOT_AFFECTED' : 'EXPLOITABLE',
    analysis_details: index === 1 ? AGREED : CONFLICT,
    tags: ['Identity'],
});

const group = {
    id: 'CVE-2026-0042',
    title: 'Decoder vulnerability',
    description: 'A crafted compressed stream makes the decoder write past its buffer.',
    severity: 'HIGH',
    cvss: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    tags: ['Identity'],
    list_metadata: { lifecycle: 'INCONSISTENT', inconsistency_reasons: ['ANALYSIS_STATE_MISMATCH'] },
    affected_versions: VERSIONS.map(([version, index]) => ({
        project_name: 'TestProject', project_version: version, project_uuid: `p${index}`, components: [finding(version, index)],
    })),
};

const workflow = { id: 'assessment-repair', label: 'Repair Assessments', description: 'Every safe, rule-based repair.', supports_apply: true, supports_document: false, version: 1 };
const repairItem = {
    group_id: group.id,
    title: group.title,
    severity: 'HIGH',
    repairs: [
        { id: 'combine_conflict', label: 'Combine the conflicting global assessments into one' },
        { id: 'ssvc_record', label: 'Carry the SSVC record the other findings agree on to 1 finding without one' },
    ],
    review: [],
    finding_count: 1,
    new_finding_count: 1,
    new_finding_places: ['7.2.0 (brotli@1.1.0)'],
    repairable: true,
    requires_review: false,
};
const preview = () => ({
    task_id: 'task-repair', workflow, preview_token: 'token-repair',
    group_fingerprints: { [group.id]: 'fp-1' },
    selectable_group_ids: [group.id],
    items: [repairItem],
    topics: [{ id: 'combine_conflict', label: 'Combine conflicts', groups: 1 }, { id: 'ssvc_record', label: 'SSVC record', groups: 1 }],
    summary: { groups: 1, findings: 1 },
});

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

    await page.route('**/api/tasks/group-vulns*', route => route.fulfill(json({ task_id: 'task-repair' })));
    await mockGroupedVulnTask(page, { taskId: 'task-repair', groups: [group] });
    // The server patches its snapshot after a write; so does this mock.
    await page.route('**/api/tasks/task-repair/groups/*', route => route.fulfill(json({
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
    // The card asks the scoped preview whether a repair applies.
    await page.route('**/api/bulk-workflows/assessment-repair/preview', route => route.fulfill(json(
        state.repaired ? { ...preview(), items: [], selectable_group_ids: [], topics: [] } : preview(),
    )));
    await page.route('**/api/bulk-workflows/summary', route => route.fulfill(json({
        task_id: 'task-repair', workflows: [{ ...workflow, candidate_count: null, summary: {} }],
    })));
    await page.route('**/api/bulk-workflows/assessment-repair/*-task', async route => {
        const body = route.request().postDataJSON();
        const apply = route.request().url().endsWith('/apply-task');
        state.started.push({ apply, ...body });
        if (apply) {
            state.repaired = true;
            state.details['f-2'] = AGREED;
            state.states['f-2'] = 'NOT_AFFECTED';
        }
        await route.fulfill(json({ task_id: apply ? 'op-apply' : 'op-preview' }));
    });
    await page.route('**/api/bulk-workflows/tasks/op-preview', route => route.fulfill(json({
        id: 'op-preview', status: 'completed', progress: 100, message: '', result: preview(),
    })));
    await page.route('**/api/bulk-workflows/tasks/op-apply', route => route.fulfill(json({
        id: 'op-apply', status: 'completed', progress: 100, message: '',
        result: { task_id: 'task-repair', workflow, summary: { selected_groups: 1, attempted: 1, succeeded: 1, queued: 0, failed: 0 }, results: [] },
    })));

    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
    });
}

test.describe('Repair one vulnerability', () => {
    test('a reviewer repairs the vulnerability from its banner after the same preview as Bulk Changes', async ({ page }) => {
        const errors: string[] = [];
        page.on('pageerror', error => errors.push(error.message));
        page.on('response', response => {
            if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
        });
        const state: State = {
            details: { 'f-1': AGREED, 'f-2': CONFLICT },
            states: { 'f-1': 'NOT_AFFECTED', 'f-2': 'EXPLOITABLE' },
            repaired: false,
            started: [],
        };
        await mockShell(page, state);
        await page.setViewportSize({ width: 1440, height: 900 });

        await page.goto('/project/TestProject?awaiting_review=false');
        const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
        await expect(row).toBeVisible({ timeout: 20000 });
        await row.click();
        const inspector = page.getByTestId('vuln-detail-inspector');
        const banner = inspector.getByTestId('card-differences-banner');
        await expect(banner).toContainText('Why this is inconsistent');
        const repair = banner.getByTestId('card-differences-repair');
        await expect(repair).toHaveAttribute('title', 'Repair Assessments for this vulnerability: Combine conflicts, SSVC record');

        // Also offered in the cleanup, as the better first step.
        await banner.getByTestId('card-differences-cleanup').click();
        await expect(page.getByTestId('cleanup-repair-hint')).toContainText('Combine conflicts, SSVC record');
        await page.getByTestId('cleanup-switch-to-repair').click();
        await expect(page.getByTestId('cleanup-assessment-modal')).toHaveCount(0);

        const modal = page.locator('.fixed.inset-0').filter({ hasText: `Repair ${group.id}` }).first();
        await expect(modal.getByTestId('bulk-workflow-group-title')).toHaveText(`Repair ${group.id}`);
        await expect(modal).toContainText('Combine the conflicting global assessments into one');
        await expect(modal).toContainText('Carry the SSVC record the other findings agree on to 1 finding without one');
        await expect(modal.getByTestId('bulk-workflow-selection-groups')).toContainText('SSVC record');
        // New findings stay unassessed unless included.
        await expect(modal.getByTestId(`include-new-findings-${group.id}`)).not.toBeChecked();
        await modal.getByTestId('bulk-workflow-apply').click();
        await expect(modal.getByTestId('bulk-workflow-completion')).toBeVisible();

        expect(state.started.map(entry => [entry.apply, entry.filters])).toEqual([
            [false, { group_id: group.id }],
            [true, { group_id: group.id }],
        ]);
        expect(state.started[1].group_ids).toEqual([group.id]);
        expect(state.started[1].include_new_findings ?? []).toEqual([]);

        await modal.getByRole('button').first().click();
        // The card is refreshed in place: the findings agree, nothing is left to repair.
        await expect(inspector.getByTestId('card-differences-banner')).toHaveCount(0);
        await expect(row).toBeVisible();
        await inspector.getByRole('tab', { name: /Assessment/ }).click();
        await inspector.getByTestId('assessment-more-button').click();
        await expect(inspector.getByTestId('assessment-repair-button')).toHaveCount(0);
        expect(errors).toEqual([]);
    });
});
