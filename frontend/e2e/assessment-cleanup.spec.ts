import { test, expect, type Page } from '@playwright/test';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// A real case, anonymised: the findings of later versions never got the SSVC
// record a reviewer had recorded, and every save kept each finding's own.
// A reviewer cleans it up from the inconsistency banner.
const RECORD = JSON.stringify({
    model: 'ssvc:DT_DP', version: '1.0.0', answers: { 'ssvc:E:1.1.0': 'A' }, rationale: '',
    outcome: null, evidence: null, assessor: 'reviewer-1', assessed_at: '2026-11-11T11:00:29+00:00', priority: 'Incomplete',
}, null, 2);
const GENERAL = '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: analyst-1] [Date: 1795535973530] [Justification: CODE_NOT_REACHABLE] ---';
const TEAM = '--- [Team: Identity] [State: NOT_AFFECTED] [Assessed By: analyst-4] [Date: 1795530016568] [Justification: CODE_NOT_REACHABLE] ---\nRequest decompression is disabled.';
const WITHOUT_SSVC = `${GENERAL}\n\n${TEAM}\n\n[Status: Pending Review]`;
const WITH_SSVC = `${GENERAL.replace(' ---', ' [SSVC: INCOMPLETE] ---')}\n[SSVC Summary]\nSSVC priority: Incomplete\n[/SSVC Summary]\n\n[SSVC Details]\n${RECORD}\n[/SSVC Details]\n\n${TEAM}\n\n[Status: Pending Review]`;

interface State {
    details: Record<string, string>;
    revisions: Record<string, number>;
    requests: any[];
}

const VERSIONS = [['7.1.0', 1], ['7.2.0', 2], ['7.1.1', 3]] as const;
const finding = (version: string, index: number) => ({
    project_name: 'TestProject',
    project_version: version,
    project_uuid: `p${index}`,
    component_name: 'brotli',
    component_version: '1.1.0',
    component_uuid: `c-${index}`,
    finding_uuid: `f-${index}`,
    vulnerability_uuid: 'v-1',
    analysis_state: 'NOT_AFFECTED',
    analysis_details: index === 3 ? WITHOUT_SSVC : WITH_SSVC,
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
    list_metadata: { lifecycle: 'INCONSISTENT', inconsistency_reasons: ['ASSESSMENT_DETAILS_MISMATCH'] },
    affected_versions: VERSIONS.map(([version, index]) => ({
        project_name: 'TestProject', project_version: version, project_uuid: `p${index}`, components: [finding(version, index)],
    })),
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

    await page.route('**/api/tasks/group-vulns*', route => route.fulfill(json({ task_id: 'task-cleanup' })));
    await mockGroupedVulnTask(page, { taskId: 'task-cleanup', groups: [group] });
    await page.route('**/api/tasks/task-cleanup/groups/*', route => route.fulfill(json(group)));

    await page.route('**/api/assessments/details', async (route) => {
        const body = route.request().postDataJSON();
        await route.fulfill(json((body.instances || []).map((instance: any) => ({
            finding_uuid: instance.finding_uuid,
            project_uuid: instance.project_uuid,
            component_uuid: instance.component_uuid,
            vulnerability_uuid: instance.vulnerability_uuid,
            analysis: {
                state: 'NOT_AFFECTED',
                analysisState: 'NOT_AFFECTED',
                isSuppressed: false,
                analysisDetails: state.details[instance.finding_uuid],
                analysisComments: [],
                dtvpRevision: state.revisions[instance.finding_uuid],
            },
        }))));
    });
    // The cleanup as the server answers it: a dry run shows each finding's
    // before and after; the save writes the kept version.
    await page.route('**/api/assessment/cleanup', async (route) => {
        const body = route.request().postDataJSON();
        state.requests.push(body);
        const entries = (body.instances || []).map((instance: any) => {
            const before = state.details[instance.finding_uuid];
            return {
                ...instance,
                revision: state.revisions[instance.finding_uuid],
                source_revision: 18,
                changed: before !== WITH_SSVC,
                before: { state: 'NOT_AFFECTED', details: before, suppressed: false },
                after: before !== WITH_SSVC ? { state: 'NOT_AFFECTED', details: WITH_SSVC, suppressed: false } : null,
            };
        });
        if (body.dry_run) {
            await route.fulfill(json(entries));
            return;
        }
        const changed = entries.filter((entry: any) => entry.changed);
        for (const entry of changed) {
            state.details[entry.finding_uuid] = WITH_SSVC;
            state.revisions[entry.finding_uuid] += 1;
        }
        await route.fulfill(json(changed.map((entry: any) => ({
            status: 'success', uuid: entry.finding_uuid, new_state: 'NOT_AFFECTED', new_details: WITH_SSVC,
            revision: state.revisions[entry.finding_uuid],
        }))));
    });

    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
    });
}

test.describe('Assessment cleanup', () => {
    test('a reviewer keeps one version for every finding after a preview', async ({ page }) => {
        const errors: string[] = [];
        page.on('pageerror', error => errors.push(error.message));
        page.on('response', response => {
            if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
        });
        const state: State = {
            details: { 'f-1': WITH_SSVC, 'f-2': WITH_SSVC, 'f-3': WITHOUT_SSVC },
            revisions: { 'f-1': 18, 'f-2': 18, 'f-3': 6 },
            requests: [],
        };
        await mockShell(page, state);
        await page.setViewportSize({ width: 1440, height: 900 });

        await page.goto('/project/TestProject?awaiting_review=false');
        const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
        await expect(row).toBeVisible({ timeout: 20000 });
        await row.click();
        const inspector = page.getByTestId('vuln-detail-inspector');
        const banner = inspector.getByTestId('card-differences-banner');
        // A missing SSVC record is no conflict, but the findings differ and
        // the cleanup tidies them up.
        await expect(banner).toContainText('Assessments differ between findings');
        await expect(banner).toContainText('1 of 3');

        await banner.getByTestId('card-differences-cleanup').click();
        const dialog = page.getByRole('dialog', { name: 'Clean up assessment' });
        await expect(dialog).toBeVisible();
        await expect(dialog.getByTestId('cleanup-version')).toHaveCount(2);
        // What differs is the SSVC record, which no form shows.
        await expect(dialog.getByTestId('cleanup-version').first()).toContainText('Global · SSVC');
        await expect(dialog.getByTestId('cleanup-version').first()).toContainText('Incomplete · recorded by reviewer-1');
        await expect(dialog.getByTestId('cleanup-finding').locator('input[type="checkbox"]')).toHaveCount(3);
        await expect(dialog.getByTestId('cleanup-finding').nth(2).locator('input')).toBeChecked();
        await expect(dialog.getByTestId('cleanup-confirm')).toBeDisabled();

        await dialog.getByTestId('cleanup-preview-button').click();
        await expect(dialog.getByTestId('cleanup-preview-row')).toHaveCount(1);
        await expect(dialog.getByTestId('cleanup-preview-row')).toContainText('7.1.1 · brotli 1.1.0');
        await expect(dialog.getByTestId('cleanup-preview-row')).toContainText('Global · SSVC');
        await page.screenshot({ path: test.info().outputPath('cleanup.png') });

        await dialog.getByTestId('cleanup-confirm').click();
        await expect(dialog).toHaveCount(0);

        const saved = state.requests.filter(request => !request.dry_run);
        expect(saved).toHaveLength(1);
        expect(saved[0]).toMatchObject({
            action: 'apply', team: null,
            source: { project_uuid: 'p1', component_uuid: 'c-1', vulnerability_uuid: 'v-1' },
            revisions: { 'p3|c-3|v-1': 6, 'p1|c-1|v-1': 18 },
        });
        expect(saved[0].instances.map((instance: any) => instance.finding_uuid)).toEqual(['f-3']);
        // The findings agree now: the banner is gone.
        await expect(inspector.getByTestId('card-differences-banner')).toHaveCount(0);
        expect(errors).toEqual([]);
    });

    test('the cleanup is in the More menu too', async ({ page }) => {
        const state: State = {
            details: { 'f-1': WITH_SSVC, 'f-2': WITH_SSVC, 'f-3': WITHOUT_SSVC },
            revisions: { 'f-1': 18, 'f-2': 18, 'f-3': 6 },
            requests: [],
        };
        await mockShell(page, state);
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.goto('/project/TestProject?awaiting_review=false');
        const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
        await expect(row).toBeVisible({ timeout: 20000 });
        await row.click();
        const inspector = page.getByTestId('vuln-detail-inspector');
        await inspector.getByRole('tab', { name: /Assessment/ }).click();
        await inspector.getByTestId('assessment-more-button').click();
        await inspector.getByTestId('assessment-cleanup-button').click();
        const dialog = page.getByRole('dialog', { name: 'Clean up assessment' });
        await expect(dialog).toBeVisible();
        await dialog.getByRole('button', { name: 'Cancel' }).click();
        await expect(dialog).toHaveCount(0);
        expect(state.requests).toEqual([]);
    });
});
