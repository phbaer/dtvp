import { test, expect, type Page } from '@playwright/test';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };
import { mockGroupedVulnTask } from './helpers/grouped-task';
import { routeMappingTeams } from './helpers/mapping-teams';

// The lifecycle decision table, rule R5 (ADR 0014): a General decision
// pending review covers the teams without an assessment of their own, so the
// vulnerability is Ready for approval, not Incomplete. The shape of 35
// production vulnerabilities (2026-11-25), anonymised: a General decision in
// triage, an empty Core block, a K-Core assessment, pending review.
const MAPPING = { '*': 'Unknown', 'core-lib': 'Core', 'k-core-lib': 'K-Core' };
const GENERAL = '--- [Team: General] [State: IN_TRIAGE] [Assessed By: alice] [Date: 1794394829173] [Justification: NOT_SET] ---\nUnder investigation.';
const CORE_EMPTY = '--- [Team: Core] [State: NOT_SET] [Assessed By: alice] [Date: 1794823339887] [Justification: NOT_SET] ---';
const K_CORE = '--- [Team: K-Core] [State: NOT_AFFECTED] [Assessed By: alice] [Date: 1794822866568] [Justification: CODE_NOT_REACHABLE] ---\nNot reachable.';
const PENDING_TEXT = `${GENERAL}\n\n${CORE_EMPTY}\n\n${K_CORE}\n\n[Status: Pending Review]`;

const finding = (index: number, overrides: Record<string, unknown> = {}) => ({
    project_uuid: `p${index}`,
    project_version: `${index}.0`,
    component_name: 'node-lib',
    component_version: '1.0.0',
    component_uuid: `c-${index}`,
    finding_uuid: `f-${index}`,
    vulnerability_uuid: 'v-1',
    analysis_state: 'IN_TRIAGE',
    analysis_details: PENDING_TEXT,
    tags: ['Core', 'K-Core'],
    ...overrides,
});

const groupOf = (lifecycle: string, components: Array<Record<string, unknown>>) => ({
    id: 'CVE-2026-111497',
    title: 'node-lib prototype pollution',
    description: 'A crafted object pollutes the prototype.',
    severity: 'HIGH',
    cvss: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
    tags: ['Core', 'K-Core'],
    list_metadata: {
        lifecycle,
        is_pending: true,
        covers_all_teams: true,
        is_approval_ready: lifecycle === 'NEEDS_APPROVAL',
        is_open: true,
        is_assessed: false,
        technical_state: 'IN_TRIAGE',
        assessed_teams: ['K-Core'],
        inconsistency_reasons: [],
    },
    affected_versions: components.map(component => ({
        project_name: 'TestProject',
        project_version: component.project_version,
        project_uuid: component.project_uuid,
        components: [component],
    })),
});

const pendingGlobal = groupOf('NEEDS_APPROVAL', [finding(1), finding(2)]);
// The same with a finding of another version that has no state: Incomplete.
const pendingGlobalMissingFinding = groupOf('INCOMPLETE', [
    finding(1), finding(2, { analysis_state: 'NOT_SET', analysis_details: '' }),
]);

const findingsOf = (group: typeof pendingGlobal) => new Map(
    group.affected_versions.flatMap(version => version.components.map(entry => [entry.finding_uuid, entry] as const)),
);

async function mockShell(page: Page, group: typeof pendingGlobal) {
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
    await routeMappingTeams(page, MAPPING);
    await page.route('**/api/settings/mapping', route => route.fulfill(json(MAPPING)));
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
        route.fulfill(json({ earlier: [] }));
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
    await mockGroupedVulnTask(page, { taskId: 'task-ws', groups: [group] });
    // The inspector loads the full group; registered last, so it wins.
    await page.route('**/api/tasks/task-ws/groups/*', route => route.fulfill(json(group)));

    await page.route('**/api/assessments/details', async (route) => {
        const body = route.request().postDataJSON();
        await route.fulfill(json((body.instances || []).map((instance: any) => {
            const finding = findingsOf(group).get(instance.finding_uuid);
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

async function openAssessment(page: Page, group: typeof pendingGlobal) {
    await page.goto('/project/TestProject?awaiting_review=false');
    const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
    await expect(row).toBeVisible({ timeout: 20000 });
    await row.click();
    const inspector = page.getByTestId('vuln-detail-inspector');
    await expect(inspector.getByRole('tab', { name: /Assessment/ })).toBeVisible({ timeout: 10000 });
    await inspector.getByRole('tab', { name: /Assessment/ }).click();
    return inspector;
}

test.describe('Lifecycle: a pending Global decision and approval', () => {
    test('is ready for approval, and the card says that approving completes it', async ({ page }) => {
        await mockShell(page, pendingGlobal);
        const errors = collectConsoleErrors(page);
        await page.setViewportSize({ width: 1280, height: 900 });
        const inspector = await openAssessment(page, pendingGlobal);

        const badge = inspector.getByTestId('lifecycle-badge').first();
        await expect(badge).toContainText('Ready for approval');
        await expect(badge).toHaveAttribute('title', /Approve the Global assessment to complete it/);

        const reasons = inspector.getByTestId('assessment-approval-reasons');
        await expect(reasons).toBeVisible();
        await expect(reasons).toContainText('What completes it');
        await expect(reasons).toContainText('No assessment of their own for Core. Approve the Global assessment to complete it.');
        await expect(inspector.getByTestId('assessment-sync-reasons')).toHaveCount(0);
        // Ready for approval: the reviewer can approve.
        await expect(inspector.getByTestId('assessment-approve-button')).toBeVisible();
        await expect(inspector.getByTestId('approval-unavailable-reason')).toHaveCount(0);
        expect(errors).toEqual([]);
    });

    test('with a finding without a state stays incomplete and names the approval', async ({ page }) => {
        await mockShell(page, pendingGlobalMissingFinding);
        const errors = collectConsoleErrors(page);
        await page.setViewportSize({ width: 1280, height: 900 });
        const inspector = await openAssessment(page, pendingGlobalMissingFinding);

        await expect(inspector.getByTestId('lifecycle-badge').first()).toContainText('Incomplete');
        const reasons = inspector.getByTestId('assessment-sync-reasons');
        await expect(reasons).toBeVisible();
        await expect(reasons).toContainText('No assessment of their own for Core; the pending Global assessment covers them once approved.');
        await expect(reasons).toContainText('1 of 2 finding instances have no analysis state');
        await expect(inspector.getByTestId('assessment-approval-reasons')).toHaveCount(0);
        // Incomplete: no Approve, and the card says why.
        await expect(inspector.getByTestId('assessment-approve-button')).toHaveCount(0);
        const why = inspector.getByTestId('approval-unavailable-reason');
        await expect(why).toBeVisible();
        await expect(why).toContainText('Approval is possible once it is ready for approval.');
        await expect(why).toContainText('1 of 2 finding instances have no analysis state');
        expect(errors).toEqual([]);
    });
});
