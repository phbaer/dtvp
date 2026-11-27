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
    dtvp_revision: 0,
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
                    dtvpRevision: finding?.dtvp_revision ?? 0,
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
    test('keeps reported component versions visible during review and team assessment', async ({ page }) => {
        const group = groupOf('NEEDS_APPROVAL', [
            finding(1, { component_version: '1.2.0' }),
            finding(2, { component_version: '1.7.0', analysis_state: 'NOT_AFFECTED' }),
        ]);
        await mockShell(page, group);
        const inspector = await openAssessment(page, group);
        const assertScope = async (scope: ReturnType<Page['getByTestId']>) => {
            await expect(scope).toBeVisible();
            const rows = scope.locator('tbody tr');
            await expect(rows).toHaveCount(2);
            await expect(rows.nth(0).locator('td')).toHaveText(['1.0', 'node-lib', '1.2.0', 'In triage']);
            await expect(rows.nth(1).locator('td')).toHaveText(['2.0', 'node-lib', '1.7.0', 'Not affected']);
        };
        await assertScope(inspector.getByTestId('reported-finding-scope'));
        await inspector.getByTestId('review-team-tab').filter({ hasText: 'K-Core' }).click();
        await assertScope(inspector.getByTestId('reported-finding-scope'));
        await page.setViewportSize({ width: 1600, height: 1000 });
        await inspector.getByTestId('workspace-toggle').click();
        const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${group.id}` });
        await assertScope(workspace.getByTestId('workspace-assessment-pane').getByTestId('reported-finding-scope'));
    });

    for (const pending of [true, false]) {
        test(`shows Review needed with missing teams when pending=${pending}`, async ({ page }) => {
            const text = `--- [Team: K-Core] [State: NOT_AFFECTED] [Assessed By: alice] [Justification: CODE_NOT_REACHABLE] ---\nNot reachable.${pending ? '\n\n[Status: Pending Review]' : ''}`;
            const group = groupOf('INCOMPLETE', [finding(1, { analysis_state: 'NOT_AFFECTED', analysis_details: text })]);
            Object.assign(group.list_metadata, { is_pending: pending, is_approval_ready: false,
                covers_all_teams: false, assessed_teams: ['K-Core'], technical_state: 'NOT_AFFECTED' });
            await mockShell(page, group);
            await page.goto('/project/TestProject?awaiting_review=false');
            const row = page.locator(`.vuln-card[data-group-id="${group.id}"]`);
            await expect(row.getByTestId('workflow-state-badge')).toHaveText('Review needed');
            await expect(row.getByTestId('missing-team-assessments')).toHaveText('Missing team assessments: Core');
            await row.click();
            const inspector = page.getByTestId('vuln-detail-inspector');
            await expect(inspector.getByTestId('header-review-chip')).toHaveText('Review needed');
            await expect(inspector.getByTestId('missing-team-assessments')).toHaveText('Missing team assessments: Core');
        });
    }

    test('resets redundant rescoring without approving a Core-only decision missing K-Core', async ({ page }) => {
        const vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H';
        const team = '--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: alice] [Justification: CODE_NOT_REACHABLE] ---\nNot reachable.';
        const savedText = `${team}\n\n[Status: Pending Review]`;
        const group = groupOf('INCOMPLETE', [finding(1, {
            analysis_state: 'NOT_AFFECTED',
            analysis_details: `[Rescored: 5.9] [Rescored Vector: ${vector}]\n\n${savedText}`,
        })]);
        Object.assign(group, { cvss: null, cvss_score: null, cvss_vector: vector, rescored_cvss: 5.9, rescored_vector: vector });
        Object.assign(group.list_metadata, { covers_all_teams: false, assessed_teams: ['Core'], technical_state: 'NOT_AFFECTED' });
        await mockShell(page, group);
        const errors = collectConsoleErrors(page);
        const saves: any[] = [];
        await page.route('**/api/assessment', async route => {
            saves.push(route.request().postDataJSON());
            Object.assign(group, { rescored_cvss: null, rescored_vector: null });
            const results = [...findingsOf(group)].map(([uuid, entry]) => {
                entry.analysis_details = savedText;
                entry.dtvp_revision++;
                return { status: 'success', uuid, new_state: 'NOT_AFFECTED', new_details: savedText, revision: entry.dtvp_revision };
            });
            await route.fulfill({ json: results });
        });
        const inspector = await openAssessment(page, group);
        await expect(inspector.getByTestId('lifecycle-badge').first()).toContainText('Incomplete');
        await expect(inspector.getByTestId('assessment-approve-button')).toHaveCount(0);
        const save = inspector.getByTestId('assessment-submit-button');
        await expect(save).toBeDisabled();
        await inspector.getByTitle('Reset to Original', { exact: true }).click();
        await expect(inspector.getByTestId('rescore-reset-hint')).toBeVisible();
        await expect(save).toBeEnabled();
        await save.click();
        await page.getByRole('button', { name: 'Submit', exact: true }).click();
        await expect.poll(() => saves.length).toBe(1);
        expect(saves[0].fields).toMatchObject({ rescored_score: null, rescored_vector: null });
        expect(saves[0].fields.teams.map((entry: any) => entry.team)).toEqual(['Core']);
        expect(saves[0].approve).toBeUndefined();
        await expect(inspector.getByTestId('rescore-reset-hint')).toHaveCount(0);
        await expect(inspector.getByTestId('lifecycle-badge').first()).toContainText('Incomplete');
        await expect(inspector.getByTestId('assessment-approve-button')).toHaveCount(0);
        expect(errors).toEqual([]);
    });

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

    test('returns a team assessment for changes and waits for resubmission', async ({ page }) => {
        const group = groupOf('NEEDS_APPROVAL', [finding(1, { dtvp_revision: 2 }), finding(2, { dtvp_revision: 3 })]);
        const rationale = 'Add evidence for the revised version range – café.';
        const marker = Buffer.from(JSON.stringify({
            team: 'K-Core', rationale, reviewer: 'rita', requested_at_ms: 1794822866568,
        })).toString('base64url');
        const requests: unknown[] = [];
        const resubmissions: unknown[] = [];
        const updateFindings = (details: string) => [...findingsOf(group)].map(([uuid, entry]) => {
            entry.analysis_details = details;
            entry.dtvp_revision = Number(entry.dtvp_revision) + 1;
            return { status: 'success', uuid, new_details: details, new_state: entry.analysis_state, revision: entry.dtvp_revision };
        });
        await mockShell(page, group);
        await page.route('**/api/assessments/request-changes', async route => {
            requests.push(route.request().postDataJSON());
            Object.assign(group.list_metadata, {
                lifecycle: 'INCOMPLETE', is_approval_ready: false, changes_requested_teams: ['K-Core'],
            });
            await route.fulfill({ json: updateFindings(`[Team Changes Requested: ${marker}]\n\n${PENDING_TEXT}`) });
        });
        await page.route('**/api/assessment', async route => {
            resubmissions.push(route.request().postDataJSON());
            Object.assign(group.list_metadata, {
                lifecycle: 'NEEDS_APPROVAL', is_approval_ready: true, changes_requested_teams: [],
            });
            await route.fulfill({ json: updateFindings(PENDING_TEXT.replace('Not reachable.', 'Revised evidence.')) });
        });
        await page.setViewportSize({ width: 1600, height: 1000 });
        const inspector = await openAssessment(page, group);
        await inspector.getByTestId('review-team-tab').filter({ hasText: 'K-Core' }).click();
        const openRequest = inspector.getByRole('button', { name: 'Request changes', exact: true });
        await expect(openRequest).toBeVisible();

        await inspector.getByTestId('workspace-toggle').click();
        const workspace = page.getByRole('dialog', { name: `Assessment workspace for ${group.id}` });
        const pane = workspace.getByTestId('workspace-assessment-pane');
        await pane.getByTestId('review-team-tab').filter({ hasText: 'K-Core' }).click();
        const workspaceRequest = pane.getByRole('button', { name: 'Request changes', exact: true });
        await workspaceRequest.click();
        const dialog = page.getByRole('dialog', { name: 'Request changes from K-Core' });
        await expect(dialog.getByLabel('Rationale')).toBeFocused();
        await expect(dialog.getByRole('button', { name: 'Request changes' })).toBeDisabled();
        await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await expect(workspace).toBeVisible();

        const details = pane.locator('#analysis-details-textarea');
        await details.fill('Revised evidence.');
        await workspaceRequest.click();
        await dialog.getByLabel('Rationale').fill(rationale);
        await dialog.getByRole('button', { name: 'Request changes' }).click();
        await expect(pane.getByTestId('assessment-changes-requested')).toContainText(rationale);
        expect(requests).toEqual([{
            task_id: 'task-ws', group_id: group.id, team: 'K-Core', rationale, revisions: { 'f-1': 2, 'f-2': 3 },
        }]);
        await expect(pane.locator('#analysis-state-select')).toContainText('Not Affected');
        await expect(details).toHaveValue('Revised evidence.');
        await expect(workspace.getByTestId('assessment-approve-button')).toHaveCount(0);

        const resubmit = workspace.getByTestId('assessment-submit-button');
        await expect(resubmit).toHaveText('Resubmit K-Core for review');
        await resubmit.click();
        await page.getByRole('button', { name: 'Submit', exact: true }).click();
        await expect.poll(() => resubmissions).toEqual([expect.objectContaining({
            team: 'K-Core', resubmit_changes: true, review_task_id: 'task-ws', review_group_id: group.id,
        })]);
        await expect(pane.getByTestId('assessment-changes-requested')).toHaveCount(0);
    });

    test('withdraws an orphaned request from Global without editing the assessment', async ({ page }) => {
        const rationale = 'Confirm the old owner’s evidence.';
        const marker = Buffer.from(JSON.stringify({
            team: 'Former Team', rationale, reviewer: 'rita', requested_at_ms: 1794822866568,
        })).toString('base64url');
        const group = groupOf('INCOMPLETE', [finding(1, {
            dtvp_revision: 4, analysis_details: `[Team Changes Requested: ${marker}]\n\n${PENDING_TEXT}`,
        })]);
        Object.assign(group.list_metadata, { changes_requested_teams: ['Former Team'] });
        const withdrawals: unknown[] = [];
        await mockShell(page, group);
        await page.route('**/api/assessments/request-changes', async route => {
            withdrawals.push(route.request().postDataJSON());
            const entry = findingsOf(group).get('f-1')!;
            entry.analysis_details = PENDING_TEXT;
            entry.dtvp_revision = 5;
            Object.assign(group.list_metadata, {
                lifecycle: 'NEEDS_APPROVAL', is_approval_ready: true, changes_requested_teams: [],
            });
            await route.fulfill({
                json: [{ status: 'success', uuid: 'f-1', new_details: PENDING_TEXT, new_state: 'IN_TRIAGE', revision: 5 }],
            });
        });
        await page.setViewportSize({ width: 1280, height: 900 });
        const inspector = await openAssessment(page, group);
        const requests = inspector.getByTestId('assessment-changes-requested');
        await expect(requests).toContainText(rationale);
        await requests.getByRole('button', { name: 'Withdraw request for Former Team' }).click();
        const dialog = page.getByRole('dialog', { name: 'Withdraw request for Former Team' });
        await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeFocused();
        await dialog.getByRole('button', { name: 'Withdraw request', exact: true }).click();
        await expect(requests).toHaveCount(0);
        expect(withdrawals).toEqual([{
            action: 'withdraw', task_id: 'task-ws', group_id: group.id, team: 'Former Team', revisions: { 'f-1': 4 },
        }]);
        await expect(inspector.getByTestId('assessment-approve-button')).toBeVisible();
    });
});
