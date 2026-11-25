import { test, expect, type Page } from '@playwright/test';
import { mockGroupedVulnTask } from './helpers/grouped-task';
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' };

const makeGroup = (index: number) => {
    const id = `CVE-2026-${String(index).padStart(4, '0')}`;
    return {
        id,
        title: `${id} title`,
        description: `${id} description`,
        severity: 'HIGH',
        cvss: 9.9 - index / 100,
        tags: ['Core'],
        list_metadata: {
            lifecycle: 'NEEDS_APPROVAL',
            is_pending: true,
            is_approval_ready: true,
            is_open: true,
            technical_state: 'NOT_AFFECTED',
            dependency_relationship: 'DIRECT',
            assessed_teams: ['Core'],
        },
        affected_versions: [{
            project_name: 'TestProject',
            project_version: '1.0',
            project_uuid: 'p1',
            components: [{
                component_name: 'core-lib',
                component_version: '1.0',
                component_uuid: `c-${index}`,
                finding_uuid: `f-${index}`,
                vulnerability_uuid: `v-${index}`,
                analysis_state: 'NOT_AFFECTED',
                analysis_details: '--- [Team: Core] [State: NOT_AFFECTED] ---\nNot reachable.\n\n[Status: Pending Review]',
                tags: ['Core'],
            }],
        }],
    };
};

export async function mockProject(page: Page, groups: any[]) {
    await page.route('**/auth/me', route => route.fulfill({ json: { username: 'reviewer', role: 'REVIEWER' } }));
    await page.route('**/api/version', route => route.fulfill({ json: { version: '1.0.0', build: 'test' } }));
    await page.route('**/api/projects?name=TestProject', route => route.fulfill({
        json: [{ name: 'TestProject', uuid: 'p1', version: '1.0', classifier: 'APPLICATION' }],
    }));
    await page.route('**/api/tasks/group-vulns*', route => route.fulfill({ json: { task_id: 'task-stable' } }));
    await mockGroupedVulnTask(page, { taskId: 'task-stable', groups });
    await page.route('**/api/settings/mapping', route => route.fulfill({ json: { 'core-lib': 'Core' } }));
    await page.route('**/api/settings/rescore-rules', route => route.fulfill({ json: { transitions: [] } }));
    await page.route('**/api/projects/*/tmrescore/proposals', route => route.fulfill({
        json: { project_name: 'TestProject', session_id: '', scope: 'merged_versions', latest_version: '1.0', analyzed_versions: [], proposals: {} },
    }));
    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0');
    });
}

const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

async function mockDetails(page: Page, groups: any[]) {
    const byId = new Map(groups.map(group => [group.id, group]));
    const findings = new Map(groups.flatMap(group => group.affected_versions[0].components.map((c: any) => [c.finding_uuid, c])));
    // The inspector loads the full group; registered last, so it wins.
    await page.route('**/api/tasks/task-stable/groups/*', route => {
        const id = decodeURIComponent(new URL(route.request().url()).pathname.split('/').pop() || '');
        return route.fulfill(json(byId.get(id)));
    });
    await page.route('**/api/assessments/details', async route => {
        const body = route.request().postDataJSON();
        await route.fulfill(json((body.instances || []).map((instance: any) => {
            const finding = findings.get(instance.finding_uuid);
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
    await page.route('**/api/ssvc/models', route => route.fulfill(json({ models: [ssvcModel] })));
    // The opened card looks the exploitation evidence up; nothing new.
    await page.route('**/api/ssvc/exploitation**', route => {
        const cves = new URL(route.request().url()).searchParams.getAll('cve');
        return route.fulfill(json({
            enabled: true, auto_fill: false, retry_after: 0, suggestion: null,
            sources: cves.flatMap(cve => [
                { source: 'CISA KEV', cve, url: '', status: 'unavailable', checked_at: null },
                { source: 'CISA Vulnrichment', cve, url: '', status: 'unavailable', checked_at: null },
            ]),
        }));
    });
    return { findings };
}

const listRequestsOf = (page: Page) => {
    const requests: string[] = [];
    page.on('request', request => {
        if (/\/api\/tasks\/task-stable\/groups(\?|$)/.test(request.url())) requests.push(request.url());
    });
    return requests;
};

const row = (page: Page, id: string) => page.getByTestId('vuln-list-scroll').locator(`.vuln-card[data-group-id="${id}"]`);
const rowOffset = (page: Page, id: string) => row(page, id).evaluate(element => {
    const list = element.closest('[data-testid="vuln-list-scroll"]')!;
    return element.getBoundingClientRect().top - list.getBoundingClientRect().top;
});
// The n-th row inside the list viewport (the virtual window also renders
// rows above it, which a click would scroll into view).
const visibleRowId = (page: Page, n: number) => page.getByTestId('vuln-list-scroll').evaluate((list, index) => {
    const top = list.getBoundingClientRect().top;
    const rows = [...list.querySelectorAll<HTMLElement>('.vuln-card[data-group-id]')]
        .filter(element => element.getBoundingClientRect().top >= top);
    return rows[index]!.dataset.groupId!;
}, n);
const listScrollTop = (page: Page) => page.getByTestId('vuln-list-scroll').evaluate(element => element.scrollTop);

test.describe('Stable vulnerability list', () => {
    test('selecting a vulnerability neither reloads nor scrolls the list', async ({ page }) => {
        const groups = Array.from({ length: 40 }, (_, index) => makeGroup(index));
        await mockProject(page, groups);
        await mockDetails(page, groups);
        await page.setViewportSize({ width: 1900, height: 1000 });
        const requests = listRequestsOf(page);
        const evidenceLookups: string[] = [];
        page.on('request', request => { if (request.url().includes('/api/ssvc/exploitation')) evidenceLookups.push(request.url()); });
        await page.goto('/project/TestProject');
        await expect(row(page, 'CVE-2026-0000')).toBeVisible({ timeout: 30000 });

        // The first selection opens the detail pane and narrows the list
        // column; the clicked row stays where it was.
        const firstOffset = await rowOffset(page, 'CVE-2026-0001');
        await row(page, 'CVE-2026-0001').click({ position: { x: 20, y: 20 } });
        await expect(page.getByTestId('vuln-detail-inspector')).toBeVisible({ timeout: 10000 });
        await page.waitForTimeout(800);
        expect(Math.abs(await rowOffset(page, 'CVE-2026-0001') - firstOffset)).toBeLessThanOrEqual(4);

        await page.getByTestId('vuln-list-scroll').evaluate(element => { element.scrollTop = 1200; });
        await page.waitForTimeout(400);
        const before = requests.length;
        const top = await listScrollTop(page);
        const targetId = await visibleRowId(page, 2);
        const target = row(page, targetId);
        await target.click({ position: { x: 20, y: 20 } });
        // A reviewer's opened card holds the approval prefill; leaving asks.
        const discard = page.getByRole('button', { name: 'Discard' });
        await discard.waitFor({ timeout: 3000 }).then(() => discard.click(), () => undefined);
        await expect(target).toHaveAttribute('aria-selected', 'true');
        await expect(page).toHaveURL(new RegExp(`vuln=${targetId}`));
        // Let the card load its details and evidence.
        await page.waitForTimeout(1500);
        expect(Math.abs(await listScrollTop(page) - top)).toBeLessThanOrEqual(4);
        expect(requests.slice(before)).toEqual([]);
        // The card did look its evidence up: before, that reloaded the list from the top.
        expect(evidenceLookups.length).toBeGreaterThan(0);
    });

    test('approving in Awaiting review selects the next vulnerability in place', async ({ page }) => {
        const groups = Array.from({ length: 30 }, (_, index) => makeGroup(index));
        await mockProject(page, groups);
        const { findings } = await mockDetails(page, groups);
        // The approval clears the pending status: the vulnerability leaves
        // the Awaiting review list.
        await page.route('**/api/assessment', async route => {
            const payload = route.request().postDataJSON();
            for (const instance of payload.instances || []) {
                const group = groups.find(entry => entry.affected_versions[0].components[0].finding_uuid === instance.finding_uuid);
                if (group) Object.assign(group.list_metadata, { lifecycle: 'ASSESSED', is_pending: false, is_approval_ready: false, is_open: false });
                const finding = findings.get(instance.finding_uuid);
                if (finding) finding.analysis_details = '--- [Team: Core] [State: NOT_AFFECTED] ---\nNot reachable.';
            }
            await route.fulfill(json((payload.instances || []).map((instance: any) => ({
                status: 'success', uuid: instance.finding_uuid, new_state: payload.state || 'NOT_AFFECTED',
                new_details: payload.details || '', revision: 2,
            }))));
        });
        await page.setViewportSize({ width: 1900, height: 1000 });
        await page.goto('/project/TestProject?awaiting_review=true');
        await expect(row(page, 'CVE-2026-0000')).toBeVisible({ timeout: 30000 });

        await page.getByTestId('vuln-list-scroll').evaluate(element => { element.scrollTop = 600; });
        await page.waitForTimeout(400);
        const selectedId = await visibleRowId(page, 2);
        const selected = row(page, selectedId);
        const nextId = `CVE-2026-${String(Number(selectedId.slice(-4)) + 1).padStart(4, '0')}`;
        await selected.click({ position: { x: 20, y: 20 } });
        await expect(selected).toHaveAttribute('aria-selected', 'true');
        const offset = await rowOffset(page, selectedId);

        const inspector = page.getByTestId('vuln-detail-inspector');
        const approve = inspector.getByTestId('assessment-approve-button');
        await expect(approve).toBeVisible({ timeout: 15000 });
        if ((await approve.textContent())?.includes('Review')) await approve.click();
        await expect(approve).toHaveText('Approve', { timeout: 10000 });
        await expect(approve).toBeEnabled({ timeout: 10000 });
        await approve.click();

        await expect(row(page, selectedId)).toHaveCount(0, { timeout: 15000 });
        await expect(row(page, nextId)).toHaveAttribute('aria-selected', 'true', { timeout: 10000 });
        await expect(page).toHaveURL(new RegExp(`vuln=${nextId}`));
        await expect(page.getByTestId('list-announcement')).toHaveText(`${selectedId} left the list; selected ${nextId}, the next vulnerability.`);
        await page.waitForTimeout(500);
        expect(Math.abs(await rowOffset(page, nextId) - offset)).toBeLessThanOrEqual(4);
    });
});
