import { test, expect, type Page } from '@playwright/test';

/**
 * One live-update stream per browser: tabs elect a leader (Web Locks) and
 * share its events (BroadcastChannel). The export warning can only show
 * "2 failing" through the event, because the cache status reports none.
 */
const sseBody = [
    'id: e2e:1',
    'event: hello',
    `data: ${JSON.stringify({ boot_id: 'e2e', seq: 1, build: 'test', source: { dt: 'ok' } })}`,
    '',
    'id: e2e:2',
    'event: export.state',
    `data: ${JSON.stringify({
        seq: 2,
        at: '2026-11-20T10:00:00Z',
        type: 'export.state',
        product: null,
        data: { pending: 2, failed: 2, oldest_pending_at: '2026-11-20T09:00:00Z' },
    })}`,
    '',
    '',
].join('\n');

test.describe('Live update stream across tabs', () => {
    test('one tab holds the stream and another takes over when it closes', async ({ context }) => {
        await context.addInitScript(() => {
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.4');
        });

        // Playwright checks routes in reverse registration order: catch-alls first.
        await context.route('**/api/**', route => route.fulfill({ status: 200, body: '{}' }));
        await context.route('**/auth/**', route => route.fulfill({ status: 200, body: '{}' }));
        await context.route('**/auth/me', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ username: 'reviewer', role: 'REVIEWER' }),
        }));
        await context.route('**/api/version', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ version: '1.0.4', build: 'test' }),
        }));
        await context.route('**/api/cache-status', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                fully_cached: true,
                last_refreshed_at: new Date().toISOString(),
                projects: 1,
                active_projects: 0,
                cached_findings: 0,
                cached_boms: 0,
                cached_analyses: 0,
                pending_updates: 0,
                failed_exports: 0,
                oldest_pending_at: null,
            }),
        }));
        await context.route('**/api/projects*', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([
                { name: 'Example', uuid: 'p1', version: '1.0.0', classifier: 'APPLICATION' },
            ]),
        }));
        await context.route(url => url.pathname.endsWith('/api/events'), route => route.fulfill({
            status: 200,
            headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' },
            body: sseBody,
        }));
        await context.route('**/api/events/poll*', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ boot_id: 'e2e', cursor: 'e2e:2', events: [], resync: null, more: false }),
        }));

        const streamRequests = new Map<Page, number>();
        const isStream = (url: string) => new URL(url).pathname.endsWith('/api/events');

        const pages: Page[] = [];
        for (let index = 0; index < 3; index += 1) {
            const page = await context.newPage();
            streamRequests.set(page, 0);
            page.on('request', request => {
                if (isStream(request.url())) {
                    streamRequests.set(page, (streamRequests.get(page) || 0) + 1);
                }
            });
            pages.push(page);
        }
        for (const page of pages) {
            await page.goto('/');
        }

        for (const page of pages) {
            await expect(page.getByTestId('export-issues-indicator')).toContainText('Export: 2 failing', {
                timeout: 15_000,
            });
        }

        const holders = pages.filter(page => (streamRequests.get(page) || 0) > 0);
        expect(holders).toHaveLength(1);
        const [leader] = holders;

        await leader.close();
        const others = pages.filter(page => page !== leader);
        await expect.poll(
            () => others.filter(page => (streamRequests.get(page) || 0) > 0).length,
            { timeout: 10_000 },
        ).toBe(1);
    });
});
