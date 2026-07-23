import type { Page } from '@playwright/test';

/**
 * Keep browser tests independent from a running backend while leaving Vite
 * source modules such as /src/lib/api/client.ts untouched.
 *
 * Register endpoint-specific routes after this fallback; Playwright evaluates
 * matching routes in reverse registration order.
 */
export async function mockUnmatchedBackendRequests(page: Page) {
    await page.route(
        ({ pathname }) => pathname.startsWith('/api/'),
        async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: '{}',
            });
        },
    );
    await page.route(
        ({ pathname }) => pathname.startsWith('/auth/'),
        async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: '{}',
            });
        },
    );
}
