/// <reference types="node" />
import { defineConfig, devices } from '@playwright/test';

// Another project may already use the default port; set DTVP_E2E_PORT then.
const port = Number(process.env.DTVP_E2E_PORT || 5173);
const baseURL = `http://localhost:${port}`;

export default defineConfig({
    testDir: './e2e',
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : 3,
    reporter: 'html',
    use: {
        baseURL,
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
    },
    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
        {
            name: 'firefox',
            use: { ...devices['Desktop Firefox'] },
        },
        {
            name: 'webkit',
            use: { ...devices['Desktop Safari'] },
        },
    ],
    // CI serves a production build: the dev server's memory grows with every
    // module it transforms and was OOM-killed on the runner mid-suite.
    webServer: {
        command: process.env.CI
            ? `npm run build && npm run preview -- --port ${port} --strictPort`
            : `npm run dev -- --port ${port} --strictPort`,
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 180000,
    },
});
