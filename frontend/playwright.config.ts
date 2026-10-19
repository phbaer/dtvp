import { defineConfig, devices } from '@playwright/test'

const testUrl = process.env.DTVP_UI_URL
if (!testUrl) throw new Error('Run uv run python scripts/playground.py test from the repository root, or set DTVP_UI_URL to a UI test server. Native browser fixtures mock API transport; real-backend checks use test:integration.')

export default defineConfig({
  testDir: './e2e', workers: 1, fullyParallel: false,
  use: { baseURL: testUrl, trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
