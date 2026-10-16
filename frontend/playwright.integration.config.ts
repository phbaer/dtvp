import { defineConfig, devices } from '@playwright/test'

const baseURL = process.env.DTVP_UI_URL
if (!baseURL) throw new Error('Set DTVP_UI_URL to a disposable playground; integration tests create synthetic native projects.')
export default defineConfig({
  testDir: './integration', workers: 1, fullyParallel: false,
  use: { baseURL, actionTimeout: 15_000, trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
