import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e', workers: 1, fullyParallel: false,
  use: { baseURL: process.env.DTVP_UI_URL || 'http://127.0.0.1:8900', trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
