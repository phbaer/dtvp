import { test, expect, type Page } from '@playwright/test'

const runAgainstRealStack = process.env.DTVP_E2E_REAL_STACK === 'true'

async function loginAsReviewer(page: Page) {
    await page.goto('/login')
    await page.getByRole('button', { name: 'Sign in with SSO' }).click()
    await page.waitForURL(/.*:8081\/auth\/authorize/, { timeout: 15000 })
    await page.getByRole('button', { name: 'Login as Reviewer' }).click()
    await page.waitForURL(/\/$/, { timeout: 15000 })
}

test.describe('Code Analysis UI Flow (Real Stack)', () => {
    test.skip(!runAgainstRealStack, 'Set DTVP_E2E_REAL_STACK=true and start the pm2 mock stack to run this spec.')

    test.beforeEach(async ({ page }) => {
        await page.addInitScript(() => {
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.6')
        })
    })

    test('shows queue operations, saved-result cache policy, and analyzer status', async ({ page }) => {
        await loginAsReviewer(page)

        await page.goto('/code-analysis')

        await expect(page.getByRole('heading', { name: 'Code Analysis' })).toBeVisible({ timeout: 20000 })
        await expect(page.getByRole('heading', { name: 'DTVP Queue' })).toBeVisible()
        await expect(page.getByRole('heading', { name: 'Result Cache' })).toBeVisible()
        await expect(page.getByRole('heading', { name: 'Analyzer Configuration' })).toBeVisible()
        await expect(page.getByText(/saved runs|not reported/i)).toBeVisible()

        const status = await page.request.get('/api/code-analysis/status')
        expect(status.ok()).toBeTruthy()
        const payload = await status.json()
        expect(payload).toHaveProperty('queue')
        expect(payload).toHaveProperty('result_cache')
    })
})
