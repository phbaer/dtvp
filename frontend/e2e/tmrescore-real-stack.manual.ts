import { test, expect } from '@playwright/test'

const runAgainstRealStack = process.env.DTVP_E2E_REAL_STACK === 'true'

async function loginAsReviewer(page: Parameters<typeof test>[0]['page']) {
    await page.goto('/login')
    await page.getByRole('button', { name: 'Sign in with SSO' }).click()
    await page.waitForURL(/.*:8081\/auth\/authorize/, { timeout: 15000 })
    await page.getByRole('button', { name: 'Login as Reviewer' }).click()
    await page.waitForURL(/\/$/, { timeout: 15000 })
}

test.describe('Threat-Model UI Flow (Real Stack)', () => {
    test.skip(!runAgainstRealStack, 'Set DTVP_E2E_REAL_STACK=true and start the pm2 mock stack to run this spec.')

    test.beforeEach(async ({ page }) => {
        await page.addInitScript(() => {
            window.localStorage.setItem('dtvp_last_seen_version', '1.0.6')
        })
    })

    test('uploads a TM7 file and shows mock tmrescore results', async ({ page }) => {
        await loginAsReviewer(page)

        const projectCard = page.locator('div.bg-gray-800.border.border-gray-700.rounded').filter({
            hasText: 'Vulnerable Project',
        }).first()
        await expect(projectCard).toBeVisible({ timeout: 20000 })

        await projectCard.getByRole('link', { name: 'Threat Model' }).click()

        await page.waitForURL(/\/project\/Vulnerable%20Project\/tmrescore$/, { timeout: 15000 })
        await expect(page.getByRole('heading', { name: 'Threat-Model Analysis for Vulnerable Project' })).toBeVisible({ timeout: 15000 })
        await expect(page.getByText('Merged Multi-Version SBOM')).toBeVisible()

        await page.getByTestId('threatmodel-input').setInputFiles('e2e/fixtures/sample-threatmodel.tm7')
        await page.getByTestId('run-tmrescore-analysis').click()

        await expect(page.getByRole('heading', { name: 'Analysis Result' })).toBeVisible({ timeout: 20000 })
        await expect(page.getByText('Merged multi-version analysis keeps historical vulnerabilities attached', { exact: false })).toBeVisible()
        await expect(page.getByText('enriched-sbom.json')).toBeVisible()
        await expect(page.getByText('rescored-report.json')).toBeVisible()
        await expect(page.getByText('summary.txt')).toBeVisible()
        await expect(page.getByText('session_id', { exact: false })).toHaveCount(0)
        await expect(page.getByText('Session ID')).toBeVisible()
    })
})