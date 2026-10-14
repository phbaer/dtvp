import { expect, test } from '@playwright/test'

test('playground personas start with findings and can recover an empty filter', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: 'Operations analyst', exact: true }).click()
  await expect(page.getByRole('button', { name: 'CVE-2099-20003', exact: true })).toBeVisible()
  await page.getByRole('textbox', { name: 'Search', exact: true }).fill('missing-playground-finding')
  await page.getByRole('button', { name: 'Search', exact: true }).click()
  await page.getByRole('button', { name: 'Show all accessible findings', exact: true }).click()
  await expect(page.getByRole('button', { name: 'CVE-2099-20003', exact: true })).toBeVisible()
  await page.getByRole('textbox', { name: 'Search', exact: true }).fill('CVE-2099-20003')
  await page.getByRole('button', { name: 'Search', exact: true }).click()
  await page.getByRole('combobox', { name: 'Persona', exact: true }).selectOption('analyst')
  await expect(page.getByRole('textbox', { name: 'Search', exact: true })).toHaveValue('')
  await expect(page.getByRole('button', { name: 'CVE-2099-20001', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'CVE-2099-20003', exact: true })).toHaveCount(0)
})
