import type { Page } from '@playwright/test'

export async function beginAssessment(page: Page) {
  await page.getByRole('dialog').getByRole('button', { name: 'Continue to assessment', exact: true }).click()
}
export async function confirmDraft(page: Page) {
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('button', { name: 'Continue to severity', exact: true }).click()
  await dialog.getByRole('button', { name: 'Review and confirm', exact: true }).click()
}
export async function confirmReview(page: Page) {
  const dialog = page.getByRole('dialog')
  await beginAssessment(page)
  await dialog.getByRole('button', { name: 'Review and confirm', exact: true }).click()
  await dialog.getByRole('checkbox', { name: 'I checked applicability, evidence and the proposed score.', exact: true }).check()
}
