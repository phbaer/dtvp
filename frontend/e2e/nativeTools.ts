import { expect, type Locator, type Page } from '@playwright/test'

// Legacy fixtures call this before selecting a product. Native tools now have
// explicit destinations; fixtures use openProductView after product selection.
export async function openNativeTools(_page: Page) {}

export async function openProductView(page: Page, view: string, setting?: string) {
  const nav = page.getByRole('navigation', { name: 'Product', exact: true })
  if (await nav.isVisible()) await nav.getByRole('button', { name: view, exact: true }).click()
  else await page.getByRole('combobox', { name: 'Product view', exact: true }).selectOption(view)
  if (setting) await page.getByRole('navigation', { name: 'Product settings', exact: true }).getByRole('button', { name: setting, exact: true }).click()
}

export async function openDisclosure(locator: Locator) {
  // A heading may share its text with a settings link; choose its actual summary.
  await expect(locator.first()).toBeAttached()
  for (const candidate of await locator.all()) {
    if (await candidate.evaluate(element => element.tagName === 'SUMMARY')) {
      if (!(await candidate.evaluate(element => (element.parentElement as HTMLDetailsElement).open))) await candidate.click()
      return
    }
  }
  throw new Error('Expected a native disclosure summary')
}
