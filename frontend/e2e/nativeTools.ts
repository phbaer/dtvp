import { expect, type Locator, type Page } from '@playwright/test'

export async function openNativeTools(_page: Page) {}

async function showProductNavigation(page: Page) {
  const nav = page.getByRole('navigation', { name: 'Product', exact: true })
  if (!await nav.isVisible()) await page.getByRole('button', { name: 'Menu', exact: true }).click()
  await expect(nav).toBeVisible()
  return nav
}
export async function openProductView(page: Page, view: string, setting?: string) {
  const nav = await showProductNavigation(page)
  await nav.locator(`[data-product-view="${view}"]`).click()
  if (setting) {
    await showProductNavigation(page)
    await page.getByRole('navigation', { name: 'Product settings', exact: true }).getByRole('button', { name: setting, exact: true }).click()
  }
}
export async function openProductTask(page: Page, view: string, task: string) {
  await openProductView(page, view)
  const nav = await showProductNavigation(page)
  await nav.locator(`[data-task-link="${task}"]`).click()
}

export async function openDisclosure(locator: Locator) {
  await expect(locator.first()).toBeAttached()
  for (const candidate of await locator.all()) {
    const tag = await candidate.evaluate(element => element.tagName)
    if (tag === 'H2') {
      const task = await candidate.evaluate(element => { const page = element.closest<HTMLElement>('[data-task]'); return page ? { view: page.dataset.taskView!, task: page.dataset.task! } : null })
      if (task && !await candidate.isVisible()) await openProductTask(candidate.page(), task.view, task.task)
      await expect(candidate).toBeVisible()
      return
    }
    if (tag === 'SUMMARY') {
      if (!(await candidate.evaluate(element => (element.parentElement as HTMLDetailsElement).open))) await candidate.click()
      return
    }
  }
  throw new Error('Expected a task heading or native disclosure summary')
}
