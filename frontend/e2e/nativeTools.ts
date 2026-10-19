import type { Page } from '@playwright/test'
// Child-workflow fixtures expose tool groups; native-entry/tools specs test discovery.
export async function openNativeTools(page: Page) {
  await page.evaluate(() => {
    const open = () => document.querySelectorAll<HTMLDetailsElement>('details[data-tool-group]').forEach(item => { item.open = true })
    open(); new MutationObserver(open).observe(document.body, { childList: true, subtree: true })
  })
}
