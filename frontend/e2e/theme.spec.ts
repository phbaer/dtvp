import { expect, test } from '@playwright/test'

function luminance(colour: string) {
  const rgb = colour.startsWith('#')
    ? (colour.length === 4 ? [...colour.slice(1)].map(value => value + value) : colour.slice(1).match(/../g)!).map(value => parseInt(value, 16))
    : colour.match(/[\d.]+/g)!.slice(0, 3).map(value => Number(value) * (colour.startsWith('color(srgb ') ? 255 : 1))
  const linear = rgb.map(value => { const s = value / 255; return s <= .04045 ? s / 12.92 : ((s + .055) / 1.055) ** 2.4 })
  return linear[0]! * .2126 + linear[1]! * .7152 + linear[2]! * .0722
}
function contrast(a: string, b: string) {
  const values = [luminance(a), luminance(b)].sort((a, b) => b - a)
  return (values[0]! + .05) / (values[1]! + .05)
}

test.beforeEach(async ({ page }) => {
  await page.route('**/api/**', route => new URL(route.request().url()).pathname.endsWith('/me')
    ? route.fulfill({ status: 401, json: { detail: 'Sign in' } })
    : route.fulfill({ json: [] }))
})

for (const theme of ['light', 'dark']) {
  test(`${theme} persists and keeps text, semantic accents and controls readable`, async ({ page }) => {
    await page.goto('/')
    await page.getByRole('combobox', { name: 'Theme', exact: true }).selectOption(theme)
    await page.reload()
    await expect(page.getByRole('combobox', { name: 'Theme', exact: true })).toHaveValue(theme)
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
    const tokens = await page.evaluate(() => {
      const styles = getComputedStyle(document.documentElement)
      return Object.fromEntries(['surface', 'ink', 'muted', 'accent', 'source-accent', 'analysis-accent', 'danger', 'positive', 'control-line', 'warning', 'warning-bg'].map(name => [name, styles.getPropertyValue(`--${name}`).trim()]))
    })
    for (const name of ['ink', 'muted', 'accent', 'source-accent', 'analysis-accent', 'danger', 'positive']) {
      expect(contrast(tokens[name]!, tokens.surface!), `${name} against ${theme} surface`).toBeGreaterThanOrEqual(4.5)
    }
    expect(contrast(tokens.warning!, tokens['warning-bg']!)).toBeGreaterThanOrEqual(4.5)
    expect(contrast(tokens['control-line']!, tokens.surface!)).toBeGreaterThanOrEqual(3)
    const primary = page.getByRole('link', { name: 'Sign in', exact: true })
    const primaryBorder = await primary.evaluate(element => { const css = getComputedStyle(element); return [css.borderWidth, css.borderColor, css.boxShadow] })
    for (const hover of [false, true]) {
      if (hover) await primary.hover()
      const colours = await primary.evaluate(element => { const css = getComputedStyle(element); return { foreground: css.color, background: css.backgroundColor } })
      expect(contrast(colours.foreground, colours.background), `primary label; hovered=${hover}`).toBeGreaterThanOrEqual(4.5)
      expect(await primary.evaluate(element => { const css = getComputedStyle(element); return [css.borderWidth, css.borderColor, css.boxShadow] })).toEqual(primaryBorder)
    }
    const select = page.getByRole('combobox', { name: 'Theme', exact: true })
    await page.mouse.move(0, 0)
    const before = await select.evaluate(element => { const css = getComputedStyle(element); return [css.borderWidth, css.borderColor, css.boxShadow] })
    await select.hover()
    expect(await select.evaluate(element => { const css = getComputedStyle(element); return [css.borderWidth, css.borderColor, css.boxShadow] })).toEqual(before)
  })
}

test('System follows OS changes and explicit preference overrides the OS', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' })
  await page.goto('/')
  const select = page.getByRole('combobox', { name: 'Theme', exact: true })
  await select.selectOption('system')
  await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(24, 24, 24)')
  await page.emulateMedia({ colorScheme: 'light' })
  await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(245, 246, 248)')
  await select.selectOption('dark')
  await page.reload()
  await expect(select).toHaveValue('dark')
  await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(24, 24, 24)')
  await select.selectOption('system')
  await page.reload()
  await expect(select).toHaveValue('system')
  await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(245, 246, 248)')
})
