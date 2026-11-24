import { test, expect, type Page } from '@playwright/test';
import { mockTeamMappingApi as mockSettings } from './helpers/team-mapping';

// Settings → Team Mapping (ADR 0012): an overview with the key numbers,
// one view at a time (Unowned, Projects, Teams, Checks, Raw JSON), and a
// save bar with the unsaved changes, their effect, Review, Discard and Save.

const openEditor = async (page: Page, saved: unknown[]) => {
    await mockSettings(page, saved);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto('/settings');
    await expect(page.getByTestId('team-mapping-editor')).toBeVisible();
    await expect(page.getByTestId('team-mapping-report-status')).toContainText('Report of');
};

test('pick an unowned component in the tree, pick the team, add it and save', async ({ page }) => {
    const saved: unknown[] = [];
    await openEditor(page, saved);

    // The overview: unowned findings, coverage, errors and warnings.
    await expect(page.getByTestId('overview-unowned')).toHaveText('1220');
    await expect(page.getByTestId('overview-errors')).toHaveText('0');
    await expect(page.getByTestId('team-mapping-save-bar')).toHaveCount(0);

    // Projects by unowned findings; the tree of ViewPoint_Product.
    await page.getByRole('tab', { name: /Projects/ }).click();
    const browser = page.getByTestId('coverage-browser');
    await expect(browser.getByTestId('coverage-project-eventserver')).toContainText('1202 unowned');
    await browser.getByTestId('coverage-project-ViewPoint_Product').click();
    const core = page.getByRole('treeitem', { name: /^core,/ });
    await expect(core).toHaveAttribute('aria-label', 'core, owner Unknown, catch-all, unowned, 18 findings, 18 unowned');
    await expect(page.getByTestId('coverage-node-stats-app')).toContainText('own entry vp-stats-app');

    // Pick core: the project-scoped entry is suggested and explained.
    await core.click();
    await expect(core).toHaveAttribute('aria-selected', 'true');
    const assign = page.getByTestId('assign-panel');
    await expect(assign.getByTestId('assign-entry-core')).toHaveValue('project:ViewPoint_Product::core');
    await expect(assign).toContainText('Components named core, or whose package URL names it, only in ViewPoint_Product');

    // The team combobox: existing teams, found by a former name too.
    const combobox = assign.getByRole('combobox', { name: 'Team' });
    await combobox.fill('de-co');
    await expect(page.getByRole('option', { name: /Core/ })).toContainText('former name DE-Core');
    await combobox.press('Enter');
    await expect(combobox).toHaveValue('Core');

    // The effect is previewed without asking.
    await expect(assign.getByTestId('assign-preview-result')).toContainText('18 findings of 1188 change owner');
    await expect(assign.getByTestId('assign-preview-result')).toContainText('Unknown → Core (18)');

    await assign.getByRole('button', { name: 'Add to Core' }).click();
    await expect(page.getByTestId('assign-feedback')).toContainText('Added project:ViewPoint_Product::core to Core. Not saved yet');
    // The tree shows the draft: core is Core's now, marked as unsaved.
    await expect(page.getByTestId('coverage-node-core')).toContainText('was Unknown');
    await expect(page.getByTestId('overview-unowned-after')).toContainText('1202 after saving');

    // The save bar: the change, its effect, review.
    const bar = page.getByTestId('team-mapping-save-bar');
    await expect(bar.getByTestId('team-mapping-unsaved')).toHaveText('1 unsaved change');
    await expect(bar).toContainText('18 findings change owner');
    await bar.getByRole('button', { name: 'Review changes' }).click();
    await expect(bar.getByTestId('team-mapping-review')).toContainText('Core: added entry project:ViewPoint_Product::core');
    await expect(bar.getByTestId('team-mapping-review')).toContainText('Unknown → Core: 18');

    await bar.getByTestId('team-mapping-save').click();
    await expect(page.getByTestId('team-mapping-message')).toContainText('Team mapping saved');
    expect(saved).toEqual([{
        Core: { aliases: ['DE-Core'], components: ['vp-stats-app', 'gone-lib', 'project:ViewPoint_Product::core'] },
        Phoenix: { components: ['VPStatsApp'] },
        '3P': { components: ['libtiff'] },
        Unknown: { components: ['*'] },
    }]);
});

test('checks block saving, offer fixes, and discard restores the saved mapping', async ({ page }) => {
    const saved: unknown[] = [];
    await openEditor(page, saved);

    // The unowned view: give the eventserver project to a new team.
    const unowned = page.getByTestId('coverage-unowned');
    await expect(unowned).toContainText('project::eventserver');
    await unowned.getByRole('checkbox', { name: 'Pick eventserver' }).check();
    const combobox = page.getByRole('combobox', { name: 'Team' });
    await combobox.fill('Events');
    await page.getByTestId('team-option-new').click();
    await expect(page.getByTestId('assign-panel')).toContainText('A new team Events is created.');
    await page.getByRole('button', { name: 'Add to Events' }).click();
    await expect(page.getByTestId('assign-feedback')).toContainText('Created team Events and added project eventserver');
    await expect(unowned.getByTestId('unowned-row-eventserver')).toContainText('Given to Events in your unsaved changes');

    // Give libtiff to Phoenix too: listed under two teams is an error.
    await page.getByRole('tab', { name: /Teams/ }).click();
    await page.getByRole('button', { name: 'Toggle Phoenix' }).click();
    const phoenix = page.getByTestId('team-card-Phoenix');
    await phoenix.getByTestId('team-add-component-Phoenix').fill('libtiff');
    await expect(page.getByTestId('team-draft-preview-Phoenix')).toContainText('Matches 1 component in 1 project');
    await phoenix.getByRole('button', { name: 'Add component' }).click();

    await expect(page.getByTestId('overview-errors')).toHaveText('1');
    const bar = page.getByTestId('team-mapping-save-bar');
    await expect(bar.getByTestId('team-mapping-save')).toBeDisabled();
    await bar.getByRole('button', { name: '1 error blocks saving' }).click();

    // The checks, grouped: the conflict first, with "Keep in …" fixes.
    const checks = page.getByTestId('validation-panel');
    const conflict = checks.getByTestId('check-group-conflict');
    await expect(conflict).toContainText('Entry libtiff is listed under Phoenix and 3P');
    await expect(checks.getByTestId('check-group-disagreement')).toContainText('vp-stats-app (Core) and VPStatsApp (Phoenix)');
    await expect(checks.getByTestId('check-group-stale')).toContainText('Core: gone-lib');
    await conflict.getByRole('button', { name: 'Keep in 3P' }).click();
    await expect(page.getByTestId('overview-errors')).toHaveText('0');
    await expect(bar.getByTestId('team-mapping-save')).toBeEnabled();

    // An inline fix for a stale entry.
    await checks.getByTestId('check-group-stale').getByRole('button', { name: 'Remove entry' }).first().click();
    await expect(checks.getByTestId('check-group-stale')).not.toContainText('gone-lib');

    // Discard asks, then restores the saved mapping.
    page.once('dialog', dialog => dialog.accept());
    await bar.getByTestId('team-mapping-discard').click();
    await expect(page.getByTestId('team-mapping-save-bar')).toHaveCount(0);
    await expect(checks.getByTestId('check-group-stale')).toContainText('Core: gone-lib');
    await page.getByRole('tab', { name: /Teams/ }).click();
    await expect(page.getByTestId('team-card-Events')).toHaveCount(0);
    expect(saved).toEqual([]);
});

test('keyboard only: tabs, the tree, the team combobox and leaving with changes', async ({ page }) => {
    const saved: unknown[] = [];
    await openEditor(page, saved);

    // The view tabs follow the ARIA tabs pattern.
    await page.getByRole('tab', { name: /Unowned/ }).focus();
    await page.keyboard.press('ArrowRight');
    await expect(page.getByRole('tab', { name: /Projects/ })).toBeFocused();
    await expect(page.getByRole('tab', { name: /Projects/ })).toHaveAttribute('aria-selected', 'true');
    await page.getByTestId('coverage-project-ViewPoint_Product').focus();
    await page.keyboard.press('Enter');

    // The tree: one tab stop, arrows move, open and close, Space picks.
    const tree = page.getByRole('tree', { name: 'Components of ViewPoint_Product' });
    const root = tree.getByRole('treeitem', { name: /^ViewPoint_Product,/ });
    await root.focus();
    await expect(root).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('ArrowDown');
    const core = tree.getByRole('treeitem', { name: /^core,/ });
    await expect(core).toBeFocused();
    await expect(core).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('ArrowRight');
    await expect(core).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('ArrowRight');
    await expect(tree.getByRole('treeitem', { name: /^zlib,/ })).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(core).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(core).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('Home');
    await expect(root).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press(' ');
    await expect(core).toHaveAttribute('aria-selected', 'true');

    // The combobox: arrows choose, Enter takes; then Tab to "Add to …".
    const combobox = page.getByRole('combobox', { name: 'Team' });
    await combobox.focus();
    await page.keyboard.press('ArrowDown');
    await expect(combobox).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await expect(combobox).toHaveValue('Phoenix');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Add to Phoenix' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.getByTestId('assign-feedback')).toContainText('to Phoenix');

    // Leaving the tab with unsaved changes asks first.
    page.once('dialog', dialog => dialog.dismiss());
    await page.getByRole('button', { name: 'User Roles' }).click();
    await expect(page.getByTestId('team-mapping-editor')).toBeVisible();
    page.once('dialog', dialog => dialog.accept());
    await page.getByRole('button', { name: 'User Roles' }).click();
    await expect(page.getByTestId('team-mapping-editor')).toHaveCount(0);
    expect(saved).toEqual([]);
});
