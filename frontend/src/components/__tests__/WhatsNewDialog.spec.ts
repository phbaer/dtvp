import { afterEach, describe, expect, it } from 'vitest'
import { mount, type VueWrapper } from '@vue/test-utils'
import WhatsNewDialog from '../WhatsNewDialog.vue'
import type { Release, ReleaseEntry } from '../../lib/whatsNew'

const entry = (text: string, extra: Partial<ReleaseEntry> = {}): ReleaseEntry => ({
    text, scope: null, pr: null, breaking: false, note: null, ...extra,
})
const release = (version: string | null, groups: Partial<Release['groups']>, prerelease = false): Release => ({
    version,
    date: '2026-11-23',
    prerelease,
    unreleased: version === null,
    groups: { breaking: [], new: [], faster: [], fixed: [], ...groups },
})

const v2 = release('2.0.0', {
    breaking: [entry('No polling of watched products', {
        scope: 'sync', pr: 337, breaking: true, note: 'Remove DTVP_SYNC_WATCHED_FINDINGS_SECONDS.',
    })],
    new: [entry('Show progress', { scope: 'sync', pr: 336 }), entry('Gone findings')],
    fixed: [entry('Export keeps the response', { pr: 12 })],
})
const rc3 = release('2.0.0rc3', { new: [entry('Flag risky losses')], fixed: [entry('A')] }, true)
const small = release('2.1.0', {
    new: [entry('One'), entry('Two'), entry('Three'), entry('Four')],
    fixed: [entry('Five'), entry('Six'), entry('Seven')],
})

const mounted: VueWrapper[] = []
type DialogProps = InstanceType<typeof WhatsNewDialog>['$props']
const mountDialog = (props: Partial<DialogProps> & Pick<DialogProps, 'mode'>) => {
    const wrapper = mount(WhatsNewDialog, {
        props: { currentVersion: '2.0.0', shown: [], releases: [], ...props } as DialogProps,
        attachTo: document.body,
    })
    mounted.push(wrapper)
    return wrapper
}

afterEach(() => {
    for (const wrapper of mounted.splice(0)) wrapper.unmount()
})

describe('WhatsNewDialog', () => {
    it('shows a major upgrade prominently: action needed first, fixes folded', () => {
        const wrapper = mountDialog({ mode: 'major', shown: [v2, rc3], previousVersion: '1.0.26' })

        expect(wrapper.find('[data-testid="whats-new-major"]').exists()).toBe(true)
        expect(wrapper.get('#whats-new-title').text()).toBe('River 2.0.0')
        expect(wrapper.text()).toContain('Changes since 1.0.26.')
        const groups = wrapper.findAll('[data-testid^="whats-new-group-"]').map(g => g.attributes('data-testid'))
        expect(groups).toEqual(['whats-new-group-breaking', 'whats-new-group-new', 'whats-new-group-fixed'])
        const breaking = wrapper.get('[data-testid="whats-new-group-breaking"]')
        expect(breaking.text()).toContain('No polling of watched products')
        expect(breaking.text()).toContain('Remove DTVP_SYNC_WATCHED_FINDINGS_SECONDS.')
        expect(breaking.get('a').attributes('href')).toBe('https://git.baer.one/phbaer/dtvp/pulls/337')
        expect(wrapper.get('[data-testid="whats-new-group-fixed"]').element.tagName).toBe('DETAILS')
        // Entries of several versions say which version they came with.
        expect(wrapper.get('[data-testid="whats-new-group-new"]').text()).toContain('v2.0.0rc3')
    })

    it('shows a minor upgrade compactly, with the rest behind "Show all"', async () => {
        const wrapper = mountDialog({ mode: 'compact', currentVersion: '2.1.0', shown: [small] })

        expect(wrapper.get('#whats-new-title').text()).toBe("What's new in River 2.1.0")
        expect(wrapper.findAll('[data-testid="whats-new-compact-list"] li')).toHaveLength(5)
        expect(wrapper.text()).toContain('and 2 more')

        await wrapper.get('[data-testid="whats-new-show-all"]').trigger('click')
        expect(wrapper.find('[data-testid="whats-new-compact-list"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="whats-new-group-fixed"]').text()).toContain('Seven')
        expect(wrapper.find('[data-testid="whats-new-show-all"]').exists()).toBe(false)
    })

    it('lets the user browse every release, starting at the running one', async () => {
        const unreleased = release(null, { new: [entry('Coming soon')] })
        const wrapper = mountDialog({ mode: 'browse', releases: [unreleased, v2, rc3] })

        const versions = wrapper.get('[data-testid="whats-new-versions"]')
        expect(versions.findAll('button').map(b => b.text())).toEqual([
            expect.stringContaining('Not yet released'),
            expect.stringContaining('v2.0.0'),
            expect.stringContaining('v2.0.0rc3'),
        ])
        expect(versions.get('[aria-current="true"]').text()).toContain('v2.0.0')
        expect(wrapper.text()).toContain('Show progress')

        await versions.findAll('button')[2].trigger('click')
        expect(wrapper.text()).toContain('Flag risky losses')
        expect(wrapper.text()).not.toContain('Show progress')
    })

    it('closes with Escape, the close button and the backdrop', async () => {
        const wrapper = mountDialog({ mode: 'compact', shown: [small] })
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
        await wrapper.get('[aria-label="Close what\'s new"]').trigger('click')
        await wrapper.get('[data-testid="whats-new-backdrop"]').trigger('click')
        expect(wrapper.emitted('close')).toHaveLength(3)
    })

    it('is a labelled modal dialog', () => {
        const wrapper = mountDialog({ mode: 'compact', shown: [small] })
        const dialog = wrapper.get('[role="dialog"]')
        expect(dialog.attributes('aria-modal')).toBe('true')
        expect(dialog.attributes('aria-labelledby')).toBe('whats-new-title')
    })
})
