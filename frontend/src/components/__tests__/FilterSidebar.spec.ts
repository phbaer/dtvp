import { afterEach, describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import FilterSidebar, { type FilterState } from '../FilterSidebar.vue'

describe('FilterSidebar.vue', () => {
    const baseFilters: FilterState = {
        sortBy: 'risk',
        sortOrder: 'desc',
        dependencyFilter: ['DIRECT'],
        tmrescoreFilter: ['WITH_PROPOSAL'],
        idFilter: 'CVE-2024-0001',
        tagFilter: 'team-a',
        componentFilter: 'auth-service',
        assigneeFilter: 'alice',
        versionFilterInput: '1.0, 2.0',
        lifecycleFilters: ['EXPLOITABLE'],
        analysisFilters: ['WITH_PROPOSAL'],
        cvssVersionMismatchOnly: false,
        attributionAgeDays: null,
        attributionAgeMode: 'older',
    }

    const lifecycleOptions = [
        { value: 'EXPLOITABLE', label: 'Exploitable', color: 'text-red-500', description: 'Exploitable issues' },
    ]
    const analysisOptions = [
        { value: 'WITH_PROPOSAL', label: 'With Proposal', color: 'text-blue-500', description: 'Proposals available' },
    ]

    const wrapperFactory = () => mount(FilterSidebar, {
        attachTo: document.body,
        global: {
            stubs: {
                teleport: false,
            },
        },
        props: {
            filters: { ...baseFilters },
            filterCounts: {
                EXPLOITABLE: 5,
                WITH_PROPOSAL: 3,
            },
            availableVersions: ['1.0', '2.0', '3.0'],
            lifecycleOptions,
            analysisOptions,
            copiedUrl: true,
        },
    })

    afterEach(() => {
        document.body.innerHTML = ''
    })

    it('emits copy and reset actions', async () => {
        const wrapper = wrapperFactory()

        await wrapper.find('button[title="Copy current filter URL"]').trigger('click')
        const resetButton = wrapper.findAll('button').find((button) => button.text() === 'Reset All Filters')
        expect(resetButton).toBeTruthy()
        await resetButton?.trigger('click')

        expect(wrapper.emitted('copy-filter-url')).toBeTruthy()
        expect(wrapper.emitted('reset-filters')).toBeTruthy()

        wrapper.unmount()
    })

    it('updates text filters and emits the new filters object', async () => {
        const wrapper = wrapperFactory()
        const idInput = wrapper.find('input[placeholder="CVE or ID..."]')
        const tagInput = wrapper.find('input[placeholder="Team Identifier..."]')

        await idInput.setValue('CVE-2026-1234')
        await tagInput.setValue('team-b')

        expect(wrapper.emitted('update:filters')).toBeTruthy()
        const emitted = wrapper.emitted('update:filters')?.map(([payload]) => payload)
        expect(emitted).toContainEqual(expect.objectContaining({ idFilter: 'CVE-2026-1234' }))
        expect(emitted).toContainEqual(expect.objectContaining({ tagFilter: 'team-b' }))

        wrapper.unmount()
    })

    it('toggles lifecycle and analysis filter buttons', async () => {
        const wrapper = wrapperFactory()
        const buttons = wrapper.findAll('button')
        const lifecycleButton = buttons.find((button) => button.text().includes('Exploitable'))
        const analysisButton = buttons.find((button) => button.text().includes('With Proposal'))

        expect(lifecycleButton).toBeTruthy()
        expect(analysisButton).toBeTruthy()

        await lifecycleButton?.trigger('click')
        await analysisButton?.trigger('click')

        const emitted = wrapper.emitted('update:filters')?.map(([payload]) => payload)
        expect(emitted).toContainEqual(expect.objectContaining({ lifecycleFilters: [] }))
        expect(emitted).toContainEqual(expect.objectContaining({ analysisFilters: [] }))

        wrapper.unmount()
    })

    it('adds a version via the select menu and emits the updated versionFilterInput', async () => {
        const wrapper = wrapperFactory()
        const customSelectTrigger = wrapper.find('div[tabindex="-1"] .cursor-text')
        expect(customSelectTrigger.exists()).toBe(true)

        await customSelectTrigger.trigger('click')
        await nextTick()

        const option = Array.from(document.body.querySelectorAll('button')).find((button) =>
            button.textContent?.trim() === '3.0'
        ) as HTMLElement | undefined

        expect(option).toBeTruthy()
        option?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
        await nextTick()

        const emitted = wrapper.emitted('update:filters')?.map(([payload]) => payload)
        expect(emitted).toContainEqual(expect.objectContaining({ versionFilterInput: '1.0, 2.0, 3.0' }))

        wrapper.unmount()
    })

    it('exposes the attribution age filter', async () => {
        const wrapper = wrapperFactory()
        const trigger = wrapper.findAll('button').find((button) => button.text().includes('Any age'))
        expect(trigger).toBeTruthy()

        await trigger?.trigger('click')
        await nextTick()

        const presetButton = Array.from(document.body.querySelectorAll('button')).find((button) =>
            button.textContent?.trim() === '30d'
        ) as HTMLElement | undefined

        expect(presetButton).toBeTruthy()
        presetButton?.click()
        await nextTick()

        const emitted = wrapper.emitted('update:filters')?.map(([payload]) => payload)
        expect(emitted).toContainEqual(expect.objectContaining({ attributionAgeDays: 30 }))

        wrapper.unmount()
    })
})
