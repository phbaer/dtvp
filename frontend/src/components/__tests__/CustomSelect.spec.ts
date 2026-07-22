import { describe, it, expect, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent, nextTick } from 'vue'
import CustomSelect from '../CustomSelect.vue'

describe('CustomSelect', () => {
    afterEach(() => {
        document.body.innerHTML = ''
    })

    it('renders the dropdown menu in a fixed body overlay', async () => {
        const Host = defineComponent({
            components: { CustomSelect },
            data: () => ({
                options: [
                    { value: 'alpha', label: 'Alpha' },
                    { value: 'beta', label: 'Beta' },
                ]
            }),
            template: `
                <div style="overflow: hidden; height: 32px; width: 220px;">
                    <CustomSelect modelValue="" :options="options" />
                </div>
            `,
        })

        const wrapper = mount(Host, {
            attachTo: document.body,
            global: {
                stubs: {
                    teleport: false,
                }
            }
        })

        await wrapper.find('button').trigger('click')
        await nextTick()

        const menu = document.body.querySelector('[data-testid="custom-select-menu"]') as HTMLElement | null

        expect(menu).not.toBeNull()
        expect(menu?.style.position).toBe('fixed')
        expect(Number(menu?.style.zIndex)).toBeGreaterThan(10000)
        expect(menu?.textContent).toContain('Alpha')
        expect(menu?.textContent).toContain('Beta')

        wrapper.unmount()
    })

    it('searches the complete option list without truncating it', async () => {
        const options = Array.from({ length: 12 }, (_, index) => ({
            value: `team-${index + 1}`,
            label: `Team ${index + 1}`,
        }))
        const wrapper = mount(CustomSelect, {
            attachTo: document.body,
            props: {
                modelValue: '',
                options,
                searchable: true,
                searchPlaceholder: 'Search teams...',
            },
            global: {
                stubs: {
                    teleport: false,
                },
            },
        })

        await wrapper.find('button').trigger('click')
        await nextTick()

        const menu = document.body.querySelector('[data-testid="custom-select-menu"]') as HTMLElement
        expect(menu.querySelectorAll('button')).toHaveLength(12)

        const search = menu.querySelector('input[placeholder="Search teams..."]') as HTMLInputElement
        search.value = 'Team 12'
        search.dispatchEvent(new Event('input', { bubbles: true }))
        await nextTick()

        expect(menu.querySelectorAll('button')).toHaveLength(1)
        expect(menu.textContent).toContain('Team 12')
        expect(menu.textContent).not.toContain('Team 11')

        wrapper.unmount()
    })
})
