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
        expect(menu?.textContent).toContain('Alpha')
        expect(menu?.textContent).toContain('Beta')

        wrapper.unmount()
    })
})