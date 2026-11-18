import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import CycloneDxExportMenu from '../CycloneDxExportMenu.vue'
import { getProjects } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getProjects: vi.fn(),
    getCycloneDxDownloadUrl: (uuid: string, variant: string) => `/api/project/${uuid}/cyclonedx?variant=${variant}&download=true`,
}))

const open = async () => {
    const wrapper = mount(CycloneDxExportMenu, { props: { projectName: 'App' }, attachTo: document.body })
    await wrapper.get('[data-testid="cyclonedx-export-button"]').trigger('click')
    await flushPromises()
    return wrapper
}

describe('CycloneDxExportMenu', () => {
    beforeEach(() => vi.clearAllMocks())

    it('lists the versions of this project, newest first, with both downloads', async () => {
        vi.mocked(getProjects).mockResolvedValue([
            { uuid: 'u1', name: 'App', version: '1.9.0' },
            { uuid: 'u2', name: 'App', version: '1.10.0' },
            { uuid: 'u3', name: 'App Tools', version: '5.0' },
        ] as any)
        const wrapper = await open()

        expect(getProjects).toHaveBeenCalledWith('App')
        const rows = wrapper.findAll('[data-testid="cyclonedx-export-version"]')
        expect(rows.map(row => row.find('span').text())).toEqual(['1.10.0', '1.9.0'])
        expect(rows[0].findAll('a').map(link => link.attributes('href'))).toEqual([
            '/api/project/u2/cyclonedx?variant=inventory&download=true',
            '/api/project/u2/cyclonedx?variant=vdr&download=true',
        ])
        wrapper.unmount()
    })

    it('says so when nothing is found or loading fails, and closes on Escape', async () => {
        vi.mocked(getProjects).mockResolvedValue([])
        const empty = await open()
        expect(empty.text()).toContain('No versions found')
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
        await flushPromises()
        expect(empty.find('[data-testid="cyclonedx-export-menu"]').exists()).toBe(false)
        empty.unmount()

        vi.mocked(getProjects).mockRejectedValue(new Error('down'))
        const failed = await open()
        expect(failed.get('[role="alert"]').text()).toContain('could not be loaded')
        failed.unmount()
    })
})
