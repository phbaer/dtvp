import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import Settings from '../Settings.vue'
import * as api from '../../lib/api'
import { ref, computed } from 'vue'

vi.mock('../../lib/api', () => ({
    getRoles: vi.fn(),
    uploadRoles: vi.fn(),
    getTeamMapping: vi.fn(),
    uploadTeamMapping: vi.fn(),
    updateTeamMapping: vi.fn(),
    getRescoreRules: vi.fn(),
    uploadRescoreRules: vi.fn(),
    updateRescoreRules: vi.fn()
}))

describe('Settings.vue', () => {
    const mockUser = ref({ role: 'REVIEWER' })

    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(api.getTeamMapping).mockResolvedValue({ 'comp': 'team' })
        vi.mocked(api.getRoles).mockResolvedValue({ 'user': 'REVIEWER' })
        vi.mocked(api.getRescoreRules).mockResolvedValue({ transitions: [] })
    })

    it('shows Rescore Rules tab for reviewers', async () => {
        const wrapper = mount(Settings, {
            global: {
                provide: {
                    user: mockUser,
                    realRole: computed(() => mockUser.value.role)
                },
                stubs: ['router-link']
            }
        })

        await wrapper.vm.$nextTick()

        const tabs = wrapper.findAll('button')
        const rescoreTab = tabs.find(t => t.text().includes('Rescore Rules'))
        expect(rescoreTab?.exists()).toBe(true)
    })

    it('loads and displays rescore rules in the editor', async () => {
        const mockRules = {
            transitions: [
                {
                    trigger: { state: 'NOT_AFFECTED' },
                    actions: { '3.1': { 'MC': 'N' } }
                }
            ]
        }
        vi.mocked(api.getRescoreRules).mockResolvedValue(mockRules)

        const wrapper = mount(Settings, {
            global: {
                provide: {
                    user: mockUser,
                    realRole: computed(() => mockUser.value.role)
                },
                stubs: ['router-link']
            }
        })

        await wrapper.vm.$nextTick()

        // Switch to rescore tab
        const buttons = wrapper.findAll('button')
        const rescoreTab = buttons.find(b => b.text().includes('Rescore Rules'))
        expect(rescoreTab).toBeDefined()
        await rescoreTab!.trigger('click')
        await wrapper.vm.$nextTick()
        await wrapper.vm.$nextTick() // Second tick for v-if

        const textarea = wrapper.find('textarea')
        expect(textarea.exists()).toBe(true)
        expect(textarea.element.value).toContain('NOT_AFFECTED')
        expect(textarea.element.value).toContain('MC')
    })

    it('saves rescore rules when Save Changes button is clicked', async () => {
        vi.mocked(api.updateRescoreRules).mockResolvedValue({ status: 'success', message: 'Saved' })

        const wrapper = mount(Settings, {
            global: {
                provide: {
                    user: mockUser,
                    realRole: computed(() => mockUser.value.role)
                },
                stubs: ['router-link']
            }
        })

        await wrapper.vm.$nextTick()

        // Switch to rescore tab
        const tabs = wrapper.findAll('button')
        const rescoreTab = tabs.find(t => t.text().includes('Rescore Rules'))
        await rescoreTab?.trigger('click')
        await wrapper.vm.$nextTick()

        const saveButton = wrapper.find('button.bg-green-600')
        await saveButton.trigger('click')

        expect(api.updateRescoreRules).toHaveBeenCalled()
    })
})
