import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import Settings from '../Settings.vue'
import * as api from '../../lib/api'
import { ref, computed } from 'vue'

vi.mock('../../lib/api', () => ({
    applyProjectArchiveImport: vi.fn(),
    getProjectArchiveSnapshotDownloadUrl: vi.fn(),
    getProjectArchiveTaskDownloadUrl: vi.fn(),
    getRoles: vi.fn(),
    getAutoAnalysisGuidance: vi.fn(),
    listProjectArchiveSnapshots: vi.fn(),
    startProjectArchiveExport: vi.fn(),
    updateAutoAnalysisGuidance: vi.fn(),
    uploadProjectArchiveImport: vi.fn(),
    uploadAutoAnalysisGuidance: vi.fn(),
    uploadRoles: vi.fn(),
    getTeamMapping: vi.fn(),
    uploadTeamMapping: vi.fn(),
    updateTeamMapping: vi.fn(),
    getRescoreRules: vi.fn(),
    uploadRescoreRules: vi.fn(),
    updateRescoreRules: vi.fn(),
    waitForProjectArchiveTask: vi.fn(),
}))

describe('Settings.vue', () => {
    const mockUser = ref({ role: 'REVIEWER' })

    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(api.getTeamMapping).mockResolvedValue({ 'comp': 'team' })
        vi.mocked(api.getRoles).mockResolvedValue({ 'user': 'REVIEWER' })
        vi.mocked(api.getRescoreRules).mockResolvedValue({ transitions: [] })
        vi.mocked(api.getAutoAnalysisGuidance).mockResolvedValue({ components: {} })
        vi.mocked(api.listProjectArchiveSnapshots).mockResolvedValue([])
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

    it('documents deterministic team mapping selector syntax in the UI', async () => {
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

        expect(wrapper.text()).toContain('deterministic SBOM selectors')
        expect(wrapper.text()).toContain('purl::pkg:type/namespace/name')
        expect(wrapper.text()).toContain('cs::name')
        expect(wrapper.text()).toContain('nogroup::name')
        expect(wrapper.text()).toContain('cs:name and nogroup:name are normal group:name selectors')
    })

    it('keeps focus while editing a structured mapping component key', async () => {
        const wrapper = mount(Settings, {
            attachTo: document.body,
            global: {
                provide: {
                    user: mockUser,
                    realRole: computed(() => mockUser.value.role)
                },
                stubs: ['router-link']
            }
        })

        await flushPromises()

        const input = wrapper.get('input[placeholder="name, group:name, purl::pkg:type/namespace/name"]')
        const inputElement = input.element as HTMLInputElement
        inputElement.focus()
        expect(document.activeElement).toBe(inputElement)

        await input.setValue('component-with-focus')
        await wrapper.vm.$nextTick()

        expect(document.activeElement).toBe(inputElement)
        expect(inputElement.value).toBe('component-with-focus')
        expect(wrapper.get('textarea').element.value).toContain('component-with-focus')

        wrapper.unmount()
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

    it('loads and saves automatic assessment guidance from the Config tab', async () => {
        vi.mocked(api.getAutoAnalysisGuidance).mockResolvedValue({
            components: {
                'keycloak-extension': 'Prefer runtime evidence.',
            },
        })
        vi.mocked(api.updateAutoAnalysisGuidance).mockResolvedValue({
            status: 'success',
            message: 'Saved',
        })

        const wrapper = mount(Settings, {
            global: {
                provide: {
                    user: mockUser,
                    realRole: computed(() => mockUser.value.role)
                },
                stubs: ['router-link']
            }
        })

        await flushPromises()

        const tabs = wrapper.findAll('button')
        const configTab = tabs.find(t => t.text().includes('Config'))
        expect(configTab).toBeDefined()
        await configTab?.trigger('click')
        await flushPromises()

        const textarea = wrapper.find('textarea')
        expect(textarea.element.value).toContain('Prefer runtime evidence')

        await textarea.setValue('{"components":{"keycloak-extension":"Check upstream Keycloak too."}}')
        const saveButton = wrapper.find('button.bg-green-600')
        await saveButton.trigger('click')

        expect(api.updateAutoAnalysisGuidance).toHaveBeenCalledWith({
            components: {
                'keycloak-extension': 'Check upstream Keycloak too.',
            },
        })
    })
})
