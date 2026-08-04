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
    getTeamGroups: vi.fn(),
    listProjectArchiveSnapshots: vi.fn(),
    startProjectArchiveExport: vi.fn(),
    updateAutoAnalysisGuidance: vi.fn(),
    updateTeamGroups: vi.fn(),
    uploadProjectArchiveImport: vi.fn(),
    uploadAutoAnalysisGuidance: vi.fn(),
    uploadRoles: vi.fn(),
    getTeamMapping: vi.fn(),
    uploadTeamMapping: vi.fn(),
    updateTeamMapping: vi.fn(),
    getRescoreRules: vi.fn(),
    getPerformanceStatus: vi.fn(),
    uploadRescoreRules: vi.fn(),
    updateRescoreRules: vi.fn(),
    waitForProjectArchiveTask: vi.fn(),
}))

describe('Settings.vue', () => {
    const mockUser = ref({ role: 'REVIEWER' })

    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(api.getTeamMapping).mockResolvedValue({ 'comp': 'team' })
        vi.mocked(api.getTeamGroups).mockResolvedValue({})
        vi.mocked(api.getRoles).mockResolvedValue({ 'user': 'REVIEWER' })
        vi.mocked(api.getRescoreRules).mockResolvedValue({ transitions: [] })
        vi.mocked(api.getAutoAnalysisGuidance).mockResolvedValue({ components: {} })
        vi.mocked(api.listProjectArchiveSnapshots).mockResolvedValue([])
        vi.mocked(api.getPerformanceStatus).mockResolvedValue({
            python: {
                implementation: 'CPython',
                version: '3.14.4',
                free_threaded_build: true,
                gil_enabled: false,
                free_threading_active: true,
                free_threading_required: true,
            },
            group_queries: {
                workers: 4, max_pending: 8, capacity: 12,
                outstanding: 2, active: 1, queued: 1,
                accepted_total: 20, completed_total: 18, rejected_total: 1,
                superseded_total: 0, failed_total: 0, max_outstanding: 4,
                queue_time_ms_total: 12, execution_time_ms_total: 120,
            },
            group_builds: {
                workers: 1, max_pending: 2, capacity: 3,
                outstanding: 0, active: 0, queued: 0, waiting: 0,
                accepted_total: 4, completed_total: 4, failed_total: 0,
                max_outstanding: 1, queue_time_ms_total: 0,
                execution_time_ms_total: 80,
            },
            group_details: {
                workers: 2, max_pending: 8, capacity: 10,
                outstanding: 0, active: 0, queued: 0, waiting: 0,
                accepted_total: 8, completed_total: 8, failed_total: 0,
                max_outstanding: 2, queue_time_ms_total: 0,
                execution_time_ms_total: 40,
            },
            grouped_tasks: { total: 3, by_status: { completed: 2, running: 1 } },
            cache: {
                memory_entries: 32, memory_entry_limit: 256,
                dirty_entries: 0, write_pending: false, write_errors: 0,
                named_project_queries: 2, named_project_query_limit: 128,
                active_projects: 3, active_project_limit: 8,
            },
        })
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

    it('shows live backend runtime and capacity information to reviewers', async () => {
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
        const runtimeTab = wrapper.findAll('button')
            .find(button => button.text().includes('Runtime'))
        await runtimeTab?.trigger('click')
        await flushPromises()

        expect(api.getPerformanceStatus).toHaveBeenCalledOnce()
        expect(wrapper.get('[data-testid="backend-python-version"]').text()).toContain('CPython 3.14.4')
        expect(wrapper.get('[data-testid="backend-gil-state"]').text()).toContain('GIL disabled')
        expect(wrapper.get('[data-testid="backend-executor-queries"]').text()).toContain('Capacity')
        expect(wrapper.get('[data-testid="backend-runtime-panel"]').text()).toContain('Memory entries')
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

    it('configures nested groups from canonical mapped teams', async () => {
        vi.mocked(api.getTeamMapping).mockResolvedValue({
            core: ['Core-MUC', 'Core Legacy'],
            vendor: '3rd Party',
            runtime: 'Runtime',
        })
        vi.mocked(api.getTeamGroups).mockResolvedValue({
            'Core-MUC': {
                teams: ['Core-MUC', '3rd Party'],
                groups: [],
            },
            Engineering: {
                teams: ['Runtime'],
                groups: ['Core-MUC'],
            },
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
        const teamGroupsTab = wrapper.findAll('button')
            .find(button => button.text().includes('Team Groups'))
        await teamGroupsTab?.trigger('click')
        await flushPromises()

        expect(wrapper.get('[data-testid="team-group-editor"]').text()).toContain('Core-MUC')
        const directTeamOptions = wrapper.findAll(
            '[data-testid^="team-group-teams-"] option',
        ).map(option => option.text())
        expect(directTeamOptions).toContain('Core-MUC')
        expect(directTeamOptions).toContain('3rd Party')
        expect(directTeamOptions).not.toContain('Core Legacy')
        expect((wrapper.get('[data-testid="team-groups-json"]').element as HTMLTextAreaElement).value)
            .toContain('"groups": [')
    })

    it('saves explicit team and nested-group membership', async () => {
        vi.mocked(api.updateTeamGroups).mockResolvedValue({
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
        const teamGroupsTab = wrapper.findAll('button')
            .find(button => button.text().includes('Team Groups'))
        await teamGroupsTab?.trigger('click')
        await flushPromises()

        const config = {
            'Core-MUC': {
                teams: ['Core-MUC', '3rd Party'],
                groups: [],
            },
            Engineering: {
                teams: [],
                groups: ['Core-MUC'],
            },
        }
        await wrapper.get('[data-testid="team-groups-json"]')
            .setValue(JSON.stringify(config))
        await wrapper.get('[data-testid="save-team-groups"]').trigger('click')
        await flushPromises()

        expect(api.updateTeamGroups).toHaveBeenCalledWith(config)
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
