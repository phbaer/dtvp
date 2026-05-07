import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import Settings from '../Settings.vue'
import * as api from '../../lib/api'
import { ref, computed } from 'vue'

vi.mock('../../lib/api', () => ({
    getCacheStatus: vi.fn(),
    getKnowledgeStoreStatus: vi.fn(),
    getOperationalHealth: vi.fn(),
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
        vi.mocked(api.getCacheStatus).mockResolvedValue({
            fully_cached: true,
            last_refreshed_at: '2026-05-05T12:00:00Z',
            projects: 4,
            active_projects: 2,
            cached_findings: 8,
            cached_boms: 2,
            cached_analyses: 6,
            pending_updates: 1,
            pending_updates_oldest_age_seconds: 45,
            knowledge_store_write_queue_size: 2,
            knowledge_store_write_queue_oldest_age_seconds: 15,
        })
        vi.mocked(api.getKnowledgeStoreStatus).mockResolvedValue({
            path: '/tmp/knowledge',
            assessment_records: 7,
            assessment_triplet_index_entries: 9,
            orphaned_assessment_records: 1,
            code_analysis_queue_items: 3,
            code_analysis_queue_status_counts: {
                completed: 2,
                failed: 1,
            },
            last_maintenance_at: '2026-05-07T10:00:00+00:00',
            last_purge_deleted_records: 2,
        })
        vi.mocked(api.getOperationalHealth).mockResolvedValue({
            status: 'warning',
            checked_at: '2026-05-07T10:05:00+00:00',
            checks: {
                pending_updates_backlog: {
                    name: 'pending_updates_backlog',
                    status: 'warning',
                    count: 1,
                    count_threshold: 1,
                    oldest_age_seconds: 45,
                    age_threshold_seconds: 300,
                },
                knowledge_store_write_backlog: {
                    name: 'knowledge_store_write_backlog',
                    status: 'ok',
                    count: 2,
                    count_threshold: 100,
                    oldest_age_seconds: 15,
                    age_threshold_seconds: 60,
                },
                knowledge_store_orphans: {
                    name: 'knowledge_store_orphans',
                    status: 'warning',
                    count: 1,
                    count_threshold: 1,
                },
                knowledge_store_maintenance_freshness: {
                    name: 'knowledge_store_maintenance_freshness',
                    status: 'ok',
                    last_maintenance_at: '2026-05-07T10:00:00+00:00',
                    age_seconds: 300,
                    age_threshold_seconds: 7200,
                },
            },
        })
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

    it('shows knowledge store runtime status for reviewers', async () => {
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
        await wrapper.vm.$nextTick()

        expect(wrapper.text()).toContain('Runtime Status')
        expect(wrapper.text()).toContain('Knowledge Store')
        expect(wrapper.text()).toContain('Assessment Records')
        expect(wrapper.text()).toContain('/tmp/knowledge')
        expect(wrapper.text()).toContain('completed: 2')
        expect(wrapper.text()).toContain('Operational Health')
        expect(wrapper.text()).toContain('Needs Attention')
        expect(wrapper.text()).toContain('Orphaned Assessments')
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
