import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import ProjectView from '../ProjectView.vue'
import { createRouter, createWebHistory } from 'vue-router'
import flushPromises from 'flush-promises'
import * as api from '../../lib/api'

// Mock api
vi.mock('../../lib/api', () => ({
    getGroupedVulns: vi.fn(),
    startGroupVulnTask: vi.fn(),
    getTaskStatus: vi.fn(),
    getCacheStatus: vi.fn(() => Promise.resolve({ fully_cached: false, last_refreshed_at: null, projects: 0, active_projects: 0, cached_findings: 0, cached_boms: 0, cached_analyses: 0, pending_updates: 0 })),
    getTeamMapping: vi.fn(() => Promise.resolve({})),
    getRescoreRules: vi.fn(() => Promise.resolve({ transitions: [] })),
    getTMRescoreProposals: vi.fn(() => Promise.resolve({ proposals: {} })),
}))

const router = createRouter({
    history: createWebHistory(),
    routes: [
        { path: '/', component: { template: '<div />' } },
        { path: '/statistics', component: { template: '<div />' } },
        { path: '/project/:name', component: ProjectView }
    ]
})

describe('ProjectView Sorting Extra', () => {
    it('sorts by tags', async () => {
        const mockVulns = [
            { id: 'V1', severity: 'HIGH', tags: ['TeamB'], affected_versions: [] },
            { id: 'V2', severity: 'LOW', tags: ['TeamA'], affected_versions: [] },
            { id: 'V3', severity: 'MEDIUM', tags: [], affected_versions: [] }
        ]
        vi.mocked(api.getGroupedVulns).mockResolvedValue(mockVulns as any)

        router.push('/project/test')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: {
                plugins: [router],
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                },
                stubs: {
                    LoadingProgress: true,
                    VulnGroupCard: {
                        props: ['group'],
                        template: '<div class="vuln-group-card" :data-id="group.id">{{ group.id }}</div>'
                    }
                }
            }
        })

        await flushPromises()
        ;(wrapper.vm as any).lifecycleFilters = ['OPEN', 'ASSESSED', 'INCOMPLETE', 'INCONSISTENT']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
        await wrapper.vm.$nextTick()

        // Set sortBy to tags
        ;(wrapper.vm as any).sortBy = 'tags'
        ;(wrapper.vm as any).sortOrder = 'asc'
        await wrapper.vm.$nextTick()

        await wrapper.vm.$nextTick()

        const cards = wrapper.findAll('.vuln-group-card')
        expect(cards.length).toBe(3)
        if (cards.length === 3) {
            // Check IDs
            expect(cards[0]!.attributes('data-id')).toBe('V3')
            expect(cards[1]!.attributes('data-id')).toBe('V2')
            expect(cards[2]!.attributes('data-id')).toBe('V1')
        }
    })
})
