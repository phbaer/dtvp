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
    getTaskStatus: vi.fn()
}))

const router = createRouter({
    history: createWebHistory(),
    routes: [{ path: '/project/:name', component: ProjectView }]
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
        await wrapper.vm.$nextTick()

        // Set sortBy to tags
        const select = wrapper.find('select')
        await select.setValue('tags')

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
