import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ProjectView from '../ProjectView.vue'
import { getGroupedVulns } from '../../lib/api'
import { createRouter, createMemoryHistory } from 'vue-router'

// Mock API
vi.mock('../../lib/api', () => ({
    getGroupedVulns: vi.fn(),
    updateAssessment: vi.fn(),
}))

// Mock Child Components
vi.mock('../../components/VulnGroupCard.vue', () => ({
    default: {
        template: '<div class="vuln-card" :data-state="group.displayState">{{ group.id }}</div>',
        props: ['group']
    }
}))

// Setup Router with name param
const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/projects/:uuid/:name', component: ProjectView }]
})

describe('ProjectView Filters', () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    const mockData = [
        {
            id: 'V1',
            severity: 'CRITICAL',
            cvss_score: 9.8,
            tags: ['team-a'],
            affected_versions: [
                {
                    components: [{ analysis_state: 'NOT_SET' }]
                }
            ]
        },
        {
            id: 'V2',
            severity: 'HIGH',
            cvss_score: 8.5,
            tags: ['team-b'],
            affected_versions: [
                {
                    components: [{ analysis_state: 'FALSE_POSITIVE' }] // Assessed
                }
            ]
        },
        {
            id: 'V3',
            severity: 'MEDIUM',
            cvss_score: 5.5,
            tags: ['team-c'],
            affected_versions: [
                {
                    components: [
                        { analysis_state: 'NOT_SET' },
                        { analysis_state: 'FALSE_POSITIVE' }
                    ]
                }
            ] // Mixed
        }
    ]

    it('filters out assessed vulnerabilities when hideAssessed is true', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)

        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: {
                plugins: [router]
            }
        })

        await flushPromises() // Wait for fetch

        // Initial state: all visible
        expect(wrapper.findAll('.vuln-card').length).toBe(3)

        // Toggle Hide Assessed (find the checkbox responsible for v-model="hideAssessed")
        const checkboxes = wrapper.findAll('input[type="checkbox"]')
        const hideAssessedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Assessed'))

        if (hideAssessedBox) {
            await hideAssessedBox.setValue(true)

            // V2 (Assessed) should be gone. V1 (Not Set) and V3 (Mixed) remain.
            const cards = wrapper.findAll('.vuln-card')
            expect(cards.length).toBe(2)
            const ids = cards.map(c => c.text())
            expect(ids).toContain('V1')
            expect(ids).toContain('V3')
            expect(ids).not.toContain('V2')
        } else {
            throw new Error('Hide Assessed checkbox not found')
        }
    })

    it('filters out mixed vulnerabilities when hideMixed is true', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)

        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: {
                plugins: [router]
            }
        })

        await flushPromises()

        const checkboxes = wrapper.findAll('input[type="checkbox"]')
        const hideMixedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Mixed'))

        if (hideMixedBox) {
            await hideMixedBox.setValue(true)

            // V3 (Mixed) should be gone. V1 (Not Set) and V2 (Assessed) remain.
            const cards = wrapper.findAll('.vuln-card')
            expect(cards.length).toBe(2)
            const ids = cards.map(c => c.text())
            expect(ids).toContain('V1')
            expect(ids).toContain('V2')
            expect(ids).not.toContain('V3')
        } else {
            throw new Error('Hide Mixed checkbox not found')
        }
    })

    it('filters vulnerabilities by ID', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)

        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: {
                plugins: [router]
            }
        })

        await flushPromises()

        const idInput = wrapper.find('input[placeholder*="Filter by ID"]')
        expect(idInput.exists()).toBe(true)

        await idInput.setValue('V1')

        const cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(1)
        expect(cards[0]?.text()).toBe('V1')

        await idInput.setValue('v') // Case insensitive check
        expect(wrapper.findAll('.vuln-card').length).toBe(3)

        await idInput.setValue('X') // No match
        expect(wrapper.findAll('.vuln-card').length).toBe(0)
    })
})
