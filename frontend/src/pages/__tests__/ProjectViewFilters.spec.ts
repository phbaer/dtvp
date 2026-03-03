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
                    components: [{ component_name: 'CompA', analysis_state: 'NOT_SET' }]
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
                    components: [{ component_name: 'CompB', analysis_state: 'FALSE_POSITIVE' }] // Assessed
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
                        { component_name: 'CompA', analysis_state: 'NOT_SET' },
                        { component_name: 'CompC', analysis_state: 'FALSE_POSITIVE' }
                    ]
                }
            ] // Mixed
        }
    ]

    const mockDataWithPending = [
        ...mockData,
        {
            id: 'V4',
            severity: 'HIGH',
            cvss_score: 8.0,
            tags: ['team-b'],
            affected_versions: [
                {
                    components: [{
                        analysis_state: 'FALSE_POSITIVE',
                        analysis_details: 'Some details\n\n[Status: Pending Review]'
                    }]
                }
            ]
        }
    ]



    it('filters out assessed vulnerabilities when hideAssessed is true', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)

        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: {
                plugins: [router],
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises() // Wait for fetch

        // Default state: Assessed is hidden, Mixed is visible.
        // We want to test that enabling the filter works, so we first disable assessed to show everything.
        const checkboxes = wrapper.findAll('input[type="checkbox"]')
        const hideAssessedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Assessed'))
        const hideMixedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Mixed'))

        if (hideAssessedBox && hideMixedBox) {
            await hideAssessedBox.setValue(false)
            // hideMixed is already false
        }

        // Initial state (after manual reset): all visible
        expect(wrapper.findAll('.vuln-card').length).toBe(3)

        // Toggle Hide Assessed

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
                plugins: [router],
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises()

        // Default state: Assessed is hidden, Mixed is visible.
        // We want to test that enabling the filter works, so we first disable assessed to show everything.
        const checkboxes = wrapper.findAll('input[type="checkbox"]')
        const hideAssessedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Assessed'))
        const hideMixedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Mixed'))

        if (hideAssessedBox && hideMixedBox) {
            await hideAssessedBox.setValue(false)
            // hideMixed is already false
        }



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
                plugins: [router],
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises()

        // Default state: Assessed is hidden, Mixed is visible.
        // We want to test ID filtering on the full set, so we disable the state filters.
        const checkboxes = wrapper.findAll('input[type="checkbox"]')
        const hideAssessedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Assessed'))
        const hideMixedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Mixed'))

        if (hideAssessedBox && hideMixedBox) {
            await hideAssessedBox.setValue(false)
            // hideMixed is already false
        }

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

    it('shows "Pending Review" vulnerabilities even when hideAssessed is true', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockDataWithPending)

        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: {
                plugins: [router],
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises()

        const checkboxes = wrapper.findAll('input[type="checkbox"]')
        const hideAssessedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Assessed'))

        if (hideAssessedBox) {
            await hideAssessedBox.setValue(true)

            // V2 (Assessed, no pending) should be gone.
            // V4 (Assessed, but Pending Review) should be visible (but will fail currently).
            const cards = wrapper.findAll('.vuln-card')
            const ids = cards.map(c => c.text())
            // Debug output if needed
            // console.log('Visible IDs:', ids)

            expect(ids).not.toContain('V2')
            expect(ids).toContain('V4')
        } else {
            throw new Error('Hide Assessed checkbox not found')
        }
    })

    it('filters vulnerabilities by component name', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)

        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: {
                plugins: [router],
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises()

        // Disable state filters to see all
        const checkboxes = wrapper.findAll('input[type="checkbox"]')
        const hideAssessedBox = checkboxes.find(c => c.element.parentElement?.textContent?.includes('Hide Assessed'))
        if (hideAssessedBox) await hideAssessedBox.setValue(false)

        const compInput = wrapper.find('input[placeholder*="Filter by Component"]')
        expect(compInput.exists()).toBe(true)

        await compInput.setValue('CompB')
        const cardsB = wrapper.findAll('.vuln-card')
        expect(cardsB.length).toBe(1)
        expect(cardsB[0]?.text()).toBe('V2')

        await compInput.setValue('CompA')
        const cardsA = wrapper.findAll('.vuln-card')
        expect(cardsA.length).toBe(2) // V1 and V3
        const ids = cardsA.map(c => c.text())
        expect(ids).toContain('V1')
        expect(ids).toContain('V3')

        await compInput.setValue('comp') // Case insensitive
        expect(wrapper.findAll('.vuln-card').length).toBe(3)

        await compInput.setValue('Unknown')
        expect(wrapper.findAll('.vuln-card').length).toBe(0)
    })
})
