import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ProjectView from '../ProjectView.vue'
import { getGroupedVulns } from '../../lib/api'
import { createRouter, createMemoryHistory } from 'vue-router'

// Mock API
vi.mock('../../lib/api', () => ({
    getGroupedVulns: vi.fn(),
    updateAssessment: vi.fn(),
    getCacheStatus: vi.fn(() => Promise.resolve({ fully_cached: false, last_refreshed_at: null })),
    getTeamMapping: vi.fn(() => Promise.resolve({})),
    getRescoreRules: vi.fn(() => Promise.resolve({ transitions: [] })),
}))

// Mock Child Components
vi.mock('../../components/VulnGroupCard.vue', () => ({
    default: {
        template: '<div class="vuln-card" :data-id="group.id">{{ group.id }}</div>',
        props: ['group']
    }
}))

describe('ProjectView Filters', () => {
    let router: ReturnType<typeof createRouter>

    beforeEach(() => {
        vi.clearAllMocks()
        router = createRouter({
            history: createMemoryHistory(),
            routes: [
                { path: '/', component: { template: '<div />' } },
                { path: '/statistics', component: { template: '<div />' } },
                { path: '/projects/:uuid/:name', component: ProjectView }
            ]
        })
    })

    const mockData = [
        {
            id: 'V1',
            severity: 'CRITICAL',
            cvss_score: 9.8,
            tags: ['team-a'], // requiredTeam: team-a
            affected_versions: [
                {
                    components: [{ 
                        component_name: 'CompA', 
                        analysis_state: 'NOT_SET',
                        analysis_details: '' // No team-a assessment -> OPEN
                    }]
                }
            ]
        },
        {
            id: 'V2',
            severity: 'HIGH',
            cvss_score: 8.5,
            tags: ['team-b'], // requiredTeam: team-b
            affected_versions: [
                {
                    components: [{ 
                        component_name: 'CompB', 
                        analysis_state: 'FALSE_POSITIVE',
                        analysis_details: '--- [Team: General] [State: FALSE_POSITIVE] [Assessed By: tester] [Justification: fixed] ---\n--- [Team: team-b] [State: FALSE_POSITIVE] ---'
                    }]
                }
            ]
        },
        {
            id: 'V3',
            severity: 'MEDIUM',
            cvss_score: 5.5,
            tags: ['team-c'], // requiredTeam: team-c
            affected_versions: [
                {
                    version: '1.0',
                    components: [
                        { 
                            component_name: 'CompC', 
                            analysis_state: 'FALSE_POSITIVE',
                            analysis_details: '--- [Team: team-c] [State: FALSE_POSITIVE] ---' 
                        }
                    ]
                },
                {
                    version: '1.1',
                    components: [
                        { 
                            component_name: 'CompC', 
                            analysis_state: 'NOT_SET',
                            analysis_details: '--- [Team: team-c] [State: NOT_SET] ---' 
                        }
                    ]
                }
            ] 
        },
        {
            id: 'V8',
            severity: 'HIGH',
            cvss_score: 8.0,
            tags: ['team-c'],
            affected_versions: [
                {
                    version: '1.0',
                    components: [
                        {
                            component_name: 'CompC',
                            analysis_state: 'FALSE_POSITIVE',
                            analysis_details: '--- [Team: team-c] [State: FALSE_POSITIVE] ---'
                        }
                    ]
                },
                {
                    version: '1.1',
                    components: [
                        {
                            component_name: 'CompC',
                            analysis_state: 'EXPLOITABLE',
                            analysis_details: '--- [Team: team-c] [State: EXPLOITABLE] ---'
                        }
                    ]
                }
            ]
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
                    },
                    {
                        analysis_state: 'NOT_SET',
                        analysis_details: ''
                    }]
                }
            ]
        }
    ]

    const mockDataWithPlaintext = [
        ...mockData,
        {
            id: 'V5',
            severity: 'LOW',
            cvss_score: 2.1,
            tags: ['team-a'],
            affected_versions: [
                {
                    components: [{
                        component_name: 'CompA',
                        analysis_state: 'NOT_SET',
                        analysis_details: 'This is a plaintext assessment with no structured blocks.'
                    }]
                }
            ]
        },
        {
            id: 'V6',
            severity: 'LOW',
            cvss_score: 2.0,
            tags: ['team-a'],
            affected_versions: [
                {
                    components: [{
                        component_name: 'CompA',
                        analysis_state: 'NOT_AFFECTED',
                        analysis_details: 'Plaintext not affected comment.'
                    }]
                }
            ]
        }
    ]

    it('filters vulnerabilities by lifecycle status chips', async () => {
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

        // Default for REVIEWER: All Lifecycle + All Analysis.
        // Shows V1, V2, V3, V8
        let cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(4)

        // Change to Analyst defaults (Open + Incomplete + Inconsistent + All Analysis)
        ;(wrapper.vm as any).lifecycleFilters = ['OPEN', 'INCOMPLETE', 'INCONSISTENT']
        await wrapper.vm.$nextTick()
        // Shows V1 (OPEN), V3 (INCONSISTENT), V8 (INCONSISTENT)
        cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(3)
        expect(cards.map(c => c.text())).toContain('V1')
        expect(cards.map(c => c.text())).toContain('V3')
        expect(cards.map(c => c.text())).toContain('V8')

        // Turn on specific 'Incomplete' chip in Lifecycle and 'Not Set' in Analysis
        ;(wrapper.vm as any).lifecycleFilters = ['INCOMPLETE']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET']
        await wrapper.vm.$nextTick()
        cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(0) // None are INCOMPLETE
    })

    it('ANDs lifecycle and analysis filters strictly', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)
        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: { plugins: [router], provide: { user: { value: { role: 'REVIEWER' } } } }
        })
        await flushPromises()
        
        // Default REVIEWER: shows 4
        expect(wrapper.findAll('.vuln-card').length).toBe(4)

        // Set Lifecycle to Open + Incomplete + Inconsistent
        ;(wrapper.vm as any).lifecycleFilters = ['OPEN', 'INCOMPLETE', 'INCONSISTENT']
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(3)

        // Set Analysis to ONLY 'False Positive'
        ;(wrapper.vm as any).analysisFilters = ['FALSE_POSITIVE']
        await wrapper.vm.$nextTick()
        
        // V1 is NOT_SET (OPEN), V3 is FALSE_POSITIVE (INCONSISTENT).
        // V3 matches Lifecycle=INCONSISTENT AND Analysis=False Positive
        expect(wrapper.findAll('.vuln-card').length).toBe(1)
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toBe('V3')

        // Set Lifecycle to ONLY 'Assessed'
        ;(wrapper.vm as any).lifecycleFilters = ['ASSESSED']
        await wrapper.vm.$nextTick()
        // V2 matches Lifecycle=Assessed AND Analysis=False Positive
        expect(wrapper.findAll('.vuln-card').length).toBe(1)
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toBe('V2')
        
        // Clear Analysis filters
        ;(wrapper.vm as any).analysisFilters = []
        await wrapper.vm.$nextTick()
        // Should show nothing
        expect(wrapper.findAll('.vuln-card').length).toBe(0)
    })

    it('supports "Reset All" to return to default view', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)
        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: { plugins: [router], provide: { user: { value: { role: 'REVIEWER' } } } }
        })
        await flushPromises()
        const getButton = (text: string) => wrapper.findAll('button').find(b => b.text().includes(text))

        ;(wrapper.vm as any).analysisFilters = []
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(0)

        // Reset All
        await getButton('Reset All')?.trigger('click')
        
        // Should return to REVIEWER defaults (all 4 findings)
        expect(wrapper.findAll('.vuln-card').length).toBe(4)
    })

    it('shows "Pending Review" vulnerabilities regardless of filters', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockDataWithPending)
        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: { plugins: [router], provide: { user: { value: { role: 'REVIEWER' } } } }
        })
        await flushPromises()
        
        // Clear all filters
        ;(wrapper.vm as any).lifecycleFilters = []
        ;(wrapper.vm as any).analysisFilters = []
        await wrapper.vm.$nextTick()
        
        // V4 (Pending Review) must NOT be visible if no filters selected
        const cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(0)

        // But it MUST be visible if "Needs Approval" filter is on
        ;(wrapper.vm as any).lifecycleFilters = ['NEEDS_APPROVAL']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(1)
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toBe('V4')
    })

    it('includes pending review items with open team assessment in OPEN filter', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockDataWithPending)
        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: { plugins: [router], provide: { user: { value: { role: 'REVIEWER' } } } }
        })
        await flushPromises()

        ;(wrapper.vm as any).lifecycleFilters = ['OPEN']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
        await wrapper.vm.$nextTick()

        const openCards = wrapper.findAll('.vuln-card')
        expect(openCards.length).toBeGreaterThanOrEqual(1)
        expect(openCards.map(c => c.text())).toContain('V4')

        const getCount = (text: string) => {
            const btns = wrapper.findAll('button').filter(b => b.text().includes(text))
            const btn = btns.find(b => b.text().trim().startsWith(text))
            return parseInt(btn?.find('span').text() || '0')
        }

        // V1 is OPEN/NOT_SET, V4 is OPEN with pending review and FALSE_POSITIVE tech state.
        expect(getCount('Not Set')).toBe(1)
        expect(getCount('False Positive')).toBeGreaterThanOrEqual(1)

    })

    it('should treat plaintext assessments as valid data for filters', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockDataWithPlaintext)
        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: { plugins: [router], provide: { user: { value: { role: 'REVIEWER' } } } }
        })
        await flushPromises()

        // All vulnerabilities should be visible by default
        expect(wrapper.findAll('.vuln-card').length).toBe(6)

        // Open + Not Set should show V1 (empty) and V5 (plaintext NOT_SET)
        ;(wrapper.vm as any).lifecycleFilters = ['OPEN']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET']
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(2)
        expect(wrapper.findAll('.vuln-card').map(c => c.text())).toContain('V1')
        expect(wrapper.findAll('.vuln-card').map(c => c.text())).toContain('V5')

        // Assessed Legacy + Not Affected should show only the plaintext NOT_AFFECTED vuln (V6)
        ;(wrapper.vm as any).lifecycleFilters = ['ASSESSED_LEGACY']
        ;(wrapper.vm as any).analysisFilters = ['NOT_AFFECTED']
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(1)
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toBe('V6')
    })

    it('supports filtering assessed legacy items separately', async () => {
        const legacyData = [
            {
                id: 'V9',
                severity: 'MEDIUM',
                cvss_score: 4.0,
                tags: ['team-a'],
                affected_versions: [
                    {
                        components: [
                            {
                                component_name: 'CompA',
                                analysis_state: 'FALSE_POSITIVE',
                                analysis_details: ''
                            }
                        ]
                    }
                ]
            }
        ];

        (getGroupedVulns as any).mockResolvedValue(legacyData)
        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: { plugins: [router], provide: { user: { value: { role: 'REVIEWER' } } } }
        })
        await flushPromises()

        // When filtering only by Open, the legacy assessed item is excluded
        ;(wrapper.vm as any).lifecycleFilters = ['OPEN']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET']
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(0)

        // When filtering by legacy assessed it should appear
        ;(wrapper.vm as any).lifecycleFilters = ['ASSESSED_LEGACY']
        ;(wrapper.vm as any).analysisFilters = ['FALSE_POSITIVE']
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(1)
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toBe('V9')
    })

    it('should match partial team identifiers like 3p when filtering', async () => {
        const mockData = [
            {
                id: 'V10',
                severity: 'LOW',
                cvss_score: 1.0,
                tags: ['3p'],
                affected_versions: [
                    {
                        components: [
                            {
                                component_name: 'CompA',
                                analysis_state: 'NOT_SET',
                                analysis_details: ''
                            }
                        ]
                    }
                ]
            }
        ];

        ;(getGroupedVulns as any).mockResolvedValue(mockData)
        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: { plugins: [router], provide: { user: { value: { role: 'REVIEWER' } } } }
        })
        await flushPromises()

        ;(wrapper.vm as any).lifecycleFilters = ['OPEN']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET']
        await wrapper.vm.$nextTick()

        // Should match on partial input
        ;(wrapper.vm as any).tagFilter = ' 3 '
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(1)

        ;(wrapper.vm as any).tagFilter = ' 3p '
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(1)

        ;(wrapper.vm as any).tagFilter = ' p '
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(1)
    })

    it('calculates hierarchical counts correctly', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)
        router.push('/projects/p1/TestProject')
        await router.isReady()

        const wrapper = mount(ProjectView, {
            global: { plugins: [router], provide: { user: { value: { role: 'REVIEWER' } } } }
        })
        await flushPromises()

        // Helper to get count from a chip button
        const getCount = (text: string) => {
            const btns = wrapper.findAll('button').filter(b => b.text().includes(text))
            // Only consider buttons that have the label exactly or with a count
            const btn = btns.find(b => b.text().trim().startsWith(text))
            return parseInt(btn?.find('span').text() || '0')
        }

        // Global Lifecycle counts: Open=1 (V1), Assessed=1 (V2), Incomplete=1 (V3), Inconsistent=1 (V8)
        expect(getCount('Open')).toBe(1)
        expect(getCount('Assessed')).toBe(1)
        expect(getCount('Incomplete')).toBe(1)
        expect(getCount('Inconsistent')).toBe(1)

        // Default Lifecycle selection for Reviewer is ALL.
        // Analysis counts should be global then.
        expect(getCount('Not Set')).toBe(1) // V1 is NOT_SET
        expect(getCount('False Positive')).toBe(2) // V2 and V3 are FALSE_POSITIVE
        expect(getCount('Exploitable')).toBe(1) // V8 is EXPLOITABLE
        
        // Change Lifecycle selection to Open
        ;(wrapper.vm as any).lifecycleFilters = ['OPEN']
        await wrapper.vm.$nextTick()

        // Hierarchical Analysis counts (only for Open):
        // V1 is NOT_SET
        expect(getCount('Not Set')).toBe(1)
        expect(getCount('False Positive')).toBe(0)

        // Switch lifecycle to Assessed
        ;(wrapper.vm as any).lifecycleFilters = ['ASSESSED']
        await wrapper.vm.$nextTick()
        // Only V2 (FALSE_POSITIVE) should be shown
        expect(getCount('Not Set')).toBe(0)
        expect(getCount('False Positive')).toBe(1)

        // Switch lifecycle to Inconsistent
        ;(wrapper.vm as any).lifecycleFilters = ['INCONSISTENT']
        await wrapper.vm.$nextTick()
        // No vulnerabilities should match (no inconsistent group in this dataset)
        expect(getCount('Not Set')).toBe(0)
        expect(getCount('False Positive')).toBe(0)
    })
})
