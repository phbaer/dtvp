import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import ProjectView from '../ProjectView.vue'
import { getGroupedVulns, getTMRescoreProposals } from '../../lib/api'
import { mountWithRouter } from './routerTestUtils'
import { setProjectViewViewport } from './projectViewTestUtils'

// Mock API
vi.mock('../../lib/api', () => ({
    drainTaskVulnGroupDetails: vi.fn(),
    drainTaskVulnGroups: vi.fn(() => Promise.resolve([])),
    getGroupedVulns: vi.fn(),
    getTaskVulnGroup: vi.fn(),
    getTaskVulnGroups: vi.fn(),
    getTaskStatistics: vi.fn(() => Promise.resolve({ severity_counts: {}, state_counts: {}, total_unique: 0, total_findings: 0, affected_projects_count: 0, version_counts: {} })),
    updateAssessment: vi.fn(),
    getCacheStatus: vi.fn(() => Promise.resolve({ fully_cached: false, last_refreshed_at: null, projects: 0, active_projects: 0, cached_findings: 0, cached_boms: 0, cached_analyses: 0, pending_updates: 0 })),
    codeAnalysisGetAssessmentIndex: vi.fn(() => Promise.resolve({ records: [], summary: {} })),
    getTeamMapping: vi.fn(() => Promise.resolve({})),
    getRescoreRules: vi.fn(() => Promise.resolve({ transitions: [] })),
    getTMRescoreProposals: vi.fn(() => Promise.resolve({ proposals: {} })),
}))

// Mock Child Components
vi.mock('../../components/VulnRowCompact.vue', () => ({
    default: {
        name: 'VulnRowCompact',
        template: '<div class="vuln-card" :data-id="item.group.id">{{ item.group.id }}</div>',
        props: ['item']
    }
}))

vi.mock('../../components/VulnDetailInspector.vue', () => ({
    default: {
        name: 'VulnDetailInspector',
        template: '<aside data-testid="detail-inspector">{{ group.id }}</aside>',
        props: ['group'],
    },
}))

describe('ProjectView Filters', () => {
    let mountProjectViewRoute: () => Promise<any>

    beforeEach(() => {
        vi.clearAllMocks()
        setProjectViewViewport(1920)
        const routes = [
                { path: '/', component: { template: '<div />' } },
                { path: '/statistics', component: { template: '<div />' } },
                { path: '/projects/:uuid/:name', component: ProjectView },
                { path: '/project/:name/tmrescore', component: { template: '<div />' } }
            ]
        mountProjectViewRoute = async () => {
            const { wrapper } = await mountWithRouter(ProjectView, {
                initialPath: '/projects/p1/TestProject',
                routes,
                mountOptions: {
                    global: {
                        provide: {
                            user: { value: { role: 'REVIEWER' } }
                        }
                    }
                }
            })
            return wrapper
        }
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
        const wrapper = await mountProjectViewRoute()

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
        expect(cards.map((card: any) => card.text())).toContain('V1')
        expect(cards.map((card: any) => card.text())).toContain('V3')
        expect(cards.map((card: any) => card.text())).toContain('V8')

        // Turn on specific 'Incomplete' chip in Lifecycle and 'Not Set' in Analysis
        ;(wrapper.vm as any).lifecycleFilters = ['INCOMPLETE']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET']
        await wrapper.vm.$nextTick()
        cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(0) // None are INCOMPLETE
    })

    it('reuses the cached project list when returning from code analysis to a vulnerability card', async () => {
        ;(getGroupedVulns as any).mockResolvedValue([
            {
                id: 'V1',
                severity: 'HIGH',
                tags: ['team-a'],
                affected_versions: [
                    {
                        project_name: 'TestProject',
                        project_uuid: 'p1',
                        project_version: '1.0',
                        components: [
                            {
                                component_name: 'CompA',
                                analysis_state: 'NOT_SET',
                                analysis_details: '',
                            },
                        ],
                    },
                ],
            },
        ])

        const { wrapper, router } = await mountWithRouter(ProjectView, {
            initialPath: '/project/TestProject',
            routes: [
                { path: '/code-analysis', component: { template: '<div />' } },
                { path: '/project/:name', component: ProjectView },
            ],
            mountOptions: {
                global: {
                    provide: {
                        user: { value: { role: 'REVIEWER' } },
                    },
                },
            },
        })

        expect(getGroupedVulns).toHaveBeenCalledTimes(1)

        await router.push('/code-analysis')
        await flushPromises()
        expect(getGroupedVulns).toHaveBeenCalledTimes(1)

        await router.push('/project/TestProject?vuln=V1')
        await flushPromises()

        expect(getGroupedVulns).toHaveBeenCalledTimes(1)
        expect(wrapper.get('[data-testid="detail-inspector"]').text()).toContain('V1')
    })

    it('ANDs lifecycle and analysis filters strictly', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)
        const wrapper = await mountProjectViewRoute()
        
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
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toContain('V3')
        // Set Lifecycle to ONLY 'Assessed'
        ;(wrapper.vm as any).lifecycleFilters = ['ASSESSED']
        await wrapper.vm.$nextTick()
        // V2 matches Lifecycle=Assessed AND Analysis=False Positive
        expect(wrapper.findAll('.vuln-card').length).toBe(1)
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toContain('V2')
        
        // Clear Analysis filters
        ;(wrapper.vm as any).analysisFilters = []
        await wrapper.vm.$nextTick()
        // Should show nothing
        expect(wrapper.findAll('.vuln-card').length).toBe(0)
    })

    it('supports "Reset All" to return to default view', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)
        const wrapper = await mountProjectViewRoute()

        ;(wrapper.vm as any).analysisFilters = []
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(0)

        // Reset filters to REVIEWER defaults
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
        ;(wrapper.vm as any).lifecycleFilters = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL']
        await wrapper.vm.$nextTick()
        
        // Should return to REVIEWER defaults (all 4 findings)
        expect(wrapper.findAll('.vuln-card').length).toBe(4)
    })

    it('filters vulnerabilities by tmrescore proposal availability', async () => {
        ;(getGroupedVulns as any).mockResolvedValue(mockData)
        ;(getTMRescoreProposals as any).mockResolvedValue({
            proposals: {
                V1: {
                    vuln_id: 'V1',
                    rescored_score: 9.8,
                    rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    original_score: 9.8,
                    original_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                },
                V2: {
                    vuln_id: 'V2',
                    rescored_score: 7.9,
                    rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L',
                    original_score: 8.5,
                    original_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                },
                V8: {
                    vuln_id: 'V8',
                    rescored_score: 6.1,
                    rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N/MAC:H',
                    original_score: 7.1,
                    original_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
                },
            },
        })

        const wrapper = await mountProjectViewRoute()
        await wrapper.vm.$nextTick()
        await Promise.resolve()

        ;(wrapper.vm as any).tmrescoreProposalFilter = 'WITH_PROPOSAL'
        await wrapper.vm.$nextTick()

        let cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(2)
        expect(cards.map((card: any) => card.text())).toContain('V2')
        expect(cards.map((card: any) => card.text())).toContain('V8')

        ;(wrapper.vm as any).tmrescoreProposalFilter = 'WITHOUT_PROPOSAL'
        await wrapper.vm.$nextTick()

        cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(2)
        expect(cards.map((card: any) => card.text())).toContain('V1')
        expect(cards.map((card: any) => card.text())).toContain('V3')
    })

    it('filters vulnerabilities by project attribution age', async () => {
        const now = Date.UTC(2026, 5, 29, 12)
        const dayMs = 24 * 60 * 60 * 1000
        const dateNowSpy = vi.spyOn(Date, 'now').mockReturnValue(now)
        ;(getGroupedVulns as any).mockResolvedValue([
            {
                id: 'V-OLD',
                severity: 'HIGH',
                cvss_score: 8.0,
                tags: ['team-a'],
                affected_versions: [
                    {
                        project_name: 'TestProject',
                        project_uuid: 'p1',
                        project_version: '1.0',
                        components: [
                            {
                                component_name: 'CompA',
                                analysis_state: 'NOT_SET',
                                analysis_details: '',
                                attributed_on: now - 29 * dayMs,
                            },
                        ],
                    },
                ],
            },
            {
                id: 'V-NEW',
                severity: 'HIGH',
                cvss_score: 8.0,
                tags: ['team-a'],
                affected_versions: [
                    {
                        project_name: 'TestProject',
                        project_uuid: 'p1',
                        project_version: '1.0',
                        components: [
                            {
                                component_name: 'CompB',
                                analysis_state: 'NOT_SET',
                                analysis_details: '',
                                attributed_on: now - 7 * dayMs,
                            },
                        ],
                    },
                ],
            },
        ])

        const wrapper = await mountProjectViewRoute()

        expect(wrapper.findAll('.vuln-card').length).toBe(2)

        // V-OLD was attributed 29 days ago, V-NEW 7 days ago. "younger" keeps
        // recent findings, "older" keeps the aged ones.
        ;(wrapper.vm as any).attributionAgeDays = 14
        ;(wrapper.vm as any).attributionAgeMode = 'younger'
        await wrapper.vm.$nextTick()

        let cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(1)
        expect(cards[0]?.text()).toContain('V-NEW')

        ;(wrapper.vm as any).attributionAgeMode = 'older'
        await wrapper.vm.$nextTick()

        cards = wrapper.findAll('.vuln-card')
        expect(cards.length).toBe(1)
        expect(cards[0]?.text()).toContain('V-OLD')

        dateNowSpy.mockRestore()
    })

    it('shows "Pending Review" vulnerabilities regardless of filters', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockDataWithPending)
        const wrapper = await mountProjectViewRoute()
        
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
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toContain('V4')
    })

    it('excludes pending review items with open team work from the OPEN lifecycle filter', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockDataWithPending)
        const wrapper = await mountProjectViewRoute()

        ;(wrapper.vm as any).lifecycleFilters = ['OPEN']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
        await wrapper.vm.$nextTick()

        const openCards = wrapper.findAll('.vuln-card')
        expect(openCards.length).toBeGreaterThanOrEqual(1)
        expect(openCards.map((card: any) => card.text())).toContain('V1')
        expect(openCards.map((card: any) => card.text())).not.toContain('V4')
    })

    it('should treat plaintext assessments as valid data for filters', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockDataWithPlaintext)
        const wrapper = await mountProjectViewRoute()

        // All vulnerabilities should be visible by default
        expect(wrapper.findAll('.vuln-card').length).toBe(6)

        // Open + Not Set should show V1 (empty) and V5 (plaintext NOT_SET)
        ;(wrapper.vm as any).lifecycleFilters = ['OPEN']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET']
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(2)
        expect(wrapper.findAll('.vuln-card').map((card: any) => card.text())).toContain('V1')
        expect(wrapper.findAll('.vuln-card').map((card: any) => card.text())).toContain('V5')

        // Assessed Legacy + Not Affected should show only the plaintext NOT_AFFECTED vuln (V6)
        ;(wrapper.vm as any).lifecycleFilters = ['ASSESSED_LEGACY']
        ;(wrapper.vm as any).analysisFilters = ['NOT_AFFECTED']
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(1)
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toContain('V6')
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
        const wrapper = await mountProjectViewRoute()

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
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toContain('V9')
    })

    it('matches the complete selected team name instead of similarly named teams', async () => {
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
            },
            {
                id: 'V11',
                severity: 'LOW',
                cvss_score: 1.0,
                tags: ['3p-security'],
                affected_versions: [
                    {
                        components: [
                            {
                                component_name: 'CompB',
                                analysis_state: 'NOT_SET',
                                analysis_details: ''
                            }
                        ]
                    }
                ]
            }
        ];

        ;(getGroupedVulns as any).mockResolvedValue(mockData)
        const wrapper = await mountProjectViewRoute()

        ;(wrapper.vm as any).lifecycleFilters = ['OPEN']
        ;(wrapper.vm as any).analysisFilters = ['NOT_SET']
        await wrapper.vm.$nextTick()

        // Partial names do not represent a dropdown selection.
        ;(wrapper.vm as any).tagFilter = ' 3 '
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(0)

        // The complete selection is trimmed and matched case-insensitively.
        ;(wrapper.vm as any).tagFilter = ' 3p '
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(1)
        expect(wrapper.findAll('.vuln-card')[0]?.text()).toContain('V10')

        ;(wrapper.vm as any).tagFilter = ' p '
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('.vuln-card').length).toBe(0)
    })

    it('calculates hierarchical counts correctly', async () => {
        (getGroupedVulns as any).mockResolvedValue(mockData)
        const wrapper = await mountProjectViewRoute()

        // Helper to get count from a chip button
        const getCount = (text: string) => {
            const btns = wrapper.findAll('button').filter((button: any) => button.text().includes(text))
            // Only consider buttons that have the label exactly or with a count
            const btn = btns.find((button: any) => button.text().trim().startsWith(text))
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
