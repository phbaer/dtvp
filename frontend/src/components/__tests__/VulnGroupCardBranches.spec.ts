import { ref } from 'vue'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'


vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(() => Promise.resolve([])),
    getAssessmentDetails: vi.fn(() => Promise.resolve([])),
    getDependencyChains: vi.fn().mockResolvedValue([])
}))

vi.mock('lucide-vue-next', () => ({
    ChevronDown: { template: '<span />' },
    ChevronUp: { template: '<span />' },
    Shield: { template: '<span />' },
    Calculator: { template: '<span />' },
    ExternalLink: { template: '<span />' },
    RefreshCw: { template: '<span />' },
    CheckCircle: { template: '<span />' },
    AlertTriangle: { template: '<span />' },
    RotateCcw: { template: '<span />' }
}))

describe('VulnGroupCard Branch Coverage', () => {
    // Helper to allow simple confirm
    beforeEach(() => {
        vi.clearAllMocks()
        global.confirm = vi.fn(() => true)
        global.alert = vi.fn()
    })

    const baseGroup = {
        id: 'CVE-1',
        title: 'T',
        severity: 'HIGH',
        affected_versions: []
    }



    it('handles initialization with empty/partial affected versions', () => {
        // Case: affected_versions undefined (if possible via prop bypass or data issue)
        // Prop type expects it, but we can pass object.
        const g1 = { ...baseGroup, affected_versions: undefined }
        const w1 = mount(VulnGroupCard, { props: { group: g1 as any } })
        // Should not crash and allInstances should be empty
        expect((w1.vm as any).allInstances).toEqual([])

        // Case: affected_versions empty
        const g2 = { ...baseGroup, affected_versions: [] }
        const w2 = mount(VulnGroupCard, { props: { group: g2 as any } })
        // State should be defaulted
        expect((w2.vm as any).state).toBe('NOT_SET')

        // Case: version with no components
        const g3 = { ...baseGroup, affected_versions: [{ components: [] }] }
        const w3 = mount(VulnGroupCard, { props: { group: g3 as any } })
        expect((w3.vm as any).state).toBe('NOT_SET')
    })



    it('correctly reports INCONSISTENT display state', () => {
        const group = {
            ...baseGroup,
            affected_versions: [
                {
                    project_uuid: 'p1', project_name: 'P1',
                    components: [{ component_uuid: 'c1', component_name: 'C1', component_version: '1.0', analysis_state: 'EXPLOITABLE' }]
                },
                {
                    project_uuid: 'p2', project_name: 'P2',
                    components: [{ component_uuid: 'c2', component_name: 'C2', component_version: '1.0', analysis_state: 'NOT_AFFECTED' }]
                }
            ]
        }
        const wrapper = mount(VulnGroupCard, { props: { group: group as any } })
        expect((wrapper.vm as any).displayState).toBe('INCONSISTENT')
    })

    it('applies consensus (Sync all) for INCOMPLETE state and combines details', async () => {
        const group = {
            ...baseGroup,
            affected_versions: [
                {
                    project_uuid: 'p1', project_name: 'P1',
                    components: [{ 
                        component_uuid: 'c1', 
                        component_name: 'C1', 
                        component_version: '1.0', 
                        analysis_state: 'EXPLOITABLE',
                        analysis_details: '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: user1] ---\nDetails from A'
                    }]
                },
                {
                    project_uuid: 'p2', project_name: 'P2',
                    components: [{ 
                        component_uuid: 'c2', 
                        component_name: 'C2', 
                        component_version: '1.0', 
                        analysis_state: 'NOT_SET',
                        analysis_details: '--- [Team: General] [State: NOT_SET] [Assessed By: system] ---\nBaseline details'
                    }]
                }
            ]
        }
        const wrapper = mount(VulnGroupCard, { 
            props: { group: group as any },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER' })
                }
            }
        })
        
        expect((wrapper.vm as any).displayState).toBe('INCOMPLETE')
        expect((wrapper.vm as any).consensusButtonLabel).toBe('Sync all')
        
        // Trigger consensus
        await (wrapper.vm as any).applyConsensusAssessment()
        
        expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
        // Details should be combined
        expect((wrapper.vm as any).details).toContain('[TeamA] Details from A')
        expect((wrapper.vm as any).details).toContain('[General] Baseline details')
    })

    it('uses Dependency Track state as the source of truth when syncing', async () => {
        const group = {
            ...baseGroup,
            affected_versions: [
                {
                    project_uuid: 'p1', project_name: 'P1',
                    components: [{ 
                        component_uuid: 'c1', 
                        component_name: 'C1', 
                        component_version: '1.0', 
                        analysis_state: 'EXPLOITABLE',
                        analysis_details: '--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: user1] [Justification: CODE_NOT_PRESENT] ---\nBlock says NOT_AFFECTED'
                    }]
                }
            ]
        }

        const wrapper = mount(VulnGroupCard, { 
            props: { group: group as any },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER' })
                }
            }
        })

        await (wrapper.vm as any).applyConsensusAssessment()
        expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
        expect((wrapper.vm as any).justification).toBe('CODE_NOT_PRESENT')
        expect((wrapper.vm as any).details).toContain('Block says NOT_AFFECTED')
    })

    it('applies consensus (Apply worst assessment) for INCONSISTENT state', async () => {
        const group = {
            ...baseGroup,
            affected_versions: [
                {
                    project_uuid: 'p1', project_name: 'P1',
                    components: [{ 
                        component_uuid: 'c1', 
                        component_name: 'C1', 
                        component_version: '1.0', 
                        analysis_state: 'EXPLOITABLE',
                        analysis_details: '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: user1] ---\nBad news'
                    }]
                },
                {
                    project_uuid: 'p2', project_name: 'P2',
                    components: [{ 
                        component_uuid: 'c2', 
                        component_name: 'C2', 
                        component_version: '1.0', 
                        analysis_state: 'NOT_AFFECTED',
                        analysis_details: '--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: user2] ---\nGood news'
                    }]
                }
            ]
        }
        const wrapper = mount(VulnGroupCard, { 
            props: { group: group as any },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER' })
                }
            }
        })
        
        expect((wrapper.vm as any).displayState).toBe('INCONSISTENT')
        expect((wrapper.vm as any).consensusButtonLabel).toBe('Apply worst assessment')
        
        // Trigger consensus
        await (wrapper.vm as any).applyConsensusAssessment()
        
        // EXPLOITABLE is worse than NOT_AFFECTED (priority 0 < priority 3)
        expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
        expect((wrapper.vm as any).details).toContain('[TeamA] Bad news')
        expect((wrapper.vm as any).details).toContain('[TeamB] Good news')
    })
})
