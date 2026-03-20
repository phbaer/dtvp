
import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'
import { CheckCircle } from 'lucide-vue-next'

// Mock dependencies
vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(),
    getAssessmentDetails: vi.fn()
}))

vi.mock('../../lib/assessment-helpers', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../lib/assessment-helpers')>()
    return {
        ...actual,
    }
})

// Mock Icons
vi.mock('lucide-vue-next', () => ({
    CheckCircle: { template: '<span class="icon-check-circle" />' },
    ChevronDown: { template: '<span class="icon-down" />' },
    ChevronUp: { template: '<span class="icon-up" />' },
    Shield: { template: '<span class="icon-shield" />' },
    RefreshCw: { template: '<span class="icon-refresh" />' },
    AlertTriangle: { template: '<span class="icon-alert" />' },
    Calculator: { template: '<span class="icon-calc" />' },
    ExternalLink: { template: '<span class="icon-link" />' }
}))

describe('VulnGroupCard Assessment Markers', () => {
    const defaultGroup = {
        id: 'VULN-123',
        severity: 'HIGH',
        cvss_score: 8.5,
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        tags: ['TeamA', 'TeamB'],
        affected_versions: [
            {
                project_uuid: 'p1',
                project_name: 'Project 1',
                project_version: '1.0',
                components: [
                    {
                        component_uuid: 'c1',
                        component_name: 'Lib A',
                        component_version: '1.0',
                        project_name: 'Project 1',
                        project_version: '1.0',
                        project_uuid: 'p1',
                        vulnerability_uuid: 'v1',
                        finding_uuid: 'f1',
                        analysis_details: '',
                        analysis_state: 'NOT_SET'
                    }
                ]
            }
        ]
    }

    const userMock = {
        username: 'testuser',
        role: 'USER'
    }

    it('does not show checkmark when no assessment exists', () => {
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: defaultGroup as any
            },
            global: {
                provide: {
                    user: userMock
                }
            }
        })

        const tags = wrapper.findAll('.flex-wrap .rounded-lg.font-black')
        expect(tags.length).toBe(2) // TeamA, TeamB

        // CheckCircle should not be present
        expect(wrapper.findComponent(CheckCircle).exists()).toBe(false)
    })

    it('shows checkmark for assessed team', () => {
        // Modify group to have assessment for TeamA
        const assessedGroup = JSON.parse(JSON.stringify(defaultGroup))
        assessedGroup.affected_versions[0].components[0].analysis_details =
            '--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: user] ---'

        const wrapper = mount(VulnGroupCard, {
            props: {
                group: assessedGroup as any
            },
            global: {
                provide: {
                    user: userMock
                }
            }
        })

        const tags = wrapper.findAll('.flex-wrap .rounded-lg.font-black')
        expect(tags.length).toBe(2)

        // First tag (TeamA) should have checkmark
        const teamATag = tags[0]
        expect(teamATag?.text()).toContain('TeamA')
        expect(teamATag?.findComponent(CheckCircle).exists()).toBe(true)

        // Second tag (TeamB) should NOT have checkmark
        const teamBTag = tags[1]
        expect(teamBTag?.text()).toContain('TeamB')
        expect(teamBTag?.findComponent(CheckCircle).exists()).toBe(false)
    })

    it('shows checkmark for multiple assessed teams', () => {
        const assessedGroup = JSON.parse(JSON.stringify(defaultGroup))
        assessedGroup.affected_versions[0].components[0].analysis_details =
            '--- [Team: TeamA] [State: NOT_AFFECTED] --- \n\n --- [Team: TeamB] [State: IN_TRIAGE] ---'

        const wrapper = mount(VulnGroupCard, {
            props: {
                group: assessedGroup as any
            },
            global: {
                provide: {
                    user: userMock
                }
            }
        })

        const tags = wrapper.findAll('.flex-wrap .rounded-lg.font-black')
        expect(tags.length).toBe(2)

        expect(tags[0]?.findComponent(CheckCircle).exists()).toBe(true)
        expect(tags[1]?.findComponent(CheckCircle).exists()).toBe(true)
    })
})
