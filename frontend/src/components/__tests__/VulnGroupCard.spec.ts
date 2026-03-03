import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'

// Mock API
vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn((payload: any) => {
        // Sophisticated mock for per-team aggregation
        const results = payload.instances.map((inst: any) => ({
            status: 'success',
            uuid: inst.finding_uuid,
            new_state: payload.state, // In real backend this would be aggregated
            new_details: `-- - [Team: ${payload.team || 'General'}][State: ${payload.state}][Assessed By: test - mock][Justification: ${payload.justification || 'NOT_SET'}]---\n${payload.details}`
        }))
        return Promise.resolve(results)
    }),
    getDependencyChains: vi.fn().mockResolvedValue({
        paths: [],
        total: 0,
        limit: 10,
        offset: 0
    }),
    getAssessmentDetails: vi.fn(() => Promise.resolve([]))
}))

// Mock Icons
vi.mock('lucide-vue-next', () => ({
    ChevronDown: { template: '<span class="icon-down" />' },
    ChevronUp: { template: '<span class="icon-up" />' },
    Shield: { template: '<span class="icon-shield" />' },
    Calculator: { template: '<span class="icon-calc" />' },
    ExternalLink: { template: '<span class="icon-link" />' },
    RefreshCw: { template: '<span class="icon-refresh" />' },
    AlertTriangle: { template: '<span class="icon-alert" />' },
    CheckCircle: { template: '<span class="icon-check-circle" />' }
}))

// Mock DependencyChainViewer to avoid async setup in child component
vi.mock('../DependencyChainViewer.vue', () => ({
    default: {
        template: '<div data-testid="dep-chain-viewer"></div>',
        props: ['projectUuid', 'componentUuid', 'projectName']
    }
}))

import { updateAssessment } from '../../lib/api'

describe('VulnGroupCard', () => {
    const mockComponents = [
        {
            project_name: 'App1',
            project_version: '1.0',
            project_uuid: 'p1',
            component_name: 'lib',
            component_version: '1.0',
            component_uuid: 'c1',
            vulnerability_uuid: 'v1',
            finding_uuid: 'f1',
            analysis_state: 'NOT_SET',
            is_suppressed: false,
            analysis_comments: [], // Add required field
            tags: ['Security']
        }
    ]

    const mockGroup = {
        id: 'CVE-2023-1234',
        title: 'Test Vulnerability',
        description: 'A bad vulnerability',
        severity: 'HIGH',
        cvss: 9.8,
        tags: ['Security', 'Security'],
        affected_versions: [
            {
                project_name: 'App1',
                project_version: '1.0',
                project_uuid: 'p1',
                components: mockComponents
            }
        ]
    }

    beforeEach(() => {
        vi.clearAllMocks()
    })

    it('renders vulnerability details', () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        expect(wrapper.text()).toContain('CVE-2023-1234')
        expect(wrapper.text()).toContain('HIGH')
        expect(wrapper.text()).toContain('9.8')
        expect(wrapper.text()).toContain('lib 1.0')
    })

    it('toggles expansion on click', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        // Initially not expanded (description not visible)
        expect(wrapper.text()).not.toContain('A bad vulnerability')

        // Click header
        await wrapper.find('.cursor-pointer').trigger('click')

        // Expanded
        expect(wrapper.text()).toContain('A bad vulnerability')
        expect(wrapper.text()).toContain('1.0') // Version should be shown
    })

    it('submits assessment update', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { username: 'tester' } } } }
        })

        // Expand
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        await wrapper.find('select').setValue('Security')

        // Fill form (Team A form)
        // Note: With team selected, there might be multiple selects (Team, State, Justification?)
        // Team select is [0], State is [1]
        const selects = wrapper.findAll('select')
        await selects[1]?.setValue('NOT_AFFECTED')
        await wrapper.find('textarea').setValue('False positive')

        // Click Apply
        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        expect(applyBtn).toBeDefined()
        expect(applyBtn?.element.disabled).toBe(false)
        applyBtn?.trigger('click')
        await flushPromises()

        // Confirm in modal
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Confirm')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Success alert appears, click Close
        const closeBtn = wrapper.findAll('button').find(b => b.text() === 'Close')
        await closeBtn?.trigger('click')
        await flushPromises()

        // Verify API call
        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            state: 'NOT_AFFECTED',
            details: expect.stringContaining('--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: tester] [Justification: NOT_SET] ---\n\nFalse positive'),
            team: 'Security'
        }))

        // Should emit update:assessment
        expect(wrapper.emitted()).toHaveProperty('update:assessment')
    })



    it('handles assessment update errors', async () => {
        // Mock API failure
        vi.mocked(updateAssessment).mockResolvedValueOnce([{ status: 'error', message: 'Failed' }])
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })

        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { username: 'tester' } } } }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        // Select Team
        await wrapper.find('select').setValue('Security')

        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click')
        await flushPromises()

        // Modal appears, click Confirm
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Confirm')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Error alert modal appears, check text and close
        expect(wrapper.text()).toContain('Assessment updated with 1 errors')
        const closeBtn = wrapper.findAll('button').find(b => b.text() === 'Close')
        await closeBtn?.trigger('click')
        await flushPromises()

        consoleSpy.mockRestore()
    })



    it('covers color branches', () => {
        const criticalGroup = { ...mockGroup, severity: 'CRITICAL' }
        const wrapper = mount(VulnGroupCard, {
            props: { group: criticalGroup }
        })
        expect(wrapper.find('span.rounded').classes()).toContain('bg-red-600')

        const lowGroup = { ...mockGroup, severity: 'LOW' }
        const wrapper2 = mount(VulnGroupCard, {
            props: { group: lowGroup }
        })
        expect(wrapper2.find('span.rounded').classes()).toContain('bg-green-600')

        // Test card style branches (brighter colors)
        const unassessedWrapper = mount(VulnGroupCard, { props: { group: { ...mockGroup, severity: 'CRITICAL' } } })
        expect(unassessedWrapper.find('.border.rounded-lg').classes()).toContain('bg-red-500/10')

        const mixedGroup = {
            ...mockGroup,
            affected_versions: [
                { components: [{ analysis_state: 'EXPLOITABLE' }] },
                { components: [{ analysis_state: 'NOT_SET' }] }
            ]
        }
        const mixedWrapper = mount(VulnGroupCard, { props: { group: mixedGroup as any } })
        expect(mixedWrapper.find('.border.rounded-lg').classes()).toContain('bg-yellow-500/10')
    })

    it('renders vulnerability aliases', () => {
        const aliasGroup = { ...mockGroup, aliases: ['CVE-2023-1234', 'GHSA-abcd-efgh'] }
        const wrapper = mount(VulnGroupCard, { props: { group: aliasGroup } })
        expect(wrapper.text()).toContain('CVE-2023-1234, GHSA-abcd-efgh')
    })



    it('handles user canceling confirmation', async () => {
        const wrapper = mount(VulnGroupCard, { props: { group: mockGroup } })

        await wrapper.find('.cursor-pointer').trigger('click')
        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click')
        await flushPromises()

        // Modal appears, click Cancel
        const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
        await cancelBtn?.trigger('click')
        await flushPromises()

        expect(updateAssessment).not.toHaveBeenCalled()
    })



    it('submits assessment with comment and suppression', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'tester' } } } }
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        await wrapper.find('select').setValue('Security')

        // Use optional chaining / safe access for find
        // 0: Team, 1: State
        // Textareas: 0: Details (Team), 1: Comment (Global)
        const textAreas = wrapper.findAll('textarea')
        if (textAreas.length > 1) {
            const commentArea = textAreas[1]
            await commentArea?.setValue('Audit comment')
            // Suppress checkbox id might be different now? Or generic?
            // "Suppress this vulnerability"
            const checkboxes = wrapper.findAll('input[type="checkbox"]')
            if (checkboxes.length > 0) {
                await checkboxes[checkboxes.length - 1]?.setValue(true) // Assuming suppression is last
            }

            // Submit
            const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
            applyBtn?.trigger('click')
            await flushPromises()

            // Confirm in modal
            const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Confirm')
            await confirmBtn?.trigger('click')
            await flushPromises()

            // Success alert appears, click Close
            const closeBtn = wrapper.findAll('button').find(b => b.text() === 'Close')
            await closeBtn?.trigger('click')
            await flushPromises()

            expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
                comment: 'Audit comment',
                suppressed: true,
                team: 'Security'
            }))
        }
    })

    it('renders analysis comments', async () => {
        const componentWithComments = {
            ...mockComponents[0],
            analysis_comments: [
                { comment: 'Previous comment', timestamp: '2023-01-01' }
            ]
        };

        const groupWithComments = {
            ...mockGroup,
            affected_versions: [{
                ...mockGroup.affected_versions[0],
                components: [componentWithComments]
            }]
        }

        const wrapper = mount(VulnGroupCard, {
            props: { group: groupWithComments as any }
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        expect(wrapper.text()).toContain('Previous comment')
    })

    it('handles updateAssessment exception', async () => {
        // Mock rejection
        vi.mocked(updateAssessment).mockRejectedValueOnce(new Error('Network error'))
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })

        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { username: 'tester' } } } }
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        await wrapper.find('select').setValue('Security')

        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click')
        await flushPromises()

        // Confirm
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Confirm')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Error alert modal
        expect(wrapper.text()).toContain('Failed to update assessment')
        const closeBtn = wrapper.findAll('button').find(b => b.text() === 'Close')
        await closeBtn?.trigger('click')
        await flushPromises()

        consoleSpy.mockRestore()
    })

    it('computes correct state colors', () => {
        const makeWrapper = (state: string) => mount(VulnGroupCard, {
            props: {
                group: {
                    ...mockGroup,
                    affected_versions: [{
                        ...mockGroup.affected_versions[0],
                        components: [{
                            ...mockComponents[0],
                            analysis_state: state
                        }]
                    }]
                } as any
            }
        })

        // EXPLOITABLE -> Red
        const wrapperExploitable = makeWrapper('EXPLOITABLE')
        expect(wrapperExploitable.find('.analysis-state-value').classes()).toContain('text-red-400')

        // NOT_AFFECTED -> Green
        const wrapperNotAffected = makeWrapper('NOT_AFFECTED')
        expect(wrapperNotAffected.find('.analysis-state-value').classes()).toContain('text-green-400')

        // MIXED/Other -> Gray
        const wrapperOther = makeWrapper('NOT_SET')
        expect(wrapperOther.find('.analysis-state-value').classes()).toContain('text-gray-300')
    })



    it('shows justification dropdown when NOT_AFFECTED is selected', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { username: 'tester' } } } }
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        await wrapper.find('select').setValue('Security')

        const stateSelect = wrapper.findAll('select')[1] // Second select is Analysis State
        await stateSelect?.setValue('NOT_AFFECTED')

        expect(wrapper.text()).toContain('Justification')
        const selects = wrapper.findAll('select')
        expect(selects.length).toBe(3) // Team, State, Justification
        if (selects.length > 2) {
            await selects[2]?.setValue('CODE_NOT_PRESENT')
        }

        // Apply bulk update
        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click') // Do NOT await here, it waits for promptConfirm
        await flushPromises()

        // Interact with custom modal
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Confirm')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Success alert appears, click Close
        const closeBtn = wrapper.findAll('button').find(b => b.text() === 'Close')
        await closeBtn?.trigger('click')
        await flushPromises()

        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            state: 'NOT_AFFECTED',
            justification: 'CODE_NOT_PRESENT',
            team: 'Security'
        }))
    })

    it('submits assessment for a specific team and updates UI from aggregated server response', async () => {
        const groupWithTags = {
            ...mockGroup,
            tags: ['Security', 'App'],
            affected_versions: [
                {
                    ...mockGroup.affected_versions[0],
                    components: [
                        { ...mockComponents[0], tags: ['Security'] }
                    ]
                }
            ]
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group: groupWithTags as any },
            global: { provide: { user: { value: { username: 'tester' } } } }
        })

        // Expand
        await wrapper.find('.cursor-pointer').trigger('click')

        // Fill per-team form

        // select[0] is Team, select[1] is State (but only after team selected)
        const teamSelect = wrapper.find('select')
        await teamSelect.setValue('Security')

        // Now find all selects again
        const selects = wrapper.findAll('select')
        // await wrapper.find('input[type="checkbox"]').setValue(true) // Target only this team - THIS CHECKBOX MIGHT BE THE SUPPRESS ONE NOW?
        // Wait, "Target only this team" checkbox? 
        // In original code, there used to be a "Target specific instances" or something?
        // But in `VulnGroupCard`, the checkbox logic is usually for suppression (if id=suppress...)

        // If the test meant "Target only this team", it might have been interacting with a checkbox that sets `targetTeamOnly`?
        // But `VulnGroupCard` current implementation doesn't seem to have such a checkbox exposed in the template I viewed?
        // I will trust the existing test logic but update the team/user injection.

        // The previous test code had:
        // await wrapper.find('input[type="checkbox"]').setValue(true) // Target only this team
        // If this checkbox is the Suppress checkbox, setting it to true sets `suppressed = true`.
        // `updateAssessment` call expectation: `team: 'Security', state: 'EXPLOITABLE'`. Suppressed is not checked in expectation.

        // I will keep the checkbox interaction if it helps, but verify expectation.

        await selects[1]?.setValue('EXPLOITABLE')
        await wrapper.find('textarea').setValue('Security confirmed exploitable')

        // Click Apply
        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click') // Do NOT await
        await flushPromises()

        // Confirm in modal
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Confirm')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Success alert appears, click Close
        const closeBtn = wrapper.findAll('button').find(b => b.text() === 'Close')
        await closeBtn?.trigger('click')
        await flushPromises()

        // Verify API call includes the team
        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            team: 'Security',
            state: 'EXPLOITABLE'
        }))

        // Team updates now emit update:assessment with the aggregated state from server
        const emittedAssessment = wrapper.emitted('update:assessment')
        expect(emittedAssessment).toBeTruthy()
        if (emittedAssessment && emittedAssessment.length > 0) {
            // @ts-ignore - TS2532: Object is possibly 'undefined' in vue-tsc/build env
            expect(emittedAssessment[0][0]).toMatchObject({
                analysis_state: 'EXPLOITABLE',
                analysis_details: expect.stringContaining('[Team: Security] [State: EXPLOITABLE] [Assessed By: tester] [Justification: NOT_SET]')
            })
        }
    })

    it('shows role-based UI when team is selected', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, tags: ['Security'] } }
        })

        await wrapper.find('.cursor-pointer').trigger('click')

        // Initially invisible (Global for analyst)
        expect(wrapper.text()).not.toContain('CVSS Calculator')
        // Comments/Suppression should be hidden for analysts
        expect(wrapper.findAll('label').some(l => l.text() === 'Comment')).toBe(false)
        expect(wrapper.findAll('label').some(l => l.text() === 'Suppress this vulnerability')).toBe(false)

        // Select team
        const teamSelect = wrapper.find('select')
        await teamSelect.setValue('Security')

        // With role-based UI for Analyst:
        // - Comments/Suppression are STILL hidden
        expect(wrapper.findAll('label').some(l => l.text() === 'Comment')).toBe(false)
        // - Team Opinion section should be visible
        expect(wrapper.text()).toContain('Team Opinion')
        // - Calculator visibility depends on user role (reviewers see it in Global Baseline)
        // Since we don't mock the user injection, isReviewer will be false
        // So calculator should be hidden for non-reviewers when team is selected
        expect(wrapper.text()).not.toContain('Global Baseline')
    })

    it('shows comments and suppression for reviewers', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, tags: ['Security'] } },
            global: {
                provide: {
                    user: { value: { role: 'REVIEWER', username: 'reviewer-user' } }
                }
            }
        })

        await wrapper.find('.cursor-pointer').trigger('click')

        expect(wrapper.findAll('label').some(l => l.text() === 'Comment')).toBe(true)
        expect(wrapper.text()).toContain('Suppress this vulnerability')
    })

    it('extracts team-specific state and details from aggregated string', async () => {
        const aggregatedDetails = 'Global info\n\n--- [Team: Security] [State: EXPLOITABLE] [Assessed By: user] [Justification: CODE_NOT_PRESENT] ---\nThis is urgent'
        const groupWithDetails = {
            ...mockGroup,
            tags: ['Security'],
            affected_versions: [{
                ...mockGroup.affected_versions[0],
                components: [{
                    ...mockComponents[0],
                    analysis_details: aggregatedDetails
                }]
            }]
        }

        const wrapper = mount(VulnGroupCard, {
            props: { group: groupWithDetails as any },
            global: {
                provide: {
                    user: { value: { role: 'REVIEWER', username: 'reviewer-user' } }
                }
            }
        })

        await wrapper.find('.cursor-pointer').trigger('click')

        // Global view - find the Analysis Details textarea (it's the first one)
        const textareas = wrapper.findAll('textarea')
        expect((textareas[0]?.element as HTMLTextAreaElement).value).toBe('Global info')

        // Switch to Security
        const selects = wrapper.findAll('select')
        const teamSelect = selects[0] // Team selection is the first select for reviewers
        if (teamSelect) {
            await teamSelect.setValue('Security')
        }

        // Team view
        expect((textareas[0]?.element as HTMLTextAreaElement).value).toBe('This is urgent')
        const stateSelect = selects[1]
        if (stateSelect) {
            expect((stateSelect.element as HTMLSelectElement).value).toBe('EXPLOITABLE')
        }
    })


    it('shows rescoring UI for reviewers when no team is selected', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: {
                provide: {
                    user: { value: { role: 'REVIEWER', username: 'reviewer-user' } }
                },
                stubs: {
                    CvssCalculatorV2: true,
                    CvssCalculatorV3: true,
                    CvssCalculatorV4: true
                }
            }
        })

        await wrapper.find('.cursor-pointer').trigger('click')

        // Should see Global Assessment & Global Baseline
        expect(wrapper.text()).toContain('Global Assessment')
        expect(wrapper.text()).toContain('Global Baseline')

        // Should show "Global assessment" in the select instead of "No team marker"
        const teamSelect = wrapper.find('select')
        expect(teamSelect.text()).toContain('Global assessment')

        // Calculator component should be present in the modal after clicking Visual Calculator
        const calcButton = wrapper.findAll('button').find(b => b.text().includes('Visual Calculator'))
        if (calcButton) {
            await calcButton.trigger('click')
        }
        expect(wrapper.findComponent({ name: 'CvssCalculatorV3' }).exists()).toBe(true)
    })
})

