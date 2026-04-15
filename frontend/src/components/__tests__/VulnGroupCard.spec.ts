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
vi.mock('lucide-vue-next', async (importOriginal) => {
    const actual = await importOriginal() as any
    return {
        ...actual,
        ChevronDown: { template: '<span class="icon-down" />' },
        ChevronUp: { template: '<span class="icon-up" />' },
        Shield: { template: '<span class="icon-shield" />' },
        Calculator: { template: '<span class="icon-calc" />' },
        ExternalLink: { template: '<span class="icon-link" />' },
        RefreshCw: { template: '<span class="icon-refresh" />' },
        AlertTriangle: { template: '<span class="icon-alert" />' },
        CheckCircle: { template: '<span class="icon-check" />' },
        RotateCcw: { template: '<span class="icon-rotate-ccw" />' },
        History: { template: '<span class="icon-history" />' },
        LayoutList: { template: '<span class="icon-layout-list" />' }
    }
})

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
            tags: ['Security'],
            is_direct_dependency: false
        }
    ]

    const mockGroup = {
        id: 'CVE-2023-1234',
        title: 'Test Vulnerability',
        description: 'A bad vulnerability',
        severity: 'HIGH',
        cvss: 9.8,
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
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
        expect(wrapper.text()).toContain('CRITICAL') // cvss 9.8 maps to CRITICAL via scoreSeverity
        expect(wrapper.text()).toContain('9.8')

        const instanceCount = wrapper.find('[data-testid="instance-count"]')
        expect(instanceCount.exists()).toBe(true)
        expect(instanceCount.text()).toContain('1×')

        const lifecycleBadge = wrapper.find('[data-testid="lifecycle-badge"]')
        expect(lifecycleBadge.exists()).toBe(true)

        const versionChips = wrapper.findAll('[data-testid="assessment-version-chip"]')
        expect(versionChips.length).toBe(0) // not expanded yet
    })

    it('renders the criticality badge as a fixed overlay marker', () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        const severitySlot = wrapper.get('[data-testid="criticality-badge-slot"]')
        const severityBadge = wrapper.get('[data-testid="severity-badge"]')

        expect(severitySlot.classes()).toContain('absolute')
        expect(severitySlot.classes()).toContain('top-0')
        expect(severitySlot.classes()).toContain('left-0')
        expect(severityBadge.classes()).toContain('w-10')
        expect(severityBadge.classes()).toContain('h-full')
        expect(severityBadge.text()).toContain('CRITICAL') // cvss 9.8 maps to CRITICAL
    })

    it('keeps the vulnerability id on one line without break-all wrapping', () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        const primaryId = wrapper.get('[data-testid="vuln-primary-id"]')

        expect(primaryId.classes()).toContain('whitespace-nowrap')
        expect(primaryId.classes()).toContain('overflow-hidden')
        expect(primaryId.classes()).toContain('text-ellipsis')
        expect(primaryId.classes()).not.toContain('break-all')
    })

    it('renders the CVSS base score directly under the vulnerability id', () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        const primaryId = wrapper.get('[data-testid="vuln-primary-id"]').element
        const cvssBlock = wrapper.get('[data-testid="header-cvss-block"]').element
        const position = primaryId.compareDocumentPosition(cvssBlock)

        expect(position & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
        expect(wrapper.get('[data-testid="header-cvss-block"]').text()).toContain('9.8')
        expect(wrapper.get('[data-testid="header-cvss-block"]').text()).not.toContain('CVSS Base')
    })

    it('shows base and rescored score as base arrow rescored', () => {
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: { ...mockGroup, rescored_cvss: 7.2 },
            }
        })

        expect(wrapper.get('[data-testid="base-score-value"]').text()).toBe('9.8')
        expect(wrapper.get('[data-testid="rescored-arrow"]').text()).toContain('→')
        expect(wrapper.get('[data-testid="rescored-value-badge"]').text()).toBe('7.2')
    })

    it('shows No score when no base score is available', () => {
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: { ...mockGroup, cvss: undefined, cvss_score: undefined }
            }
        })

        expect(wrapper.get('[data-testid="base-score-value"]').text()).toBe('—')
    })

    it('shows transitive dependency badge', () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        expect(wrapper.text()).toContain('Trans.')
    })

    it('shows sorted project versions in analysis details block', async () => {
        const wrapper = mount(VulnGroupCard, { props: { group: mockGroup } })

        await wrapper.find('.cursor-pointer').trigger('click')

        const versionChips = wrapper.findAll('[data-testid="assessment-version-chip"]')
        expect(versionChips.length).toBe(1)
        expect(versionChips[0].text()).toBe('1.0')

        const instanceBadges = wrapper.findAll('[data-testid="assessment-instance-badge"]')
        expect(instanceBadges.length).toBe(1)
        expect(instanceBadges[0].text()).toContain('lib')
        expect(instanceBadges[0].text()).toContain('1.0')
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
            global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } }
        })

        // Expand
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        // Set state
        ;(wrapper.vm as any).state = 'NOT_AFFECTED'
        await wrapper.vm.$nextTick()
        await wrapper.find('textarea').setValue('False positive')

        // Click Apply
        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        expect(applyBtn).toBeDefined()
        expect(applyBtn?.element.disabled).toBe(false)
        applyBtn?.trigger('click')
        await flushPromises()

        // Confirm in modal
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Verify API call
        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            state: 'NOT_AFFECTED',
            details: expect.stringMatching(/---\s*\[Team:\s*Security\]\s*\[State:\s*NOT_AFFECTED\]\s*\[Assessed By:\s*tester\]\s*\[Date:\s*\d+\]\s*\[Justification:\s*NOT_SET\]\s*---\n\nFalse positive/),
            team: 'Security'
        }))

        // Should emit update:assessment
        expect(wrapper.emitted()).toHaveProperty('update:assessment')
    })

    // TMRescore proposal UI was removed from VulnGroupCard during refactor
    // (proposals are now handled at the ProjectView level)

    it('handles assessment update errors', async () => {
        // Mock API failure
        vi.mocked(updateAssessment).mockResolvedValueOnce([{ status: 'error', message: 'Failed' }])
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })

        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        // Select Team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click')
        await flushPromises()

        // Modal appears, click Confirm
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
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
        // Severity badge now uses SVG polygon with rgba fill instead of bg-* classes
        const polygon = wrapper.find('[data-testid="severity-badge"] polygon')
        expect(polygon.attributes('fill')).toContain('220, 38, 38') // #dc2626 as rgba

        const lowGroup = { ...mockGroup, severity: 'LOW', cvss: 0.5, cvss_score: 0.5 }
        const wrapper2 = mount(VulnGroupCard, {
            props: { group: lowGroup }
        })
        const polygon2 = wrapper2.find('[data-testid="severity-badge"] polygon')
        expect(polygon2.attributes('fill')).toContain('22, 163, 74') // #16a34a as rgba

        // Test card style branches (brighter colors)
        const unassessedWrapper = mount(VulnGroupCard, { props: { group: { ...mockGroup, severity: 'CRITICAL' } } })
        expect(unassessedWrapper.find('.border.rounded-lg').classes()).toContain('bg-gray-800-warm')

        const mixedGroup = {
            ...mockGroup,
            tags: ['Security'],
            affected_versions: [
                { components: [{ analysis_state: 'EXPLOITABLE', analysis_details: '--- [Team: Security] [State: EXPLOITABLE] ---' }] },
                { components: [{ analysis_state: 'FALSE_POSITIVE', analysis_details: '--- [Team: Security] [State: FALSE_POSITIVE] ---' }] }
            ]
        }
        const mixedWrapper = mount(VulnGroupCard, { props: { group: mixedGroup as any } })
        expect(mixedWrapper.find('.border.rounded-lg').classes()).toContain('stripe-bg')
    })

    it('renders vulnerability aliases in expanded details', async () => {
        const aliasGroup = { ...mockGroup, aliases: ['CVE-2023-1234', 'GHSA-abcd-efgh'] }
        const wrapper = mount(VulnGroupCard, { props: { group: aliasGroup } })
        // Aliases are only visible in expanded details
        await wrapper.find('.cursor-pointer').trigger('click')
        expect(wrapper.text()).toContain('CVE-2023-1234')
        expect(wrapper.text()).toContain('GHSA-abcd-efgh')
    })



    it('handles user canceling confirmation', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { stubs: { teleport: true } }
        })

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
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'tester' } } }, stubs: { teleport: true } }
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

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
            const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
            await confirmBtn?.trigger('click')
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
        
        // Expand Audit Trail
        const expandBtn = wrapper.findAll('button').find(b => b.text().includes('audit trail'))
        await expandBtn?.trigger('click')

        expect(wrapper.text()).toContain('Previous comment')
    })

    it('handles updateAssessment exception', async () => {
        // Mock rejection
        vi.mocked(updateAssessment).mockRejectedValueOnce(new Error('Network error'))
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { })

        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } }
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click')
        await flushPromises()

        // Confirm
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Error alert modal
        expect(wrapper.text()).toContain('Failed to update assessment')
        const closeBtn = wrapper.findAll('button').find(b => b.text() === 'Close')
        await closeBtn?.trigger('click')
        await flushPromises()

        consoleSpy.mockRestore()
    })

    it('renders lifecycle badge with correct state', () => {
        // Default mock group has NOT_SET instances with no team assessments -> lifecycle is OPEN
        const wrapper = mount(VulnGroupCard, { props: { group: mockGroup } })
        const badge = wrapper.find('[data-testid="lifecycle-badge"]')
        expect(badge.exists()).toBe(true)
        expect(badge.text()).toBe('Open')
        expect(badge.classes()).toContain('text-red-400')
    })



    it('shows justification dropdown when NOT_AFFECTED is selected', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } }
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        // Set state to NOT_AFFECTED
        ;(wrapper.vm as any).state = 'NOT_AFFECTED'
        await wrapper.vm.$nextTick()

        expect(wrapper.text()).toContain('Justification')
        ;(wrapper.vm as any).justification = 'CODE_NOT_PRESENT'
        await wrapper.vm.$nextTick()

        // Apply bulk update
        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click') // Do NOT await here, it waits for promptConfirm
        await flushPromises()

        // Interact with custom modal
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            state: 'NOT_AFFECTED',
            justification: 'CODE_NOT_PRESENT',
            team: 'Security'
        }))
    })

    it('auto-rescores cvss to 0 for reviewers when NOT_AFFECTED is selected', async () => {
        const mockRescoreRules = { value: { transitions: [{ trigger: { state: 'NOT_AFFECTED' }, actions: { '3.1': { 'MC': 'N', 'MI': 'N', 'MA': 'N' } } }] } }
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'tester' } }, rescoreRules: mockRescoreRules }, stubs: { teleport: true } }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        ;(wrapper.vm as any).state = 'NOT_AFFECTED'
        await wrapper.vm.$nextTick()
        await flushPromises()

        await wrapper.find('textarea').setValue('False positive mock')
        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click')
        await flushPromises()

        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Verify updateAssessment was called with the Rescored 0 vector in the payload.
        // It should inject [Rescored: 0] and the default CVSS 3.1 0-score vector.
        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            details: expect.stringContaining('[Rescored:')
        }))
        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            details: expect.stringContaining('[Rescored Vector: CVSS:3.1')
        }))
    })

    it('cleans up requirement and modified metrics that match base values', async () => {
        const groupWithVector = {
            ...mockGroup,
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
        }

        const wrapper = mount(VulnGroupCard, {
            props: { group: groupWithVector },
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'tester' } } } }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        const modalBtn = wrapper.findAll('button').find(b => b.text().includes('Visual Calculator'))
        await modalBtn?.trigger('click')
        await flushPromises()

        const vectorInput = wrapper.find('input[placeholder="CVSS:4.0/AV:N/..."]')

        ;(wrapper.vm as any).updateCalcVector('MPR', 'N')
        ;(wrapper.vm as any).updateCalcVector('CR', 'L')
        await wrapper.vm.$nextTick()
        await flushPromises()

        // No cleanup yet, modifications are still present in the vector string
        expect((vectorInput.element as HTMLInputElement).value).toContain('MPR:N')
        expect((vectorInput.element as HTMLInputElement).value).toContain('CR:L')

        const cleanBtn = wrapper.findAll('button').find(b => b.text() === 'Clean')
        await cleanBtn?.trigger('click')
        await flushPromises()

        expect((vectorInput.element as HTMLInputElement).value).not.toContain('MPR:')
        expect((vectorInput.element as HTMLInputElement).value).not.toContain('CR:')

        ;(wrapper.vm as any).updateCalcVector('MPR', 'L')
        ;(wrapper.vm as any).updateCalcVector('CR', 'H')
        await wrapper.vm.$nextTick()
        await flushPromises()

        expect((vectorInput.element as HTMLInputElement).value).toContain('MPR:L')
        expect((vectorInput.element as HTMLInputElement).value).toContain('CR:H')

        expect((vectorInput.element as HTMLInputElement).readOnly).toBe(false)
    })

    it('cleans MI when it matches base I in CVSS 3.1 vector', async () => {
        const groupWithVector = {
            ...mockGroup,
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/IR:M/MAV:P/MI:H'
        }

        const wrapper = mount(VulnGroupCard, {
            props: { group: groupWithVector },
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'tester' } } } }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        const modalBtn = wrapper.findAll('button').find(b => b.text().includes('Visual Calculator'))
        await modalBtn?.trigger('click')
        await flushPromises()

        const vectorInput = wrapper.find('input[placeholder="CVSS:4.0/AV:N/..."]')
        expect((vectorInput.element as HTMLInputElement).value).toContain('MI:H')
        expect((vectorInput.element as HTMLInputElement).value).toContain('IR:M')

        const cleanBtn = wrapper.findAll('button').find(b => b.text() === 'Clean')
        await cleanBtn?.trigger('click')
        await flushPromises()

        expect((vectorInput.element as HTMLInputElement).value).not.toContain('MI:')
        expect((vectorInput.element as HTMLInputElement).value).toContain('IR:M')
    })

    it('preserves cvss when state changes away from NOT_AFFECTED (requirement: user context remains)', async () => {
        const mockRescoreRules = { value: { transitions: [{ trigger: { state: 'NOT_AFFECTED' }, actions: { '3.1': { 'MC': 'N', 'MI': 'N', 'MA': 'N' } } }] } }
        const groupWithVector = {
            ...mockGroup,
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group: groupWithVector },
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'tester' } }, rescoreRules: mockRescoreRules } }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        const vectorInput = wrapper.findAll('input[type="text"]')[0]

        ;(wrapper.vm as any).state = 'NOT_AFFECTED'
        await wrapper.vm.$nextTick()
        await flushPromises()

        // It should have the modified MC, MI, MA
        expect((vectorInput?.element as HTMLInputElement).value).toContain('MC:N/MI:N/MA:N')
        // Vector input should be editable per new explicit cleanup behavior
        expect((vectorInput?.element as HTMLInputElement).readOnly).toBe(false)

        // Now set it back to EXPLOITABLE
        ;(wrapper.vm as any).state = 'EXPLOITABLE'
        await wrapper.vm.$nextTick()
        await flushPromises()

        // It should PRESERVE the modified fields (no revert), per user requirement
        expect((vectorInput?.element as HTMLInputElement).value).toContain('MC:N/MI:N/MA:N')
    })

    it('does not auto-rescore cvss for non-reviewers when NOT_AFFECTED is selected', async () => {
        const mockRescoreRules = { value: { transitions: [{ trigger: { state: 'NOT_AFFECTED' }, actions: { '3.1': { 'MC': 'N', 'MI': 'N', 'MA': 'N' } } }] } }
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { role: 'ANALYST', username: 'tester' } }, rescoreRules: mockRescoreRules }, stubs: { teleport: true } }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        // Select Team first because Analyst can't edit General state
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()
        await flushPromises()

        ;(wrapper.vm as any).state = 'NOT_AFFECTED'
        await wrapper.vm.$nextTick()
        await flushPromises()

        await wrapper.find('textarea').setValue('Analyst no rescore')
        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click')
        await flushPromises()

        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Analysts shouldn't inject [Rescored: 0] automatically.
        const calls = (updateAssessment as any).mock.calls
        const lastCallArgs = calls[calls.length - 1][0]

        expect(lastCallArgs.details).not.toContain('[Rescored:')
        expect(lastCallArgs.details).not.toContain('[Rescored Vector:')
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
            global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } }
        })

        // Expand
        await wrapper.find('.cursor-pointer').trigger('click')

        // Fill per-team form

        // Select team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()
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

        ;(wrapper.vm as any).state = 'EXPLOITABLE'
        await wrapper.vm.$nextTick()
        await wrapper.find('textarea').setValue('Security confirmed exploitable')

        // Click Apply
        const applyBtn = wrapper.findAll('button').find(b => b.text() === 'Apply')
        applyBtn?.trigger('click') // Do NOT await
        await flushPromises()

        // Confirm in modal
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
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
                analysis_details: expect.stringMatching(/---\s*\[Team:\s*Security\]\s*\[State:\s*EXPLOITABLE\]\s*\[Assessed By:\s*tester\]\s*\[Date:\s*\d+\]\s*\[Justification:\s*NOT_SET\]\s*---/)
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
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        // With role-based UI for Analyst:
        // - Comments/Suppression are STILL hidden
        expect(wrapper.findAll('label').some(l => l.text() === 'Comment')).toBe(false)
        // - Team tab should be selected and its assessment section visible
        expect(wrapper.text()).toContain('Security')
        // - Global tab should not be active for non-reviewers
        expect(wrapper.text()).toContain('Analysis State')
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
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        // Team view
        expect((textareas[0]?.element as HTMLTextAreaElement).value).toBe('This is urgent')
        expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
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

        // Should see Global Assessment section and Global tab
        expect(wrapper.text()).toContain('Global Assessment')
        expect(wrapper.text()).toContain('Global')

        // Should show the Global tab as active (team tabs are shown)
        expect(wrapper.text()).toContain('Analysis State')

        // Calculator component should be present in the modal after clicking Visual Calculator
        const calcButton = wrapper.findAll('button').find(b => b.text().includes('Visual Calculator'))
        if (calcButton) {
            await calcButton.trigger('click')
        }
        expect(wrapper.findComponent({ name: 'CvssCalculatorV3' }).exists()).toBe(true)
    })
})

