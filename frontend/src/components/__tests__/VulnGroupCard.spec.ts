import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import VulnGroupCard from '../VulnGroupCard.vue'
import CodeAnalysisPanel from '../CodeAnalysisPanel.vue'
import defaultRescoreRules from '../../../../data/rescore_rules.json'

const clipboardWriteText = vi.fn()

// Mock API
vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn((payload: any) => {
        // Sophisticated mock for per-team aggregation
        const results = payload.instances.map((inst: any) => ({
            status: 'success',
            uuid: inst.finding_uuid,
            new_state: payload.state, // In real backend this would be aggregated
            new_details: `-- - [Team: ${payload.team || 'General'}][State: ${payload.state}][Assessed By: test - mock][Justification: ${payload.justification || 'NOT_SET'}]---\n${payload.details}`,
            queued: true,
            sync_status: 'pending',
            update_id: `update-${inst.finding_uuid}`,
            revision: 1,
        }))
        return Promise.resolve(results)
    }),
    getDependencyChains: vi.fn().mockResolvedValue({
        paths: [],
        total: 0,
        limit: 10,
        offset: 0
    }),
    getAssessmentDetails: vi.fn(() => Promise.resolve([])),
    getKnownUsers: vi.fn(() => Promise.resolve([]))
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

    const analyzerResult = (verdict: string, summary: string, reasoning: string, ticketText = '') => ({
        assessment: {
            affected: verdict === 'Affected',
            verdict,
            confidence: 'High',
            exposure: verdict === 'Affected' ? 'reachable' : 'not reachable',
            summary,
            reasoning,
            ...(ticketText ? { ticket_text: ticketText } : {}),
        },
        steps: [],
        versions_checked: ['1.0'],
    })

    beforeEach(() => {
        vi.clearAllMocks()
        clipboardWriteText.mockResolvedValue(undefined)
        Object.defineProperty(navigator, 'clipboard', {
            configurable: true,
            value: { writeText: clipboardWriteText },
        })
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

    it('renders the CVSS base score as a header chip', () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        const primaryId = wrapper.get('[data-testid="vuln-primary-id"]').element
        const cvssBlock = wrapper.get('[data-testid="header-cvss-block"]')
        const position = primaryId.compareDocumentPosition(cvssBlock.element)

        expect(position & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
        expect(cvssBlock.classes()).toContain('rounded')
        expect(cvssBlock.text()).toContain('CVSS')
        expect(cvssBlock.text()).toContain('9.8')
        expect(cvssBlock.text()).not.toContain('CVSS Base')
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

    it('shows vulnerability age from the oldest attribution date', () => {
        vi.useFakeTimers()
        vi.setSystemTime(new Date('2026-06-29T12:00:00Z'))

        try {
            const wrapper = mount(VulnGroupCard, {
                props: {
                    group: {
                        ...mockGroup,
                        affected_versions: [
                            {
                                project_name: 'App1',
                                project_version: '1.0',
                                project_uuid: 'p1',
                                components: [
                                    {
                                        ...mockComponents[0],
                                        attributed_on: '2026-06-01T12:00:00Z',
                                    },
                                ],
                            },
                        ],
                    },
                },
            })

            const ageChip = wrapper.get('[data-testid="attribution-age-chip"]')
            expect(ageChip.text()).toContain('Age 4w')
            expect(ageChip.attributes('title')).toContain('2026-06-01')
        } finally {
            vi.useRealTimers()
        }
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

    it('keeps the sticky detail bar focused on tabs and renders the next action only once', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        await wrapper.find('.cursor-pointer').trigger('click')

        const stickyBar = wrapper.get('[data-vuln-card-sticky-nav]')
        expect(stickyBar.text()).toContain('Context')
        expect(stickyBar.text()).toContain('Code Evidence')
        expect(stickyBar.text()).toContain('Assessment')
        expect(stickyBar.text()).not.toContain('Review context')
        expect(stickyBar.find('[data-testid="sticky-tab-apply-button"]').exists()).toBe(false)
        expect(wrapper.findAll('[data-testid="analyst-next-action"]')).toHaveLength(1)
        expect(wrapper.findAll('[data-testid="workflow-primary-action"]').length).toBeLessThanOrEqual(1)
        expect(stickyBar.text()).not.toContain('CVSS & Rescoring')
        expect(stickyBar.text()).not.toContain('Global')
        expect(stickyBar.text()).not.toContain('Synced')
        expect(stickyBar.text()).not.toContain('CVSS 9.8')
        expect(stickyBar.text()).not.toContain('1 target')
    })

    it('turns next-action navigation into concrete guidance at the destination tab', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: {
                provide: {
                    user: ref({ role: 'ANALYST', username: 'analyst' }),
                    teamMapping: ref({ lib: ['Security'] }),
                },
            },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        expect(wrapper.get('[data-testid="workflow-primary-action"]').text()).toContain('Open code evidence')

        await wrapper.get('[data-testid="workflow-primary-action"]').trigger('click')
        await wrapper.vm.$nextTick()

        expect((wrapper.vm as any).activeDetailTab).toBe('analysis')
        expect(wrapper.find('[data-testid="workflow-primary-action"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="analyst-next-action"]').text()).toContain('You are at the next step')
        expect(wrapper.get('[data-testid="analyst-next-action"]').text()).toContain('Expand Run new analysis')
    })

    it('orders Context from description through scope and dependencies to assessment evidence', async () => {
        const wrapper = mount(VulnGroupCard, { props: { group: mockGroup } })
        await wrapper.find('.cursor-pointer').trigger('click')

        const html = wrapper.html()
        const description = html.indexOf('Description &amp; references')
        const scope = html.indexOf('Finding scope &amp; affected components')
        const dependencies = html.indexOf('Dependency context')
        const assessments = html.indexOf('Existing assessment evidence')
        expect(description).toBeGreaterThanOrEqual(0)
        expect(description).toBeLessThan(scope)
        expect(scope).toBeLessThan(dependencies)
        expect(dependencies).toBeLessThan(assessments)
    })

    it('shows scoped affected components in Context for analysts', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup, activeTeamFilter: 'Security' },
            global: {
                provide: {
                    user: ref({ role: 'ANALYST', username: 'analyst' }),
                    teamMapping: ref({ lib: ['Security'] }),
                },
            },
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        const components = wrapper.get('[data-testid="affected-components"]')
        expect(components.text()).toContain('Affected Components')
        expect(components.text()).toContain('lib@1.0')
    })

    it('guides analysts through the required assessment fields before submission', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        const assessmentTab = wrapper.findAll('[role="tab"]')
            .find(tab => tab.text().includes('Assessment'))
        await assessmentTab?.trigger('click')
        await wrapper.vm.$nextTick()

        expect((wrapper.vm as any).selectedTeam).toBe('Security')
        expect(wrapper.get('[data-testid="assessment-completeness"]').text())
            .toContain('analysis state, analysis details')
        expect(wrapper.get('[data-testid="assessment-submit-button"]').attributes('disabled'))
            .toBeDefined()

        ;(wrapper.vm as any).state = 'NOT_AFFECTED'
        await wrapper.find('textarea').setValue('The vulnerable code is absent.')
        await wrapper.vm.$nextTick()

        expect(wrapper.get('[data-testid="assessment-completeness"]').text())
            .toContain('justification')
        expect(wrapper.get('[data-testid="assessment-submit-button"]').attributes('disabled'))
            .toBeDefined()

        ;(wrapper.vm as any).justification = 'CODE_NOT_PRESENT'
        await wrapper.vm.$nextTick()

        expect(wrapper.get('[data-testid="assessment-completeness"]').text())
            .toContain('Assessment is ready to submit')
        expect(wrapper.get('[data-testid="assessment-submit-button"]').attributes('disabled'))
            .toBeUndefined()
        expect(wrapper.get('[data-testid="assessment-submit-button"]').text())
            .toBe('Submit Security for review')
    })

    it('renders advisory descriptions as markdown', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: {
                    ...mockGroup,
                    description: 'Summary with **bold** text.\n\n- first item\n- second item\n\n`inline code`'
                }
            }
        })

        await wrapper.find('.cursor-pointer').trigger('click')

        const description = wrapper.get('[data-testid="vuln-description"]')
        expect(description.html()).toContain('<strong>bold</strong>')
        expect(description.html()).toContain('<ul>')
        expect(description.html()).toContain('<code>inline code</code>')
        expect(description.html()).not.toContain('**bold**')
    })

    it('submits assessment update', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup, hasNextVulnerability: true },
            global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } }
        })

        // Expand
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        // Set state
        ;(wrapper.vm as any).state = 'NOT_AFFECTED'
        ;(wrapper.vm as any).justification = 'CODE_NOT_PRESENT'
        await wrapper.vm.$nextTick()
        await wrapper.find('textarea').setValue('False positive')

        // Click Apply
        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        expect(applyBtn).toBeDefined()
        expect((applyBtn.element as HTMLButtonElement).disabled).toBe(false)
        await applyBtn.trigger('click')
        await flushPromises()

        // Confirm in modal
        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Verify API call
        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            state: 'NOT_AFFECTED',
            details: expect.stringMatching(/---\s*\[Team:\s*Security\]\s*\[State:\s*NOT_AFFECTED\]\s*\[Assessed By:\s*tester\]\s*\[Date:\s*\d+\]\s*\[Justification:\s*CODE_NOT_PRESENT\]\s*---\n\nFalse positive/),
            team: 'Security'
        }))

        // Should emit update:assessment
        expect(wrapper.emitted()).toHaveProperty('update:assessment')
        expect(wrapper.get('[data-testid="assessment-persistence-status"]').text())
            .toContain('Saved locally — syncing to Dependency-Track')
        expect(wrapper.get('[data-testid="analyst-next-action"]').text()).toContain('Assessment submitted for review')
        await wrapper.get('[data-testid="workflow-primary-action"]').trigger('click')
        expect(wrapper.emitted('request-next')).toHaveLength(1)
        expect((wrapper.vm as any).originalAnalysis.f1).toEqual(expect.objectContaining({
            dtvpRevision: 1,
            dtvpSyncStatus: 'pending',
            dtvpUpdateId: 'update-f1',
        }))
    })

    it('keeps analysis provenance and adds one global reference to a team code-analysis draft', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: {
                provide: { user: { value: { username: 'tester' } } },
                stubs: { teleport: true },
            },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()
        const analysisResult = {
            assessment: {
                affected: false,
                verdict: 'Not Affected',
                confidence: 'High',
                exposure: 'none',
                summary: 'No vulnerable code path was found.',
                reasoning: 'The vulnerable package is absent.',
            },
            steps: [],
            versions_checked: ['1.0'],
        }

        await (wrapper.vm as any).handleCodeAnalysisResult(
            analysisResult,
            ['lib'],
            ['automatic-run-1'],
            'Security',
        )

        expect((wrapper.vm as any).codeAnalysisRunIds).toEqual(['automatic-run-1'])
        expect((wrapper.vm as any).codeAnalysisDraftApplied).toBe(true)
        expect((wrapper.vm as any).selectedTeam).toBe('Security')
        expect((wrapper.vm as any).activeDetailTab).toBe('review')
        expect((wrapper.vm as any).state).toBe('NOT_AFFECTED')
        expect((wrapper.vm as any).details).toContain('No vulnerable code path was found.')
        expect((wrapper.vm as any).teamDrafts.get('General')).toEqual(expect.objectContaining({
            state: 'NOT_AFFECTED',
            justification: 'CODE_NOT_PRESENT',
            details: expect.stringContaining('Assessed Teams: Security'),
        }))
        expect((wrapper.vm as any).teamDrafts.get('General').details)
            .not.toContain('No vulnerable code path was found.')

        await wrapper.get('[data-testid="assessment-submit-button"]').trigger('click')
        await flushPromises()
        await wrapper.findAll('button').find(button => button.text() === 'Submit')?.trigger('click')
        await flushPromises()

        const payload = vi.mocked(updateAssessment).mock.calls[0]?.[0] as any
        expect(payload.analysis_run_ids).toEqual(['automatic-run-1'])
        expect(payload.details.match(/\[Team: General\]/g)).toHaveLength(1)
        expect(payload.details.match(/\[Team: Security\]/g)).toHaveLength(1)
        const globalBlock = payload.details.split('--- [Team: Security]')[0]
        expect(globalBlock).toContain('Assessed Teams: Security')
        expect(globalBlock).not.toContain('No vulnerable code path was found.')
    })

    it('preserves existing global analysis when applying a selected team update', async () => {
        const groupWithGlobal = {
            ...mockGroup,
            affected_versions: [
                {
                    project_name: 'App1',
                    project_version: '1.0',
                    project_uuid: 'p1',
                    components: [
                        {
                            ...mockComponents[0],
                            analysis_details: '--- [Team: General] [State: IN_TRIAGE] [Assessed By: system] ---\nGlobal policy note.',
                            analysis_state: 'IN_TRIAGE',
                        },
                        {
                            ...mockComponents[0],
                            finding_uuid: 'f2',
                            analysis_details: '--- [Team: Security] [State: EXPLOITABLE] [Assessed By: analyst] ---\nTeam-specific issue.',
                            analysis_state: 'EXPLOITABLE',
                            tags: ['Security'],
                        }
                    ]
                }
            ]
        }

        const wrapper = mount(VulnGroupCard, {
            props: { group: groupWithGlobal },
            global: { provide: { user: { value: { username: 'tester' } } }, stubs: { teleport: true } }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        ;(wrapper.vm as any).state = 'NOT_AFFECTED'
        ;(wrapper.vm as any).justification = 'CODE_NOT_PRESENT'
        await wrapper.find('textarea').setValue('Updated team details')

        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
        await flushPromises()

        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            team: 'Security',
            details: expect.stringContaining('--- [Team: General] [State: IN_TRIAGE] [Assessed By: system]'),
        }))
    })

    it('shows tmrescore proposal inside the global review', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER', username: 'tester' }),
                    tmrescoreProposals: ref({
                        'CVE-2023-1234': {
                            original_score: 9.8,
                            rescored_score: 4.2,
                            original_vector: mockGroup.cvss_vector,
                            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N',
                            analysis: {
                                detail: 'Threat model reduces exposure for the reviewed deployment.',
                                response: ['Network path is constrained.'],
                            },
                        },
                    }),
                },
                stubs: { teleport: true },
            },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        const reviewTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))
        await reviewTab?.trigger('click')
        await wrapper.vm.$nextTick()

        expect(wrapper.text()).toContain('CVSS & Rescoring')
        expect(wrapper.text()).toContain('Threat Model Proposal')
        expect(wrapper.text()).toContain('Use Proposal Draft')
        expect(wrapper.text()).toContain('Threat model reduces exposure for the reviewed deployment.')
    })

    it('shows mapped overview context and enables code analysis for analysts', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: {
                provide: {
                    user: ref({ role: 'ANALYST', username: 'analyst' }),
                    teamMapping: ref({ lib: ['Security'] }),
                },
            },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        expect(wrapper.get('[data-testid="triggering-team-components"]').text()).toContain('Security')
        expect(wrapper.get('[data-testid="dependency-context"]').text()).toContain('Team:Security')

        const analysisTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Code Evidence'))
        await analysisTab?.trigger('click')
        await flushPromises()

        expect(wrapper.get('[data-testid="code-analysis-start"]').attributes('disabled')).toBeUndefined()
    })

    it('shows the latest analyzer result as an optional proposal in the team assessment', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: {
                provide: {
                    user: ref({ role: 'ANALYST', username: 'analyst' }),
                    teamMapping: ref({ lib: ['Security'] }),
                },
            },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        wrapper.getComponent(CodeAnalysisPanel).vm.$emit('proposals-change', [{
            component: 'lib',
            runId: 'auto-security',
            result: analyzerResult(
                'Affected',
                'Reachable parser use.',
                'The request path reaches the parser.',
                'Title: Remediate CVE-2023-1234 in lib',
            ),
        }])
        await wrapper.vm.$nextTick()

        const assessmentTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))
        await assessmentTab?.trigger('click')
        await wrapper.vm.$nextTick()

        const proposal = wrapper.get('[data-testid="automatic-assessment-proposal"]')
        expect(wrapper.get('[data-testid="assessment-team-components"]').text()).toContain('Component for Security:')
        expect(wrapper.get('[data-testid="assessment-team-components"]').text()).toContain('lib')
        expect(proposal.text()).toContain('Analyzer proposal')
        expect(proposal.text()).toContain('Reachable parser use.')
        expect(proposal.text()).toContain('The request path reaches the parser.')
        expect((wrapper.vm as any).state).toBe('NOT_SET')

        await proposal.get('[data-testid="copy-team-ticket"]').trigger('click')
        await flushPromises()
        expect(clipboardWriteText).toHaveBeenCalledWith('Title: Remediate CVE-2023-1234 in lib')
        expect(proposal.get('[data-testid="copy-team-ticket"]').text()).toContain('Ticket copied')

        await proposal.get('[data-testid="use-automatic-assessment-proposal"]').trigger('click')
        expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
        expect((wrapper.vm as any).details).toContain('Reachable parser use.')
        expect((wrapper.vm as any).teamDrafts.get('General')).toEqual(expect.objectContaining({
            state: 'EXPLOITABLE',
            details: expect.stringContaining('Assessed Teams: Security'),
        }))
        expect(wrapper.get('[data-testid="code-analysis-draft-banner"]').text()).toContain('Analyzer proposal selected for Security')
    })

    it('prefers saved team assessments and uses analyzer proposals only for missing teams in reviewer summary', async () => {
        const securityComponent = {
            ...mockComponents[0],
            analysis_state: 'NOT_AFFECTED',
            analysis_details: '--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: alice] [Justification: CODE_NOT_PRESENT] ---\nManual Security rationale.',
        }
        const runtimeComponent = {
            ...mockComponents[0],
            component_name: 'worker',
            component_uuid: 'c2',
            finding_uuid: 'f2',
            tags: ['Runtime'],
            analysis_state: 'NOT_SET',
            analysis_details: '',
        }
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: {
                    ...mockGroup,
                    affected_versions: [{
                        ...mockGroup.affected_versions[0],
                        components: [securityComponent, runtimeComponent],
                    }],
                },
            },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER', username: 'reviewer' }),
                    teamMapping: ref({ lib: ['Security'], worker: ['Runtime'] }),
                },
            },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        wrapper.getComponent(CodeAnalysisPanel).vm.$emit('proposals-change', [
            {
                component: 'lib',
                runId: 'auto-security',
                result: analyzerResult('Affected', 'Automatic Security result.', 'Automatic Security rationale.'),
            },
            {
                component: 'worker',
                runId: 'auto-runtime',
                result: analyzerResult('Not Affected', 'Automatic Runtime result.', 'Automatic Runtime rationale.'),
            },
        ])
        await wrapper.vm.$nextTick()

        const assessmentTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))
        await assessmentTab?.trigger('click')
        await wrapper.vm.$nextTick()

        const summary = wrapper.get('[data-testid="effective-team-assessment-summary"]')
        expect(summary.text()).toContain('Security')
        expect(summary.text()).toContain('Team assessment')
        expect(summary.text()).toContain('Runtime')
        expect(summary.text()).toContain('Analyzer fallback')
        expect(summary.text()).toContain('Worst: NOT AFFECTED')
        expect(summary.text()).not.toContain('Worst: EXPLOITABLE')

        await summary.get('[data-testid="use-effective-assessment-summary"]').trigger('click')
        await wrapper.vm.$nextTick()
        expect((wrapper.vm as any).state).toBe('NOT_AFFECTED')
        expect((wrapper.vm as any).details).toContain('Assessed Teams: Runtime, Security')
        expect((wrapper.vm as any).details).not.toContain('Manual Security rationale.')
        expect((wrapper.vm as any).details).not.toContain('Automatic Runtime result.')
    })

    it('scopes vulnerability component context to the selected team', async () => {
        const otherComponent = {
            ...mockComponents[0],
            component_name: 'worker',
            component_uuid: 'c2',
            finding_uuid: 'f2',
            tags: ['Runtime'],
            analysis_state: 'EXPLOITABLE',
            analysis_details: '--- [Team: Runtime] [State: EXPLOITABLE] [Assessed By: runtime-user] ---\nRuntime assessment.',
        }
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: {
                    ...mockGroup,
                    affected_versions: [{
                        ...mockGroup.affected_versions[0],
                        components: [mockComponents[0], otherComponent],
                    }],
                },
                activeTeamFilter: 'Security',
                automaticAssessmentStatus: 'auto',
            },
            global: {
                provide: {
                    user: ref({ role: 'ANALYST', username: 'analyst' }),
                    teamMapping: ref({ lib: ['Security', 'Sec Alias'], worker: ['Runtime'] }),
                },
            },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        expect(wrapper.get('[data-testid="vulnerability-team-scope"]').text()).toContain('1 of 2 findings shown')
        expect(wrapper.get('[data-testid="instance-count"]').text()).toContain('1×')
        expect(wrapper.get('[data-testid="component-summary"]').text()).toContain('lib')
        expect(wrapper.get('[data-testid="component-summary"]').text()).not.toContain('worker')
        expect(wrapper.get('[data-testid="dependency-context"]').text()).toContain('lib')
        expect(wrapper.get('[data-testid="dependency-context"]').text()).not.toContain('worker')

        expect(wrapper.get('[data-testid="vulnerability-assessments"]').text()).toContain('lib')
        expect(wrapper.get('[data-testid="vulnerability-assessments"]').text()).not.toContain('worker')
        expect(wrapper.getComponent(CodeAnalysisPanel).props('teamScope')).toBe('Security')
        expect(wrapper.getComponent(CodeAnalysisPanel).props('teamScopeAliases')).toEqual(['Sec Alias'])

        const assessmentTab = wrapper.findAll('[role="tab"]')
            .find(tab => tab.text().includes('Assessment'))
        await assessmentTab?.trigger('click')
        await wrapper.vm.$nextTick()

        expect(wrapper.get('[data-testid="assessment-team-scope"]').text())
            .toContain('Assessment scope: Security · other teams are hidden')
        expect((wrapper.vm as any).selectedTeam).toBe('Security')
        expect(wrapper.findAll('[data-testid="review-team-tab"]').map(tab => tab.text()))
            .toEqual(['Security'])
        expect(assessmentTab?.text()).toContain('Needed')
        expect(wrapper.get('[data-testid="analyst-next-action"]').text()).toContain('Gather code evidence')
    })

    it('focuses reviewers on the filtered team while keeping an explicit all-team view', async () => {
        const runtimeComponent = {
            ...mockComponents[0],
            component_name: 'worker',
            component_uuid: 'c2',
            finding_uuid: 'f2',
        }
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: {
                    ...mockGroup,
                    affected_versions: [{
                        ...mockGroup.affected_versions[0],
                        components: [mockComponents[0], runtimeComponent],
                    }],
                },
                activeTeamFilter: 'Security',
            },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER', username: 'reviewer' }),
                    teamMapping: ref({ lib: ['Security'], worker: ['Runtime'] }),
                },
            },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        const assessmentTab = wrapper.findAll('[role="tab"]')
            .find(tab => tab.text().includes('Assessment'))
        await assessmentTab?.trigger('click')
        await wrapper.vm.$nextTick()

        expect((wrapper.vm as any).selectedTeam).toBe('Security')
        expect(wrapper.findAll('[data-testid="review-team-tab"]').map(tab => tab.text()))
            .toEqual(['Security'])
        expect(wrapper.findAll('button').some(button => button.text().trim() === 'Global')).toBe(true)

        await wrapper.get('[data-testid="toggle-assessment-team-scope"]').trigger('click')
        await wrapper.vm.$nextTick()

        expect(wrapper.findAll('[data-testid="review-team-tab"]').map(tab => tab.text()))
            .toEqual(['Security', 'Runtime'])
        expect(wrapper.findAll('button').some(button => button.text().trim() === 'Global')).toBe(true)
        await wrapper.findAll('[data-testid="review-team-tab"]')
            .find(tab => tab.text() === 'Runtime')
            ?.trigger('click')
        expect(wrapper.get('[data-testid="assessment-team-components"]').text()).toContain('Component for Runtime:')
        expect(wrapper.get('[data-testid="assessment-team-components"]').text()).toContain('worker')

        await wrapper.get('[data-testid="toggle-assessment-team-scope"]').trigger('click')
        await wrapper.vm.$nextTick()
        expect((wrapper.vm as any).selectedTeam).toBe('Security')
        expect(wrapper.findAll('[data-testid="review-team-tab"]').map(tab => tab.text()))
            .toEqual(['Security'])
    })

    it('keeps automation out of Review and stages proposals without saving', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, tags: ['Security', 'automation'] } },
            global: {
                provide: {
                    user: ref({ role: 'REVIEWER', username: 'reviewer' }),
                    teamMapping: ref({ lib: ['Security'] }),
                    tmrescoreProposals: ref({
                        'CVE-2023-1234': {
                            original_score: 9.8,
                            rescored_score: 4.2,
                            original_vector: mockGroup.cvss_vector,
                            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N',
                            analysis: { detail: 'Scoped deployment evidence.' },
                        },
                    }),
                },
            },
        })

        await openReviewTab(wrapper)
        expect(wrapper.findAll('[data-testid="review-team-tab"]').map(tab => tab.text())).not.toContain('Automation')

        await (wrapper.vm as any).applyProposal()
        await wrapper.vm.$nextTick()

        expect((wrapper.vm as any).selectedTeam).toBe('')
        expect((wrapper.vm as any).formTouched).toBe(true)
        expect((wrapper.vm as any).details).toContain('Scoped deployment evidence.')
        expect(updateAssessment).not.toHaveBeenCalled()
    })

    it('shows whether a tmrescore/vscorer analysis is available in the header', () => {
        const withoutAnalysis = mount(VulnGroupCard, {
            props: { group: mockGroup },
        })

        const unavailableBadge = withoutAnalysis.get('[data-testid="tmrescore-analysis-badge"]')
        expect(unavailableBadge.text()).toContain('TMRescore unavailable')
        expect(unavailableBadge.attributes('data-availability')).toBe('unavailable')
        expect(unavailableBadge.attributes('title')).toBe('No TMRescore/vscorer analysis is available')
        expect(withoutAnalysis.get('[data-testid="automatic-assessment-badge"]').attributes('data-availability')).toBe('unavailable')

        const withAnalysis = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: {
                provide: {
                    tmrescoreProposals: ref({
                        'CVE-2023-1234': {
                            original_score: 9.8,
                            rescored_score: 4.2,
                            original_vector: mockGroup.cvss_vector,
                            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N',
                        },
                    }),
                },
            },
        })

        const availableBadge = withAnalysis.get('[data-testid="tmrescore-analysis-badge"]')
        expect(availableBadge.text()).toContain('TMRescore available')
        expect(availableBadge.attributes('data-availability')).toBe('available')
        expect(availableBadge.attributes('title')).toBe('TMRescore/vscorer analysis is available')
    })

    const openReviewTab = async (wrapper: ReturnType<typeof mount>) => {
        await wrapper.find('.cursor-pointer').trigger('click')
        const reviewTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))
        expect(reviewTab).toBeDefined()
        await reviewTab?.trigger('click')
        await wrapper.vm.$nextTick()
    }

    it('keeps CVSS and rescoring in the reviewer global review only', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, tags: ['Security'] } },
            global: {
                provide: { user: ref({ role: 'REVIEWER', username: 'tester' }) },
                stubs: { teleport: true },
            },
        })

        await openReviewTab(wrapper)

        expect(wrapper.findAll('[role="tab"]').map(tab => tab.text())).not.toContain('CVSS & Rescoring')
        expect(wrapper.get('[data-testid="global-cvss-rescoring"]').isVisible()).toBe(true)
        expect(wrapper.get('[data-testid="global-cvss-rescoring"]').text()).toContain('Applied with the global assessment')

        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        expect(wrapper.find('[data-testid="global-cvss-rescoring"]').exists()).toBe(false)
        expect(wrapper.text()).toContain('Team Assessment: Security')
    })

    it('enables the assessment header action when the CVSS vector or score changes', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, tags: ['Security'] } },
            global: {
                provide: { user: ref({ role: 'REVIEWER', username: 'tester' }) },
                stubs: { teleport: true },
            },
        })

        await openReviewTab(wrapper)
        await flushPromises()

        const decisionSection = wrapper.get('[data-testid="assessment-decision-section"]')
        const actions = decisionSection.get('[data-testid="assessment-decision-actions"]')
        const saveButton = actions.get('[data-testid="assessment-submit-button"]')
        expect(decisionSection.get('header').element.contains(saveButton.element)).toBe(true)
        expect(wrapper.findAll('[data-testid="assessment-submit-button"]')).toHaveLength(1)
        expect(saveButton.attributes('disabled')).toBeDefined()

        const vectorInput = decisionSection.get('#cvss-vector-input')
        await vectorInput.setValue('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L')
        expect((wrapper.vm as any).formTouched).toBe(true)
        expect(saveButton.attributes('disabled')).toBeUndefined()

        ;(wrapper.vm as any).updateFormFromGroup(true)
        ;(wrapper.vm as any).isManualBaseMode = true
        await wrapper.vm.$nextTick()
        expect(saveButton.attributes('disabled')).toBeDefined()

        const scoreInput = decisionSection.get('#cvss-score-input')
        expect(scoreInput.attributes('readonly')).toBeUndefined()
        await scoreInput.setValue('8.7')
        expect((wrapper.vm as any).pendingScore).toBe(8.7)
        expect((wrapper.vm as any).formTouched).toBe(true)
        expect(saveButton.attributes('disabled')).toBeUndefined()
    })

    it('keeps ticket reference optional when only the original score is critical', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: {
                provide: { user: ref({ role: 'REVIEWER', username: 'tester' }) },
                stubs: { teleport: true },
            },
        })

        await openReviewTab(wrapper)

        const context = wrapper.get('[data-testid="review-context"]')
        expect(context.text()).toContain('0/2 required')
        expect(wrapper.get('[data-testid="ticket-requirement-badge"]').text()).toBe('Optional')
        expect(context.text()).toContain('Optional unless rescoring leaves this High or Critical.')
        expect(wrapper.get('input[placeholder="e.g. SEC-1234 or remediation ticket"]').attributes('aria-required')).toBe('false')
    })

    it('requires ticket reference for high rescored severity', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, rescored_cvss: 7.2 } },
            global: {
                provide: { user: ref({ role: 'REVIEWER', username: 'tester' }) },
                stubs: { teleport: true },
            },
        })

        await openReviewTab(wrapper)

        const context = wrapper.get('[data-testid="review-context"]')
        expect(context.text()).toContain('0/3 required')
        expect(wrapper.get('[data-testid="ticket-requirement-badge"]').text()).toBe('Required')
        expect(context.text()).toContain('Required for HIGH after rescoring.')
        expect(wrapper.get('input[placeholder="e.g. SEC-1234 or remediation ticket"]').attributes('aria-required')).toBe('true')
    })

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
        ;(wrapper.vm as any).state = 'EXPLOITABLE'
        await wrapper.vm.$nextTick()
        await wrapper.find('textarea').setValue('Validated exploitable path')

        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
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
        ;(wrapper.vm as any).selectedTeam = 'Security'
        ;(wrapper.vm as any).state = 'EXPLOITABLE'
        await wrapper.vm.$nextTick()
        await wrapper.find('textarea').setValue('Draft that should remain local')
        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
        await flushPromises()

        // Modal appears, click Cancel
        const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
        await cancelBtn?.trigger('click')
        await flushPromises()

        expect(updateAssessment).not.toHaveBeenCalled()
    })



    it('submits assessment with suppression without audit comment', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'tester' } } }, stubs: { teleport: true } }
        })
        await wrapper.find('.cursor-pointer').trigger('click')

        // Select Team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        expect(wrapper.find('#assessment-comment-textarea').exists()).toBe(false)

        const checkboxes = wrapper.findAll('input[type="checkbox"]')
        if (checkboxes.length > 0) {
            await checkboxes[checkboxes.length - 1]?.setValue(true) // Suppression is last
        }

        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
        await flushPromises()

        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            suppressed: true,
            team: 'Security'
        }))
        const lastPayload = vi.mocked(updateAssessment).mock.calls.at(-1)?.[0] as unknown as Record<string, unknown>
        expect(lastPayload).not.toHaveProperty('comment')
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
        ;(wrapper.vm as any).state = 'EXPLOITABLE'
        await wrapper.vm.$nextTick()
        await wrapper.find('textarea').setValue('Validated exploitable path')

        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
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

    it('asks analysts to submit an unsaved draft before leaving the card', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup, inModal: true },
            global: { stubs: { teleport: true } }
        })

        ;(wrapper.vm as any).formTouched = true
        await wrapper.vm.$nextTick()

        expect(wrapper.get('[data-testid="header-draft-chip"]').text()).toContain('Unsaved draft')

        const leavePromise = (wrapper.vm as any).confirmApplyDraftBeforeLeave()
        await flushPromises()

        expect(wrapper.text()).toContain('Submit this assessment before leaving?')
        expect(wrapper.findAll('button').some(button => button.text() === 'Submit')).toBe(true)
        expect(wrapper.findAll('button').some(button => button.text() === 'Discard')).toBe(true)

        const stayButton = wrapper.findAll('button').find(button => button.text() === 'Stay')
        expect(stayButton).toBeDefined()
        await stayButton?.trigger('click')
        await expect(leavePromise).resolves.toBe(false)
    })

    it('discards an unsaved draft and closes without applying it', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup, inModal: true },
            global: { stubs: { teleport: true } }
        })

        ;(wrapper.vm as any).details = 'Unsaved local explanation'
        ;(wrapper.vm as any).formTouched = true
        await wrapper.vm.$nextTick()

        await wrapper.get('button[title="Close details"]').trigger('click')
        await flushPromises()

        const discardButton = wrapper.findAll('button').find(button => button.text() === 'Discard')
        expect(discardButton).toBeDefined()
        await discardButton?.trigger('click')
        await flushPromises()

        expect(wrapper.emitted('close')).toHaveLength(1)
        expect((wrapper.vm as any).hasUnsavedDraft).toBe(false)
        expect((wrapper.vm as any).details).not.toBe('Unsaved local explanation')
        expect(updateAssessment).not.toHaveBeenCalled()
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
        await wrapper.find('textarea').setValue('Vulnerable code is not present')

        // Apply bulk update
        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        applyBtn.trigger('click') // Do NOT await here, it waits for promptConfirm
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
        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
        await flushPromises()

        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Verify updateAssessment was called with the Rescored 0.0 vector in the payload.
        // It should inject [Rescored: 0.0] and the default CVSS 3.1 0-score vector.
        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            details: expect.stringContaining('[Rescored: 0.0]')
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
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'tester' } }, rescoreRules: ref(defaultRescoreRules) } }
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
            global: { provide: { user: { value: { role: 'REVIEWER', username: 'tester' } }, rescoreRules: ref(defaultRescoreRules) } }
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
        expect((vectorInput.element as HTMLInputElement).value).not.toContain('IR:')
    })

    it('offers to sync an existing rescored vector that is missing required rule fields', async () => {
        const rescoreRules = ref({
            metric_rules: defaultRescoreRules.metric_rules,
            transitions: [{
                trigger: { state: 'NOT_AFFECTED' },
                actions: {
                    '3.1': { CR: 'L', IR: 'L', AR: 'L', MC: 'N', MI: 'N', MA: 'N' },
                },
            }],
        })
        const groupWithIncompleteRescore = {
            ...mockGroup,
            rescored_cvss: 0,
            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N',
            affected_versions: [{
                ...mockGroup.affected_versions[0],
                components: mockComponents.map(component => ({
                    ...component,
                    analysis_state: 'NOT_AFFECTED',
                    analysis_details: '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: tester] ---\nNot reachable',
                })),
            }],
        }

        const wrapper = mount(VulnGroupCard, {
            props: { group: groupWithIncompleteRescore },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'tester' }), rescoreRules } },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        expect(wrapper.get('[data-testid="sync-rescore-rules"]').text()).toContain('Sync rules')
        await wrapper.get('[data-testid="sync-rescore-rules"]').trigger('click')
        await wrapper.vm.$nextTick()

        expect((wrapper.vm as any).pendingVector).toContain('CR:L/IR:L/AR:L')
        expect(wrapper.find('[data-testid="sync-rescore-rules"]').exists()).toBe(false)
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
        ;(wrapper.vm as any).justification = 'CODE_NOT_PRESENT'
        await wrapper.vm.$nextTick()
        await flushPromises()

        await wrapper.find('textarea').setValue('Analyst no rescore')
        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
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
        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        applyBtn.trigger('click') // Do NOT await
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
        // Audit comment and suppression controls should be hidden for analysts
        expect(wrapper.findAll('label').some(l => l.text() === 'Comment')).toBe(false)
        expect(wrapper.findAll('label').some(l => l.text() === 'Suppress this vulnerability')).toBe(false)

        // Select team
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        // With role-based UI for Analyst:
        // - Audit comment and suppression controls are STILL hidden
        expect(wrapper.findAll('label').some(l => l.text() === 'Comment')).toBe(false)
        // - Team tab should be selected and its assessment section visible
        expect(wrapper.text()).toContain('Security')
        // - Global tab should not be active for non-reviewers
        expect(wrapper.text()).toContain('Analysis State')
    })

    it('shows suppression but no audit comment input for reviewers', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, tags: ['Security'] } },
            global: {
                provide: {
                    user: { value: { role: 'REVIEWER', username: 'reviewer-user' } }
                }
            }
        })

        await wrapper.find('.cursor-pointer').trigger('click')

        expect(wrapper.findAll('label').some(l => l.text() === 'Comment')).toBe(false)
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

        await openReviewTab(wrapper)

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
