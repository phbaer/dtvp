import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import VulnGroupCard from '../VulnGroupCard.vue'
import CodeAnalysisPanel from '../CodeAnalysisPanel.vue'
import SsvcCalculator from '../SsvcCalculator.vue'
import defaultRescoreRules from '../../../../data/rescore_rules.json'
import ssvcModel from '../../../../dtvp/resources/ssvc/deployer-1.0.0.json'

const clipboardWriteText = vi.fn()

// Mock API
vi.mock('../../lib/api', async () => {
    // The server renders the stored text from the fields a save sends.
    const { renderAssessmentFields } = await import('../../lib/__tests__/assessmentFieldsText')
    return {
    getSsvcModels: vi.fn(() => Promise.resolve([ssvcModel])),
    getSsvcExploitation: vi.fn(() => Promise.resolve({ enabled: true, sources: [], suggestion: null, auto_fill: false, retry_after: 0 })),
    updateAssessment: vi.fn((payload: any) => {
        // Sophisticated mock for per-team aggregation
        const results = payload.instances.map((inst: any) => ({
            status: 'success',
            uuid: inst.finding_uuid,
            new_state: payload.state, // In real backend this would be aggregated
            new_details: `-- - [Team: ${payload.team || 'General'}][State: ${payload.state}][Assessed By: test - mock][Justification: ${payload.justification || 'NOT_SET'}]---\n${renderAssessmentFields(payload.fields)}`,
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
    getKnownUsers: vi.fn(() => Promise.resolve([])),
    deleteAssessment: vi.fn(() => Promise.resolve([])),
    previewGroupRepair: vi.fn(() => Promise.resolve({ items: [], topics: [], selectable_group_ids: [] })),
    getBulkWorkflowSummary: vi.fn(() => Promise.resolve({ workflows: [] })),
    previewBulkWorkflow: vi.fn(() => new Promise(() => {})),
    }
})

// Mock Icons
vi.mock('@lucide/vue', async (importOriginal) => {
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
import { renderAssessmentFields } from '../../lib/__tests__/assessmentFieldsText'

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
            application_eligible: true,
            rescoring_eligible: false,
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

    it('shows cached source badges without requiring a saved SSVC assessment', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, evidence_sources: ['KEV', 'CISA_SSVC', 'STALE'] } },
        })
        expect(wrapper.findAll('[data-testid="evidence-badge"]').map(badge => badge.text())).toEqual(['KEV', 'CISA SSVC'])
        expect(wrapper.get('[data-testid="evidence-badge"]').attributes('title')).toContain('Stale cached data')
        await wrapper.setProps({ group: { ...mockGroup, evidence_sources: ['NOT_CHECKED'] } })
        expect(wrapper.findAll('[data-testid="evidence-badge"]')).toHaveLength(0)
        wrapper.unmount()
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

    it('keeps tabs and all actions in the sticky bar and shows no next-action banner or team mapping tab', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup }
        })

        await wrapper.find('.cursor-pointer').trigger('click')

        const stickyBar = wrapper.get('[data-vuln-card-sticky-nav]')
        expect(stickyBar.text()).toContain('Context')
        expect(stickyBar.text()).toContain('Code Evidence')
        expect(stickyBar.text()).toContain('Assessment')
        expect(stickyBar.text()).not.toContain('Review context')
        // Every action of the card sits in this bar, and only once.
        expect(stickyBar.findAll('[data-testid="assessment-submit-button"]')).toHaveLength(1)
        expect(stickyBar.find('[data-testid="assessment-more-button"]').exists()).toBe(true)
        expect(stickyBar.text()).not.toContain('Team Mapping')
        expect(wrapper.find('[data-testid="analyst-next-action"]').exists()).toBe(false)
        expect(wrapper.find('[data-testid="workflow-primary-action"]').exists()).toBe(false)
        expect(stickyBar.text()).not.toContain('CVSS & Rescoring')
        expect(stickyBar.text()).not.toContain('Global')
        expect(stickyBar.text()).not.toContain('Synced')
        expect(stickyBar.text()).not.toContain('CVSS 9.8')
        expect(stickyBar.text()).not.toContain('1 target')
    })

    it('orders Context from description through where it was found to assessment evidence', async () => {
        const wrapper = mount(VulnGroupCard, { props: { group: mockGroup } })
        await wrapper.find('.cursor-pointer').trigger('click')

        const html = wrapper.html()
        const description = html.indexOf('Description &amp; references')
        const scope = html.indexOf('Where it was found')
        const assessments = html.indexOf('Existing assessment evidence')
        expect(description).toBeGreaterThanOrEqual(0)
        expect(description).toBeLessThan(scope)
        expect(scope).toBeLessThan(assessments)
        // The separate version, component and dependency lists are one matrix now.
        expect(html).not.toContain('Dependency context')
        expect(wrapper.find('[data-testid="affected-components"]').exists()).toBe(false)
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

        const matrix = wrapper.get('[data-testid="where-found"] [data-testid="finding-matrix"]')
        expect(matrix.get('[data-testid="finding-matrix-summary"]').text()).toBe('1 component · 1 version')
        expect(matrix.get('[data-testid="finding-matrix-row"]').text()).toContain('lib@1.0')
        expect(matrix.findAll('[data-testid="context-project-version"]').map(cell => cell.text())).toEqual(['1.0'])
        expect(matrix.get('[data-testid="finding-matrix-cell"]').text()).toContain('Not set')
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
        await wrapper.get('#analysis-details-textarea').setValue('The vulnerable code is absent.')
        await wrapper.vm.$nextTick()

        expect(wrapper.get('[data-testid="assessment-completeness"]').text())
            .toContain('justification')
        expect(wrapper.get('[data-testid="assessment-submit-button"]').attributes('disabled'))
            .toBeDefined()

        ;(wrapper.vm as any).justification = 'CODE_NOT_PRESENT'
        await wrapper.vm.$nextTick()

        // Nothing is missing: the hint goes away, the button says the rest.
        expect(wrapper.find('[data-testid="assessment-completeness"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="assessment-submit-button"]').attributes('disabled'))
            .toBeUndefined()
        expect(wrapper.get('[data-testid="assessment-submit-button"]').text())
            .toBe('Submit Security for review')
    })

    it('lets the current team use a former owner assessment as an unsaved draft', async () => {
        const group = {
            ...mockGroup,
            affected_versions: [{
                ...mockGroup.affected_versions[0],
                components: [{
                    ...mockComponents[0],
                    analysis_state: 'NOT_AFFECTED',
                    analysis_details: '--- [Team: Former] [State: NOT_AFFECTED] [Assessed By: alice] [Justification: CODE_NOT_PRESENT] [Assigned: alice] [Evidence Reviewed: yes] ---\nFormer rationale',
                }],
            }],
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group, activeTeamFilter: 'Security' },
            global: {
                provide: {
                    user: ref({ role: 'ANALYST', username: 'bob' }),
                    teamMapping: ref({ lib: ['Security'] }),
                },
            },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        await wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))?.trigger('click')
        await wrapper.vm.$nextTick()
        expect(wrapper.findAll('[data-testid="review-team-tab"]').map(tab => tab.text())).toEqual(['Security'])
        expect(wrapper.get('[data-testid="previous-team-assessments"]').text()).toContain('Former')
        await wrapper.get('[data-testid="use-previous-team-Former"]').trigger('click')
        await wrapper.vm.$nextTick()
        expect((wrapper.vm as any).state).toBe('NOT_AFFECTED')
        expect((wrapper.vm as any).details).toBe('Former rationale')
        expect((wrapper.vm as any).currentAssigned).toEqual([])
        expect((wrapper.vm as any).evidenceReviewed).toBe(false)
        expect(wrapper.get('[data-testid="assessment-submit-button"]').attributes('disabled')).toBeUndefined()
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
        await wrapper.get('#analysis-details-textarea').setValue('False positive')

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
            // The assessment is sent as fields, not as composed text.
            fields: expect.objectContaining({
                teams: [expect.objectContaining({
                    team: 'Security',
                    state: 'NOT_AFFECTED',
                    assessed_by: 'tester',
                    assessed_at_ms: expect.any(Number),
                    justification: 'CODE_NOT_PRESENT',
                    details: 'False positive',
                })],
            }),
            team: 'Security'
        }))
        const sent = vi.mocked(updateAssessment).mock.calls.at(-1)?.[0] as any
        expect(sent.details).toBeUndefined()
        expect(sent.comparison_mode).toBeUndefined()

        // Should emit update:assessment
        expect(wrapper.emitted()).toHaveProperty('update:assessment')
        expect(wrapper.get('[data-testid="assessment-persistence-status"]').text())
            .toContain('Saved locally — syncing to Dependency-Track')
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
                application_eligible: true,
                rescoring_eligible: false,
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
        expect(renderAssessmentFields(payload.fields).match(/\[Team: General\]/g)).toHaveLength(1)
        expect(renderAssessmentFields(payload.fields).match(/\[Team: Security\]/g)).toHaveLength(1)
        const globalBlock = renderAssessmentFields(payload.fields).split('--- [Team: Security]')[0]
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
        await wrapper.get('#analysis-details-textarea').setValue('Updated team details')

        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
        await flushPromises()

        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            team: 'Security',
            fields: expect.objectContaining({
                teams: expect.arrayContaining([expect.objectContaining({
                    team: 'General', state: 'IN_TRIAGE', assessed_by: 'system',
                })]),
            }),
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

        expect(wrapper.text()).toContain('CVSS & SSVC')
        const rescoring = wrapper.get('[data-testid="global-cvss-rescoring"]')
        const cvssScore = rescoring.get('#cvss-score-input').element
        const ssvc = rescoring.getComponent(SsvcCalculator).element
        expect(cvssScore.compareDocumentPosition(ssvc) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
        expect(wrapper.text()).toContain('Threat Model Proposal')
        expect(wrapper.text()).toContain('Use Proposal Draft')
        expect(wrapper.text()).toContain('Threat model reduces exposure for the reviewed deployment.')
    })

    it('summarises the vulnerability at the top of the Assessment tab', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: {
                    ...mockGroup,
                    description: [
                        'A **crafted** document makes the parser read past its buffer.<script>alert(1)</script>',
                        '',
                        ...Array.from({ length: 4 }, (_, index) => `Paragraph ${index + 2} explains more.`).flatMap(line => [line, '']),
                    ].join('\n'),
                    cwes: [{ id: 125, name: 'Out-of-bounds Read' }],
                    recommendation: 'Upgrade to **2.0**.',
                },
            },
            global: { provide: { user: ref({ role: 'ANALYST', username: 'analyst' }) } },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        const assessmentTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))
        await assessmentTab?.trigger('click')
        await flushPromises()

        const review = wrapper.get(`#vuln-${mockGroup.id}-detail-panel-review`)
        const about = review.get('[data-testid="vuln-about"]')
        // The advisory summary remains above the decision.
        expect(review.element.querySelector('[data-testid="vuln-about"]')!
            .compareDocumentPosition(review.get('[data-testid="assessment-decision-section"]').element)
            & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
        expect(about.get('[data-testid="vuln-about-toggle"]').attributes('aria-expanded')).toBe('true')
        expect(about.get('[data-testid="vuln-about-title"]').text()).toBe('Test Vulnerability')

        // Plain text, sanitised: no markup, no script text.
        const description = about.get('[data-testid="vuln-about-description"]')
        expect(description.text()).toContain('A crafted document makes the parser read past its buffer.')
        expect(description.text()).not.toContain('**')
        expect(description.text()).not.toContain('alert')
        expect(description.element.querySelector('script, strong')).toBeNull()
        expect(description.classes()).toContain('line-clamp-3')
        const more = about.get('[data-testid="vuln-about-more"]')
        expect(more.text()).toBe('Show more')
        await more.trigger('click')
        expect(description.classes()).not.toContain('line-clamp-3')
        expect(more.text()).toBe('Show less')
        expect(more.attributes('aria-expanded')).toBe('true')

        expect(about.get('[data-testid="vuln-about-affects"]').text()).toContain('lib 1.0')
        expect(about.get('[data-testid="vuln-about-affects"]').text()).toContain('in version 1.0')
        expect(about.get('[data-testid="vuln-about-attack"]').text())
            .toContain('network, low complexity, no privileges, no user interaction')
        expect(about.get('[data-testid="vuln-about-cwe"]').text()).toContain('CWE-125 Out-of-bounds Read')
        expect(about.get('[data-testid="vuln-about-fix"] dd').text()).toBe('Upgrade to 2.0.')
        expect(about.findAll('a').map(link => link.text())).toEqual(['NVD', 'MITRE'])

        // The block folds to one line.
        await about.get('[data-testid="vuln-about-toggle"]').trigger('click')
        expect(about.find('[data-testid="vuln-about-description"]').exists()).toBe(false)
        expect(about.text()).toContain('Test Vulnerability')
    })

    it('lists the team-mapped components once and notes the team filter only when it hides findings', async () => {
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
        await flushPromises()

        const whereFound = wrapper.get('[data-testid="where-found"]')
        const mapped = whereFound.findAll('[data-testid="triggering-team-component"]')
        expect(mapped).toHaveLength(1)
        expect(mapped[0].text()).toMatch(/^lib\s*@1\.0\s*\(Security\)$/)
        expect(whereFound.text()).not.toContain('Affected components with team tags')
        // Every finding belongs to the filtered team: nothing to say.
        expect(wrapper.find('[data-testid="vulnerability-team-scope"]').exists()).toBe(false)
        // Explanations are tooltips (and screen-reader descriptions), not subtitles.
        expect(whereFound.find('header p').exists()).toBe(false)
        expect(whereFound.get('[data-testid="detail-section-help"]').attributes('title'))
            .toContain('Every affected component by project version')
    })

    it('shows the generated text read-only instead of an editable raw text', async () => {
        const group = JSON.parse(JSON.stringify(mockGroup))
        group.affected_versions[0].components[0].analysis_state = 'NOT_AFFECTED'
        group.affected_versions[0].components[0].analysis_details =
            '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'reviewer' }) } },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        expect(wrapper.text()).not.toContain('Raw Assessment Text')
        const generated = wrapper.get('[data-testid="generated-assessment-text"]')
        const toggle = generated.get('[data-testid="generated-assessment-text-toggle"]')
        expect(toggle.attributes('aria-expanded')).toBe('false')
        expect(generated.find('[data-testid="generated-assessment-text-body"]').exists()).toBe(false)
        await toggle.trigger('click')
        const body = generated.get('[data-testid="generated-assessment-text-body"]')
        expect(body.element.tagName).toBe('PRE')
        expect(body.text()).toContain('[Team: General] [State: NOT_AFFECTED]')
        // Read-only: nothing to type into, and showing it changes nothing.
        expect(generated.find('textarea, input[type="text"]').exists()).toBe(false)
        expect((wrapper.vm as any).hasUnsavedDraft).toBe(false)

        await generated.get('[data-testid="copy-generated-assessment-text"]').trigger('click')
        await flushPromises()
        expect(clipboardWriteText).toHaveBeenCalledWith(expect.stringContaining('[Team: General] [State: NOT_AFFECTED]'))
        expect(generated.get('[data-testid="copy-generated-assessment-text"]').text()).toBe('Copied')
    })

    it('clears the open team assessment from the More menu after a confirmation', async () => {
        const { deleteAssessment } = await import('../../lib/api')
        const group = JSON.parse(JSON.stringify(mockGroup))
        group.affected_versions[0].components[0].analysis_state = 'NOT_AFFECTED'
        group.affected_versions[0].components[0].analysis_details =
            '--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: analyst] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: {
                provide: { user: ref({ role: 'ANALYST', username: 'analyst' }), teamMapping: ref({ lib: ['Security'] }) },
                stubs: { teleport: true },
            },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        const assessmentTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))
        await assessmentTab?.trigger('click')
        await flushPromises()
        expect((wrapper.vm as any).selectedTeam).toBe('Security')

        await wrapper.get('[data-testid="assessment-more-button"]').trigger('click')
        await wrapper.get('[data-testid="assessment-clear-button"]').trigger('click')
        const dialog = wrapper.get('[data-testid="clear-assessment-modal"]')
        expect(dialog.text()).toContain('Only the Security assessment')
        expect(dialog.get('[data-testid="clear-applies-to"]').text()).toContain('the finding of lib in version 1.0')
        expect(dialog.find('[data-testid="clear-all"]').exists()).toBe(false)

        await dialog.get('[data-testid="clear-confirm"]').trigger('click')
        await flushPromises()
        expect(deleteAssessment).toHaveBeenCalledWith(expect.any(Array), 'Security')
        expect(wrapper.find('[data-testid="clear-assessment-modal"]').exists()).toBe(false)
    })

    it('puts the reviewer decision before CVSS and SSVC', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: mockGroup },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'reviewer' }) } },
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        const decision = wrapper.get('#analysis-state-select').element
        const cvss = wrapper.get('[data-testid="global-cvss-rescoring"]').element
        expect(decision.compareDocumentPosition(cvss) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
        // Reviewers have nothing missing to submit: no hint.
        expect(wrapper.find('[data-testid="assessment-completeness"]').exists()).toBe(false)
        expect(wrapper.text()).toContain('Global Assessment')
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
        // The dependency chains of a component open from its row.
        expect(wrapper.find('[data-testid="finding-matrix-chains"]').exists()).toBe(false)
        await wrapper.get('[data-testid="finding-matrix-row-toggle"]').trigger('click')
        expect(wrapper.get('[data-testid="finding-matrix-chains"]').text()).toContain('Team:Security')

        const analysisTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Code Evidence'))
        await analysisTab?.trigger('click')
        await flushPromises()

        expect(wrapper.get('[data-testid="run-analysis-toggle"]').attributes('disabled')).toBeUndefined()
        await wrapper.get('[data-testid="run-analysis-toggle"]').trigger('click')
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
        expect(wrapper.get('[data-testid="assessment-team-components"]').text()).toContain('Component:')
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

        // The team overview: the saved decision, the analyzer fallback only for a missing team.
        const summary = wrapper.get('[data-testid="team-assessment-overview"]')
        const rows = summary.findAll('[data-testid="team-overview-row"]')
        expect(rows.map(row => row.attributes('data-team'))).toEqual(['Runtime', 'Security'])
        expect(rows[0]!.attributes('data-status')).toBe('missing')
        expect(rows[0]!.get('[data-testid="team-overview-state"]').text()).toBe('Not affected · Code not reachable (analyzer)')
        expect(rows[1]!.attributes('data-status')).toBe('submitted')
        expect(rows[1]!.get('[data-testid="team-overview-state"]').text()).toBe('Not affected · Code not present')
        expect(summary.get('[data-testid="team-overview-summary"]').text()).toBe('2 teams: 1 Not affected · 1 missing (Runtime)')
        expect(summary.text()).toContain('Worst: Not affected')
        expect(summary.text()).not.toContain('Exploitable')
        expect(wrapper.find('[data-testid="effective-team-assessment-summary"]').exists()).toBe(false)

        await summary.get('[data-testid="use-effective-assessment-summary"]').trigger('click')
        await wrapper.vm.$nextTick()
        expect((wrapper.vm as any).state).toBe('NOT_AFFECTED')
        expect((wrapper.vm as any).details).toContain('Assessed Teams: Runtime, Security')
        expect((wrapper.vm as any).details).not.toContain('Manual Security rationale.')
        expect((wrapper.vm as any).details).not.toContain('Automatic Runtime result.')
    })

    it('keeps a reviewer on the Global form they chose, with a team filter and an edited team draft', async () => {
        const runtimeComponent = {
            ...mockComponents[0],
            component_name: 'worker',
            component_uuid: 'c2',
            finding_uuid: 'f2',
            tags: ['Runtime'],
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
        const vm = wrapper.vm as any
        const globalTab = () => wrapper.findAll('[data-testid="assessment-scope"] button').find(button => button.text().trim() === 'Global')!
        const tab = (name: string) => wrapper.findAll('[role="tab"]').find(candidate => candidate.text().includes(name))!

        await wrapper.find('.cursor-pointer').trigger('click')
        await tab('Assessment').trigger('click')
        await flushPromises()
        // The team filter preselects the team on first open.
        expect(vm.selectedTeam).toBe('Security')

        await wrapper.get('#analysis-details-textarea').setValue('Security draft.')
        expect(vm.formTouched).toBe(true)

        await globalTab().trigger('click')
        await flushPromises()
        expect(vm.selectedTeam).toBe('')
        expect(globalTab().attributes('aria-pressed')).toBe('true')
        expect(wrapper.find('[data-testid="global-cvss-rescoring"]').exists()).toBe(true)
        expect((wrapper.get('#analysis-details-textarea').element as HTMLTextAreaElement).value).not.toBe('Security draft.')

        // Another detail tab and back does not override the choice.
        await tab('Context').trigger('click')
        await tab('Assessment').trigger('click')
        await flushPromises()
        expect(vm.selectedTeam).toBe('')

        // Back to the team: its draft is still there.
        await wrapper.findAll('[data-testid="review-team-tab"]').find(button => button.text() === 'Security')!.trigger('click')
        await flushPromises()
        expect(vm.selectedTeam).toBe('Security')
        expect((wrapper.get('#analysis-details-textarea').element as HTMLTextAreaElement).value).toBe('Security draft.')

        // A change of the team filter preselects again.
        await globalTab().trigger('click')
        await flushPromises()
        await wrapper.setProps({ activeTeamFilter: 'Runtime' })
        await flushPromises()
        expect(vm.selectedTeam).toBe('Runtime')
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
        expect(wrapper.get('[data-testid="finding-matrix"]').text()).toContain('lib')
        expect(wrapper.get('[data-testid="finding-matrix"]').text()).not.toContain('worker')

        expect(wrapper.get('[data-testid="vulnerability-assessments"]').text()).toContain('lib')
        expect(wrapper.get('[data-testid="vulnerability-assessments"]').text()).not.toContain('worker')
        expect(wrapper.getComponent(CodeAnalysisPanel).props('teamScope')).toBe('Security')
        expect(wrapper.getComponent(CodeAnalysisPanel).props('teamScopeAliases')).toEqual(['Sec Alias'])

        const assessmentTab = wrapper.findAll('[role="tab"]')
            .find(tab => tab.text().includes('Assessment'))
        await assessmentTab?.trigger('click')
        await wrapper.vm.$nextTick()

        expect(wrapper.get('[data-testid="assessment-team-scope"]').text())
            .toContain('Other teams are hidden by the team filter')
        expect((wrapper.vm as any).selectedTeam).toBe('Security')
        expect(wrapper.findAll('[data-testid="review-team-tab"]').map(tab => tab.text()))
            .toEqual(['Security'])
        expect(assessmentTab?.text()).toContain('Needed')
    })

    it('focuses reviewers on the filtered team while keeping an explicit all-team view', async () => {
        const runtimeComponent = {
            ...mockComponents[0],
            component_name: 'worker',
            component_uuid: 'c2',
            finding_uuid: 'f2',
            tags: ['Runtime'],
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
        expect(wrapper.get('[data-testid="assessment-team-components"]').text()).toContain('Component:')
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

    it('keeps the rescored score when switching between assessment tabs', async () => {
        const rescoredVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N'
        const wrapper = mount(VulnGroupCard, {
            props: {
                group: {
                    ...mockGroup,
                    tags: ['Security'],
                    cvss_score: 9.8,
                    rescored_cvss: null,
                    rescored_vector: rescoredVector,
                },
            },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'tester' }) }, stubs: { teleport: true } },
        })
        await openReviewTab(wrapper)
        const vm = wrapper.vm as any
        expect(vm.pendingScore).toBe(0)
        expect(vm.formTouched).toBe(false)

        vm.selectedTeam = 'Security'
        await wrapper.vm.$nextTick()
        expect(vm.pendingVector).toBe(rescoredVector)
        expect(vm.pendingScore).toBe(0)

        vm.selectedTeam = ''
        await wrapper.vm.$nextTick()
        expect(vm.pendingScore).toBe(0)
        expect(vm.formTouched).toBe(false)
        wrapper.unmount()
    })

    it('tracks SSVC-only edits and sends an explicit global selection', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, tags: ['Security'] } },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'tester' }) }, stubs: { teleport: true } },
        })
        await openReviewTab(wrapper)
        const selection = { model: 'ssvc:DT_DP', version: '1.0.0', answers: { 'ssvc:E:1.1.0': 'A' }, rationale: 'Review deployment', exploitation_evidence: 'signed-evidence' }
        wrapper.getComponent(SsvcCalculator).vm.$emit('update:modelValue', selection)
        await wrapper.vm.$nextTick()
        expect(wrapper.get('[data-testid="assessment-submit-button"]').attributes('disabled')).toBeUndefined()
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()
        expect(wrapper.text()).toContain('Unsaved SSVC changes')
        ;(wrapper.vm as any).selectedTeam = ''
        await wrapper.vm.$nextTick()
        const saving = (wrapper.vm as any).handleUpdate(false)
        await flushPromises()
        expect((wrapper.vm as any).reviewModal.blocks.find((block: any) => block.team === 'General').details).toContain('SSVC priority: Incomplete')
        ;(wrapper.vm as any).handleReviewConfirm()
        await saving
        expect(updateAssessment).toHaveBeenLastCalledWith(expect.objectContaining({ ssvc: selection }))
        expect((wrapper.vm as any).ssvcTouched).toBe(false)
        wrapper.unmount()
    })

    it('keeps CVSS and rescoring in the reviewer global review only', async () => {
        const wrapper = mount(VulnGroupCard, {
            props: { group: { ...mockGroup, tags: ['Security'] } },
            global: {
                provide: { user: ref({ role: 'REVIEWER', username: 'tester' }) },
                stubs: { teleport: true },
            },
        })

        await openReviewTab(wrapper)

        expect(wrapper.findAll('[role="tab"]').map(tab => tab.text())).not.toContain('CVSS & SSVC')
        expect(wrapper.get('[data-testid="global-cvss-rescoring"]').isVisible()).toBe(true)
        expect(wrapper.get('[data-testid="global-cvss-rescoring"]').text()).toContain('Applied with the global assessment')

        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        expect(wrapper.find('[data-testid="global-cvss-rescoring"]').exists()).toBe(false)
        expect(wrapper.text()).toContain('Team Assessment: Security')
    })

    it('enables the Save action when the CVSS vector or score changes', async () => {
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
        // All actions live in the sticky bar, not in the form sections.
        expect(decisionSection.find('[data-testid="assessment-submit-button"]').exists()).toBe(false)
        const actions = wrapper.get('[data-vuln-card-sticky-nav] [data-testid="assessment-actions"]')
        const saveButton = actions.get('[data-testid="assessment-submit-button"]')
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
        await wrapper.get('#analysis-details-textarea').setValue('Validated exploitable path')

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
        await wrapper.get('#analysis-details-textarea').setValue('Draft that should remain local')
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

        // Suppression sits in the "More" menu, not on the form.
        expect(wrapper.find('[data-testid="assessment-more-menu"]').exists()).toBe(false)
        await wrapper.get('[data-testid="assessment-more-button"]').trigger('click')
        await wrapper.get('[data-testid="assessment-more-menu"] input[type="checkbox"]').setValue(true)

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
        await wrapper.get('#analysis-details-textarea').setValue('Validated exploitable path')

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
        await wrapper.get('#analysis-details-textarea').setValue('Vulnerable code is not present')

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

        await wrapper.get('#analysis-details-textarea').setValue('False positive mock')
        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
        await flushPromises()

        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Verify updateAssessment was called with the Rescored 0.0 vector in the payload.
        // It should inject [Rescored: 0.0] and the default CVSS 3.1 0-score vector.
        expect(updateAssessment).toHaveBeenCalledWith(expect.objectContaining({
            fields: expect.objectContaining({
                rescored_score: 0,
                rescored_vector: expect.stringContaining('CVSS:3.1'),
            }),
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

        const vectorInput = wrapper.find('#cvss-vector-input')

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

        await wrapper.get('#analysis-details-textarea').setValue('Analyst no rescore')
        const applyBtn = wrapper.get('[data-testid="assessment-submit-button"]')
        await applyBtn.trigger('click')
        await flushPromises()

        const confirmBtn = wrapper.findAll('button').find(b => b.text() === 'Submit')
        await confirmBtn?.trigger('click')
        await flushPromises()

        // Analysts shouldn't inject [Rescored: 0] automatically.
        const calls = (updateAssessment as any).mock.calls
        const lastCallArgs = calls[calls.length - 1][0]

        expect(lastCallArgs.details).toBeUndefined()
        expect(lastCallArgs.fields.rescored_score).toBeNull()
        expect(renderAssessmentFields(lastCallArgs.fields)).not.toContain('[Rescored:')
        expect(lastCallArgs.fields.rescored_vector).toBeNull()
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
        await wrapper.get('#analysis-details-textarea').setValue('Security confirmed exploitable')

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
        expect(wrapper.text()).not.toContain('Suppress')
        await wrapper.get('[data-testid="assessment-more-button"]').trigger('click')
        expect(wrapper.get('[data-testid="assessment-more-menu"]').text()).toContain('Suppress in Dependency-Track')
        expect(wrapper.get('[data-testid="assessment-more-menu"]').text()).toContain('Clear assessment')
    })

    it('lets a reviewer approve a pending assessment in one step', async () => {
        const pending = JSON.parse(JSON.stringify(mockGroup))
        pending.affected_versions[0].components[0].analysis_state = 'NOT_AFFECTED'
        pending.affected_versions[0].components[0].analysis_details =
            '--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: ana] [Justification: CODE_NOT_PRESENT] ---\nThe parser is not shipped.\n\n[Status: Pending Review]'
        const wrapper = mount(VulnGroupCard, {
            props: { group: pending },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'rita' }), teamMapping: ref({}) } },
        })
        // Collapsed, the header button is the way in.
        expect(wrapper.find('[data-testid="assessment-approve-button"]').exists()).toBe(false)
        await wrapper.get('[data-testid="approve-btn"]').trigger('click')
        await flushPromises()

        // It opens the Global assessment with the team decision taken over.
        expect((wrapper.vm as any).activeDetailTab).toBe('review')
        expect((wrapper.vm as any).selectedTeam).toBe('')
        expect((wrapper.vm as any).state).toBe('NOT_AFFECTED')
        expect(wrapper.get('[data-testid="approval-prefilled-note"]').text()).toContain('Nothing is saved until you press Approve')
        expect(updateAssessment).not.toHaveBeenCalled()
        expect(wrapper.find('[data-testid="approve-btn"]').exists()).toBe(false)

        const approve = wrapper.get('[data-vuln-card-sticky-nav] [data-testid="assessment-approve-button"]')
        expect(approve.text()).toBe('Approve')
        await approve.trigger('click')
        await flushPromises()

        expect(updateAssessment).toHaveBeenCalledTimes(1)
        const payload = vi.mocked(updateAssessment).mock.calls[0]![0] as any
        expect(payload.state).toBe('NOT_AFFECTED')
        expect(payload.fields.pending_review).toBeFalsy()
        expect(payload.fields.teams.map((team: any) => team.team).sort()).toEqual(['General', 'Security'])
    })

    it('does not overwrite an existing Global assessment when opening the approval', async () => {
        const pending = JSON.parse(JSON.stringify(mockGroup))
        pending.affected_versions[0].components[0].analysis_state = 'EXPLOITABLE'
        pending.affected_versions[0].components[0].analysis_details =
            '--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] ---\nKept as decided.\n\n'
            + '--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: ana] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.\n\n[Status: Pending Review]'
        const wrapper = mount(VulnGroupCard, {
            props: { group: pending },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'rita' }), teamMapping: ref({}) } },
        })
        await wrapper.get('[data-testid="approve-btn"]').trigger('click')
        await flushPromises()

        expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
        expect(wrapper.find('[data-testid="approval-prefilled-note"]').exists()).toBe(false)
    })

    it('notes findings with different assessments without warning when nothing is inconsistent', async () => {
        const group = JSON.parse(JSON.stringify(mockGroup))
        const first = group.affected_versions[0].components[0]
        first.analysis_state = 'NOT_AFFECTED'
        first.analysis_details = '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
        group.affected_versions.push({
            ...group.affected_versions[0],
            project_version: '2.0',
            project_uuid: 'p2',
            components: [{
                ...first, project_version: '2.0', project_uuid: 'p2', finding_uuid: 'f2',
                // Rescored differently: checked on its own, not an inconsistency.
                analysis_details: '[Rescored: 5.0] [Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L]\n\n--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.',
            }],
        })
        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'rita' }), teamMapping: ref({}) } },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        const banner = wrapper.get('[data-testid="card-differences-banner"]')
        expect(banner.findAll('[data-testid="card-inconsistency-reason"]')).toHaveLength(0)
        expect(banner.attributes('data-inconsistent')).toBe('false')
        expect(banner.text()).toContain('Assessments differ between findings')
        expect(banner.text()).not.toContain('Why this is inconsistent')
        expect(banner.find('[data-testid="card-differences-cleanup"]').exists()).toBe(true)
    })

    it('offers Repair… with its stages when a repair applies, for reviewers only', async () => {
        const api = await import('../../lib/api')
        vi.mocked(api.previewGroupRepair).mockResolvedValue({
            task_id: 'task-1', workflow: {} as any, preview_token: 't', group_fingerprints: {},
            selectable_group_ids: [mockGroup.id],
            items: [{ group_id: mockGroup.id, repairable: true, repairs: [
                { id: 'sync_findings', label: 'Synchronize 1 finding' },
                { id: 'rescoring', label: 'Repair rescoring on 2 findings' },
            ] }],
            topics: [{ id: 'sync_findings', label: 'Synchronize' }, { id: 'rescoring', label: 'Rescoring' }],
            summary: {},
        } as any)
        const group = JSON.parse(JSON.stringify(mockGroup))
        const first = group.affected_versions[0].components[0]
        first.analysis_state = 'NOT_AFFECTED'
        first.analysis_details = '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
        group.affected_versions.push({
            ...group.affected_versions[0], project_version: '2.0', project_uuid: 'p2',
            components: [{ ...first, project_version: '2.0', project_uuid: 'p2', finding_uuid: 'f2', analysis_state: 'EXPLOITABLE',
                analysis_details: '--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] ---\nReachable.' }],
        })
        const mountAs = (role: string) => mount(VulnGroupCard, {
            props: { group },
            global: { provide: { user: ref({ role, username: 'rita' }), teamMapping: ref({}), vulnTaskId: ref('task-1') } },
        })

        const wrapper = mountAs('REVIEWER')
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        expect(api.previewGroupRepair).toHaveBeenCalledWith('task-1', mockGroup.id)
        const repair = wrapper.get('[data-testid="card-differences-repair"]')
        expect(repair.attributes('title')).toBe('Repair Assessments for this vulnerability: Synchronize, Rescoring')
        await wrapper.get('[data-testid="assessment-more-button"]').trigger('click')
        expect(wrapper.get('[data-testid="assessment-repair-button"]').text()).toContain('Synchronize, Rescoring')

        vi.mocked(api.previewGroupRepair).mockClear()
        const analyst = mountAs('ANALYST')
        await analyst.find('.cursor-pointer').trigger('click')
        await flushPromises()
        expect(api.previewGroupRepair).not.toHaveBeenCalled()
        expect(analyst.find('[data-testid="card-differences-repair"]').exists()).toBe(false)
    })

    it('does not count a review note or the order of the team blocks as a different assessment', async () => {
        const group = JSON.parse(JSON.stringify(mockGroup))
        const first = group.affected_versions[0].components[0]
        const general = '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
        const teamA = '--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: ana] [Justification: CODE_NOT_PRESENT] ---\nNot used.'
        const teamB = '--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: ben] [Justification: CODE_NOT_PRESENT] ---\nNot used.'
        first.analysis_state = 'NOT_AFFECTED'
        first.analysis_details = `${general}\n\n${teamA}\n\n${teamB}`
        group.affected_versions.push({
            ...group.affected_versions[0],
            project_version: '2.0',
            project_uuid: 'p2',
            components: [{
                ...first, project_version: '2.0', project_uuid: 'p2', finding_uuid: 'f2',
                analysis_details: `${general.replace(' ---', ' [Version Coverage: 2.0] ---')}\n\n${teamB}\n\n${teamA}`,
            }],
        })
        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'rita' }), teamMapping: ref({}) } },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        expect(wrapper.find('[data-testid="card-differences-banner"]').exists()).toBe(false)
    })

    it('lists the version overrides read-only, with pending approval', async () => {
        const group = JSON.parse(JSON.stringify(mockGroup))
        const first = group.affected_versions[0].components[0]
        first.analysis_state = 'NOT_AFFECTED'
        first.analysis_details = '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
        group.affected_versions.push({
            ...group.affected_versions[0],
            project_version: '2.0',
            project_uuid: 'p2',
            components: [{
                ...first, project_version: '2.0', project_uuid: 'p2', finding_uuid: 'f2',
                analysis_state: 'EXPLOITABLE',
                analysis_details: '[Version Override: legacy] [Override Reason: old build]\n\n--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] ---\nShips it.\n\n[Status: Pending Review]',
            }],
        })
        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'rita' }), teamMapping: ref({}) } },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        expect(wrapper.get('[data-testid="card-version-scope"]').text()).toBe('legacy · 2.0 · pending approval')
        // Differing from base is not a conflict: no inconsistency is reported.
        expect(wrapper.findAll('[data-testid="card-inconsistency-reason"]')).toHaveLength(0)
    })

    it('shows which findings differ, in which fields, and lets a reviewer take one version for all', async () => {
        const group = JSON.parse(JSON.stringify(mockGroup))
        const first = group.affected_versions[0].components[0]
        first.analysis_state = 'NOT_AFFECTED'
        first.analysis_details = '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
        group.affected_versions.push({
            ...group.affected_versions[0],
            project_version: '2.0',
            project_uuid: 'p2',
            components: [
                { ...first, project_version: '2.0', project_uuid: 'p2', finding_uuid: 'f2' },
                {
                    ...first, project_version: '2.0', project_uuid: 'p2', finding_uuid: 'f3',
                    component_name: 'worker', component_uuid: 'c3',
                    analysis_state: 'EXPLOITABLE',
                    analysis_details: '--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] ---\nReachable in the worker.',
                },
            ],
        })
        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'rita' }), teamMapping: ref({}) } },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        const matrix = wrapper.get('[data-testid="finding-matrix"]')
        expect(matrix.get('[data-testid="finding-matrix-summary"]').text()).toBe('2 components · 2 versions')
        // The card says once, above every tab, that findings differ and why.
        expect(matrix.find('[data-testid="finding-differences-banner"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="card-differences-variants"]').text()).toContain('1 of 3')
        const cells = matrix.findAll('[data-testid="finding-matrix-cell"]')
        expect(cells.map(cell => cell.attributes('data-differs'))).toEqual(['false', 'false', 'true'])
        expect(cells[2]!.text()).toContain('Exploitable')

        // On another tab the card says so and leads back to the comparison.
        ;(wrapper.vm as any).setDetailTab('analysis')
        await wrapper.vm.$nextTick()
        const banner = wrapper.get('[data-testid="card-differences-banner"]')
        expect(banner.text()).toContain('2 different assessments')
        expect(wrapper.findAll('[data-testid="card-differences-open"]')).toHaveLength(1)
        expect(banner.findAll('[data-testid="card-inconsistency-reason"]').map(reason => reason.text()).join(' '))
            .toContain('Analysis states differ')
        expect(banner.attributes('data-inconsistent')).toBe('true')
        await wrapper.get('[data-testid="card-differences-open"]').trigger('click')
        await flushPromises()
        expect((wrapper.vm as any).activeDetailTab).toBe('overview')

        const differences = wrapper.get('[data-testid="finding-differences"]')
        const rows = differences.findAll('[data-testid="finding-difference-row"]')
        expect(rows.map(row => row.get('th').text())).toEqual(['State', 'Global · state', 'Global · justification', 'Global · rationale'])
        expect(rows[3]!.text()).toContain('Not shipped.')
        expect(rows[3]!.text()).toContain('Reachable in the worker.')

        await differences.findAll('[data-testid="finding-variant-apply"]')[1]!.trigger('click')
        await flushPromises()
        expect((wrapper.vm as any).activeDetailTab).toBe('review')
        expect((wrapper.vm as any).selectedTeam).toBe('')
        expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
        expect((wrapper.vm as any).details).toBe('Reachable in the worker.')
        expect(updateAssessment).not.toHaveBeenCalled()
    })

    it('does not call teams that decide differently in one finding inconsistent', async () => {
        const group = JSON.parse(JSON.stringify(mockGroup))
        group.affected_versions[0].components[0].analysis_state = 'IN_TRIAGE'
        group.affected_versions[0].components[0].analysis_details =
            '--- [Team: Platform] [State: IN_TRIAGE] [Assessed By: ana] ---\nLooking.\n\n'
            + '--- [Team: Edge] [State: NOT_AFFECTED] [Assessed By: ben] [Justification: CODE_NOT_PRESENT] ---\nNot reachable.'
        const wrapper = mount(VulnGroupCard, { props: { group } })
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        // Teams may disagree: a vulnerability affects components differently.
        // One finding, one assessment: nothing differs between findings either.
        expect((wrapper.vm as any).displayState).not.toBe('INCONSISTENT')
        expect(wrapper.find('[data-testid="card-differences-banner"]').exists()).toBe(false)
    })

    it('does not count a historical record as a team\'s current assessment', async () => {
        const group = JSON.parse(JSON.stringify(mockGroup))
        group.affected_versions[0].components[0].analysis_state = 'NOT_AFFECTED'
        group.affected_versions[0].components[0].analysis_details =
            '--- [Team: Platform] [State: NOT_AFFECTED] [Assessed By: ana] [Date: 1700000000000] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.\n\n'
            + '--- [Team: Platform] [State: EXPLOITABLE] [Assessed By: old] [Date: 1800000000000] [Justification: NOT_SET] [Historical: yes] ---\nAn older owner thought so.\n\n'
            + '--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] [Justification: NOT_SET] [Historical: yes] ---\nOverruled.'
        const wrapper = mount(VulnGroupCard, { props: { group } })
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        const vm = wrapper.vm as any
        // The newer record does not stand in for Platform's current block,
        // and a historical General block is no saved Global decision.
        expect(vm.conflictingTeamStates).toEqual([])
        expect(vm.hasSavedGlobalAssessment).toBe(false)
        expect(vm.teamBlockMeta('Platform')?.state).toBe('NOT_AFFECTED')
        expect(wrapper.find('[data-testid="card-team-states"]').exists()).toBe(false)
    })

    it('marks a suppressed vulnerability in the header', async () => {
        const suppressedGroup = JSON.parse(JSON.stringify(mockGroup))
        suppressedGroup.affected_versions[0].components[0].is_suppressed = true
        const plain = mount(VulnGroupCard, { props: { group: mockGroup } })
        const wrapper = mount(VulnGroupCard, { props: { group: suppressedGroup } })

        expect(plain.find('[data-testid="suppressed-chip"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="suppressed-chip"]').attributes('title'))
            .toContain('1 finding is suppressed in Dependency-Track')
    })

    it('offers an Unassigned team when no component belongs to a team', async () => {
        const untagged = JSON.parse(JSON.stringify({ ...mockGroup, tags: [] }))
        untagged.affected_versions[0].components[0].tags = []
        const wrapper = mount(VulnGroupCard, {
            props: { group: untagged },
            global: { provide: { user: ref({ role: 'ANALYST', username: 'analyst' }), teamMapping: ref({}) } },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        const assessmentTab = wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))
        await assessmentTab?.trigger('click')
        await wrapper.vm.$nextTick()

        expect(wrapper.findAll('[data-testid="review-team-tab"]').map(tab => tab.text())).toEqual(['Unassigned'])
        expect((wrapper.vm as any).selectedTeam).toBe('Unassigned')
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

        // The SSVC rationale is a separate textarea.
        expect((wrapper.get('#analysis-details-textarea').element as HTMLTextAreaElement).value).toBe('Global info')

        // Switch to Security
        ;(wrapper.vm as any).selectedTeam = 'Security'
        await wrapper.vm.$nextTick()

        // Team view
        expect((wrapper.get('#analysis-details-textarea').element as HTMLTextAreaElement).value).toBe('This is urgent')
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

    it('shows one existing assessment when findings differ only in whitespace', async () => {
        // The form used to write a blank line after each block header and a
        // bulk workflow did not: the same assessment in two spellings.
        const header = '--- [Team: General] [State: EXPLOITABLE] [Assessed By: alice] [Date: 1794916578955] [Justification: NOT_SET] ---'
        const fromForm = `[Rescored: 4.0]\n\n${header}\n\nReachable through the parser.\n\n\n[Status: Pending Review]`
        const fromWorkflow = `[Rescored: 4.0]\n\n${header}\nReachable through the parser.\n\n[Status: Pending Review]`
        const component = (suffix: string, details: string, state = 'EXPLOITABLE') => ({
            ...mockComponents[0],
            component_uuid: `c${suffix}`,
            finding_uuid: `f${suffix}`,
            analysis_state: state,
            analysis_details: details,
        })
        const group = {
            ...mockGroup,
            affected_versions: [{
                ...mockGroup.affected_versions[0],
                components: [
                    component('1', fromForm),
                    component('2', fromWorkflow),
                    component('3', fromWorkflow.replace('Reachable', 'Not reachable'), 'NOT_AFFECTED'),
                ],
            }],
        }
        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'tester' }) } },
        })
        await flushPromises()

        const groups = (wrapper.vm as any).groupedAssessments
        expect(groups.map((entry: any) => [entry.state, entry.instances.length])).toEqual([
            ['EXPLOITABLE', 2],
            ['NOT_AFFECTED', 1],
        ])
    })

    it('opens the Assessment tab when Apply in Context · 3 fills the form', async () => {
        const group = JSON.parse(JSON.stringify(mockGroup))
        group.affected_versions[0].components[0].analysis_state = 'NOT_AFFECTED'
        group.affected_versions[0].components[0].analysis_details =
            '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: { provide: { user: ref({ role: 'REVIEWER', username: 'rita' }), teamMapping: ref({}) } },
        })
        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()
        expect((wrapper.vm as any).activeDetailTab).toBe('overview')

        const apply = wrapper.get('[data-testid="vulnerability-assessments"]').findAll('button')
            .find(button => button.text() === 'Apply')
        await apply!.trigger('click')
        await flushPromises()

        expect((wrapper.vm as any).activeDetailTab).toBe('review')
        expect((wrapper.get('#analysis-details-textarea').element as HTMLTextAreaElement).value).toBe('Not shipped.')
    })

    describe('assessment workspace', () => {
        const originalScrollTo = HTMLElement.prototype.scrollTo
        const originalScrollIntoView = HTMLElement.prototype.scrollIntoView
        let scrollTo: ReturnType<typeof vi.fn>
        let scrollIntoView: ReturnType<typeof vi.fn>

        beforeEach(() => {
            scrollTo = vi.fn()
            scrollIntoView = vi.fn()
            HTMLElement.prototype.scrollTo = scrollTo as any
            HTMLElement.prototype.scrollIntoView = scrollIntoView as any
        })

        afterEach(() => {
            HTMLElement.prototype.scrollTo = originalScrollTo
            HTMLElement.prototype.scrollIntoView = originalScrollIntoView
        })

        const assessedGroup = () => {
            const group = JSON.parse(JSON.stringify(mockGroup))
            group.affected_versions[0].components[0].analysis_state = 'NOT_AFFECTED'
            group.affected_versions[0].components[0].analysis_details =
                '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
            return group
        }

        const differingGroup = () => {
            const group = JSON.parse(JSON.stringify(mockGroup))
            const first = group.affected_versions[0].components[0]
            first.analysis_state = 'NOT_AFFECTED'
            first.analysis_details = '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.'
            group.affected_versions.push({
                ...group.affected_versions[0],
                project_version: '2.0',
                project_uuid: 'p2',
                components: [
                    { ...first, project_version: '2.0', project_uuid: 'p2', finding_uuid: 'f2' },
                    {
                    ...first, project_version: '2.0', project_uuid: 'p2', finding_uuid: 'f3',
                    component_name: 'worker', component_uuid: 'c3',
                    analysis_state: 'EXPLOITABLE',
                    analysis_details: '--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] ---\nReachable in the worker.',
                    },
                ],
            })
            return group
        }

        const pendingGroup = () => {
            const pending = JSON.parse(JSON.stringify(mockGroup))
            pending.affected_versions[0].components[0].analysis_state = 'NOT_AFFECTED'
            pending.affected_versions[0].components[0].analysis_details =
                '--- [Team: Security] [State: NOT_AFFECTED] [Assessed By: ana] [Justification: CODE_NOT_PRESENT] ---\nThe parser is not shipped.\n\n[Status: Pending Review]'
            return pending
        }

        const mountCard = async (options: {
            group?: any
            role?: string
            workspace?: boolean
            inModal?: boolean
            workspaceAvailable?: boolean
            activeTeamFilter?: string
            teamMapping?: Record<string, string[]>
        } = {}) => {
            const wrapper = mount(VulnGroupCard, {
                props: {
                    group: options.group ?? mockGroup,
                    inModal: options.inModal ?? true,
                    workspace: options.workspace ?? true,
                    workspaceAvailable: options.workspaceAvailable ?? true,
                    ...(options.activeTeamFilter ? { activeTeamFilter: options.activeTeamFilter } : {}),
                },
                global: {
                    provide: {
                        user: ref({ role: options.role ?? 'ANALYST', username: 'rita' }),
                        teamMapping: ref(options.teamMapping ?? {}),
                    },
                    stubs: { teleport: true },
                },
            })
            await flushPromises()
            return wrapper
        }

        const tabLabels = (wrapper: ReturnType<typeof mount>) =>
            wrapper.findAll('[role="tab"]').map(tab => tab.text())
        const contextPane = (wrapper: ReturnType<typeof mount>) => wrapper.get('[data-testid="workspace-context-pane"]')
        const assessmentPane = (wrapper: ReturnType<typeof mount>) => wrapper.get('[data-testid="workspace-assessment-pane"]')
        const decisionSection = (wrapper: ReturnType<typeof mount>) => wrapper.get('[data-testid="assessment-decision-section"]')
        const scrolledIntoView = () => scrollIntoView.mock.contexts as HTMLElement[]
        // v-show hides the review section with an inline display: none.
        const panelShown = (wrapper: ReturnType<typeof mount>, panel: string) =>
            !(wrapper.get(`#vuln-${mockGroup.id}-detail-panel-${panel}`).attributes('style') || '').includes('display: none')
        const reviewShown = (wrapper: ReturnType<typeof mount>) => panelShown(wrapper, 'review')

        it('shows the context and the assessment form side by side', async () => {
            const wrapper = await mountCard()

            const tabs = tabLabels(wrapper)
            expect(tabs).toHaveLength(2)
            expect(tabs[0]).toContain('Context')
            expect(tabs[1]).toContain('Code Evidence')
            expect(contextPane(wrapper).find('[data-testid="vuln-description"]').exists()).toBe(true)
            expect(contextPane(wrapper).find('[data-testid="where-found"]').exists()).toBe(true)
            expect(assessmentPane(wrapper).find('[data-testid="assessment-decision-section"]').exists()).toBe(true)
            expect(panelShown(wrapper, 'overview')).toBe(true)
            expect(reviewShown(wrapper)).toBe(true)
            expect(wrapper.get('[data-testid="workspace-assessment-heading"]').text()).toContain('Assessment')
            expect(wrapper.get(`#vuln-${mockGroup.id}-detail-panel-review`).attributes('role')).toBe('region')
            // The one-time instruction is a tooltip on the heading.
            expect(wrapper.get('[data-testid="workspace-assessment-heading"]').attributes('title'))
                .toBe('The context is on the left; save with the action bar above.')
            expect(wrapper.get('[data-testid="vulnerability-assessments"]').text()).not.toContain('Assessment tab')
        })

        it('folds the vulnerability summary in the workspace, where the context shows the description', async () => {
            const wrapper = await mountCard()

            const about = assessmentPane(wrapper).get('[data-testid="vuln-about"]')
            const toggle = about.get('[data-testid="vuln-about-toggle"]')
            expect(toggle.attributes('aria-expanded')).toBe('false')
            expect(about.text()).toContain('Test Vulnerability')
            expect(about.find('[data-testid="vuln-about-description"]').exists()).toBe(false)
            await toggle.trigger('click')
            expect(about.get('[data-testid="vuln-about-description"]').text()).toBe('A bad vulnerability')

            // Back in tab mode it is open again.
            await wrapper.setProps({ workspace: false })
            expect(wrapper.get('[data-testid="vuln-about-toggle"]').attributes('aria-expanded')).toBe('true')
        })

        it('keeps tab mode as it was when the workspace is closed', async () => {
            const wrapper = await mountCard({ workspace: false })

            expect(tabLabels(wrapper)).toHaveLength(3)
            for (const testid of ['workspace-columns', 'workspace-context-pane', 'workspace-assessment-pane']) {
                expect(wrapper.get(`[data-testid="${testid}"]`).classes()).toEqual(['contents'])
            }
            expect(wrapper.find('[data-testid="workspace-assessment-heading"]').exists()).toBe(false)
            expect((wrapper.vm as any).activeDetailTab).toBe('overview')
            expect(reviewShown(wrapper)).toBe(false)
            expect(wrapper.get(`#vuln-${mockGroup.id}-detail-panel-review`).attributes('role')).toBe('tabpanel')
        })

        it('fills the form from Apply in Context · 3 and keeps the context in view', async () => {
            const wrapper = await mountCard({ group: assessedGroup(), role: 'REVIEWER' })

            const apply = wrapper.get('[data-testid="vulnerability-assessments"]').findAll('button')
                .find(button => button.text() === 'Apply')
            await apply!.trigger('click')
            await flushPromises()

            expect((wrapper.get('#analysis-details-textarea').element as HTMLTextAreaElement).value).toBe('Not shipped.')
            expect((wrapper.vm as any).activeDetailTab).toBe('overview')
            expect(scrolledIntoView()).toContain(decisionSection(wrapper).element)
            expect(decisionSection(wrapper).classes()).toContain('ring-2')
        })

        it('takes one finding variant into the form without scrolling the context pane', async () => {
            const wrapper = await mountCard({ group: differingGroup(), role: 'REVIEWER' })

            await wrapper.get('[data-testid="card-differences-open"]').trigger('click')
            await flushPromises()
            scrollTo.mockClear()
            scrollIntoView.mockClear()

            await wrapper.get('[data-testid="finding-differences"]').findAll('[data-testid="finding-variant-apply"]')[1]!.trigger('click')
            await flushPromises()

            expect((wrapper.vm as any).activeDetailTab).toBe('overview')
            expect((wrapper.vm as any).details).toBe('Reachable in the worker.')
            expect(scrolledIntoView()).toContain(decisionSection(wrapper).element)
            expect(scrollTo.mock.contexts).not.toContain(contextPane(wrapper).element)
        })

        it('keeps Code Evidence open when an analyzer result fills the form', async () => {
            const wrapper = await mountCard({ teamMapping: { lib: ['Security'] } })
            await wrapper.findAll('[role="tab"]').find(tab => tab.text().includes('Code Evidence'))!.trigger('click')
            expect((wrapper.vm as any).activeDetailTab).toBe('analysis')

            wrapper.getComponent(CodeAnalysisPanel).vm.$emit(
                'apply-result',
                analyzerResult('Not Affected', 'No vulnerable code path was found.', 'The parser is not shipped.'),
                ['lib'],
                ['run-1'],
                'Security',
            )
            await flushPromises()

            expect((wrapper.vm as any).activeDetailTab).toBe('analysis')
            expect((wrapper.vm as any).details).toContain('No vulnerable code path was found.')
            expect(assessmentPane(wrapper).find('[data-testid="code-analysis-draft-banner"]').exists()).toBe(true)
            expect(reviewShown(wrapper)).toBe(true)
            expect(panelShown(wrapper, 'analysis')).toBe(true)
            expect(scrolledIntoView()).toContain(decisionSection(wrapper).element)
        })

        it('shows the differences in the context pane and keeps the form visible', async () => {
            const wrapper = await mountCard({ group: differingGroup(), role: 'REVIEWER' })

            expect(contextPane(wrapper).find('[data-testid="card-differences-banner"]').exists()).toBe(true)
            await wrapper.get('[data-testid="card-differences-open"]').trigger('click')
            await flushPromises()

            expect(contextPane(wrapper).find('[data-testid="finding-differences"]').exists()).toBe(true)
            expect(reviewShown(wrapper)).toBe(true)
        })

        it('approves the Global form in place and leads from a team to the Global form', async () => {
            const wrapper = await mountCard({ group: pendingGroup(), role: 'REVIEWER' })

            expect((wrapper.vm as any).activeDetailTab).toBe('overview')
            expect((wrapper.vm as any).selectedTeam).toBe('')
            const approve = () => wrapper.get('[data-vuln-card-sticky-nav] [data-testid="assessment-approve-button"]')
            expect(approve().text()).toBe('Approve')

            ;(wrapper.vm as any).selectedTeam = 'Security'
            await flushPromises()
            expect(approve().text()).toBe('Review & approve')
            await approve().trigger('click')
            await flushPromises()
            expect((wrapper.vm as any).selectedTeam).toBe('')
            expect((wrapper.vm as any).activeDetailTab).toBe('overview')
            expect(approve().text()).toBe('Approve')

            await approve().trigger('click')
            await flushPromises()
            expect(updateAssessment).toHaveBeenCalledTimes(1)
            const payload = vi.mocked(updateAssessment).mock.calls[0]![0] as any
            expect(payload.state).toBe('NOT_AFFECTED')
            expect(payload.fields.pending_review).toBeFalsy()
            // The approval is said in so many words; the server asks for it.
            expect(payload.approve).toBe(true)
        })

        it('saves a reviewer\'s change to a pending assessment without approving it', async () => {
            const wrapper = await mountCard({ group: pendingGroup(), role: 'REVIEWER' })

            const save = wrapper.get('[data-vuln-card-sticky-nav] [data-testid="assessment-submit-button"]')
            expect(save.attributes('title')).toContain('stays pending review until you approve')
            const saving = (wrapper.vm as any).handleUpdate(false)
            await flushPromises()
            ;(wrapper.vm as any).handleReviewConfirm()
            await saving

            expect(updateAssessment).toHaveBeenCalledTimes(1)
            const payload = vi.mocked(updateAssessment).mock.calls[0]![0] as any
            expect(payload.approve).toBeUndefined()
            expect(payload.fields.pending_review).toBe(true)
        })

        it('activates the SSVC evidence while the form is visible', async () => {
            const workspace = await mountCard({ role: 'REVIEWER' })
            expect((workspace.vm as any).activeDetailTab).toBe('overview')
            expect(workspace.getComponent(SsvcCalculator).props('active')).toBe(true)

            const tabs = await mountCard({ role: 'REVIEWER', workspace: false })
            expect((tabs.vm as any).activeDetailTab).toBe('overview')
            expect(tabs.getComponent(SsvcCalculator).props('active')).toBe(false)
        })

        it('preselects the scoped team on entry and keeps a team chosen on the form', async () => {
            const scoped = await mountCard({
                workspace: false,
                activeTeamFilter: 'Security',
                teamMapping: { lib: ['Security'] },
            })
            ;(scoped.vm as any).selectedTeam = ''
            await flushPromises()
            await scoped.setProps({ workspace: true })
            await flushPromises()
            expect((scoped.vm as any).selectedTeam).toBe('Security')
            expect((scoped.vm as any).activeDetailTab).toBe('overview')

            const chosen = await mountCard({
                role: 'REVIEWER',
                workspace: false,
                activeTeamFilter: 'Security',
                teamMapping: { lib: ['Security'] },
            })
            await chosen.findAll('[role="tab"]').find(tab => tab.text().includes('Assessment'))!.trigger('click')
            expect((chosen.vm as any).selectedTeam).toBe('Security')
            ;(chosen.vm as any).selectedTeam = ''
            await flushPromises()
            await chosen.setProps({ workspace: true })
            await flushPromises()
            expect((chosen.vm as any).selectedTeam).toBe('')
            expect((chosen.vm as any).activeDetailTab).toBe('overview')
        })

        it('returns to the scoped team after a save, as on the Assessment tab', async () => {
            const wrapper = await mountCard({
                role: 'REVIEWER',
                activeTeamFilter: 'Security',
                teamMapping: { lib: ['Security'] },
            })
            expect((wrapper.vm as any).selectedTeam).toBe('Security')
            // The reviewer edits the Global form, then a save clears the draft.
            ;(wrapper.vm as any).selectedTeam = ''
            await flushPromises()
            ;(wrapper.vm as any).formTouched = true
            await flushPromises()
            expect((wrapper.vm as any).selectedTeam).toBe('')
            ;(wrapper.vm as any).formTouched = false
            await flushPromises()

            expect((wrapper.vm as any).selectedTeam).toBe('Security')
        })

        it.each([
            ['evidence Apply', (vm: any) => vm.onEvidenceApplyAll('GLOBAL TEXT', 'NOT_AFFECTED', 'CODE_NOT_PRESENT')],
            ['evidence Adopt', (vm: any) => vm.onEvidenceAdoptTeam({
                team: 'Runtime', state: 'NOT_AFFECTED', justification: 'CODE_NOT_PRESENT', details: 'GLOBAL TEXT',
            })],
            ['Use for all findings', (vm: any) => vm.applyFindingVariant('GLOBAL TEXT', 'NOT_AFFECTED')],
        ])('fills the Global form, not the scoped team draft, on %s', async (_label, apply) => {
            const wrapper = await mountCard({
                activeTeamFilter: 'Security',
                teamMapping: { lib: ['Security'] },
            })
            const vm = wrapper.vm as any
            expect(vm.selectedTeam).toBe('Security')
            await wrapper.get('#analysis-details-textarea').setValue('SEC EDIT')
            await flushPromises()
            expect(vm.formTouched).toBe(true)

            await apply(vm)
            await flushPromises()

            expect(vm.selectedTeam).toBe('')
            expect(vm.details).toBe('GLOBAL TEXT')
            expect(vm.teamDrafts.get('Security').details).toBe('SEC EDIT')
        })

        it('lands on the Assessment tab with every edit kept when the workspace closes', async () => {
            const wrapper = await mountCard({ role: 'REVIEWER' })
            ;(wrapper.vm as any).state = 'EXPLOITABLE'
            await wrapper.get('#analysis-details-textarea').setValue('Reachable through the parser.')
            ;(wrapper.vm as any).teamDrafts.set('Security', {
                state: 'IN_TRIAGE', details: 'Team draft', justification: 'NOT_SET', assigned: [],
                evidenceReviewed: false, versionCoverageChecked: false, ticket: '',
            })
            await flushPromises()
            expect((wrapper.vm as any).formTouched).toBe(true)

            await wrapper.setProps({ workspace: false })
            await flushPromises()

            expect((wrapper.vm as any).activeDetailTab).toBe('review')
            expect(tabLabels(wrapper)).toHaveLength(3)
            expect((wrapper.vm as any).details).toBe('Reachable through the parser.')
            expect((wrapper.vm as any).state).toBe('EXPLOITABLE')
            expect((wrapper.vm as any).formTouched).toBe(true)
            expect((wrapper.vm as any).teamDrafts.get('Security').details).toBe('Team draft')
            expect(reviewShown(wrapper)).toBe(true)
        })

        it('still asks about an unsaved edit when the details close', async () => {
            const wrapper = await mountCard()
            await wrapper.get('#analysis-details-textarea').setValue('Unsaved local explanation')
            await flushPromises()

            await wrapper.get('button[title="Close details"]').trigger('click')
            await flushPromises()

            expect(wrapper.text()).toContain('Submit this assessment before leaving?')
            expect(wrapper.emitted('close')).toBeUndefined()
        })

        it('offers the workspace toggle only in the inspector on a wide viewport', async () => {
            const open = await mountCard()
            const toggle = open.get('[data-testid="workspace-toggle"]')
            expect(toggle.attributes('aria-pressed')).toBe('true')
            expect(toggle.attributes('aria-label')).toBe('Leave assessment workspace')
            await toggle.trigger('click')
            expect(open.emitted('toggle-workspace')).toHaveLength(1)
            expect(open.emitted('close')).toBeUndefined()

            const closed = await mountCard({ workspace: false })
            expect(closed.get('[data-testid="workspace-toggle"]').attributes('aria-pressed')).toBe('false')
            expect(closed.get('[data-testid="workspace-toggle"]').attributes('aria-label')).toBe('Open assessment workspace')

            const narrow = await mountCard({ workspace: false, workspaceAvailable: false })
            expect(narrow.find('[data-testid="workspace-toggle"]').exists()).toBe(false)

            const listCard = await mountCard({ inModal: false, workspace: false })
            await listCard.find('.cursor-pointer').trigger('click')
            expect(listCard.find('[data-testid="workspace-toggle"]').exists()).toBe(false)
        })

        it('ignores the workspace outside the inspector', async () => {
            const wrapper = await mountCard({ inModal: false })
            await wrapper.find('.cursor-pointer').trigger('click')

            expect(tabLabels(wrapper)).toHaveLength(3)
            expect(wrapper.get('[data-testid="workspace-columns"]').classes()).toEqual(['contents'])
            expect(wrapper.find('[data-testid="workspace-assessment-heading"]').exists()).toBe(false)
        })

        it('stacks the reviewer Global form in the narrower assessment pane', async () => {
            const workspace = await mountCard({ role: 'REVIEWER' })
            const workspaceGrid = workspace.get('[data-testid="global-cvss-rescoring"]').element.parentElement!
            expect(workspaceGrid.className).toContain('grid')
            expect(workspaceGrid.className).not.toContain('xl:grid-cols-2')

            const tabs = await mountCard({ role: 'REVIEWER', workspace: false })
            expect(tabs.get('[data-testid="global-cvss-rescoring"]').element.parentElement!.className).toContain('xl:grid-cols-2')
        })

        it.each([
            ['tab mode', false],
            ['workspace', true],
        ])('keeps every action in the sticky bar in %s', async (_label, workspace) => {
            const wrapper = await mountCard({ group: pendingGroup(), role: 'REVIEWER', workspace })
            const actions = '[data-vuln-card-sticky-nav] [data-testid="assessment-actions"]'

            expect(wrapper.findAll('[data-testid="assessment-submit-button"]')).toHaveLength(1)
            expect(wrapper.findAll(`${actions} [data-testid="assessment-submit-button"]`)).toHaveLength(1)
            expect(wrapper.findAll('[data-testid="assessment-approve-button"]')).toHaveLength(1)
            expect(wrapper.findAll(`${actions} [data-testid="assessment-approve-button"]`)).toHaveLength(1)
            expect(wrapper.findAll(`${actions} [data-testid="assessment-more-button"]`)).toHaveLength(1)
        })

        it('reports each open modal and the More menu as an open overlay', async () => {
            const wrapper = await mountCard({ role: 'REVIEWER' })
            const vm = wrapper.vm as any
            expect(vm.hasOpenOverlay()).toBe(false)

            const overlays: Array<[string, () => void, () => void]> = [
                ['generic modal', () => { vm.genericModal.show = true }, () => { vm.genericModal.show = false }],
                ['conflict modal', () => { vm.showConflictModal = true }, () => { vm.showConflictModal = false }],
                ['calculator modal', () => { vm.showCalculatorModal = true }, () => { vm.showCalculatorModal = false }],
                ['clear modal', () => { vm.showClearModal = true }, () => { vm.showClearModal = false }],
                ['review modal', () => { vm.reviewModal.show = true }, () => { vm.reviewModal.show = false }],
                ['more menu', () => { vm.showMoreMenu = true }, () => { vm.showMoreMenu = false }],
            ]
            for (const [label, open, close] of overlays) {
                open()
                expect(vm.hasOpenOverlay(), label).toBe(true)
                close()
                expect(vm.hasOpenOverlay(), label).toBe(false)
            }
        })

        it('closes the More menu with the first Esc in the workspace only', async () => {
            const workspace = await mountCard({ role: 'REVIEWER' })
            ;(workspace.vm as any).showMoreMenu = true
            globalThis.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
            expect((workspace.vm as any).showMoreMenu).toBe(false)
            workspace.unmount()

            const tabs = await mountCard({ role: 'REVIEWER', workspace: false })
            ;(tabs.vm as any).showMoreMenu = true
            globalThis.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
            expect((tabs.vm as any).showMoreMenu).toBe(true)
            tabs.unmount()
        })
    })
})
