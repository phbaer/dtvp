import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCardHeader from '../VulnGroupCardHeader.vue'

vi.mock('lucide-vue-next', async (importOriginal) => {
    const actual = await importOriginal() as any
    return {
        ...actual,
        ChevronDown: { template: '<span class="icon-down" />' },
        ChevronUp: { template: '<span class="icon-up" />' },
        CheckCircle: { template: '<span class="icon-check" />' },
        AlertTriangle: { template: '<span class="icon-alert" />' },
        CircleDot: { template: '<span class="icon-circle" />' },
        Search: { template: '<span class="icon-search" />' },
        ShieldCheck: { template: '<span class="icon-shield-check" />' },
        ShieldOff: { template: '<span class="icon-shield-off" />' },
        Bug: { template: '<span class="icon-bug" />' },
        GitBranch: { template: '<span class="icon-branch" />' },
        Layers: { template: '<span class="icon-layers" />' },
        Eye: { template: '<span class="icon-eye" />' },
        Package: { template: '<span class="icon-package" />' },
        User: { template: '<span class="icon-user" />' },
    }
})

const baseGroup = {
    id: 'CVE-2023-1234',
    cvss: 9.8,
    affected_versions: [
        {
            project_name: 'App1',
            project_version: '1.0',
            project_uuid: 'p1',
            components: [
                {
                    project_name: 'App1',
                    project_version: '1.0',
                    project_uuid: 'p1',
                    component_name: 'lib-one',
                    component_version: '1.0',
                    component_uuid: 'c1',
                    vulnerability_uuid: 'v1',
                    finding_uuid: 'f1',
                    analysis_state: 'NOT_SET',
                    is_suppressed: false,
                    tags: ['Security'],
                },
                {
                    project_name: 'App1',
                    project_version: '1.0',
                    project_uuid: 'p1',
                    component_name: 'lib-two',
                    component_version: '1.1',
                    component_uuid: 'c2',
                    vulnerability_uuid: 'v2',
                    finding_uuid: 'f2',
                    analysis_state: 'NOT_SET',
                    is_suppressed: false,
                    tags: ['App'],
                }
            ]
        }
    ]
}

const mountHeader = (overrides: Record<string, unknown> = {}) => mount(VulnGroupCardHeader, {
    props: {
        group: baseGroup as any,
        displayState: 'INCOMPLETE',
        technicalState: 'EXPLOITABLE',
        isRescoredOrModified: false,
        currentDisplayScore: 9.8,
        pendingScore: null,
        stableRescoredScore: null,
        hasStableRescore: false,
        normalizedTags: ['Security', 'App'],
        assessedTeams: new Set(['Security']),
        expanded: false,
        canApprove: true,
        isPendingReview: true,
        dependencyRelationship: 'DIRECT',
        assignees: ['alice'],
        codeAnalysisStatus: 'available',
        ...overrides,
    }
})

describe('VulnGroupCardHeader', () => {
    it('uses a 4-column grid layout with top-aligned content', () => {
        const wrapper = mountHeader()

        const grid = wrapper.get('[data-testid="header-grid"]')
        expect(grid.classes()).toContain('grid')
        expect(grid.classes()).toContain('items-start')
        expect(grid.attributes('style')).toContain('grid-template-columns: 12rem minmax(min-content, 1fr) 8rem 8rem 6rem 1.5rem')

        const scoreBlock = wrapper.get('[data-testid="header-cvss-block"]')
        expect(scoreBlock.classes()).toContain('items-start')
    })

    it('splits lifecycle and assessment into separate left-aligned columns', () => {
        const wrapper = mountHeader()

        const lifecycleColumn = wrapper.get('[data-testid="lifecycle-column"]')
        const analysisColumn = wrapper.get('[data-testid="analysis-column"]')
        const statusChips = wrapper.get('[data-testid="status-chips"]')

        expect(lifecycleColumn.classes()).toContain('flex-col')
        expect(lifecycleColumn.classes()).toContain('items-start')
        expect(analysisColumn.classes()).toContain('flex-col')
        expect(analysisColumn.classes()).toContain('items-start')
        expect(statusChips.classes()).toContain('flex-wrap')
    })

    it('shows a placeholder analysis chip for open lifecycle rows', () => {
        const wrapper = mountHeader({ technicalState: 'NOT_SET', displayState: 'OPEN' })

        expect(wrapper.get('[data-testid="analysis-state-badge"]').text()).toContain('Not Set')
        expect(wrapper.get('[data-testid="analysis-state-icon-slot"]').classes()).toContain('w-[9px]')

        const lifecycleColumnClassName = wrapper.get('[data-testid="lifecycle-column"]').attributes('class')
        const analysisColumnClassName = wrapper.get('[data-testid="analysis-column"]').attributes('class')
        expect(lifecycleColumnClassName).toContain('items-start')
        expect(lifecycleColumnClassName).toContain('text-left')
        expect(analysisColumnClassName).toContain('items-start')
        expect(analysisColumnClassName).toContain('text-left')
    })

    it('renders lifecycle and analysis as separate rounded chips', () => {
        const wrapper = mountHeader()

        expect(wrapper.get('[data-testid="lifecycle-column-inner"]').classes()).toContain('flex-wrap')
        expect(wrapper.get('[data-testid="analysis-column-inner"]').classes()).toContain('flex-wrap')
        expect(wrapper.get('[data-testid="lifecycle-badge"]').classes()).toContain('rounded')
        expect(wrapper.get('[data-testid="lifecycle-badge"]').classes()).not.toContain('rounded-l')
        expect(wrapper.get('[data-testid="analysis-state-badge"]').classes()).toContain('rounded')
        expect(wrapper.get('[data-testid="analysis-state-badge"]').classes()).not.toContain('rounded-r')
        expect(wrapper.get('[data-testid="analysis-state-icon-slot"]').classes()).toContain('w-[9px]')
    })

    it('renders icon-only status chips', () => {
        const wrapper = mountHeader({ canApprove: false })

        expect(wrapper.get('[data-testid="code-analysis-status-badge"]').classes()).toContain('h-5')
        expect(wrapper.get('[data-testid="code-analysis-status-badge"]').classes()).toContain('w-5')
        expect(wrapper.get('[data-testid="dep-badge"]').classes()).toContain('h-5')
        expect(wrapper.get('[data-testid="dep-badge"]').classes()).toContain('w-5')
        expect(wrapper.get('[data-testid="instance-count"]').classes()).toContain('h-5')
    })

    it('renders the compact approval button with an accessible label', () => {
        const wrapper = mountHeader()

        const approveButton = wrapper.get('[data-testid="approve-btn"]')

        expect(approveButton.attributes('aria-label')).toBe('Approve assessment')
        expect(approveButton.classes()).toContain('h-6')
        expect(approveButton.classes()).toContain('w-6')
    })
})