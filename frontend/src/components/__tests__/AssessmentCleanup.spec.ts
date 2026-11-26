import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'
import ClearAssessmentModal from '../ClearAssessmentModal.vue'
import * as api from '../../lib/api'
import { activeTeams, assessedTeamsOf, cleanupChanges, cleanupVersions, teamStatus } from '../../lib/assessmentCleanup'
import { buildFindingMatrix, compareVariants } from '../../lib/findingMatrix'

vi.mock('../../lib/api', () => ({
    previewAssessmentCleanup: vi.fn(),
    applyAssessmentCleanup: vi.fn(),
}))

// The texts of a real vulnerability, anonymised: three of twelve findings
// came later and never got the SSVC record the reviewer had recorded.
const RECORD = JSON.stringify({
    model: 'ssvc:DT_DP', version: '1.0.0', answers: { 'ssvc:E:1.1.0': 'A' }, rationale: '',
    outcome: null, evidence: null, assessor: 'reviewer-1', assessed_at: '2026-11-11T11:00:29+00:00', priority: 'Incomplete',
}, null, 2)
const GENERAL = '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: analyst-1] [Date: 1795535973530] [Justification: CODE_NOT_REACHABLE] ---'
const TEAM = '--- [Team: Identity] [State: NOT_AFFECTED] [Assessed By: analyst-4] [Date: 1795530016568] [Justification: CODE_NOT_REACHABLE] ---\nRequest decompression is disabled.'
const WITHOUT_SSVC = `${GENERAL}\n\n${TEAM}\n\n[Status: Pending Review]`
const WITH_SSVC = `${GENERAL.replace(' ---', ' [SSVC: INCOMPLETE] ---')}\n[SSVC Summary]\nSSVC priority: Incomplete\n[/SSVC Summary]\n\n[SSVC Details]\n${RECORD}\n[/SSVC Details]\n\n${TEAM}\n\n[Status: Pending Review]`

const finding = (version: string, component: string, details: string, extra: Record<string, unknown> = {}) => ({
    project_version: version,
    project_uuid: `p-${version}`,
    component_name: component,
    component_version: '1.1.0',
    component_uuid: `c-${component}`,
    vulnerability_uuid: 'v-1',
    finding_uuid: `f-${version}-${component}`,
    analysis_state: 'NOT_AFFECTED',
    analysis_details: details,
    is_suppressed: false,
    ...extra,
}) as any

const FINDINGS = [
    finding('7.1.0', 'brotli', WITH_SSVC),
    finding('7.2.0', 'brotli', WITH_SSVC),
    finding('7.1.1', 'brotli', WITHOUT_SSVC),
]

describe('assessment cleanup', () => {
    it('shows the SSVC record as the field in which the versions differ', () => {
        const rows = compareVariants(buildFindingMatrix(FINDINGS).variants).filter(row => row.differs)

        expect(rows.map(row => [row.label, row.values])).toEqual([
            ['Global · SSVC', ['Incomplete · recorded by reviewer-1 on 2026-11-11', '']],
        ])
    })

    it('lists the versions of the assessment, the most common first, with their teams and differences', () => {
        const versions = cleanupVersions(FINDINGS)

        expect(versions.map(version => [version.variant.label, version.variant.instances.length])).toEqual([['A', 2], ['B', 1]])
        expect(versions[0]!.teams).toEqual(['General', 'Identity'])
        expect(versions[1]!.differences).toEqual([{ key: 'team:General:ssvc', label: 'Global · SSVC', value: '' }])
        expect(assessedTeamsOf([finding('1', 'x', TEAM), ...FINDINGS])).toEqual(['General', 'Identity'])
        expect(activeTeams(`${TEAM}\n\n--- [Team: Former] [State: EXPLOITABLE] [Historical: yes] ---\nOld.`)).toEqual(['Identity'])
    })

    it('names teams the mapping does not know, or only as an alias', () => {
        const mapping = { 'org.example:*': ['Identity', 'ID'], '*': 'Platform' }

        expect(teamStatus('Identity', mapping)).toBeNull()
        expect(teamStatus('platform', mapping)).toBeNull()
        expect(teamStatus('ID', mapping)).toBe('alias')
        expect(teamStatus('Retired', mapping)).toBe('unknown')
        expect(teamStatus('General', mapping)).toBeNull()
        expect(teamStatus('Retired', {})).toBeNull()
    })

    it('says what a cleanup changes on a finding', () => {
        const before = { state: 'NOT_AFFECTED', details: WITHOUT_SSVC, suppressed: false }

        expect(cleanupChanges(before, { ...before, details: WITH_SSVC })).toEqual(['Global · SSVC'])
        expect(cleanupChanges(before, { state: 'NOT_SET', details: '', suppressed: false })).toEqual(['Whole assessment removed'])
        expect(cleanupChanges(before, { ...before, details: `${GENERAL}\n\n[Status: Pending Review]` })).toEqual(['Identity assessment removed'])
        expect(cleanupChanges(before, { ...before, details: GENERAL })).toEqual(['Identity assessment removed', 'Pending review'])
        expect(cleanupChanges(before, null)).toEqual([])
    })
})

describe('ClearAssessmentModal in cleanup mode', () => {
    beforeEach(() => {
        vi.mocked(api.previewAssessmentCleanup).mockReset()
        vi.mocked(api.applyAssessmentCleanup).mockReset()
    })

    const mountModal = (props: Record<string, unknown> = {}) => mount(ClearAssessmentModal, {
        props: {
            show: true, mode: 'cleanup', team: '', assessedTeams: ['General', 'Identity'], isReviewer: true,
            findingCount: FINDINGS.length, instances: FINDINGS, ...props,
        },
        global: { stubs: { teleport: true }, provide: { teamMapping: ref({ '*': ['Identity'] }) } },
    })

    const preview = (changed: boolean) => [
        {
            finding_uuid: 'f-7.1.1-brotli', project_uuid: 'p-7.1.1', component_uuid: 'c-brotli', vulnerability_uuid: 'v-1',
            revision: 6, source_revision: 18, changed,
            before: { state: 'NOT_AFFECTED', details: WITHOUT_SSVC, suppressed: false },
            after: changed ? { state: 'NOT_AFFECTED', details: WITH_SSVC, suppressed: false } : null,
        },
    ]

    it('keeps the most common version for the findings that differ, previews and saves what it previewed', async () => {
        vi.mocked(api.previewAssessmentCleanup).mockResolvedValue(preview(true))
        vi.mocked(api.applyAssessmentCleanup).mockResolvedValue([])
        const wrapper = mountModal()

        expect(wrapper.findAll('[data-testid="cleanup-version"]')).toHaveLength(2)
        expect(wrapper.get('[data-testid="cleanup-version"]').text()).toContain('Global · SSVC')
        const boxes = wrapper.findAll('[data-testid="cleanup-finding"] input[type="checkbox"]')
        expect(boxes.map(box => (box.element as HTMLInputElement).checked)).toEqual([false, false, true])
        expect(wrapper.get('[data-testid="cleanup-confirm"]').attributes('disabled')).toBeDefined()

        await wrapper.get('[data-testid="cleanup-preview-button"]').trigger('click')
        await flushPromises()

        const request = vi.mocked(api.previewAssessmentCleanup).mock.calls[0]![0]
        expect(request).toMatchObject({
            action: 'apply', team: null,
            source: { project_uuid: 'p-7.1.0', component_uuid: 'c-brotli', vulnerability_uuid: 'v-1' },
        })
        expect(request.instances.map((instance: any) => instance.finding_uuid)).toEqual(['f-7.1.1-brotli'])
        expect(wrapper.get('[data-testid="cleanup-preview-row"]').text()).toContain('7.1.1 · brotli 1.1.0')
        expect(wrapper.get('[data-testid="cleanup-preview-row"]').text()).toContain('Global · SSVC')

        await wrapper.get('[data-testid="cleanup-confirm"]').trigger('click')
        await flushPromises()

        expect(vi.mocked(api.applyAssessmentCleanup).mock.calls[0]![0].revisions).toEqual({
            'p-7.1.1|c-brotli|v-1': 6,
            'p-7.1.0|c-brotli|v-1': 18,
        })
        expect(wrapper.emitted('cleaned')).toHaveLength(1)
    })

    it('needs a new preview after the selection changes, and reports a change in between', async () => {
        vi.mocked(api.previewAssessmentCleanup).mockResolvedValue(preview(true))
        vi.mocked(api.applyAssessmentCleanup).mockRejectedValue({ response: { status: 409 } })
        const wrapper = mountModal()

        await wrapper.get('[data-testid="cleanup-preview-button"]').trigger('click')
        await flushPromises()
        await wrapper.get('[data-testid="cleanup-select-all"]').trigger('click')
        expect(wrapper.find('[data-testid="cleanup-preview"]').exists()).toBe(false)
        expect(wrapper.get('[data-testid="cleanup-confirm"]').attributes('disabled')).toBeDefined()

        await wrapper.get('[data-testid="cleanup-preview-button"]').trigger('click')
        await flushPromises()
        await wrapper.get('[data-testid="cleanup-confirm"]').trigger('click')
        await flushPromises()

        expect(wrapper.get('[role="alert"]').text()).toContain('changed since the preview')
        expect(wrapper.emitted('cleaned')).toBeUndefined()
    })

    it('says when nothing would change', async () => {
        vi.mocked(api.previewAssessmentCleanup).mockResolvedValue(preview(false))
        const wrapper = mountModal()

        await wrapper.get('[data-testid="cleanup-preview-button"]').trigger('click')
        await flushPromises()

        expect(wrapper.get('[data-testid="cleanup-preview"]').text()).toContain('Nothing would change.')
        expect(wrapper.get('[data-testid="cleanup-confirm"]').attributes('disabled')).toBeDefined()
    })

    it('limits an analyst to team assessments and marks unknown teams', () => {
        const stale = '--- [Team: Retired] [State: IN_TRIAGE] [Assessed By: bob] ---\nLooking.'
        const wrapper = mountModal({
            isReviewer: false, team: 'Identity',
            instances: [...FINDINGS.slice(0, 2), finding('7.1.1', 'brotli', `${WITH_SSVC}\n\n${stale}`)],
        })

        const options = wrapper.findAll('[data-testid="cleanup-scope"] option')
        expect(options.map(option => option.text())).toEqual([
            "Identity's assessment",
            "Retired's assessment (not in the team mapping)",
        ])
        expect((wrapper.get('[data-testid="cleanup-scope"]').element as HTMLSelectElement).value).toBe('Identity')
    })

    it('points to Repair when a rule-based repair would make the findings agree', async () => {
        const wrapper = mountModal({ repairStages: [{ id: 'combine_conflict', label: 'Combine conflicts' }] })

        expect(wrapper.get('[data-testid="cleanup-repair-hint"]').text()).toContain('Combine conflicts')
        await wrapper.get('[data-testid="cleanup-switch-to-repair"]').trigger('click')
        expect(wrapper.emitted('repair')).toHaveLength(1)

        // The SSVC record the findings agree on, carried to those without one.
        const ssvc = mountModal({ repairStages: [{ id: 'ssvc_record', label: 'SSVC record' }] })
        expect(ssvc.get('[data-testid="cleanup-repair-hint"]').text()).toContain('SSVC record')
        const response = mountModal({ repairStages: [{ id: 'response', label: 'Response' }] })
        expect(response.get('[data-testid="cleanup-repair-hint"]').text()).toContain('Response')

        const rescoringOnly = mountModal({ repairStages: [{ id: 'rescoring', label: 'Rescoring' }] })
        expect(rescoringOnly.find('[data-testid="cleanup-repair-hint"]').exists()).toBe(false)
    })

    it('does not offer to use a version without the chosen assessment', async () => {
        const wrapper = mountModal({ instances: [finding('1', 'a', TEAM), finding('2', 'a', TEAM), finding('3', 'a', WITH_SSVC)] })

        await wrapper.get('[data-testid="cleanup-scope"]').setValue('General')

        expect(wrapper.find('[data-testid="cleanup-scope-missing"]').exists()).toBe(true)
        expect(wrapper.get('[data-testid="cleanup-preview-button"]').attributes('disabled')).toBeDefined()
        await wrapper.get('[data-testid="cleanup-action-clear"]').setValue(true)
        expect(wrapper.get('[data-testid="cleanup-preview-button"]').attributes('disabled')).toBeUndefined()
    })
})
