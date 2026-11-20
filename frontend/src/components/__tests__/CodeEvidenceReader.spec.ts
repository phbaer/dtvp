import { describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import CodeEvidenceReader from '../CodeEvidenceReader.vue'
import { agentRow, analyzerRow } from '../../lib/codeEvidence'
import type { CodeEvidence } from '../../lib/api'

const evidence = (overrides: Partial<CodeEvidence> = {}): CodeEvidence => ({
    kind: 'agent',
    evidence_id: 'ev_1',
    project_name: 'App',
    vuln_id: 'CVE-1',
    scope: 'findings',
    targets: [
        { component: 'lib-a', component_version: '1.0', project_version: '2.0', finding_uuid: 'f1' },
        { component: 'lib-a', component_version: '1.0', project_version: '2.1', finding_uuid: 'f2' },
    ],
    title: 'Not reachable',
    body_markdown: '**Bold** evidence <img src=x onerror=alert(1)>',
    references: ['https://example.org/pr/1', 'internal note'],
    suggested_state: 'NOT_AFFECTED',
    suggested_justification: 'CODE_NOT_REACHABLE',
    confidence: 'medium',
    author: { username: 'alice', agent_label: 'triage-bot', token_id: 'tok_9', authority: 'ANALYST' },
    created_at: '2026-07-06T13:00:00Z',
    withdrawn: null,
    applications: [],
    ...overrides,
})

const mountReader = (props: Record<string, any>) => mount(CodeEvidenceReader, {
    props: { targetLabel: 'TEAM-A', ...props } as any,
    attachTo: document.body,
})

describe('CodeEvidenceReader', () => {
    it('renders provenance and sanitised Markdown', async () => {
        const wrapper = mountReader({ row: agentRow(evidence()) })
        await flushPromises()
        const provenance = wrapper.get('[data-testid="evidence-provenance"]')
        expect(provenance.element.tagName).toBe('DL')
        expect(provenance.text()).toContain('AI agent through MCP')
        expect(wrapper.get('[data-testid="evidence-added-by"]').text()).toBe('alice via token triage-bot (id tok_9), analyst authority')
        expect(wrapper.get('[data-testid="evidence-for"]').text()).toContain('lib-a 1.0 · project 2.0, 2.1 · 2 findings')
        expect(provenance.find('a[href="https://example.org/pr/1"]').exists()).toBe(true)
        expect(provenance.text()).toContain('internal note')
        expect(provenance.findAll('a')).toHaveLength(1)
        expect(provenance.find('dd[title]').attributes('title')).toContain('UTC')
        expect(wrapper.get('[data-testid="evidence-body"] strong').text()).toBe('Bold')
        expect(wrapper.find('img').exists()).toBe(false)
        expect(document.activeElement).toBe(wrapper.get('[data-testid="evidence-reader"]').element)
        wrapper.unmount()
    })

    it('keeps the apply step apart and gates the suggested decision', async () => {
        const wrapper = mountReader({ row: agentRow(evidence()) })
        const box = wrapper.get('[data-testid="evidence-apply-box"]')
        expect(box.element.closest('[data-testid="evidence-body"]')).toBeNull()
        expect(wrapper.get('[data-testid="evidence-body"]').element.contains(box.element)).toBe(false)
        expect(box.text()).toContain('Apply to the assessment')
        expect(box.text()).toContain('Adds a reference to this evidence to the TEAM-A assessment draft. Nothing is saved until you save the assessment.')
        expect(box.text()).toContain('Also use the suggested decision: NOT_AFFECTED · CODE_NOT_REACHABLE')
        const checkbox = box.get('[data-testid="evidence-use-suggestion"]')
        expect((checkbox.element as HTMLInputElement).checked).toBe(false)

        await box.get('[data-testid="evidence-apply"]').trigger('click')
        await checkbox.setValue(true)
        await box.get('[data-testid="evidence-apply"]').trigger('click')
        expect(wrapper.emitted('apply')).toEqual([[{ useSuggestion: false }], [{ useSuggestion: true }]])
        wrapper.unmount()
    })

    it('marks evidence none of whose findings is reported any more', () => {
        const current = mountReader({ row: agentRow(evidence()), reportedFindingUuids: ['f2', 'f3'] })
        expect(current.get('[data-testid="evidence-for"]').text()).not.toContain('no longer reported')
        current.unmount()
        const stale = mountReader({ row: agentRow(evidence()), reportedFindingUuids: ['f3'] })
        expect(stale.get('[data-testid="evidence-for"]').text()).toContain('no longer reported')
        stale.unmount()
        const unknown = mountReader({ row: agentRow(evidence()) })
        expect(unknown.get('[data-testid="evidence-for"]').text()).not.toContain('no longer reported')
        unknown.unmount()
    })

    it('has no suggestion checkbox without a suggestion', () => {
        const wrapper = mountReader({ row: agentRow(evidence({ suggested_state: null, suggested_justification: null })) })
        expect(wrapper.find('[data-testid="evidence-use-suggestion"]').exists()).toBe(false)
        wrapper.unmount()
    })

    it('cannot apply withdrawn evidence or an ineligible run', async () => {
        const withdrawn = mountReader({
            row: agentRow(evidence({ withdrawn: { at: '2026-07-07T00:00:00Z', by: 'rita', reason: 'duplicate' } })),
        })
        expect(withdrawn.get('[data-testid="evidence-apply"]').attributes('disabled')).toBeDefined()
        expect(withdrawn.get('[data-testid="evidence-apply-disabled-reason"]').text()).toContain('Withdrawn')
        expect(withdrawn.get('[data-testid="evidence-withdrawn"]').text()).toContain('rita')
        withdrawn.unmount()

        const record = {
            analysis_run_id: 'run-1', vuln_id: 'CVE-1', component_name: 'lib-a', source: 'automatic',
            model: 'model-x', submitted_by: 'bob', finished_at: '2026-07-06T12:00:00Z',
            summary: { verdict: 'Not Affected' },
        } as any
        const run = mountReader({
            row: analyzerRow(record),
            result: { assessment: { verdict: 'Not Affected', summary: 'Analyzer summary' }, steps: [] },
            applicable: false,
        })
        expect(run.get('[data-testid="evidence-added-by"]').text()).toBe('Agentyzer run run-1 · model-x · automatic · started by bob')
        expect(run.get('[data-testid="evidence-apply"]').attributes('disabled')).toBeDefined()
        expect(run.get('[data-testid="evidence-apply-disabled-reason"]').text()).toContain('not eligible')
        expect(run.get('[data-testid="evidence-apply-box"]').text()).toContain('its state, justification, and CVSS')
        await run.get('[data-testid="evidence-reader-more"]').trigger('click')
        expect(run.find('[data-testid="evidence-remove-run"]').exists()).toBe(true)
        expect(run.find('[data-testid="evidence-withdraw"]').exists()).toBe(false)
        run.unmount()
    })

    it('offers Withdraw only to a reviewer or the author', async () => {
        for (const [props, visible] of [
            [{ currentUser: 'bob', isReviewer: false }, false],
            [{ currentUser: 'alice', isReviewer: false }, true],
            [{ currentUser: 'rita', isReviewer: true }, true],
        ] as const) {
            const wrapper = mountReader({ row: agentRow(evidence()), ...props })
            await wrapper.get('[data-testid="evidence-reader-more"]').trigger('click')
            expect(wrapper.find('[data-testid="evidence-withdraw"]').exists()).toBe(visible)
            if (visible) {
                await wrapper.get('[data-testid="evidence-withdraw"]').trigger('click')
                expect(wrapper.get('[data-testid="evidence-withdraw-confirm"]').attributes('disabled')).toBeDefined()
                await wrapper.get('[data-testid="evidence-withdraw-reason"]').setValue('Wrong component')
                await wrapper.get('[data-testid="evidence-withdraw-confirm"]').trigger('click')
                expect(wrapper.emitted('withdraw')).toEqual([['Wrong component']])
            }
            wrapper.unmount()
        }
    })
})
