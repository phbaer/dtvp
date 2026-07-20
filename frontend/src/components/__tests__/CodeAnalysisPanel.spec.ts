import { beforeEach, describe, it, expect, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import CodeAnalysisPanel from '../CodeAnalysisPanel.vue'

const mocks = vi.hoisted(() => ({
    submit: vi.fn(),
    submitFollowUp: vi.fn(),
    cancel: vi.fn(),
    queueItems: { value: [] as any[] },
    listResults: vi.fn(),
    getResult: vi.fn(),
    deleteResult: vi.fn(),
    getPrompts: vi.fn(),
    benchmarkResult: vi.fn(),
}))

const clipboardWriteText = vi.fn()
const windowOpen = vi.fn()

vi.mock('../../lib/api', () => ({
    codeAnalysisBenchmarkResult: mocks.benchmarkResult,
    codeAnalysisDeleteResult: mocks.deleteResult,
    codeAnalysisGetPrompts: mocks.getPrompts,
    codeAnalysisGetResult: mocks.getResult,
    codeAnalysisListVulnerabilityResults: mocks.listResults,
}))

vi.mock('../../lib/analysisQueueStore', () => ({
    analysisQueueStore: {
        items: mocks.queueItems,
        activeCount: { value: 0 },
        runningItem: { value: null },
        queuedItems: { value: [] },
        hasActivity: { value: false },
        submit: mocks.submit,
        submitFollowUp: mocks.submitFollowUp,
        cancel: mocks.cancel,
        fetchResult: vi.fn(),
        getCachedResult: vi.fn(),
    },
}))

const makeAnalysisResult = (summary: string) => ({
    assessment: {
        affected: false,
        verdict: 'Not Affected',
        confidence: 'High',
        exposure: 'not reachable',
        summary,
        reasoning: 'No reachable vulnerable call path was found.',
    },
    steps: [],
    versions_checked: ['1.0.0'],
})

const loadHistory = async (_wrapper: ReturnType<typeof mount>) => {
    await flushPromises()
}

const viewHistoryRun = async (wrapper: ReturnType<typeof mount>, runId: string) => {
    await loadHistory(wrapper)
    await wrapper.get(`[data-testid="analysis-history-row"][data-run-id="${runId}"]`).trigger('click')
    await flushPromises()
}

describe('CodeAnalysisPanel', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        clipboardWriteText.mockResolvedValue(undefined)
        Object.defineProperty(navigator, 'clipboard', {
            configurable: true,
            value: { writeText: clipboardWriteText },
        })
        Object.defineProperty(window, 'open', {
            configurable: true,
            value: windowOpen,
        })
        ;(window as any).__env__ = { DTVP_JIRA_CREATE_URL: '' }
        mocks.queueItems.value = []
        mocks.listResults.mockResolvedValue([])
        mocks.deleteResult.mockResolvedValue({ status: 'removed', analysis_run_id: 'run-1' })
        mocks.benchmarkResult.mockResolvedValue({
            schema_version: 'dtvp.code-analysis-benchmark/v1',
            analysis_run_id: 'run-1',
            compared_at: 'now',
            rating: { score: 5, max_score: 5, grade: 'A', label: 'Strong match', tone: 'green' },
            human: { state: 'NOT_AFFECTED', state_family: 'not_affected', justification: 'CODE_NOT_PRESENT' },
            automated: { state: 'NOT_AFFECTED', state_family: 'not_affected', justification: 'CODE_NOT_PRESENT' },
            deltas: {
                state_match: true,
                state_family_match: true,
                state_distance: 0,
                justification_match: true,
            },
            findings: [],
            recommendation: 'Automated assessment strongly agrees.',
        })
        mocks.getPrompts.mockResolvedValue({
            bundles: [
                {
                    bundle: 'verdict',
                    values: { system: 'System prompt text' },
                },
            ],
        })
    })

    it('disables scanning when no team-assigned target is available', async () => {
        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                componentNames: [],
            },
        })

        expect(wrapper.text()).toContain('No team-assigned component target is available')
        const analyzeButton = wrapper.findAll('button').find(button => button.text().includes('Analyze'))
        expect(analyzeButton?.attributes('disabled')).toBeDefined()
    })

    it('automatically loads only the current vulnerability history without full results', async () => {
        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                projectName: 'ExampleApp',
                componentNames: ['owned-service'],
                assessmentStatus: 'mixed',
            },
        })

        await flushPromises()

        expect(mocks.listResults).toHaveBeenCalledWith(
            'ExampleApp',
            'CVE-2026-0001',
            { limit: 20 },
        )
        expect(mocks.getResult).not.toHaveBeenCalled()
        expect(wrapper.text()).toContain('Automatic and manual assessments available')
    })

    it('reconciles selected components when the vulnerability target list changes', async () => {
        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                componentNames: ['owned-api', 'owned-worker'],
            },
        })

        expect(wrapper.text()).toContain('All Components (2)')
        expect(wrapper.text()).toContain('2 selected')

        await wrapper.setProps({ componentNames: ['owned-api'] })
        await flushPromises()

        expect(wrapper.text()).toContain('All Components (1)')
        expect(wrapper.text()).toContain('1 selected')
        expect(wrapper.text()).not.toContain('2 of 1 components')
    })

    it('submits only provided team-assigned components', async () => {
        mocks.submit.mockResolvedValue({
            queue_id: 'queue-1',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'queued',
            position: 1,
        })

        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                componentNames: ['owned-service'],
                affectedProductVersions: ['1.0.0', '1.1.0'],
            },
        })

        const analyzeButton = wrapper.findAll('button').find(button => button.text().includes('Analyze'))
        await analyzeButton?.trigger('click')

        expect(mocks.submit).toHaveBeenCalledWith(
            'CVE-2026-0001',
            'owned-service',
            undefined,
            undefined,
            undefined,
            expect.any(Function),
            expect.any(Function),
            ['1.0.0', '1.1.0'],
            'manual',
        )
    })

    it('runs one analysis action and automatically shows the benchmark comparison', async () => {
        const benchmarkResult = makeAnalysisResult('Analysis result')
        const benchmarkRecord = {
            analysis_run_id: 'queue-benchmark',
            queue_id: 'queue-benchmark',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            source: 'manual',
            summary: { affected: false, verdict: 'Not Affected' },
            finished_at: '2026-07-06T12:00:00Z',
        }
        const queueItem = {
            queue_id: 'queue-benchmark',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'completed',
            position: 0,
            source: 'manual',
        }

        mocks.listResults.mockResolvedValue([benchmarkRecord])
        mocks.submit.mockImplementation(async (...args: any[]) => {
            const onComplete = args[5]
            onComplete(benchmarkResult, queueItem)
            return queueItem
        })
        mocks.benchmarkResult.mockResolvedValue({
            schema_version: 'agentyzer.benchmark-comparison/v1',
            comparison_method: 'agentyzer_probabilistic',
            evaluator: { provider: 'agentyzer', probabilistic: true, model: 'judge-model' },
            analysis_run_id: 'queue-benchmark',
            compared_at: 'now',
            rating: { score: 4, max_score: 5, grade: 'B', label: 'Good match', tone: 'cyan', confidence: 0.8 },
            human: {
                state: 'NOT_AFFECTED',
                state_family: 'not_affected',
                justification: 'CODE_NOT_PRESENT',
                cvss_score: 0,
                cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N',
            },
            automated: {
                state: 'NOT_AFFECTED',
                state_family: 'not_affected',
                justification: 'CODE_NOT_PRESENT',
                cvss_score: 0,
                cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
            },
            deltas: {
                state_match: true,
                state_family_match: true,
                state_distance: 0,
                justification_match: true,
                cvss_delta: 0,
                cvss_vector_match: false,
                reasoning_overlap: 0.72,
            },
            findings: [{ kind: 'state', severity: 'info', title: 'Assessment state matches', detail: 'Both assessments agree.' }],
            recommendation: 'Aligned.',
            reasoning_summary: 'The reasoning is semantically aligned.',
        })

        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                projectName: 'ExampleApp',
                componentNames: ['owned-service'],
                currentState: 'NOT_AFFECTED',
                currentJustification: 'CODE_NOT_PRESENT',
                currentDetails: 'No vulnerable code path was found.',
                currentCvssScore: 0,
                currentCvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N',
            },
        })

        await flushPromises()
        expect(wrapper.findAll('button').some(button => button.text().trim() === 'Benchmark')).toBe(false)
        await wrapper.findAll('button').find(button => button.text().trim() === 'Analyze')?.trigger('click')
        await flushPromises()
        await flushPromises()

        expect(mocks.submit).toHaveBeenCalledWith(
            'CVE-2026-0001',
            'owned-service',
            'ExampleApp',
            undefined,
            undefined,
            expect.any(Function),
            expect.any(Function),
            undefined,
            'manual',
        )
        expect(mocks.benchmarkResult).toHaveBeenCalledWith('queue-benchmark', {
            current_team: 'General',
            current_state: 'NOT_AFFECTED',
            current_justification: 'CODE_NOT_PRESENT',
            current_details: 'No vulnerable code path was found.',
            current_cvss_score: 0,
            current_cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N',
        })
        expect(wrapper.text()).toContain('Agreement 4/5')
        expect(wrapper.text()).toContain('Good match')
        expect(wrapper.text()).toContain('Agentyzer probabilistic')
        expect(wrapper.text()).toContain('judge-model')
        expect(wrapper.text()).toContain('Existing Assessment')
        expect(wrapper.text()).toContain('Analysis Result')
        expect(wrapper.text()).toContain('neither side is assumed to be human-authored or ground truth')
        expect(wrapper.text()).toContain('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N')
        expect(wrapper.text()).toContain('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')
        expect(wrapper.text()).not.toContain('CVSS Delta')
        expect(wrapper.text()).not.toContain('Human State')
        expect(wrapper.text()).not.toContain('Automated State')

        const comparisonStates = wrapper.findAll('[data-testid="benchmark-comparison-state"]')
        expect(comparisonStates).toHaveLength(4)
        const stateAgreement = comparisonStates.find(state => state.text().includes('State Agreement'))
        const vectorAgreement = comparisonStates.find(state => state.text().includes('CVSS Vector Agreement'))
        expect(stateAgreement?.attributes('data-alignment')).toBe('aligned')
        expect(stateAgreement?.text()).toContain('Aligned')
        expect(stateAgreement?.find('svg').exists()).toBe(true)
        expect(vectorAgreement?.attributes('data-alignment')).toBe('different')
        expect(vectorAgreement?.text()).toContain('Different')
        expect(vectorAgreement?.find('svg').exists()).toBe(true)
        const benchmarkFinding = wrapper.get('[data-testid="benchmark-finding"]')
        expect(benchmarkFinding.attributes('data-alignment')).toBe('aligned')
        expect(benchmarkFinding.text()).toContain('Aligned')
        expect(benchmarkFinding.find('svg').exists()).toBe(true)

        const decision = wrapper.get('[data-testid="assessment-decision"]')
        const summary = wrapper.get('[data-testid="assessment-summary"]')
        expect(wrapper.html().indexOf('data-testid="assessment-decision"')).toBeLessThan(
            wrapper.html().indexOf('data-testid="assessment-summary"'),
        )
        expect(decision.text()).toContain('Evidence Quality')
        expect(decision.text()).not.toContain('Follow-up Question')
        expect(summary.text()).toContain('Follow-up Question')
        expect(summary.text()).not.toContain('Evidence Quality')
        expect(wrapper.get('[data-testid="assessment-summary-body"]').element.parentElement).toBe(summary.element)
        expect(wrapper.get('[data-testid="assessment-draft-body"]').element.parentElement).toBe(
            wrapper.get('[data-testid="assessment-draft"]').element,
        )
        expect(wrapper.get('[data-testid="assessment-benchmark-body"]').element.parentElement).toBe(
            wrapper.get('[data-testid="assessment-benchmark"]').element,
        )

        const disclosureButtons = wrapper.findAll('button[aria-expanded]')
        const summaryIndex = disclosureButtons.findIndex(button => button.text().includes('Summary'))
        const draftIndex = disclosureButtons.findIndex(button => button.text().includes('Assessment Draft'))
        const benchmarkIndex = disclosureButtons.findIndex(button => button.text().includes('Assessment Benchmark'))
        expect(summaryIndex).toBeGreaterThanOrEqual(0)
        expect(draftIndex).toBeGreaterThan(summaryIndex)
        expect(benchmarkIndex).toBeGreaterThan(draftIndex)
        expect(disclosureButtons[summaryIndex].attributes('aria-expanded')).toBe('true')
        expect(disclosureButtons[draftIndex].attributes('aria-expanded')).toBe('true')
        expect(disclosureButtons[benchmarkIndex].attributes('aria-expanded')).toBe('true')

        await disclosureButtons[draftIndex].trigger('click')
        expect(disclosureButtons[draftIndex].attributes('aria-expanded')).toBe('false')
        expect(disclosureButtons[summaryIndex].attributes('aria-expanded')).toBe('true')
        expect(disclosureButtons[benchmarkIndex].attributes('aria-expanded')).toBe('true')
        expect(wrapper.text()).toContain('Agreement 4/5')
    })

    it('does not offer a separate benchmark or load a comparison without an existing assessment', async () => {
        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                projectName: 'ExampleApp',
                componentNames: ['owned-service'],
                currentState: 'NOT_SET',
            },
        })

        await flushPromises()

        expect(wrapper.findAll('button').some(button => button.text().trim() === 'Benchmark')).toBe(false)
        expect(wrapper.find('[data-testid="assessment-benchmark"]').exists()).toBe(false)
        expect(mocks.benchmarkResult).not.toHaveBeenCalled()
    })

    it('allows queue interaction and skips already active components when starting more', async () => {
        mocks.queueItems.value = [
            {
                queue_id: 'queue-running',
                vuln_id: 'CVE-2026-0001',
                component_name: 'owned-service',
                submitted_by: 'tester',
                submitted_at: 'now',
                status: 'running',
                position: 0,
            },
        ]
        mocks.submit.mockResolvedValue({
            queue_id: 'queue-2',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-worker',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'queued',
            position: 1,
        })
        mocks.cancel.mockResolvedValue({ status: 'abort_requested' })

        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                componentNames: ['owned-service', 'owned-worker'],
            },
        })

        await wrapper.findAll('button').find(button => button.text().includes('Abort'))?.trigger('click')
        await wrapper.findAll('button').find(button => button.text().includes('Analyze More'))?.trigger('click')

        expect(mocks.cancel).toHaveBeenCalledWith('queue-running')
        expect(mocks.submit).toHaveBeenCalledTimes(1)
        expect(mocks.submit.mock.calls[0][1]).toBe('owned-worker')
    })

    it('loads configured prompt fallback with additional request guidance only when requested', async () => {
        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                componentNames: ['owned-service'],
                analysisGuidance: 'TMRescore reviewer context.',
            },
        })

        expect(mocks.getPrompts).not.toHaveBeenCalled()

        await wrapper.find('#code-analysis-guidance').setValue('Also check upstream Keycloak exposure.')
        await wrapper.findAll('button').find(button => button.text().includes('LLM Conversation'))?.trigger('click')
        await flushPromises()

        expect(mocks.getPrompts).toHaveBeenCalledWith({
            include_values: true,
            system_only: false,
        })
        expect(wrapper.text()).toContain('System prompt text')
        expect(wrapper.text()).toContain('Additional request guidance')
        expect(wrapper.text()).toContain('TMRescore reviewer context.')
        expect(wrapper.text()).toContain('Also check upstream Keycloak exposure.')
    })

    it('shows the actual selected-run LLM conversation when available', async () => {
        const baseResult = makeAnalysisResult('Actual trace assessment')
        const analysisResult = {
            ...baseResult,
            assessment: {
                ...baseResult.assessment,
                version_analysis: {
                    checked_versions: [
                        {
                            ref: 'CURRENT',
                            ref_type: 'worktree',
                            version: '2.0.0',
                            source: 'manifest',
                            affected: true,
                            notes: 'current branch version is affected',
                        },
                        {
                            ref: 'release/1.x',
                            ref_type: 'branch',
                            version: '1.9.5',
                            source: 'lock',
                            affected: true,
                            notes: 'release branch still resolves affected dependency',
                        },
                        {
                            ref: 'v2.0.1',
                            ref_type: 'tag',
                            version: '2.0.1',
                            source: 'manifest',
                            affected: false,
                            notes: 'tag contains fixed dependency',
                        },
                        {
                            ref: 'release/no-match',
                            ref_type: 'branch',
                            version: '-',
                            source: 'manifest',
                            affected: null,
                            notes: 'not found',
                        },
                    ],
                },
            },
            llm_conversation: [
                {
                    model: 'mistral',
                    provider: 'openwebui',
                    status: 'completed',
                    usage: { total_tokens: 18 },
                    messages: [
                        { role: 'system', content: 'Actual system prompt sent to the model.' },
                        {
                            role: 'user',
                            content: [
                                'Example input:',
                                'VULNERABILITY: CVE-EXAMPLE',
                                'STRUCTURE:',
                                'Example output:',
                                'REACHABLE: NO',
                                'Now analyze the following:',
                                'VULNERABILITY: CVE-2026-0001',
                                'ADVISORY: Vulnerable parser in owned-service dependency.',
                                'SNIPPETS:',
                                '--- src/app.ts:7 ---',
                                'callVulnerableParser(input)',
                                'STRUCTURE:',
                                '=== src/app.ts ===',
                                '  appHandler() [line 1]',
                                'ANALYST GUIDANCE:',
                                'Per-component reviewer guidance.',
                                'Respond with EXACTLY the four fields.',
                            ].join('\n'),
                        },
                    ],
                    response: { role: 'assistant', content: 'Actual assistant response.' },
                },
                {
                    model: 'mistral',
                    provider: 'openwebui',
                    status: 'completed',
                    usage: { total_tokens: 7 },
                    messages: [
                        { role: 'system', content: 'Research-capable system prompt.' },
                        { role: 'user', content: 'Now analyze the following:\nVULNERABILITY: CVE-2026-0001' },
                    ],
                    response: {
                        role: 'assistant',
                        content: [
                            'FETCH_SEARCH: CVE-2026-0001 owned-service advisory',
                            'FETCH_URL: https://advisories.example/CVE-2026-0001',
                        ].join('\n'),
                    },
                },
                {
                    model: 'mistral',
                    provider: 'openwebui',
                    status: 'completed',
                    usage: { total_tokens: 9 },
                    messages: [
                        { role: 'system', content: 'Research-capable system prompt.' },
                        { role: 'user', content: 'Now analyze the following:\nVULNERABILITY: CVE-2026-0001' },
                    ],
                    response: {
                        role: 'assistant',
                        content: '',
                        tool_calls: [
                            {
                                id: 'call_package',
                                type: 'function',
                                function: {
                                    name: 'fetch_package',
                                    arguments: '{"package":"org.keycloak:keycloak-core"}',
                                },
                            },
                        ],
                    },
                },
                {
                    model: 'mistral',
                    provider: 'openwebui',
                    status: 'completed',
                    usage: { total_tokens: 11 },
                    messages: [
                        { role: 'system', content: 'Research-capable system prompt.' },
                        { role: 'user', content: 'Now analyze the following:\nVULNERABILITY: CVE-2026-0001' },
                        {
                            role: 'assistant',
                            content: '',
                            tool_calls: [
                                {
                                    id: 'call_package',
                                    type: 'function',
                                    function: {
                                        name: 'fetch_package',
                                        arguments: '{"package":"org.keycloak:keycloak-core"}',
                                    },
                                },
                            ],
                        },
                        {
                            role: 'tool',
                            name: 'fetch_package',
                            tool_call_id: 'call_package',
                            content: [
                                '--- Package info: org.keycloak:keycloak-core ---',
                                'Registry metadata for Keycloak core.',
                            ].join('\n'),
                        },
                    ],
                    response: { role: 'assistant', content: 'Final native-tool researched answer.' },
                },
                {
                    model: 'mistral',
                    provider: 'openwebui',
                    status: 'completed',
                    usage: { total_tokens: 22 },
                    messages: [
                        { role: 'system', content: 'Research continuation system prompt.' },
                        {
                            role: 'user',
                            content: [
                                'Now analyze the following:',
                                'VULNERABILITY: CVE-2026-0001',
                                '',
                                'MANDATORY EXTERNAL CHECK:',
                                '- Analyzer-required tool request:',
                                '  FETCH_SEARCH: Keycloak netty CVE-2026-0001 dependency version',
                                '',
                                '--- RESEARCH RESULTS (round 1) ---',
                                '--- Search results for: CVE-2026-0001 owned-service advisory ---',
                                'Search results:',
                                '1. Vendor advisory',
                                '--- Fetched: https://advisories.example/CVE-2026-0001 ---',
                                'Vendor advisory text.',
                                '--- Search failed: overloaded advisory search (HTTP 429) ---',
                            ].join('\n'),
                        },
                    ],
                    response: { role: 'assistant', content: 'Final researched answer.' },
                },
            ],
        }
        const traceRecord = {
            analysis_run_id: 'run-with-trace',
            queue_id: 'run-with-trace',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            source: 'manual',
            summary: { affected: false, verdict: 'Not Affected' },
            finished_at: '2026-07-06T12:00:00Z',
        }
        mocks.listResults.mockResolvedValue([traceRecord])
        mocks.getResult.mockResolvedValue({ ...traceRecord, result: analysisResult })

        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                projectName: 'ExampleApp',
                componentNames: ['owned-service'],
            },
        })

        await viewHistoryRun(wrapper, 'run-with-trace')
        await wrapper.findAll('button').find(button => button.text().includes('LLM Conversation'))?.trigger('click')
        await wrapper.findAll('button').find(button => button.text().includes('Version Coverage'))?.trigger('click')
        await flushPromises()

        expect(mocks.getPrompts).not.toHaveBeenCalled()
        expect(wrapper.text()).toContain('Actual LLM conversation')
        expect(wrapper.text()).toContain('Version Coverage')
        expect(wrapper.text()).toContain('Checked Ref')
        expect(wrapper.text()).toContain('Product Version')
        expect(wrapper.text()).toContain('Current workspace')
        expect(wrapper.text()).toContain('Not tied to product version')
        expect(wrapper.text()).toContain('CURRENT')
        expect(wrapper.text()).toContain('release/1.x')
        expect(wrapper.text()).toContain('v2.0.1')
        expect(wrapper.text()).toContain('release/no-match')
        expect(wrapper.text()).toContain('2.0.0')
        expect(wrapper.text()).toContain('unknown')
        expect(wrapper.text()).toContain('not affected')
        expect(wrapper.text()).toContain('What was sent to the LLM')
        expect(wrapper.text()).toContain('sent to LLM · static prompt')
        expect(wrapper.text()).toContain('Static · system prompt')
        expect(wrapper.text()).toContain('Actual system prompt sent to the model.')
        expect(wrapper.text()).toContain('Static · prompt template prefix')
        expect(wrapper.text()).toContain('Example input:')
        expect(wrapper.text()).toContain('Dynamic · task instruction')
        expect(wrapper.text()).toContain('Dynamic · vulnerability/advisory')
        expect(wrapper.text()).toContain('Dynamic · source/dependency context')
        expect(wrapper.text()).toContain('Dynamic · component guidance')
        expect(wrapper.text()).toContain('Static · response contract')
        expect(wrapper.text()).toContain('Tool activity')
        expect(wrapper.text()).toContain('Requested web search')
        expect(wrapper.text()).toContain('Requested URL download')
        expect(wrapper.text()).toContain('Requested package lookup')
        expect(wrapper.text()).toContain('Analyzer-required web search')
        expect(wrapper.text()).toContain('CVE-2026-0001 owned-service advisory')
        expect(wrapper.text()).toContain('org.keycloak:keycloak-core')
        expect(wrapper.text()).toContain('Keycloak netty CVE-2026-0001 dependency version')
        expect(wrapper.text()).toContain('Search results provided')
        expect(wrapper.text()).toContain('Downloaded URL text provided')
        expect(wrapper.text()).toContain('Package metadata provided')
        expect(wrapper.text()).toContain('Dynamic · tool result')
        expect(wrapper.text()).toContain('Web search failed')
        expect(wrapper.text()).toContain('Per-component reviewer guidance.')
        expect(wrapper.text()).toContain('How the LLM answered')
        expect(wrapper.text()).toContain('received from LLM · assistant response')
        expect(wrapper.text()).toContain('Actual assistant response.')
    })

    it('shows saved selected-run guidance when no LLM trace is available', async () => {
        const summaryRecord = {
            analysis_run_id: 'run-with-guidance',
            queue_id: 'run-with-guidance',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            source: 'automatic',
            summary: { affected: false, verdict: 'Not Affected' },
            finished_at: '2026-07-06T12:00:00Z',
        }
        mocks.listResults.mockResolvedValue([summaryRecord])
        mocks.getResult.mockResolvedValue({
            ...summaryRecord,
            user_guidance: 'Component-specific auto-assessment guidance configured in DTVP.\nCheck owned-service runtime exposure.',
            result: makeAnalysisResult('Stored automatic assessment'),
        })

        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                projectName: 'ExampleApp',
                componentNames: ['owned-service'],
            },
        })

        await viewHistoryRun(wrapper, 'run-with-guidance')
        await wrapper.findAll('button').find(button => button.text().includes('LLM Conversation'))?.trigger('click')
        await flushPromises()

        expect(mocks.getResult).toHaveBeenCalledWith('run-with-guidance')
        expect(mocks.getPrompts).toHaveBeenCalledWith({
            include_values: true,
            system_only: false,
        })
        expect(wrapper.text()).toContain('Additional request guidance')
        expect(wrapper.text()).toContain('Component-specific auto-assessment guidance configured in DTVP.')
        expect(wrapper.text()).toContain('Check owned-service runtime exposure.')
    })

    it('emits the persisted analysis run id with an individual assessment draft', async () => {
        const record = {
            analysis_run_id: 'run-provenance',
            queue_id: 'run-provenance',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            source: 'automatic',
            summary: { affected: false, verdict: 'Not Affected' },
            finished_at: '2026-07-06T12:00:00Z',
        }
        mocks.listResults.mockResolvedValue([record])
        mocks.getResult.mockResolvedValue({
            ...record,
            result: makeAnalysisResult('Stored automatic assessment'),
        })

        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                projectName: 'ExampleApp',
                componentNames: ['owned-service'],
            },
        })
        await viewHistoryRun(wrapper, 'run-provenance')

        await wrapper.findAll('button').find(button => button.text().includes('Use as Assessment Draft'))?.trigger('click')

        expect(wrapper.emitted('apply-result')?.[0]?.[2]).toEqual(['run-provenance'])
    })

    it('removes a saved analysis run from the card history', async () => {
        const firstResult = makeAnalysisResult('First stored assessment')
        const firstRecord = {
            analysis_run_id: 'run-delete',
            queue_id: 'run-delete',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            source: 'manual',
            summary: { affected: false, verdict: 'Not Affected' },
            result: firstResult,
            finished_at: '2026-07-06T12:00:00Z',
        }
        const secondRecord = {
            analysis_run_id: 'run-keep',
            queue_id: 'run-keep',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-worker',
            project_name: 'ExampleApp',
            source: 'automatic',
            summary: { affected: false, verdict: 'Not Affected' },
            result: makeAnalysisResult('Second stored assessment'),
            finished_at: '2026-07-06T12:05:00Z',
        }
        mocks.listResults.mockResolvedValue([firstRecord, secondRecord])
        const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)

        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                projectName: 'ExampleApp',
                componentNames: ['owned-service', 'owned-worker'],
            },
        })

        await loadHistory(wrapper)
        expect(wrapper.text()).toContain('owned-service')

        const removeButtons = wrapper.findAll('button[aria-label="Remove analysis run"]')
        await removeButtons[0].trigger('click')
        await flushPromises()

        expect(confirmSpy).toHaveBeenCalledWith(
            'Remove saved analysis run for owned-service? This cannot be undone.',
        )
        expect(mocks.deleteResult).toHaveBeenCalledWith('run-delete')
        expect(wrapper.text()).not.toContain('owned-service')
        expect(wrapper.text()).toContain('owned-worker')

        confirmSpy.mockRestore()
    })

    it('shows and selects a follow-up result when completion arrives before submit resolves', async () => {
        const parentResult = makeAnalysisResult('Initial extension assessment')
        const followUpResult = makeAnalysisResult('Follow-up platform assessment')
        const parentRecord = {
            analysis_run_id: 'parent-run',
            queue_id: 'parent-run',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            source: 'manual',
            summary: { affected: false, verdict: 'Not Affected' },
            result: parentResult,
            finished_at: '2026-07-06T12:00:00Z',
        }
        const followUpRecord = {
            analysis_run_id: 'follow-run',
            queue_id: 'follow-run',
            parent_run_id: 'parent-run',
            follow_up_question: 'Is Keycloak itself vulnerable?',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            source: 'follow-up',
            summary: { affected: false, verdict: 'Not Affected' },
            result: followUpResult,
            finished_at: '2026-07-06T12:05:00Z',
        }
        const followUpQueueItem = {
            queue_id: 'follow-run',
            vuln_id: 'CVE-2026-0001',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'completed',
            position: 0,
            source: 'follow-up',
        }

        mocks.listResults
            .mockResolvedValueOnce([parentRecord])
            .mockResolvedValueOnce([followUpRecord, parentRecord])
        mocks.submitFollowUp.mockImplementation(async (...args: any[]) => {
            const onComplete = args[6]
            onComplete(followUpResult, followUpQueueItem)
            return followUpQueueItem
        })

        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0001',
                projectName: 'ExampleApp',
                componentNames: ['owned-service'],
            },
        })

        await viewHistoryRun(wrapper, 'parent-run')
        await wrapper.find('#code-analysis-follow-up').setValue('Is Keycloak itself vulnerable?')
        await wrapper.findAll('button').find(button => button.text().includes('Follow-up'))?.trigger('click')
        await flushPromises()

        expect(mocks.submitFollowUp).toHaveBeenCalledWith(
            'parent-run',
            'Is Keycloak itself vulnerable?',
            'owned-service',
            'ExampleApp',
            undefined,
            undefined,
            expect.any(Function),
            expect.any(Function),
        )

        const selectedFollowUpRow = wrapper.findAll('div').find(node =>
            node.text().includes('Follow-up')
            && node.text().includes('Selected')
            && node.text().includes('owned-service')
        )
        expect(selectedFollowUpRow).toBeDefined()
        expect(wrapper.text()).toContain('Follow-up platform assessment')
    })

    it('uses and copies analyzer-generated ticket text for affected analysis results', async () => {
        ;(window as any).__env__ = {
            DTVP_JIRA_CREATE_URL: 'https://jira.example/secure/CreateIssue!default.jspa',
        }
        const generatedTicketText = [
            'Title: Remediate CVE-2026-0002 in owned-service via vulnerable-parser',
            '',
            'Description',
            'owned-service reaches vulnerable-parser through a public request handler.',
            '',
            'Remediation',
            '- Upgrade vulnerable-parser or the direct parent dependency that resolves it.',
        ].join('\n')
        const affectedResult = {
            assessment: {
                affected: true,
                verdict: 'Affected',
                confidence: 'High',
                exposure: 'reachable vulnerable handler',
                ticket_text: generatedTicketText,
                summary: 'The vulnerable call path is reachable from the public API.',
                reasoning: 'The scanner found a request handler that invokes the vulnerable parser.',
                adjusted_cvss: {
                    original_score: 9.8,
                    adjusted_score: 9.8,
                    original_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    adjusted_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    summary: 'No environmental reduction was justified.',
                    reasons: ['reachable without authentication'],
                },
            },
            steps: [
                {
                    step: 'scan_code',
                    title: 'Code reachability',
                    status: 'fail',
                    findings: {},
                    evidence: ['Request handler calls vulnerable parser directly.'],
                },
                {
                    step: 'prepare_repo',
                    title: 'Repository Clone',
                    status: 'ok',
                    findings: {},
                    evidence: ['Cloned repo to /tmp/agentyzer/worktree'],
                },
            ],
            versions_checked: ['1.0.0'],
            component_results: [
                {
                    component: 'owned-service',
                    assessment: {
                        affected: true,
                        verdict: 'Affected',
                        confidence: 'High',
                        exposure: 'reachable vulnerable handler',
                        summary: 'Reachable vulnerable use.',
                        reasoning: 'Direct call was found.',
                    },
                    versions_checked: ['1.0.0'],
                },
            ],
        }
        const queueItem = {
            queue_id: 'queue-affected',
            vuln_id: 'CVE-2026-0002',
            component_name: 'owned-service',
            project_name: 'ExampleApp',
            submitted_by: 'tester',
            submitted_at: 'now',
            status: 'completed',
            position: 0,
        }

        mocks.submit.mockImplementation(async (...args: any[]) => {
            const onComplete = args[5]
            onComplete(affectedResult, queueItem)
            return queueItem
        })

        const wrapper = mount(CodeAnalysisPanel, {
            props: {
                vulnId: 'CVE-2026-0002',
                projectName: 'ExampleApp',
                cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                componentNames: ['owned-service'],
            },
        })

        await wrapper.findAll('button').find(button => button.text().includes('Analyze'))?.trigger('click')
        await flushPromises()

        expect(wrapper.text()).toContain('Ticket Draft')
        expect(wrapper.find('textarea[aria-label="Generated ticket text"]').exists()).toBe(false)
        await wrapper.findAll('button').find(button => button.text().includes('Ticket Draft'))?.trigger('click')
        expect(wrapper.get('[data-testid="ticket-draft-body"]').element.parentElement).toBe(
            wrapper.get('[data-testid="ticket-draft"]').element,
        )
        const ticket = wrapper.find('textarea[aria-label="Generated ticket text"]')
        const ticketText = (ticket.element as HTMLTextAreaElement).value
        expect(ticketText).toBe(generatedTicketText)
        expect(ticketText).not.toContain('Repository Clone')
        expect(ticketText).not.toContain('/tmp/agentyzer/worktree')
        expect(ticketText).not.toContain('Update owned-service')

        await wrapper.findAll('button').find(button => button.text().includes('Create Jira issue'))?.trigger('click')
        await flushPromises()
        expect(windowOpen).toHaveBeenCalledWith(
            'https://jira.example/secure/CreateIssue!default.jspa',
            '_blank',
            'noopener,noreferrer',
        )
        expect(clipboardWriteText).toHaveBeenCalledWith(ticketText)

        await wrapper.findAll('button').find(button => button.text().includes('Copy'))?.trigger('click')
        expect(clipboardWriteText).toHaveBeenCalledWith(ticketText)
    })
})
