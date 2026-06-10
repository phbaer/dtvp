import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import VScorer from '../VScorer.vue'
import {
    getPreparedVScorerWizardEditor,
    getVScorerContext,
    getVScorerProjectState,
    getVScorerSyntheticSbomDownloadUrl,
    getVScorerSyntheticSbomSummary,
    patchPreparedVScorerWizardEditor,
    prepareVScorerAnalysis,
    refreshPreparedVScorerWizardContext,
    resumeVScorerAnalysis,
    runPreparedVScorerAnalysis,
    runVScorerAnalysis,
    validatePreparedVScorerWizardInputs,
} from '../../lib/api'
import { mountWithRouter } from './routerTestUtils'

vi.mock('../../lib/api', () => ({
    getPreparedVScorerThreatModelDownloadUrl: vi.fn((sessionId: string) => `/api/vscorer/sessions/${sessionId}/wizard/threatmodel`),
    getPreparedVScorerWizardEditor: vi.fn(),
    getVScorerContext: vi.fn(),
    getVScorerProjectState: vi.fn(),
    getVScorerSyntheticSbomDownloadUrl: vi.fn((projectName: string, scope: string) => `/api/projects/${projectName}/vscorer/sbom?scope=${scope}`),
    getVScorerSyntheticSbomSummary: vi.fn(async (_projectName: string, scope: string) => ({
        scope,
        latest_version: '1.10.0',
        analyzed_versions: scope === 'merged_versions' ? ['1.9.0', '1.10.0'] : ['1.10.0'],
        component_count: scope === 'merged_versions' ? 6 : 3,
        vulnerability_count: scope === 'merged_versions' ? 4 : 2,
        strategy_note: scope === 'merged_versions'
            ? 'Merged multi-version analysis keeps historical vulnerabilities attached to the versioned components they came from.'
            : 'Latest-only analysis is limited to the newest version and does not account for vulnerabilities seen only in older releases.',
    })),
    patchPreparedVScorerWizardEditor: vi.fn(),
    prepareVScorerAnalysis: vi.fn(),
    refreshPreparedVScorerWizardContext: vi.fn(),
    resumeVScorerAnalysis: vi.fn(),
    runPreparedVScorerAnalysis: vi.fn(),
    runVScorerAnalysis: vi.fn(),
    validatePreparedVScorerWizardInputs: vi.fn(),
}))

describe('VScorer.vue', () => {
    const vscorerRoutes = [
        { path: '/project/:name', component: { template: '<div />' } },
        { path: '/project/:name/vscorer', component: VScorer },
        { path: '/project/:name/tmrescore', component: VScorer },
    ]

    beforeEach(() => {
        vi.clearAllMocks()
        window.sessionStorage.clear()
        vi.mocked(getVScorerProjectState).mockRejectedValue({ response: { status: 404 } })
        vi.spyOn(Date, 'now').mockReturnValue(new Date('2024-03-30T12:10:00Z').getTime())
    })

    const deferred = <T,>() => {
        let resolve!: (value: T) => void
        let reject!: (reason?: unknown) => void
        const promise = new Promise<T>((res, rej) => {
            resolve = res
            reject = rej
        })
        return { promise, resolve, reject }
    }

    it('loads context and renders recommended scope', async () => {
        vi.mocked(getVScorerContext).mockResolvedValue({
            enabled: true,
            wizard_url: 'http://vscorer.local/wizard',
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.9.0', '1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
                { id: 'latest_only', label: 'Latest Version Only', description: 'Single-version scope' },
            ],
            warnings: ['Do not combine latest SBOM with historical vulnerabilities.'],
            llm_enrichment: {
                available: true,
                status: 'available',
                default_model: 'qwen2.5:14b',
                host_configured: true,
                warning: null,
            },
        } as any)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })

        expect(getVScorerContext).toHaveBeenCalledWith('ExampleApp')
        expect(wrapper.text()).toContain('Merged Multi-Version SBOM')
        expect(wrapper.text()).toContain('Recommended')
        expect(wrapper.text()).toContain('1.10.0')
        expect(wrapper.text()).toContain('LLM enrichment')
        expect(wrapper.get('[data-testid="llm-enrichment-status"]').text()).toBe('Available')
        expect((wrapper.get('[data-testid="ollama-model-input"]').element as HTMLInputElement).value).toBe('qwen2.5:14b')
        expect(getVScorerSyntheticSbomDownloadUrl).toHaveBeenCalledWith('ExampleApp', 'merged_versions')
        expect(getVScorerSyntheticSbomSummary).toHaveBeenCalledWith('ExampleApp', 'merged_versions')
        expect(wrapper.get('[data-testid="download-analysis-sbom"]').attributes('href')).toBe('/api/projects/ExampleApp/vscorer/sbom?scope=merged_versions')
        expect(wrapper.get('[data-testid="open-vscorer-wizard"]').attributes('href')).toBe('http://vscorer.local/wizard')
        expect(wrapper.get('[data-testid="open-vscorer-wizard"]').attributes('target')).toBe('_blank')
        expect(wrapper.get('[data-testid="analysis-sbom-summary-components"]').text()).toBe('6')
        expect(wrapper.get('[data-testid="analysis-sbom-summary-vulnerabilities"]').text()).toBe('4')
        expect(wrapper.get('a[href="/project/ExampleApp"]').text()).toContain('Back to Project View')
    })

    it('refreshes the synthetic SBOM summary when the scope changes', async () => {
        vi.mocked(getVScorerContext).mockResolvedValue({
            enabled: true,
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.9.0', '1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
                { id: 'latest_only', label: 'Latest Version Only', description: 'Single-version scope' },
            ],
            warnings: [],
            llm_enrichment: {
                available: true,
                status: 'available',
                default_model: 'qwen2.5:7b',
                host_configured: true,
                warning: null,
            },
        } as any)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })
        await flushPromises()

        await wrapper.get('[data-testid="scope-latest_only"]').trigger('click')
        await flushPromises()

        expect(getVScorerSyntheticSbomSummary).toHaveBeenLastCalledWith('ExampleApp', 'latest_only')
        expect(getVScorerSyntheticSbomDownloadUrl).toHaveBeenLastCalledWith('ExampleApp', 'latest_only')
        expect(wrapper.get('[data-testid="analysis-sbom-summary-components"]').text()).toBe('3')
        expect(wrapper.get('[data-testid="analysis-sbom-summary-vulnerabilities"]').text()).toBe('2')
    })

    it('restores a cached VScorer session after page reload', async () => {
        const nowSeconds = Math.floor(Date.now() / 1000)
        vi.mocked(getVScorerContext).mockResolvedValue({
            enabled: true,
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.9.0', '1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
                { id: 'latest_only', label: 'Latest Version Only', description: 'Single-version scope' },
            ],
            warnings: [],
            llm_enrichment: {
                available: true,
                status: 'available',
                default_model: 'qwen2.5:7b',
                host_configured: true,
                warning: null,
            },
        } as any)
        vi.mocked(getVScorerProjectState).mockResolvedValue({
            session_id: 'session-1',
            status: 'running',
            progress: 64,
            message: 'Rescoring vulnerabilities against the threat model...',
            log: ['Queued VScorer analysis.', 'Rescoring vulnerabilities against the threat model...'],
            scope: 'latest_only',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            llm_enrichment: {
                enabled: true,
                ollama_model: 'llama3.1:8b',
            },
            created_at: nowSeconds - 600,
            updated_at: nowSeconds - 300,
            completed_at: null,
            result: null,
        } as any)
        vi.mocked(resumeVScorerAnalysis).mockResolvedValue({
            session_id: 'session-1',
            status: 'completed',
            total_cves: 2,
            rescored_count: 1,
            avg_score_reduction: 0.4,
            elapsed_seconds: 1.2,
            scope: 'latest_only',
            recommended_scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            sbom_component_count: 3,
            sbom_vulnerability_count: 2,
            strategy_note: 'Latest-only analysis is limited to the newest version and does not account for vulnerabilities seen only in older releases.',
            download_urls: {
                json: '/api/vscorer/sessions/session-1/results/json',
                vex: '/api/vscorer/sessions/session-1/results/vex',
            },
            outputs: {},
        } as any)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })
        await flushPromises()

        expect(getVScorerProjectState).toHaveBeenCalledWith('ExampleApp')
        expect(resumeVScorerAnalysis).toHaveBeenCalledWith(
            'session-1',
            expect.objectContaining({ scope: 'latest_only', status: 'running' }),
            expect.objectContaining({ onAnalysisProgress: expect.any(Function) }),
        )
        expect(getVScorerSyntheticSbomDownloadUrl).toHaveBeenLastCalledWith('ExampleApp', 'latest_only')
        expect(wrapper.get('[data-testid="analysis-sbom-summary-components"]').text()).toBe('3')
        expect(wrapper.get('[data-testid="cached-analysis-state-meta"]').text()).toContain('Latest Version')
        expect(wrapper.get('[data-testid="cached-analysis-state-meta"]').text()).toContain('1.10.0')
        expect(wrapper.get('[data-testid="cached-analysis-state-meta"]').text()).toContain('Last Updated')
        expect(wrapper.get('[data-testid="cached-analysis-state-meta"]').text()).toContain('5 minutes ago')
        expect(wrapper.text()).toContain('Analysis Result')
        expect(wrapper.text()).toContain('session-1')

        vi.mocked(getVScorerProjectState).mockResolvedValueOnce({
            session_id: 'session-1',
            status: 'completed',
            progress: 100,
            message: 'VScorer analysis completed.',
            log: ['VScorer analysis completed.'],
            scope: 'latest_only',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            llm_enrichment: {
                enabled: true,
                ollama_model: 'llama3.1:8b',
            },
            created_at: nowSeconds - 600,
            updated_at: nowSeconds,
            completed_at: nowSeconds,
            result: {
                session_id: 'session-1',
                status: 'completed',
                total_cves: 2,
                rescored_count: 1,
                avg_score_reduction: 0.4,
                elapsed_seconds: 1.2,
                scope: 'latest_only',
                recommended_scope: 'merged_versions',
                latest_version: '1.10.0',
                analyzed_versions: ['1.10.0'],
                sbom_component_count: 3,
                sbom_vulnerability_count: 2,
                strategy_note: 'Latest-only analysis is limited to the newest version and does not account for vulnerabilities seen only in older releases.',
                download_urls: {
                    json: '/api/vscorer/sessions/session-1/results/json',
                    vex: '/api/vscorer/sessions/session-1/results/vex',
                },
                outputs: {},
            },
        } as any)

        await wrapper.get('[data-testid="refresh-cached-analysis-state"]').trigger('click')
        await flushPromises()

        expect(getVScorerProjectState).toHaveBeenCalledTimes(2)
        expect(wrapper.get('[data-testid="cached-analysis-state-meta"]').text()).toContain('0 seconds ago')
    })

    it('shows a scrolling progress log while loading context', async () => {
        const pendingContext = deferred<any>()
        vi.mocked(getVScorerContext).mockReturnValue(pendingContext.promise)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })

        const log = wrapper.get('[data-testid="vscorer-progress-log"]')
        expect(log.text()).toContain('Opening threat-model analysis page...')
        expect(log.text()).toContain('Loading project versions, VScorer settings, and enrichment options...')

        pendingContext.resolve({
            enabled: true,
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
            ],
            warnings: [],
            llm_enrichment: {
                available: true,
                status: 'available',
                default_model: 'qwen2.5:7b',
                host_configured: true,
                warning: null,
            },
        })
        await flushPromises()

        expect(wrapper.text()).toContain('VScorer Analysis for ExampleApp')
        expect(log.text()).toContain('Preparing merged multi-version synthetic SBOM preview from Dependency-Track data...')
        expect(log.text()).toContain('Prepared SBOM preview for 2 versions with 6 components and 4 vulnerabilities.')
    })

    it('shows a scrolling progress log while loading context', async () => {
        const pendingContext = deferred<any>()
        vi.mocked(getVScorerContext).mockReturnValue(pendingContext.promise)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })

        const log = wrapper.get('[data-testid="vscorer-progress-log"]')
        expect(log.text()).toContain('Opening threat-model analysis page...')
        expect(log.text()).toContain('Loading project versions, VScorer settings, and enrichment options...')

        pendingContext.resolve({
            enabled: true,
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
            ],
            warnings: [],
            llm_enrichment: {
                available: true,
                status: 'available',
                default_model: 'qwen2.5:7b',
                host_configured: true,
                warning: null,
            },
        })
        await flushPromises()

        expect(wrapper.text()).toContain('VScorer Analysis for ExampleApp')
    })

    it('submits analysis once a threat model file is selected', async () => {
        vi.mocked(getVScorerContext).mockResolvedValue({
            enabled: true,
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
            ],
            warnings: [],
            llm_enrichment: {
                available: true,
                status: 'available',
                default_model: 'qwen2.5:7b',
                host_configured: true,
                warning: null,
            },
        } as any)
        vi.mocked(runVScorerAnalysis).mockResolvedValue({
            session_id: 'session-1',
            status: 'completed',
            total_cves: 2,
            rescored_count: 1,
            avg_score_reduction: 0.4,
            elapsed_seconds: 1.2,
            scope: 'merged_versions',
            recommended_scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            sbom_component_count: 4,
            sbom_vulnerability_count: 2,
            strategy_note: 'Merged multi-version analysis keeps findings attached.',
            download_urls: {
                json: '/api/vscorer/sessions/session-1/results/json',
                vex: '/api/vscorer/sessions/session-1/results/vex',
            },
            outputs: {},
        } as any)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })

        const input = wrapper.get('[data-testid="threatmodel-input"]')
        const file = new File(['tm7'], 'model.tm7', { type: 'application/octet-stream' })
        Object.defineProperty(input.element, 'files', {
            value: [file],
            configurable: true,
        })
        await input.trigger('change')
        const enrichToggle = wrapper.findAll('input[type="checkbox"]')[3]
        await enrichToggle.setValue(true)
        await wrapper.get('[data-testid="ollama-model-input"]').setValue('llama3.1:8b')
        await wrapper.get('form').trigger('submit.prevent')
        await flushPromises()

        expect(runVScorerAnalysis).toHaveBeenCalledOnce()
        expect(runVScorerAnalysis).toHaveBeenCalledWith('ExampleApp', expect.objectContaining({
            scope: 'merged_versions',
            threatmodel: file,
            enrich: true,
            ollamaModel: 'llama3.1:8b',
        }), expect.objectContaining({
            onUploadProgress: expect.any(Function),
        }))
        expect(wrapper.text()).toContain('Analysis Result')
        expect(wrapper.text()).toContain('session-1')
        expect(window.sessionStorage.getItem('dtvp:vscorer-refresh:ExampleApp')).toBeTruthy()
        expect(window.sessionStorage.getItem('dtvp:tmrescore-refresh:ExampleApp')).toBeTruthy()
        expect(wrapper.getComponent({ name: 'RouterLink' }).props('to')).toBe('/project/ExampleApp')
    })

    it('prepares a VScorer wizard session and runs that prepared session', async () => {
        vi.mocked(getVScorerContext).mockResolvedValue({
            enabled: true,
            wizard_url: 'http://vscorer.local/wizard',
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
            ],
            warnings: [],
            llm_enrichment: {
                available: true,
                status: 'available',
                default_model: 'qwen2.5:7b',
                host_configured: true,
                warning: null,
            },
        } as any)
        vi.mocked(prepareVScorerAnalysis).mockResolvedValue({
            session_id: 'session-prepared',
            status: 'prepared',
            progress: 25,
            message: 'VScorer wizard session prepared.',
            log: ['Created VScorer session.', 'Loaded VScorer wizard context and catalogs.'],
            scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            llm_enrichment: { enabled: false, ollama_model: null },
            result: null,
            wizard_url: 'http://vscorer.local/wizard',
            wizard_context: {
                validation: { summary: { errors: 0, warnings: 1 } },
                threat_model: {
                    elements: [{ guid: 'TM-1', name: 'API' }, { guid: 'TM-2', name: 'DB' }],
                    boundaries: [{ guid: 'B-1', name: 'Internet' }],
                },
                editor: { issues: [{ issue_id: 'issue-1', title: 'Missing authentication', editable: true }] },
            },
            wizard_catalogs: {
                rescoring_rule_types: [{ id: 'attack_vector' }, { id: 'privileges_required' }],
                attack_mitigations: [{ id: 'M1032' }],
            },
        } as any)
        vi.mocked(validatePreparedVScorerWizardInputs).mockResolvedValue({
            session_id: 'session-prepared',
            status: 'prepared',
            progress: 28,
            message: 'Validated VScorer wizard inputs.',
            log: ['Created VScorer session.', 'Validated VScorer wizard inputs.'],
            scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            llm_enrichment: { enabled: false, ollama_model: null },
            result: null,
            wizard_url: 'http://vscorer.local/wizard',
            wizard_context: {
                validation: {
                    summary: { errors: 0, warnings: 0 },
                    reports: [{ artefact: 'threat_model', grade: 'A', ok: true, summary: { errors: 0, warnings: 0 } }],
                },
                threat_model: {
                    elements: [{ guid: 'TM-1', name: 'API' }, { guid: 'TM-2', name: 'DB' }],
                    boundaries: [{ guid: 'B-1', name: 'Internet' }],
                },
                editor: { issues: [{ issue_id: 'issue-1', title: 'Missing authentication', editable: true }] },
            },
            wizard_catalogs: {
                rescoring_rule_types: [{ id: 'attack_vector' }, { id: 'privileges_required' }],
                attack_mitigations: [{ id: 'M1032' }],
            },
        } as any)
        vi.mocked(getPreparedVScorerWizardEditor).mockResolvedValue({
            session_id: 'session-prepared',
            status: 'prepared',
            progress: 28,
            message: 'Loaded VScorer threat-model editor state.',
            log: ['Created VScorer session.', 'Loaded VScorer threat-model editor state.'],
            scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            llm_enrichment: { enabled: false, ollama_model: null },
            result: null,
            wizard_url: 'http://vscorer.local/wizard',
            wizard_context: {
                validation: {
                    summary: { errors: 0, warnings: 0 },
                    reports: [{ artefact: 'threat_model', grade: 'A', ok: true, summary: { errors: 0, warnings: 0 } }],
                },
                threat_model: {
                    elements: [{ guid: 'TM-1', name: 'API' }, { guid: 'TM-2', name: 'DB' }],
                    boundaries: [{ guid: 'B-1', name: 'Internet' }],
                },
                threat_model_editor: {
                    issues: [{
                        issue_id: 'issue-1',
                        title: 'Missing authentication',
                        message: 'Set or keep this issue.',
                        target_type: 'element',
                        target_id: 'TM-1',
                        editable: true,
                    }],
                },
            },
            wizard_catalogs: {
                rescoring_rule_types: [{ id: 'attack_vector' }, { id: 'privileges_required' }],
                attack_mitigations: [{ id: 'M1032' }],
            },
        } as any)
        vi.mocked(patchPreparedVScorerWizardEditor).mockResolvedValue({
            session_id: 'session-prepared',
            status: 'prepared',
            progress: 30,
            message: 'Updated VScorer threat-model editor state.',
            log: ['Created VScorer session.', 'Updated VScorer threat-model editor state.'],
            scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            llm_enrichment: { enabled: false, ollama_model: null },
            result: null,
            wizard_url: 'http://vscorer.local/wizard',
            wizard_context: {
                validation: {
                    summary: { errors: 0, warnings: 0 },
                    reports: [{ artefact: 'threat_model', grade: 'A', ok: true, summary: { errors: 0, warnings: 0 } }],
                },
                threat_model: {
                    elements: [{ guid: 'TM-1', name: 'API' }, { guid: 'TM-2', name: 'DB' }],
                    boundaries: [{ guid: 'B-1', name: 'Internet' }],
                },
                editor: {
                    issues: [{
                        issue_id: 'issue-1',
                        title: 'Missing authentication',
                        message: 'Set or keep this issue.',
                        target_type: 'element',
                        target_id: 'TM-1',
                        editable: true,
                        kept: true,
                    }],
                },
            },
            wizard_catalogs: {
                rescoring_rule_types: [{ id: 'attack_vector' }, { id: 'privileges_required' }],
                attack_mitigations: [{ id: 'M1032' }],
            },
        } as any)
        vi.mocked(refreshPreparedVScorerWizardContext).mockResolvedValue({
            session_id: 'session-prepared',
            status: 'prepared',
            progress: 25,
            message: 'Refreshed VScorer wizard context.',
            log: ['Created VScorer session.', 'Refreshed VScorer wizard context.'],
            scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            llm_enrichment: { enabled: false, ollama_model: null },
            result: null,
            wizard_url: 'http://vscorer.local/wizard',
            wizard_context: {
                validation: { summary: { errors: 0, warnings: 0 } },
                threat_model: {
                    elements: [
                        { guid: 'TM-1', name: 'API' },
                        { guid: 'TM-2', name: 'DB' },
                        { guid: 'TM-3', name: 'Worker' },
                    ],
                    boundaries: [{ guid: 'B-1', name: 'Internet' }],
                },
                editor: { issues: [] },
            },
            wizard_catalogs: {
                rescoring_rule_types: [{ id: 'attack_vector' }, { id: 'privileges_required' }, { id: 'user_interaction' }],
                attack_mitigations: [{ id: 'M1032' }],
            },
        } as any)
        vi.mocked(runPreparedVScorerAnalysis).mockResolvedValue({
            session_id: 'session-prepared',
            status: 'completed',
            total_cves: 2,
            rescored_count: 1,
            avg_score_reduction: 0.4,
            elapsed_seconds: 1.2,
            scope: 'merged_versions',
            recommended_scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            sbom_component_count: 4,
            sbom_vulnerability_count: 2,
            strategy_note: 'Merged multi-version analysis keeps findings attached.',
            download_urls: {
                json: '/api/vscorer/sessions/session-prepared/results/json',
                vex: '/api/vscorer/sessions/session-prepared/results/vex',
            },
            outputs: {},
        } as any)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })
        await flushPromises()

        const input = wrapper.get('[data-testid="threatmodel-input"]')
        const file = new File(['tm7'], 'model.tm7', { type: 'application/octet-stream' })
        Object.defineProperty(input.element, 'files', {
            value: [file],
            configurable: true,
        })
        await input.trigger('change')
        await wrapper.get('[data-testid="prepare-vscorer-wizard"]').trigger('click')
        await flushPromises()

        expect(prepareVScorerAnalysis).toHaveBeenCalledWith('ExampleApp', expect.objectContaining({
            scope: 'merged_versions',
            threatmodel: file,
        }), expect.objectContaining({
            onUploadProgress: expect.any(Function),
        }))
        expect(wrapper.get('[data-testid="vscorer-wizard-summary"]').text()).toContain('session-prepared')
        expect(wrapper.get('[data-testid="vscorer-wizard-validation"]').text()).toContain('0 errors / 1 warnings')
        expect(wrapper.get('[data-testid="vscorer-wizard-threatmodel"]').text()).toContain('2 elements / 1 boundaries')
        expect(wrapper.get('[data-testid="vscorer-wizard-editor-issues"]').text()).toContain('1 open / 1 total')
        expect(wrapper.get('[data-testid="vscorer-wizard-rule-types"]').text()).toBe('2')
        expect(wrapper.get('[data-testid="download-prepared-vscorer-threatmodel"]').attributes('href')).toBe('/api/vscorer/sessions/session-prepared/wizard/threatmodel')
        expect(wrapper.get('[data-testid="run-vscorer-analysis"]').text()).toContain('Run Prepared VScorer Analysis')

        await wrapper.get('[data-testid="validate-vscorer-wizard-inputs"]').trigger('click')
        await flushPromises()

        expect(validatePreparedVScorerWizardInputs).toHaveBeenCalledWith('session-prepared')
        expect(wrapper.get('[data-testid="vscorer-wizard-validation"]').text()).toContain('0 errors / 0 warnings')
        expect(wrapper.get('[data-testid="vscorer-wizard-validation-reports"]').text()).toContain('threat_model')
        expect(wrapper.get('[data-testid="vscorer-wizard-validation-reports"]').text()).toContain('A')

        await wrapper.get('[data-testid="load-vscorer-wizard-editor"]').trigger('click')
        await flushPromises()

        expect(getPreparedVScorerWizardEditor).toHaveBeenCalledWith('session-prepared')
        expect(wrapper.get('[data-testid="vscorer-wizard-editor-list"]').text()).toContain('Missing authentication')
        expect(wrapper.get('[data-testid="vscorer-wizard-editor-list"]').text()).toContain('TM-1')

        await wrapper.get('[data-testid="keep-vscorer-editor-issue-issue-1"]').trigger('click')
        await flushPromises()

        expect(patchPreparedVScorerWizardEditor).toHaveBeenCalledWith('session-prepared', [expect.objectContaining({
            issue_id: 'issue-1',
            action: 'keep',
        })])
        expect(wrapper.get('[data-testid="vscorer-wizard-editor-issues"]').text()).toContain('0 open / 1 total')
        expect(wrapper.get('[data-testid="vscorer-wizard-editor-list"]').text()).toContain('Kept')

        await wrapper.get('[data-testid="refresh-vscorer-wizard-context"]').trigger('click')
        await flushPromises()

        expect(refreshPreparedVScorerWizardContext).toHaveBeenCalledWith('session-prepared')
        expect(wrapper.get('[data-testid="vscorer-wizard-validation"]').text()).toContain('0 errors / 0 warnings')
        expect(wrapper.get('[data-testid="vscorer-wizard-threatmodel"]').text()).toContain('3 elements / 1 boundaries')
        expect(wrapper.get('[data-testid="vscorer-wizard-rule-types"]').text()).toBe('3')

        await wrapper.get('form').trigger('submit.prevent')
        await flushPromises()

        expect(runPreparedVScorerAnalysis).toHaveBeenCalledWith('session-prepared', expect.objectContaining({
            chainAnalysis: true,
            prioritize: true,
            enrich: false,
        }), expect.objectContaining({
            onAnalysisProgress: expect.any(Function),
        }))
        expect(runVScorerAnalysis).not.toHaveBeenCalled()
        expect(wrapper.text()).toContain('Analysis Result')
        expect(wrapper.text()).toContain('session-prepared')
    })

    it('shows a scrolling progress log while analysis is running', async () => {
        vi.mocked(getVScorerContext).mockResolvedValue({
            enabled: true,
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
            ],
            warnings: [],
            llm_enrichment: {
                available: true,
                status: 'available',
                default_model: 'qwen2.5:7b',
                host_configured: true,
                warning: null,
            },
        } as any)

        const pendingAnalysis = deferred<any>()
        vi.mocked(runVScorerAnalysis).mockReturnValue(pendingAnalysis.promise)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })
        await flushPromises()

        const input = wrapper.get('[data-testid="threatmodel-input"]')
        const file = new File(['tm7'], 'model.tm7', { type: 'application/octet-stream' })
        Object.defineProperty(input.element, 'files', {
            value: [file],
            configurable: true,
        })
        await input.trigger('change')
        await wrapper.get('form').trigger('submit.prevent')
        await wrapper.vm.$nextTick()

        const log = wrapper.get('[data-testid="vscorer-progress-log"]')
        expect(log.text()).toContain('Preparing VScorer analysis request...')
        expect(log.text()).toContain('Uploading threat model and analysis inputs...')

        pendingAnalysis.resolve({
            session_id: 'session-1',
            status: 'completed',
            total_cves: 2,
            rescored_count: 1,
            avg_score_reduction: 0.4,
            elapsed_seconds: 1.2,
            scope: 'merged_versions',
            recommended_scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            sbom_component_count: 4,
            sbom_vulnerability_count: 2,
            strategy_note: 'Merged multi-version analysis keeps findings attached.',
            download_urls: {
                json: '/api/vscorer/sessions/session-1/results/json',
                vex: '/api/vscorer/sessions/session-1/results/vex',
            },
            outputs: {},
        })
        await flushPromises()

        expect(wrapper.text()).toContain('Analysis completed. 1 of 2 CVEs were rescored.')
    })

    it('shows a scrolling progress log while analysis is running', async () => {
        vi.mocked(getVScorerContext).mockResolvedValue({
            enabled: true,
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
            ],
            warnings: [],
            llm_enrichment: {
                available: true,
                status: 'available',
                default_model: 'qwen2.5:7b',
                host_configured: true,
                warning: null,
            },
        } as any)

        const pendingAnalysis = deferred<any>()
        vi.mocked(runVScorerAnalysis).mockReturnValue(pendingAnalysis.promise)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })
        await flushPromises()

        const input = wrapper.get('[data-testid="threatmodel-input"]')
        const file = new File(['tm7'], 'model.tm7', { type: 'application/octet-stream' })
        Object.defineProperty(input.element, 'files', {
            value: [file],
            configurable: true,
        })
        await input.trigger('change')
        await wrapper.get('form').trigger('submit.prevent')
        await wrapper.vm.$nextTick()

        const log = wrapper.get('[data-testid="vscorer-progress-log"]')
        expect(log.text()).toContain('Preparing VScorer analysis request...')
        expect(log.text()).toContain('Uploading threat model and analysis inputs...')

        pendingAnalysis.resolve({
            session_id: 'session-1',
            status: 'completed',
            total_cves: 2,
            rescored_count: 1,
            avg_score_reduction: 0.4,
            elapsed_seconds: 1.2,
            scope: 'merged_versions',
            recommended_scope: 'merged_versions',
            latest_version: '1.10.0',
            analyzed_versions: ['1.10.0'],
            sbom_component_count: 4,
            sbom_vulnerability_count: 2,
            strategy_note: 'Merged multi-version analysis keeps findings attached.',
            download_urls: {
                json: '/api/vscorer/sessions/session-1/results/json',
                vex: '/api/vscorer/sessions/session-1/results/vex',
            },
            outputs: {},
        })
        await flushPromises()

        expect(wrapper.text()).toContain('Analysis completed. 1 of 2 CVEs were rescored.')
    })

    it('renders unavailable when remote enrichment status cannot be verified', async () => {
        vi.mocked(getVScorerContext).mockResolvedValue({
            enabled: true,
            project_name: 'ExampleApp',
            latest_version: '1.10.0',
            versions: ['1.10.0'],
            recommended_scope: 'merged_versions',
            scopes: [
                { id: 'merged_versions', label: 'Merged Multi-Version SBOM', description: 'Recommended scope' },
            ],
            warnings: [],
            llm_enrichment: {
                available: false,
                status: 'unreachable',
                default_model: 'qwen2.5:7b',
                host_configured: false,
                warning: 'Could not verify LLM enrichment availability from the VScorer backend.',
            },
        } as any)

        const { wrapper } = await mountWithRouter(VScorer, {
            initialPath: '/project/ExampleApp/vscorer',
            routes: vscorerRoutes,
        })

        expect(wrapper.get('[data-testid="llm-enrichment-status"]').text()).toBe('Unavailable')
        expect(wrapper.text()).toContain('Could not verify LLM enrichment availability from the VScorer backend.')
        expect((wrapper.get('[data-testid="ollama-model-input"]').element as HTMLInputElement).disabled).toBe(true)
    })
})
