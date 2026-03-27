import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import TMRescore from '../TMRescore.vue'
import { getTMRescoreContext, runTMRescoreAnalysis } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getTMRescoreContext: vi.fn(),
    runTMRescoreAnalysis: vi.fn(),
}))

describe('TMRescore.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        window.sessionStorage.clear()
    })

    it('loads context and renders recommended scope', async () => {
        vi.mocked(getTMRescoreContext).mockResolvedValue({
            enabled: true,
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

        const router = createRouter({
            history: createMemoryHistory(),
            routes: [
                { path: '/project/:name', component: { template: '<div />' } },
                { path: '/project/:name/tmrescore', component: TMRescore },
            ],
        })

        router.push('/project/ExampleApp/tmrescore')
        await router.isReady()

        const wrapper = mount(TMRescore, {
            global: {
                plugins: [router],
            },
        })

        await flushPromises()

        expect(getTMRescoreContext).toHaveBeenCalledWith('ExampleApp')
        expect(wrapper.text()).toContain('Merged Multi-Version SBOM')
        expect(wrapper.text()).toContain('Recommended')
        expect(wrapper.text()).toContain('1.10.0')
        expect(wrapper.text()).toContain('LLM enrichment')
        expect(wrapper.get('[data-testid="llm-enrichment-status"]').text()).toBe('Available')
        expect((wrapper.get('[data-testid="ollama-model-input"]').element as HTMLInputElement).value).toBe('qwen2.5:14b')
    })

    it('submits analysis once a threat model file is selected', async () => {
        vi.mocked(getTMRescoreContext).mockResolvedValue({
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
        vi.mocked(runTMRescoreAnalysis).mockResolvedValue({
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
                json: '/api/tmrescore/sessions/session-1/results/json',
                vex: '/api/tmrescore/sessions/session-1/results/vex',
            },
            outputs: {},
        } as any)

        const router = createRouter({
            history: createMemoryHistory(),
            routes: [
                { path: '/project/:name', component: { template: '<div />' } },
                { path: '/project/:name/tmrescore', component: TMRescore },
            ],
        })

        router.push('/project/ExampleApp/tmrescore')
        await router.isReady()

        const wrapper = mount(TMRescore, {
            global: {
                plugins: [router],
            },
        })

        await flushPromises()

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

        expect(runTMRescoreAnalysis).toHaveBeenCalledOnce()
        expect(runTMRescoreAnalysis).toHaveBeenCalledWith('ExampleApp', expect.objectContaining({
            scope: 'merged_versions',
            threatmodel: file,
            enrich: true,
            ollamaModel: 'llama3.1:8b',
        }))
        expect(wrapper.text()).toContain('Analysis Result')
        expect(wrapper.text()).toContain('session-1')
        expect(window.sessionStorage.getItem('dtvp:tmrescore-refresh:ExampleApp')).toBeTruthy()
        expect(wrapper.getComponent({ name: 'RouterLink' }).props('to')).toBe('/project/ExampleApp?refreshThreatModel=1')
    })

    it('renders unavailable when remote enrichment status cannot be verified', async () => {
        vi.mocked(getTMRescoreContext).mockResolvedValue({
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
                warning: 'Could not verify LLM enrichment availability from the tmrescore backend.',
            },
        } as any)

        const router = createRouter({
            history: createMemoryHistory(),
            routes: [
                { path: '/project/:name', component: { template: '<div />' } },
                { path: '/project/:name/tmrescore', component: TMRescore },
            ],
        })

        router.push('/project/ExampleApp/tmrescore')
        await router.isReady()

        const wrapper = mount(TMRescore, {
            global: {
                plugins: [router],
            },
        })

        await flushPromises()

        expect(wrapper.get('[data-testid="llm-enrichment-status"]').text()).toBe('Unavailable')
        expect(wrapper.text()).toContain('Could not verify LLM enrichment availability from the tmrescore backend.')
        expect((wrapper.get('[data-testid="ollama-model-input"]').element as HTMLInputElement).disabled).toBe(true)
    })
})