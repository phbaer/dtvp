import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'

const axiosMocks = vi.hoisted(() => ({
    get: vi.fn(),
    post: vi.fn(),
}))

vi.mock('axios', () => {
    return {
        default: {
            create: vi.fn(() => ({
                get: axiosMocks.get,
                post: axiosMocks.post,
                interceptors: {
                    request: { use: vi.fn(), eject: vi.fn() },
                    response: { use: vi.fn(), eject: vi.fn() },
                },
            })),
            get: axiosMocks.get,
        },
    }
})

describe('TMRescore integration via api.ts', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.resetModules()
        ;(window as any).__env__ = {
            DTVP_CONTEXT_PATH: '/',
            DTVP_API_URL: '',
            DTVP_FRONTEND_URL: '',
        }
    })

    it('loads context and submits analysis through the real API layer', async () => {
        axiosMocks.get.mockResolvedValueOnce({
            data: {
                enabled: true,
                project_name: 'ExampleApp',
                latest_version: '1.10.0',
                versions: ['1.9.0', '1.10.0'],
                recommended_scope: 'merged_versions',
                scopes: [
                    {
                        id: 'merged_versions',
                        label: 'Merged Multi-Version SBOM',
                        description: 'Recommended scope',
                    },
                    {
                        id: 'latest_only',
                        label: 'Latest Version Only',
                        description: 'Single-version scope',
                    },
                ],
                warnings: ['Do not combine latest SBOM with historical vulnerabilities.'],
                llm_enrichment: {
                    available: true,
                    status: 'available',
                    default_model: 'qwen2.5:7b',
                    host_configured: true,
                    warning: null,
                },
            },
        })

        axiosMocks.post.mockResolvedValueOnce({
            data: {
                session_id: 'session-1',
                status: 'completed',
                total_cves: 2,
                rescored_count: 2,
                avg_score_reduction: 0.6,
                elapsed_seconds: 1.4,
                scope: 'merged_versions',
                recommended_scope: 'merged_versions',
                latest_version: '1.10.0',
                analyzed_versions: ['1.9.0', '1.10.0'],
                sbom_component_count: 5,
                sbom_vulnerability_count: 2,
                strategy_note: 'Merged multi-version analysis keeps findings attached.',
                download_urls: {
                    json: '/api/tmrescore/sessions/session-1/results/json',
                    vex: '/api/tmrescore/sessions/session-1/results/vex',
                },
                outputs: {
                    'enriched-sbom.json': { size: 1234, content_type: 'application/json' },
                },
            },
        })

        const module = await import('../TMRescore.vue')
        const TMRescore = module.default

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

        expect(axiosMocks.get).toHaveBeenCalledWith('/projects/ExampleApp/tmrescore/context')
        expect(wrapper.text()).toContain('Merged Multi-Version SBOM')

        const input = wrapper.get('[data-testid="threatmodel-input"]')
        const file = new File(['tm7'], 'model.tm7', { type: 'application/octet-stream' })
        Object.defineProperty(input.element, 'files', {
            value: [file],
            configurable: true,
        })
        await input.trigger('change')
        const enrichToggle = wrapper.findAll('input[type="checkbox"]')[3]
        await enrichToggle.setValue(true)
        await wrapper.get('[data-testid="ollama-model-input"]').setValue('qwen2.5:14b')
        await wrapper.get('form').trigger('submit.prevent')
        await flushPromises()

        expect(axiosMocks.post).toHaveBeenCalledTimes(1)
        expect(axiosMocks.post.mock.calls[0]?.[0]).toBe('/projects/ExampleApp/tmrescore/analyze')
        expect(axiosMocks.post.mock.calls[0]?.[1]).toBeInstanceOf(FormData)
        const payload = axiosMocks.post.mock.calls[0]?.[1] as FormData
        expect(payload.get('enrich')).toBe('true')
        expect(payload.get('ollama_model')).toBe('qwen2.5:14b')
        expect(wrapper.text()).toContain('Analysis Result')
        expect(wrapper.text()).toContain('session-1')
        expect(wrapper.text()).toContain('enriched-sbom.json')
    })
})