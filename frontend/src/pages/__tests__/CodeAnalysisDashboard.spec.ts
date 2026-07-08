import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { nextTick } from 'vue'
import CodeAnalysisDashboard from '../CodeAnalysisDashboard.vue'
import {
    analysisQueueCancel,
    analysisQueueCancelQueued,
    analysisQueueClear,
    codeAnalysisGetDashboardStatus,
} from '../../lib/api'

vi.mock('../../lib/api', () => ({
    analysisQueueCancel: vi.fn(),
    analysisQueueCancelQueued: vi.fn(),
    analysisQueueClear: vi.fn(),
    codeAnalysisGetDashboardStatus: vi.fn(),
    codeAnalysisRunAutoSweep: vi.fn(),
}))

const dashboardStatus = {
    overall_state: 'running',
    updated_at: '2026-07-02T10:00:00Z',
    configured: true,
    result_cache: {
        record_count: 12,
        max_records: 2000,
        retention_days: 90,
        freshness_days: 30,
        store_guidance: false,
        path: '/data/code_analysis_results.json',
    },
    queue: {
        capacity: 1,
        running_count: 1,
        available_slots: 0,
        dtvp_worker_busy: true,
        waiting_for_slot: true,
        counts_by_status: { running: 1, queued: 1, completed: 1 },
        counts_by_source: { automatic: 1, manual: 2 },
        active_item: null,
        items: [
            {
                queue_id: 'queue-running',
                vuln_id: 'CVE-2026-0001',
                component_name: 'owned-service',
                project_name: 'ExampleApp',
                source: 'automatic',
                submitted_by: 'tester',
                submitted_at: '2026-07-02T09:59:00Z',
                status: 'running',
                position: 0,
                job_id: 'job-1',
                model: 'gpt-4o',
                llm_backend: 'openwebui',
                llm_provider: 'OpenWebUI',
                logs: [
                    'DTVP started scan',
                    'running code_scanner: Scanning source',
                    'warning Analyzer waiting for repository checkout',
                    'error Repository unavailable',
                ],
                progress: {
                    completed_steps: 2,
                    total_steps: 4,
                    percent: 50,
                    current_activity: 'Scanning source',
                },
            },
            {
                queue_id: 'queue-queued',
                vuln_id: 'CVE-2026-0002',
                component_name: 'owned-worker',
                source: 'manual',
                submitted_by: 'tester',
                submitted_at: '2026-07-02T09:58:00Z',
                status: 'queued',
                position: 1,
            },
            {
                queue_id: 'queue-done',
                vuln_id: 'CVE-2026-0003',
                component_name: 'owned-ui',
                source: 'manual',
                submitted_by: 'tester',
                submitted_at: '2026-07-02T09:57:00Z',
                status: 'completed',
                position: 0,
            },
        ],
    },
    recent_results: [
        {
            analysis_run_id: 'run-1',
            queue_id: 'queue-done',
            job_id: 'job-done',
            vuln_id: 'CVE-2026-0003',
            component_name: 'owned-ui',
            project_name: 'ExampleApp',
            source: 'manual',
            finished_at: '2026-07-02T10:02:00Z',
            summary: {
                affected: false,
                verdict: 'Not Affected',
                confidence: 'High',
                exposure: 'none',
                summary: 'No vulnerable path',
            },
        },
    ],
    auto_sweep: {
        enabled: true,
        code_analysis_configured: true,
        active: true,
        interval_seconds: 900,
        running: false,
        last_started_at: '2026-07-02T09:00:00Z',
        last_finished_at: '2026-07-02T09:01:00Z',
        last_queued_count: 2,
        last_error: null,
        last_trigger: 'scheduled',
        next_run_at: '2026-07-02T09:16:00Z',
    },
    external: {
        health: {
            status: 'ok',
            configuration: {
                service_name: 'agentyzer',
                service_version: '0.4.0',
                config_dir: '/etc/agentyzer',
                repos_config_path: '/etc/agentyzer/repos.yaml',
                repositories: {
                    workspace_dir: '/srv/agentyzer/repos',
                    component_count: 4,
                    default_template_configured: true,
                },
                features: {
                    job_logs: true,
                    running_abort: true,
                },
            },
            backend: {
                llm: {
                    provider: 'OpenWebUI',
                    backend: 'openwebui',
                    host: 'http://openwebui.local',
                    model: 'gpt-4o',
                    healthy: true,
                    supports_model_override: true,
                },
                repositories: {
                    workspace_dir: '/srv/agentyzer/repos',
                    reuse_strategy: 'existing-checkout',
                    update_strategy: 'fetch',
                },
                jobs: {
                    job_store: 'sqlite',
                    known_jobs: 3,
                    max_concurrent_jobs: 2,
                    running_jobs: 1,
                    queued_jobs: 1,
                    available_slots: 1,
                    status_counts: { pending: 1, running: 1, completed: 2 },
                },
            },
        },
        health_error: null,
        jobs: [
            {
                job_id: 'job-1',
                status: 'running',
                created_at: '2026-07-02T09:59:10Z',
                progress: { completed_steps: 2, total_steps: 4, percent: 50 },
                request: {
                    component_name: 'owned-service',
                    vuln_id: 'CVE-2026-0001',
                },
                model: 'gpt-4o',
                llm_backend: 'openwebui',
                llm_provider: 'OpenWebUI',
            },
        ],
        jobs_error: null,
        configuration: {
            service_name: 'agentyzer',
            service_version: '0.4.0',
            config_dir: '/etc/agentyzer',
            repos_config_path: '/etc/agentyzer/repos.yaml',
            repositories: {
                workspace_dir: '/srv/agentyzer/repos',
                component_count: 4,
                default_template_configured: true,
            },
            features: {
                job_logs: true,
                running_abort: true,
            },
        },
        backend: {
            llm: {
                provider: 'OpenWebUI',
                backend: 'openwebui',
                host: 'http://openwebui.local',
                model: 'gpt-4o',
                healthy: true,
                supports_model_override: true,
            },
            repositories: {
                workspace_dir: '/srv/agentyzer/repos',
                reuse_strategy: 'existing-checkout',
                update_strategy: 'fetch',
            },
            jobs: {
                job_store: 'sqlite',
                known_jobs: 3,
                max_concurrent_jobs: 2,
                running_jobs: 1,
                queued_jobs: 1,
                available_slots: 1,
                status_counts: { pending: 1, running: 1, completed: 2 },
            },
        },
        busy: true,
        capacity: 2,
        running_jobs: 1,
        queued_jobs: 1,
        available_slots: 1,
    },
    active_agents: [
        {
            step: 'scan_code',
            title: 'Code Scan',
            agent: 'code_scanner',
            activity: 'Scanning source',
            status: 'running',
        },
    ],
    model: 'gpt-4o',
    model_source: 'queue',
    llm_backend: 'openwebui',
    llm_backend_source: 'queue',
    llm_provider: 'OpenWebUI',
    llm_provider_source: 'queue',
}

const RouterLinkStub = {
    props: ['to'],
    computed: {
        href(): string {
            const to = (this as any).to
            if (typeof to === 'string') return to
            const path = to?.path || ''
            const query = to?.query ? `?${new URLSearchParams(to.query).toString()}` : ''
            return `${path}${query}`
        },
    },
    template: '<a :href="href"><slot /></a>',
}

const mountDashboard = () => mount(CodeAnalysisDashboard, {
    global: {
        stubs: {
            RouterLink: RouterLinkStub,
        },
    },
})

describe('CodeAnalysisDashboard.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(codeAnalysisGetDashboardStatus).mockResolvedValue(dashboardStatus as any)
        vi.mocked(analysisQueueCancel).mockResolvedValue({ status: 'cancelled' })
        vi.mocked(analysisQueueCancelQueued).mockResolvedValue({ status: 'cancelled', cancelled: 1 })
        vi.mocked(analysisQueueClear).mockResolvedValue({ status: 'cleared', removed: 1 })
    })

    it('renders queue, external, agent, and model status', async () => {
        const wrapper = mountDashboard()
        await flushPromises()

        expect(wrapper.text()).toContain('Code Analysis')
        expect(wrapper.text()).toContain('Busy')
        expect(wrapper.text()).toContain('waiting for slot')
        expect(wrapper.text()).toContain('gpt-4o')
        expect(wrapper.text()).toContain('OpenWebUI')
        expect(wrapper.text()).toContain('Scanning source')
        expect(wrapper.text()).toContain('owned-service')
        expect(wrapper.text()).toContain('Code Scan')
        expect(wrapper.text()).toContain('job-1')
        expect(wrapper.text()).toContain('Analyzer Configuration')
        expect(wrapper.text()).toContain('/etc/agentyzer/repos.yaml')
        expect(wrapper.text()).toContain('/srv/agentyzer/repos')
        expect(wrapper.text()).toContain('Analyzer Backend')
        expect(wrapper.text()).toContain('Result Cache')
        expect(wrapper.text()).toContain('12 saved runs')
        expect(wrapper.text()).toContain('redacted')
        expect(wrapper.text()).toContain('http://openwebui.local')
        expect(wrapper.text()).toContain('sqlite')
        expect(wrapper.text()).toContain('1 analyzer slots free')
        expect(wrapper.text()).toContain('Slots free')
        expect(wrapper.text()).toContain('ExampleApp')
        expect(wrapper.get('[data-testid="queue-open-vuln-queue-running"]').attributes('href')).toBe('/project/ExampleApp?vuln=CVE-2026-0001')
        expect(wrapper.text()).toContain('Latest Results')
        expect(wrapper.text()).toContain('Not Affected')
        expect(wrapper.get('[data-testid="result-open-vuln-run-1"]').attributes('href')).toBe('/project/ExampleApp?vuln=CVE-2026-0003')

        wrapper.unmount()
    })

    it('calls queue control APIs from dashboard actions', async () => {
        const wrapper = mountDashboard()
        await flushPromises()

        await wrapper.findAll('button').find(button => button.text().includes('Cancel queued'))?.trigger('click')
        await flushPromises()
        await wrapper.findAll('button').find(button => button.text().includes('Clear finished'))?.trigger('click')
        await flushPromises()
        await wrapper.findAll('button').find(button => button.text().includes('Abort'))?.trigger('click')
        await flushPromises()

        expect(analysisQueueCancelQueued).toHaveBeenCalledTimes(1)
        expect(analysisQueueClear).toHaveBeenCalledTimes(1)
        expect(analysisQueueCancel).toHaveBeenCalledWith('queue-running')

        wrapper.unmount()
    })

    it('shows structured scan logs on request below a queue item', async () => {
        const wrapper = mountDashboard()
        await flushPromises()

        expect(wrapper.find('[data-testid="queue-log-panel-queue-running"]').exists()).toBe(false)
        expect(wrapper.text()).not.toContain('Repository unavailable')

        await wrapper.find('[data-testid="queue-log-toggle-queue-running"]').trigger('click')
        await flushPromises()

        const panel = wrapper.find('[data-testid="queue-log-panel-queue-running"]')
        expect(panel.exists()).toBe(true)
        expect(panel.element.closest('td')?.getAttribute('colspan')).toBe('7')
        expect(panel.text()).toContain('Scan Log')
        expect(panel.text()).toContain('DTVP started scan')
        expect(panel.text()).toContain('Repository unavailable')
        expect(panel.find('[data-log-level="running"]').exists()).toBe(true)
        expect(panel.find('[data-log-level="warning"]').exists()).toBe(true)
        expect(panel.find('[data-log-level="error"]').exists()).toBe(true)

        const logEntries = panel.findAll('[data-testid="queue-log-entry-queue-running"]')
        expect(logEntries.length).toBeGreaterThan(0)
        for (const entry of logEntries) {
            expect(entry.classes()).not.toContain('border')
            expect(entry.classes()).not.toContain('rounded')
            expect(entry.classes().some(className => className.startsWith('bg-'))).toBe(false)
        }

        wrapper.unmount()
    })

    it('keeps expanded scan logs scrolled to the newest line', async () => {
        const originalScrollHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollHeight')
        Object.defineProperty(HTMLElement.prototype, 'scrollHeight', {
            configurable: true,
            get() {
                return this.getAttribute('data-testid') === 'queue-log-scroll-queue-running' ? 720 : 0
            },
        })

        try {
            const wrapper = mountDashboard()
            await flushPromises()

            await wrapper.find('[data-testid="queue-log-toggle-queue-running"]').trigger('click')
            await flushPromises()
            await nextTick()

            const scrollElement = wrapper.get('[data-testid="queue-log-scroll-queue-running"]').element as HTMLElement
            expect(scrollElement.scrollTop).toBe(720)

            scrollElement.scrollTop = 0
            await wrapper.findAll('button').find(button => button.text().includes('Refresh'))?.trigger('click')
            await flushPromises()
            await nextTick()

            expect(scrollElement.scrollTop).toBe(720)

            wrapper.unmount()
        } finally {
            if (originalScrollHeight) {
                Object.defineProperty(HTMLElement.prototype, 'scrollHeight', originalScrollHeight)
            } else {
                delete (HTMLElement.prototype as any).scrollHeight
            }
        }
    })
})
