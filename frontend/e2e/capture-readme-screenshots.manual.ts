import { test, expect, type Locator, type Page } from '@playwright/test'

const mockProjects = [
    { name: 'TestProject', uuid: 'p1', version: '2.0.0', classifier: 'APPLICATION' },
    { name: 'TestProject', uuid: 'p2', version: '1.1.0', classifier: 'APPLICATION' },
    { name: 'TestProject', uuid: 'p3', version: '1.0.0', classifier: 'APPLICATION' },
    { name: 'BillingAPI', uuid: 'p4', version: '3.4.1', classifier: 'APPLICATION' },
    { name: 'BillingAPI', uuid: 'p5', version: '3.3.0', classifier: 'APPLICATION' },
    { name: 'shared-runtime', uuid: 'p6', version: '5.2.0', classifier: 'LIBRARY' },
    { name: 'shared-runtime', uuid: 'p7', version: '5.1.4', classifier: 'LIBRARY' },
]

const mockStatistics = {
    severity_counts: {
        CRITICAL: 4,
        HIGH: 8,
        MEDIUM: 4,
        LOW: 1,
        INFO: 1,
        UNKNOWN: 0,
    },
    state_counts: {
        EXPLOITABLE: 3,
        IN_TRIAGE: 6,
        FALSE_POSITIVE: 2,
        NOT_AFFECTED: 3,
        RESOLVED: 2,
        NOT_SET: 3,
        MIXED: 2,
    },
    total_unique: 18,
    total_findings: 32,
    affected_projects_count: 3,
    version_counts: {
        '1.0.0': 9,
        '1.1.0': 8,
        '2.0.0': 10,
    },
    major_version_counts: {
        '1': 17,
        '2': 10,
    },
    major_version_details: {
        '1': {
            '1.0.0': 9,
            '1.1.0': 8,
        },
        '2': {
            '2.0.0': 10,
        },
    },
    major_version_severity_counts: {
        '1': { CRITICAL: 2, HIGH: 4, MEDIUM: 2, LOW: 1, INFO: 0, UNKNOWN: 0 },
        '2': { CRITICAL: 2, HIGH: 2, MEDIUM: 1, LOW: 0, INFO: 1, UNKNOWN: 0 },
    },
    version_severity_counts: {
        '1.0.0': { CRITICAL: 1, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, UNKNOWN: 0 },
        '1.1.0': { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0, UNKNOWN: 0 },
        '2.0.0': { CRITICAL: 2, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 1, UNKNOWN: 0 },
    },
}

const mockCodeAnalysisResults = [
    {
        analysis_run_id: 'docs-auto-parser-wrapper',
        queue_id: 'docs-dashboard-completed',
        job_id: 'agentyzer-job-40',
        project_name: 'TestProject',
        vuln_id: 'CVE-2024-4002',
        component_name: 'parser-wrapper',
        source: 'automatic',
        submitted_by: 'auto-sweep',
        submitted_at: '2026-05-02T11:40:00Z',
        finished_at: '2026-05-02T11:48:00Z',
        status: 'completed',
        summary: {
            affected: false,
            verdict: 'Not Affected',
            confidence: 'Medium',
            exposure: 'Job runner only',
            text: 'The vulnerable parser-wrapper path is limited to a disabled batch import pipeline.',
        },
        result: {
            versions_checked: ['2.0.0'],
            assessment: {
                affected: false,
                verdict: 'Not Affected',
                confidence: 'Medium',
                exposure: 'Job runner only',
                summary: 'The vulnerable parser-wrapper path is limited to a disabled batch import pipeline.',
                reasoning: 'No production-facing route references the affected import flow in the current deployment.',
            },
        },
    },
]

const README_CAPTURE_BACKGROUND = '#0f172a'

async function captureWithPadding(
    locator: Locator,
    path: string,
    padding = 24,
) {
    await locator.waitFor({ state: 'visible', timeout: 10000 })
    await locator.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => undefined)
    await locator.evaluate((element, { background, capturePadding }) => {
        const htmlElement = element as HTMLElement
        htmlElement.dataset.docsOriginalStyle = htmlElement.getAttribute('style') ?? ''
        htmlElement.style.border = `${capturePadding}px solid ${background}`
        htmlElement.style.boxSizing = 'content-box'
        htmlElement.style.backgroundClip = 'padding-box'
    }, { background: README_CAPTURE_BACKGROUND, capturePadding: padding })

    try {
        await locator.screenshot({ path, timeout: 20000 })
    } finally {
        await locator.evaluate((element) => {
            const htmlElement = element as HTMLElement
            const originalStyle = htmlElement.dataset.docsOriginalStyle ?? ''
            if (originalStyle) {
                htmlElement.setAttribute('style', originalStyle)
            } else {
                htmlElement.removeAttribute('style')
            }
            delete htmlElement.dataset.docsOriginalStyle
        })
    }
}

async function mockAnalysisQueue(
    page: Page,
    {
        items,
        results = {},
    }: {
        items: Array<Record<string, any>>
        results?: Record<string, any>
    },
) {
    const queueItems = items.map(item => ({ ...item }))

    await page.unroute('**/api/analysis-queue')
    await page.unroute('**/api/analysis-queue/submit')
    await page.unroute(/\/api\/analysis-queue\/(?!submit$)[^/]+$/)

    await page.route('**/api/analysis-queue', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(queueItems),
        })
    })

    await page.route(/\/api\/analysis-queue\/(?!submit$)[^/]+$/, async (route) => {
        const queueId = decodeURIComponent(route.request().url().split('/').pop() || '')
        const item = queueItems.find(entry => entry.queue_id === queueId)
        if (!item) {
            await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ detail: 'Not found' }) })
            return
        }

        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                ...item,
                result: results[queueId],
            }),
        })
    })

    await page.route('**/api/analysis-queue/submit', async (route) => {
        const payload = route.request().postDataJSON()
        const submittedItem = {
            queue_id: `docs-analysis-${queueItems.length + 1}`,
            vuln_id: payload.vuln_id,
            component_name: payload.component_name,
            cvss_vector: payload.cvss_vector,
            user_guidance: payload.user_guidance,
            submitted_by: 'reviewer',
            submitted_at: '2026-05-02T12:00:00Z',
            status: 'queued',
            position: 1,
        }
        queueItems.unshift(submittedItem)
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(submittedItem),
        })
    })
}

async function mockCodeAnalysisDashboardStatus(page: Page) {
    const runningProgress = {
        percent: 64,
        current_step: 'semantic-validation',
        current_title: 'Semantic validation',
        current_agent: 'ReachabilityAgent',
        current_activity: 'Tracing request entrypoints and guard conditions',
        completed_steps: 7,
        total_steps: 11,
        last_updated_at: '2026-05-02T12:12:40Z',
        active_agents: [
            {
                step: 'source-scan',
                title: 'Source scan',
                agent: 'RepositoryAgent',
                activity: 'Indexed platform-gateway and parser-wrapper references',
                status: 'completed',
            },
            {
                step: 'semantic-validation',
                title: 'Semantic validation',
                agent: 'ReachabilityAgent',
                activity: 'Reviewing inbound handlers and runtime guards',
                status: 'running',
            },
            {
                step: 'cvss-adjustment',
                title: 'CVSS adjustment',
                agent: 'ScoringAgent',
                activity: 'Waiting for reachability evidence',
                status: 'pending',
            },
        ],
    }
    const queueItems = [
        {
            queue_id: 'docs-dashboard-running',
            vuln_id: 'CVE-2024-9999',
            component_name: 'platform-gateway',
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            model: 'qwen2.5-coder:14b',
            llm_backend: 'http://ollama:11434',
            llm_provider: 'ollama',
            source: 'automatic',
            submitted_by: 'auto-sweep',
            submitted_at: '2026-05-02T12:10:00Z',
            started_at: '2026-05-02T12:11:00Z',
            status: 'running',
            position: 0,
            job_id: 'agentyzer-job-42',
            progress: runningProgress,
            logs: [
                '2026-05-02T12:11:03Z INFO DTVP: Submitted scan to Agentyzer job agentyzer-job-42',
                '2026-05-02T12:11:11Z RUN RepositoryAgent: Indexed 148 source files and 19 manifests',
                '2026-05-02T12:11:36Z WAIT Analyzer: Waiting for the single LLM backend slot',
                '2026-05-02T12:12:08Z RUN ReachabilityAgent: Tracing request entrypoints and guard conditions',
                '2026-05-02T12:12:28Z WARN ScoringAgent: CVSS adjustment blocked until reachability evidence is complete',
            ],
        },
        {
            queue_id: 'docs-dashboard-queued',
            vuln_id: 'CVE-2024-3001',
            component_name: 'api-gateway',
            model: 'qwen2.5-coder:14b',
            llm_backend: 'http://ollama:11434',
            llm_provider: 'ollama',
            source: 'manual',
            submitted_by: 'reviewer',
            submitted_at: '2026-05-02T12:09:00Z',
            status: 'queued',
            position: 1,
            logs: ['2026-05-02T12:09:00Z WAIT DTVP: Queued behind running analysis docs-dashboard-running'],
        },
        {
            queue_id: 'docs-dashboard-completed',
            vuln_id: 'CVE-2024-4002',
            component_name: 'parser-wrapper',
            source: 'automatic',
            submitted_by: 'auto-sweep',
            submitted_at: '2026-05-02T11:40:00Z',
            started_at: '2026-05-02T11:41:00Z',
            finished_at: '2026-05-02T11:48:00Z',
            status: 'completed',
            position: 0,
            job_id: 'agentyzer-job-40',
            logs: ['2026-05-02T11:48:00Z DONE Analyzer: Completed with a not-affected recommendation'],
        },
    ]
    const configuration = {
        service_name: 'agentyzer',
        service_version: '0.3.0',
        config_dir: '/app/config',
        repos_config_path: '/app/config/repos.yaml',
        repositories: {
            workspace_dir: '/workspace/repositories',
            component_count: 7,
            default_template_configured: true,
            hot_reload: true,
        },
        features: {
            queue_control: true,
            scan_logs: true,
            model_override: true,
            deterministic_targets: true,
        },
    }
    const backend = {
        llm: {
            provider: 'ollama',
            backend: 'ollama',
            host: 'http://ollama:11434',
            model: 'qwen2.5-coder:14b',
            healthy: true,
            supports_model_override: true,
        },
        repositories: {
            workspace_dir: '/workspace/repositories',
            reuse_strategy: 'reuse_existing',
            update_strategy: 'pull_before_scan',
        },
        jobs: {
            job_store: 'memory',
            execution_model: 'single-llm-backend',
            known_jobs: 3,
            status_counts: { running: 1, pending: 1, completed: 1 },
            max_concurrent_jobs: 1,
            running_jobs: 1,
            queued_jobs: 1,
            available_slots: 0,
        },
    }
    const body = {
        overall_state: 'running',
        updated_at: '2026-05-02T12:12:45Z',
        configured: true,
        queue: {
            capacity: 1,
            running_count: 1,
            available_slots: 0,
            dtvp_worker_busy: true,
            waiting_for_slot: true,
            counts_by_status: { running: 1, queued: 1, completed: 1 },
            counts_by_source: { automatic: 2, manual: 1 },
            active_item: queueItems[0],
            active_items: [queueItems[0]],
            items: queueItems,
        },
        auto_sweep: {
            enabled: true,
            code_analysis_configured: true,
            active: true,
            interval_seconds: 900,
            running: false,
            last_started_at: '2026-05-02T12:00:00Z',
            last_finished_at: '2026-05-02T12:00:09Z',
            last_queued_count: 2,
            last_trigger: 'interval',
            next_run_at: '2026-05-02T12:15:00Z',
        },
        external: {
            health: {
                status: 'ok',
                service_name: 'agentyzer',
                service_version: '0.3.0',
                configuration,
                backend,
            },
            health_error: null,
            jobs: [
                {
                    job_id: 'agentyzer-job-42',
                    status: 'running',
                    created_at: '2026-05-02T12:11:03Z',
                    progress: runningProgress,
                    request: {
                        vuln_id: 'CVE-2024-9999',
                        component_name: 'platform-gateway',
                    },
                    model: 'qwen2.5-coder:14b',
                    llm_backend: 'http://ollama:11434',
                    llm_provider: 'ollama',
                    configuration,
                    backend,
                },
                {
                    job_id: 'agentyzer-job-41',
                    status: 'pending',
                    created_at: '2026-05-02T12:09:05Z',
                    request: {
                        vuln_id: 'CVE-2024-3001',
                        component_name: 'api-gateway',
                    },
                    model: 'qwen2.5-coder:14b',
                },
            ],
            jobs_error: null,
            configuration,
            backend,
            busy: true,
            capacity: 1,
            running_jobs: 1,
            queued_jobs: 1,
            available_slots: 0,
        },
        active_agents: runningProgress.active_agents,
        model: 'qwen2.5-coder:14b',
        model_source: 'queue',
        llm_backend: 'http://ollama:11434',
        llm_backend_source: 'queue',
        llm_provider: 'ollama',
        llm_provider_source: 'queue',
    }

    await page.unroute('**/api/code-analysis/status')
    await page.route('**/api/code-analysis/status', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(body),
        })
    })
}

async function openProjectCard(page: Page, groupId: string) {
    const listCard = page.locator(`.vuln-card[data-group-id="${groupId}"]`)
    await expect(listCard).toBeVisible({ timeout: 20000 })
    await listCard.click()

    const inspector = page.getByTestId('vuln-detail-inspector')
    await expect(inspector).toBeVisible({ timeout: 10000 })

    const detailCard = inspector.locator('.vuln-card').first()
    await expect(detailCard.getByRole('tab', { name: 'Overview' })).toBeVisible({ timeout: 10000 })
    await expect(detailCard.getByTestId('vuln-description')).toBeVisible({ timeout: 10000 })
    return detailCard
}

async function selectDetailTab(card: Locator, name: string) {
    const tab = card.getByRole('tab', { name })
    await expect(tab).toBeVisible({ timeout: 10000 })
    await tab.click()
    await expect(tab).toHaveAttribute('aria-selected', 'true', { timeout: 10000 })
}

async function mockCommonShell(page: Page) {
    await page.setViewportSize({ width: 1800, height: 1400 })

    await page.route('**/auth/me', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ username: 'reviewer', role: 'REVIEWER' }),
        })
    })

    await page.route('**/api/version', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ version: '1.0.0', build: 'docs' }),
        })
    })

    await page.route('**/api/metadata', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                authors: ['phbaer <phbaer@example.invalid>'],
                urls: {
                    'Main repo': 'https://git.baer.one/phbaer/dtvp',
                    GitHub: 'https://github.com/phbaer/dtvp',
                },
            }),
        })
    })

    await page.route('**/api/changelog', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ content: '## Changelog\n\nDocumentation screenshot refresh.' }),
        })
    })

    await page.route('**/api/cache-status', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                fully_cached: true,
                last_refreshed_at: '2026-05-02T12:00:00Z',
                projects: 3,
                active_projects: 3,
                cached_findings: 32,
                cached_boms: 7,
                cached_analyses: 18,
                pending_updates: 0,
            }),
        })
    })

    await page.route('**/api/projects*', async (route) => {
        const url = new URL(route.request().url())
        const name = (url.searchParams.get('name') || '').toLowerCase()
        const filtered = name
            ? mockProjects.filter((project) => project.name.toLowerCase().includes(name))
            : mockProjects
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(filtered),
        })
    })

    await page.route('**/api/settings/mapping', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                'platform-gateway': ['PlatformTeam', 'LegacyPlatformAlias'],
                'service-shell': ['PlatformTeam', 'OldShellTeam'],
                'api-gateway': ['EdgeTeam', 'LegacyEdgeAlias'],
                'parser-wrapper': ['RuntimeTeam', 'LegacyRuntimeAlias'],
                'validation-core': ['RuntimeTeam', 'HistoricRuntimeAlias'],
                'frontend-shell': ['UXTeam', 'LegacyUXAlias'],
                '*': 'Unassigned',
            }),
        })
    })

    await page.route('**/api/settings/roles', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                reviewer: 'REVIEWER',
                analyst: 'ANALYST',
                release_manager: 'REVIEWER',
            }),
        })
    })

    await page.route('**/api/settings/rescore-rules', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                transitions: [
                    { trigger: { state: 'IN_TRIAGE' }, to: 'RESOLVED', requiresJustification: true },
                    { trigger: { state: 'EXPLOITABLE' }, to: 'NOT_AFFECTED', requiresJustification: true },
                ],
            }),
        })
    })

    await page.route('**/api/settings/auto-analysis-guidance', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                components: {
                    'keycloak-extension': 'Also consider the surrounding Keycloak runtime when evaluating reachability.',
                },
            }),
        })
    })

    await page.route('**/api/project-archives/snapshots', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([
                {
                    filename: 'TestProject-2026-05-02.dtvp-project-archive.zip',
                    size: 245760,
                    modified_at: '2026-05-02T12:00:00Z',
                    project_name: 'TestProject',
                    created_at: '2026-05-02T12:00:00Z',
                    version_count: 3,
                },
                {
                    filename: 'BillingAPI-2026-05-01.dtvp-project-archive.zip',
                    size: 184320,
                    modified_at: '2026-05-01T18:30:00Z',
                    project_name: 'BillingAPI',
                    created_at: '2026-05-01T18:30:00Z',
                    version_count: 2,
                },
            ]),
        })
    })

    await page.route('**/api/known-users', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(['reviewer', 'analyst', 'release_manager', 'dev_lead', 'security_team']),
        })
    })

    await page.route('**/api/projects/*/tmrescore/context', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                enabled: true,
                project_name: 'TestProject',
                latest_version: '2.0.0',
                versions: ['1.0.0', '1.1.0', '2.0.0'],
                recommended_scope: 'merged_versions',
                scopes: [
                    {
                        id: 'merged_versions',
                        label: 'Merged multi-version',
                        description: 'Build one synthetic SBOM across all discovered versions before rescoring.',
                    },
                    {
                        id: 'latest_only',
                        label: 'Latest only',
                        description: 'Analyze only the newest Dependency-Track project version.',
                    },
                ],
                warnings: [
                    'Merged mode keeps historical vulnerabilities attached to the versioned components that carried them.',
                    'Latest-only mode is faster but may hide vulnerabilities that were already fixed in newer releases.',
                ],
                llm_enrichment: {
                    available: true,
                    status: 'available',
                    model: 'qwen2.5:7b',
                    backend: 'ollama',
                    provider: 'Ollama',
                    host_configured: true,
                    warning: null,
                },
            }),
        })
    })

    await page.route('**/api/projects/*/tmrescore/state', async (route) => {
        await route.fulfill({
            status: 404,
            contentType: 'application/json',
            body: JSON.stringify({ detail: 'No cached tmrescore session' }),
        })
    })

    await page.route('**/api/projects/*/tmrescore/sbom/summary**', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                scope: 'merged_versions',
                latest_version: '2.0.0',
                analyzed_versions: ['1.0.0', '1.1.0', '2.0.0'],
                component_count: 42,
                vulnerability_count: 18,
                strategy_note: 'The analysis SBOM keeps version-specific component identities while presenting tmrescore with one reviewable input.',
            }),
        })
    })

    await page.route('**/api/projects/*/tmrescore/proposals', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ proposals: {} }),
        })
    })

    await page.route('**/api/code-analysis/auto-sweep', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                enabled: true,
                code_analysis_configured: true,
                active: true,
                interval_seconds: 900,
                running: false,
                last_started_at: '2026-05-02T12:00:00Z',
                last_finished_at: '2026-05-02T12:00:09Z',
                last_queued_count: 2,
                last_error: null,
                last_trigger: route.request().method() === 'POST' ? 'manual' : 'interval',
                next_run_at: '2026-05-02T12:15:00Z',
            }),
        })
    })

    const listCodeAnalysisResults = (url: URL, pathVulnId?: string) => {
        const projectName = (url.searchParams.get('project_name') || '').toLowerCase()
        const vulnId = (pathVulnId || url.searchParams.get('vuln_id') || '').toLowerCase()
        const componentName = (url.searchParams.get('component_name') || '').toLowerCase()
        const source = (url.searchParams.get('source') || '').toLowerCase()
        const includeResult = url.searchParams.get('include_result') === 'true'
        const limit = Math.max(1, Math.min(Number(url.searchParams.get('limit') || 100), 500))

        return mockCodeAnalysisResults
            .filter((record) => !projectName || String(record.project_name || '').toLowerCase() === projectName)
            .filter((record) => !vulnId || String(record.vuln_id || '').toLowerCase() === vulnId)
            .filter((record) => !componentName || String(record.component_name || '').toLowerCase() === componentName)
            .filter((record) => !source || String(record.source || '').toLowerCase() === source)
            .slice(0, limit)
            .map((record) => {
                if (includeResult) return { ...record }
                const { result, ...payload } = record
                return payload
            })
    }

    await page.route('**/api/code-analysis/results**', async (route) => {
        const url = new URL(route.request().url())
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(listCodeAnalysisResults(url)),
        })
    })

    await page.route('**/api/projects/*/vulnerabilities/*/analysis-results**', async (route) => {
        const url = new URL(route.request().url())
        const pathParts = url.pathname.split('/').map(part => decodeURIComponent(part))
        const vulnId = pathParts[pathParts.indexOf('vulnerabilities') + 1] || ''
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(listCodeAnalysisResults(url, vulnId)),
        })
    })

    await page.route('**/api/statistics*', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(mockStatistics),
        })
    })

    await page.route('**/api/tasks/group-vulns**', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ task_id: 'task-docs' }),
        })
    })

    const docsGroupedVulns = [
                    {
                        id: 'CVE-2024-9999',
                        title: 'Critical dependency issue in shared parser',
                        description: 'A grouped vulnerability with direct and transitive dependencies across several versions.',
                        severity: 'CRITICAL',
                        cvss: 9.8,
                        cvss_score: 9.8,
                        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                        rescored_cvss: 8.8,
                        rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L',
                        tags: ['PlatformTeam', 'LegacyPlatformAlias'],
                        affected_versions: [
                            {
                                project_name: 'TestProject',
                                project_version: '1.0.0',
                                project_uuid: 'p3',
                                components: [
                                    {
                                        component_name: 'shared-parser',
                                        component_version: '4.2.1',
                                        component_uuid: 'c1',
                                        finding_uuid: 'f1',
                                        vulnerability_uuid: 'v1',
                                        analysis_state: 'IN_TRIAGE',
                                        analysis_details: '--- [Team: LegacyPlatformAlias] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1710000000000] [Justification: CODE_NOT_PRESENT] ---\nLegacy alias assessment block retained for compatibility.',
                                        tags: ['LegacyPlatformAlias'],
                                        dependency_chains: [
                                            'TestProject -> platform-gateway -> shared-parser',
                                            'TestProject -> service-shell -> api-gateway -> parser-wrapper -> shared-parser',
                                            'TestProject -> service-shell -> gateway-facade -> parser-wrapper -> shared-parser',
                                            'TestProject -> service-shell -> request-router -> parser-wrapper -> shared-parser',
                                            'TestProject -> service-shell -> telemetry-bridge -> parser-wrapper -> validation-core -> shared-parser',
                                            'TestProject -> batch-runner -> import-pipeline -> parser-wrapper -> validation-core -> shared-parser',
                                        ],
                                        is_direct_dependency: false,
                                    },
                                ],
                            },
                            {
                                project_name: 'TestProject',
                                project_version: '1.1.0',
                                project_uuid: 'p2',
                                components: [
                                    {
                                        component_name: 'shared-parser',
                                        component_version: '4.2.2',
                                        component_uuid: 'c2',
                                        finding_uuid: 'f2',
                                        vulnerability_uuid: 'v1',
                                        analysis_state: 'IN_TRIAGE',
                                        analysis_details: '--- [Team: PlatformTeam] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1711000000000] [Justification: CODE_NOT_PRESENT] ---\nPrimary assessment block.',
                                        tags: ['PlatformTeam'],
                                        dependency_chains: [
                                            'TestProject -> service-shell -> api-gateway -> parser-wrapper -> shared-parser',
                                        ],
                                        is_direct_dependency: false,
                                    },
                                ],
                            },
                            {
                                project_name: 'TestProject',
                                project_version: '2.0.0',
                                project_uuid: 'p1',
                                components: [
                                    {
                                        component_name: 'platform-gateway',
                                        component_version: '2.5.0',
                                        component_uuid: 'c3',
                                        finding_uuid: 'f3',
                                        vulnerability_uuid: 'v1',
                                        analysis_state: 'NOT_SET',
                                        analysis_details: '',
                                        tags: ['PlatformTeam'],
                                        dependency_chains: [
                                            'TestProject -> platform-gateway',
                                        ],
                                        is_direct_dependency: true,
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        id: 'CVE-2023-1111',
                        title: 'Secondary issue for filter counts',
                        description: 'Used to show dashboarded counts and additional project data.',
                        severity: 'HIGH',
                        cvss: 7.4,
                        cvss_score: 7.4,
                        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N',
                        tags: ['UXTeam'],
                        affected_versions: [
                            {
                                project_name: 'TestProject',
                                project_version: '2.0.0',
                                project_uuid: 'p1',
                                components: [
                                    {
                                        component_name: 'frontend-shell',
                                        component_version: '8.4.0',
                                        component_uuid: 'c4',
                                        finding_uuid: 'f4',
                                        vulnerability_uuid: 'v2',
                                        analysis_state: 'NOT_SET',
                                        analysis_details: '',
                                        tags: ['UXTeam'],
                                        dependency_chains: [
                                            'TestProject -> frontend-shell',
                                        ],
                                        is_direct_dependency: true,
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        id: 'CVE-2022-5555',
                        title: 'Fully assessed low-severity issue in logging library',
                        description: 'A vulnerability that has been fully assessed and approved via the structured workflow.',
                        severity: 'LOW',
                        cvss: 3.1,
                        cvss_score: 3.1,
                        cvss_vector: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:L',
                        tags: ['PlatformTeam'],
                        affected_versions: [
                            {
                                project_name: 'TestProject',
                                project_version: '2.0.0',
                                project_uuid: 'p1',
                                components: [
                                    {
                                        component_name: 'logging-core',
                                        component_version: '1.8.3',
                                        component_uuid: 'c5',
                                        finding_uuid: 'f5',
                                        vulnerability_uuid: 'v3',
                                        analysis_state: 'NOT_AFFECTED',
                                        analysis_details: '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] [Date: 1712000000000] [Justification: VULNERABLE_CODE_NOT_IN_EXECUTION_PATH] ---\nLogging path not reachable in production configuration.\n\n--- [Team: PlatformTeam] [State: NOT_AFFECTED] [Assessed By: analyst] [Date: 1711500000000] [Justification: VULNERABLE_CODE_NOT_IN_EXECUTION_PATH] ---\nConfirmed: logging only used in debug mode.',
                                        tags: ['PlatformTeam'],
                                        dependency_chains: [
                                            'TestProject -> platform-gateway -> logging-core',
                                        ],
                                        is_direct_dependency: false,
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        id: 'CVE-2024-3001',
                        title: 'Pending review — analyst assessment awaiting reviewer approval',
                        description: 'Analyst submitted an assessment that requires reviewer approval before it becomes effective.',
                        severity: 'HIGH',
                        cvss: 7.5,
                        cvss_score: 7.5,
                        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                        tags: ['EdgeTeam'],
                        assignees: ['analyst', 'dev_lead'],
                        affected_versions: [
                            {
                                project_name: 'TestProject',
                                project_version: '2.0.0',
                                project_uuid: 'p1',
                                components: [
                                    {
                                        component_name: 'api-gateway',
                                        component_version: '3.1.0',
                                        component_uuid: 'c6',
                                        finding_uuid: 'f6',
                                        vulnerability_uuid: 'v4',
                                        analysis_state: 'FALSE_POSITIVE',
                                        analysis_details: '--- [Team: EdgeTeam] [State: FALSE_POSITIVE] [Assessed By: analyst] [Date: 1713000000000] [Justification: REQUIRES_ENVIRONMENT] [Assigned: analyst, dev_lead] [Status: Pending Review] ---\nAffected code path is behind a feature flag not enabled in production.',
                                        tags: ['EdgeTeam'],
                                        dependency_chains: [
                                            'TestProject -> api-gateway',
                                        ],
                                        is_direct_dependency: true,
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        id: 'CVE-2024-4002',
                        title: 'Incomplete assessment — RuntimeTeam has not yet assessed',
                        description: 'Some teams have assessed this vulnerability but others have not, leaving it in an incomplete state.',
                        severity: 'MEDIUM',
                        cvss: 5.3,
                        cvss_score: 5.3,
                        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
                        tags: ['PlatformTeam', 'RuntimeTeam'],
                        assignees: ['security_team'],
                        affected_versions: [
                            {
                                project_name: 'TestProject',
                                project_version: '2.0.0',
                                project_uuid: 'p1',
                                components: [
                                    {
                                        component_name: 'parser-wrapper',
                                        component_version: '2.0.5',
                                        component_uuid: 'c7',
                                        finding_uuid: 'f7',
                                        vulnerability_uuid: 'v5',
                                        analysis_state: 'IN_TRIAGE',
                                        analysis_details: '--- [Team: PlatformTeam] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1713100000000] [Assigned: security_team] ---\nUnder investigation by platform team.',
                                        tags: ['PlatformTeam', 'RuntimeTeam'],
                                        dependency_chains: [
                                            'TestProject -> service-shell -> parser-wrapper',
                                        ],
                                        is_direct_dependency: false,
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        id: 'CVE-2024-5003',
                        title: 'Inconsistent analysis — teams disagree on assessment state',
                        description: 'Different teams have assessed this vulnerability differently, creating an inconsistent state that needs resolution.',
                        severity: 'HIGH',
                        cvss: 8.1,
                        cvss_score: 8.1,
                        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
                        tags: ['PlatformTeam', 'EdgeTeam'],
                        affected_versions: [
                            {
                                project_name: 'TestProject',
                                project_version: '2.0.0',
                                project_uuid: 'p1',
                                components: [
                                    {
                                        component_name: 'validation-core',
                                        component_version: '1.3.0',
                                        component_uuid: 'c8',
                                        finding_uuid: 'f8',
                                        vulnerability_uuid: 'v6',
                                        analysis_state: 'IN_TRIAGE',
                                        analysis_details: '--- [Team: PlatformTeam] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1713200000000] ---\nStill evaluating impact.\n\n--- [Team: EdgeTeam] [State: NOT_AFFECTED] [Assessed By: analyst] [Date: 1713100000000] [Justification: REQUIRES_ENVIRONMENT] ---\nNot reachable via our edge configuration.',
                                        tags: ['PlatformTeam', 'EdgeTeam'],
                                        dependency_chains: [
                                            'TestProject -> service-shell -> validation-core',
                                        ],
                                        is_direct_dependency: false,
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        id: 'CVE-2024-6004',
                        title: 'Rescored vulnerability — CVSS adjusted after contextual analysis',
                        description: 'This vulnerability has been rescored from a high base score to a lower contextual score after environment analysis.',
                        severity: 'HIGH',
                        cvss: 7.2,
                        cvss_score: 7.2,
                        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
                        rescored_cvss: 4.1,
                        rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAC:H/MPR:H',
                        tags: ['UXTeam'],
                        assignees: ['reviewer'],
                        affected_versions: [
                            {
                                project_name: 'TestProject',
                                project_version: '2.0.0',
                                project_uuid: 'p1',
                                components: [
                                    {
                                        component_name: 'frontend-shell',
                                        component_version: '8.4.0',
                                        component_uuid: 'c9',
                                        finding_uuid: 'f9',
                                        vulnerability_uuid: 'v7',
                                        analysis_state: 'NOT_AFFECTED',
                                        analysis_details: '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] [Date: 1713300000000] [Justification: VULNERABLE_CODE_NOT_IN_EXECUTION_PATH] [Rescored: 4.1] [Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAC:H/MPR:H] [Assigned: reviewer] ---\nAttack vector requires local access which is not applicable in our deployment.',
                                        tags: ['UXTeam'],
                                        dependency_chains: [
                                            'TestProject -> frontend-shell',
                                        ],
                                        is_direct_dependency: true,
                                    },
                                ],
                            },
                        ],
                    },
    ]

    const automaticAssessmentIds = new Set(
        mockCodeAnalysisResults
            .filter(record => record.source === 'automatic')
            .map(record => String(record.vuln_id || '').trim().toLowerCase())
            .filter(Boolean),
    )
    const groupHasAutomaticAssessment = (group: any) =>
        [group.id, ...(group.aliases || [])]
            .map(candidate => String(candidate || '').trim().toLowerCase())
            .some(candidate => automaticAssessmentIds.has(candidate))
    const automaticAssessmentCountsFor = (items: any[]) => ({
        WITH_AUTOMATIC_ASSESSMENT: items.filter(groupHasAutomaticAssessment).length,
        WITHOUT_AUTOMATIC_ASSESSMENT: items.filter(group => !groupHasAutomaticAssessment(group)).length,
    })

    const docsGroupCounts = {
        total: docsGroupedVulns.length,
        lifecycle: {
            OPEN: 2,
            ASSESSED: 2,
            ASSESSED_LEGACY: 0,
            INCOMPLETE: 1,
            INCONSISTENT: 1,
            NEEDS_APPROVAL: 1,
        },
        analysis: {
            NOT_SET: 2,
            EXPLOITABLE: 0,
            IN_TRIAGE: 3,
            RESOLVED: 0,
            FALSE_POSITIVE: 1,
            NOT_AFFECTED: 2,
        },
        dependency_relationship: {
            direct: 4,
            transitive: 4,
            unknown: 0,
        },
        cvss_version_mismatch: 0,
        ids: Object.fromEntries(docsGroupedVulns.map((group) => [group.id, 1])),
        versions: { '1.0.0': 1, '1.1.0': 1, '2.0.0': docsGroupedVulns.length },
        tags: { PlatformTeam: 4, EdgeTeam: 2, RuntimeTeam: 1, UXTeam: 2 },
        assignees: { analyst: 1, dev_lead: 1, security_team: 1, reviewer: 1 },
        components: {
            'platform-gateway': 1,
            'frontend-shell': 2,
            'logging-core': 1,
            'api-gateway': 1,
            'parser-wrapper': 1,
            'validation-core': 1,
        },
        team_tags: {
            PlatformTeam: { open: 2, assessed: 1 },
            EdgeTeam: { open: 1, assessed: 1 },
            RuntimeTeam: { open: 1, assessed: 0 },
            UXTeam: { open: 1, assessed: 1 },
        },
        tmrescore: { WITH_PROPOSAL: 0, WITHOUT_PROPOSAL: docsGroupedVulns.length },
        automatic_assessment: automaticAssessmentCountsFor(docsGroupedVulns),
        attribution_age: 30,
    }
    const docsTaskLog = [
        'Starting...',
        'Fetching projects...',
        'Found 3 versions. Fetching vulnerabilities...',
        'Processed version 1.0.0 (1/3)...',
        'Processed version 1.1.0 (2/3)...',
        'Processed version 2.0.0 (3/3)...',
        'Grouping vulnerabilities...',
    ]
    const docsTaskWindowResponse = (url: URL, items = docsGroupedVulns) => {
        const automaticAssessmentFilter = url.searchParams.getAll('automatic_assessment')
        const filteredItems = automaticAssessmentFilter.includes('WITH_AUTOMATIC_ASSESSMENT') &&
            !automaticAssessmentFilter.includes('WITHOUT_AUTOMATIC_ASSESSMENT')
            ? items.filter(groupHasAutomaticAssessment)
            : automaticAssessmentFilter.includes('WITHOUT_AUTOMATIC_ASSESSMENT') &&
                !automaticAssessmentFilter.includes('WITH_AUTOMATIC_ASSESSMENT')
                ? items.filter(group => !groupHasAutomaticAssessment(group))
                : items
        const filteredCounts = {
            ...docsGroupCounts,
            total: filteredItems.length,
            automatic_assessment: automaticAssessmentCountsFor(filteredItems),
        }

        return {
            items: filteredItems,
            total: docsGroupedVulns.length,
            filtered: filteredItems.length,
            counts: {
                all: docsGroupCounts,
                filtered: filteredCounts,
            },
            offset: Number(url.searchParams.get('offset') || 0),
            limit: Number(url.searchParams.get('limit') || 250),
            cursor: null,
            next_cursor: null,
            has_more: false,
            sort: url.searchParams.get('sort') || 'rescored-severity',
            order: url.searchParams.get('order') === 'asc' ? 'asc' : 'desc',
            result_mode: 'summary',
            source_result_mode: 'summary',
            partial: false,
            partial_versions_completed: null,
            partial_total_versions: null,
        }
    }

    let taskPollCount = 0
    await page.route('**/api/tasks/task-docs**', async (route) => {
        const url = new URL(route.request().url())
        const groupMatch = url.pathname.match(/\/groups\/([^/]+)$/)

        if (groupMatch) {
            const groupId = decodeURIComponent(groupMatch[1] || '')
            const group = docsGroupedVulns.find((entry) => entry.id === groupId)
            await route.fulfill({
                status: group ? 200 : 404,
                contentType: 'application/json',
                body: JSON.stringify(group || { detail: 'Not found' }),
            })
            return
        }

        if (url.pathname.endsWith('/groups') || url.pathname.endsWith('/group-details')) {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(docsTaskWindowResponse(url)),
            })
            return
        }

        taskPollCount += 1
        if (taskPollCount === 1) {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    status: 'running',
                    progress: 55,
                    message: 'Processed version 1.1.0 (2/3)...',
                    partial_result_available: true,
                    partial_versions_completed: 2,
                    partial_total_versions: 3,
                    log: docsTaskLog.slice(0, 5),
                }),
            })
            return
        }

        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                status: 'completed',
                progress: 100,
                message: 'Grouping vulnerabilities...',
                result_mode: 'summary',
                partial_result_available: true,
                partial_versions_completed: 3,
                partial_total_versions: 3,
                log: docsTaskLog,
                result: docsGroupedVulns,
            }),
        })
    })

    await page.route('**/api/assessments/details', async (route) => {
        const body = route.request().postDataJSON()

        const detailsMap: Record<string, { state: string; details: string }> = {
            c1: {
                state: 'IN_TRIAGE',
                details: '--- [Team: LegacyPlatformAlias] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1710000000000] [Justification: CODE_NOT_PRESENT] ---\nLegacy alias assessment block retained for compatibility.',
            },
            c2: {
                state: 'IN_TRIAGE',
                details: '--- [Team: PlatformTeam] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1711000000000] [Justification: CODE_NOT_PRESENT] ---\nPrimary assessment block.',
            },
            c5: {
                state: 'NOT_AFFECTED',
                details: '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] [Date: 1712000000000] [Justification: VULNERABLE_CODE_NOT_IN_EXECUTION_PATH] ---\nLogging path not reachable in production configuration.\n\n--- [Team: PlatformTeam] [State: NOT_AFFECTED] [Assessed By: analyst] [Date: 1711500000000] [Justification: VULNERABLE_CODE_NOT_IN_EXECUTION_PATH] ---\nConfirmed: logging only used in debug mode.',
            },
            c6: {
                state: 'FALSE_POSITIVE',
                details: '--- [Team: EdgeTeam] [State: FALSE_POSITIVE] [Assessed By: analyst] [Date: 1713000000000] [Justification: REQUIRES_ENVIRONMENT] [Assigned: analyst, dev_lead] [Status: Pending Review] ---\nAffected code path is behind a feature flag not enabled in production.',
            },
            c7: {
                state: 'IN_TRIAGE',
                details: '--- [Team: PlatformTeam] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1713100000000] [Assigned: security_team] ---\nUnder investigation by platform team.',
            },
            c8: {
                state: 'IN_TRIAGE',
                details: '--- [Team: PlatformTeam] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1713200000000] ---\nStill evaluating impact.\n\n--- [Team: EdgeTeam] [State: NOT_AFFECTED] [Assessed By: analyst] [Date: 1713100000000] [Justification: REQUIRES_ENVIRONMENT] ---\nNot reachable via our edge configuration.',
            },
            c9: {
                state: 'NOT_AFFECTED',
                details: '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] [Date: 1713300000000] [Justification: VULNERABLE_CODE_NOT_IN_EXECUTION_PATH] [Rescored: 4.1] [Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAC:H/MPR:H] [Assigned: reviewer] ---\nAttack vector requires local access which is not applicable in our deployment.',
            },
        }

        const results = (body.instances || []).map((inst: any) => {
            const entry = detailsMap[inst.component_uuid] || { state: 'NOT_SET', details: '' }
            return {
                finding_uuid: inst.finding_uuid,
                project_uuid: inst.project_uuid,
                component_uuid: inst.component_uuid,
                vulnerability_uuid: inst.vulnerability_uuid,
                analysis: {
                    state: entry.state,
                    analysisState: entry.state,
                    isSuppressed: false,
                    analysisDetails: entry.details,
                    analysisComments: [],
                },
            }
        })
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(results),
        })
    })

    await page.addInitScript(() => {
        globalThis.localStorage.setItem('dtvp_last_seen_version', '1.0.0')
    })

    await mockAnalysisQueue(page, { items: [] })
    await mockCodeAnalysisDashboardStatus(page)
}

test.describe('Capture README screenshots', () => {
    test.beforeEach(async ({ page }) => {
        await mockCommonShell(page)
    })

    test('capture login screenshot', async ({ page }) => {
        await page.goto('/login')
        await expect(page.getByRole('button', { name: 'Sign in with SSO' })).toBeVisible()

        await captureWithPadding(page.locator('.min-h-screen > .bg-gray-800').first(), '../docs/screenshots/login.png', 16)
    })

    test('capture dashboard screenshot', async ({ page }) => {
        await page.goto('/')
        await page.waitForLoadState('networkidle')
        await expect(page.getByRole('link', { name: 'TestProject' }).first()).toBeVisible({ timeout: 10000 })
        await expect(page.getByRole('link', { name: 'BillingAPI' }).first()).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('LIBRARY')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/dashboard.png')
    })

    test('capture project view screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')

        await expect(card.getByRole('tab', { name: 'CVSS & Rescoring' })).toBeVisible({ timeout: 10000 })
        await expect(card.getByRole('tab', { name: 'Team Mapping' })).toBeVisible({ timeout: 10000 })
        await expect(card.getByTestId('vuln-description')).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('PlatformTeam').first()).toBeVisible({ timeout: 10000 })

        const chainsButton = page.getByRole('button', { name: /^chains$/ }).first()
        await chainsButton.click()
        await expect(page.getByText('platform-gateway').first()).toBeVisible({ timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/project-view.png')

        const morePathsButton = page.locator('button').filter({ hasText: /^\+\d+ more$/ }).first()
        if (await morePathsButton.count() > 0) {
            await expect(morePathsButton).toBeVisible({ timeout: 10000 })
            await morePathsButton.click()
            await expect(page.getByText('gateway-facade').first()).toBeVisible({ timeout: 10000 })
        }

        await page.setViewportSize({ width: 2200, height: 1800 })
        await captureWithPadding(card, '../docs/screenshots/vuln-card-overview.png')
    })

    test('capture CVSS and rescoring tab screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-6004')
        await selectDetailTab(card, 'CVSS & Rescoring')
        await expect(card.getByText('CVSS Calculator')).toBeVisible({ timeout: 10000 })
        await expect(card.getByRole('heading', { name: 'CVSS & Rescoring' })).toBeVisible({ timeout: 10000 })
        await expect(card.locator('#cvss-vector-input')).toBeVisible({ timeout: 10000 })

        await page.setViewportSize({ width: 2200, height: 1800 })
        await captureWithPadding(card, '../docs/screenshots/vuln-card-cvss-rescoring.png')
    })

    test('capture statistics screenshot', async ({ page }) => {
        await page.goto('/statistics?name=TestProject&id=CVE-2024-9999')
        await page.waitForLoadState('networkidle')
        await expect(page.getByText('Stacked vulnerability totals by severity (per version) for v1')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/statistics.png')
    })

    test('capture settings screenshot', async ({ page }) => {
        await page.goto('/settings')
        await page.waitForLoadState('networkidle')
        await expect(page.getByText('Team Mapping Configuration')).toBeVisible({ timeout: 10000 })
        await expect(page.getByRole('button', { name: 'User Roles' })).toBeVisible({ timeout: 10000 })
        await expect(page.locator('textarea')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/settings.png')
    })

    test('capture settings archives screenshot', async ({ page }) => {
        await page.goto('/settings')
        await page.waitForLoadState('networkidle')

        await page.getByRole('button', { name: /Archives/ }).click()
        await expect(page.getByText('Project Archives')).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('Stored Archives')).toBeVisible({ timeout: 10000 })
        await expect(page.getByRole('cell', { name: 'TestProject' })).toBeVisible({ timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/settings-archives.png')
    })

    test('capture threat-model rescoring screenshot', async ({ page }) => {
        await page.goto('/project/TestProject/tmrescore')
        await page.waitForLoadState('networkidle')

        await expect(page.getByRole('heading', { name: /Threat-Model Analysis for TestProject/ })).toBeVisible({ timeout: 10000 })
        await expect(page.getByTestId('scope-merged_versions')).toBeVisible({ timeout: 10000 })
        await expect(page.getByTestId('analysis-sbom-summary-components')).toHaveText('42', { timeout: 10000 })

        await page.setViewportSize({ width: 2200, height: 1800 })
        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/tmrescore.png')
    })

    test('capture lifecycle badges screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        // Wait for all cards to render (we have 7 vulns now)
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })
        await page.waitForTimeout(1000)

        // Capture the full vulnerability list showing various lifecycle badges
        // (OPEN, NEEDS_APPROVAL, INCOMPLETE, INCONSISTENT, ASSESSED, rescored scores)
        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/lifecycle-badges.png')
    })

    test('capture assignee chips and approve button screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        // CVE-2024-3001 has assignees ['analyst', 'dev_lead'] and NEEDS_APPROVAL state
        const needsApprovalCard = page.locator('.vuln-card').filter({ hasText: /CVE-2024-3001/ }).first()
        await expect(needsApprovalCard).toBeVisible({ timeout: 20000 })

        // Verify assignee chips are visible on the card header
        await expect(needsApprovalCard.locator('[data-testid="assignee-chip"]').first()).toBeVisible({ timeout: 5000 })
        await expect(needsApprovalCard.getByText('Needs Approval')).toBeVisible({ timeout: 5000 })

        await captureWithPadding(needsApprovalCard, '../docs/screenshots/assignee-chips-approve.png')
    })

    test('capture rescored CVSS display screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        // CVE-2024-6004 has rescored_cvss: 4.1 (base: 7.2)
        const rescoredCard = page.locator('.vuln-card').filter({ hasText: /CVE-2024-6004/ }).first()
        await expect(rescoredCard).toBeVisible({ timeout: 20000 })

        // Verify rescored score is displayed (arrow from base to rescored)
        await expect(rescoredCard.locator('[data-testid="rescored-arrow"]')).toBeVisible({ timeout: 5000 })
        await expect(rescoredCard.locator('[data-testid="rescored-value-badge"]')).toBeVisible({ timeout: 5000 })

        await captureWithPadding(rescoredCard, '../docs/screenshots/rescored-cvss.png')
    })

    test('capture user assignment form screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        // Expand the NEEDS_APPROVAL card to see the assignment form
        const card = await openProjectCard(page, 'CVE-2024-3001')
        await selectDetailTab(card, 'Review')

        // Wait for the expanded section
        await expect(page.getByText('Assigned Users').first()).toBeVisible({ timeout: 10000 })
        // Verify existing assignee chips are shown in the form
        await expect(page.locator('text=analyst').first()).toBeVisible({ timeout: 5000 })

        // Click the assignee input and type to show suggestions
        const assigneeInput = page.locator('input[placeholder="Type username and press Enter..."]').first()
        await assigneeInput.click()
        await assigneeInput.fill('re')
        await page.waitForTimeout(500)

        // Capture with the suggestion dropdown visible
        await page.setViewportSize({ width: 2200, height: 1800 })
        await captureWithPadding(card, '../docs/screenshots/user-assignment-form.png')
    })

    test('capture statistics sidebar tab screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })
        await page.waitForTimeout(1000)

        // Click the Results tab in the sidebar to show the compact statistics panel.
        const statsTab = page.getByRole('button', { name: 'Results' }).first()
        await expect(statsTab).toBeVisible({ timeout: 5000 })
        await statsTab.click()
        await page.waitForTimeout(500)

        const sidebar = page.getByTestId('stats-sidebar')
        const resultsPanel = page.getByTestId('stats-sidebar-results')
        await expect(resultsPanel).toBeVisible({ timeout: 5000 })
        await expect(resultsPanel.getByText('7 Findings')).toBeVisible({ timeout: 5000 })
        await expect(resultsPanel.getByText('Per Team')).toBeVisible({ timeout: 5000 })
        await expect(resultsPanel.getByText('Cache Status')).toBeVisible({ timeout: 5000 })

        await captureWithPadding(sidebar, '../docs/screenshots/statistics-sidebar.png', 0)
    })

    test('capture assignee filter screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })
        await page.waitForTimeout(500)

        // Type in the assignee filter input
        const assigneeFilterInput = page.locator('input[placeholder*="assignee" i], input[placeholder*="Assignee" i]').first()
        if (await assigneeFilterInput.isVisible()) {
            await assigneeFilterInput.fill('analyst')
            await page.waitForTimeout(500)
        }

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/assignee-filter.png')
    })

    test('capture automatic assessment filter screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        const autoCard = page.locator('.vuln-card').filter({ hasText: /CVE-2024-4002/ }).first()
        await expect(autoCard).toBeVisible({ timeout: 20000 })
        await expect(autoCard.locator('[data-testid="automatic-assessment-badge"]')).toBeVisible({ timeout: 10000 })

        const sidebar = page.getByTestId('stats-sidebar')
        await expect(sidebar.getByText('Automatic Assessment')).toBeVisible({ timeout: 10000 })

        const automaticAssessmentFilters = sidebar
            .getByText('Automatic Assessment', { exact: true })
            .locator('..')
        const missingButton = automaticAssessmentFilters.getByRole('button', { name: /^missing\b/i })
        await missingButton.click()
        await expect(page.getByText('Auto: available', { exact: true })).toBeVisible({ timeout: 10000 })
        await expect(autoCard).toBeVisible({ timeout: 10000 })
        await page.waitForTimeout(500)

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/automatic-assessment-filter.png')
    })

    test('capture expanded card with assessment details screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        // Expand the inconsistent card to show conflicting team assessments
        const card = await openProjectCard(page, 'CVE-2024-5003')
        await selectDetailTab(card, 'Assessments')

        // Wait for assessment details to load
        await page.waitForTimeout(2000)

        // Should show the conflicting team blocks (PlatformTeam: IN_TRIAGE vs EdgeTeam: NOT_AFFECTED)
        await expect(page.getByText('PlatformTeam').first()).toBeVisible({ timeout: 10000 })

        await page.setViewportSize({ width: 2200, height: 1800 })
        await captureWithPadding(card, '../docs/screenshots/inconsistent-assessment.png')
    })

    test('capture CVSS calculator modal screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        // Expand the rescored card to access the calculator
        const card = await openProjectCard(page, 'CVE-2024-6004')
        await selectDetailTab(card, 'CVSS & Rescoring')

        // Wait for expanded state and find the calculator button
        await page.waitForTimeout(1500)
        const calcButton = card.getByRole('button', { name: /Visual Calculator/i }).first()
        if (await calcButton.isVisible({ timeout: 5000 })) {
            await calcButton.click()
            await page.waitForTimeout(500)

            // Verify the calculator modal is open
            await expect(page.getByText('CVSS v3.1 Calculator')).toBeVisible({ timeout: 5000 })

            // Capture the modal
            const modal = page.locator('.fixed.inset-0').filter({ hasText: 'CVSS' }).first()
            await captureWithPadding(modal, '../docs/screenshots/cvss-calculator.png')
        }
    })

    test('capture bulk sync modal screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })

        await page.getByRole('button', { name: /Bulk Sync/ }).click()

        const modal = page.locator('.fixed.inset-0').filter({ hasText: 'Confirm Bulk Sync' }).first()
        await expect(modal).toBeVisible({ timeout: 10000 })
        await captureWithPadding(modal, '../docs/screenshots/bulk-sync-modal.png')
    })

    test('capture conflict resolution modal screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })
        await page.waitForTimeout(500)

        // Expand the inconsistent card and force a conflict via the API response.
        const card = await openProjectCard(page, 'CVE-2024-5003')
        await selectDetailTab(card, 'Review')
        await page.waitForTimeout(1000)

        await page.route('**/api/assessment', async (route) => {
            await route.fulfill({
                status: 409,
                contentType: 'application/json',
                body: JSON.stringify({
                    conflicts: [
                        {
                            finding_uuid: 'test-finding',
                            project_name: 'TestProject',
                            project_version: '2.0.0',
                            component_name: 'api-gateway',
                            component_version: '1.0.0',
                            current: {
                                analysisState: 'NOT_AFFECTED',
                                isSuppressed: false,
                                analysisDetails: '--- [Team: EdgeTeam] [State: NOT_AFFECTED] [Assessed By: release_manager] [Date: 1713500000000] ---\nApproved by release manager after review.',
                            },
                            your_change: {
                                analysisState: 'FALSE_POSITIVE',
                                isSuppressed: false,
                                analysisDetails: '--- [Team: EdgeTeam] [State: FALSE_POSITIVE] [Assessed By: analyst] [Date: 1713400000000] ---\nMarked as false positive — feature flag disabled.',
                            },
                        },
                    ],
                }),
            })
        })

        const applyButton = card.getByRole('button', { name: /^Apply$/ }).nth(1)
        await expect(applyButton).toBeVisible({ timeout: 10000 })
        await applyButton.click()

        const submitButton = page.getByRole('button', { name: 'Submit' }).first()
        await expect(submitButton).toBeVisible({ timeout: 10000 })
        await submitButton.click()

        const modalOverlay = page.locator('.fixed.inset-0').filter({ hasText: 'Conflict Detected' }).first()
        await expect(modalOverlay).toBeVisible({ timeout: 10000 })

        const dialog = modalOverlay.locator(':scope > div').first()
        await expect(dialog).toBeVisible({ timeout: 10000 })
        await captureWithPadding(dialog, '../docs/screenshots/conflict-resolution.png')
    })

    test('capture review context screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Review')
        await expect(card.getByText('Review Context')).toBeVisible({ timeout: 10000 })
        await expect(card.getByTestId('ticket-requirement-badge')).toHaveText('Required', { timeout: 10000 })

        await page.setViewportSize({ width: 2200, height: 1800 })
        await captureWithPadding(card, '../docs/screenshots/vuln-card-review-context.png')
    })

    test('capture team mapping screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Team Mapping')
        await expect(card.getByText('Component Team Mapping')).toBeVisible({ timeout: 10000 })
        await expect(card.getByTestId('component-team-mapping-row').first()).toBeVisible({ timeout: 10000 })
        await expect(card.getByText('platform-gateway').first()).toBeVisible({ timeout: 10000 })

        await page.setViewportSize({ width: 2200, height: 1800 })
        await captureWithPadding(card, '../docs/screenshots/vuln-card-team-mapping.png')
    })

    test('capture code analysis dashboard screenshot', async ({ page }) => {
        await page.goto('/code-analysis')
        await page.waitForLoadState('networkidle')

        await expect(page.getByRole('heading', { name: 'Code Analysis' })).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('DTVP Queue')).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('Analyzer Configuration')).toBeVisible({ timeout: 10000 })

        await page.getByTestId('queue-log-toggle-docs-dashboard-running').click()
        await expect(page.getByTestId('queue-log-panel-docs-dashboard-running')).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('ReachabilityAgent', { exact: true }).first()).toBeVisible({ timeout: 10000 })

        await page.setViewportSize({ width: 2200, height: 1900 })
        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/code-analysis-dashboard.png')
    })

    test('capture code analysis running screenshot', async ({ page }) => {
        await mockAnalysisQueue(page, {
            items: [
                {
                    queue_id: 'analysis-running-latest',
                    vuln_id: 'CVE-2024-9999',
                    component_name: 'platform-gateway',
                    submitted_by: 'reviewer',
                    submitted_at: '2026-05-02T12:00:00Z',
                    status: 'running',
                    position: 0,
                    progress: {
                        percent: 72,
                        current_step: 'semantic-validation',
                        current_title: 'Semantic validation',
                        current_activity: 'Tracing request entrypoints and guard conditions',
                        completed_steps: 8,
                        total_steps: 11,
                        active_agents: [
                            { step: 'source-scan', title: 'Source scan', activity: 'Controller graph complete', status: 'completed' },
                            { step: 'semantic-validation', title: 'Semantic validation', activity: 'Reviewing inbound handlers', status: 'running' },
                        ],
                    },
                },
                {
                    queue_id: 'analysis-queued-older',
                    vuln_id: 'CVE-2023-1111',
                    component_name: 'frontend-shell',
                    submitted_by: 'analyst',
                    submitted_at: '2026-05-02T11:55:00Z',
                    status: 'queued',
                    position: 2,
                },
            ],
        })

        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Code Analysis')
        await expect(card.getByText('Analyzing…')).toBeVisible({ timeout: 10000 })
        await expect(card.getByText('running', { exact: true })).toBeVisible({ timeout: 10000 })

        await page.setViewportSize({ width: 2200, height: 1800 })
        await captureWithPadding(card, '../docs/screenshots/code-analysis-running.png')
    })

    test('capture code analysis result screenshot', async ({ page }) => {
        await mockAnalysisQueue(page, {
            items: [
                {
                    queue_id: 'analysis-completed-platform',
                    vuln_id: 'CVE-2024-9999',
                    component_name: 'platform-gateway',
                    submitted_by: 'reviewer',
                    submitted_at: '2026-05-02T12:05:00Z',
                    status: 'completed',
                    position: 0,
                    finished_at: '2026-05-02T12:06:30Z',
                },
            ],
            results: {
                'analysis-completed-platform': {
                    versions_checked: ['1.0.0', '1.1.0', '2.0.0'],
                    assessment: {
                        affected: true,
                        verdict: 'Affected',
                        confidence: 'High',
                        exposure: 'HTTP request path reachable',
                        summary: 'platform-gateway exposes a reachable parser initialization path used by external requests.',
                        reasoning: 'The service boot path wires the vulnerable parser into authenticated request handlers with no deployment-specific guard that removes the code path.',
                        adjusted_cvss: {
                            original_score: 9.8,
                            adjusted_score: 8.6,
                            adjusted_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                            summary: 'Privileges required reduce exploitability slightly but do not eliminate exposure.',
                            reasons: [
                                'Authentication is required before the vulnerable parser executes.',
                                'The vulnerable flow remains reachable from the primary API surface.',
                            ],
                        },
                    },
                    steps: [
                        {
                            step: 'reachability-scan',
                            title: 'Reachability scan',
                            status: 'pass',
                            evidence: ['Found parser-wrapper invocation in request bootstrap.', 'Matched vulnerable component version 2.5.0 in deployment manifest.'],
                        },
                        {
                            step: 'guard-analysis',
                            title: 'Guard analysis',
                            status: 'warn',
                            evidence: ['Authentication reduces anonymous exposure but the route is still reachable to standard users.'],
                        },
                    ],
                },
            },
        })

        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Code Analysis')
        await expect(card.getByText('platform-gateway exposes a reachable parser initialization path used by external requests.')).toBeVisible({ timeout: 10000 })
        await expect(card.getByText('Use as Assessment Draft')).toBeVisible({ timeout: 10000 })

        await card.getByRole('button', { name: /Pipeline Evidence/ }).click()
        await expect(card.getByText('Reachability scan')).toBeVisible({ timeout: 10000 })

        await page.setViewportSize({ width: 2200, height: 3400 })
        await captureWithPadding(card, '../docs/screenshots/code-analysis-result.png')
    })

    test('capture analysis queue dropdown screenshot', async ({ page }) => {
        await mockAnalysisQueue(page, {
            items: [
                {
                    queue_id: 'analysis-older-completed',
                    vuln_id: 'CVE-2024-4002',
                    component_name: 'parser-wrapper',
                    submitted_by: 'analyst',
                    submitted_at: '2026-05-02T11:40:00Z',
                    status: 'completed',
                    position: 0,
                    finished_at: '2026-05-02T11:48:00Z',
                },
                {
                    queue_id: 'analysis-latest-running',
                    vuln_id: 'CVE-2024-9999',
                    component_name: 'platform-gateway',
                    submitted_by: 'reviewer',
                    submitted_at: '2026-05-02T12:15:00Z',
                    status: 'running',
                    position: 0,
                    progress: {
                        percent: 41,
                        current_step: 'component-mapping',
                        current_title: 'Component mapping',
                        current_activity: 'Correlating dependency paths across affected versions',
                        completed_steps: 4,
                        total_steps: 10,
                        active_agents: [
                            { step: 'component-mapping', title: 'Component mapping', activity: 'Correlating dependency paths', status: 'running' },
                            { step: 'version-merge', title: 'Version merge', activity: 'Waiting for upstream state', status: 'pending' },
                        ],
                    },
                },
                {
                    queue_id: 'analysis-middle-queued',
                    vuln_id: 'CVE-2023-1111',
                    component_name: 'frontend-shell',
                    submitted_by: 'security_team',
                    submitted_at: '2026-05-02T12:00:00Z',
                    status: 'queued',
                    position: 1,
                },
            ],
            results: {
                'analysis-older-completed': {
                    versions_checked: ['1.0.0', '1.1.0'],
                    assessment: {
                        affected: false,
                        verdict: 'Not Affected',
                        confidence: 'Medium',
                        exposure: 'Job runner only',
                        summary: 'The vulnerable parser-wrapper path is limited to a disabled batch import pipeline.',
                        reasoning: 'No production-facing route references the affected import flow in the current deployment.',
                    },
                    steps: [
                        {
                            step: 'batch-path-check',
                            title: 'Batch path check',
                            status: 'pass',
                            evidence: ['The import pipeline is disabled in production configuration.'],
                        },
                    ],
                },
            },
        })

        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        const queueButton = page.getByTestId('analysis-queue-trigger')
        await expect(queueButton).toBeVisible({ timeout: 10000 })
        await queueButton.click()

        const dropdown = page.getByTestId('analysis-queue-panel')
        await expect(dropdown).toBeVisible({ timeout: 10000 })
        const queueRows = dropdown.locator('.min-h-0 > div')
        await expect(queueRows.first()).toContainText('CVE-2024-9999')
        await expect(queueRows.nth(1)).toContainText('CVE-2023-1111')

        await dropdown.getByText('CVE-2024-4002').click()
        await expect(dropdown.getByText('The vulnerable parser-wrapper path is limited to a disabled batch import pipeline.')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(dropdown, '../docs/screenshots/analysis-queue-dropdown.png')
    })
})
