import { test, expect, type Locator, type Page } from '@playwright/test'
import { mockTeamMappingApi } from './helpers/team-mapping'
import { routeMappingTeams } from './helpers/mapping-teams'
import ssvcModel from '../../dtvp/resources/ssvc/deployer-1.0.0.json' with { type: 'json' }

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

const docsAgentEvidence = {
    kind: 'agent',
    evidence_id: 'ev_3f9c2a71d4e84b0f9a6c1e2d7b5a8c40',
    project_name: 'TestProject',
    vuln_id: 'CVE-2024-9999',
    scope: 'components',
    targets: [
        { component: 'platform-gateway', component_version: '2.5.0', project_version: '2.0.0', finding_uuid: 'docs-f2' },
    ],
    title: 'Parser initialization is reachable only behind authentication',
    body_markdown: [
        '## What I checked',
        '',
        '- `GatewayBootstrap.configure()` registers the vulnerable parser for every `/api/v2/*` route.',
        '- `AuthFilter` runs before the parser; anonymous requests are rejected with 401.',
        '',
        '| File | Line | Finding |',
        '|---|---|---|',
        '| `src/boot/GatewayBootstrap.java` | 88 | parser registered |',
        '| `src/security/AuthFilter.java` | 41 | authentication required |',
        '',
        'The vulnerable path stays reachable to any signed-in user, so the finding is **exploitable** with low privileges.',
    ].join('\n'),
    references: ['https://github.com/example/platform-gateway/blob/main/src/boot/GatewayBootstrap.java#L88'],
    suggested_state: 'EXPLOITABLE',
    suggested_justification: null,
    confidence: 'medium',
    author: { username: 'analyst', agent_label: 'triage-bot', token_id: 'tok_7d2e', authority: 'ANALYST' },
    created_at: '2026-05-02T12:20:00Z',
    withdrawn: null,
    applications: [],
}

async function captureWithPadding(
    locator: Locator,
    path: string,
    padding = 24,
) {
    await locator.waitFor({ state: 'visible', timeout: 10000 })
    const ssvc = locator.getByTestId('ssvc-calculator')
    if (await ssvc.isVisible()) {
        await expect(ssvc.getByText(/^CERT\/CC /)).toBeVisible()
    }
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
    await page.unroute('**/api/analysis-queue/status')
    await page.unroute('**/api/analysis-queue/submit')
    await page.unroute(/\/api\/analysis-queue\/(?!(?:submit|status)$)[^/]+$/)

    await page.route('**/api/analysis-queue', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(queueItems),
        })
    })

    await page.route('**/api/analysis-queue/status', async (route) => {
        const countsByStatus = queueItems.reduce<Record<string, number>>((counts, item) => {
            const status = String(item.status || 'unknown')
            counts[status] = (counts[status] || 0) + 1
            return counts
        }, {})
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                counts_by_status: countsByStatus,
                items: queueItems,
                auto_sweep: null,
            }),
        })
    })

    await page.route(/\/api\/analysis-queue\/(?!(?:submit|status)$)[^/]+$/, async (route) => {
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
                '2026-05-02T12:11:03Z INFO River: Submitted scan to Agentyzer job agentyzer-job-42',
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
            logs: ['2026-05-02T12:09:00Z WAIT River: Queued behind running analysis docs-dashboard-running'],
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
    await expect(detailCard.getByRole('tab', { name: 'Context' })).toBeVisible({ timeout: 10000 })
    // A reviewer opening a pending assessment lands on the Assessment tab.
    await detailCard.getByRole('tab', { name: 'Context' }).click()
    await expect(detailCard.getByTestId('vuln-description')).toBeVisible({ timeout: 10000 })
    return detailCard
}

/** Opens the full-screen assessment workspace of an inspector card. */
async function openWorkspace(card: Locator) {
    await card.getByTestId('workspace-toggle').click()
    const workspace = card.page().getByRole('dialog', { name: /^Assessment workspace for / })
    await expect(workspace).toBeVisible({ timeout: 10000 })
    await expect(workspace.getByTestId('workspace-assessment-heading')).toBeVisible({ timeout: 10000 })
    await expect(workspace.getByTestId('assessment-decision-section')).toBeVisible({ timeout: 10000 })
    return workspace
}

/** The workspace fills the viewport, so the capture is the viewport itself. */
async function captureWorkspace(workspace: Locator, path: string) {
    const ssvc = workspace.getByTestId('ssvc-calculator')
    if (await ssvc.isVisible()) {
        await expect(ssvc.getByText(/^CERT\/CC /)).toBeVisible()
    }
    // Let the smooth scroll and the highlight of a filled form settle.
    await workspace.page().waitForTimeout(1800)
    await workspace.page().screenshot({ path })
}

async function selectDetailTab(card: Locator, name: string) {
    const tab = card.getByRole('tab', { name })
    await expect(tab).toBeVisible({ timeout: 10000 })
    await tab.click()
    await expect(tab).toHaveAttribute('aria-selected', 'true', { timeout: 10000 })
}

async function mockCommonShell(page: Page) {
    await page.setViewportSize({ width: 1800, height: 1400 })

    await page.route('**/api/ssvc/models', route => route.fulfill({ json: { models: [ssvcModel] } }))
    await page.route('**/api/ssvc/exploitation**', route => route.fulfill({ json: {
        enabled: true, auto_fill: false, retry_after: 0, suggestion: null, sources: [],
    } }))
    await page.route('**/api/settings/team-groups', route => route.fulfill({ json: {} }))
    // Saved views (ADR 0015): a personal and a shared view, the shared one the
    // reviewers' default for all projects.
    const docsView = (code: string, name: string, scope: string, project: string | null, query: string, editable = true) => ({
        code, name, scope, project, query, owner: 'reviewer', created_at: '', updated_at: '', updated_by: 'reviewer', editable,
    })
    await page.route('**/api/views?**', route => route.fulfill({ json: {
        views: [
            docsView('k7m2p9qa', 'Release 7.2 freeze', 'personal', 'TestProject', 'awaiting_review=false&cutoff=2026-03-01&versions=2.0.0'),
            docsView('r4t8w2ze', 'Platform triage', 'global', null, 'awaiting_review=false&lifecycle=OPEN&lifecycle=INCOMPLETE&teams=PlatformTeam'),
        ],
        defaults: {
            user_project: null, user_all: null, role_project: null, role_all: null,
            roles: { REVIEWER: { project: null, all: null }, ANALYST: { project: null, all: 'r4t8w2ze' } },
            effective: { source: 'builtin', code: null, query: null },
        },
        role: 'REVIEWER',
        can_manage_global: true,
        limits: {},
    } }))

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

    const selectorMapping = {
        'platform-gateway': ['PlatformTeam', 'LegacyPlatformAlias'],
        'service-shell': ['PlatformTeam', 'OldShellTeam'],
        'api-gateway': ['EdgeTeam', 'LegacyEdgeAlias'],
        'parser-wrapper': ['RuntimeTeam', 'LegacyRuntimeAlias'],
        'validation-core': ['RuntimeTeam', 'HistoricRuntimeAlias'],
        'frontend-shell': ['UXTeam', 'LegacyUXAlias'],
        '*': 'Unassigned',
    }
    await routeMappingTeams(page, selectorMapping)
    await page.route('**/api/settings/mapping', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(selectorMapping),
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

    // Code evidence an AI agent added through MCP (see docs/ai-access.md).
    await page.route('**/api/projects/*/vulnerabilities/*/code-evidence**', async (route) => {
        const url = new URL(route.request().url())
        const pathParts = url.pathname.split('/').map(part => decodeURIComponent(part))
        const vulnId = pathParts[pathParts.indexOf('vulnerabilities') + 1] || ''
        const items = vulnId === 'CVE-2024-9999' ? [docsAgentEvidence] : []
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ items, withdrawn_count: 0 }),
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
                        description: [
                            'A crafted document makes `shared-parser` read past the end of its input buffer while it resolves nested entity references.',
                            'An unauthenticated remote attacker who can submit documents to a service using the parser can leak process memory or crash the process.',
                            '',
                            'Versions before 4.3.0 are affected. The `platform-gateway` bundles the parser directly; other components reach it transitively.',
                        ].join('\n'),
                        cwes: [{ id: 125, name: 'Out-of-bounds Read' }],
                        recommendation: 'Upgrade shared-parser to 4.3.0 or later, or disable entity resolution in the parser configuration.',
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
                                        published_ms: Date.UTC(2024, 1, 8),
                                        attributed_on: Date.UTC(2026, 3, 6),
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
                        cwes: [{ id: 400, name: 'Uncontrolled Resource Consumption' }],
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
    // Served at request time: a test may adjust a group before it opens the page.
    currentDocsGroups = docsGroupedVulns

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
            OPEN: 1,
            ASSESSED: 2,
            ASSESSED_LEGACY: 0,
            INCOMPLETE: 1,
            INCONSISTENT: 2,
            NEEDS_APPROVAL: 1,
            READY_FOR_APPROVAL: 1,
        },
        analysis: {
            NOT_SET: 1,
            EXPLOITABLE: 0,
            IN_TRIAGE: 3,
            RESOLVED: 0,
            FALSE_POSITIVE: 1,
            NOT_AFFECTED: 2,
        },
        dependency_relationship: {
            direct: 4,
            transitive: 3,
            unknown: 0,
        },
        cvss_version_mismatch: 0,
        awaiting_review: 1,
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
        cutoff: 30,
        cutoff_unknown: 0,
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
    // Status and analysis state of each fixture vulnerability, as the cards
    // show them; the mock counts the listed ones the way the server does.
    const docsListStates: Record<string, [string, string]> = {
        'CVE-2024-9999': ['INCONSISTENT', 'IN_TRIAGE'],
        'CVE-2023-1111': ['OPEN', 'NOT_SET'],
        'CVE-2022-5555': ['ASSESSED', 'NOT_AFFECTED'],
        'CVE-2024-3001': ['NEEDS_APPROVAL', 'FALSE_POSITIVE'],
        'CVE-2024-4002': ['INCOMPLETE', 'IN_TRIAGE'],
        'CVE-2024-5003': ['INCONSISTENT', 'IN_TRIAGE'],
        'CVE-2024-6004': ['ASSESSED', 'NOT_AFFECTED'],
    }
    const statusCountsFor = (items: any[]) => {
        const lifecycle: Record<string, number> = { OPEN: 0, ASSESSED: 0, ASSESSED_LEGACY: 0, INCOMPLETE: 0, INCONSISTENT: 0, NEEDS_APPROVAL: 0, READY_FOR_APPROVAL: 0 }
        const analysis: Record<string, number> = { NOT_SET: 0, EXPLOITABLE: 0, IN_TRIAGE: 0, RESOLVED: 0, FALSE_POSITIVE: 0, NOT_AFFECTED: 0 }
        for (const item of items) {
            const [status, state] = docsListStates[item.id] || ['OPEN', 'NOT_SET']
            lifecycle[status] = (lifecycle[status] || 0) + 1
            if (status === 'NEEDS_APPROVAL') lifecycle.READY_FOR_APPROVAL! += 1
            analysis[state] = (analysis[state] || 0) + 1
        }
        return { lifecycle, analysis }
    }
    const isAwaitingReview = (group: any) => group.list_metadata?.is_pending
        ?? (group.affected_versions || []).some((version: any) => (version.components || [])
            .some((component: any) => String(component.analysis_details || '').includes('[Status: Pending Review]')))
    const docsTaskWindowResponse = (url: URL, allItems = docsGroupedVulns) => {
        const items = url.searchParams.get('awaiting_review') === 'true'
            ? allItems.filter(isAwaitingReview)
            : allItems
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
            ...statusCountsFor(filteredItems),
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


// The fixture groups of the current test (set up in mockApis).
let currentDocsGroups: any[] = []

// CVE-2024-5003 with a real conflict: PlatformTeam contradicts itself. Teams
// that decide differently are not a conflict, so the shared fixture (two
// teams that disagree, used by the team overview) does not show one.
const routeSelfContradictingConflict = async (page: Page) => {
    const details = '--- [Team: PlatformTeam] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1713200000000] ---\nStill evaluating impact.\n\n'
        + '--- [Team: PlatformTeam] [State: NOT_AFFECTED] [Assessed By: analyst] [Date: 1713100000000] [Justification: REQUIRES_ENVIRONMENT] ---\nNot reachable via our edge configuration.'
    for (const group of currentDocsGroups.filter(entry => entry.id === 'CVE-2024-5003')) {
        for (const version of group.affected_versions) {
            for (const component of version.components) component.analysis_details = details
        }
    }
    await page.route('**/api/assessments/details', async (route) => {
        const body = route.request().postDataJSON()
        if (!(body.instances || []).some((instance: any) => instance.component_uuid === 'c8')) {
            await route.fallback()
            return
        }
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify((body.instances || []).map((instance: any) => ({
                ...instance,
                analysis: { state: 'IN_TRIAGE', analysisState: 'IN_TRIAGE', isSuppressed: false, analysisDetails: details, analysisComments: [] },
            }))),
        })
    })
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
        await page.setViewportSize({ width: 2200, height: 1800 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')

        await expect(card.getByRole('tab', { name: 'Assessment' })).toBeVisible({ timeout: 10000 })
        await expect(card.getByRole('tab', { name: 'CVSS & Rescoring' })).toHaveCount(0)
        await expect(card.getByRole('tab', { name: 'Team Mapping' })).toHaveCount(0)
        await expect(card.getByTestId('vuln-description')).toBeVisible({ timeout: 10000 })
        await expect(card.getByText('PlatformTeam', { exact: true }).first()).toBeVisible({ timeout: 10000 })

        // The dependency chains of a component open from its row in the matrix.
        await card.getByTestId('finding-matrix-row-toggle').first().click()
        await expect(card.getByTestId('finding-matrix-chains').first()).toBeVisible({ timeout: 10000 })
        const chainsButton = card.getByRole('button', { name: /^chains$/ }).first()
        if (await chainsButton.count() > 0) await chainsButton.click()
        await expect(page.getByText('platform-gateway').first()).toBeVisible({ timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/project-view.png')

        const morePathsButton = page.locator('button').filter({ hasText: /^\+\d+ more$/ }).first()
        if (await morePathsButton.count() > 0) {
            await expect(morePathsButton).toBeVisible({ timeout: 10000 })
            await morePathsButton.click()
            await expect(page.getByText('gateway-facade').first()).toBeVisible({ timeout: 10000 })
        }

        await captureWithPadding(card, '../docs/screenshots/vuln-card-overview.png')

        // Which findings differ, and in which fields.
        await card.getByTestId('finding-matrix-row-toggle').first().click()
        await card.getByTestId('card-differences-open').click()
        await expect(card.getByTestId('finding-differences')).toBeVisible({ timeout: 10000 })
        await captureWithPadding(card.getByTestId('where-found'), '../docs/screenshots/assessment-differences.png')
    })

    test('capture global review CVSS and rescoring screenshot', async ({ page }) => {
        await page.setViewportSize({ width: 2200, height: 2600 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-6004')
        await selectDetailTab(card, 'Assessment')
        await expect(card.getByText('CVSS Calculator')).toBeVisible({ timeout: 10000 })
        await expect(card.getByRole('heading', { name: 'CVSS & SSVC', exact: true })).toBeVisible({ timeout: 10000 })
        await expect(card.locator('#cvss-vector-input')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(card, '../docs/screenshots/vuln-card-cvss-rescoring.png')
    })

    test('capture assessment workspace screenshot', async ({ page }) => {
        await page.route('**/auth/me', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ username: 'analyst', role: 'ANALYST' }),
        }))
        await page.setViewportSize({ width: 1800, height: 1100 })
        await page.goto('/project/TestProject?teams=PlatformTeam&lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        const workspace = await openWorkspace(card)
        // The analyst's team is preselected on the form beside the context.
        await expect(workspace.getByTestId('review-team-tab')).toHaveText(['PlatformTeam'])
        await expect(workspace.getByTestId('assessment-team-scope')).toContainText('Other teams are hidden')
        await expect(workspace.getByTestId('workspace-context-pane').getByTestId('where-found')).toBeVisible()

        await captureWorkspace(workspace, '../docs/screenshots/assessment-workspace.png')
    })

    test('capture assessment workspace approval screenshot', async ({ page }) => {
        await page.setViewportSize({ width: 1800, height: 1100 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-3001')
        const workspace = await openWorkspace(card)
        // The reviewer approves the Global form; the team evidence is on the left.
        await workspace.getByRole('button', { name: 'Review & approve' }).click()
        await expect(workspace.getByTestId('assessment-approve-button')).toHaveText('Approve')
        const evidence = workspace.getByTestId('workspace-context-pane').getByTestId('vulnerability-assessments')
        await expect(evidence).toContainText('EdgeTeam')
        await expect(evidence).toBeInViewport()

        await captureWorkspace(workspace, '../docs/screenshots/assessment-workspace-approval.png')
    })

    test('capture assessment workspace differences screenshot', async ({ page }) => {
        await page.setViewportSize({ width: 1800, height: 1100 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        const workspace = await openWorkspace(card)
        // The comparison opens in the context pane; the form stays beside it.
        await workspace.getByTestId('card-differences-open').click()
        await expect(workspace.getByTestId('finding-differences')).toBeVisible({ timeout: 10000 })

        await captureWorkspace(workspace, '../docs/screenshots/assessment-workspace-differences.png')
    })

    test('capture statistics screenshot', async ({ page }) => {
        await page.goto('/statistics?name=TestProject&id=CVE-2024-9999')
        await page.waitForLoadState('networkidle')
        await expect(page.getByText('Stacked vulnerability totals by severity (per version) for v1')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/statistics.png')
    })

    test('capture settings screenshot', async ({ page }) => {
        await mockTeamMappingApi(page, [], { catchAll: false })
        await page.setViewportSize({ width: 1440, height: 1400 })
        await page.goto('/settings')
        await expect(page.getByTestId('team-mapping-editor')).toBeVisible({ timeout: 10000 })
        await expect(page.getByRole('button', { name: 'User Roles' })).toBeVisible({ timeout: 10000 })
        // The projects view with a component picked, the team chosen and
        // the effect previewed, and a fix applied before (the save bar).
        await page.getByRole('tab', { name: /Checks/ }).click()
        await page.getByTestId('check-group-stale').getByRole('button', { name: 'Remove entry' }).first().click()
        await page.getByRole('tab', { name: /Projects/ }).click()
        await page.getByTestId('coverage-project-ViewPoint_Product').click()
        const core = page.getByRole('treeitem', { name: /^core,/ })
        await core.click()
        await core.press('ArrowRight')
        await expect(page.getByTestId('coverage-node-zlib')).toBeVisible({ timeout: 10000 })
        await page.getByRole('combobox', { name: 'Team' }).fill('Core')
        await page.getByRole('combobox', { name: 'Team' }).press('Enter')
        await expect(page.getByTestId('assign-preview-result')).toContainText('change owner', { timeout: 10000 })
        await expect(page.getByTestId('team-mapping-save-bar')).toContainText('change owner', { timeout: 10000 })

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

    test('capture settings access tokens screenshot', async ({ page }) => {
        await page.route('**/api/settings/tokens', route => route.fulfill({
            json: {
                enabled: true,
                scopes: ['read', 'write'],
                default_expiry_days: 90,
                max_expiry_days: 365,
                tokens: [
                    {
                        id: 'docs-token-1',
                        name: 'triage agent',
                        scopes: ['read', 'write'],
                        created_at: '2026-11-02T08:15:00+00:00',
                        expires_at: '2027-01-31T08:15:00+00:00',
                        last_used_at: '2026-11-16T14:42:00+00:00',
                        revoked_at: null,
                    },
                    {
                        id: 'docs-token-2',
                        name: 'reporting script',
                        scopes: ['read'],
                        created_at: '2026-10-20T09:00:00+00:00',
                        expires_at: '2027-01-18T09:00:00+00:00',
                        last_used_at: null,
                        revoked_at: null,
                    },
                ],
            },
        }))
        await page.route('**/api/settings/tokens/audit**', route => route.fulfill({
            json: [
                {
                    id: 2,
                    occurred_at: '2026-11-16T14:42:00+00:00',
                    username: 'reviewer',
                    token_id: 'docs-token-1',
                    agent: 'triage agent',
                    action: 'save_assessment',
                    outcome: 'success',
                    target: { project: 'TestProject', vulnerability: 'CVE-2026-0001', team: 'Team Alpha' },
                    detail: '',
                },
                {
                    id: 1,
                    occurred_at: '2026-11-16T14:40:00+00:00',
                    username: 'reviewer',
                    token_id: 'docs-token-1',
                    agent: 'triage agent',
                    action: 'save_assessment',
                    outcome: 'conflict',
                    target: { project: 'TestProject', vulnerability: 'CVE-2026-0002', team: 'Team Alpha' },
                    detail: 'stale revisions',
                },
            ],
        }))
        await page.goto('/settings')
        await page.waitForLoadState('networkidle')

        await page.getByRole('button', { name: 'Access Tokens' }).click()
        await expect(page.getByTestId('mcp-url')).toBeVisible({ timeout: 10000 })
        await expect(page.getByTestId('token-row')).toHaveCount(2)
        await expect(page.getByTestId('audit-row')).toHaveCount(2)
        await page.getByTestId('token-name').fill('triage agent on my laptop')
        // The URL follows the capture host; show a representative deployment.
        await page.getByTestId('mcp-url').evaluate((element) => {
            element.textContent = 'https://dtvp.example.com/dtvp/mcp'
        })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/settings-access-tokens.png')
    })

    test('capture threat-model rescoring screenshot', async ({ page }) => {
        await page.setViewportSize({ width: 2200, height: 1800 })
        await page.goto('/project/TestProject/tmrescore')
        await page.waitForLoadState('networkidle')

        await expect(page.getByRole('heading', { name: /Threat-Model Analysis for TestProject/ })).toBeVisible({ timeout: 10000 })
        await expect(page.getByTestId('scope-merged_versions')).toBeVisible({ timeout: 10000 })
        await expect(page.getByTestId('analysis-sbom-summary-components')).toHaveText('42', { timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/tmrescore.png')
    })

    test('capture lifecycle badges screenshot', async ({ page }) => {
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        // Wait for all cards to render (we have 7 vulns now)
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })
        await page.waitForTimeout(1000)

        // Capture the full vulnerability list showing various lifecycle badges
        // (OPEN, NEEDS_APPROVAL, INCOMPLETE, INCONSISTENT, ASSESSED, rescored scores)
        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/lifecycle-badges.png')
    })

    test('capture ready for approval card screenshot', async ({ page }) => {
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        // CVE-2024-3001 has assignees ['analyst', 'dev_lead'] and NEEDS_APPROVAL state
        const needsApprovalCard = page.locator('.vuln-card').filter({ hasText: /CVE-2024-3001/ }).first()
        await expect(needsApprovalCard).toBeVisible({ timeout: 20000 })

        await expect(needsApprovalCard.getByTestId('workflow-state-badge')).toHaveText('Ready for approval', { timeout: 5000 })

        await captureWithPadding(needsApprovalCard, '../docs/screenshots/assignee-chips-approve.png')
    })

    test('capture rescored CVSS display screenshot', async ({ page }) => {
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        // CVE-2024-6004 has rescored_cvss: 4.1 (base: 7.2)
        const rescoredCard = page.locator('.vuln-card').filter({ hasText: /CVE-2024-6004/ }).first()
        await expect(rescoredCard).toBeVisible({ timeout: 20000 })

        await expect(rescoredCard.getByTestId('base-score-value')).toHaveText('7.2', { timeout: 5000 })
        await expect(rescoredCard.getByTestId('rescored-value-badge')).toHaveText('4.1', { timeout: 5000 })

        await captureWithPadding(rescoredCard, '../docs/screenshots/rescored-cvss.png')
    })

    test('capture user assignment form screenshot', async ({ page }) => {
        await page.setViewportSize({ width: 2200, height: 2600 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        // Expand the NEEDS_APPROVAL card to see the assignment form
        const card = await openProjectCard(page, 'CVE-2024-3001')
        await selectDetailTab(card, 'Assessment')

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
        await captureWithPadding(card, '../docs/screenshots/user-assignment-form.png')
    })

    test('capture statistics sidebar tab screenshot', async ({ page }) => {
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
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
        await expect(resultsPanel.getByText('7 Vulnerabilities', { exact: true })).toBeVisible({ timeout: 5000 })
        await expect(resultsPanel.getByText('Per Team')).toBeVisible({ timeout: 5000 })
        await expect(resultsPanel.getByText('Cache Status')).toBeVisible({ timeout: 5000 })

        await captureWithPadding(sidebar, '../docs/screenshots/statistics-sidebar.png', 0)
    })

    test('capture filter sidebar and drawer screenshots', async ({ page }) => {
        await page.setViewportSize({ width: 1800, height: 2200 })
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })
        await page.waitForTimeout(500)

        const sidebar = page.getByTestId('stats-sidebar')
        await captureWithPadding(sidebar, '../docs/screenshots/filter-sidebar.png', 0)

        await sidebar.getByText('More filters', { exact: true }).click()
        await page.waitForTimeout(300)
        await captureWithPadding(sidebar, '../docs/screenshots/filter-sidebar-more.png', 0)
        await sidebar.getByText('More filters', { exact: true }).click()

        // The reviewer's preset: everything submitted and not yet approved.
        await sidebar.getByTestId('filter-preset-awaiting-review').click()
        await expect(page.getByTestId('project-toolbar').getByText('Awaiting review', { exact: true })).toBeVisible({ timeout: 10000 })
        await page.waitForTimeout(500)
        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/filter-awaiting-review.png')
        await sidebar.getByTestId('filter-preset-all').click()

        // Saved views (ADR 0015), opened from the sidebar header.
        await sidebar.getByTestId('saved-views-trigger').click()
        const viewsMenu = page.getByTestId('saved-views-menu')
        await expect(viewsMenu).toContainText('Release 7.2 freeze', { timeout: 10000 })
        await page.waitForTimeout(300)
        const sidebarBox = (await sidebar.boundingBox())!
        const menuBox = (await viewsMenu.boundingBox())!
        const left = Math.min(sidebarBox.x, menuBox.x) - 16
        const top = Math.max(0, sidebarBox.y - 16)
        await page.screenshot({
            path: '../docs/screenshots/saved-views.png',
            clip: {
                x: Math.max(0, left),
                y: top,
                width: Math.max(sidebarBox.x + sidebarBox.width, menuBox.x + menuBox.width) + 16 - Math.max(0, left),
                height: Math.min(menuBox.y + menuBox.height + 16, sidebarBox.y + 700) - top,
            },
        })
        await page.keyboard.press('Escape')

        // The cutoff with the purpose of each date (ADR 0015).
        await sidebar.getByTestId('cutoff-date').fill('2026-03-01')
        await sidebar.getByTestId('cutoff-date').dispatchEvent('change')
        await sidebar.getByTestId('cutoff-help-toggle').click()
        await expect(sidebar.getByTestId('cutoff-help')).toBeVisible()
        await page.waitForTimeout(300)
        await captureWithPadding(sidebar.getByTestId('cutoff-filter'), '../docs/screenshots/cutoff-help.png', 12)
        await sidebar.getByTestId('cutoff-help-toggle').click()
        await sidebar.getByTestId('cutoff-clear').click()

        // Below the rail breakpoint the same panel opens as a drawer.
        await page.setViewportSize({ width: 900, height: 1300 })
        await page.getByTitle('Open filters').click()
        await expect(page.locator('aside').getByTestId('stats-sidebar')).toBeVisible({ timeout: 10000 })
        await page.waitForTimeout(300)
        await page.screenshot({ path: '../docs/screenshots/filter-drawer.png' })
    })

    test('capture assignee filter screenshot', async ({ page }) => {
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
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
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const autoCard = page.locator('.vuln-card').filter({ hasText: /CVE-2024-4002/ }).first()
        await expect(autoCard).toBeVisible({ timeout: 20000 })
        await expect(autoCard.locator('[data-testid="automatic-assessment-badge"]')).toBeVisible({ timeout: 10000 })

        const sidebar = page.getByTestId('stats-sidebar')
        await sidebar.getByText('More filters', { exact: true }).click()
        await sidebar.getByText('Legacy analysis filters', { exact: true }).click()
        await expect(sidebar.getByText('Automatic Assessment', { exact: true })).toBeVisible({ timeout: 10000 })

        const automaticAssessmentFilters = sidebar
            .getByText('Automatic Assessment', { exact: true })
            .locator('..')
        const missingButton = automaticAssessmentFilters.getByRole('button', { name: /^missing\b/i })
        await missingButton.click()
        await expect(page.getByText('Automatic assessment: available', { exact: true })).toBeVisible({ timeout: 10000 })
        await expect(autoCard).toBeVisible({ timeout: 10000 })
        await page.waitForTimeout(500)

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/automatic-assessment-filter.png')
    })

    test('capture expanded card with assessment details screenshot', async ({ page }) => {
        await routeSelfContradictingConflict(page)
        await page.setViewportSize({ width: 2200, height: 1800 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        // Expand the inconsistent card to show conflicting team assessments
        const card = await openProjectCard(page, 'CVE-2024-5003')
        await selectDetailTab(card, 'Context')

        // Wait for assessment details to load
        await page.waitForTimeout(2000)

        // Should show the conflicting team blocks (PlatformTeam contradicts itself: IN_TRIAGE vs NOT_AFFECTED)
        await expect(card.getByText('PlatformTeam').first()).toBeVisible({ timeout: 10000 })

        await expect(card.getByTestId('card-differences-banner')).toBeVisible({ timeout: 10000 })
        await captureWithPadding(card, '../docs/screenshots/inconsistent-assessment.png')
    })

    test('capture CVSS calculator modal screenshot', async ({ page }) => {
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        // Expand the rescored card to access the calculator
        const card = await openProjectCard(page, 'CVE-2024-6004')
        await selectDetailTab(card, 'Assessment')

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
        const workflow = {
            id: 'assessment-repair',
            label: 'Repair Assessments',
            description: 'Synchronize partial assessments, keep assessments of former teams as historical, restore lost CVSS vectors, and repair rule-based rescoring.',
            supports_apply: true,
            supports_document: false,
            version: 1,
        }
        await page.route('**/api/bulk-workflows/summary', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                task_id: 'task-docs',
                workflows: [{ ...workflow, candidate_count: 1, summary: { groups: 1 } }],
            }),
        }))
        await page.route('**/api/bulk-workflows/assessment-repair/preview-task', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ task_id: 'docs-bulk-preview' }),
        }))
        await page.route('**/api/bulk-workflows/tasks/docs-bulk-preview', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                task_id: 'docs-bulk-preview',
                status: 'completed',
                progress: 100,
                result: {
                    task_id: 'task-docs',
                    workflow,
                    preview_token: 'docs-preview-token',
                    selectable_group_ids: ['CVE-2024-4002', 'CVE-2024-5003'],
                    items: [{
                        group_id: 'CVE-2024-4002',
                        title: 'Prototype pollution in request parser',
                        finding_count: 2,
                        repairable: true,
                        repairs: [
                            { id: 'sync_findings', label: 'Synchronize assessment to 1 finding' },
                            { id: 'former_teams', label: 'Keep former team assessment as historical: Platform' },
                        ],
                        review: [],
                        rescore_findings: [],
                    }, {
                        group_id: 'CVE-2024-5003',
                        title: 'Conflicting team assessments',
                        finding_count: 3,
                        repairable: true,
                        requires_review: true,
                        repairs: [{
                            id: 'combine_conflict',
                            label: 'Combine conflicting assessments into one global decision (IN_TRIAGE): former teams EdgeTeam, PlatformTeam; sources disagree, pending review, Security still to assess',
                        }],
                        review: [],
                        rescore_findings: [],
                    }],
                    topics: [
                        { id: 'sync_findings', label: 'Synchronize', groups: 1 },
                        { id: 'former_teams', label: 'Former teams', groups: 1 },
                        { id: 'combine_conflict', label: 'Combine conflicts', groups: 1 },
                    ],
                    summary: { groups: 1, findings: 2 },
                },
            }),
        }))

        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })

        await page.getByRole('button', { name: 'Bulk Changes' }).click()
        const modal = page.locator('.fixed.inset-0').filter({ hasText: 'Bulk Changes' }).first()
        await expect(modal).toBeVisible({ timeout: 10000 })
        await modal.getByTestId('bulk-workflow-assessment-repair').click()
        await expect(modal.getByRole('heading', { name: 'Repair Assessments' })).toBeVisible({ timeout: 10000 })

        await captureWithPadding(modal, '../docs/screenshots/bulk-sync-modal.png')
    })

    test('capture vulnerability repair dialog screenshot', async ({ page }) => {
        await routeSelfContradictingConflict(page)
        const workflow = { id: 'assessment-repair', label: 'Repair Assessments', description: 'Every safe, rule-based repair in one operation.', supports_apply: true, supports_document: false, version: 1 }
        const item = {
            group_id: 'CVE-2024-5003',
            title: 'Inconsistent analysis — teams disagree on assessment state',
            finding_count: 1,
            new_finding_count: 1,
            new_finding_places: ['2.1.0 (validation-core@1.3.0)'],
            repairable: true,
            requires_review: false,
            repairs: [
                { id: 'combine_conflict', label: 'Combine conflicting assessments into one global decision (IN_TRIAGE): former teams EdgeTeam, PlatformTeam; sources disagree, pending review' },
                { id: 'rescoring', label: 'Repair rescoring on 1 finding' },
            ],
            review: [],
            rescore_findings: [],
        }
        const preview = {
            task_id: 'task-docs', workflow, preview_token: 'docs-repair-token',
            group_fingerprints: { 'CVE-2024-5003': 'fp' },
            selectable_group_ids: ['CVE-2024-5003'],
            items: [item],
            topics: [{ id: 'combine_conflict', label: 'Combine conflicts', groups: 1 }, { id: 'rescoring', label: 'Rescoring', groups: 1 }],
            summary: { groups: 1, findings: 1 },
        }
        const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
        await page.route('**/api/bulk-workflows/assessment-repair/preview', route => route.fulfill(json(preview)))
        await page.route('**/api/bulk-workflows/summary', route => route.fulfill(json({ task_id: 'task-docs', workflows: [{ ...workflow, candidate_count: null, summary: {} }] })))
        await page.route('**/api/bulk-workflows/assessment-repair/preview-task', route => route.fulfill(json({ task_id: 'docs-repair-preview' })))
        await page.route('**/api/bulk-workflows/tasks/docs-repair-preview', route => route.fulfill(json({
            task_id: 'docs-repair-preview', status: 'completed', progress: 100, result: preview,
        })))
        await page.setViewportSize({ width: 1600, height: 1000 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-5003')
        await selectDetailTab(card, 'Context')
        await card.getByTestId('card-differences-repair').click()
        const modal = page.locator('.fixed.inset-0').filter({ hasText: 'Repair CVE-2024-5003' }).first()
        await expect(modal.getByTestId('bulk-workflow-apply')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(modal.locator(':scope > div').first(), '../docs/screenshots/vulnerability-repair.png')
    })

    test('capture conflict resolution modal screenshot', async ({ page }) => {
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })
        await page.waitForTimeout(500)

        // Expand the inconsistent card and force a conflict via the API response.
        const card = await openProjectCard(page, 'CVE-2024-5003')
        await selectDetailTab(card, 'Assessment')
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

        const analysisDetails = card.locator('#analysis-details-textarea')
        const existingDetails = await analysisDetails.inputValue()
        await analysisDetails.fill(`${existingDetails}\nConflict screenshot edit.`.trim())

        const saveButton = card.getByTestId('assessment-submit-button')
        await expect(saveButton).toBeEnabled({ timeout: 10000 })
        await saveButton.click()

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
        await page.setViewportSize({ width: 2200, height: 2600 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Assessment')
        await expect(card.getByText('Review Context')).toBeVisible({ timeout: 10000 })
        await expect(card.getByTestId('ticket-requirement-badge')).toHaveText('Required', { timeout: 10000 })

        await captureWithPadding(card, '../docs/screenshots/vuln-card-review-context.png')
    })

    test('capture team overview screenshot', async ({ page }) => {
        // CVE-2024-5003: PlatformTeam is in triage, EdgeTeam says not affected.
        await page.setViewportSize({ width: 1600, height: 1400 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-5003')
        await selectDetailTab(card, 'Assessment')
        await card.getByRole('button', { name: /^Global/ }).click()
        const overview = card.getByTestId('team-assessment-overview')
        await expect(overview.getByTestId('team-overview-row')).toHaveCount(2)
        await expect(overview.locator('[data-disagrees="true"]')).toHaveCount(2)

        await captureWithPadding(card.getByTestId('assessment-scope'), '../docs/screenshots/team-overview.png')
    })

    test('capture team assessment tab screenshot', async ({ page }) => {
        await page.route('**/auth/me', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ username: 'analyst', role: 'ANALYST' }),
        }))
        await page.setViewportSize({ width: 1600, height: 1600 })
        await page.goto('/project/TestProject?teams=PlatformTeam&lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Assessment')
        await expect(card.getByTestId('assessment-decision-section')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(card, '../docs/screenshots/vuln-card-team-assessment.png')
    })

    test('capture clear assessment dialog screenshot', async ({ page }) => {
        await page.route('**/auth/me', route => route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ username: 'analyst', role: 'ANALYST' }),
        }))
        await page.setViewportSize({ width: 1600, height: 1000 })
        await page.goto('/project/TestProject?teams=PlatformTeam&lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Assessment')
        await card.getByTestId('assessment-more-button').click()
        await card.getByTestId('assessment-clear-button').click()
        const dialog = page.getByTestId('clear-assessment-modal').locator(':scope > div').first()
        await expect(dialog).toContainText('Only the PlatformTeam assessment')

        await captureWithPadding(dialog, '../docs/screenshots/clear-assessment.png')
    })

    test('capture assessment cleanup dialog screenshot', async ({ page }) => {
        // Two findings of CVE-2024-9999 carry different assessments: one has
        // a block under the mapping's old alias of PlatformTeam.
        const texts: Record<string, string> = {
            c1: '--- [Team: LegacyPlatformAlias] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1710000000000] [Justification: CODE_NOT_PRESENT] ---\nLegacy alias assessment block retained for compatibility.',
            c2: '--- [Team: PlatformTeam] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1711000000000] [Justification: CODE_NOT_PRESENT] ---\nPrimary assessment block.',
        }
        await page.route('**/api/assessment/cleanup', async (route) => {
            const body = route.request().postDataJSON()
            const kept = texts[body.source?.component_uuid] ?? ''
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify((body.instances || []).map((instance: any) => ({
                    ...instance,
                    revision: 3,
                    source_revision: 4,
                    changed: texts[instance.component_uuid] !== kept,
                    before: { state: texts[instance.component_uuid] ? 'IN_TRIAGE' : 'NOT_SET', details: texts[instance.component_uuid] ?? '', suppressed: false },
                    after: texts[instance.component_uuid] !== kept ? { state: 'IN_TRIAGE', details: kept, suppressed: false } : null,
                }))),
            })
        })
        await page.setViewportSize({ width: 1600, height: 1100 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Context')
        await card.getByTestId('card-differences-cleanup').click()
        const modal = page.getByTestId('cleanup-assessment-modal')
        await expect(modal.getByTestId('cleanup-version')).toHaveCount(3)
        await modal.getByTestId('cleanup-preview-button').click()
        await expect(modal.getByTestId('cleanup-preview-row')).toHaveCount(2)

        await captureWithPadding(modal.locator(':scope > div').first(), '../docs/screenshots/assessment-cleanup.png')
    })

    test('capture code analysis dashboard screenshot', async ({ page }) => {
        await page.setViewportSize({ width: 2200, height: 1900 })
        await page.goto('/code-analysis')
        await page.waitForLoadState('networkidle')

        await expect(page.getByRole('heading', { name: 'Code Analysis' })).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('River Queue')).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('Analyzer Configuration')).toBeVisible({ timeout: 10000 })

        await page.getByTestId('queue-log-toggle-docs-dashboard-running').click()
        await expect(page.getByTestId('queue-log-panel-docs-dashboard-running')).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('ReachabilityAgent', { exact: true }).first()).toBeVisible({ timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/code-analysis-dashboard.png')
    })

    test('capture code analysis running screenshot', async ({ page }) => {
        await page.setViewportSize({ width: 2200, height: 1800 })
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

        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Code Evidence')
        await expect(card.getByText('Analyzing…')).toBeVisible({ timeout: 10000 })
        await expect(card.getByText('running', { exact: true })).toBeVisible({ timeout: 10000 })

        await captureWithPadding(card, '../docs/screenshots/code-analysis-running.png')
    })

    test('capture code analysis result screenshot', async ({ page }) => {
        await page.setViewportSize({ width: 2200, height: 3400 })
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

        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Code Evidence')
        await expect(card.getByRole('button', { name: 'View', exact: true })).toBeVisible({ timeout: 10000 })
        await card.getByRole('button', { name: 'View', exact: true }).click()
        await expect(card.getByTestId('inline-analysis-outcome').getByText('platform-gateway exposes a reachable parser initialization path used by external requests.')).toBeVisible({ timeout: 10000 })
        await expect(card.getByText('Use as draft').first()).toBeVisible({ timeout: 10000 })
        await expect(card.getByTestId('evidence-row').first()).toBeVisible({ timeout: 10000 })

        await card.getByRole('button', { name: /Pipeline Evidence/ }).click()
        await expect(card.getByText('Reachability scan')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(card, '../docs/screenshots/code-analysis-result.png')
    })

    test('capture code evidence reader screenshot', async ({ page }) => {
        await page.setViewportSize({ width: 2200, height: 2600 })
        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
        await page.waitForLoadState('networkidle')

        const card = await openProjectCard(page, 'CVE-2024-9999')
        await selectDetailTab(card, 'Code Evidence')
        const row = card.locator('[data-testid="evidence-row"][data-kind="agent"]').first()
        await expect(row).toContainText('Agent: triage-bot', { timeout: 10000 })
        await row.click()
        const reader = card.getByTestId('evidence-reader')
        await expect(reader.getByRole('heading', { name: 'What I checked' })).toBeVisible({ timeout: 10000 })
        await expect(reader.getByTestId('evidence-apply-box')).toBeVisible()

        await captureWithPadding(card.getByTestId('code-evidence-panel'), '../docs/screenshots/code-evidence-reader.png')
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

        await page.goto('/project/TestProject?lifecycle=OPEN&lifecycle=INCOMPLETE&lifecycle=INCONSISTENT&lifecycle=READY_FOR_APPROVAL&lifecycle=ASSESSED')
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
