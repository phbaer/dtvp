import { test, expect } from '@playwright/test'

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

const README_CAPTURE_BACKGROUND = '#0f172a'

async function captureWithPadding(
    locator: Parameters<typeof test>[0]['page']['locator'],
    path: string,
    padding = 24,
) {
    await locator.scrollIntoViewIfNeeded()
    await locator.evaluate((element, { background, capturePadding }) => {
        const htmlElement = element as HTMLElement
        htmlElement.dataset.docsOriginalStyle = htmlElement.getAttribute('style') ?? ''
        htmlElement.style.border = `${capturePadding}px solid ${background}`
        htmlElement.style.boxSizing = 'content-box'
        htmlElement.style.backgroundClip = 'padding-box'
    }, { background: README_CAPTURE_BACKGROUND, capturePadding: padding })

    try {
        await locator.screenshot({ path })
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
    page: Parameters<typeof test.beforeEach>[0]['page'],
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

async function openProjectCard(page: Parameters<typeof test>[0]['page'], groupId: string) {
    const card = page.locator(`.vuln-card[data-group-id="${groupId}"]`)
    await expect(card).toBeVisible({ timeout: 20000 })
    const cardBox = await card.boundingBox()
    if (!cardBox) throw new Error(`Expected bounding box for ${groupId}`)
    await page.mouse.click(cardBox.x + 120, cardBox.y + 40)
    return card
}

async function mockCommonShell(page: Parameters<typeof test.beforeEach>[0]['page']) {
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

    await page.route('**/api/known-users', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(['reviewer', 'analyst', 'release_manager', 'dev_lead', 'security_team']),
        })
    })

    await page.route('**/api/projects/*/tmrescore/proposals', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ proposals: {} }),
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

    let taskPollCount = 0
    await page.route('**/api/tasks/task-docs**', async (route) => {
        taskPollCount += 1
        console.log('mock route: task-docs attempt', taskPollCount, route.request().method(), route.request().url())
        if (taskPollCount === 1) {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    status: 'running',
                    progress: 55,
                    message: 'Processed version 1.1.0 (2/3)...',
                    log: [
                        'Starting...',
                        'Fetching projects...',
                        'Found 3 versions. Fetching vulnerabilities...',
                        'Processed version 1.0.0 (1/3)...',
                        'Processed version 1.1.0 (2/3)...',
                    ],
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
                log: [
                    'Starting...',
                    'Fetching projects...',
                    'Found 3 versions. Fetching vulnerabilities...',
                    'Processed version 1.0.0 (1/3)...',
                    'Processed version 1.1.0 (2/3)...',
                    'Processed version 2.0.0 (3/3)...',
                    'Grouping vulnerabilities...',
                ],
                result: [
                    {
                        id: 'CVE-2024-9999',
                        title: 'Critical dependency issue in shared parser',
                        description: 'A grouped vulnerability with direct and transitive dependencies across several versions.',
                        severity: 'CRITICAL',
                        cvss: 9.8,
                        cvss_score: 9.8,
                        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
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
                ],
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

        await expect(page.getByRole('heading', { name: 'Global Assessment' })).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('PlatformTeam').first()).toBeVisible({ timeout: 10000 })
        await expect(page.locator('text=Legacy alias assessment block retained for compatibility.').first()).toBeVisible({ timeout: 10000 })

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
        await captureWithPadding(card, '../docs/screenshots/project-view-dependencies.png')
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
        // Verify the approve button is visible (reviewer role + pending review)
        await expect(needsApprovalCard.locator('[data-testid="approve-btn"]')).toBeVisible({ timeout: 5000 })

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

        // Click the Statistics tab in the sidebar
        const statsTab = page.getByText('Statistics', { exact: true }).first()
        await expect(statsTab).toBeVisible({ timeout: 5000 })
        await statsTab.click()
        await page.waitForTimeout(500)

        // Verify the statistics content is visible
        await expect(page.getByText('Findings', { exact: false }).first()).toBeVisible({ timeout: 5000 })

        // Capture just the sidebar area
        const sidebar = page.locator('[class*="sticky"]').filter({ hasText: 'Statistics' }).first()
        await captureWithPadding(sidebar, '../docs/screenshots/statistics-sidebar.png')
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

    test('capture expanded card with assessment details screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        // Expand the inconsistent card to show conflicting team assessments
        const card = await openProjectCard(page, 'CVE-2024-5003')

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
        await openProjectCard(page, 'CVE-2024-6004')

        // Wait for expanded state and find the calculator button
        await page.waitForTimeout(1500)
        const calcButton = page.locator('button').filter({ hasText: /calculator/i }).first()
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

    test('capture bulk approve modal screenshot', async ({ page }) => {
        // We need to trigger the bulk approve modal programmatically since
        // there's no direct button in the header for it
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })
        await page.waitForTimeout(1000)

        // Trigger the bulk approve modal via evaluate
        await page.evaluate(() => {
            // Find the Vue app instance and trigger the modal
            const el = document.querySelector('[data-v-app]') || document.getElementById('app')
            if (el && (el as any).__vue_app__) {
                // Walk through to find the ProjectView component
                const walkComponents = (instance: any): any => {
                    if (instance?.proxy?.showBulkApproveModal !== undefined) return instance.proxy
                    if (instance.subTree?.component) {
                        const found = walkComponents(instance.subTree.component)
                        if (found) return found
                    }
                    if (instance.subTree?.children) {
                        for (const child of instance.subTree.children) {
                            if (child?.component) {
                                const found = walkComponents(child.component)
                                if (found) return found
                            }
                        }
                    }
                    return null
                }
                const root = (el as any).__vue_app__._instance
                const proxy = walkComponents(root)
                if (proxy) proxy.showBulkApproveModal = true
            }
        })
        await page.waitForTimeout(500)

        const modal = page.locator('.fixed.inset-0').filter({ hasText: 'Bulk Approve' }).first()
        if (await modal.isVisible({ timeout: 3000 })) {
            await captureWithPadding(modal, '../docs/screenshots/bulk-approve-modal.png')
        }
    })

    test('capture conflict resolution modal screenshot', async ({ page }) => {
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')
        await expect(page.locator('.vuln-card').first()).toBeVisible({ timeout: 20000 })
        await page.waitForTimeout(500)

        // Expand the inconsistent card and force a conflict via the API response.
        const card = await openProjectCard(page, 'CVE-2024-5003')
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
        await expect(card.getByText('Code Analysis')).toBeVisible({ timeout: 10000 })
        await expect(card.getByText('Analyzing…')).toBeVisible({ timeout: 10000 })
        await expect(card.getByRole('button', { name: 'Running…' })).toBeVisible({ timeout: 10000 })

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
        await expect(card.getByText('Code Analysis')).toBeVisible({ timeout: 10000 })
        await expect(card.getByText('platform-gateway exposes a reachable parser initialization path used by external requests.')).toBeVisible({ timeout: 10000 })
        await expect(card.getByText('Apply to Assessment (code_analysis)')).toBeVisible({ timeout: 10000 })

        await card.getByRole('button', { name: /Pipeline Steps \(2\)/ }).click()
        await expect(card.getByText('Reachability scan')).toBeVisible({ timeout: 10000 })

        await page.setViewportSize({ width: 2200, height: 1800 })
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

        const queueButton = page.getByTitle('Analysis Queue')
        await expect(queueButton).toBeVisible({ timeout: 10000 })
        await queueButton.click()

        const dropdown = page.locator('.absolute.right-0.top-full.mt-2.w-96').first()
        await expect(dropdown).toBeVisible({ timeout: 10000 })
        const queueRows = dropdown.locator('.max-h-96 > div')
        await expect(queueRows.first()).toContainText('CVE-2024-9999')
        await expect(queueRows.nth(1)).toContainText('CVE-2023-1111')

        await dropdown.getByText('CVE-2024-4002').click()
        await expect(dropdown.getByText('The vulnerable parser-wrapper path is limited to a disabled batch import pipeline.')).toBeVisible({ timeout: 10000 })

        await captureWithPadding(dropdown, '../docs/screenshots/analysis-queue-dropdown.png')
    })
})
