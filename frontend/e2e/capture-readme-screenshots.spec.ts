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
        HIGH: 6,
        MEDIUM: 3,
        LOW: 1,
        INFO: 1,
        UNKNOWN: 0,
    },
    state_counts: {
        EXPLOITABLE: 3,
        IN_TRIAGE: 5,
        FALSE_POSITIVE: 1,
        NOT_AFFECTED: 2,
        RESOLVED: 2,
        NOT_SET: 2,
        MIXED: 1,
    },
    total_unique: 15,
    total_findings: 27,
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

async function mockCommonShell(page: Parameters<typeof test.beforeEach>[0]['page']) {
    await page.setViewportSize({ width: 1180, height: 1400 })

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
                    { from: 'IN_TRIAGE', to: 'RESOLVED', requiresJustification: true },
                    { from: 'EXPLOITABLE', to: 'NOT_AFFECTED', requiresJustification: true },
                ],
            }),
        })
    })

    await page.route('**/api/statistics*', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(mockStatistics),
        })
    })

    await page.route('**/api/tasks/group-vulns*', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ task_id: 'task-docs' }),
        })
    })

    let taskPollCount = 0
    await page.route('**/api/tasks/task-docs', async (route) => {
        taskPollCount += 1
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
                ],
            }),
        })
    })

    await page.route('**/api/assessments/details', async (route) => {
        const body = route.request().postDataJSON()
        const results = (body.instances || []).map((inst: any) => ({
            finding_uuid: inst.finding_uuid,
            project_uuid: inst.project_uuid,
            component_uuid: inst.component_uuid,
            vulnerability_uuid: inst.vulnerability_uuid,
            analysis: {
                state: inst.component_uuid === 'c1' || inst.component_uuid === 'c2' ? 'IN_TRIAGE' : 'NOT_SET',
                analysisState: inst.component_uuid === 'c1' || inst.component_uuid === 'c2' ? 'IN_TRIAGE' : 'NOT_SET',
                isSuppressed: false,
                analysisDetails: inst.component_uuid === 'c1'
                    ? '--- [Team: LegacyPlatformAlias] [State: IN_TRIAGE] [Assessed By: reviewer] [Date: 1710000000000] [Justification: CODE_NOT_PRESENT] ---\nLegacy alias assessment block retained for compatibility.'
                    : '',
                analysisComments: [],
            },
        }))
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(results),
        })
    })

    await page.addInitScript(() => {
        window.localStorage.setItem('dtvp_last_seen_version', '1.0.0')
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
        await page.goto('/project/TestProject')
        await page.waitForLoadState('networkidle')

        const card = page.locator('.vuln-card').filter({ hasText: /CVE-2024-9999/ }).first()
        await expect(card).toBeVisible({ timeout: 20000 })
        const cardBox = await card.boundingBox()
        if (!cardBox) throw new Error('Expected vulnerability card bounding box')
        await page.mouse.click(cardBox.x + 120, cardBox.y + 40)

        await expect(page.getByRole('heading', { name: 'Global Assessment' })).toBeVisible({ timeout: 10000 })
        await expect(page.getByText('PlatformTeam').first()).toBeVisible({ timeout: 10000 })
        await expect(page.locator('text=Legacy alias assessment block retained for compatibility.').first()).toBeVisible({ timeout: 10000 })

        const chainsButton = page.getByRole('button', { name: /^chains$/ }).first()
        await chainsButton.click()
        await expect(page.getByText('platform-gateway').first()).toBeVisible({ timeout: 10000 })

        await captureWithPadding(page.locator('main > div').first(), '../docs/screenshots/project-view.png')

        const morePathsButton = page.getByRole('button', { name: /^\+1 more$/ }).first()
        await expect(morePathsButton).toBeVisible({ timeout: 10000 })
        await morePathsButton.click()
        await expect(page.getByText('gateway-facade').first()).toBeVisible({ timeout: 10000 })

        const dependencySection = page.getByText('Dependencies').first().locator('..')
        await captureWithPadding(dependencySection, '../docs/screenshots/project-view-dependencies.png')
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
})
