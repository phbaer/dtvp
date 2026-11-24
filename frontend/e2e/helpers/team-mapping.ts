import type { Page } from '@playwright/test';

// Mocked API of Settings → Team Mapping, used by
// e2e/team-mapping-editor.spec.ts and the documentation screenshots.
const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

export const teams = {
    Core: { aliases: ['DE-Core'], components: ['vp-stats-app', 'gone-lib'] },
    Phoenix: { components: ['VPStatsApp'] },
    '3P': { components: ['libtiff'] },
    Unknown: { components: ['*'] },
};

export const report = {
    totals: { versions: 3, projects: 2, findings: 2400, owned_by_component: 1180, owned_by_project: 0, unmapped: 1220 },
    projects: [
        {
            name: 'ViewPoint_Product', findings: 1188, unmapped: 18, owned_by: { component: 1170, wildcard: 18 }, fallback_key: null,
            versions: [{ uuid: 'vp-6.14', version: '6.14.0' }, { uuid: 'vp-6.15', version: '6.15.0' }],
            root: { name: 'ViewPoint_Product', group: '', purl: '' },
        },
        {
            name: 'eventserver', findings: 1212, unmapped: 1202, owned_by: { wildcard: 1202, component: 10 }, fallback_key: null,
            versions: [{ uuid: 'ev-5', version: '5.0' }],
            root: { name: 'eventserver', group: '', purl: '' },
        },
    ],
    entries: { 'vp-stats-app': { findings: 993, projects: [{ name: 'ViewPoint_Product', findings: 993 }] }, libtiff: { findings: 187, projects: [] }, '*': { findings: 1220, projects: [] } },
    unmapped: [
        { kind: 'root', name: 'eventserver', group: '', purl: '', in_bom: true, findings: 1202,
            projects: [{ name: 'eventserver', findings: 1202, versions: ['5.0'] }], suggested_key: 'project::eventserver',
            suggestion_reason: 'Owns every finding of the project no component owns' },
        { kind: 'component', name: 'core', group: '', purl: '', in_bom: true, findings: 18,
            projects: [{ name: 'ViewPoint_Product', findings: 18, versions: ['6.14.0', '6.15.0'] }],
            suggested_key: 'project:ViewPoint_Product::core', suggestion_reason: 'A name without purl or group; scoped to the project' },
    ],
    unmapped_total: 2,
    near_duplicates: [],
    missing_versions: [],
    inventory: {
        projects: ['eventserver', 'ViewPoint_Product'],
        components: [
            ['ViewPoint_Product', '', '', [[1, 1188, 18, 1]]],
            ['stats-app', '', 'pkg:npm/vp-stats-app', [[1, 993, 0, 2]]],
            ['libtiff', '', 'pkg:generic/libtiff', [[1, 187, 0, 2]]],
            ['core', '', '', [[1, 18, 18, 2]]],
            ['zlib', '', 'pkg:generic/zlib', [[1, 18, 18, 0]]],
            ['eventserver', '', '', [[0, 1212, 1202, 1]]],
        ],
        total: 6,
        truncated: false,
    },
};

const node = (ref: string, name: string, extra: Record<string, unknown>) => ({
    ref, name, group: '', purl: '', root: false, unlinked: false, children: 0, findings_here: 0, findings: 0, unowned: 0,
    owner: { team: 'Unknown', kind: 'wildcard', key: '*' }, ...extra,
});
const root = node('root', 'ViewPoint_Product', { root: true, children: 3, findings: 1188, unowned: 18 });
const children = [
    node('core', 'core', { children: 1, findings: 18, unowned: 18 }),
    node('stats', 'stats-app', { purl: 'pkg:npm/vp-stats-app', children: 4, findings: 993, owner: { team: 'Core', kind: 'component', key: 'vp-stats-app' } }),
    node('tiff', 'libtiff', { purl: 'pkg:generic/libtiff', findings: 187, findings_here: 187, owner: { team: '3P', kind: 'component', key: 'libtiff' } }),
];
const below = [node('zlib', 'zlib', { purl: 'pkg:generic/zlib', findings: 18, findings_here: 18, unowned: 18 })];

/** ``catchAll`` answers every other API request with {} (registered first,
 * so the specific routes win); off where a suite mocks the rest itself. */
export async function mockTeamMappingApi(page: Page, saved: unknown[], { catchAll = true } = {}) {
    if (catchAll) await page.route('**/api/**', route => route.fulfill(json({})));
    await page.route(url => url.pathname.endsWith('/api/events'), route => route.fulfill({
        status: 200,
        headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' },
        body: 'id: e2e:1\nevent: hello\ndata: {"boot_id":"e2e","seq":1}\n\n',
    }));
    await page.route('**/auth/me', route => route.fulfill(json({ username: 'rita', role: 'REVIEWER' })));
    await page.route('**/api/version', route => route.fulfill(json({ version: '1.0.0', build: 'test' })));
    await page.route('**/api/settings/roles', route => route.fulfill(json({ rita: 'REVIEWER' })));
    await page.route('**/api/settings/rescore-rules', route => route.fulfill(json({ transitions: [] })));
    await page.route('**/api/project-archives**', route => route.fulfill(json([])));
    await page.route('**/api/settings/mapping', route => {
        if (route.request().method() === 'PUT') {
            saved.push(route.request().postDataJSON());
            return route.fulfill(json({ status: 'success', message: 'saved' }));
        }
        return route.fulfill(json({ 'vp-stats-app': ['Core', 'DE-Core'], libtiff: '3P', '*': 'Unknown' }));
    });
    await page.route('**/api/settings/mapping/teams', route => route.fulfill(json({ format: 'teams', teams, warnings: [] })));
    await page.route('**/api/settings/mapping/report**', route => route.fulfill(json({
        status: 'ready', stale: false, built_at: '2026-11-24T05:00:00Z', error: null, report,
    })));
    const treeLevel = (projectUuid: string | null, ref: string | null, draft?: Record<string, { components?: string[]; projects?: string[] }>) => {
        if (projectUuid === 'ev-5') {
            // A standalone project whose root owns its findings (a flat BOM).
            const team = Object.entries(draft || {}).find(([, value]) => (value.projects || []).includes('eventserver'))?.[0];
            const owner = team ? { team, kind: 'project', key: 'project::eventserver' } : { team: 'Unknown', kind: 'wildcard', key: '*' };
            const evRoot = node('ev-root', 'eventserver', {
                root: true, findings: 1212, findings_here: 1202, unowned: team ? 0 : 1202, owner,
                ...(team ? { saved_owner: { team: 'Unknown', kind: 'wildcard', key: '*' } } : {}),
            });
            const evBase = { project_uuid: projectUuid, project: 'eventserver', version: '5.0', findings: 1212, findings_outside_bom: 0 };
            return ref === null ? { ...evBase, root: evRoot } : { ...evBase, parent: ref, nodes: [], total: 0 };
        }
        const base = { project_uuid: projectUuid, project: 'ViewPoint_Product', version: '6.15.0', findings: 1188, findings_outside_bom: 0 };
        // A draft giving core to a team: core and zlib move from the catch-all.
        const coreTeam = Object.entries(draft || {}).find(([, team]) =>
            (team.components || []).some(key => key === 'project:ViewPoint_Product::core' || key === 'core'))?.[0];
        const wildcard = { team: 'Unknown', kind: 'wildcard', key: '*' };
        const moved = (item: ReturnType<typeof node>, kind: 'component' | 'inherited') => coreTeam
            ? { ...item, unowned: 0, owner: { team: coreTeam, kind, key: 'project:ViewPoint_Product::core', ...(kind === 'inherited' ? { from: ['core'] } : {}) }, saved_owner: wildcard }
            : item;
        if (ref === null) return { ...base, root: coreTeam ? { ...root, unowned: 0 } : root };
        if (ref === 'root') {
            const nodes = children.map(item => item.ref === 'core' ? moved(item, 'component') : item);
            return { ...base, parent: 'root', nodes, total: nodes.length };
        }
        if (ref === 'core') {
            const nodes = below.map(item => moved(item, 'inherited'));
            return { ...base, parent: 'core', nodes, total: nodes.length };
        }
        return { ...base, parent: ref, nodes: [], total: 0 };
    };
    await page.route('**/api/settings/mapping/tree?**', (route) => {
        const params = new URL(route.request().url()).searchParams;
        return route.fulfill(json(treeLevel(params.get('project_uuid'), params.get('ref'))));
    });
    // The tree of a draft (POST): owners as the draft would set them.
    await page.route(url => url.pathname.endsWith('/api/settings/mapping/tree'), (route) => {
        if (route.request().method() !== 'POST') return route.fallback();
        const body = route.request().postDataJSON();
        return route.fulfill(json(treeLevel(body.project_uuid, body.ref ?? null, body.mapping)));
    });
    // The preview: giving core to a team moves its 18 findings off the catch-all.
    await page.route('**/api/settings/mapping/preview', (route) => {
        const mapping: Record<string, { components?: string[] }> = route.request().postDataJSON()?.mapping || {};
        const team = Object.entries(mapping).find(([, value]) =>
            (value.components || []).some(key => key === 'project:ViewPoint_Product::core' || key === 'core'))?.[0];
        return route.fulfill(json(team
            ? { findings: 1188, changed: 18, moves: [{ from: 'Unknown', to: team, findings: 18 }], projects: [{ name: 'ViewPoint_Product', changed: 18 }] }
            : { findings: 2400, changed: 0, moves: [], projects: [] }));
    });
    await page.addInitScript(() => window.localStorage.setItem('dtvp_last_seen_version', '1.0.0'));
}

