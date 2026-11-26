import type { Page } from '@playwright/test';

type GroupedTaskItem = Record<string, any>;

interface MockGroupedVulnTaskOptions {
    taskId: string;
    groups: GroupedTaskItem[];
}

const completedStatus = (groups: GroupedTaskItem[]) => ({
    status: 'completed',
    message: 'Completed',
    progress: 100,
    result: groups,
    result_mode: 'summary',
});

const lifecycleForGroup = (group: GroupedTaskItem) => String(group.list_metadata?.lifecycle || 'OPEN').toUpperCase();

const matchesLifecycle = (group: GroupedTaskItem, filters: string[]) => {
    if (filters.length === 0) return true;

    const normalized = new Set(filters.map(value => value.toUpperCase()));
    const metadata = group.list_metadata || {};
    const lifecycle = lifecycleForGroup(group);
    const pending = metadata.is_pending ?? lifecycle === 'NEEDS_APPROVAL';
    return (
        (normalized.has('OPEN') && lifecycle === 'OPEN') ||
        (normalized.has('ASSESSED') && ['ASSESSED', 'ASSESSED_LEGACY'].includes(lifecycle)) ||
        (normalized.has('ASSESSED_LEGACY') && lifecycle === 'ASSESSED_LEGACY') ||
        (normalized.has('INCOMPLETE') && lifecycle === 'INCOMPLETE') ||
        (normalized.has('INCONSISTENT') && lifecycle === 'INCONSISTENT') ||
        (normalized.has('NEEDS_APPROVAL') && pending) ||
        (normalized.has('READY_FOR_APPROVAL') && (metadata.is_approval_ready ?? (pending && lifecycle === 'NEEDS_APPROVAL')))
    );
};

// The cutoff (ADR 0015), as dtvp/first_seen.py decides it from
// list_metadata.cutoff_dates[basis].
const cutoffEnd = (cutoff: string) => {
    const relative = /^(\d+)d$/.exec(cutoff);
    const day = relative
        ? new Date(Date.now() - Number(relative[1]) * 86400000).toISOString().slice(0, 10)
        : cutoff;
    return Date.parse(`${day}T00:00:00Z`) + 86400000;
};
const cutoffStatus = (group: GroupedTaskItem, cutoff: string, mode: string, versions: string[], basis = 'published') => {
    if (!cutoff) return 'known';
    const end = cutoffEnd(cutoff);
    const scope = versions.length ? new Set(versions.map(v => v.toLowerCase())) : null;
    const dates = group.list_metadata?.cutoff_dates?.[basis] || { by_version: {}, unknown: [] };
    const byVersion: Record<string, number[]> = dates.by_version || {};
    for (const [label, [low, high]] of Object.entries(byVersion)) {
        if (scope && !scope.has(label.toLowerCase())) continue;
        if (mode === 'after' ? high! >= end : low! < end) return 'known';
    }
    const unknown: string[] = dates.unknown || [];
    return unknown.some(label => !scope || scope.has(label.toLowerCase())) ? 'unknown' : null;
};

// A recorded General decision, or a closed vulnerability, stands for every
// team (the server's list_metadata.covers_all_teams).
const coversAllTeams = (group: GroupedTaskItem) => group.list_metadata?.covers_all_teams
    ?? (['ASSESSED', 'ASSESSED_LEGACY'].includes(lifecycleForGroup(group)) && !group.list_metadata?.is_pending);

// Small API-shaped counters; keep browser fixtures independent of Vite-only modules.
const countsForGroups = (groups: GroupedTaskItem[]) => {
    const lifecycle = Object.fromEntries(['OPEN', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL', 'READY_FOR_APPROVAL', 'ASSESSED', 'ASSESSED_LEGACY'].map(key => [key, 0]));
    const tags: Record<string, number> = {};
    const team_tags: Record<string, { open: number; assessed: number }> = {};
    const analysis: Record<string, number> = {};
    const dependency_relationship = { direct: 0, transitive: 0, unknown: 0 };
    let awaiting_review = 0;
    for (const group of groups) {
        if (group.list_metadata?.is_pending) awaiting_review++;
        for (const key of Object.keys(lifecycle)) if (matchesLifecycle(group, [key])) lifecycle[key]!++;
        const state = group.list_metadata?.technical_state || 'NOT_SET';
        analysis[state] = (analysis[state] || 0) + 1;
        const dependency = String(group.list_metadata?.dependency_relationship || 'UNKNOWN').toLowerCase() as keyof typeof dependency_relationship;
        dependency_relationship[dependency]++;
        for (const tag of group.tags || []) {
            tags[tag] = (tags[tag] || 0) + 1;
            const count = team_tags[tag] ||= { open: 0, assessed: 0 };
            const assessed = coversAllTeams(group)
                || (group.list_metadata?.assessed_teams || []).some((name: string) => name.toLowerCase() === tag.toLowerCase());
            if (assessed) count.assessed++;
            else count.open++;
        }
    }
    return { total: groups.length, lifecycle, analysis, dependency_relationship, tags, team_tags, cvss_version_mismatch: 0, awaiting_review };
};

/** No saved views and the built-in default (ADR 0015); specs override it. */
export async function mockNoSavedViews(page: Page) {
    await page.route('**/api/views?**', route => route.fulfill({
        json: {
            views: [],
            defaults: {
                user_project: null, user_all: null, role_project: null, role_all: null, roles: {},
                effective: { source: 'builtin', code: null, query: null },
            },
            role: 'REVIEWER',
            can_manage_global: true,
            limits: {},
        },
    }));
}

export async function mockGroupedVulnTask(
    page: Page,
    { taskId, groups }: MockGroupedVulnTaskOptions,
) {
    await mockNoSavedViews(page);
    // A reviewer's card asks whether Repair Assessments applies to its
    // vulnerability (Repair…). By default nothing does; a spec that needs a
    // repair routes this again after calling this helper, which then wins.
    await page.route('**/api/bulk-workflows/assessment-repair/preview', async (route) => {
        const body = route.request().postDataJSON() || {};
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                task_id: body.task_id || taskId,
                workflow: { id: 'assessment-repair', label: 'Repair Assessments', description: '', supports_apply: true, supports_document: false, version: 1 },
                preview_token: 'no-repair',
                group_fingerprints: {},
                selectable_group_ids: [],
                items: [],
                topics: [],
                summary: { groups: 0, findings: 0 },
            }),
        });
    });

    await page.route(`**/api/tasks/${taskId}**`, async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(completedStatus(groups)),
        });
    });

    await page.route(`**/api/tasks/${taskId}/groups**`, async (route) => {
        const url = new URL(route.request().url());
        const lifecycleFilters = url.searchParams.getAll('lifecycle').flatMap(value => value.split(','));
        const team = (url.searchParams.get('team') || '').toLowerCase();
        const teamAssessment = url.searchParams.get('team_assessment') || 'ANY';
        const selectedTeams = [...url.searchParams.getAll('teams'), ...(team ? [team] : [])].map(name => name.toLowerCase());
        const awaitingReview = url.searchParams.get('awaiting_review') === 'true';
        const textTerms = (url.searchParams.get('q') || '').toLowerCase().split(/\s+/).filter(Boolean);
        const cutoff = url.searchParams.get('cutoff') || '';
        const cutoffMode = url.searchParams.get('cutoff_mode') || 'before';
        const cutoffBasis = url.searchParams.get('cutoff_basis') || 'published';
        const versions = url.searchParams.getAll('versions').flatMap(value => value.split(',')).filter(Boolean);
        const filteredGroups = groups.filter(group => {
            if (versions.length && !(group.affected_versions || []).some((v: any) => versions.includes(v.project_version))) return false;
            if (cutoffStatus(group, cutoff, cutoffMode, versions, cutoffBasis) === null) return false;
            const tags = (group.tags || []).map((tag: string) => tag.toLowerCase());
            if (selectedTeams.length && !selectedTeams.some(name => tags.includes(name))) return false;
            const searchable = [group.id, group.title, group.description, ...tags].join(' ').toLowerCase();
            if (!textTerms.every(term => searchable.includes(term))) return false;
            const explicitTerms = (url.searchParams.get('tag') || '').toLowerCase().split(/\s+/).filter(Boolean);
            if (!explicitTerms.every(term => tags.some((tag: string) => tag.includes(term)))) return false;
            const assessed = new Set((group.list_metadata?.assessed_teams || []).map((name: string) => name.toLowerCase()));
            const selected = tags.filter((tag: string) => tag !== 'unassigned' && selectedTeams.includes(tag));
            const status = !selected.length ? null
                : !coversAllTeams(group) && selected.some((tag: string) => !assessed.has(tag)) ? 'MISSING' : 'DOCUMENTED';
            if (selectedTeams.length && teamAssessment !== 'ANY' && status !== teamAssessment) return false;
            if (awaitingReview && !group.list_metadata?.is_pending) return false;
            return matchesLifecycle(group, lifecycleFilters);
        });
        const requestedOffset = url.searchParams.get('cursor') || url.searchParams.get('offset') || '0';
        const offset = Math.max(0, Number.parseInt(requestedOffset, 10) || 0);
        const limit = Math.max(1, Number.parseInt(url.searchParams.get('limit') || '', 10) || filteredGroups.length || 50);
        const items = filteredGroups.slice(offset, offset + limit);
        const nextOffset = offset + items.length;
        const hasMore = nextOffset < filteredGroups.length;

        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                items,
                counts: {
                    all: countsForGroups(groups),
                    filtered: {
                        ...countsForGroups(filteredGroups),
                        cutoff: filteredGroups.length,
                        cutoff_unknown: cutoff
                            ? filteredGroups.filter(group => cutoffStatus(group, cutoff, cutoffMode, versions, cutoffBasis) === 'unknown').length
                            : 0,
                    },
                },
                total: groups.length,
                filtered: filteredGroups.length,
                offset,
                limit,
                cursor: url.searchParams.get('cursor') || null,
                next_cursor: hasMore ? String(nextOffset) : null,
                has_more: hasMore,
                sort: url.searchParams.get('sort') || 'rescored-severity',
                order: url.searchParams.get('order') || 'desc',
                cutoff_basis: cutoffBasis,
                result_mode: 'summary',
                source_result_mode: 'summary',
            }),
        });
    });

    await page.route(`**/api/tasks/${taskId}/events`, async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/x-ndjson',
            body: `${JSON.stringify({
                status: 'completed',
                message: 'Completed',
                progress: 100,
                result_mode: 'summary',
            })}\n`,
        });
    });
}
