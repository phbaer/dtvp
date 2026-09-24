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

// Small API-shaped counters; keep browser fixtures independent of Vite-only modules.
const countsForGroups = (groups: GroupedTaskItem[]) => {
    const lifecycle = Object.fromEntries(['OPEN', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL', 'READY_FOR_APPROVAL', 'ASSESSED', 'ASSESSED_LEGACY'].map(key => [key, 0]));
    const tags: Record<string, number> = {};
    const team_tags: Record<string, { open: number; assessed: number }> = {};
    const analysis: Record<string, number> = {};
    const dependency_relationship = { direct: 0, transitive: 0, unknown: 0 };
    for (const group of groups) {
        for (const key of Object.keys(lifecycle)) if (matchesLifecycle(group, [key])) lifecycle[key]!++;
        const state = group.list_metadata?.technical_state || 'NOT_SET';
        analysis[state] = (analysis[state] || 0) + 1;
        const dependency = String(group.list_metadata?.dependency_relationship || 'UNKNOWN').toLowerCase() as keyof typeof dependency_relationship;
        dependency_relationship[dependency]++;
        for (const tag of group.tags || []) {
            tags[tag] = (tags[tag] || 0) + 1;
            const count = team_tags[tag] ||= { open: 0, assessed: 0 };
            if (['ASSESSED', 'ASSESSED_LEGACY'].includes(lifecycleForGroup(group))) count.assessed++;
            else count.open++;
        }
    }
    return { total: groups.length, lifecycle, analysis, dependency_relationship, tags, team_tags, cvss_version_mismatch: 0 };
};

export async function mockGroupedVulnTask(
    page: Page,
    { taskId, groups }: MockGroupedVulnTaskOptions,
) {
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
        const textTerms = (url.searchParams.get('q') || '').toLowerCase().split(/\s+/).filter(Boolean);
        const filteredGroups = groups.filter(group => {
            const tags = (group.tags || []).map((tag: string) => tag.toLowerCase());
            if (selectedTeams.length && !selectedTeams.some(name => tags.includes(name))) return false;
            const searchable = [group.id, group.title, group.description, ...tags].join(' ').toLowerCase();
            if (!textTerms.every(term => searchable.includes(term))) return false;
            const explicitTerms = (url.searchParams.get('tag') || '').toLowerCase().split(/\s+/).filter(Boolean);
            if (!explicitTerms.every(term => tags.some((tag: string) => tag.includes(term)))) return false;
            const assessed = new Set((group.list_metadata?.assessed_teams || []).map((name: string) => name.toLowerCase()));
            const selected = tags.filter((tag: string) => tag !== 'unassigned' && selectedTeams.includes(tag));
            const status = !selected.length ? null : selected.some((tag: string) => !assessed.has(tag)) ? 'MISSING' : 'DOCUMENTED';
            if (selectedTeams.length && teamAssessment !== 'ANY' && status !== teamAssessment) return false;
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
                    filtered: countsForGroups(filteredGroups),
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
