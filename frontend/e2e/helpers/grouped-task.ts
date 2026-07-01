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
    return (
        (normalized.has('OPEN') && (metadata.is_open ?? lifecycle === 'OPEN')) ||
        (normalized.has('ASSESSED') && lifecycle === 'ASSESSED') ||
        (normalized.has('ASSESSED_LEGACY') && lifecycle === 'ASSESSED_LEGACY') ||
        (normalized.has('INCOMPLETE') && lifecycle === 'INCOMPLETE') ||
        (normalized.has('INCONSISTENT') && lifecycle === 'INCONSISTENT') ||
        (normalized.has('NEEDS_APPROVAL') && (metadata.is_pending ?? lifecycle === 'NEEDS_APPROVAL'))
    );
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
        const filteredGroups = groups.filter(group => matchesLifecycle(group, lifecycleFilters));
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
