import type { Page } from '@playwright/test';

type SelectorMapping = Record<string, string | string[]>;
type TeamEntry = { aliases?: string[]; components: string[] };

/** The team document the server derives from a selector mapping (old
 * format): each key under its primary team, alias lists as team aliases. */
export const teamsFromSelectorMapping = (mapping: SelectorMapping): Record<string, TeamEntry> => {
    const teams: Record<string, TeamEntry> = {};
    for (const [key, value] of Object.entries(mapping)) {
        const [primary, ...aliases] = Array.isArray(value) ? value : [value];
        if (!primary) continue;
        const team = (teams[primary] ??= { components: [] });
        team.components.push(key);
        for (const alias of aliases) {
            team.aliases ??= [];
            if (!team.aliases.includes(alias)) team.aliases.push(alias);
        }
    }
    return teams;
};

/** Answer GET /api/settings/mapping/teams (the team list of the project
 * view and Settings) for a spec that mocks the selector mapping. */
export const routeMappingTeams = async (page: Page, mapping: SelectorMapping) => {
    await page.route('**/api/settings/mapping/teams', route => route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ format: 'selectors', teams: teamsFromSelectorMapping(mapping), warnings: [] }),
    }));
};
