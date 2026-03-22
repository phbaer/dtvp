import type { GroupedVuln, Tags, TagValue } from '../types';

export interface AssessmentBlock {
    team: string; // 'General' or specific team name
    state: string;
    user: string;
    details: string;
    justification: string;
    timestamp?: number;
}

export const STATE_PRIORITY: Record<string, number> = {
    "EXPLOITABLE": 0,
    "IN_TRIAGE": 1,
    "FALSE_POSITIVE": 2,
    "NOT_AFFECTED": 3,
    "RESOLVED": 4,
    "NOT_SET": 5,
};

export function tagToString(tag: TagValue | undefined | null): string {
    if (tag == null) return '';
    if (typeof tag === 'string') return tag;

    // Some legacy payloads may send tags as objects, either structured or arbitrary.
    const obj = tag as Record<string, any>;
    if (typeof obj.name === 'string' && obj.name) return obj.name;
    if (typeof obj.tag === 'string' && obj.tag) return obj.tag;
    return String(tag);
}

export function parseAssessmentBlocks(fullText: string): AssessmentBlock[] {
    const blocks: AssessmentBlock[] = [];
    if (!fullText) return blocks;

    // Split by team headers: --- [Team: Name] [State: State] ... ---
    const firstHeaderIndex = fullText.indexOf('--- [Team:');

    if (firstHeaderIndex > 0) {
        // There is something BEFORE the first header.
        // Check if it's just shared tags or real content
        const textBeforeHeader = fullText.slice(0, firstHeaderIndex);
        const contentBeforeHeader = textBeforeHeader
            .replace(/\[Rescored:\s*[\d\.]+\]/g, '')
            .replace(/\[Rescored Vector:\s*[^\]]+\]/g, '')
            .replace(/\[Status: Pending Review\]/g, '')
            .trim();

        if (contentBeforeHeader) {
            blocks.push({
                team: 'General',
                state: 'NOT_SET',
                user: 'Unknown',
                details: contentBeforeHeader,
                justification: 'NOT_SET'
            });
        }
    } else if (firstHeaderIndex === -1) {
        // No headers at all. Check if there's real content (ignoring tags)
        const content = fullText
            .replace(/\[Rescored:\s*[\d\.]+\]/g, '')
            .replace(/\[Rescored Vector:\s*[^\]]+\]/g, '')
            .replace(/\[Status: Pending Review\]/g, '')
            .trim();

        if (content) {
            blocks.push({
                team: 'General',
                state: 'NOT_SET',
                user: 'Unknown',
                details: content,
                justification: 'NOT_SET'
            });
            return blocks;
        }
    }

    // Now parse explicit blocks
    const headerRegex = /---\s*\[Team:\s*([^\]]+)\]\s*\[State:\s*([^\]]+)\](?:\s*\[Assessed By:\s*([^\]]+)\])?(?:\s*\[Date:\s*([^\]]+)\])?(?:\s*\[Justification:\s*([^\]]+)\])?.*?\s*---/g;

    let match;
    while ((match = headerRegex.exec(fullText)) !== null) {
        const team = match[1];
        if (!team) continue;

        const state = match[2] || 'NOT_SET';
        const user = match[3] || 'Unknown';

        let timestamp: number | undefined = undefined;
        let justification = 'NOT_SET';

        if (match[4] && !isNaN(Number(match[4]))) {
            timestamp = Number(match[4]);
            justification = match[5] || 'NOT_SET';
        } else if (match[4]) {
            timestamp = undefined;
            justification = match[5] || 'NOT_SET';
        }

        if (match[5]) {
            justification = match[5];
        }

        const startOfContent = match.index + match[0].length;

        // Find end of content (start of next header or end of string)
        const nextHeaderRegex = /---\s*\[Team:/g;
        nextHeaderRegex.lastIndex = startOfContent;
        const nextMatch = nextHeaderRegex.exec(fullText);

        const endOfContent = nextMatch ? nextMatch.index : fullText.length;
        const rawContent = fullText.slice(startOfContent, endOfContent).trim();

        // Clean up redundant metadata from the display text
        let content = rawContent
        // Cleanup all metadata from content to prevent leakage
        content = content
            .replace(/\[(Rescored|Rescored Vector|Assessed By|Reviewed By|Team|State|Justification|Date):\s*[^\]]*\]/g, '')
            .replace(/\[Status: Pending Review\]/g, '')
            .replace(/\[Comment\]/g, '')
            .replace(/\bAssessed\s*--\s*\S+/g, '')
            .replace(/--\s*\S+\s*$/gm, '')
            .trim();

        // Also remove the specific header and any subsequent headers if they somehow leaked into content
        content = content.replace(/---\s*\[Team:.*?---\s*/g, '').trim();

        const userEscaped = user.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        content = content.replace(new RegExp(`--\\s*${userEscaped}\\s*$`, 'm'), '').trim();

        blocks.push({
            team,
            state,
            user,
            details: content,
            justification,
            timestamp
        });
    }

    return blocks;
}

export function constructAssessmentDetails(
    blocks: AssessmentBlock[],
    sharedTags: string[] = [],
    isPending: boolean = true
): { text: string, aggregatedState: string } {
    const parts: string[] = [];

    // Add shared tags first (e.g. [Rescored: ...])
    if (sharedTags.length > 0) {
        parts.push(sharedTags.join(' '));
    }

    // Preserve the order in the array for generation
    for (const b of blocks) {
        const dateStr = b.timestamp ? ` [Date: ${b.timestamp}]` : '';
        const header = `--- [Team: ${b.team}] [State: ${b.state}] [Assessed By: ${b.user}]${dateStr} [Justification: ${b.justification || 'NOT_SET'}] ---`;
        parts.push(header);
        if (b.details) parts.push(b.details);
    }

    // Calculate Aggregated State
    const generalBlock = blocks.find(b => b.team === 'General');
    let aggState = 'NOT_SET';

    if (generalBlock && generalBlock.state !== 'NOT_SET') {
        // Global Precedence: If General is set, it wins
        aggState = generalBlock.state;
    } else {
        // Fallback: Worst of all team states
        const allStates = blocks.map(b => b.state).filter(s => s !== 'NOT_SET');
        if (allStates.length > 0) {
            allStates.sort((a, b) => (STATE_PRIORITY[a] ?? 10) - (STATE_PRIORITY[b] ?? 10));
            aggState = allStates[0] || 'NOT_SET';
        }
    }

    // Add status tag if pending
    if (isPending) {
        parts.push(`\n[Status: Pending Review]`);
    }

    return {
        text: parts.join('\n\n'),
        aggregatedState: aggState
    };
}

/**
 * Calculates a consensus assessment from multiple blocks.
 * Used by "Sync all" (INCOMPLETE) and "Apply worst assessment" (INCONSISTENT).
 */
export function getConsensusAssessment(
    blocks: AssessmentBlock[],
    displayState: 'INCOMPLETE' | 'INCONSISTENT' | string,
    dependencyTrackStates: string[] = [],
    dependencyTrackJustification?: string
): { state: string, justification: string, details: string } {
    let state = 'NOT_SET'
    let justification = 'NOT_SET'
    let details = ''

    // If DT provides a known consensus state, let it override the derived state.
    // Dependency Track is the source of truth for what state is actually stored.
    const dtStates = dependencyTrackStates
        .filter(s => s && s !== 'NOT_SET')
        .sort((a, b) => (STATE_PRIORITY[a] ?? 10) - (STATE_PRIORITY[b] ?? 10));
    const dtWorstState = dtStates.length > 0 ? dtStates[0] : 'NOT_SET';

    const dtJustification = dependencyTrackJustification && dependencyTrackJustification !== 'NOT_SET'
        ? dependencyTrackJustification
        : undefined;

    if (blocks.length === 0) return { state, justification, details }

    // 1. Determine state and justification
    const justificationFromBlocks = blocks.find(b => b.justification && b.justification !== 'NOT_SET')?.justification

    if (dtWorstState !== 'NOT_SET') {
        state = dtWorstState
        // If DT provides a justification, treat it as authoritative as well.
        if (dtJustification) {
            justification = dtJustification
        } else {
            // Prefer a justification from a matching DT state block if present.
            const matchingStateJustification = blocks.find(
                b => b.state === dtWorstState && b.justification && b.justification !== 'NOT_SET'
            )?.justification

            if (matchingStateJustification) {
                justification = matchingStateJustification
            } else if (justificationFromBlocks) {
                // If no matching state justification, use any available assessment justification.
                justification = justificationFromBlocks
            } else {
                justification = 'NOT_SET'
            }
        }
    } else if (dtJustification) {
        // No DT state, but DT still has a justification — keep it.
        justification = dtJustification
    } else if (displayState === 'INCONSISTENT') {
        const nonMissing = blocks.filter(b => b.state !== 'NOT_SET')
        if (nonMissing.length > 0) {
            const sorted = [...nonMissing].sort((a, b) => (STATE_PRIORITY[a.state] ?? 10) - (STATE_PRIORITY[b.state] ?? 10))
            const worst = sorted[0]
            if (worst) {
                state = worst.state
                justification = worst.justification || 'NOT_SET'
            }
        }
    } else {
        const firstActive = blocks.find(b => b.state !== 'NOT_SET')
        if (firstActive) {
            state = firstActive.state
            justification = firstActive.justification || 'NOT_SET'
        }
    }

    // 2. Combine all details.
    // In INCONSISTENT mode ("Apply worst assessment"), skip the General block:
    // it stores the previously derived combination, so including it would
    // re-duplicate all team-block content on repeated applies.
    // In INCOMPLETE mode ("Sync all"), the General block is a legitimate
    // first-party assessment and should be included.
    const combinedParts: string[] = []
    for (const b of blocks) {
        if (displayState === 'INCONSISTENT' && b.team === 'General') continue
        const cleaned = (b.details || '')
            .replace(/\n\n\[Status: Pending Review\]/g, '')
            .replace(/\[Status: Pending Review\]/g, '')
            .trim()
        if (cleaned) {
            combinedParts.push(`[${b.team}] ${cleaned}`)
        }
    }
    details = combinedParts.join('\n\n')

    return { state, justification, details }
}

export function parseJustificationFromText(text: string): string | undefined {
    if (!text) return undefined
    const match = text.match(/justification\s*:\s*([A-Z0-9_]+)/i)
    if (match?.[1]) return match[1].toUpperCase()
    return undefined
}

export function mergeTeamAssessment(
    currentFullText: string,
    team: string,
    newState: string,
    newDetails: string,
    user: string,
    newJustification: string = 'NOT_SET',
    rescoredTags?: string[],
    isPending: boolean = true
): { text: string, aggregatedState: string } {
    // 1. Parse existing
    const blocks = parseAssessmentBlocks(currentFullText);

    // 2. Update or Create block for this team
    const targetIndex = blocks.findIndex(b => b.team === team);
    const newBlock: AssessmentBlock = {
        team: team,
        state: newState,
        user: user,
        details: newDetails.trim(),
        justification: newJustification,
        timestamp: Date.now()
    };

    if (targetIndex >= 0) {
        blocks[targetIndex] = newBlock;
    } else {
        blocks.push(newBlock);
    }

    // 3. Extract or use provided tags
    let tags: string[] = [];
    if (rescoredTags) {
        tags = rescoredTags;
    } else {
        // Simple regex for now - assumes they are at the very start
        const rescoredMatch = currentFullText.match(/\[Rescored:\s*[\d\.]+\]/);
        if (rescoredMatch) tags.push(rescoredMatch[0]);

        const vectorMatch = currentFullText.match(/\[Rescored Vector:\s*[^\]]+\]/);
        if (vectorMatch) tags.push(vectorMatch[0]);
    }

    // 4. Construct new text
    return constructAssessmentDetails(blocks, tags, isPending);
}

/**
 * Builds the full assessment text for a bulk sync operation.
 *
 * Strategy:
 * - Preserves all existing team-specific blocks verbatim (state + details).
 * - Creates or updates the "General" (global policy) block:
 *     - Keeps any existing user-added comment in the General block.
 *     - Appends a compact team-state summary (e.g. "[TeamA] IN_TRIAGE") so
 *       the reader has context without duplicating raw team details.
 *     - Does NOT introduce duplicate team entries.
 * - Aggregated state: uses General block state if explicitly set, otherwise
 *   worst state across all team blocks.
 *
 * @param allBlocks   Collected blocks from all instances (de-duplicated by team).
 * @param existingGeneralText Full text of the instance that currently carries a
 *                            General block (if any). Used to extract an existing
 *                            user comment. Pass empty string if none.
 * @returns { text, aggregatedState }
 */
export function buildBulkSyncDetails(
    allBlocks: AssessmentBlock[],
    existingGeneralText: string = '',
    overrideGeneralState: string = 'NOT_SET'
): { text: string, aggregatedState: string } {
    // 1. Separate out the General block from team-specific blocks.
    const teamBlocks = allBlocks.filter(b => b.team !== 'General');
    const existingGeneral = allBlocks.find(b => b.team === 'General');

    // 2. Recover any user-added comment from the existing General block.
    //    Priority: block already in allBlocks → parse from existingGeneralText.
    let userComment = (existingGeneral?.details || '').trim();
    if (!userComment && existingGeneralText) {
        const parsed = parseAssessmentBlocks(existingGeneralText);
        const generalBlock = parsed.find(b => b.team === 'General');
        userComment = (generalBlock?.details || '').trim();
    }

    // 3. Build a compact team-state summary (skip teams with NOT_SET state).
    const summaryLines = teamBlocks
        .filter(b => b.state && b.state !== 'NOT_SET')
        .map(b => `[${b.team}] ${b.state}`);
    const summaryText = summaryLines.length > 0
        ? `Team assessments:\n${summaryLines.join('\n')}`
        : '';

    // 4. Compose General block details: keep user comment, append summary.
    const generalDetailsParts: string[] = [];
    if (userComment) generalDetailsParts.push(userComment);
    if (summaryText) generalDetailsParts.push(summaryText);
    const generalDetails = generalDetailsParts.join('\n\n');

    // 5. Determine the General block state.
    //    If it was explicitly set (not NOT_SET), keep it; otherwise NOT_SET so
    //    the aggregation falls through to worst-team-state logic.
    const generalState = (overrideGeneralState && overrideGeneralState !== 'NOT_SET')
        ? overrideGeneralState
        : (existingGeneral?.state && existingGeneral.state !== 'NOT_SET')
            ? existingGeneral.state
            : 'NOT_SET';
    const generalUser = existingGeneral?.user || 'General';
    const generalJustification = existingGeneral?.justification || 'NOT_SET';

    // 6. Assemble the final block list: General first, then team blocks.
    const generalBlock: AssessmentBlock = {
        team: 'General',
        state: generalState,
        user: generalUser,
        details: generalDetails,
        justification: generalJustification,
    };

    const finalBlocks: AssessmentBlock[] = [generalBlock, ...teamBlocks];

    // 7. Construct the final text — NOT pending (this is a reviewer-level bulk action).
    return constructAssessmentDetails(finalBlocks, [], false);
}

export function hasGlobalAssessment(blocks: AssessmentBlock[]): boolean {
    return blocks.some(b => b.team === 'General' && b.state !== 'NOT_SET');
}

export function isPendingReview(group: GroupedVuln): boolean {
    return (group.affected_versions || []).some(v => 
        (v.components || []).some(c => {
            const details = (c as any).analysis_details || (c as any).analysisDetails || '';
            return details.includes('[Status: Pending Review]');
        })
    );
}

export function getGroupLifecycle(group: GroupedVuln, requiredTeamsOrTags: Tags | undefined, teamMapping?: Record<string, string | string[]>): string {
    const requiredTeams = teamMapping
        ? normalizeTags(requiredTeamsOrTags, teamMapping)
        : (requiredTeamsOrTags || []).map(tagToString).filter(Boolean);
    const allInstances = (group.affected_versions || []).flatMap(v => v.components || []);
    if (allInstances.length === 0) return 'OPEN';

    const allCompStates = allInstances.map(i => (i as any).analysis_state || (i as any).analysisState || 'NOT_SET');
    const hasMissingComponent = allCompStates.includes('NOT_SET');
    const hasAnyAssessment = allCompStates.some(s => s !== 'NOT_SET');

    // If multiple distinct technical states exist across components and there is
    // no structured block information, treat as INCONSISTENT.
    const distinctNonMissingStates = Array.from(new Set(allCompStates.filter(s => s !== 'NOT_SET')));
    if (distinctNonMissingStates.length > 1) {
        return 'INCONSISTENT';
    }

    const allBlocks: AssessmentBlock[] = [];
    allInstances.forEach(inst => {
        const details = (inst as any).analysis_details || (inst as any).analysisDetails || '';
        if (details) {
            allBlocks.push(...parseAssessmentBlocks(details));
        }
    });

    const blocks = allBlocks;
    const hasGlobal = hasGlobalAssessment(blocks);

    // If there are no structured assessment blocks but the system has a technical
    // state (analysis_state) set, it was likely assessed via a legacy workflow.
    // These are still considered "assessed" but are distinguished from ones
    // approved using the tool's structured workflow.
    if (blocks.length === 0 && hasAnyAssessment) {
        return 'ASSESSED_LEGACY';
    }

    // If we only have a single General block (from plaintext) but the component
    // already has a non-NOT_SET analysis_state, treat it as legacy assessed.
    if (
        blocks.length === 1 &&
        blocks[0].team === 'General' &&
        blocks[0].state === 'NOT_SET' &&
        hasAnyAssessment
    ) {
        return 'ASSESSED_LEGACY';
    }

    if (isPendingReview(group)) return 'NEEDS_APPROVAL';

    const missingTeams = (requiredTeams || []).filter((t: string) => !blocks.some(b => b.team === t && b.state !== 'NOT_SET'));
    // OPEN should only mean nothing is assessed yet. If a technical state exists but
    // required team/global assessments are missing, classify it as INCOMPLETE.
    if (!hasGlobal && missingTeams.length > 0) {
        return hasAnyAssessment ? 'INCOMPLETE' : 'OPEN';
    }

    // Incomplete / Inconsistent logic based on VERSIONS
    const versionStates = (group.affected_versions || []).map(v => {
        const states = Array.from(new Set((v.components || []).map(c => (c as any).analysis_state || (c as any).analysisState || 'NOT_SET')));
        if (states.length === 0) return 'NOT_SET';
        if (states.length === 1) return states[0];
        const nonMissing = states.filter(s => s !== 'NOT_SET');
        if (nonMissing.length === 1) return nonMissing[0];
        if (nonMissing.length > 1) return 'INCONSISTENT_VERSION';
        return 'NOT_SET';
    });

    const nonEmptyStates = versionStates.filter(s => s !== 'NOT_SET' && s !== 'INCONSISTENT_VERSION');
    const uniqueNonEmpty = new Set(nonEmptyStates);

    if (uniqueNonEmpty.size > 1 || versionStates.includes('INCONSISTENT_VERSION')) return 'INCONSISTENT';
    
    // Stricter Incomplete: Also check if ANY individual component is NOT_SET
    // when others in the same group have an assessment.
    if (hasMissingComponent && hasAnyAssessment) {
        // We have some assessments but not all components are covered.
        // Check if the existing ones are at least consistent.
        if (uniqueNonEmpty.size <= 1) {
            return 'INCOMPLETE';
        }
        return 'INCONSISTENT';
    }

    if (hasGlobal) return 'ASSESSED';

    // Fallback: if we have components but no global, it's either INCONSISTENT, INCOMPLETE, 
    // or if we specifically lack global and a team, it's OPEN.
    if (allInstances.length > 0 && !hasGlobal) {
        // If we reached here, it means missingTeams was 0 and versionStates was consistent.
        // But if there's no global, we usually want it to be ASSESSABLE.
        // The user definition says OPEN is missing a team.
        // If all teams are present but no global, it's basically "Ready for Global".
        // Let's call it INCOMPLETE (as it lacks the global version of the truth).
        return hasAnyAssessment ? 'INCOMPLETE' : 'OPEN';
    }
    
    return 'OPEN';
}

/**
 * Returns the technical state of a group for sorting/filtering.
 * Logic: Global Assessment State -> Worst Team Assessment State fallback.
 */
export function getGroupTechnicalState(group: GroupedVuln): string {
    const allInstances = (group.affected_versions || []).flatMap(v => v.components || []);
    if (allInstances.length === 0) return 'NOT_SET';

    // Parse all assessment blocks across all instances (versions/components).
    // This ensures we correctly capture the "worst" state even when a group is
    // represented by multiple components or versions with different states.
    const blocks: AssessmentBlock[] = [];
    allInstances.forEach(inst => {
        const details = (inst as any).analysis_details || (inst as any).analysisDetails || '';
        if (details) {
            blocks.push(...parseAssessmentBlocks(details));
        }
    });

    // 1. Global Precedence
    const globalState = blocks.find(b => b.team === 'General')?.state;
    if (globalState && globalState !== 'NOT_SET') return globalState;

    // 2. Worst Team State (across all blocks)
    const teamStates = blocks
        .filter(b => b.team !== 'General' && b.state !== 'NOT_SET')
        .map(b => b.state);

    if (teamStates.length > 0) {
        teamStates.sort((a, b) => (STATE_PRIORITY[a] ?? 10) - (STATE_PRIORITY[b] ?? 10));
        return teamStates[0];
    }

    // 3. Last Fallback: Worst of the raw component analysis_states (handles mock data without details)
    const rawStates = allInstances
        .map(i => (i as any).analysis_state || (i as any).analysisState || 'NOT_SET')
        .filter(s => s !== 'NOT_SET');

    if (rawStates.length > 0) {
        const uniqueRaw = Array.from(new Set(rawStates));
        uniqueRaw.sort((a, b) => (STATE_PRIORITY[a] ?? 10) - (STATE_PRIORITY[b] ?? 10));
        return uniqueRaw[0];
    }

    return 'NOT_SET';
}


export function normalizeTags(tags: Tags | undefined, teamMapping: Record<string, any>): string[] {
    if (!tags) return [];
    if (!teamMapping) return tags.map(tagToString).filter(Boolean);

    const result = new Set<string>();
    tags.forEach((tag: TagValue) => {
        const strTag = tagToString(tag);
        if (!strTag) return;

        let foundPrimary = strTag;
        for (const componentName in teamMapping) {
            const mappingVal = teamMapping[componentName];
            if (Array.isArray(mappingVal) && mappingVal.length > 1) {
                const primary = mappingVal[0];
                const aliases = mappingVal.slice(1);
                if (aliases.includes(strTag)) {
                    foundPrimary = primary;
                    break;
                }
            }
        }
        result.add(foundPrimary);
    });
    return Array.from(result);
}

export function matchesFilters(
    group: GroupedVuln, 
    lifecycleFilters: string[], 
    analysisFilters: string[], 
    teamMapping: Record<string, any>
): boolean {
    if (lifecycleFilters.length === 0 || analysisFilters.length === 0) return false;

    const tags = normalizeTags(group.tags, teamMapping);
    const state = getGroupLifecycle(group, tags, teamMapping);
    const isPending = isPendingReview(group);

    // 1. Lifecycle Match
    const lifecycleMatch = (lifecycleFilters.includes('OPEN') && state === 'OPEN') ||
                           (lifecycleFilters.includes('ASSESSED') && state === 'ASSESSED') ||
                           (lifecycleFilters.includes('ASSESSED_LEGACY') && state === 'ASSESSED_LEGACY') ||
                           (lifecycleFilters.includes('INCOMPLETE') && state === 'INCOMPLETE') ||
                           (lifecycleFilters.includes('INCONSISTENT') && state === 'INCONSISTENT') ||
                           (lifecycleFilters.includes('NEEDS_APPROVAL') && isPending);

    if (!lifecycleMatch) return false;

    // 2. Analysis Match (Strict Hierarchical logic)
    // A group matches if:
    // - It is OPEN (no technical state yet, so it matches any analysis filter that includes NOT_SET)
    // - OR its overall technical state matches one of the filters
    const techState = getGroupTechnicalState(group);
    if (techState === 'NOT_SET') {
        return analysisFilters.includes('NOT_SET');
    }
    return analysisFilters.includes(techState);
}
