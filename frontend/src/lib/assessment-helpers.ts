
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

export function parseAssessmentBlocks(fullText: string): Record<string, AssessmentBlock> {
    const blocks: Record<string, AssessmentBlock> = {};
    if (!fullText) return blocks;

    // Split by team headers: --- [Team: Name] [State: State] ... ---
    // We need to capture the delimiter to know where blocks start
    // Using positive lookahead to split but keep the delimiter for the next part is tricky in JS split
    // Easier to regex match all parts

    // First, check for "Legacy" or "General" text at the start (before any header)
    const firstHeaderIndex = fullText.indexOf('--- [Team:');
    if (firstHeaderIndex > 0) {
        const generalText = fullText.slice(0, firstHeaderIndex).trim();
        if (generalText) {
            blocks['General'] = {
                team: 'General',
                state: 'NOT_SET', // Implicit
                user: 'Unknown',
                details: generalText,
                justification: 'NOT_SET'
            };
        }
    } else if (firstHeaderIndex === -1 && fullText.trim()) {
        // No headers at all, treat whole text as General
        blocks['General'] = {
            team: 'General',
            state: 'NOT_SET',
            user: 'Unknown',
            details: fullText.trim(),
            justification: 'NOT_SET'
        };
        return blocks;
    }

    // Now parse explicit blocks
    // Regex to match header and content (now adding optional Date)
    // We iterate through matches
    const headerRegex = /---\s*\[Team:\s*([^\]]+)\]\s*\[State:\s*([^\]]+)\](?:\s*\[Assessed By:\s*([^\]]+)\])?(?:\s*\[Date:\s*([^\]]+)\])?(?:\s*\[Justification:\s*([^\]]+)\])?.*?\s*---/g;

    let match;
    while ((match = headerRegex.exec(fullText)) !== null) {
        const team = match[1];
        if (!team) continue; // Should not happen based on regex but satisfies TS

        const state = match[2] || 'NOT_SET';
        const user = match[3] || 'Unknown';

        // Handle optional groups where Date might be present or absent
        // Because of the order in the regex, match[4] is Date, match[5] is Justification
        // If Justification format was used before Date exist, we need to be careful, but we control the format.
        let timestamp: number | undefined = undefined;
        let justification = 'NOT_SET';

        if (match[4] && !isNaN(Number(match[4]))) {
            timestamp = Number(match[4]);
            justification = match[5] || 'NOT_SET';
        } else if (match[4]) {
            // It might be justification if Date is missing and the regex matched a justification block into group 4 due to how optional non-capturing groups behave?
            // Actually, the literal `[Date:` vs `[Justification:` inside the non-capturing groups forces correct capturing or undefined.
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
        const content = rawContent
            .replace(/\n\n\[Status: Pending Review\]/g, '')
            .replace(/\[Status: Pending Review\]/g, '')
            .trim();

        blocks[team] = {
            team,
            state,
            user,
            details: content,
            justification,
            timestamp
        };
    }

    return blocks;
}

export function constructAssessmentDetails(
    blocks: Record<string, AssessmentBlock>,
    sharedTags: string[] = [],
    isPending: boolean = true
): { text: string, aggregatedState: string } {
    const parts: string[] = [];

    // Add shared tags first (e.g. [Rescored: ...])
    if (sharedTags.length > 0) {
        parts.push(sharedTags.join(' '));
    }

    // Always put General first if it exists
    if (blocks['General']) {
        const b = blocks['General'];
        if (b) {
            const dateStr = b.timestamp ? ` [Date: ${b.timestamp}]` : '';
            const header = `--- [Team: General] [State: ${b.state}] [Assessed By: ${b.user}]${dateStr} [Justification: ${b.justification || 'NOT_SET'}] ---`;
            parts.push(header);
            if (b.details) parts.push(b.details);
        }
    }

    // Sort other teams alphabetically
    const teamNames = Object.keys(blocks).filter(k => k !== 'General').sort();

    for (const team of teamNames) {
        const b = blocks[team];
        if (b) {
            const dateStr = b.timestamp ? ` [Date: ${b.timestamp}]` : '';
            const header = `--- [Team: ${team}] [State: ${b.state}] [Assessed By: ${b.user}]${dateStr} [Justification: ${b.justification || 'NOT_SET'}] ---`;
            parts.push(header);
            if (b.details) parts.push(b.details);
        }
    }

    // Calculate Aggregated State
    const generalBlock = blocks['General'];
    let aggState = 'NOT_SET';

    if (generalBlock && generalBlock.state !== 'NOT_SET') {
        // Global Precedence: If General is set, it wins
        aggState = generalBlock.state;
    } else {
        // Fallback: Worst of all team states
        const allStates = Object.values(blocks).filter(b => b !== undefined).map(b => b.state);
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
    blocks[team] = {
        team: team,
        state: newState,
        user: user,
        details: newDetails.trim(),
        justification: newJustification,
        timestamp: Date.now()
    };

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
