
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
