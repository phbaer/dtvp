import { combineLifecycles, getAssessmentScopes, scopedGroup, type AssessmentScopeView } from './assessmentScopes';
import type { GroupedVuln, InconsistencyReason, Tags, TagValue } from '../types';
import { normalizeInconsistencyReasons } from './inconsistency';
import { maskSsvcDetails, ssvcDetailsPattern, stripSsvcDetails, stripSsvcDocumentation } from './ssvc';

export interface AssessmentBlock {
    ssvc?: string;
    ssvcDetails?: string;
    team: string; // 'General' or specific team name
    historical?: boolean;
    copiedFrom?: string;
    state: string;
    user: string;
    details: string;
    justification: string;
    timestamp?: number;
    assigned?: string[];
    evidenceReviewed?: boolean;
    versionCoverageChecked?: boolean;
    ticket?: string;
    /** The stored [Evidence Reviewed] / [Version Coverage] values. */
    evidenceReviewedValue?: string;
    versionCoverageValue?: string;
    // Read from a header that carries them; the form does not edit them.
    reviewer?: string;
    rescored?: number;
    vector?: string;
}

/** One team's assessment (or the General one) as the server stores it. */
export interface AssessmentTeamFields {
    team: string;
    state: string;
    justification: string | null;
    assessed_by: string | null;
    reviewed_by: string | null;
    assessed_at_ms: number | null;
    rescored_score: number | null;
    rescored_vector: string | null;
    ssvc: string | null;
    ssvc_details: string | null;
    assigned: string[];
    ticket: string | null;
    evidence_reviewed: string | null;
    version_coverage: string | null;
    historical: boolean;
    copied_from: string | null;
    details: string;
}

/**
 * A whole assessment as fields. This is what a save sends: the server
 * stores the fields and renders the text Dependency-Track receives.
 */
export interface AssessmentFields {
    /** Text outside the team assessments; null keeps what the server has stored. */
    free_text: string | null;
    pending_review: boolean;
    rescored_score: number | null;
    rescored_vector: string | null;
    /**
     * What is done about the finding; part of the Global assessment. null
     * removes it. Left out, the server keeps what each finding has, as it
     * does for every save that is not a reviewer's.
     */
    response?: string | null;
    /** The finding's version override (ADR 0010). Read only: saves keep it. */
    version_override?: VersionOverride | null;
    teams: AssessmentTeamFields[];
}

/** A version override: the label shared by the versions in its scope. */
export interface VersionOverride {
    label: string;
    reason: string | null;
}

/**
 * The responses of Dependency-Track's analysis (CycloneDX
 * `analysis.response`), in the order the form offers them.
 */
export const ANALYSIS_RESPONSE_OPTIONS = [
    { value: 'NOT_SET', label: 'Not set', description: 'No response recorded.' },
    { value: 'UPDATE', label: 'Update', description: 'Update the component to a version without the vulnerability.' },
    { value: 'ROLLBACK', label: 'Rollback', description: 'Go back to a version without the vulnerability.' },
    { value: 'WORKAROUND_AVAILABLE', label: 'Workaround available', description: 'A workaround avoids the vulnerability.' },
    { value: 'WILL_NOT_FIX', label: 'Will not fix', description: 'The vulnerability will not be fixed.' },
    { value: 'CAN_NOT_FIX', label: 'Can not fix', description: 'The vulnerability can not be fixed.' },
] as const;

const ANALYSIS_RESPONSES: ReadonlySet<string> = new Set(
    ANALYSIS_RESPONSE_OPTIONS.map(option => option.value).filter(value => value !== 'NOT_SET'),
);

// Only a tag with a value of the list is the field, as in the backend's
// `assessment_model.py`; other text in brackets stays text.
const responseTagPattern = (): RegExp =>
    new RegExp(String.raw`\[Response:\s*(${[...ANALYSIS_RESPONSES, 'NOT_SET'].join('|')})\s*\]`, 'gi');

/** A response of the list, or null for none, "NOT_SET", and anything else. */
export const normalizeAssessmentResponse = (value: string | undefined | null): string | null => {
    const text = String(value ?? '').trim().replace(/[\s-]+/g, '_').toUpperCase();
    return ANALYSIS_RESPONSES.has(text) ? text : null;
};

export const analysisResponseLabel = (value: string | undefined | null): string => {
    const normalized = normalizeAssessmentResponse(value);
    return ANALYSIS_RESPONSE_OPTIONS.find(option => option.value === normalized)?.label ?? '';
};

/** Text without response tags: a team's rationale never carries one. */
export const stripAssessmentResponseTags = (text: string): string =>
    (text || '').replace(responseTagPattern(), '');

// Version override tags (ADR 0010). Only a tag with a valid value is the
// field; anything else stays text, as on the server (assessment_model.py).
const VERSION_OVERRIDE_TAG = /\[Version Override:\s*([A-Za-z0-9._+\- ]{1,40}?)\s*\]/gi;
const OVERRIDE_REASON_TAG = /\[Override Reason:\s*((?:(?!---)[^[\]\r\n]){1,200}?)\s*\]/gi;
const RESERVED_OVERRIDE_LABELS = ['base', 'ambiguous'];

const validOverrideLabel = (value: string): string | null => {
    const label = (value || '').trim();
    if (!label || label.length > 40 || !/^[A-Za-z0-9._+\- ]+$/.test(label)) return null;
    const normalized = label.split(/\s+/).join(' ').toLowerCase();
    return RESERVED_OVERRIDE_LABELS.includes(normalized) ? null : label;
};

const validOverrideReason = (value: string): string | null => {
    const reason = (value || '').trim();
    if (!reason || reason.length > 200 || /[[\]\r\n]|---/.test(reason)) return null;
    return reason;
};

/** Text without the valid version override tags. */
export const stripVersionOverrideTags = (text: string): string =>
    (text || '')
        .replace(VERSION_OVERRIDE_TAG, (tag, label) => validOverrideLabel(label) ? '' : tag)
        .replace(OVERRIDE_REASON_TAG, (tag, reason) => validOverrideReason(reason) ? '' : tag);

/** The version override an assessment text carries beside its team blocks. */
export const parseVersionOverride = (fullText: string | undefined | null): VersionOverride | null => {
    const [shared] = splitAtFirstTeamBlock(fullText || '');
    let label: string | null = null;
    for (const match of shared.matchAll(VERSION_OVERRIDE_TAG)) {
        label = validOverrideLabel(match[1]);
        if (label) break;
    }
    if (!label) return null;
    let reason: string | null = null;
    for (const match of shared.matchAll(OVERRIDE_REASON_TAG)) {
        reason = validOverrideReason(match[1]);
        if (reason) break;
    }
    return { label, reason };
};

/** Text ahead of the blocks without the tags that are fields of their own. */
const stripSharedFieldTags = (text: string): string =>
    stripVersionOverrideTags(stripAssessmentResponseTags(text));

function splitAtFirstTeamBlock(fullText: string): [string, string] {
    const source = fullText || '';
    const firstHeaderIndex = maskSsvcDetails(source).search(/---(?=\s*\[Team:)/);
    return firstHeaderIndex === -1
        ? [source, '']
        : [source.slice(0, firstHeaderIndex), source.slice(firstHeaderIndex)];
}

/** The response an assessment text carries beside its team blocks. */
export const parseAssessmentResponse = (fullText: string | undefined | null): string | null => {
    const [shared] = splitAtFirstTeamBlock(fullText || '');
    for (const match of shared.matchAll(responseTagPattern())) {
        const value = normalizeAssessmentResponse(match[1]);
        if (value) return value;
    }
    return null;
};

/**
 * The assessment text with `response` as its response; null or "NOT_SET"
 * removes the one it has. The tag stands where the server writes it: after
 * the rescoring tags, ahead of the team blocks.
 */
export const setAssessmentResponse = (fullText: string, response: string | undefined | null): string => {
    const value = normalizeAssessmentResponse(response);
    if (parseAssessmentResponse(fullText) === value) return fullText || '';
    const [shared, blocks] = splitAtFirstTeamBlock(fullText || '');
    const rest = stripAssessmentResponseTags(shared).trim();
    let head = rest;
    if (value) {
        const tag = `[Response: ${value}]`;
        const lead = /^(?:\s*\[Rescored(?: Vector)?:[^\]]*\])+/.exec(rest);
        if (lead) head = `${lead[0].trim()} ${tag}${rest.slice(lead[0].length)}`;
        else head = rest ? `${tag}\n\n${rest}` : tag;
    }
    return [head, blocks.trim()].filter(Boolean).join('\n\n');
};

export const STATE_PRIORITY: Record<string, number> = {
    "EXPLOITABLE": 0,
    "IN_TRIAGE": 1,
    "FALSE_POSITIVE": 2,
    "NOT_AFFECTED": 3,
    "RESOLVED": 4,
    "NOT_SET": 5,
};

const MAX_PARSE_CACHE_ENTRIES = 1000;

const cloneAssessmentBlock = (block: AssessmentBlock): AssessmentBlock => ({
    ...block,
    assigned: block.assigned ? [...block.assigned] : [],
});

export interface AssessmentReviewMetadata {
    evidenceReviewed?: boolean;
    versionCoverageChecked?: boolean;
    ticket?: string;
    copiedFrom?: string;
}

const formatAssessmentHeaderValue = (value: string): string =>
    value.replace(/[\r\n\[\]]+/g, ' ').replace(/\s+/g, ' ').trim();

const cloneAssessmentBlocks = (blocks: readonly AssessmentBlock[]): AssessmentBlock[] => {
    return blocks.map(cloneAssessmentBlock);
};

export const assessmentTeamKey = (team: string | undefined | null): string =>
    String(team || '').trim().toLocaleLowerCase();

/**
 * The assessed teams as required teams name them: a block under a team's
 * alias (an earlier name in the team mapping) counts for the team, and names
 * match regardless of case and surrounding space.
 */
export const assessedTeamKeys = (
    teams: Iterable<string>,
    teamMapping?: Record<string, string | string[]>,
): Set<string> => new Set(
    normalizeTags([...teams].map(team => String(team || '').trim()), teamMapping as Record<string, any>)
        .map(assessmentTeamKey)
);

export const markAssessmentBlocksHistorical = (fullText: string, teams: Iterable<string>): string => {
    const sourceKeys = new Set([...teams].map(assessmentTeamKey));
    if (!sourceKeys.size) return fullText;
    return fullText.replace(/---\s*\[Team:\s*([^\]]+)\][^\r\n]*?---/g, (header, team: string) => {
        if (!sourceKeys.has(assessmentTeamKey(team)) || /\[Historical:\s*yes\s*\]/i.test(header)) return header;
        return header.replace(/\s*---$/, ' [Historical: yes] ---');
    });
};


/**
 * The text without its historical team blocks. A historical block is a
 * record: its rescoring tags do not rescore the finding, so the finding's
 * rescoring is read from this text.
 */
export const withoutHistoricalBlocks = (fullText: string): string => {
    const text = String(fullText || '');
    const masked = maskSsvcDetails(text);
    const starts = [...masked.matchAll(/---(?=\s*\[Team:)/g)].map(match => match.index ?? 0);
    if (!starts.length) return text;
    const kept = [text.slice(0, starts[0])];
    starts.forEach((start, index) => {
        const block = text.slice(start, index + 1 < starts.length ? starts[index + 1] : text.length);
        const headerEnd = block.indexOf('---', 3);
        const header = headerEnd === -1 ? block.slice(3) : block.slice(3, headerEnd);
        if (!/\[Historical:\s*yes\s*\]/i.test(header)) kept.push(block);
    });
    return kept.join('');
};

/**
 * The text with its team blocks sorted by team, General first. Their order
 * carries no meaning and writers differ in it. For comparing only, as the
 * server's ``blocks_in_team_order``.
 */
export const blocksInTeamOrder = (fullText: string): string => {
    const text = String(fullText || '');
    const masked = maskSsvcDetails(text);
    const starts = [...masked.matchAll(/---(?=\s*\[Team:)/g)].map(match => match.index ?? 0);
    if (starts.length < 2) return text;
    const blocks = starts.map((start, index) => {
        const block = text.slice(start, index + 1 < starts.length ? starts[index + 1] : text.length);
        const headerEnd = block.indexOf('---', 3);
        const header = headerEnd === -1 ? block.slice(3) : block.slice(3, headerEnd);
        const team = (header.match(/\[Team:\s*([^\]]+)\]/)?.[1] || '').trim().toLocaleLowerCase();
        return { team, index, block: block.trim() };
    });
    blocks.sort((left, right) => (
        Number(left.team !== 'general') - Number(right.team !== 'general')
        || (left.team < right.team ? -1 : left.team > right.team ? 1 : 0)
        || left.index - right.index
    ));
    return [text.slice(0, starts[0]).trim(), ...blocks.map(entry => entry.block)].join('\n\n').trim();
};

/**
 * The part of an assessment text that the findings of a vulnerability must
 * agree on. Historical blocks are records that belong to one finding; they
 * are left out, as are the tags that say who assessed when, the rescoring,
 * the pending status and the version coverage, and the order of the team
 * blocks. As the server's ``comparable_assessment_text``; both are tested against
 * fixtures/assessment_scope_cases.json.
 */
/**
 * The text without the SSVC record (tag, summary and details) and the
 * response: both are optional, so a finding without one does not differ from
 * one with it; two different ones do (`ssvcComparisonKey`,
 * `parseAssessmentResponse`). As the server's ``_without_optional_decisions``.
 */
const withoutOptionalDecisions = (details: string): string =>
    stripSsvcDocumentation(String(details || ''))
        .replace(/\[SSVC:\s*([^\]]+)\]/g, '')
        .replace(responseTagPattern(), '');

/** The SSVC record as compared between findings; null when there is none. */
export const ssvcComparisonKey = (details: string | undefined | null): string | null => {
    const text = String(details || '');
    const header = maskSsvcDetails(text).match(/---\s*\[Team:\s*General\][^\n]*?---/i);
    const tags = header ? [...header[0].matchAll(/\[SSVC:\s*([^\]]+)\]/g)].map(match => match[1]!.trim()) : [];
    const blocks = [...text.matchAll(ssvcDetailsPattern())].map(match => String(match[1] || '').replace(/\s+/g, ' ').trim());
    if (!tags.length && !blocks.length) return null;
    return `${tags.join('|')}||${blocks.join('||')}`;
};

/** A block as findings compare it: team (case aside), state, justification, text. */
export const normalizeBlockSignature = (block: AssessmentBlock): string => JSON.stringify({
    team: block.team.trim().toLocaleLowerCase(),
    state: block.state,
    justification: !block.justification || block.justification === 'NOT_SET' ? '' : block.justification,
    details: String(block.details || '').replace(/\s+/g, ' ').trim(),
});

/**
 * What findings are compared on, part by part: the text ahead of the blocks
 * and per current block its team and signature. A part one finding lacks is
 * a gap, not a difference. As the server's ``assessment_comparison_parts``.
 */
export const assessmentComparisonParts = (details: string | undefined | null): { lead: string; blocks: Array<[string, string]> } => {
    const current = withoutHistoricalBlocks(withoutOptionalDecisions(String(details || '')));
    const [shared] = splitAtFirstTeamBlock(current);
    const lead = shared.trim() ? comparableAssessmentText(shared) : '';
    const blocks = parseAssessmentBlocks(current)
        .filter(block => !block.historical)
        .map(block => [block.team.trim().toLocaleLowerCase(), normalizeBlockSignature(block)] as [string, string]);
    return { lead, blocks };
};

export const comparableAssessmentText = (details: string | undefined | null): string =>
    blocksInTeamOrder(withoutHistoricalBlocks(withoutOptionalDecisions(String(details || ''))))
        .replace(/\[Date:\s*[^\]]*\]/g, '')
        .replace(/\[Assessed By:\s*[^\]]*\]/g, '')
        .replace(/\[Rescored:\s*[\d\.]+\]/g, '')
        .replace(/\[Rescored Vector:\s*[^\]]+\]/g, '')
        .replace(/\[Status: Pending Review\]/g, '')
        .replace(/\[Version Coverage:\s*[^\]]*\]/g, '')
        // Findings are compared within their scope, the reason on its own.
        .replace(/\[Version Override:\s*[^\]]*\]/g, '')
        .replace(/\[Override Reason:\s*[^\]]*\]/g, '')
        .replace(/\s+/g, ' ')
        .trim();

/**
 * What makes two findings' texts different versions of the assessment for
 * the views that list them: what the server compares
 * (``comparableAssessmentText``), and the rescoring, version override,
 * response and SSVC record, which it checks on their own but a reviewer
 * must see. Who assessed when,
 * the review marker, records of one finding, whitespace and the order of
 * the team blocks do not count.
 */
export const assessmentVariantKey = (details: string | undefined | null): string => {
    const current = withoutHistoricalBlocks(String(details || ''));
    const tags = [...current.matchAll(/\[(?:Rescored(?: Vector)?|Version Override|Override Reason):\s*[^\]]*\]/g)]
        .map(match => match[0].replace(/\s+/g, ' '))
        .sort();
    // The optional response and SSVC record: a finding without one is no
    // conflict, but it is a version of its own here, so that the views show
    // what a tidy-up (Repair, a save) would carry.
    return `${comparableAssessmentText(details)}|${tags.join(' ')}|${parseAssessmentResponse(details) || ''}|${ssvcComparisonKey(details) || ''}`;
};

/**
 * One active block per team; a historical block is a record of its own and
 * only one with exactly the same team, decision, text, assessor, reviewer,
 * date, ticket and rescoring is the same record. As the server's
 * ``_record_key``.
 */
export const assessmentBlockKey = (block: AssessmentBlock): string => {
    const team = assessmentTeamKey(block.team);
    if (!block.historical) return `active\u0000${team}`;
    const collapse = (value: unknown) => String(value ?? '').replace(/\s+/g, ' ').trim();
    const user = collapse(block.user);
    const tickets = [...new Set(String(block.ticket || '').split(',').map(key => key.trim()).filter(Boolean))];
    return [
        'historical',
        team,
        block.state || 'NOT_SET',
        block.justification && block.justification !== 'NOT_SET' ? block.justification : '',
        collapse(block.details),
        user.toLocaleLowerCase() === 'unknown' ? '' : user,
        block.timestamp || '',
        collapse(block.reviewer),
        tickets.join(','),
        block.rescored ?? '',
        collapse(block.vector),
    ].join('\u0000');
};

export const deduplicateAssessmentBlocks = (
    blocks: readonly AssessmentBlock[],
): AssessmentBlock[] => {
    const unique = new Map<string, { index: number, block: AssessmentBlock }>();
    blocks.forEach((rawBlock, index) => {
        if (!assessmentTeamKey(rawBlock.team)) return;
        const key = assessmentBlockKey(rawBlock);
        const block = cloneAssessmentBlock({
            ...rawBlock,
            team: assessmentTeamKey(rawBlock.team) === 'general' ? 'General' : rawBlock.team.trim(),
        });
        const existing = unique.get(key);
        if (!existing) {
            unique.set(key, { index, block });
            return;
        }
        const existingTimestamp = existing.block.timestamp || 0;
        const candidateTimestamp = block.timestamp || 0;
        if (
            candidateTimestamp > existingTimestamp
            || (
                candidateTimestamp === existingTimestamp
                && (block.details?.length || 0) >= (existing.block.details?.length || 0)
            )
        ) {
            unique.set(key, { index: existing.index, block });
        }
    });
    return [...unique.values()]
        .sort((left, right) => left.index - right.index)
        .map(entry => entry.block);
};

const setBoundedCacheEntry = <T>(cache: Map<string, T>, key: string, value: T, maxEntries: number) => {
    if (cache.has(key)) {
        cache.delete(key);
    }
    cache.set(key, value);
    if (cache.size > maxEntries) {
        const oldestKey = cache.keys().next().value;
        if (oldestKey !== undefined) {
            cache.delete(oldestKey);
        }
    }
};

const parsedAssessmentBlocksCache = new Map<string, readonly AssessmentBlock[]>();

interface GroupAssessmentSummary {
    allInstances: Array<Record<string, any>>;
    componentStates: string[];
    blocks: AssessmentBlock[];
    assessedTeams: Set<string>;
    hasAnyAssessment: boolean;
    hasMissingComponent: boolean;
    hasGlobalAssessment: boolean;
    isPendingReview: boolean;
    technicalState: string;
}

const groupAssessmentSummaryCache = new WeakMap<GroupedVuln, { signature: string; summary: GroupAssessmentSummary }>();

const getInstanceAssessmentState = (instance: Record<string, any>): string => {
    return instance.analysis_state || instance.analysisState || 'NOT_SET';
};

const getInstanceAssessmentDetails = (instance: Record<string, any>): string => {
    return instance.analysis_details || instance.analysisDetails || '';
};

const buildGroupAssessmentSignature = (group: GroupedVuln): string => {
    const parts: string[] = [];
    for (const version of group.affected_versions || []) {
        for (const component of version.components || []) {
            const state = getInstanceAssessmentState(component as Record<string, any>);
            const details = getInstanceAssessmentDetails(component as Record<string, any>);
            parts.push(`${state.length}:${state}|${details.length}:${details}`);
        }
    }
    return parts.join('||');
};

const buildGroupAssessmentSummary = (group: GroupedVuln): GroupAssessmentSummary => {
    const allInstances = (group.affected_versions || []).flatMap(v => v.components || []) as Array<Record<string, any>>;
    const componentStates = allInstances.map(getInstanceAssessmentState);
    const blocks: AssessmentBlock[] = [];
    const instanceBlocks: AssessmentBlock[][] = [];

    for (const instance of allInstances) {
        const details = getInstanceAssessmentDetails(instance);
        const active = details
            ? parseAssessmentBlocks(details).filter(block => !block.historical)
            : [];
        instanceBlocks.push(active);
        blocks.push(...active);
    }

    const assessedTeams = new Set<string>();
    for (const block of blocks) {
        if (block.team && block.team !== 'General' && block.state && block.state !== 'NOT_SET') {
            assessedTeams.add(block.team);
        }
    }

    // The name breaks ties, so that the result does not depend on the order
    // the states were collected in. As the server's _sort_states_by_priority.
    const byPriority = (left: string, right: string) =>
        (STATE_PRIORITY[left] ?? 10) - (STATE_PRIORITY[right] ?? 10)
        || (left < right ? -1 : left > right ? 1 : 0);
    const teamStates = blocks
        .filter(block => block.team !== 'General' && block.state !== 'NOT_SET')
        .map(block => block.state)
        .sort(byPriority);

    const rawStates = Array.from(new Set(componentStates.filter(state => state !== 'NOT_SET')))
        .sort(byPriority);

    // The first General decision in the order of the findings' keys, so that
    // the value does not depend on the order the versions arrive in.
    const findingOrderKey = (instance: Record<string, any>) =>
        ['project_uuid', 'component_uuid', 'vulnerability_uuid'].map(name => String(instance[name] || ''));
    const compareKeys = (left: string[], right: string[]) => {
        for (let index = 0; index < left.length; index++) {
            if (left[index]! < right[index]!) return -1;
            if (left[index]! > right[index]!) return 1;
        }
        return 0;
    };
    const globalState = allInstances
        .map((instance, index) => ({ key: findingOrderKey(instance), index }))
        .sort((left, right) => compareKeys(left.key, right.key) || left.index - right.index)
        .flatMap(entry => instanceBlocks[entry.index]!)
        .find(block => block.team === 'General' && block.state !== 'NOT_SET')?.state;
    const technicalState = globalState || teamStates[0] || rawStates[0] || 'NOT_SET';

    return {
        allInstances,
        componentStates,
        blocks,
        assessedTeams,
        hasAnyAssessment: componentStates.some(state => state !== 'NOT_SET'),
        hasMissingComponent: componentStates.includes('NOT_SET'),
        hasGlobalAssessment: blocks.some(block => block.team === 'General' && block.state !== 'NOT_SET'),
        isPendingReview: allInstances.some(instance => stripSsvcDetails(getInstanceAssessmentDetails(instance)).includes('[Status: Pending Review]')),
        technicalState,
    };
};

const getGroupAssessmentSummary = (group: GroupedVuln): GroupAssessmentSummary => {
    const signature = buildGroupAssessmentSignature(group);
    const cached = groupAssessmentSummaryCache.get(group);
    if (cached?.signature === signature) {
        return cached.summary;
    }

    const summary = buildGroupAssessmentSummary(group);
    groupAssessmentSummaryCache.set(group, { signature, summary });
    return summary;
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

    const cached = parsedAssessmentBlocksCache.get(fullText);
    if (cached) {
        return cloneAssessmentBlocks(cached);
    }

    const originalText = fullText;
    fullText = maskSsvcDetails(fullText);
    // Split by team headers: --- [Team: Name] [State: State] ... ---
    const firstHeaderIndex = fullText.indexOf('--- [Team:');

    if (firstHeaderIndex > 0) {
        // There is something BEFORE the first header.
        // Check if it's just shared tags or real content
        const textBeforeHeader = fullText.slice(0, firstHeaderIndex);
        const contentBeforeHeader = stripSharedFieldTags(textBeforeHeader)
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
        const content = stripSharedFieldTags(fullText)
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

    // Now parse explicit blocks, the way the server's _parse_assessment_blocks
    // does: a header runs from "---" before "[Team:" to the next "---"; its
    // tags are read in any order; the text is the rest up to the next header.
    const headers: Array<{ start: number; end: number; tags: string }> = [];
    // Same pattern as the server's HEADER_PATTERN: a header is read whole,
    // so its closing "---" never starts the next one.
    const headerRegex = /---(?=\s*\[Team:)\s*((?:\[[^\]\n]*\]\s*)+)---/g;
    let found;
    while ((found = headerRegex.exec(fullText)) !== null) {
        headers.push({ start: found.index, end: found.index + found[0].length, tags: found[1]! });
    }

    headers.forEach((header, index) => {
        const segmentEnd = index + 1 < headers.length ? headers[index + 1]!.start : originalText.length;
        const headerText = header.tags;

        const tags: Record<string, string> = {};
        for (const tag of headerText.matchAll(/\[([\w\s]+):\s*([^\]]+)\]/g)) {
            tags[tag[1]!.trim()] = tag[2]!.trim();
        }
        const team = tags['Team'];
        if (!team) return;

        const originalContent = originalText.slice(header.end, segmentEnd).trim();
        const ssvcDetails = [...originalContent.matchAll(ssvcDetailsPattern())].map(match => match[0].trimStart()).join('\n\n');
        // Only what the server removes: the text of a block stays as
        // written, so both sides read the same record.
        const content = stripAssessmentResponseTags(stripSsvcDetails(originalContent))
            .replace(/\[(Rescored|Rescored Vector|Assessed By|Reviewed By|Team|State|Justification|Date):\s*[^\]]*\]/g, '')
            .replace(/\[Status: Pending Review\]/gi, '')
            .replace(/\bAssessed\s*--\s*\S+/g, '')
            .replace(/--\s*\S+\s*$/gm, '')
            .trim();

        const dateText = tags['Date'];
        const timestamp = dateText && !isNaN(Number(dateText)) ? Number(dateText) : undefined;
        const assigned = (tags['Assigned'] || '').split(',').map(u => u.trim()).filter(u => u.length > 0);
        const evidenceValue = tags['Evidence Reviewed'];
        const coverageValue = tags['Version Coverage'];
        const rescoredText = tags['Rescored'];
        const vector = tags['Rescored Vector'];
        const reviewer = tags['Reviewed By'];

        blocks.push({
            team,
            historical: (tags['Historical'] || '').toLocaleLowerCase() === 'yes',
            copiedFrom: tags['Copied From'],
            ssvc: tags['SSVC'],
            ssvcDetails,
            state: tags['State'] || 'NOT_SET',
            user: tags['Assessed By'] || 'Unknown',
            details: content,
            justification: tags['Justification'] || 'NOT_SET',
            timestamp,
            assigned,
            evidenceReviewed: /^(?:yes|true|checked)$/i.test(evidenceValue || ''),
            versionCoverageChecked: /^(?:yes|true|checked)$/i.test(coverageValue || ''),
            // The stored values, which may say more than yes or no; a block
            // the form did not edit is written back with them unchanged.
            ...(evidenceValue ? { evidenceReviewedValue: evidenceValue } : {}),
            ...(coverageValue ? { versionCoverageValue: coverageValue } : {}),
            ticket: tags['Ticket'] || '',
            ...(reviewer ? { reviewer } : {}),
            ...(rescoredText !== undefined && /^[\d.]+$/.test(rescoredText) && !Number.isNaN(Number(rescoredText))
                ? { rescored: Number(rescoredText) }
                : {}),
            ...(vector ? { vector } : {}),
        });
    });

    setBoundedCacheEntry(parsedAssessmentBlocksCache, originalText, cloneAssessmentBlocks(blocks), MAX_PARSE_CACHE_ENTRIES);
    return blocks;
}

const YES_FLAG = /^(?:yes|true|checked)$/i;

/**
 * The value an [Evidence Reviewed] or [Version Coverage] tag is written
 * with: the stored value while it agrees with the form's checkbox (it may
 * say more than yes or no, e.g. "partial"), otherwise "yes" or nothing.
 */
export const flagTagValue = (checked: boolean | undefined, stored: string | undefined): string | null => {
    if (stored && YES_FLAG.test(stored) === Boolean(checked)) return stored;
    return checked ? 'yes' : null;
};

const SHARED_RESCORED = /\[Rescored:\s*([\d.]+)\]/;
const SHARED_RESCORED_VECTOR = /\[Rescored Vector:\s*([^\]]+)\]/;
const PENDING_REVIEW_MARKER = /\[Status: Pending Review\]/i;

const textOrNull = (value: string | undefined | null): string | null => {
    const text = String(value ?? '').trim();
    return text ? text : null;
};

const blockToTeamFields = (block: AssessmentBlock): AssessmentTeamFields => {
    const user = String(block.user || '').trim();
    const justification = String(block.justification || '').trim();
    return {
        team: block.team,
        state: block.state || 'NOT_SET',
        justification: justification && justification !== 'NOT_SET' ? justification : null,
        assessed_by: user && user.toLocaleLowerCase() !== 'unknown' ? user : null,
        reviewed_by: textOrNull(block.reviewer),
        assessed_at_ms: block.timestamp ? block.timestamp : null,
        rescored_score: block.rescored ?? null,
        rescored_vector: textOrNull(block.vector),
        ssvc: textOrNull(block.ssvc),
        ssvc_details: textOrNull(block.ssvcDetails),
        assigned: [...(block.assigned || [])],
        ticket: textOrNull(block.ticket),
        evidence_reviewed: flagTagValue(block.evidenceReviewed, block.evidenceReviewedValue),
        version_coverage: flagTagValue(block.versionCoverageChecked, block.versionCoverageValue),
        historical: Boolean(block.historical),
        copied_from: textOrNull(block.copiedFrom),
        details: block.details || '',
    };
};

/**
 * The fields of an assessment given as text in DTVP's markup.
 *
 * Text before the first team block is the rescoring, the review marker, and
 * free text; it is not folded into a General assessment as the form's block
 * model does. Team blocks are de-duplicated exactly as the form does it.
 */
export function assessmentTextToFields(fullText: string): AssessmentFields {
    const source = fullText || '';
    const masked = maskSsvcDetails(source);
    const firstHeaderIndex = masked.indexOf('--- [Team:');
    const shared = firstHeaderIndex === -1 ? masked : masked.slice(0, firstHeaderIndex);
    const rescored = SHARED_RESCORED.exec(shared)?.[1];
    const vector = SHARED_RESCORED_VECTOR.exec(shared)?.[1]?.trim();
    const freeText = stripSharedFieldTags(shared)
        .replace(/\[Rescored:\s*[\d.]+\]/g, '')
        .replace(/\[Rescored Vector:\s*[^\]]+\]/g, '')
        .replace(/\[Status: Pending Review\]/gi, '')
        .trim();

    const blocks = parseAssessmentBlocks(source);
    // The parser turns text ahead of the blocks into a General block of its
    // own, always the first one. Here that text is the free text.
    if (freeText && firstHeaderIndex !== 0 && blocks.length > 0) {
        blocks.shift();
    }

    return {
        // The form has no field for free text. Beside team assessments an
        // empty value therefore means "not edited here", and the server
        // keeps what each finding has.
        free_text: freeText || (blocks.length > 0 ? null : ''),
        pending_review: PENDING_REVIEW_MARKER.test(stripSsvcDetails(source)),
        rescored_score: rescored !== undefined && !Number.isNaN(Number(rescored))
            ? Number(rescored)
            : null,
        rescored_vector: vector || null,
        response: parseAssessmentResponse(source),
        // Sent back only as the finding has it; the server keeps the stored one.
        ...(parseVersionOverride(source) ? { version_override: parseVersionOverride(source) } : {}),
        teams: deduplicateAssessmentBlocks(blocks).map(blockToTeamFields),
    };
}

/**
 * Whether two stored assessment texts say the same. Writers differ in
 * whitespace (a blank line after a block header or not); that is not a
 * difference in the assessment.
 */
export const assessmentTextKey = (details: string | undefined | null): string =>
    String(details || '').replace(/\s+/g, ' ').trim();

export function constructAssessmentDetails(
    blocks: AssessmentBlock[],
    sharedTags: string[] = [],
    isPending: boolean = true
): { text: string, aggregatedState: string } {
    const uniqueBlocks = deduplicateAssessmentBlocks(blocks);
    const parts: string[] = [];

    // Add shared tags first (e.g. [Rescored: ...])
    if (sharedTags.length > 0) {
        parts.push(sharedTags.join(' '));
    }

    // Preserve the order in the array for generation
    for (const b of uniqueBlocks) {
        const dateStr = b.timestamp ? ` [Date: ${b.timestamp}]` : '';
        const assignedStr = b.assigned && b.assigned.length > 0 ? ` [Assigned: ${b.assigned.join(', ')}]` : '';
        const evidenceValue = flagTagValue(b.evidenceReviewed, b.evidenceReviewedValue);
        const coverageValue = flagTagValue(b.versionCoverageChecked, b.versionCoverageValue);
        const evidenceStr = evidenceValue ? ` [Evidence Reviewed: ${formatAssessmentHeaderValue(evidenceValue)}]` : '';
        const versionCoverageStr = coverageValue ? ` [Version Coverage: ${formatAssessmentHeaderValue(coverageValue)}]` : '';
        const ticketStr = b.ticket?.trim() ? ` [Ticket: ${formatAssessmentHeaderValue(b.ticket)}]` : '';
        const ssvcStr = b.ssvc ? ` [SSVC: ${b.ssvc}]` : '';
        // A historical block keeps the rescoring it was recorded with; it
        // does not rescore the finding (see withoutHistoricalBlocks).
        const historicalRescoreStr = b.historical
            ? `${b.rescored !== undefined ? ` [Rescored: ${b.rescored}]` : ''}${b.vector ? ` [Rescored Vector: ${b.vector}]` : ''}`
            : '';
        const historicalStr = b.historical ? ' [Historical: yes]' : '';
        const copiedFromStr = b.copiedFrom ? ` [Copied From: ${formatAssessmentHeaderValue(b.copiedFrom)}]` : '';
        const reviewerStr = b.reviewer?.trim() ? ` [Reviewed By: ${formatAssessmentHeaderValue(b.reviewer)}]` : '';
        const header = `--- [Team: ${b.team}] [State: ${b.state}] [Assessed By: ${b.user}]${reviewerStr}${dateStr} [Justification: ${b.justification || 'NOT_SET'}]${assignedStr}${evidenceStr}${versionCoverageStr}${ticketStr}${historicalRescoreStr}${ssvcStr}${historicalStr}${copiedFromStr} ---`;
        parts.push(header);
        if (b.details) parts.push(b.details);
        if (b.ssvcDetails) parts.push(b.ssvcDetails);
    }

    // Calculate Aggregated State
    const generalBlock = uniqueBlocks.find(b => assessmentTeamKey(b.team) === 'general' && !b.historical);
    let aggState = 'NOT_SET';

    if (generalBlock && generalBlock.state !== 'NOT_SET') {
        // Global Precedence: If General is set, it wins
        aggState = generalBlock.state;
    } else {
        // Fallback: Worst of all team states
        const allStates = uniqueBlocks.filter(b => !b.historical).map(b => b.state).filter(s => s !== 'NOT_SET');
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
 * Sanitizes assessment details text by:
 * 1. Parsing all blocks
 * 2. Deduplicating by team (keeping the latest timestamp, or longest details on
 *    tie); every distinct historical block stays
 * 3. Sorting alphabetically by team name, with "General" always first
 * 4. Reconstructing clean text
 *
 * Returns the sanitized text and the aggregated state.
 */
export function sanitizeAssessmentDetails(
    fullText: string
): { text: string, aggregatedState: string, blocks: AssessmentBlock[] } {
    if (!fullText || !fullText.trim()) {
        return { text: '', aggregatedState: 'NOT_SET', blocks: [] };
    }

    const blocks = parseAssessmentBlocks(fullText);
    if (blocks.length === 0) {
        return { text: fullText.trim(), aggregatedState: 'NOT_SET', blocks: [] };
    }

    // Sort: General first, then alphabetical
    const dedupedBlocks = deduplicateAssessmentBlocks(blocks).sort((a, b) => {
        if (assessmentTeamKey(a.team) === 'general') return -1;
        if (assessmentTeamKey(b.team) === 'general') return 1;
        return a.team.localeCompare(b.team);
    });

    // Extract shared tags; a historical block's rescoring is not the finding's.
    const prose = stripSsvcDetails(withoutHistoricalBlocks(fullText));
    const tags: string[] = [];
    const rescoredMatch = prose.match(/\[Rescored:\s*[\d\.]+\]/);
    if (rescoredMatch) tags.push(rescoredMatch[0]);
    const vectorMatch = prose.match(/\[Rescored Vector:\s*[^\]]+\]/);
    if (vectorMatch) tags.push(vectorMatch[0]);
    const response = parseAssessmentResponse(fullText);
    if (response) tags.push(`[Response: ${response}]`);

    const isPending = prose.includes('[Status: Pending Review]');

    const result = constructAssessmentDetails(dedupedBlocks, tags, isPending);
    return { ...result, blocks: dedupedBlocks };
}

/**
 * Builds the reviewer draft used to synchronize an incomplete assessment.
 */
export function getAssessmentSyncDraft(
    blocks: AssessmentBlock[],
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
    } else {
        const firstActive = blocks.find(b => b.state !== 'NOT_SET')
        if (firstActive) {
            state = firstActive.state
            justification = firstActive.justification || 'NOT_SET'
        }
    }

    // 2. Combine all details. The General block is a legitimate first-party
    // assessment during incomplete-assessment synchronization.
    const combinedParts: string[] = []
    const seenDetails = new Set<string>()
    for (const b of deduplicateAssessmentBlocks(blocks)) {
        const cleaned = (b.details || '')
            .replace(/\n\n\[Status: Pending Review\]/g, '')
            .replace(/\[Status: Pending Review\]/g, '')
            .trim()
        const signature = cleaned.replace(/\s+/g, ' ').trim().toLocaleLowerCase()
        if (cleaned && !seenDetails.has(signature)) {
            seenDetails.add(signature)
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
    isPending: boolean = true,
    newAssigned?: string[],
    reviewMetadata?: AssessmentReviewMetadata
): { text: string, aggregatedState: string } {
    // 1. Parse existing
    const blocks = deduplicateAssessmentBlocks(parseAssessmentBlocks(currentFullText));

    // 2. Update, Create, or Remove block for this team
    const targetKey = assessmentTeamKey(team);
    // A historical block of the team is a record: it stays beside the
    // team's new assessment and is never replaced by it.
    const targetIndex = blocks.findIndex(b => assessmentTeamKey(b.team) === targetKey && !b.historical);
    const existingBlock = targetIndex >= 0 ? blocks[targetIndex] : undefined;
    const hasAssignees = newAssigned !== undefined ? newAssigned.length > 0 : ((existingBlock?.assigned?.length ?? 0) > 0);
    const finalEvidenceReviewed = reviewMetadata?.evidenceReviewed ?? existingBlock?.evidenceReviewed ?? false;
    const finalVersionCoverageChecked = reviewMetadata?.versionCoverageChecked ?? existingBlock?.versionCoverageChecked ?? false;
    const finalTicket = reviewMetadata?.ticket !== undefined ? reviewMetadata.ticket.trim() : (existingBlock?.ticket || '');
    const finalCopiedFrom = reviewMetadata?.copiedFrom ?? existingBlock?.copiedFrom;
    const hasReviewMetadata = finalEvidenceReviewed || finalVersionCoverageChecked || Boolean(finalTicket) || Boolean(existingBlock?.ssvc);
    const isCleared = newState === 'NOT_SET' && !newDetails.trim() && (!newJustification || newJustification === 'NOT_SET') && !hasAssignees && !hasReviewMetadata;

    if (isCleared) {
        // Remove the block entirely when all fields are cleared
        if (targetIndex >= 0) {
            blocks.splice(targetIndex, 1);
        }
    } else {
        // Preserve existing assigned if not explicitly provided
        const existingAssigned = existingBlock?.assigned;
        const finalAssigned = newAssigned !== undefined ? newAssigned : (existingAssigned || []);

        // A save that changes only ticket, evidence, coverage or assignment
        // is not a new assessment: it keeps who made it, when, and who
        // reviewed it. An approval (not pending) is always re-stamped.
        const collapse = (value: string | undefined) => (value || '').replace(/\s+/g, ' ').trim();
        const sameAssessment = Boolean(existingBlock)
            && existingBlock!.state === newState
            && (existingBlock!.justification || 'NOT_SET') === (newJustification || 'NOT_SET')
            && collapse(existingBlock!.details) === collapse(newDetails)
            && rescoredTags === undefined
            && finalCopiedFrom === existingBlock!.copiedFrom;
        const sortedNames = (names: string[] | undefined) => [...(names || [])].sort().join('\u0000');
        const metadataChanged = Boolean(existingBlock) && (
            (existingBlock!.ticket || '') !== finalTicket
            || Boolean(existingBlock!.evidenceReviewed) !== Boolean(finalEvidenceReviewed)
            || Boolean(existingBlock!.versionCoverageChecked) !== Boolean(finalVersionCoverageChecked)
            || sortedNames(existingBlock!.assigned) !== sortedNames(finalAssigned)
        );
        const keepAttribution = isPending && sameAssessment && metadataChanged;

        const newBlock: AssessmentBlock = {
            ssvc: existingBlock?.ssvc,
            ssvcDetails: existingBlock?.ssvcDetails,
            team: team,
            historical: false,
            copiedFrom: finalCopiedFrom,
            state: newState,
            user: keepAttribution ? existingBlock!.user : user,
            details: newDetails.trim(),
            justification: newJustification,
            timestamp: keepAttribution ? existingBlock!.timestamp : Date.now(),
            assigned: finalAssigned,
            evidenceReviewed: finalEvidenceReviewed,
            versionCoverageChecked: finalVersionCoverageChecked,
            ...(existingBlock?.evidenceReviewedValue ? { evidenceReviewedValue: existingBlock.evidenceReviewedValue } : {}),
            ...(existingBlock?.versionCoverageValue ? { versionCoverageValue: existingBlock.versionCoverageValue } : {}),
            ticket: finalTicket,
            ...(keepAttribution && existingBlock!.reviewer ? { reviewer: existingBlock!.reviewer } : {}),
        };

        if (targetIndex >= 0) {
            blocks[targetIndex] = newBlock;
        } else {
            blocks.push(newBlock);
        }
    }

    // 3. Extract or use provided tags
    let tags: string[] = [];
    if (rescoredTags) {
        tags = rescoredTags;
    } else {
        // Simple regex for now - assumes they are at the very start. A
        // historical block's rescoring is not the finding's.
        const prose = stripSsvcDetails(withoutHistoricalBlocks(currentFullText));
        const rescoredMatch = prose.match(/\[Rescored:\s*[\d\.]+\]/);
        if (rescoredMatch) tags.push(rescoredMatch[0]);

        const vectorMatch = prose.match(/\[Rescored Vector:\s*[^\]]+\]/);
        if (vectorMatch) tags.push(vectorMatch[0]);
    }
    // The response is the finding's: saving one team's assessment, with or
    // without a new rescoring, keeps it.
    const response = parseAssessmentResponse(currentFullText);
    if (response && !tags.some(tag => parseAssessmentResponse(tag))) {
        tags = [...tags, `[Response: ${response}]`];
    }

    // 4. Construct new text
    return constructAssessmentDetails(blocks, tags, isPending);
}

/**
 * Builds the full assessment text for a bulk sync operation.
 *
 * Strategy:
 * - Preserves one active block per team, case-insensitively, and every
 *   distinct historical block.
 * - Preserves an existing General block but never synthesizes one from team
 *   assessments or copies team state/details into it.
 * - Removes team summaries generated by older releases because the team blocks
 *   already contain that information.
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
    const uniqueBlocks = deduplicateAssessmentBlocks(allBlocks);
    // 1. Separate out the General block from team-specific blocks.
    // A historical General block is a record and stays with the others.
    const isActiveGeneral = (block: AssessmentBlock) => assessmentTeamKey(block.team) === 'general' && !block.historical;
    const teamBlocks = uniqueBlocks.filter(b => !isActiveGeneral(b));
    let existingGeneral = uniqueBlocks.find(isActiveGeneral);
    if (!existingGeneral && existingGeneralText) {
        existingGeneral = deduplicateAssessmentBlocks(parseAssessmentBlocks(existingGeneralText))
            .find(isActiveGeneral);
    }

    // 2. Recover any user-added comment from the existing General block.
    //    Priority: block already in allBlocks → parse from existingGeneralText.
    let userComment = (existingGeneral?.details || '').trim();
    if (!userComment && existingGeneralText) {
        const parsed = parseAssessmentBlocks(existingGeneralText);
        const generalBlock = parsed.find(b => b.team === 'General' && !b.historical);
        userComment = (generalBlock?.details || '').trim();
    }

    // Remove summaries produced by older releases; the team blocks already carry
    // this information and remain the source of truth.
    userComment = userComment
        .split(/\n\s*\n/)
        .filter(paragraph => !paragraph.trim().toLocaleLowerCase().startsWith('team assessments:\n'))
        .join('\n\n')
        .trim();

    // 5. Determine the General block state.
    //    If it was explicitly set (not NOT_SET), keep it; otherwise NOT_SET so
    //    the aggregation falls through to worst-team-state logic.
    const generalState = (overrideGeneralState && overrideGeneralState !== 'NOT_SET')
        ? overrideGeneralState
        : (existingGeneral?.state && existingGeneral.state !== 'NOT_SET')
            ? existingGeneral.state
            : 'NOT_SET';
    const finalBlocks: AssessmentBlock[] = [];
    if (existingGeneral || generalState !== 'NOT_SET') {
        finalBlocks.push({
            ...existingGeneral,
            team: 'General',
            state: generalState,
            user: existingGeneral?.user || 'General',
            details: userComment,
            justification: existingGeneral?.justification || 'NOT_SET',
        });
    }
    finalBlocks.push(...teamBlocks);

    // 7. Construct the final text — NOT pending (this is a reviewer-level bulk action).
    const response = parseAssessmentResponse(existingGeneralText);
    return constructAssessmentDetails(finalBlocks, response ? [`[Response: ${response}]`] : [], false);
}

export function hasGlobalAssessment(blocks: AssessmentBlock[]): boolean {
    return blocks.some(b => b.team === 'General' && b.state !== 'NOT_SET');
}

export function isPendingReview(group: GroupedVuln): boolean {
    return getGroupAssessmentSummary(group).isPendingReview;
}

export function getAssessedTeams(group: GroupedVuln): Set<string> {
    return new Set(getGroupAssessmentSummary(group).assessedTeams);
}

export function hasGlobalAssessmentForGroup(group: GroupedVuln): boolean {
    return getGroupAssessmentSummary(group).hasGlobalAssessment;
}

const hasOpenTeamAssessmentFromSummary = (
    summary: GroupAssessmentSummary,
    requiredTeamsOrTags?: Tags | undefined,
    teamMapping?: Record<string, string | string[]>,
): boolean => {
    const requiredTeams = teamMapping
        ? normalizeTags(requiredTeamsOrTags, teamMapping)
        : (requiredTeamsOrTags || []).map(tagToString).filter(Boolean);
    const assessableTeams = requiredTeams.filter(team => assessmentTeamKey(team) !== 'unassigned');

    if (assessableTeams.length > 0) {
        const assessedKeys = assessedTeamKeys(summary.assessedTeams, teamMapping);
        const missingAssessment = assessableTeams.some(team => !assessedKeys.has(assessmentTeamKey(team)));
        const singleTeamGlobalAssessment = assessableTeams.length === 1
            && summary.hasGlobalAssessment
            && summary.assessedTeams.size === 0;
        if (missingAssessment && !singleTeamGlobalAssessment) return true;
    }

    if (summary.hasMissingComponent) return true;

    return summary.blocks.some(block => block.team !== 'General' && block.state === 'NOT_SET');
}

export function hasOpenTeamAssessment(group: GroupedVuln, requiredTeamsOrTags?: Tags | undefined, teamMapping?: Record<string, string | string[]>): boolean {
    return hasOpenTeamAssessmentFromSummary(getGroupAssessmentSummary(group), requiredTeamsOrTags, teamMapping);
}

const getGroupInconsistencyReasonsFromSummary = (
    group: GroupedVuln,
    summary: GroupAssessmentSummary,
): InconsistencyReason[] => {
    const { allInstances, componentStates, blocks, hasAnyAssessment, hasGlobalAssessment } = summary;
    const reasons: InconsistencyReason[] = [];
    if (allInstances.length === 0) return reasons;

    if ((group.assessment_restore_count || group.list_metadata?.assessment_restore_count || 0) > 0) {
        reasons.push('MISSING_RESCORING_VECTOR');
    }

    const distinctNonMissingStates = new Set(componentStates.filter(state => state !== 'NOT_SET'));
    if (distinctNonMissingStates.size > 1) {
        reasons.push('ANALYSIS_STATE_MISMATCH');
    }

    const isLegacy = (blocks.length === 0 && hasAnyAssessment) || (
        blocks.length === 1
        && blocks[0].team === 'General'
        && blocks[0].state === 'NOT_SET'
        && hasAnyAssessment
    );

    if (!hasGlobalAssessment) {
        // A team contradicts itself: its current blocks differ, in one finding
        // or across the findings. Teams may disagree with each other, and a
        // block some findings lack is a gap for Synchronize. As the server.
        const byTeam = new Map<string, Set<string>>();
        for (const instance of allInstances) {
            for (const block of parseAssessmentBlocks(getInstanceAssessmentDetails(instance))) {
                if (block.historical || block.state === 'NOT_SET' || block.team === 'General') continue;
                const team = block.team.trim().toLocaleLowerCase();
                if (!byTeam.has(team)) byTeam.set(team, new Set());
                byTeam.get(team)!.add(normalizeBlockSignature(block));
            }
        }

        if ([...byTeam.values()].some(signatures => signatures.size > 1)) {
            reasons.push('TEAM_ASSESSMENT_MISMATCH');
        }
    }

    // The assessed findings agree when the parts they have are the same: the
    // text ahead of the blocks, each block (the Global one included) where
    // present, and the optional SSVC record and response where set. A part
    // that some findings lack is a gap, not a difference. As the server.
    const assessedTexts = allInstances
        .filter(instance => getInstanceAssessmentState(instance) !== 'NOT_SET')
        .map(instance => getInstanceAssessmentDetails(instance));
    const leads = new Set<string>();
    const blockSignatures = new Map<string, Set<string>>();
    for (const text of assessedTexts) {
        const { lead, blocks: parts } = assessmentComparisonParts(text);
        if (lead) leads.add(lead);
        for (const [team, signature] of parts) {
            if (!blockSignatures.has(team)) blockSignatures.set(team, new Set());
            blockSignatures.get(team)!.add(signature);
        }
    }
    const ssvcKeys = new Set(assessedTexts.map(ssvcComparisonKey).filter(Boolean));
    const responses = new Set(assessedTexts.map(parseAssessmentResponse).filter(Boolean));
    const detailsMismatch = leads.size > 1
        || [...blockSignatures.values()].some(signatures => signatures.size > 1)
        || ssvcKeys.size > 1
        || responses.size > 1;
    if (detailsMismatch && (!isLegacy || reasons.length > 0)) {
        reasons.push('ASSESSMENT_DETAILS_MISMATCH');
    }

    return reasons;
};

export function getGroupInconsistencyReasons(group: GroupedVuln): InconsistencyReason[] {
    if (group.list_metadata && Array.isArray(group.list_metadata.inconsistency_reasons)) {
        return normalizeInconsistencyReasons(group.list_metadata.inconsistency_reasons);
    }
    const view = getAssessmentScopes(group);
    if (view.hasOverrides) return getScopedAssessment(group, view, undefined).reasons;
    return getGroupInconsistencyReasonsFromSummary(group, getGroupAssessmentSummary(group));
}

export interface ScopedAssessmentScope {
    name: string;
    label: string | null;
    lifecycle: string;
    reasons: InconsistencyReason[];
    gaps: string[];
    pending: boolean;
    technicalState: string;
}

/**
 * Lifecycle, reasons and technical state of a vulnerability with version
 * overrides: the rules run inside each scope and are combined (ADR 0010
 * section 5), as on the server (grouped_vuln_services._scoped_lifecycle).
 */
export function getScopedAssessment(
    group: GroupedVuln,
    view: AssessmentScopeView,
    requiredTeamsOrTags: Tags | undefined,
    teamMapping?: Record<string, string | string[]>,
): { lifecycle: string; reasons: InconsistencyReason[]; technicalState: string; scopes: ScopedAssessmentScope[] } {
    const reasons: InconsistencyReason[] = [];
    const scopes: ScopedAssessmentScope[] = [];
    let technicalState = 'NOT_SET';
    for (const scope of view.scopes) {
        if (scope.instances.length === 0) continue;
        const part = scopedGroup(group, scope.instances);
        const summary = buildGroupAssessmentSummary(part);
        const scopeReasons = getGroupInconsistencyReasonsFromSummary(part, summary);
        if (scope.partial.length > 0) scopeReasons.push('VERSION_OVERRIDE_PARTIAL');
        if (scope.reasonMismatch && !scopeReasons.includes('ASSESSMENT_DETAILS_MISMATCH')) {
            scopeReasons.push('ASSESSMENT_DETAILS_MISMATCH');
        }
        // The teams owning the scope's findings, else the given teams.
        const owned = scope.instances.some(instance => Array.isArray(instance.tags));
        const teams = owned
            ? scope.instances.flatMap(instance => (instance.tags || []) as TagValue[])
            : requiredTeamsOrTags;
        const lifecycle = scopeReasons.length > 0
            ? 'INCONSISTENT'
            : getGroupLifecycleFromSummary(part, summary, teams, teamMapping);
        for (const reason of scopeReasons) if (!reasons.includes(reason)) reasons.push(reason);
        if (scope === view.primary) technicalState = summary.technicalState;
        scopes.push({
            name: scope.name,
            label: scope.label,
            lifecycle,
            reasons: scopeReasons,
            gaps: scope.gaps,
            pending: scope.pending,
            technicalState: summary.technicalState,
        });
    }
    if (view.ambiguous.length > 0 && !reasons.includes('VERSION_OVERRIDE_LABEL_MISMATCH')) {
        reasons.push('VERSION_OVERRIDE_LABEL_MISMATCH');
    }
    return {
        lifecycle: combineLifecycles(scopes.map(scope => scope.lifecycle), view.ambiguous.length > 0),
        reasons,
        technicalState,
        scopes,
    };
}

/** Whether a team's current block (with a decision) is on some assessed findings and missing on others. */
const hasTeamBlockGap = (instances: readonly any[]): boolean => {
    const teamsPerFinding = instances
        .filter(instance => getInstanceAssessmentState(instance) !== 'NOT_SET')
        .map(instance => new Set(parseAssessmentBlocks(getInstanceAssessmentDetails(instance))
            .filter(block => !block.historical && block.team !== 'General' && block.state !== 'NOT_SET')
            .map(block => block.team.trim().toLocaleLowerCase())));
    if (teamsPerFinding.length < 2) return false;
    const every = new Set(teamsPerFinding.flatMap(teams => [...teams]));
    return teamsPerFinding.some(teams => teams.size !== every.size);
};

const getGroupLifecycleFromSummary = (
    group: GroupedVuln,
    summary: GroupAssessmentSummary,
    requiredTeamsOrTags: Tags | undefined,
    teamMapping?: Record<string, string | string[]>,
): string => {
    const requiredTeams = teamMapping
        ? normalizeTags(requiredTeamsOrTags, teamMapping)
        : (requiredTeamsOrTags || []).map(tagToString).filter(Boolean);
    const assessableTeams = requiredTeams.filter(team => assessmentTeamKey(team) !== 'unassigned');
    const { allInstances, hasAnyAssessment, hasMissingComponent, blocks, hasGlobalAssessment: hasGlobal, isPendingReview } = summary;
    if (allInstances.length === 0) return 'OPEN';

    if (getGroupInconsistencyReasonsFromSummary(group, summary).length > 0) {
        return 'INCONSISTENT';
    }

    const assessedKeys = assessedTeamKeys(
        blocks.filter(b => b.state !== 'NOT_SET').map(b => b.team),
        teamMapping,
    );
    const missingTeams = (assessableTeams || []).filter((t: string) => !assessedKeys.has(assessmentTeamKey(t)));

    // Pending review always wins over legacy detection. If coverage is also
    // incomplete, keep the lifecycle in INCOMPLETE; the pending flag still
    // exposes the item through the separate NEEDS_APPROVAL filter.
    if (isPendingReview) {
        if (missingTeams.length > 0 || hasMissingComponent) return 'INCOMPLETE';
        return 'NEEDS_APPROVAL';
    }

    // Finding coverage comes before every assessed classification: a legacy
    // or reviewer-approved General assessment that never reached some finding
    // instances (for example another project version) is still incomplete.
    if (hasMissingComponent && hasAnyAssessment) return 'INCOMPLETE';

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

    // A reviewer-approved General assessment that covers every finding is
    // terminal. It may have been approved before every team-specific block was
    // recorded, but it still means the vulnerability is done.
    if (hasGlobal) return 'ASSESSED';

    // Without an approved General result, every required team must have an
    // assessment before the vulnerability can be considered complete.
    // OPEN should only mean nothing is assessed yet. If a technical state exists but
    // required team assessments are missing, classify it as INCOMPLETE.
    if (missingTeams.length > 0) {
        return hasAnyAssessment ? 'INCOMPLETE' : 'OPEN';
    }

    // A team's block that some assessed findings have and others lack is a
    // gap for Synchronize, not a contradiction. As the server.
    if (hasTeamBlockGap(allInstances)) return 'INCOMPLETE';

    // Findings that disagree on the state were returned as INCONSISTENT
    // above (ANALYSIS_STATE_MISMATCH), whichever version they belong to.
    // Complete, consistent team coverage does not require a General block.
    return hasAnyAssessment ? 'ASSESSED' : 'OPEN';
}

export function getGroupLifecycle(group: GroupedVuln, requiredTeamsOrTags: Tags | undefined, teamMapping?: Record<string, string | string[]>): string {
    const view = getAssessmentScopes(group);
    if (view.hasOverrides) return getScopedAssessment(group, view, requiredTeamsOrTags, teamMapping).lifecycle;
    return getGroupLifecycleFromSummary(group, getGroupAssessmentSummary(group), requiredTeamsOrTags, teamMapping);
}

/**
 * Returns the technical state of a group for sorting/filtering.
 * Logic: Global Assessment State -> Worst Team Assessment State fallback.
 */
export function getGroupTechnicalState(group: GroupedVuln): string {
    // With version overrides, the primary scope's state (base if it has findings).
    const view = getAssessmentScopes(group);
    if (view.hasOverrides) return getScopedAssessment(group, view, undefined).technicalState;
    return getGroupAssessmentSummary(group).technicalState;
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

/**
 * Detect the CVSS major version from a vector string.
 * Returns '4', '3', '2', or null.
 */
export function getCvssMajorVersion(vector: string | null | undefined): string | null {
    if (!vector) return null
    const v = vector.trim()
    if (v.startsWith('CVSS:4.')) return '4'
    if (v.startsWith('CVSS:3.')) return '3'
    if (v.startsWith('CVSS:2.') || /^\(?AV:[NAL]/.test(v)) return '2'
    return null
}

/**
 * Check if a group has mismatched CVSS vector versions
 * (rescored vector major version differs from original).
 */
export function hasCvssVersionMismatch(group: GroupedVuln): boolean {
    const origVer = getCvssMajorVersion(group.cvss_vector)
    const rescoredVer = getCvssMajorVersion(group.rescored_vector)
    if (!origVer || !rescoredVer) return false
    return origVer !== rescoredVer
}

export function matchesFilters(
    group: GroupedVuln, 
    lifecycleFilters: string[], 
    analysisFilters: string[], 
    teamMapping: Record<string, any>
): boolean {
    if (lifecycleFilters.length === 0 || analysisFilters.length === 0) return false;

    const summary = getGroupAssessmentSummary(group);
    const tags = normalizeTags(group.tags, teamMapping);
    const state = getGroupLifecycleFromSummary(group, summary, tags, teamMapping);
    const isPending = summary.isPendingReview;

    // 1. Lifecycle Match
    const lifecycleMatch = (lifecycleFilters.includes('OPEN') && state === 'OPEN') ||
                           (lifecycleFilters.includes('ASSESSED') && ['ASSESSED', 'ASSESSED_LEGACY'].includes(state)) ||
                           (lifecycleFilters.includes('ASSESSED_LEGACY') && state === 'ASSESSED_LEGACY') ||
                           (lifecycleFilters.includes('INCOMPLETE') && state === 'INCOMPLETE') ||
                           (lifecycleFilters.includes('INCONSISTENT') && state === 'INCONSISTENT') ||
                           (lifecycleFilters.includes('NEEDS_APPROVAL') && isPending) ||
                           (lifecycleFilters.includes('READY_FOR_APPROVAL') && isPending && state === 'NEEDS_APPROVAL');

    if (!lifecycleMatch) return false;

    // 2. Analysis Match (Strict Hierarchical logic)
    // A group matches if:
    // - It is OPEN (no technical state yet, so it matches any analysis filter that includes NOT_SET)
    // - OR its overall technical state matches one of the filters
    const techState = summary.technicalState;
    if (techState === 'NOT_SET') {
        return analysisFilters.includes('NOT_SET');
    }
    return analysisFilters.includes(techState);
}
