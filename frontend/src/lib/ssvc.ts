export interface SsvcSelection {
    model: string;
    version: string;
    answers: Record<string, string>;
    rationale: string;
    exploitation_evidence?: string | null;
}

export interface SsvcEvidence {
    value: string;
    source: string;
    cve: string;
    url: string;
    assessed_at: string;
    checked_at: string;
    stale: boolean;
    token: string;
}

export interface SsvcEnrichment {
    enabled: boolean;
    auto_fill: boolean;
    retry_after: number;
    suggestion: SsvcEvidence | null;
    sources: {
        source: string; cve: string; url: string; status: string;
        checked_at: string | null; assessed_at?: string; error?: string | null;
    }[];
}

export interface SsvcRecord extends SsvcSelection {
    outcome: string | null;
    assessor: string;
    assessed_at: string;
}

export interface SsvcSummary {
    status: string;
    assessed: number;
    missing: number;
    invalid: number;
    record: SsvcRecord | null;
}

export interface SsvcModel {
    namespace: string;
    key: string;
    name: string;
    version: string;
    outcome: string;
    decision_points: Record<string, {
        name: string;
        definition?: string;
        values: { key: string; name: string; definition?: string }[];
    }>;
    mapping: Record<string, string>[];
    documentation: string;
    calculator: string;
    attribution: string;
}

// The server and client consume the same immutable resources. Include historical
// versions so saved metadata can be validated without duplicating decision rules.
const bundledModels = Object.values(import.meta.glob<SsvcModel>(
    '../../../dtvp/resources/ssvc/*.json', { eager: true, import: 'default' },
));
const findModel = (selection: Pick<SsvcSelection, 'model' | 'version'>) => bundledModels.find(
    model => ssvcModelId(model) === selection.model && model.version === selection.version,
);

export const SSVC_STATUSES = ['DEFER', 'SCHEDULED', 'OUT_OF_CYCLE', 'IMMEDIATE', 'UNASSESSED', 'INCOMPLETE', 'MIXED', 'INVALID'];
export const ORIGINAL_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'];
export const ssvcLabel = (status: string) => status.toLowerCase().replaceAll('_', ' ').replace(/^./, c => c.toUpperCase());
export const ssvcModelId = (model: SsvcModel) => `${model.namespace}:${model.key}`;

export const ssvcDetailsPattern = () => /(?:^|\r?\n(?:\r?\n)?)\[SSVC Details\]\r?\n([\s\S]*?)\r?\n\[\/SSVC Details\]/g;
export const stripSsvcDetails = (text: string) => text.includes('[SSVC Details]') ? text.replace(ssvcDetailsPattern(), '') : text;
export const maskSsvcDetails = (text: string) => text.includes('[SSVC Details]') ? text.replace(ssvcDetailsPattern(), match => ' '.repeat(match.length)) : text;

export function stripSsvcDocumentation(text: string): string {
    return stripSsvcDetails(text).replace(/(?:^|\r?\n(?:\r?\n)?)\[SSVC Summary\]\r?\n[\s\S]*?\r?\n\[\/SSVC Summary\]/g, '');
}

/** Preview only; the server writes the authoritative priority and evidence. */
export function ssvcReviewSummary(selection: SsvcSelection | null): string {
    if (!selection) return 'SSVC: cleared';
    const model = findModel(selection);
    if (!model) return 'SSVC priority: Unsupported assessment version';
    const outcome = evaluateSsvc(model, selection.answers);
    const priority = model.decision_points[model.outcome]?.values.find(v => v.key === outcome)?.name || 'Incomplete';
    const lines = [`SSVC priority: ${priority}`, `Model: ${model.name} v${model.version}`];
    for (const [key, point] of Object.entries(model.decision_points)) {
        if (key !== model.outcome) lines.push(`${point.name}: ${point.values.find(v => v.key === selection.answers[key])?.name || 'Not assessed'}`);
    }
    if (selection.rationale) lines.push(`SSVC rationale: ${selection.rationale.replaceAll('---', '—').replaceAll('[', '(').replaceAll(']', ')')}`);
    return lines.join('\n');
}

export function ssvcReviewText(text: string, selection: SsvcSelection | null): string {
    const cleaned = stripSsvcDocumentation(text);
    const summary = `\n\n[SSVC Summary]\n${ssvcReviewSummary(selection)}\n[/SSVC Summary]`;
    const header = /---\s*\[Team:\s*General\][^\n]*?---/i;
    return header.test(cleaned) ? cleaned.replace(header, match => match + summary) : cleaned + summary;
}

/** Incomplete answers never imply the lowest-priority decision. */
export function evaluateSsvc(model: SsvcModel, answers: Record<string, string>): string | null {
    const inputs = Object.entries(model.decision_points).filter(([key]) => key !== model.outcome);
    if (Object.keys(answers).some(key => !inputs.some(([input]) => input === key))) return null;
    if (inputs.some(([key, point]) => !point.values.some(value => value.key === answers[key]))) return null;
    return model.mapping.find(row => inputs.every(([key]) => row[key] === answers[key]))?.[model.outcome] ?? null;
}

export function readSsvcRecord(details: string): SsvcRecord | null {
    const masked = maskSsvcDetails(details);
    const header = /---\s*\[Team:\s*General\][^\n]*?---/i.exec(masked);
    if (!header) return null;
    const start = header.index + header[0].length;
    const next = /---\s*\[Team:/i.exec(masked.slice(start));
    const blocks = [...details.slice(start, next ? start + next.index : undefined).matchAll(ssvcDetailsPattern())];
    const tags = [...header[0].matchAll(/\[SSVC:\s*([^\]]+)\]/g)];
    if (tags.length > 1 || blocks.length > 1) throw new Error('Duplicate SSVC metadata');
    const token = tags[0]?.[1]?.trim();
    if (!token) {
        if (blocks.length) throw new Error('SSVC details without outcome');
        return null;
    }
    const atomic = ['DEFER', 'SCHEDULED', 'OUT_OF_CYCLE', 'IMMEDIATE', 'INCOMPLETE', 'INVALID'].includes(token);
    if (atomic ? blocks.length !== 1 : blocks.length !== 0) throw new Error('Conflicting or missing SSVC details');
    const record = JSON.parse(atomic ? blocks[0]![1]! : decodeURIComponent(token));
    if (!record || typeof record.model !== 'string' || typeof record.version !== 'string'
        || !record.answers || typeof record.answers !== 'object' || Array.isArray(record.answers)
        || typeof record.rationale !== 'string' || !(record.outcome === null || typeof record.outcome === 'string')) {
        throw new Error('Invalid SSVC record');
    }
    const model = findModel(record);
    if (!model || Object.entries(record.answers).some(([key, value]) =>
        key === model.outcome || !model.decision_points[key]?.values.some(answer => answer.key === value),
    ) || evaluateSsvc(model, record.answers) !== record.outcome) throw new Error('Invalid SSVC decision');
    const name = model.decision_points[model.outcome]?.values.find(value => value.key === record.outcome)?.name || 'Incomplete';
    if (atomic && token !== name.toUpperCase().replaceAll('-', '_').replaceAll(' ', '_')) throw new Error('SSVC header does not match decision');
    return record;
}

/** Local post-save display; the server validates decisions against the versioned table. */
export function summarizeSsvc(details: string[]): SsvcSummary {
    const records: SsvcRecord[] = [];
    let missing = 0;
    let invalid = 0;
    for (const text of details) {
        try {
            const record = readSsvcRecord(text);
            if (record) records.push(record);
            else missing++;
        } catch { invalid++; }
    }
    const signatures = new Set(records.map(record => JSON.stringify([
        record.model, record.version, Object.entries(record.answers).sort(), record.rationale,
    ])));
    const record = signatures.size === 1 && !invalid ? records[0]! : null;
    const model = record ? findModel(record) : undefined;
    const outcomeName = model?.decision_points[model.outcome]?.values.find(value => value.key === record?.outcome)?.name;
    const status = invalid ? 'INVALID' : signatures.size > 1 ? 'MIXED' : !record ? 'UNASSESSED'
        : missing || record.outcome === null ? 'INCOMPLETE'
        : outcomeName?.toUpperCase().replaceAll('-', '_').replaceAll(' ', '_') || 'INVALID';
    return { status, assessed: records.length, missing, invalid, record };
}
