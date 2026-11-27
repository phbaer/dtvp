import type { CodeAnalysisResultRecord, CodeEvidence } from './api'

/**
 * One list of code evidence: analyzer runs (Agentyzer) and entries agents
 * added through MCP. See docs/analysis-integrations.md#agent-code-evidence.
 */
export type EvidenceKind = 'analyzer' | 'agent'
export type EvidenceFilter = 'all' | EvidenceKind

export const ALL_COMPONENTS = 'All components'

export interface EvidenceRow {
    key: string
    kind: EvidenceKind
    /** The id shown and used for selection: analysis run id or evidence id. */
    id: string
    createdAt: string
    /** Agent title, or the analyzer's executive-summary assessment. */
    title: string
    /** Analyzer verdict, or the agent's suggested state. */
    decision: string
    confidence: string
    /** "Analyzer" or "Agent: <label>". */
    sourceLabel: string
    author: string
    used: boolean
    withdrawn: boolean
    record?: CodeAnalysisResultRecord
    evidence?: CodeEvidence
}

export interface EvidenceGroup {
    key: string
    label: string
    /** Agent entries and the latest analyzer run, newest first. */
    rows: EvidenceRow[]
    /** Older analyzer runs of this component, newest first. */
    earlier: EvidenceRow[]
}

export interface MergeEvidenceOptions {
    /** Component a run belongs to in this scope; null drops the run. */
    componentOf?: (record: CodeAnalysisResultRecord) => string | null | undefined
    filter?: EvidenceFilter
    /** Vulnerable dependencies for agent evidence; analyzer scope uses application names. */
    agentComponentNames?: string[]
}

const timestamp = (value?: string | null) => Date.parse(String(value || '')) || 0

const recordTime = (record: CodeAnalysisResultRecord) =>
    record.finished_at || record.recorded_at || record.submitted_at || ''

const newestFirst = (left: EvidenceRow, right: EvidenceRow) =>
    timestamp(right.createdAt) - timestamp(left.createdAt) || right.id.localeCompare(left.id)

export const analyzerRow = (record: CodeAnalysisResultRecord): EvidenceRow => {
    const summary = record.summary || ({} as NonNullable<CodeAnalysisResultRecord['summary']>)
    const executive = (summary as any).executive_summary || {}
    return {
        key: `analyzer:${record.analysis_run_id}`,
        kind: 'analyzer',
        id: record.analysis_run_id,
        createdAt: recordTime(record),
        title: String(executive.assessment || (summary as any).summary || (summary as any).analysis || '').trim()
            || 'No summary recorded',
        decision: String((summary as any).verdict || '').trim(),
        confidence: String((summary as any).confidence || '').trim(),
        sourceLabel: 'Analyzer',
        author: String(record.submitted_by || '').trim() || (record.source === 'automatic' ? 'automatic' : ''),
        used: Boolean(record.used_in_assessment),
        withdrawn: false,
        record,
    }
}

export const agentRow = (evidence: CodeEvidence): EvidenceRow => ({
    key: `agent:${evidence.evidence_id}`,
    kind: 'agent',
    id: evidence.evidence_id,
    createdAt: evidence.created_at,
    title: evidence.title,
    decision: [evidence.suggested_state, evidence.suggested_justification].filter(Boolean).join(' · '),
    confidence: String(evidence.confidence || ''),
    sourceLabel: `Agent: ${evidence.author?.agent_label || 'unknown'}`,
    author: evidence.author?.username || '',
    used: (evidence.applications || []).length > 0,
    withdrawn: Boolean(evidence.withdrawn),
    evidence,
})

const defaultComponentOf = (record: CodeAnalysisResultRecord) =>
    record.scan_target || record.component_name || null

/** The components of an agent entry that are in scope, in scope spelling. */
const agentComponents = (evidence: CodeEvidence, scope: Map<string, string>) => {
    const names = new Set<string>()
    for (const target of evidence.targets || []) {
        const key = String(target.component || '').trim().toLocaleLowerCase()
        if (!key) continue
        if (scope.size === 0) names.add(String(target.component))
        else if (scope.has(key)) names.add(scope.get(key) as string)
    }
    return [...names].sort((a, b) => a.localeCompare(b))
}

/**
 * Groups analyzer runs and agent evidence by component, newest first, and
 * keeps only what concerns the scope's components. Entries about the whole
 * vulnerability form an "All components" group, which comes first.
 */
export const mergeEvidenceRows = (
    analyzerRecords: CodeAnalysisResultRecord[],
    agentEvidence: CodeEvidence[],
    componentNames: string[],
    options: MergeEvidenceOptions = {},
): EvidenceGroup[] => {
    const scope = new Map(
        componentNames
            .map(name => String(name || '').trim())
            .filter(Boolean)
            .map(name => [name.toLocaleLowerCase(), name] as const),
    )
    const agentScope = options.agentComponentNames === undefined ? scope : new Map(
        options.agentComponentNames.map(name => [name.toLocaleLowerCase(), name] as const),
    )
    const componentOf = options.componentOf || defaultComponentOf
    const filter = options.filter || 'all'
    const groups = new Map<string, EvidenceGroup>()
    const groupFor = (label: string) => {
        const key = label === ALL_COMPONENTS ? '*' : label.toLocaleLowerCase()
        let group = groups.get(key)
        if (!group) {
            group = { key, label, rows: [], earlier: [] }
            groups.set(key, group)
        }
        return group
    }

    if (filter !== 'agent') {
        const byComponent = new Map<string, CodeAnalysisResultRecord[]>()
        for (const record of analyzerRecords) {
            if (record.source === 'benchmark') continue
            const component = String(componentOf(record) || '').trim()
            if (!component) continue
            const key = component.toLocaleLowerCase()
            if (scope.size && !scope.has(key)) continue
            const label = scope.get(key) || component
            byComponent.set(label, [...(byComponent.get(label) || []), record])
        }
        for (const [label, records] of byComponent) {
            const rows = records
                .map(record => analyzerRow(record))
                .sort(newestFirst)
            const group = groupFor(label)
            group.rows.push(rows[0])
            group.earlier.push(...rows.slice(1))
        }
    }

    if (filter !== 'analyzer') {
        for (const evidence of agentEvidence) {
            const components = evidence.scope === 'vulnerability' ? [] : agentComponents(evidence, agentScope)
            if (evidence.scope !== 'vulnerability' && components.length === 0) continue
            const label = components.length === 0 ? ALL_COMPONENTS : components.join(', ')
            groupFor(label).rows.push(agentRow(evidence))
        }
    }

    const result = [...groups.values()].filter(group => group.rows.length > 0)
    result.forEach(group => {
        group.rows.sort(newestFirst)
        group.earlier.sort(newestFirst)
    })
    return result.sort((left, right) => {
        if (left.key === '*') return -1
        if (right.key === '*') return 1
        return left.label.localeCompare(right.label)
    })
}

/** The evidence id a rejected save names when that evidence can no longer be
 * used (unknown, withdrawn, another project or vulnerability), else null. */
export const unusableEvidenceId = (message: unknown): string | null => {
    if (typeof message !== 'string') return null
    const match = /^(?:Unknown code evidence (\S+)|Code evidence (\S+) (?:was withdrawn|belongs to another))/.exec(message)
    return match ? (match[1] || match[2] || null) : null
}

/** "3 min ago", "2 h ago", "4 d ago", or the date. */
export const formatRelativeTime = (value: string | null | undefined, now = Date.now()) => {
    const time = timestamp(value)
    if (!time) return 'unknown time'
    const seconds = Math.round((now - time) / 1000)
    if (seconds < 60) return 'just now'
    const minutes = Math.round(seconds / 60)
    if (minutes < 60) return `${minutes} min ago`
    const hours = Math.round(minutes / 60)
    if (hours < 24) return `${hours} h ago`
    const days = Math.round(hours / 24)
    if (days < 30) return `${days} d ago`
    return new Date(time).toISOString().slice(0, 10)
}

/** Local time for display; the exact UTC time belongs in a title attribute. */
export const formatLocalTime = (value: string | null | undefined) => {
    const time = timestamp(value)
    return time ? new Date(time).toLocaleString() : 'unknown'
}

export const formatUtcTime = (value: string | null | undefined) => {
    const time = timestamp(value)
    return time ? new Date(time).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : ''
}
