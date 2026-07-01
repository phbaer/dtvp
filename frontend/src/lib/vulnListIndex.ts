import type { GroupedVuln, TMRescoreProposal } from '../types'
import {
    getAssessedTeams,
    hasCvssVersionMismatch,
    hasGlobalAssessmentForGroup,
    normalizeTags,
    tagToString,
} from './assessment-helpers'
import { classifyGroup } from './group-classifier'
import type { FilterCounts, TeamCounts } from './group-classifier'

export type DependencyRelationship = 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'
export type TMRescoreProposalFilter = 'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL'
export const DEFAULT_ATTRIBUTION_AGE_DAYS = 28
const DAY_MS = 24 * 60 * 60 * 1000

export interface VulnListItem {
    group: GroupedVuln
    id: string
    idLower: string
    titleLower: string
    aliasesLower: string[]
    tagsLower: string[]
    normalizedTags: string[]
    assessedTeams: Set<string>
    componentNames: string[]
    componentNamesLower: string[]
    assigneesLower: string[]
    versions: string[]
    versionsLower: string[]
    attributedOnMsValues: number[]
    oldestAttributedOnMs: number | null
    instanceCount: number
    componentSummary: string
    searchableTextLower: string
    dependencyRelationship: DependencyRelationship
    hasTmrescoreProposal: boolean
    cvssVersionMismatch: boolean
    lifecycle: string
    isPending: boolean
    isOpen: boolean
    isAssessed: boolean
    technicalState: string
    firstTag: string
    baseScore: number
    rescoredScore: number
    baseSeverityRank: number
    rescoredSeverityRank: number
    baseScoreDisplay: string
    rescoredScoreDisplay: string
    currentDisplayScore: number | string
    stableRescoredScore: number | null
    hasStableRescore: boolean
    isRescoredOrModified: boolean
    originalSeverity: string
    rescoredSeverity: string | null
}

export interface VulnListFilterInput {
    smartSearch?: ParsedVulnSearchQuery | string
    tagFilter?: string
    idFilter?: string
    componentFilter?: string
    assigneeFilter?: string
    dependencyFilter?: FilterSelection<DependencyRelationship>
    tmrescoreProposalFilter?: FilterSelection<TMRescoreProposalFilter>
    versionFilterList?: readonly string[]
    cvssVersionMismatchOnly?: boolean
    attributionAgeDays?: number | string | null
    attributionAgeMode?: 'older' | 'younger'
}

export interface CompiledVulnListFilters {
    smartSearch?: ParsedVulnSearchQuery | string
    dependencyFilter: DependencyRelationship[]
    dependencyFilterSet: Set<DependencyRelationship>
    tmrescoreProposalFilter: TMRescoreProposalFilter[]
    tmrescoreProposalFilterSet: Set<TMRescoreProposalFilter>
    includesTmrescoreProposal: boolean
    includesNoTmrescoreProposal: boolean
    tagFilterLower: string
    idFilterLower: string
    componentFilterLower: string
    assigneeFilterLower: string
    versionFilterSet: Set<string>
    cvssVersionMismatchOnly: boolean
    attributionAgeActive: boolean
    attributionAgeCutoffMs: number | null
    attributionAgeMode: 'older' | 'younger'
}

export interface VulnStateFilterInput {
    lifecycleFilters?: FilterSelection<string>
    analysisFilters?: FilterSelection<string>
}

export interface CompiledVulnStateFilters {
    lifecycleFilters: string[]
    lifecycleFilterSet: Set<string>
    analysisFilterSet: Set<string>
}

type FilterSelection<T extends string> = readonly T[] | T | null | undefined

const unique = (values: string[]) => Array.from(new Set(values))

const lower = (value: unknown) => String(value || '').trim().toLowerCase()

const metadataStringArray = (value: unknown): string[] | null => {
    if (!Array.isArray(value)) return null
    return unique(value
        .map(entry => String(entry || '').trim())
        .filter(Boolean))
}

const metadataNumberArray = (value: unknown): number[] | null => {
    if (!Array.isArray(value)) return null
    const normalized: number[] = []
    const seen = new Set<number>()
    for (const entry of value) {
        const numberValue = Number(entry)
        if (!Number.isFinite(numberValue) || seen.has(numberValue)) continue
        normalized.push(numberValue)
        seen.add(numberValue)
    }
    return normalized
}

const metadataNumber = (value: unknown): number | null => {
    if (value == null || value === '') return null
    const numberValue = Number(value)
    return Number.isFinite(numberValue) ? numberValue : null
}

const metadataDependencyRelationship = (value: unknown): DependencyRelationship | null => {
    const relationship = String(value || '').trim().toUpperCase()
    return relationship === 'DIRECT' || relationship === 'TRANSITIVE' || relationship === 'UNKNOWN'
        ? relationship
        : null
}

const scoreSeverity = (score: number): string => {
    if (score >= 9) return 'CRITICAL'
    if (score >= 7) return 'HIGH'
    if (score >= 4) return 'MEDIUM'
    if (score >= 0.1) return 'LOW'
    return 'INFO'
}

const scoreSeverityRank = (score: number | undefined | null): number => {
    const s = score ?? 0
    if (s >= 9.0) return 0
    if (s >= 7.0) return 1
    if (s >= 4.0) return 2
    if (s >= 0.1) return 3
    return 4
}

const hasAssessedAliasForTag = (
    tag: string,
    assessed: Set<string>,
    teamMapping: Record<string, any>,
) => {
    for (const mappingVal of Object.values(teamMapping || {})) {
        if (!Array.isArray(mappingVal) || mappingVal.length <= 1 || mappingVal[0] !== tag) continue
        if ((mappingVal as string[]).slice(1).some(alias => assessed.has(alias))) {
            return true
        }
    }
    return false
}

const getMatchedAssessedTeams = (
    group: GroupedVuln,
    normalizedTags: string[],
    teamMapping: Record<string, any>,
) => {
    const assessed = getAssessedTeams(group)
    const matched = new Set<string>()
    for (const tag of normalizedTags) {
        if (assessed.has(tag) || hasAssessedAliasForTag(tag, assessed, teamMapping)) {
            matched.add(tag)
        }
    }
    return matched
}

const summarizeComponents = (componentNames: string[]) => {
    if (componentNames.length === 0) return ''
    if (componentNames.length === 1) return componentNames[0] || ''
    if (componentNames.length === 2) return componentNames.join(', ')
    return `${componentNames[0]}, ${componentNames[1]} +${componentNames.length - 2}`
}

export const parseAttributionTimestamp = (value: unknown): number | null => {
    if (value == null || value === '') return null

    if (typeof value === 'number') {
        if (!Number.isFinite(value) || value <= 0) return null
        return value < 1_000_000_000_000 ? value * 1000 : value
    }

    const raw = String(value).trim()
    if (!raw) return null

    const numeric = Number(raw)
    if (Number.isFinite(numeric) && numeric > 0) {
        return numeric < 1_000_000_000_000 ? numeric * 1000 : numeric
    }

    const parsed = Date.parse(raw)
    return Number.isFinite(parsed) ? parsed : null
}

export const normalizeAttributionAgeDays = (value: unknown): number | null => {
    const parsed = Number(value)
    if (!Number.isFinite(parsed) || parsed <= 0) return null
    return Math.floor(parsed)
}

const upperKey = (value: unknown) => String(value || '')
    .trim()
    .replace(/[\s-]+/g, '_')
    .toUpperCase()

type SmartSearchField =
    | 'text'
    | 'id'
    | 'component'
    | 'team'
    | 'assignee'
    | 'version'
    | 'lifecycle'
    | 'analysis'
    | 'dependency'
    | 'tmrescore'
    | 'cvss'

export interface SmartSearchChip {
    field: SmartSearchField
    value: string
    label: string
    raw: string
}

export interface ParsedVulnSearchQuery {
    raw: string
    chips: SmartSearchChip[]
    textTerms: string[]
    idTerms: string[]
    componentTerms: string[]
    teamTerms: string[]
    assigneeTerms: string[]
    versionTerms: string[]
    lifecycleTerms: string[]
    analysisTerms: string[]
    dependencyTerms: DependencyRelationship[]
    tmrescoreTerms: TMRescoreProposalFilter[]
    cvssMismatchOnly: boolean
}

const emptyParsedSearch = (raw = ''): ParsedVulnSearchQuery => ({
    raw,
    chips: [],
    textTerms: [],
    idTerms: [],
    componentTerms: [],
    teamTerms: [],
    assigneeTerms: [],
    versionTerms: [],
    lifecycleTerms: [],
    analysisTerms: [],
    dependencyTerms: [],
    tmrescoreTerms: [],
    cvssMismatchOnly: false,
})

const tokenizeSearchQuery = (query: string): string[] => {
    const tokens: string[] = []
    const regex = /([A-Za-z_][\w-]*):"([^"]*)"|([A-Za-z_][\w-]*):'([^']*)'|"([^"]+)"|'([^']+)'|(\S+)/g
    let match: RegExpExecArray | null
    while ((match = regex.exec(query)) !== null) {
        const token = match[1]
            ? `${match[1]}:${match[2]}`
            : match[3]
                ? `${match[3]}:${match[4]}`
                : match[5] || match[6] || match[7] || ''
        if (token.trim()) tokens.push(token.trim())
    }
    return tokens
}

const pushUnique = <T>(values: T[], value: T) => {
    if (!values.includes(value)) values.push(value)
}

const lifecycleAlias = (value: string): string | null => {
    const normalized = upperKey(value)
    const aliases: Record<string, string> = {
        OPEN: 'OPEN',
        ASSESSED: 'ASSESSED',
        ASSESSED_LEGACY: 'ASSESSED_LEGACY',
        LEGACY: 'ASSESSED_LEGACY',
        INCOMPLETE: 'INCOMPLETE',
        INCONSISTENT: 'INCONSISTENT',
        NEEDS_APPROVAL: 'NEEDS_APPROVAL',
        NEEDS_REVIEW: 'NEEDS_APPROVAL',
        PENDING: 'NEEDS_APPROVAL',
        PENDING_REVIEW: 'NEEDS_APPROVAL',
    }
    return aliases[normalized] || null
}

const analysisAlias = (value: string): string | null => {
    const normalized = upperKey(value)
    const aliases: Record<string, string> = {
        NOT_SET: 'NOT_SET',
        UNSET: 'NOT_SET',
        NONE: 'NOT_SET',
        EXPLOITABLE: 'EXPLOITABLE',
        EXPLOIT: 'EXPLOITABLE',
        IN_TRIAGE: 'IN_TRIAGE',
        TRIAGE: 'IN_TRIAGE',
        RESOLVED: 'RESOLVED',
        FALSE_POSITIVE: 'FALSE_POSITIVE',
        FP: 'FALSE_POSITIVE',
        NOT_AFFECTED: 'NOT_AFFECTED',
        NA: 'NOT_AFFECTED',
    }
    return aliases[normalized] || null
}

const dependencyAlias = (value: string): DependencyRelationship | null => {
    const normalized = upperKey(value)
    if (normalized === 'DIRECT') return 'DIRECT'
    if (normalized === 'TRANSITIVE' || normalized === 'TRANS') return 'TRANSITIVE'
    if (normalized === 'UNKNOWN' || normalized === 'UNK') return 'UNKNOWN'
    return null
}

const parseTmrescoreValue = (value: string): TMRescoreProposalFilter | null => {
    const normalized = upperKey(value)
    if (['WITH', 'YES', 'TRUE', 'PROPOSAL', 'PROPOSALS', 'TMRESCORE', 'HAS'].includes(normalized)) {
        return 'WITH_PROPOSAL'
    }
    if (['WITHOUT', 'NO', 'FALSE', 'NONE', 'NO_PROPOSAL', 'NO_PROPOSALS', 'MISSING'].includes(normalized)) {
        return 'WITHOUT_PROPOSAL'
    }
    return null
}

export function parseVulnSearchQuery(query: string): ParsedVulnSearchQuery {
    const trimmed = query.trim()
    const parsed = emptyParsedSearch(trimmed)
    if (!trimmed) return parsed

    for (const rawToken of tokenizeSearchQuery(trimmed)) {
        const separatorIndex = rawToken.indexOf(':')
        const key = separatorIndex > 0 ? rawToken.slice(0, separatorIndex).toLowerCase() : ''
        const rawValue = separatorIndex > 0 ? rawToken.slice(separatorIndex + 1).trim() : rawToken
        const value = lower(rawValue)

        if (!value) continue

        const addChip = (field: SmartSearchField, label: string, storedValue = value) => {
            parsed.chips.push({ field, value: storedValue, label, raw: rawToken })
        }

        switch (key) {
            case 'id':
            case 'cve':
            case 'alias':
            case 'vuln':
                pushUnique(parsed.idTerms, value)
                addChip('id', `ID: ${rawValue}`)
                break
            case 'component':
            case 'comp':
            case 'pkg':
            case 'package':
                pushUnique(parsed.componentTerms, value)
                addChip('component', `Component: ${rawValue}`)
                break
            case 'team':
            case 'tag':
                pushUnique(parsed.teamTerms, value)
                addChip('team', `Team: ${rawValue}`)
                break
            case 'assignee':
            case 'assigned':
            case 'owner':
                pushUnique(parsed.assigneeTerms, value)
                addChip('assignee', `Assignee: ${rawValue}`)
                break
            case 'version':
            case 'ver':
            case 'v':
                pushUnique(parsed.versionTerms, value)
                addChip('version', `Version: ${rawValue}`)
                break
            case 'dep':
            case 'dependency': {
                const dep = dependencyAlias(rawValue)
                if (dep) {
                    pushUnique(parsed.dependencyTerms, dep)
                    addChip('dependency', `Dependency: ${dep.toLowerCase()}`, dep)
                } else {
                    pushUnique(parsed.textTerms, value)
                    addChip('text', rawValue)
                }
                break
            }
            case 'lifecycle': {
                const lifecycle = lifecycleAlias(rawValue)
                if (lifecycle) {
                    pushUnique(parsed.lifecycleTerms, lifecycle)
                    addChip('lifecycle', `Lifecycle: ${lifecycle.replace(/_/g, ' ').toLowerCase()}`, lifecycle)
                }
                break
            }
            case 'analysis':
            case 'state': {
                const lifecycle = lifecycleAlias(rawValue)
                const analysis = analysisAlias(rawValue)
                if (lifecycle) {
                    pushUnique(parsed.lifecycleTerms, lifecycle)
                    addChip('lifecycle', `State: ${lifecycle.replace(/_/g, ' ').toLowerCase()}`, lifecycle)
                } else if (analysis) {
                    pushUnique(parsed.analysisTerms, analysis)
                    addChip('analysis', `State: ${analysis.replace(/_/g, ' ').toLowerCase()}`, analysis)
                }
                break
            }
            case 'tm':
            case 'tmrescore':
            case 'proposal': {
                const proposal = parseTmrescoreValue(rawValue)
                if (proposal) {
                    pushUnique(parsed.tmrescoreTerms, proposal)
                    addChip('tmrescore', proposal === 'WITH_PROPOSAL' ? 'TM: with proposal' : 'TM: without proposal', proposal)
                }
                break
            }
            case 'has': {
                const normalized = upperKey(rawValue)
                if (['TMRESCORE', 'PROPOSAL', 'PROPOSALS'].includes(normalized)) {
                    pushUnique(parsed.tmrescoreTerms, 'WITH_PROPOSAL')
                    addChip('tmrescore', 'Has: tmrescore', 'WITH_PROPOSAL')
                } else if (['NO_TMRESCORE', 'NO_PROPOSAL', 'NO_PROPOSALS'].includes(normalized)) {
                    pushUnique(parsed.tmrescoreTerms, 'WITHOUT_PROPOSAL')
                    addChip('tmrescore', 'Has: no tmrescore', 'WITHOUT_PROPOSAL')
                } else if (['CVSS_MISMATCH', 'MISMATCH'].includes(normalized)) {
                    parsed.cvssMismatchOnly = true
                    addChip('cvss', 'Has: CVSS mismatch', 'mismatch')
                }
                break
            }
            case 'cvss':
                if (['mismatch', 'version-mismatch', 'version_mismatch'].includes(value)) {
                    parsed.cvssMismatchOnly = true
                    addChip('cvss', 'CVSS: mismatch', 'mismatch')
                }
                break
            default:
                pushUnique(parsed.textTerms, value)
                addChip('text', rawValue)
        }
    }

    return parsed
}

export function normalizeFilterSelection<T extends string>(selection: FilterSelection<T>): T[] {
    if (!selection) return []
    return Array.isArray(selection) ? [...selection] : [selection as T]
}

export function getGroupDependencyRelationship(group: GroupedVuln): DependencyRelationship {
    const directFlags = (group.affected_versions || [])
        .flatMap(version => (version.components || []).map(component => component.is_direct_dependency))
        .filter((value): value is boolean => value === true || value === false)

    if (directFlags.includes(true)) return 'DIRECT'
    if (directFlags.includes(false)) return 'TRANSITIVE'
    return 'UNKNOWN'
}

export function isMeaningfulTMRescoreProposalCandidate(proposal: TMRescoreProposal | null | undefined): boolean {
    const rescoredVector = proposal?.rescored_vector || null
    const originalVector = proposal?.original_vector || null
    const rescoredScore = proposal?.rescored_score
    const originalScore = proposal?.original_score
    if (!rescoredVector) return false
    if (originalVector && rescoredVector === originalVector) return false
    if (originalVector == null && rescoredScore != null && originalScore != null && rescoredScore === originalScore) {
        return false
    }
    return true
}

export function isMeaningfulTMRescoreProposal(group: GroupedVuln, proposal: TMRescoreProposal | null | undefined): boolean {
    if (!isMeaningfulTMRescoreProposalCandidate(proposal)) return false
    const rescoredVector = proposal?.rescored_vector || null
    const originalVector = proposal?.original_vector || group.cvss_vector || null
    return !originalVector || rescoredVector !== originalVector
}

export function hasTMRescoreProposalForGroup(
    group: GroupedVuln,
    proposals: Record<string, TMRescoreProposal> = {},
): boolean {
    const candidateIds = [group.id, ...(group.aliases || [])]
    return candidateIds.some(candidateId => {
        const normalized = String(candidateId || '').trim().toUpperCase()
        return normalized.length > 0 && isMeaningfulTMRescoreProposal(group, proposals[normalized])
    })
}

export function buildVulnListItem(
    group: GroupedVuln,
    teamMapping: Record<string, any>,
    proposals: Record<string, TMRescoreProposal> = {},
): VulnListItem {
    const metadata = group.list_metadata
    const rawTags = (group.tags || []).map(tagToString).filter(Boolean)
    const normalizedTags = normalizeTags(group.tags || [], teamMapping)
    const assessedTeams = metadata?.assessed_teams
        ? new Set(normalizeTags(metadata.assessed_teams, teamMapping))
        : getMatchedAssessedTeams(group, normalizedTags, teamMapping)
    const allTagText = unique([...rawTags, ...normalizedTags])
    const componentNames = metadataStringArray(metadata?.component_names) ?? unique(
        (group.affected_versions || [])
            .flatMap(version => version.components || [])
            .map(component => component.component_name)
            .filter((value): value is string => typeof value === 'string' && value.trim().length > 0),
    )
    const versions = metadataStringArray(metadata?.versions) ?? unique(
        (group.affected_versions || [])
            .map(version => version.project_version || (version as any).version)
            .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
            .map(value => value.trim()),
    )
    const aliasesLower = (group.aliases || []).map(alias => lower(alias)).filter(Boolean)
    const tagsLower = allTagText.map(tag => tag.toLowerCase())
    const componentNamesLower = componentNames.map(component => component.toLowerCase())
    const assigneesLower = (group.assignees || []).map(assignee => lower(assignee)).filter(Boolean)
    const versionsLower = versions.map(version => version.toLowerCase())
    const attributedOnMsValues = metadataNumberArray(metadata?.attributed_on_ms_values) ?? unique(
        (group.affected_versions || [])
            .flatMap(version => version.components || [])
            .map(component => parseAttributionTimestamp(component.attributed_on))
            .filter((value): value is number => value != null)
            .map(value => String(value)),
    ).map(value => Number(value))
    const oldestAttributedOnMs = metadataNumber(metadata?.oldest_attributed_on_ms)
        ?? (attributedOnMsValues.length
        ? Math.min(...attributedOnMsValues)
        : null)
    const titleLower = lower(group.title)
    const fallbackClassification = metadata ? null : classifyGroup(group, teamMapping)
    const classification = {
        lifecycle: metadata?.lifecycle || fallbackClassification?.lifecycle || 'OPEN',
        isPending: metadata?.is_pending ?? fallbackClassification?.isPending ?? false,
        isOpen: metadata?.is_open ?? fallbackClassification?.isOpen ?? false,
        technicalState: metadata?.technical_state || fallbackClassification?.technicalState || 'NOT_SET',
    }
    const isAssessed = metadata?.is_assessed ?? (
        (hasGlobalAssessmentForGroup(group) && !classification.isPending) ||
        classification.lifecycle === 'ASSESSED_LEGACY'
    )
    const instanceCount = metadataNumber(metadata?.instance_count) ?? (group.affected_versions || [])
        .reduce((total, version) => total + (version.components?.length || 0), 0)
    const baseScoreValue = group.cvss ?? group.cvss_score
    const stableRescoredScore = group.rescored_cvss ?? null
    const currentDisplayScore = group.rescored_cvss ?? baseScoreValue ?? 'N/A'
    const hasStableRescore = stableRescoredScore != null
        && baseScoreValue != null
        && Math.abs(stableRescoredScore - baseScoreValue) > 0.05
    const isRescoredOrModified = currentDisplayScore !== 'N/A'
        && baseScoreValue !== undefined
        && baseScoreValue !== null
        && Math.abs(Number(currentDisplayScore) - Number(baseScoreValue)) > 0.05
    const rescoredSeverity = stableRescoredScore != null && hasStableRescore
        ? scoreSeverity(stableRescoredScore)
        : isRescoredOrModified
            ? scoreSeverity(Number(currentDisplayScore))
            : null
    const baseScore = group.cvss_score ?? group.cvss ?? 0
    const rescoredScore = group.rescored_cvss ?? group.cvss_score ?? group.cvss ?? 0
    const searchableTextLower = unique([
        lower(group.id),
        titleLower,
        lower(group.description),
        ...aliasesLower,
        ...tagsLower,
        ...componentNamesLower,
        ...assigneesLower,
        ...versionsLower,
    ].filter(Boolean)).join(' ')

    return {
        group,
        id: group.id,
        idLower: lower(group.id),
        titleLower,
        aliasesLower,
        tagsLower,
        normalizedTags,
        assessedTeams,
        componentNames,
        componentNamesLower,
        assigneesLower,
        versions,
        versionsLower,
        attributedOnMsValues,
        oldestAttributedOnMs,
        instanceCount,
        componentSummary: summarizeComponents(componentNames),
        searchableTextLower,
        dependencyRelationship: metadataDependencyRelationship(metadata?.dependency_relationship)
            ?? getGroupDependencyRelationship(group),
        hasTmrescoreProposal: hasTMRescoreProposalForGroup(group, proposals),
        cvssVersionMismatch: typeof metadata?.cvss_version_mismatch === 'boolean'
            ? metadata.cvss_version_mismatch
            : hasCvssVersionMismatch(group),
        lifecycle: classification.lifecycle,
        isPending: classification.isPending,
        isOpen: classification.isOpen,
        isAssessed,
        technicalState: classification.technicalState,
        firstTag: normalizedTags[0] || '',
        baseScore,
        rescoredScore,
        baseSeverityRank: scoreSeverityRank(baseScore),
        rescoredSeverityRank: scoreSeverityRank(rescoredScore),
        baseScoreDisplay: baseScoreValue == null ? '—' : String(baseScoreValue),
        rescoredScoreDisplay: currentDisplayScore === undefined
            || currentDisplayScore === null
            || currentDisplayScore === 'N/A'
            ? '—'
            : String(currentDisplayScore),
        currentDisplayScore,
        stableRescoredScore,
        hasStableRescore,
        isRescoredOrModified,
        originalSeverity: baseScoreValue != null && !Number.isNaN(Number(baseScoreValue))
            ? scoreSeverity(Number(baseScoreValue))
            : 'UNKNOWN',
        rescoredSeverity,
    }
}

export function buildVulnListItems(
    groups: GroupedVuln[],
    teamMapping: Record<string, any>,
    proposals: Record<string, TMRescoreProposal> = {},
): VulnListItem[] {
    return groups.map(group => buildVulnListItem(group, teamMapping, proposals))
}

const everyTermMatches = (terms: readonly string[], values: readonly string[]) => {
    return terms.every(term => values.some(value => value.includes(term)))
}

const everyTermMatchesValue = (terms: readonly string[], value: string) => {
    return terms.every(term => value.includes(term))
}

const everyTermMatchesPrimaryOrAliases = (
    terms: readonly string[],
    primary: string,
    aliases: readonly string[],
) => {
    return terms.every(term => primary.includes(term) || aliases.some(alias => alias.includes(term)))
}

export function matchesAttributionAgeFilter(
    item: VulnListItem,
    days: unknown,
    mode: 'older' | 'younger' = 'older',
    nowMs = Date.now(),
): boolean {
    const normalizedDays = normalizeAttributionAgeDays(days)
    if (normalizedDays == null) return false
    const cutoff = nowMs - normalizedDays * DAY_MS
    return item.attributedOnMsValues.some(value =>
        mode === 'younger' ? value >= cutoff : value < cutoff,
    )
}

export function compileVulnListFilters(
    filters: VulnListFilterInput,
    nowMs = Date.now(),
): CompiledVulnListFilters {
    const normalizedAgeDays = normalizeAttributionAgeDays(filters.attributionAgeDays)
    const dependencyFilter = normalizeFilterSelection(filters.dependencyFilter)
    const tmrescoreProposalFilter = normalizeFilterSelection(filters.tmrescoreProposalFilter)
    const tmrescoreProposalFilterSet = new Set(tmrescoreProposalFilter)

    return {
        smartSearch: filters.smartSearch,
        dependencyFilter,
        dependencyFilterSet: new Set(dependencyFilter),
        tmrescoreProposalFilter,
        tmrescoreProposalFilterSet,
        includesTmrescoreProposal: tmrescoreProposalFilterSet.has('WITH_PROPOSAL'),
        includesNoTmrescoreProposal: tmrescoreProposalFilterSet.has('WITHOUT_PROPOSAL'),
        tagFilterLower: lower(filters.tagFilter),
        idFilterLower: lower(filters.idFilter),
        componentFilterLower: lower(filters.componentFilter),
        assigneeFilterLower: lower(filters.assigneeFilter),
        versionFilterSet: new Set(filters.versionFilterList || []),
        cvssVersionMismatchOnly: !!filters.cvssVersionMismatchOnly,
        attributionAgeActive: filters.attributionAgeDays != null,
        attributionAgeCutoffMs: normalizedAgeDays == null ? null : nowMs - normalizedAgeDays * DAY_MS,
        attributionAgeMode: filters.attributionAgeMode || 'older',
    }
}

export function matchesCompiledAttributionAgeFilter(
    item: VulnListItem,
    filters: CompiledVulnListFilters,
): boolean {
    if (!filters.attributionAgeActive) return true
    const cutoff = filters.attributionAgeCutoffMs
    if (cutoff == null) return false
    return item.attributedOnMsValues.some(value =>
        filters.attributionAgeMode === 'younger' ? value >= cutoff : value < cutoff,
    )
}

export function matchesCompiledDependencySelection(
    item: VulnListItem,
    filters: CompiledVulnListFilters,
    emptyMatches = false,
): boolean {
    if (filters.dependencyFilterSet.size === 0) return emptyMatches
    return filters.dependencyFilterSet.has(item.dependencyRelationship)
}

export function matchesCompiledTMRescoreSelection(
    item: VulnListItem,
    filters: CompiledVulnListFilters,
    emptyMatches = false,
): boolean {
    if (filters.tmrescoreProposalFilterSet.size === 0) return emptyMatches
    return (filters.includesTmrescoreProposal && item.hasTmrescoreProposal) ||
        (filters.includesNoTmrescoreProposal && !item.hasTmrescoreProposal)
}

export function matchesSmartSearch(item: VulnListItem, search: ParsedVulnSearchQuery | string | undefined): boolean {
    const parsed = typeof search === 'string' ? parseVulnSearchQuery(search) : search
    if (!parsed || parsed.chips.length === 0) return true

    if (!everyTermMatchesValue(parsed.textTerms, item.searchableTextLower)) {
        return false
    }
    if (!everyTermMatchesPrimaryOrAliases(parsed.idTerms, item.idLower, item.aliasesLower)) {
        return false
    }
    if (!everyTermMatches(parsed.componentTerms, item.componentNamesLower)) {
        return false
    }
    if (!everyTermMatches(parsed.teamTerms, item.tagsLower)) {
        return false
    }
    if (!everyTermMatches(parsed.assigneeTerms, item.assigneesLower)) {
        return false
    }
    if (!everyTermMatches(parsed.versionTerms, item.versionsLower)) {
        return false
    }
    if (parsed.lifecycleTerms.length > 0 && !matchesLifecycleFilter(item, parsed.lifecycleTerms)) {
        return false
    }
    if (parsed.analysisTerms.length > 0 && !parsed.analysisTerms.includes(item.technicalState)) {
        return false
    }
    if (parsed.dependencyTerms.length > 0 && !parsed.dependencyTerms.includes(item.dependencyRelationship)) {
        return false
    }
    if (parsed.tmrescoreTerms.length > 0) {
        const matchesProposal =
            (parsed.tmrescoreTerms.includes('WITH_PROPOSAL') && item.hasTmrescoreProposal) ||
            (parsed.tmrescoreTerms.includes('WITHOUT_PROPOSAL') && !item.hasTmrescoreProposal)
        if (!matchesProposal) {
            return false
        }
    }
    if (parsed.cvssMismatchOnly && !item.cvssVersionMismatch) {
        return false
    }

    return true
}

export function matchesCompiledListFilters(
    item: VulnListItem,
    filters: CompiledVulnListFilters,
): boolean {
    if (!matchesSmartSearch(item, filters.smartSearch)) {
        return false
    }

    if (!matchesCompiledDependencySelection(item, filters)) {
        return false
    }

    if (!matchesCompiledTMRescoreSelection(item, filters)) {
        return false
    }

    if (filters.tagFilterLower && !item.tagsLower.some(tag => tag.includes(filters.tagFilterLower))) {
        return false
    }

    if (
        filters.idFilterLower
        && !item.idLower.includes(filters.idFilterLower)
        && !item.aliasesLower.some(alias => alias.includes(filters.idFilterLower))
    ) {
        return false
    }

    if (
        filters.componentFilterLower
        && !item.componentNamesLower.some(component => component.includes(filters.componentFilterLower))
    ) {
        return false
    }

    if (
        filters.assigneeFilterLower
        && !item.assigneesLower.some(assignee => assignee.includes(filters.assigneeFilterLower))
    ) {
        return false
    }

    if (filters.versionFilterSet.size > 0 && !item.versions.some(version => filters.versionFilterSet.has(version))) {
        return false
    }

    if (filters.cvssVersionMismatchOnly && !item.cvssVersionMismatch) {
        return false
    }

    if (!matchesCompiledAttributionAgeFilter(item, filters)) {
        return false
    }

    return true
}

export function matchesListFilters(item: VulnListItem, filters: VulnListFilterInput): boolean {
    return matchesCompiledListFilters(item, compileVulnListFilters(filters))
}

export function matchesLifecycleFilter(item: VulnListItem, lifecycleFilters: FilterSelection<string>): boolean {
    const filters = normalizeFilterSelection(lifecycleFilters)
    if (filters.length === 0) {
        return false
    }

    return (
        (filters.includes('OPEN') && item.isOpen) ||
        (filters.includes('ASSESSED') && item.lifecycle === 'ASSESSED') ||
        (filters.includes('ASSESSED_LEGACY') && item.lifecycle === 'ASSESSED_LEGACY') ||
        (filters.includes('INCOMPLETE') && item.lifecycle === 'INCOMPLETE') ||
        (filters.includes('INCONSISTENT') && item.lifecycle === 'INCONSISTENT') ||
        (filters.includes('NEEDS_APPROVAL') && item.isPending)
    )
}

export function compileVulnStateFilters(filters: VulnStateFilterInput): CompiledVulnStateFilters {
    const lifecycleFilters = normalizeFilterSelection(filters.lifecycleFilters)
    return {
        lifecycleFilters,
        lifecycleFilterSet: new Set(lifecycleFilters),
        analysisFilterSet: new Set(normalizeFilterSelection(filters.analysisFilters)),
    }
}

export function matchesCompiledLifecycleFilter(
    item: VulnListItem,
    filters: CompiledVulnStateFilters,
): boolean {
    if (filters.lifecycleFilterSet.size === 0) {
        return false
    }

    return (
        (filters.lifecycleFilterSet.has('OPEN') && item.isOpen) ||
        (filters.lifecycleFilterSet.has('ASSESSED') && item.lifecycle === 'ASSESSED') ||
        (filters.lifecycleFilterSet.has('ASSESSED_LEGACY') && item.lifecycle === 'ASSESSED_LEGACY') ||
        (filters.lifecycleFilterSet.has('INCOMPLETE') && item.lifecycle === 'INCOMPLETE') ||
        (filters.lifecycleFilterSet.has('INCONSISTENT') && item.lifecycle === 'INCONSISTENT') ||
        (filters.lifecycleFilterSet.has('NEEDS_APPROVAL') && item.isPending)
    )
}

export function matchesCompiledStateFilters(
    item: VulnListItem,
    filters: CompiledVulnStateFilters,
): boolean {
    if (filters.lifecycleFilterSet.size === 0 || filters.analysisFilterSet.size === 0) {
        return false
    }

    if (!matchesCompiledLifecycleFilter(item, filters)) {
        return false
    }

    return filters.analysisFilterSet.has(item.technicalState)
}

export function matchesStateFilters(item: VulnListItem, filters: VulnStateFilterInput): boolean {
    return matchesCompiledStateFilters(item, compileVulnStateFilters(filters))
}

export function computeListFilterCounts(
    items: VulnListItem[],
    activeLifecycleFilters: FilterSelection<string>,
): FilterCounts {
    const counts: FilterCounts = {
        OPEN: 0,
        ASSESSED: 0,
        ASSESSED_LEGACY: 0,
        INCOMPLETE: 0,
        INCONSISTENT: 0,
        NOT_SET: 0,
        EXPLOITABLE: 0,
        IN_TRIAGE: 0,
        RESOLVED: 0,
        FALSE_POSITIVE: 0,
        NOT_AFFECTED: 0,
        NEEDS_APPROVAL: 0,
    }
    const lifecycleFilters = normalizeFilterSelection(activeLifecycleFilters)

    for (const item of items) {
        if (item.isOpen) counts.OPEN++
        if (item.lifecycle === 'ASSESSED') counts.ASSESSED++
        if (item.lifecycle === 'ASSESSED_LEGACY') counts.ASSESSED_LEGACY++
        if (item.lifecycle === 'INCOMPLETE') counts.INCOMPLETE++
        if (item.lifecycle === 'INCONSISTENT') counts.INCONSISTENT++
        if (item.isPending) counts.NEEDS_APPROVAL++

        if (lifecycleFilters.length === 0 || matchesLifecycleFilter(item, lifecycleFilters)) {
            counts[item.technicalState] = (counts[item.technicalState] || 0) + 1
        }
    }

    return counts
}

export function computeListTeamCounts(items: VulnListItem[]): Record<string, TeamCounts> {
    const counts: Record<string, TeamCounts> = {}

    for (const item of items) {
        if (!item.normalizedTags.length) continue

        for (const team of item.normalizedTags) {
            if (!counts[team]) counts[team] = { open: 0, assessed: 0 }
            if (item.isOpen) {
                counts[team].open++
            } else {
                counts[team].assessed++
            }
        }
    }

    return counts
}
