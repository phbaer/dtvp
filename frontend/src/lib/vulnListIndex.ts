import type { GroupedVuln, TMRescoreProposal } from '../types'
import { tagToString, hasCvssVersionMismatch, normalizeTags } from './assessment-helpers'
import { classifyGroup } from './group-classifier'
import type { FilterCounts, TeamCounts } from './group-classifier'

export type DependencyRelationship = 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'
export type TMRescoreProposalFilter = 'WITH_PROPOSAL' | 'WITHOUT_PROPOSAL'

export interface VulnListItem {
    group: GroupedVuln
    id: string
    idLower: string
    titleLower: string
    aliasesLower: string[]
    tagsLower: string[]
    normalizedTags: string[]
    componentNamesLower: string[]
    assigneesLower: string[]
    versions: string[]
    searchableTextLower: string
    dependencyRelationship: DependencyRelationship
    hasTmrescoreProposal: boolean
    cvssVersionMismatch: boolean
    lifecycle: string
    isPending: boolean
    isOpen: boolean
    technicalState: string
    firstTag: string
    baseScore: number
    rescoredScore: number
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
}

export interface VulnStateFilterInput {
    lifecycleFilters?: FilterSelection<string>
    analysisFilters?: FilterSelection<string>
}

type FilterSelection<T extends string> = readonly T[] | T | null | undefined

const unique = (values: string[]) => Array.from(new Set(values))

const lower = (value: unknown) => String(value || '').trim().toLowerCase()

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

export function isMeaningfulTMRescoreProposal(group: GroupedVuln, proposal: TMRescoreProposal | null | undefined): boolean {
    const rescoredVector = proposal?.rescored_vector || null
    const originalVector = proposal?.original_vector || group.cvss_vector || null
    if (!rescoredVector) return false
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
    const rawTags = (group.tags || []).map(tagToString).filter(Boolean)
    const normalizedTags = normalizeTags(group.tags || [], teamMapping)
    const allTagText = unique([...rawTags, ...normalizedTags])
    const componentNames = unique(
        (group.affected_versions || [])
            .flatMap(version => version.components || [])
            .map(component => component.component_name)
            .filter((value): value is string => typeof value === 'string' && value.trim().length > 0),
    )
    const versions = unique(
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
    const titleLower = lower(group.title)
    const classification = classifyGroup(group, teamMapping)
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
        componentNamesLower,
        assigneesLower,
        versions,
        searchableTextLower,
        dependencyRelationship: getGroupDependencyRelationship(group),
        hasTmrescoreProposal: hasTMRescoreProposalForGroup(group, proposals),
        cvssVersionMismatch: hasCvssVersionMismatch(group),
        lifecycle: classification.lifecycle,
        isPending: classification.isPending,
        isOpen: classification.isOpen,
        technicalState: classification.technicalState,
        firstTag: normalizedTags[0] || '',
        baseScore: group.cvss_score ?? group.cvss ?? 0,
        rescoredScore: group.rescored_cvss ?? group.cvss_score ?? group.cvss ?? 0,
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

export function matchesSmartSearch(item: VulnListItem, search: ParsedVulnSearchQuery | string | undefined): boolean {
    const parsed = typeof search === 'string' ? parseVulnSearchQuery(search) : search
    if (!parsed || parsed.chips.length === 0) return true

    if (!everyTermMatches(parsed.textTerms, [item.searchableTextLower])) {
        return false
    }
    if (!everyTermMatches(parsed.idTerms, [item.idLower, ...item.aliasesLower])) {
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
    if (!everyTermMatches(parsed.versionTerms, item.versions.map(version => version.toLowerCase()))) {
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

export function matchesListFilters(item: VulnListItem, filters: VulnListFilterInput): boolean {
    if (!matchesSmartSearch(item, filters.smartSearch)) {
        return false
    }

    const dependencyFilter = normalizeFilterSelection(filters.dependencyFilter)
    if (dependencyFilter.length === 0 || !dependencyFilter.includes(item.dependencyRelationship)) {
        return false
    }

    const tmrescoreFilter = normalizeFilterSelection(filters.tmrescoreProposalFilter)
    if (tmrescoreFilter.length === 0) {
        return false
    }
    const matchesProposal =
        (tmrescoreFilter.includes('WITH_PROPOSAL') && item.hasTmrescoreProposal) ||
        (tmrescoreFilter.includes('WITHOUT_PROPOSAL') && !item.hasTmrescoreProposal)
    if (!matchesProposal) {
        return false
    }

    const tagFilter = lower(filters.tagFilter)
    if (tagFilter && !item.tagsLower.some(tag => tag.includes(tagFilter))) {
        return false
    }

    const idFilter = lower(filters.idFilter)
    if (idFilter && !item.idLower.includes(idFilter) && !item.aliasesLower.some(alias => alias.includes(idFilter))) {
        return false
    }

    const componentFilter = lower(filters.componentFilter)
    if (componentFilter && !item.componentNamesLower.some(component => component.includes(componentFilter))) {
        return false
    }

    const assigneeFilter = lower(filters.assigneeFilter)
    if (assigneeFilter && !item.assigneesLower.some(assignee => assignee.includes(assigneeFilter))) {
        return false
    }

    const versionFilterList = filters.versionFilterList || []
    if (versionFilterList.length > 0 && !versionFilterList.some(version => item.versions.includes(version))) {
        return false
    }

    if (filters.cvssVersionMismatchOnly && !item.cvssVersionMismatch) {
        return false
    }

    return true
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

export function matchesStateFilters(item: VulnListItem, filters: VulnStateFilterInput): boolean {
    const lifecycleFilters = normalizeFilterSelection(filters.lifecycleFilters)
    const analysisFilters = normalizeFilterSelection(filters.analysisFilters)

    if (lifecycleFilters.length === 0 || analysisFilters.length === 0) {
        return false
    }

    if (!matchesLifecycleFilter(item, lifecycleFilters)) {
        return false
    }

    return analysisFilters.includes(item.technicalState)
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
