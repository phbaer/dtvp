import type { GroupedVuln } from '../types'

export const EVIDENCE_OPTIONS = [
    { value: 'KEV', label: 'KEV listed' },
    { value: 'CISA_SSVC', label: 'CISA SSVC available' },
    { value: 'NOT_CHECKED', label: 'Not fully checked' },
    { value: 'NO_DATA', label: 'Checked — no data' },
    { value: 'STALE', label: 'Stale cached data' },
    { value: 'UNAVAILABLE', label: 'Source unavailable' },
    { value: 'NO_CVE', label: 'No CVE identifier' },
]
export const evidenceLabel = (value: string) => EVIDENCE_OPTIONS.find(option => option.value === value)?.label || value
export const evidenceSources = (group: GroupedVuln): string[] => group.evidence_sources
    ?? ([group.id, ...(group.aliases || [])].some(id => /^CVE-\d{4}-\d{4,19}$/i.test(id.trim())) ? ['NOT_CHECKED'] : ['NO_CVE'])
export const EVIDENCE_UPDATED_EVENT = 'dtvp-evidence-updated'

export interface EvidenceLookupSource {
    source: string
    status: string
    error?: string | null
    value?: string
}

/** What an evidence lookup tells the list: the CVEs asked for and their flags. */
export interface EvidenceUpdate {
    cves: string[]
    sources: string[]
}

const CVE_ID = /^CVE-\d{4}-\d{4,19}$/i

/** The CVE identifiers of a vulnerability: its id and aliases. */
export const groupCves = (group: Pick<GroupedVuln, 'id' | 'aliases'>): string[] =>
    [...new Set([group.id, ...(group.aliases || [])]
        .map(id => String(id || '').trim().toUpperCase())
        .filter(id => CVE_ID.test(id)))].sort()

/**
 * The list's evidence flags for the sources an evidence lookup returned,
 * by the rules of the server's list filter (evidence_services.py
 * ``evidence_sources``). Comparing them with a row's ``evidence_sources``
 * says whether the lookup changed what the list shows.
 */
export const evidenceSourcesFromLookup = (sources: readonly EvidenceLookupSource[]): string[] => {
    const flags = new Set<string>()
    for (const source of sources) {
        if (source.value) flags.add(source.source === 'CISA KEV' ? 'KEV' : 'CISA_SSVC')
        if (source.error) flags.add('UNAVAILABLE')
        if (source.status === 'unavailable') {
            if (!source.error) flags.add('NOT_CHECKED')
        } else if (source.error || source.status === 'stale') {
            flags.add('STALE')
        }
    }
    if (!flags.size) flags.add('NO_DATA')
    return EVIDENCE_OPTIONS.map(option => option.value).filter(value => flags.has(value))
}
