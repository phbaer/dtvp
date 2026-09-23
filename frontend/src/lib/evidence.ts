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
