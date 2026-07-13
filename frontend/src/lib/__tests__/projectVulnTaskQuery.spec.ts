import { describe, expect, it } from 'vitest'
import type { TMRescoreProposal } from '../../types'
import {
    buildMeaningfulTMRescoreProposalIds,
    buildTaskVulnGroupListQuery,
    NO_MATCH_FILTER,
    type BuildTaskVulnGroupListQueryInput,
} from '../projectVulnTaskQuery'
import { parseVulnSearchQuery } from '../vulnListIndex'
import {
    DEFAULT_ANALYSIS_FILTERS,
    DEFAULT_REVIEWER_LIFECYCLE_FILTERS,
} from '../useProjectVulnFilters'

const baseInput = (overrides: Partial<BuildTaskVulnGroupListQueryInput> = {}): BuildTaskVulnGroupListQueryInput => ({
    parsedSearch: parseVulnSearchQuery(''),
    filtersReady: true,
    lifecycleFilters: DEFAULT_REVIEWER_LIFECYCLE_FILTERS,
    inconsistencyReasonFilters: [],
    defaultLifecycleFilters: DEFAULT_REVIEWER_LIFECYCLE_FILTERS,
    analysisFilters: DEFAULT_ANALYSIS_FILTERS,
    defaultAnalysisFilters: DEFAULT_ANALYSIS_FILTERS,
    tagFilter: '',
    idFilter: '',
    componentFilter: '',
    assigneeFilter: '',
    dependencyFilters: ['DIRECT', 'TRANSITIVE', 'UNKNOWN'],
    versionFilters: [],
    cvssVersionMismatchOnly: false,
    attributionAgeDays: null,
    attributionAgeMode: 'older',
    tmrescoreFilters: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'],
    allTMRescoreFilterValues: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'],
    meaningfulTMRescoreProposalIds: ['CVE-2026-0001'],
    automaticAssessmentFilters: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'],
    allAutomaticAssessmentFilterValues: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'],
    automaticAssessmentIds: ['cve-2026-auto'],
    sortBy: 'rescored-severity',
    sortOrder: 'desc',
    ...overrides,
})

const proposal = (overrides: Partial<TMRescoreProposal>): TMRescoreProposal => ({
    vuln_id: 'CVE-2026-0001',
    original_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
    original_score: 5,
    rescored_score: 4,
    affected_refs: [],
    session_id: 'session',
    scope: 'latest_only',
    latest_version: '1.0.0',
    analyzed_versions: ['1.0.0'],
    ...overrides,
})

describe('projectVulnTaskQuery', () => {
    it('combines sidebar filters and smart-search tokens into a backend task-window query', () => {
        const query = buildTaskVulnGroupListQuery(baseInput({
            parsedSearch: parseVulnSearchQuery('urgent lifecycle:open analysis:resolved team:platform id:CVE-2026-9999 component:spring assignee:alice version:2.0.0 dependency:direct tm:with has:cvss_mismatch'),
            lifecycleFilters: ['OPEN', 'INCOMPLETE'],
            inconsistencyReasonFilters: ['ANALYSIS_STATE_MISMATCH'],
            analysisFilters: DEFAULT_ANALYSIS_FILTERS,
            tagFilter: 'backend',
            idFilter: 'GHSA-1234',
            componentFilter: 'gateway',
            assigneeFilter: 'bob',
            versionFilters: ['1.0.0', '2.0.0'],
            attributionAgeDays: 14,
            attributionAgeMode: 'younger',
            sortBy: 'id',
            sortOrder: 'asc',
        }))

        expect(query).toMatchObject({
            q: 'urgent',
            lifecycle: ['OPEN'],
            inconsistency_reason: ['ANALYSIS_STATE_MISMATCH'],
            analysis: ['RESOLVED'],
            tag: 'backend platform',
            id: 'GHSA-1234 cve-2026-9999',
            component: 'gateway spring',
            assignee: 'bob alice',
            dependency: ['DIRECT'],
            versions: ['1.0.0', '2.0.0'],
            cvss_mismatch: true,
            attributed_before_days: 14,
            attribution_mode: 'younger',
            tmrescore: ['WITH_PROPOSAL'],
            tmrescore_proposal_ids: ['CVE-2026-0001'],
            automatic_assessment: [],
            automatic_assessment_ids: ['cve-2026-auto'],
            sort: 'id',
            order: 'asc',
        })
    })

    it('uses role defaults before filters are hydrated', () => {
        const query = buildTaskVulnGroupListQuery(baseInput({
            filtersReady: false,
            lifecycleFilters: [],
            analysisFilters: [],
        }))

        expect(query.lifecycle).toEqual(DEFAULT_REVIEWER_LIFECYCLE_FILTERS)
        expect(query.analysis).toEqual(DEFAULT_ANALYSIS_FILTERS)
    })

    it('returns a no-match sentinel when token restrictions exclude every selected value', () => {
        const query = buildTaskVulnGroupListQuery(baseInput({
            parsedSearch: parseVulnSearchQuery('lifecycle:open dependency:direct'),
            lifecycleFilters: ['ASSESSED'],
            dependencyFilters: ['TRANSITIVE'],
        }))

        expect(query.lifecycle).toEqual([NO_MATCH_FILTER])
        expect(query.dependency).toEqual([NO_MATCH_FILTER])
    })

    it('omits tmrescore filters and proposal IDs when the TM selection is unrestricted', () => {
        const query = buildTaskVulnGroupListQuery(baseInput())

        expect(query.tmrescore).toEqual([])
        expect(query.tmrescore_proposal_ids).toEqual([])
    })

    it('passes automatic assessment ids and only restricts when selection is customized', () => {
        const unrestricted = buildTaskVulnGroupListQuery(baseInput())
        expect(unrestricted.automatic_assessment).toEqual([])
        expect(unrestricted.automatic_assessment_ids).toEqual(['cve-2026-auto'])

        const restricted = buildTaskVulnGroupListQuery(baseInput({
            automaticAssessmentFilters: ['WITH_AUTOMATIC_ASSESSMENT'],
        }))
        expect(restricted.automatic_assessment).toEqual(['WITH_AUTOMATIC_ASSESSMENT'])
        expect(restricted.automatic_assessment_ids).toEqual(['cve-2026-auto'])
    })

    it('deduplicates meaningful proposal IDs and ignores no-op proposals', () => {
        const ids = buildMeaningfulTMRescoreProposalIds({
            'CVE-2026-0001': proposal({ vuln_id: 'GHSA-0001' }),
            'ghsa-0001': proposal({ vuln_id: 'GHSA-0001' }),
            'CVE-2026-0002': proposal({
                vuln_id: 'CVE-2026-0002',
                rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            }),
        })

        expect(ids).toEqual(['CVE-2026-0001', 'GHSA-0001'])
    })
})
