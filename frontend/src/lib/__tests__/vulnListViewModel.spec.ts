import { describe, expect, it } from 'vitest'
import type { GroupedVuln } from '../../types'
import { buildVulnListItems } from '../vulnListIndex'
import {
    deriveVulnListBaseIndex,
    deriveVulnListGroupLookup,
    deriveVulnListFilterModel,
    deriveVulnListStaticStats,
    deriveVulnListViewModel,
    sortVulnListItems,
} from '../vulnListViewModel'
import type { VulnListViewFilters } from '../vulnListViewModel'

const dayMs = 24 * 60 * 60 * 1000
const nowMs = Date.UTC(2026, 5, 30)

const makeGroup = (overrides: Partial<GroupedVuln>): GroupedVuln => ({
    id: 'CVE-2026-0001',
    tags: ['team-a'],
    aliases: [],
    assignees: [],
    cvss_score: 5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    affected_versions: [
        {
            project_name: 'Project',
            project_uuid: 'project-uuid',
            project_version: '1.0.0',
            components: [
                {
                    project_name: 'Project',
                    project_version: '1.0.0',
                    project_uuid: 'project-uuid',
                    component_name: 'library-a',
                    component_version: '2.0.0',
                    component_uuid: 'component-uuid',
                    vulnerability_uuid: 'vuln-uuid',
                    finding_uuid: 'finding-uuid',
                    attributed_on: nowMs - 35 * dayMs,
                    analysis_state: 'NOT_SET',
                    analysis_details: '',
                    is_suppressed: false,
                    is_direct_dependency: true,
                },
            ],
        },
    ],
    ...overrides,
})

const baseFilters = (overrides: Partial<VulnListViewFilters> = {}): VulnListViewFilters => ({
    smartSearch: '',
    tagFilter: '',
    idFilter: '',
    componentFilter: '',
    assigneeFilter: '',
    dependencyFilter: ['DIRECT', 'TRANSITIVE', 'UNKNOWN'],
    tmrescoreProposalFilter: ['WITH_PROPOSAL', 'WITHOUT_PROPOSAL'],
    automaticAssessmentFilter: ['WITH_AUTOMATIC_ASSESSMENT', 'WITHOUT_AUTOMATIC_ASSESSMENT'],
    inconsistencyReasonFilter: [],
    versionFilterList: [],
    cvssVersionMismatchOnly: false,
    attributionAgeDays: null,
    attributionAgeMode: 'older',
    lifecycleFilters: ['OPEN', 'ASSESSED', 'INCOMPLETE', 'INCONSISTENT', 'NEEDS_APPROVAL'],
    analysisFilters: ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED'],
    sortBy: 'score',
    sortOrder: 'desc',
    ...overrides,
})

describe('vulnListViewModel', () => {
    it('counts ambiguous restoration gaps for the restore preview entry point', () => {
        const items = buildVulnListItems([
            makeGroup({
                id: 'CVE-AMBIGUOUS-RESTORE',
                assessment_restore_count: 1,
                assessment_restore_recoverable_count: 0,
                assessment_restore_status: 'ambiguous',
                list_metadata: {
                    lifecycle: 'INCONSISTENT',
                    assessment_restore_count: 1,
                    assessment_restore_recoverable_count: 0,
                    assessment_restore_status: 'ambiguous',
                    inconsistency_reasons: ['MISSING_RESCORING_VECTOR'],
                },
            }),
        ], {}, {})

        const stats = deriveVulnListStaticStats(items)
        expect(stats.assessmentRestoreCount).toBe(1)
        expect(stats.assessmentRestoreRecoverableCount).toBe(0)
    })

    it('filters inconsistent groups by any selected reason', () => {
        const items = buildVulnListItems([
            makeGroup({
                id: 'CVE-STATE',
                list_metadata: {
                    lifecycle: 'INCONSISTENT',
                    inconsistency_reasons: ['ANALYSIS_STATE_MISMATCH'],
                },
            }),
            makeGroup({
                id: 'CVE-DETAILS',
                list_metadata: {
                    lifecycle: 'INCONSISTENT',
                    inconsistency_reasons: ['ASSESSMENT_DETAILS_MISMATCH'],
                },
            }),
        ], {}, {})

        const view = deriveVulnListViewModel(items, baseFilters({
            inconsistencyReasonFilter: ['ASSESSMENT_DETAILS_MISMATCH'],
        }))

        expect(view.matchingItems.map(item => item.id)).toEqual(['CVE-DETAILS'])
        expect(view.inconsistencyReasonCounts.ANALYSIS_STATE_MISMATCH).toBe(1)
        expect(view.inconsistencyReasonCounts.ASSESSMENT_DETAILS_MISMATCH).toBe(1)
    })

    it('derives filtered rows, sorted rows, and sidebar counts in one model', () => {
        const openDirect = makeGroup({
            id: 'CVE-2026-0001',
            tags: ['team-a'],
            cvss_score: 4,
        })
        const assessedTransitive = makeGroup({
            id: 'CVE-2026-0002',
            tags: ['team-b'],
            cvss_score: 9.8,
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '1.0.0',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '1.0.0',
                            project_uuid: 'project-uuid',
                            component_name: 'library-b',
                            component_version: '3.0.0',
                            component_uuid: 'component-b',
                            vulnerability_uuid: 'vuln-b',
                            finding_uuid: 'finding-b',
                            attributed_on: nowMs - 7 * dayMs,
                            analysis_state: 'FALSE_POSITIVE',
                            analysis_details: '--- [Team: General] [State: FALSE_POSITIVE] ---\nSafe path',
                            is_suppressed: false,
                            is_direct_dependency: false,
                        },
                    ],
                },
            ],
        })
        const incompleteSummary = makeGroup({
            id: 'CVE-2026-0003',
            tags: ['team-c'],
            cvss_score: 7.1,
            list_metadata: {
                lifecycle: 'INCOMPLETE',
                is_open: false,
                is_pending: false,
                is_assessed: false,
                technical_state: 'IN_TRIAGE',
                assessed_teams: ['team-c'],
            },
        })
        const pendingSummary = makeGroup({
            id: 'CVE-2026-0004',
            tags: ['team-a'],
            cvss_score: 6,
            list_metadata: {
                lifecycle: 'NEEDS_APPROVAL',
                is_open: true,
                is_pending: true,
                is_assessed: false,
                technical_state: 'NOT_AFFECTED',
                assessed_teams: ['team-a'],
            },
        })

        const items = buildVulnListItems([
            openDirect,
            assessedTransitive,
            incompleteSummary,
            pendingSummary,
        ], {}, {})

        const view = deriveVulnListViewModel(items, baseFilters({
            idFilter: '2026-000',
            sortBy: 'score',
            sortOrder: 'desc',
        }))

        expect(view.sortedItems.map(item => item.id)).toEqual([
            'CVE-2026-0002',
            'CVE-2026-0003',
            'CVE-2026-0004',
            'CVE-2026-0001',
        ])
        expect(view.filterCounts.OPEN).toBe(2)
        expect(view.filterCounts.ASSESSED).toBe(1)
        expect(view.filterCounts.INCOMPLETE).toBe(1)
        expect(view.filterCounts.NEEDS_APPROVAL).toBe(1)
        expect(view.analysisCounts.FALSE_POSITIVE).toBe(1)
        expect(view.analysisCounts.IN_TRIAGE).toBe(1)
        expect(view.teamTagCounts).toEqual({
            'team-a': { open: 2, assessed: 0 },
            'team-b': { open: 0, assessed: 1 },
            'team-c': { open: 0, assessed: 1 },
        })
        expect(view.dependencyFilterCounts).toEqual({ direct: 3, transitive: 1, unknown: 0 })
        expect(view.dependencyRelationshipCounts).toEqual({ direct: 3, transitive: 1, unknown: 0 })
        expect(view.needsApprovalGroups.map(group => group.id)).toEqual(['CVE-2026-0004'])
        expect(view.incompleteGroups.map(group => group.id)).toEqual(['CVE-2026-0003'])
    })

    it('keeps counts broad while matching rows obey non-state filters', () => {
        const items = buildVulnListItems([
            makeGroup({ id: 'CVE-2026-0001', tags: ['team-a'] }),
            makeGroup({
                id: 'CVE-2026-0002',
                tags: ['team-b'],
                affected_versions: [
                    {
                        project_name: 'Project',
                        project_uuid: 'project-uuid',
                        project_version: '1.0.0',
                        components: [
                            {
                                project_name: 'Project',
                                project_version: '1.0.0',
                                project_uuid: 'project-uuid',
                                component_name: 'library-b',
                                component_version: '3.0.0',
                                component_uuid: 'component-b',
                                vulnerability_uuid: 'vuln-b',
                                finding_uuid: 'finding-b',
                                analysis_state: 'NOT_SET',
                                analysis_details: '',
                                is_suppressed: false,
                                is_direct_dependency: false,
                            },
                        ],
                    },
                ],
            }),
        ], {}, {})

        const view = deriveVulnListViewModel(items, baseFilters({
            dependencyFilter: ['DIRECT'],
            tagFilter: 'team-a',
        }))

        expect(view.matchingItems.map(item => item.id)).toEqual(['CVE-2026-0001'])
        expect(view.filterCounts.OPEN).toBe(2)
        expect(view.dependencyFilterCounts).toEqual({ direct: 1, transitive: 1, unknown: 0 })
        expect(view.dependencyRelationshipCounts).toEqual({ direct: 1, transitive: 0, unknown: 0 })
    })

    it('can reuse static stats while filtering and sorting stay separate', () => {
        const items = buildVulnListItems([
            makeGroup({ id: 'CVE-2026-0001', tags: ['team-a'], cvss_score: 3 }),
            makeGroup({ id: 'CVE-2026-0002', tags: ['team-b'], cvss_score: 9 }),
        ], {}, {})

        const staticStats = deriveVulnListStaticStats(items)
        const filterModel = deriveVulnListFilterModel(items, baseFilters({
            idFilter: 'CVE-2026',
        }), staticStats)

        expect(staticStats.filterCounts.OPEN).toBe(2)
        expect(staticStats.filterCounts.NOT_SET).toBe(0)
        expect(filterModel.filterCounts.OPEN).toBe(2)
        expect(filterModel.filterCounts.NOT_SET).toBe(2)
        expect(filterModel.teamTagCounts).toBe(staticStats.teamTagCounts)
        expect(filterModel.matchingItems.map(item => item.id)).toEqual([
            'CVE-2026-0001',
            'CVE-2026-0002',
        ])
        expect(sortVulnListItems(filterModel.matchingItems, 'score', 'desc').map(item => item.id)).toEqual([
            'CVE-2026-0002',
            'CVE-2026-0001',
        ])
        expect(sortVulnListItems(filterModel.matchingItems, 'score', 'asc').map(item => item.id)).toEqual([
            'CVE-2026-0001',
            'CVE-2026-0002',
        ])
    })

    it('sorts severity using precomputed item ranks', () => {
        const items = buildVulnListItems([
            makeGroup({ id: 'CVE-2026-0001', cvss_score: 0 }),
            makeGroup({ id: 'CVE-2026-0002', cvss_score: 9.8 }),
            makeGroup({ id: 'CVE-2026-0003', cvss_score: 5 }),
        ], {}, {})

        expect(items.find(item => item.id === 'CVE-2026-0002')?.baseSeverityRank).toBe(0)
        expect(sortVulnListItems(items, 'severity', 'desc').map(item => item.id)).toEqual([
            'CVE-2026-0002',
            'CVE-2026-0003',
            'CVE-2026-0001',
        ])
        expect(sortVulnListItems(items, 'severity', 'asc').map(item => item.id)).toEqual([
            'CVE-2026-0001',
            'CVE-2026-0003',
            'CVE-2026-0002',
        ])
    })

    it('builds group arrays and ID lookups from list items in one pass', () => {
        const items = buildVulnListItems([
            makeGroup({ id: 'CVE-2026-0001', cvss_score: 3 }),
            makeGroup({ id: 'CVE-2026-0002', cvss_score: 9 }),
        ], {}, {})
        const sortedItems = sortVulnListItems(items, 'score', 'desc')

        const lookup = deriveVulnListGroupLookup(sortedItems)

        expect(lookup.groups.map(group => group.id)).toEqual([
            'CVE-2026-0002',
            'CVE-2026-0001',
        ])
        expect(lookup.groupById.get('CVE-2026-0002')).toBe(lookup.groups[0])
        expect(lookup.groupById.get('CVE-2026-0001')).toBe(lookup.groups[1])
        expect(lookup.groupById.has('CVE-2026-9999')).toBe(false)
    })

    it('derives facets, static stats, and group lookups in one base index', () => {
        const firstGroup = makeGroup({
            id: 'CVE-2026-0001',
            aliases: ['GHSA-alpha'],
            tags: ['team-a'],
            assignees: ['Alice'],
        })
        const secondGroup = makeGroup({
            id: 'CVE-2026-0002',
            tags: ['team-b'],
            assignees: ['Bob'],
            list_metadata: {
                lifecycle: 'INCOMPLETE',
                is_open: false,
                is_pending: false,
                is_assessed: false,
                technical_state: 'IN_TRIAGE',
                assessed_teams: ['team-b'],
            },
        })
        const items = buildVulnListItems([firstGroup, secondGroup], {}, {})

        const index = deriveVulnListBaseIndex(items)

        expect(index.facets.ids).toEqual(['CVE-2026-0001', 'CVE-2026-0002', 'GHSA-alpha'])
        expect(index.facets.teams).toEqual(['team-a', 'team-b'])
        expect(index.facets.assignees).toEqual(['Alice', 'Bob'])
        expect(index.facets.components).toEqual(['library-a'])
        expect(index.facets.availableVersions).toEqual(['1.0.0'])
        expect(index.staticStats.filterCounts.OPEN).toBe(1)
        expect(index.staticStats.filterCounts.INCOMPLETE).toBe(1)
        expect(index.staticStats.teamTagCounts).toEqual({
            'team-a': { open: 1, assessed: 0 },
            'team-b': { open: 0, assessed: 1 },
        })
        expect(index.staticStats.incompleteGroups).toEqual([secondGroup])
        expect(index.groupLookup.groups).toEqual([firstGroup, secondGroup])
        expect(index.groupLookup.groupById.get('CVE-2026-0002')).toBe(secondGroup)
    })

    it('applies attribution age to matching rows and analysis counts consistently', () => {
        const oldItem = makeGroup({ id: 'CVE-2026-0001' })
        const recentItem = makeGroup({
            id: 'CVE-2026-0002',
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '1.0.0',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '1.0.0',
                            project_uuid: 'project-uuid',
                            component_name: 'library-b',
                            component_version: '3.0.0',
                            component_uuid: 'component-b',
                            vulnerability_uuid: 'vuln-b',
                            finding_uuid: 'finding-b',
                            attributed_on: nowMs - 7 * dayMs,
                            analysis_state: 'NOT_SET',
                            analysis_details: '',
                            is_suppressed: false,
                            is_direct_dependency: true,
                        },
                    ],
                },
            ],
        })

        const items = buildVulnListItems([oldItem, recentItem], {}, {})
        const view = deriveVulnListViewModel(items, baseFilters({
            attributionAgeDays: 28,
            attributionAgeMode: 'older',
        }))

        expect(view.matchingItems.map(item => item.id)).toEqual(['CVE-2026-0001'])
        expect(view.attributionAgeCount).toBe(1)
        expect(view.analysisCounts.NOT_SET).toBe(1)
    })
})
