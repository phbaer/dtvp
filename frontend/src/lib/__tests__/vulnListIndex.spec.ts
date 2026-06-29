import { describe, expect, it } from 'vitest'
import type { GroupedVuln, TMRescoreProposal } from '../../types'
import {
    buildVulnListItem,
    buildVulnListItems,
    computeListFilterCounts,
    computeListTeamCounts,
    getGroupDependencyRelationship,
    hasTMRescoreProposalForGroup,
    matchesAttributionAgeFilter,
    matchesLifecycleFilter,
    matchesListFilters,
    matchesSmartSearch,
    matchesStateFilters,
    parseAttributionTimestamp,
    normalizeFilterSelection,
    parseVulnSearchQuery,
} from '../vulnListIndex'

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
                    analysis_state: 'NOT_SET',
                    analysis_details: '',
                    is_suppressed: false,
                },
            ],
        },
    ],
    ...overrides,
})

const makeProposal = (overrides: Partial<TMRescoreProposal>): TMRescoreProposal => ({
    vuln_id: 'CVE-2026-0001',
    rescored_score: 4.2,
    rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
    original_score: 5,
    original_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    affected_refs: [],
    session_id: 'session',
    scope: 'latest_only',
    latest_version: '1.0.0',
    analyzed_versions: ['1.0.0'],
    ...overrides,
})

describe('vulnListIndex', () => {
    it('normalizes scalar and array filter selections', () => {
        expect(normalizeFilterSelection('DIRECT')).toEqual(['DIRECT'])
        expect(normalizeFilterSelection(['DIRECT', 'UNKNOWN'])).toEqual(['DIRECT', 'UNKNOWN'])
        expect(normalizeFilterSelection(undefined)).toEqual([])
    })

    it('precomputes searchable fields and proposal/dependency metadata', () => {
        const group = makeGroup({
            id: 'CVE-2026-1234',
            aliases: ['GHSA-abcd'],
            tags: ['Team Alias'],
            assignees: ['Alice'],
            rescored_vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '2.0.0',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '2.0.0',
                            project_uuid: 'project-uuid',
                            component_name: 'Spring Core',
                            component_version: '6.0.0',
                            component_uuid: 'component-uuid',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-uuid',
                            analysis_state: 'NOT_SET',
                            analysis_details: '',
                            is_suppressed: false,
                            is_direct_dependency: true,
                        },
                    ],
                },
            ],
        })
        const item = buildVulnListItem(group, { component: ['Team Primary', 'Team Alias'] }, {
            'GHSA-ABCD': makeProposal({ vuln_id: 'GHSA-abcd' }),
        })

        expect(item.idLower).toBe('cve-2026-1234')
        expect(item.aliasesLower).toContain('ghsa-abcd')
        expect(item.normalizedTags).toEqual(['Team Primary'])
        expect(item.componentNamesLower).toEqual(['spring core'])
        expect(item.assigneesLower).toEqual(['alice'])
        expect(item.versions).toEqual(['2.0.0'])
        expect(item.dependencyRelationship).toBe('DIRECT')
        expect(item.hasTmrescoreProposal).toBe(true)
        expect(item.cvssVersionMismatch).toBe(true)
    })

    it('matches list filters from precomputed item fields', () => {
        const group = makeGroup({
            id: 'CVE-2026-1234',
            aliases: ['GHSA-zzzz'],
            tags: ['3p-security'],
            assignees: ['bob'],
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '2026.4',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '2026.4',
                            project_uuid: 'project-uuid',
                            component_name: 'Netty Handler',
                            component_version: '4.1.0',
                            component_uuid: 'component-uuid',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-uuid',
                            analysis_state: 'NOT_SET',
                            analysis_details: '',
                            is_suppressed: false,
                            is_direct_dependency: false,
                        },
                    ],
                },
            ],
        })
        const item = buildVulnListItem(group, {}, {})

        expect(matchesListFilters(item, {
            dependencyFilter: 'TRANSITIVE',
            tmrescoreProposalFilter: 'WITHOUT_PROPOSAL',
            tagFilter: '3p',
            idFilter: 'ghsa',
            componentFilter: 'handler',
            assigneeFilter: 'bo',
            versionFilterList: ['2026.4'],
        })).toBe(true)

        expect(matchesListFilters(item, {
            dependencyFilter: 'DIRECT',
            tmrescoreProposalFilter: 'WITHOUT_PROPOSAL',
        })).toBe(false)
    })

    it('matches findings attributed before the selected age threshold', () => {
        const nowMs = Date.UTC(2026, 5, 29)
        const oldMs = nowMs - 29 * 24 * 60 * 60 * 1000
        const exactMs = nowMs - 28 * 24 * 60 * 60 * 1000
        const group = makeGroup({
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '2026.4',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '2026.4',
                            project_uuid: 'project-uuid',
                            component_name: 'Netty Handler',
                            component_version: '4.1.0',
                            component_uuid: 'component-old',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-old',
                            attributed_on: oldMs,
                            analysis_state: 'NOT_SET',
                            analysis_details: '',
                            is_suppressed: false,
                        },
                        {
                            project_name: 'Project',
                            project_version: '2026.4',
                            project_uuid: 'project-uuid',
                            component_name: 'Netty Handler',
                            component_version: '4.1.0',
                            component_uuid: 'component-exact',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-exact',
                            attributed_on: exactMs,
                            analysis_state: 'NOT_SET',
                            analysis_details: '',
                            is_suppressed: false,
                        },
                    ],
                },
            ],
        })
        const item = buildVulnListItem(group, {}, {})

        expect(parseAttributionTimestamp(String(Math.floor(oldMs / 1000)))).toBe(oldMs)
        expect(parseAttributionTimestamp(new Date(oldMs).toISOString())).toBe(oldMs)
        expect(item.oldestAttributedOnMs).toBe(oldMs)
        expect(matchesAttributionAgeFilter(item, 28, 'older', nowMs)).toBe(true)
        expect(matchesAttributionAgeFilter(item, 30, 'older', nowMs)).toBe(false)
    })

    it('does not match the attribution age filter when timestamps are missing or invalid', () => {
        const item = buildVulnListItem(makeGroup({
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '2026.4',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '2026.4',
                            project_uuid: 'project-uuid',
                            component_name: 'Netty Handler',
                            component_version: '4.1.0',
                            component_uuid: 'component-invalid',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-invalid',
                            attributed_on: 'not-a-date',
                            analysis_state: 'NOT_SET',
                            analysis_details: '',
                            is_suppressed: false,
                        },
                    ],
                },
            ],
        }), {}, {})

        expect(item.attributedOnMsValues).toEqual([])
        expect(matchesAttributionAgeFilter(item, 28, 'older', Date.UTC(2026, 5, 29))).toBe(false)
    })

    it('matches younger and older attribution ages using the mode', () => {
        const dayMs = 24 * 60 * 60 * 1000
        const nowMs = Date.UTC(2026, 5, 29, 12)
        const oldMs = nowMs - 29 * dayMs
        const recentMs = nowMs - 7 * dayMs
        const item = buildVulnListItem(makeGroup({
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '2026.4',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '2026.4',
                            project_uuid: 'project-uuid',
                            component_name: 'Netty Handler',
                            component_version: '4.1.0',
                            component_uuid: 'component-old',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-old',
                            attributed_on: oldMs,
                            analysis_state: 'NOT_SET',
                            analysis_details: '',
                            is_suppressed: false,
                        },
                    ],
                },
            ],
        }), {}, {})

        const recentOnlyItem = buildVulnListItem(makeGroup({
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '2026.4',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '2026.4',
                            project_uuid: 'project-uuid',
                            component_name: 'Netty Handler',
                            component_version: '4.1.0',
                            component_uuid: 'component-recent',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-recent',
                            attributed_on: recentMs,
                            analysis_state: 'NOT_SET',
                            analysis_details: '',
                            is_suppressed: false,
                        },
                    ],
                },
            ],
        }), {}, {})

        expect(matchesAttributionAgeFilter(item, 14, 'older', nowMs)).toBe(true)
        expect(matchesAttributionAgeFilter(item, 14, 'younger', nowMs)).toBe(false)
        expect(matchesAttributionAgeFilter(recentOnlyItem, 14, 'younger', nowMs)).toBe(true)
        expect(matchesAttributionAgeFilter(recentOnlyItem, 14, 'older', nowMs)).toBe(false)
    })

    it('parses broad smart search terms and typed filter tokens', () => {
        const parsed = parseVulnSearchQuery('log4j team:platform state:open dep:direct has:tmrescore cvss:mismatch')

        expect(parsed.textTerms).toEqual(['log4j'])
        expect(parsed.teamTerms).toEqual(['platform'])
        expect(parsed.lifecycleTerms).toEqual(['OPEN'])
        expect(parsed.dependencyTerms).toEqual(['DIRECT'])
        expect(parsed.tmrescoreTerms).toEqual(['WITH_PROPOSAL'])
        expect(parsed.cvssMismatchOnly).toBe(true)
        expect(parsed.chips.map(chip => chip.label)).toContain('Team: platform')
    })

    it('parses quoted values after typed filter prefixes', () => {
        const parsed = parseVulnSearchQuery('team:"App Sec" component:\'Spring Core\' assignee:"Alice Doe"')

        expect(parsed.teamTerms).toEqual(['app sec'])
        expect(parsed.componentTerms).toEqual(['spring core'])
        expect(parsed.assigneeTerms).toEqual(['alice doe'])
        expect(parsed.chips.map(chip => chip.label)).toContain('Component: Spring Core')
    })

    it('matches smart search against ids, titles, components, teams, assignees, versions, and typed tokens', () => {
        const group = makeGroup({
            id: 'CVE-2026-4242',
            title: 'Remote execution in Log4j bridge',
            aliases: ['GHSA-smart-search'],
            tags: ['platform'],
            assignees: ['alice'],
            rescored_vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '2.5.0',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '2.5.0',
                            project_uuid: 'project-uuid',
                            component_name: 'log4j-core',
                            component_version: '2.17.0',
                            component_uuid: 'component-uuid',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-uuid',
                            analysis_state: 'NOT_SET',
                            analysis_details: '',
                            is_suppressed: false,
                            is_direct_dependency: true,
                        },
                    ],
                },
            ],
        })
        const item = buildVulnListItem(group, {}, {
            'CVE-2026-4242': makeProposal({ vuln_id: 'CVE-2026-4242' }),
        })

        expect(matchesSmartSearch(item, 'log4j')).toBe(true)
        expect(matchesSmartSearch(item, 'id:GHSA-smart')).toBe(true)
        expect(matchesSmartSearch(item, 'component:core team:platform assignee:alice version:2.5')).toBe(true)
        expect(matchesSmartSearch(item, 'state:open dep:direct has:tmrescore cvss:mismatch')).toBe(true)
        expect(matchesSmartSearch(item, 'component:netty')).toBe(false)
    })

    it('preserves pending review lifecycle semantics', () => {
        const pending = makeGroup({
            id: 'CVE-2026-9999',
            tags: ['team-a'],
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
                            analysis_state: 'NOT_SET',
                            analysis_details: '[Status: Pending Review]',
                            is_suppressed: false,
                        },
                    ],
                },
            ],
        })
        const item = buildVulnListItem(pending, {}, {})

        expect(matchesLifecycleFilter(item, ['NEEDS_APPROVAL'])).toBe(true)
        expect(matchesLifecycleFilter(item, ['OPEN'])).toBe(true)
        expect(matchesStateFilters(item, {
            lifecycleFilters: ['NEEDS_APPROVAL'],
            analysisFilters: ['NOT_SET'],
        })).toBe(true)
    })

    it('computes sidebar counts from indexed items', () => {
        const open = makeGroup({ id: 'CVE-2026-0001', tags: ['team-a'] })
        const assessed = makeGroup({
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
                            component_version: '2.0.0',
                            component_uuid: 'component-uuid',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-uuid',
                            analysis_state: 'FALSE_POSITIVE',
                            analysis_details: '--- [Team: General] [State: FALSE_POSITIVE] ---',
                            is_suppressed: false,
                        },
                    ],
                },
            ],
        })
        const items = buildVulnListItems([open, assessed], {}, {})

        expect(computeListFilterCounts(items, ['OPEN']).OPEN).toBe(1)
        expect(computeListFilterCounts(items, ['OPEN']).NOT_SET).toBe(1)
        expect(computeListFilterCounts(items, ['ASSESSED']).FALSE_POSITIVE).toBe(1)
        expect(computeListTeamCounts(items)).toEqual({
            'team-a': { open: 1, assessed: 0 },
            'team-b': { open: 0, assessed: 1 },
        })
    })

    it('ignores tmrescore proposals that do not change the vector', () => {
        const group = makeGroup({ id: 'CVE-2026-1234' })

        expect(hasTMRescoreProposalForGroup(group, {
            'CVE-2026-1234': makeProposal({
                rescored_vector: group.cvss_vector || null,
                original_vector: group.cvss_vector || null,
            }),
        })).toBe(false)
        expect(getGroupDependencyRelationship(group)).toBe('UNKNOWN')
    })
})
