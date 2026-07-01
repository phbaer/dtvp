import { describe, expect, it } from 'vitest'
import type { GroupedVuln, TMRescoreProposal } from '../../types'
import { createVulnListItemCache } from '../vulnListItemCache'

const makeGroup = (id: string, overrides: Partial<GroupedVuln> = {}): GroupedVuln => ({
    id,
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

const makeProposal = (vulnId: string): TMRescoreProposal => ({
    vuln_id: vulnId,
    rescored_score: 4.2,
    rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
    original_score: 5,
    original_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    affected_refs: [],
    session_id: 'session',
    scope: 'latest_only',
    latest_version: '1.0.0',
    analyzed_versions: ['1.0.0'],
})

describe('vulnListItemCache', () => {
    it('reuses list items when group and metadata inputs are unchanged', () => {
        const cache = createVulnListItemCache()
        const teamMapping = {}
        const proposals = {}
        const firstGroup = makeGroup('CVE-2026-0001')
        const secondGroup = makeGroup('CVE-2026-0002')

        const first = cache.build([firstGroup, secondGroup], teamMapping, proposals)
        const second = cache.build([firstGroup, secondGroup], teamMapping, proposals)

        expect(second[0]).toBe(first[0])
        expect(second[1]).toBe(first[1])
    })

    it('rebuilds only the replaced group object', () => {
        const cache = createVulnListItemCache()
        const teamMapping = {}
        const proposals = {}
        const firstGroup = makeGroup('CVE-2026-0001')
        const secondGroup = makeGroup('CVE-2026-0002')
        const first = cache.build([firstGroup, secondGroup], teamMapping, proposals)

        const updatedSecondGroup = makeGroup('CVE-2026-0002', { cvss_score: 9.8 })
        const second = cache.build([firstGroup, updatedSecondGroup], teamMapping, proposals)

        expect(second[0]).toBe(first[0])
        expect(second[1]).not.toBe(first[1])
        expect(second[1].baseScore).toBe(9.8)
    })

    it('invalidates cached items when team mapping or proposals change', () => {
        const cache = createVulnListItemCache()
        const group = makeGroup('CVE-2026-0001', {
            tags: ['Team Alias'],
        })
        const initial = cache.build([group], {}, {})[0]

        const mapped = cache.build([group], {
            'library-a': ['Team Primary', 'Team Alias'],
        }, {})[0]
        expect(mapped).not.toBe(initial)
        expect(mapped.normalizedTags).toEqual(['Team Primary'])

        const withProposal = cache.build([group], {
            'library-a': ['Team Primary', 'Team Alias'],
        }, {
            'CVE-2026-0001': makeProposal('CVE-2026-0001'),
        })[0]

        expect(withProposal).not.toBe(mapped)
        expect(withProposal.hasTmrescoreProposal).toBe(true)
    })

    it('can be cleared explicitly', () => {
        const cache = createVulnListItemCache()
        const group = makeGroup('CVE-2026-0001')
        const teamMapping = {}
        const proposals = {}
        const first = cache.build([group], teamMapping, proposals)

        cache.clear()
        const second = cache.build([group], teamMapping, proposals)

        expect(second[0]).not.toBe(first[0])
    })
})
