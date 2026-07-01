import { describe, expect, it } from 'vitest'
import type { GroupedVuln } from '../../types'
import { deriveVulnListFacets, deriveVulnListFacetsFromTaskCounts } from '../vulnListFacets'
import { buildVulnListItems } from '../vulnListIndex'

const makeComponent = (componentName: string, overrides: Record<string, unknown> = {}) => ({
    project_name: 'Project',
    project_version: '1.0.0',
    project_uuid: 'project-uuid',
    component_name: componentName,
    component_version: '2.0.0',
    component_uuid: `component-${componentName}`,
    vulnerability_uuid: `vuln-${componentName}`,
    finding_uuid: `finding-${componentName}`,
    analysis_state: 'NOT_SET',
    analysis_details: '',
    is_suppressed: false,
    is_direct_dependency: true,
    ...overrides,
})

const makeGroup = (id: string, overrides: Partial<GroupedVuln> = {}): GroupedVuln => ({
    id,
    tags: ['Platform'],
    aliases: [],
    assignees: [],
    cvss_score: 5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    affected_versions: [
        {
            project_name: 'Project',
            project_uuid: 'project-uuid',
            project_version: '1.0.0',
            components: [makeComponent('core')],
        },
    ],
    ...overrides,
})

describe('vulnListFacets', () => {
    it('derives unique sorted values for list controls and search completions', () => {
        const items = buildVulnListItems([
            makeGroup('CVE-2026-0010', {
                aliases: ['GHSA-ZZZZ', ' GHSA-AAAA '],
                tags: ['Platform Alias', 'Platform'],
                assignees: ['Alice', 'Bob', ''],
                affected_versions: [
                    {
                        project_name: 'Project',
                        project_uuid: 'project-uuid',
                        project_version: '1.10.0',
                        components: [makeComponent('core'), makeComponent('api')],
                    },
                    {
                        project_name: 'Project',
                        project_uuid: 'project-uuid',
                        project_version: '1.2.0',
                        components: [makeComponent('core')],
                    },
                ],
            }),
            makeGroup('CVE-2026-0002', {
                aliases: ['GHSA-AAAA'],
                tags: ['Platform Alias', 'Backend'],
                assignees: ['Alice', 'Cara'],
                affected_versions: [
                    {
                        project_name: 'Project',
                        project_uuid: 'project-uuid',
                        project_version: '1.2.0',
                        components: [makeComponent('worker')],
                    },
                ],
            }),
        ], {
            backend: ['Platform', 'Platform Alias'],
        }, {})

        expect(deriveVulnListFacets(items)).toEqual({
            ids: ['CVE-2026-0002', 'CVE-2026-0010', 'GHSA-AAAA', 'GHSA-ZZZZ'],
            components: ['api', 'core', 'worker'],
            teams: ['Backend', 'Platform'],
            assignees: ['Alice', 'Bob', 'Cara'],
            availableVersions: ['1.2.0', '1.10.0'],
        })
    })

    it('derives task-wide facets from backend count maps', () => {
        expect(deriveVulnListFacetsFromTaskCounts({
            ids: {
                'CVE-2026-0100': 1,
                ' GHSA-BBBB ': 1,
                'CVE-2026-0002': 1,
            },
            components: {
                worker: 3,
                api: 1,
                core: 2,
            },
            tags: {
                Platform: 4,
                Backend: 2,
            },
            assignees: {
                Cara: 1,
                Alice: 2,
            },
            versions: {
                '1.10.0': 1,
                '1.2.0': 2,
            },
        })).toEqual({
            ids: ['CVE-2026-0002', 'CVE-2026-0100', 'GHSA-BBBB'],
            components: ['api', 'core', 'worker'],
            teams: ['Backend', 'Platform'],
            assignees: ['Alice', 'Cara'],
            availableVersions: ['1.2.0', '1.10.0'],
        })
    })
})
