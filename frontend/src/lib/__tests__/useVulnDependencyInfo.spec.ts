import { computed, ref } from 'vue'
import { describe, expect, it } from 'vitest'
import { useVulnDependencyInfo } from '../useVulnDependencyInfo'
import type { GroupedVuln } from '../../types'

describe('useVulnDependencyInfo', () => {
    const createGroup = (): GroupedVuln => ({
        id: 'CVE-1234-5678',
        tags: ['legacy-team'],
        affected_versions: [
            {
                project_name: 'Example',
                project_version: '2.0.0',
                project_uuid: 'project-2',
                components: [
                    {
                        project_name: 'Example',
                        project_version: '2.0.0',
                        project_uuid: 'project-2',
                        component_name: 'log4j-core',
                        component_version: '2.17.0',
                        component_uuid: 'component-2',
                        vulnerability_uuid: 'vuln-2',
                        finding_uuid: 'finding-2',
                        analysis_state: 'NOT_SET',
                        is_suppressed: false,
                        is_direct_dependency: true,
                        dependency_chains: ['log4j-core -> service-a -> Example'],
                    },
                ],
            },
            {
                project_name: 'Example',
                project_version: '1.5.0',
                project_uuid: 'project-1',
                components: [
                    {
                        project_name: 'Example',
                        project_version: '1.5.0',
                        project_uuid: 'project-1',
                        component_name: 'slf4j-api',
                        component_version: '1.7.36',
                        component_uuid: 'component-1',
                        vulnerability_uuid: 'vuln-1',
                        finding_uuid: 'finding-1',
                        analysis_state: 'NOT_SET',
                        is_suppressed: false,
                        is_direct_dependency: false,
                        dependency_chains: ['slf4j-api -> shared-lib -> Example'],
                    },
                ],
            },
        ],
    })

    it('derives effective tags, dependency relationship, and sorted versions', () => {
        const group = ref(createGroup())
        const teamMapping = ref<Record<string, string | string[]>>({
            'log4j-core': ['TEAM-DIRECT'],
            'shared-lib': ['TEAM-SHARED'],
        })

        const info = useVulnDependencyInfo({
            group: computed(() => group.value),
            teamMapping,
            refreshCounter: ref(0),
        })

        expect(info.effectiveTags.value).toEqual(['TEAM-DIRECT', 'TEAM-SHARED'])
        expect(info.dependencyRelationship.value).toBe('DIRECT')
        expect(info.sortedAffectedProjectVersions.value).toEqual(['1.5.0', '2.0.0'])
        expect(info.normalizedTags.value).toEqual(['TEAM-DIRECT', 'TEAM-SHARED'])
    })

    it('builds tagged component summaries from direct mappings and dependency paths', () => {
        const group = ref(createGroup())
        const teamMapping = ref<Record<string, string | string[]>>({
            'log4j-core': ['TEAM-DIRECT'],
            'shared-lib': ['TEAM-SHARED'],
        })

        const info = useVulnDependencyInfo({
            group: computed(() => group.value),
            teamMapping,
            refreshCounter: ref(0),
        })

        expect(info.instanceTeams.value.get('finding-2')).toEqual(['TEAM-DIRECT'])
        expect(info.instanceTeams.value.get('finding-1')).toEqual(['TEAM-SHARED'])

        expect(info.affectedTaggedComponents.value).toEqual([
            {
                name: 'log4j-core',
                versions: ['2.17.0'],
                tag: 'TEAM-DIRECT',
            },
        ])

        expect(info.triggeringTaggedComponents.value).toEqual([
            {
                name: 'log4j-core',
                versions: ['2.17.0'],
                tag: 'TEAM-DIRECT',
            },
            {
                name: 'shared-lib',
                versions: [],
                tag: 'TEAM-SHARED',
            },
        ])

        expect(info.uniqueComponents.value).toEqual([
            {
                name: 'log4j-core',
                versions: ['2.17.0'],
            },
            {
                name: 'slf4j-api',
                versions: ['1.7.36'],
            },
        ])
    })
})