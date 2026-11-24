import { describe, expect, it } from 'vitest'
import {
    buildTeamAliasGroups,
    findTeamMappingMatch,
    getPrimaryTeamForComponent,
    getTeamMappingTags,
    parseTeamMappingKey,
    resolveCanonicalTeamName,
} from '../team-mapping'

describe('team mapping selectors', () => {
    it('groups configured aliases under their canonical team', () => {
        expect(buildTeamAliasGroups({
            componentA: ['Platform Security', 'Platform', 'Platform Sec'],
            componentB: ['Platform Security', 'Platform'],
            componentC: 'Runtime',
        })).toEqual({
            'Platform Security': ['Platform', 'Platform Sec'],
            Runtime: [],
        })
    })

    it('parses case-sensitive and no-group selector prefixes', () => {
        expect(parseTeamMappingKey('cs,nogroup::Core')).toMatchObject({
            name: 'Core',
            requireNoGroup: true,
            caseSensitive: true,
            wildcard: false,
        })
    })

    it('matches plain names case-insensitively with deterministic exact-case preference', () => {
        const match = findTeamMappingMatch(
            { core: 'LowerTeam', Core: 'ExactTeam' },
            { name: 'Core', groupKnown: true },
        )

        expect(match?.key).toBe('Core')
        expect(match?.tags).toEqual(['ExactTeam'])
    })

    it('requires exact case for cs selectors', () => {
        const mapping = { 'cs::Core': 'ExactTeam' }

        expect(getPrimaryTeamForComponent('core', mapping, null, true)).toBe('')
        expect(getPrimaryTeamForComponent('Core', mapping, null, true)).toBe('ExactTeam')
    })

    it('matches group-qualified selectors only when group is known', () => {
        const mapping = { '@angular:core': 'FrontendTeam', core: 'NativeTeam' }

        expect(getPrimaryTeamForComponent('core', mapping, '@angular', true)).toBe('FrontendTeam')
        expect(getPrimaryTeamForComponent('core', mapping, null, true)).toBe('NativeTeam')
        expect(getPrimaryTeamForComponent('core', mapping, '@angular', false)).toBe('NativeTeam')
    })

    it('matches scoped package keys against BOM group and name', () => {
        const mapping = {
            '@gehc/nest-back-pack': 'TeamB',
            'nest-back-pack': 'OtherTeam',
        }

        expect(parseTeamMappingKey('@gehc/nest-back-pack')).toMatchObject({
            group: '@gehc', name: 'nest-back-pack',
        })
        expect(getPrimaryTeamForComponent('nest-back-pack', mapping, '@gehc', true)).toBe('TeamB')
        expect(getPrimaryTeamForComponent('nest-back-pack', mapping, null, true)).toBe('OtherTeam')
    })

    it('requires known empty group for nogroup selectors', () => {
        const mapping = { 'nogroup::core': 'NoGroupTeam', '*': 'Fallback' }

        expect(getTeamMappingTags(mapping, { name: 'core', groupKnown: true })).toEqual(['NoGroupTeam'])
        expect(getTeamMappingTags(mapping, { name: 'core', groupKnown: false })).toEqual([])
        expect(getTeamMappingTags(mapping, { name: 'core', groupKnown: false }, true)).toEqual(['Fallback'])
        expect(getTeamMappingTags(mapping, { name: 'core', group: '@angular', groupKnown: true }, true)).toEqual(['Fallback'])
    })

    it('treats cs and nogroup as ordinary groups with single-colon keys', () => {
        const mapping = {
            'cs:core': 'CaseGroupTeam',
            'nogroup:core': 'NamedNoGroupTeam',
        }

        expect(getPrimaryTeamForComponent('core', mapping, 'cs', true)).toBe('CaseGroupTeam')
        expect(getPrimaryTeamForComponent('core', mapping, 'nogroup', true)).toBe('NamedNoGroupTeam')
    })

    it('matches purl selectors against versioned component purls', () => {
        const mapping = {
            'purl::pkg:maven/org.example/core': 'PurlTeam',
        }

        expect(
            getTeamMappingTags(
                mapping,
                {
                    name: 'core',
                    purl: 'pkg:maven/org.example/core@1.2.3',
                    groupKnown: true,
                },
            ),
        ).toEqual(['PurlTeam'])
    })

    it('lets purl selectors request an exact version', () => {
        const mapping = {
            'purl::pkg:maven/org.example/core@1.2.3': 'ExactTeam',
        }

        expect(
            getTeamMappingTags(
                mapping,
                { name: 'core', purl: 'pkg:maven/org.example/core@9.9.9' },
            ),
        ).toEqual([])
        expect(
            getTeamMappingTags(
                mapping,
                { name: 'core', purl: 'pkg:maven/org.example/core@1.2.3' },
            ),
        ).toEqual(['ExactTeam'])
    })

    it('prefers purl selectors over group and name selectors', () => {
        const mapping = {
            core: 'NameTeam',
            '@angular:core': 'GroupTeam',
            'purl::pkg:maven/org.example/core': 'PurlTeam',
        }

        expect(
            getTeamMappingTags(
                mapping,
                {
                    name: 'core',
                    group: '@angular',
                    purl: 'pkg:maven/org.example/core@1.2.3',
                    groupKnown: true,
                },
            ),
        ).toEqual(['PurlTeam'])
    })

    it('compiles a mapping only once across repeated component lookups', () => {
        let ownKeysCalls = 0
        const mapping = new Proxy({
            core: ['CoreTeam', 'core alias'],
            worker: 'RuntimeTeam',
        }, {
            ownKeys(target) {
                ownKeysCalls += 1
                return Reflect.ownKeys(target)
            },
        })

        expect(getPrimaryTeamForComponent('core', mapping, null, true)).toBe('CoreTeam')
        expect(getPrimaryTeamForComponent('worker', mapping, null, true)).toBe('RuntimeTeam')
        expect(getPrimaryTeamForComponent('core', mapping, null, true)).toBe('CoreTeam')
        expect(resolveCanonicalTeamName(mapping, 'core alias')).toBe('CoreTeam')
        expect(ownKeysCalls).toBe(1)
    })

    it('matches by the package name the purl names when the own name matches nothing', () => {
        const mapping = {
            'vp-stats-app': 'Core',
            'org.keycloak:keycloak-core': 'Identity',
            '@scope/widget': 'Web',
            '*': 'Unknown',
        }
        const tags = (name: string, purl: string | null, includeWildcard = true) =>
            getTeamMappingTags(mapping, { name, purl, groupKnown: true }, includeWildcard)

        expect(tags('stats-app', 'pkg:npm/vp-stats-app@0.1.2')).toEqual(['Core'])
        expect(tags('Keycloak Core', 'pkg:maven/org.keycloak/keycloak-core@26.0.5?type=jar')).toEqual(['Identity'])
        expect(tags('widget-ui', 'pkg:npm/%40scope/widget@1.0.0')).toEqual(['Web'])
        expect(tags('x', 'pkg:maven/org.other/vp-stats-app@1')).toEqual(['Unknown'])
        expect(tags('stats-app', null)).toEqual(['Unknown'])
        expect(tags('stats-app', 'pkg:npm/other@1', false)).toEqual([])
    })

    it('prefers the own name over the package name', () => {
        expect(getTeamMappingTags(
            { 'stats-app': 'Phoenix', 'vp-stats-app': 'Core' },
            { name: 'stats-app', purl: 'pkg:npm/vp-stats-app@0.1.2', groupKnown: true },
        )).toEqual(['Phoenix'])
    })
})

