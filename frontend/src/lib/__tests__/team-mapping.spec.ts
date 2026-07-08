import { describe, expect, it } from 'vitest'
import {
    findTeamMappingMatch,
    getPrimaryTeamForComponent,
    getTeamMappingTags,
    parseTeamMappingKey,
} from '../team-mapping'

describe('team mapping selectors', () => {
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
})
