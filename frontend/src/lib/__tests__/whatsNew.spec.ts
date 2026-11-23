import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
    compareVersions,
    loadSeen,
    nextSeen,
    releasesSince,
    saveSeen,
    topEntries,
    upgradeSize,
    type Release,
} from '../whatsNew'

const release = (version: string | null, groups: Partial<Release['groups']> = {}): Release => ({
    version,
    date: '2026-11-23',
    prerelease: /rc\d+$/.test(version ?? ''),
    unreleased: version === null,
    groups: { breaking: [], new: [], faster: [], fixed: [], ...groups },
})
const entry = (text: string, extra: Partial<Release['groups']['new'][number]> = {}) => ({
    text, scope: null, pr: null, breaking: false, note: null, ...extra,
})

describe('versions', () => {
    it('orders pre-releases before their final version', () => {
        const sorted = ['2.0.0', '1.0.26', '2.0.0rc3', '2.0.0rc10', '2.0.1', '2.0.0b1']
            .sort(compareVersions)
        expect(sorted).toEqual(['1.0.26', '2.0.0b1', '2.0.0rc3', '2.0.0rc10', '2.0.0', '2.0.1'])
    })
})

describe('upgradeSize', () => {
    it('is a first visit when nothing was seen', () => {
        expect(upgradeSize(null, '2.0.0')).toBe('first')
    })

    it('is nothing for the same or an older version', () => {
        expect(upgradeSize({ version: '2.0.0', final: '2.0.0' }, '2.0.0')).toBe('none')
        expect(upgradeSize({ version: '2.0.1', final: '2.0.1' }, '2.0.0')).toBe('none')
    })

    it('sizes by the first number that grew', () => {
        expect(upgradeSize({ version: '1.0.26', final: '1.0.26' }, '2.0.0')).toBe('major')
        expect(upgradeSize({ version: '2.0.0', final: '2.0.0' }, '2.1.0')).toBe('minor')
        expect(upgradeSize({ version: '2.1.0', final: '2.1.0' }, '2.1.3')).toBe('patch')
    })

    it('sizes a pre-release against the last final version seen', () => {
        expect(upgradeSize({ version: '1.0.26', final: '1.0.26' }, '2.0.0rc4')).toBe('major')
        expect(upgradeSize({ version: '2.0.0rc3', final: '1.0.26' }, '2.0.0rc4')).toBe('major')
        expect(upgradeSize({ version: '2.0.0rc4', final: '1.0.26' }, '2.0.0')).toBe('major')
        // Without a final version known, the pre-release seen is the base.
        expect(upgradeSize({ version: '2.0.0rc3', final: null }, '2.0.0rc4')).toBe('patch')
    })

    it('keeps the last final version across pre-releases', () => {
        const seen = nextSeen({ version: '1.0.26', final: '1.0.26' }, '2.0.0rc3')
        expect(seen).toEqual({ version: '2.0.0rc3', final: '1.0.26' })
        expect(nextSeen(seen, '2.0.0')).toEqual({ version: '2.0.0', final: '2.0.0' })
        expect(nextSeen(null, '2.0.0rc1')).toEqual({ version: '2.0.0rc1', final: null })
    })
})

describe('what a user has seen', () => {
    beforeEach(() => {
        const store = new Map<string, string>()
        vi.stubGlobal('localStorage', {
            getItem: (key: string) => store.get(key) ?? null,
            setItem: (key: string, value: string) => store.set(key, value),
            removeItem: (key: string) => store.delete(key),
        })
    })

    it('is kept per user and starts from the browser-wide key of earlier versions', () => {
        localStorage.setItem('dtvp_last_seen_version', '1.0.26')
        expect(loadSeen('alice')).toEqual({ version: '1.0.26', final: '1.0.26' })

        saveSeen('alice', { version: '2.0.0', final: '2.0.0' })
        expect(loadSeen('alice')).toEqual({ version: '2.0.0', final: '2.0.0' })
        expect(loadSeen('bob')).toEqual({ version: '1.0.26', final: '1.0.26' })
    })

    it('is a first visit without any record', () => {
        expect(loadSeen('carol')).toBeNull()
    })
})

describe('releasesSince', () => {
    const releases = [
        release(null, { new: [entry('Unreleased thing')] }),
        release('2.0.1', { fixed: [entry('Later fix')] }),
        release('2.0.0', { new: [entry('Two')] }),
        release('2.0.0rc3', { breaking: [entry('No polling', { breaking: true })] }),
        release('2.0.0rc2'),
        release('1.0.26', { fixed: [entry('Old fix')] }),
    ]

    it('lists the releases after the seen one up to the running one, newest first', () => {
        expect(releasesSince(releases, '1.0.26', '2.0.0').map(r => r.version)).toEqual(['2.0.0', '2.0.0rc3'])
    })

    it('leaves out unreleased and empty releases', () => {
        expect(releasesSince(releases, '2.0.0rc1', '2.0.1').map(r => r.version)).toEqual([
            '2.0.1', '2.0.0', '2.0.0rc3',
        ])
    })

    it('puts what needs action first', () => {
        const top = topEntries(releasesSince(releases, '1.0.26', '2.0.1'), 2)
        expect(top.map(e => [e.text, e.version])).toEqual([['No polling', '2.0.0rc3'], ['Two', '2.0.0']])
    })
})
