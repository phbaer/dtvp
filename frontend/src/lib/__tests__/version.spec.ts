import { describe, it, expect } from 'vitest'
import { compareVersions, sortVersions } from '../version'

describe('version helper', () => {
    describe('compareVersions', () => {
        it('should correctly compare simple versions', () => {
            expect(compareVersions('1.0.0', '1.0.1')).toBe(-1)
            expect(compareVersions('1.1.0', '1.0.1')).toBe(1)
            expect(compareVersions('1.0.0', '1.0.0')).toBe(0)
        })

        it('should handle different lengths', () => {
            expect(compareVersions('1.1', '1.1.1')).toBe(-1)
            expect(compareVersions('1.2.1', '1.2')).toBe(1)
        })

        it('should handle non-numeric parts gracefully', () => {
            expect(compareVersions('1.0.0-alpha', '1.0.0')).toBe(-1)
        })

        it('should handle "v" prefix', () => {
            expect(compareVersions('v1.0.0', '1.0.0')).toBe(0)
            expect(compareVersions('v1.2.3', 'v1.2.4')).toBe(-1)
        })

        it('should handle multiple digits', () => {
            expect(compareVersions('1.10.0', '1.2.0')).toBe(1)
        })
    })

    describe('sortVersions', () => {
        it('should sort versions descending by default', () => {
            const versions = ['1.0.0', '1.10.0', '1.2.0', 'v2.0.0']
            expect(sortVersions(versions)).toEqual(['v2.0.0', '1.10.0', '1.2.0', '1.0.0'])
        })

        it('should sort versions ascending when requested', () => {
            const versions = ['1.0.0', '1.10.0', '1.2.0']
            expect(sortVersions(versions, true)).toEqual(['1.0.0', '1.2.0', '1.10.0'])
        })
    })
})
