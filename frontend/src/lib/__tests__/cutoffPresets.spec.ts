import { afterEach, describe, expect, it } from 'vitest'
import {
    DEFAULT_CUTOFF_PRESET_DAYS,
    getCutoffPresetDays,
    parseCutoffPresetDays,
} from '../cutoffPresets'

describe('cutoffPresets', () => {
    afterEach(() => {
        delete (window as any).__env__
    })

    it('parses comma-separated days with optional d suffixes', () => {
        expect(parseCutoffPresetDays('5d, 10, 21D')).toEqual([5, 10, 21])
    })

    it('ignores invalid, zero, and duplicate values', () => {
        expect(parseCutoffPresetDays('0, nope, 14d, 14, -3, 28d')).toEqual([14, 28])
    })

    it('falls back to the default presets when no valid days are configured', () => {
        expect(parseCutoffPresetDays('nope, 0')).toEqual(DEFAULT_CUTOFF_PRESET_DAYS)
    })

    it('reads runtime config for attribution age presets', () => {
        ;(window as any).__env__ = { DTVP_CUTOFF_PRESET_DAYS: '3d, 9d' }

        expect(getCutoffPresetDays()).toEqual([3, 9])
    })
})
