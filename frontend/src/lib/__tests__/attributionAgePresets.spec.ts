import { afterEach, describe, expect, it } from 'vitest'
import {
    DEFAULT_ATTRIBUTION_AGE_FILTER_DAYS,
    getAttributionAgeFilterDays,
    parseAttributionAgeFilterDays,
} from '../attributionAgePresets'

describe('attributionAgePresets', () => {
    afterEach(() => {
        delete (window as any).__env__
    })

    it('parses comma-separated days with optional d suffixes', () => {
        expect(parseAttributionAgeFilterDays('5d, 10, 21D')).toEqual([5, 10, 21])
    })

    it('ignores invalid, zero, and duplicate values', () => {
        expect(parseAttributionAgeFilterDays('0, nope, 14d, 14, -3, 28d')).toEqual([14, 28])
    })

    it('falls back to the default presets when no valid days are configured', () => {
        expect(parseAttributionAgeFilterDays('nope, 0')).toEqual(DEFAULT_ATTRIBUTION_AGE_FILTER_DAYS)
    })

    it('reads runtime config for attribution age presets', () => {
        ;(window as any).__env__ = { DTVP_ATTRIBUTION_AGE_FILTER_DAYS: '3d, 9d' }

        expect(getAttributionAgeFilterDays()).toEqual([3, 9])
    })
})
