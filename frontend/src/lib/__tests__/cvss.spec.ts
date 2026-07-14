import { describe, expect, it } from 'vitest'
import { Cvss3P0 } from 'ae-cvss-calculator'
import { calculateScoreFromVector } from '../cvss'

describe('calculateScoreFromVector', () => {
    it('uses the CVSS 3.0 calculator for CVSS 3.0 vectors', () => {
        const vector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L/MC:N/MI:N/MA:N'
        const expected = new Cvss3P0(vector).calculateScores(false).overall

        expect(calculateScoreFromVector(vector)).toBe(Number(expected.toFixed(1)))
    })
})
