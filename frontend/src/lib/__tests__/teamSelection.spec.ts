import { describe, expect, it } from 'vitest'
import { resolveTeamTerm } from '../teamSelection'

describe('explicit team selection', () => {
    const teams = ['Security', 'Security Operations', 'Platform', 'Sec']
    const aliases = { Security: ['Sec'] }
    it('prefers exact names and canonicalizes aliases', () => {
        expect(resolveTeamTerm('SECURITY', teams, aliases).resolved).toBe('Security')
        expect(resolveTeamTerm('sec', teams, aliases).matches).toEqual(['Security'])
        expect(resolveTeamTerm('operat', teams, aliases).resolved).toBe('Security Operations')
    })
    it('requires a choice for ambiguous partial names', () => {
        expect(resolveTeamTerm('secur', teams, aliases)).toEqual({ resolved: null, matches: ['Security', 'Security Operations'] })
        expect(resolveTeamTerm('unknown', teams, aliases)).toEqual({ resolved: null, matches: [] })
        expect(resolveTeamTerm('', teams, aliases).matches).toEqual(['Platform', 'Security', 'Security Operations'])
    })
})
