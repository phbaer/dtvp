import { describe, expect, it } from 'vitest'
import { componentLabel } from '../goneFindings'
import type { GoneFinding } from '../../types'

const finding = (overrides: Partial<GoneFinding>) => ({
    component_uuid: 'c157b606-8add-41fe-8d9d-56b78a36f92e',
    component_name: null,
    component_version: null,
    ...overrides,
}) as GoneFinding

describe('componentLabel', () => {
    it('names the component and its version', () => {
        expect(componentLabel(finding({ component_name: 'lib-a', component_version: '1.0' }))).toBe('lib-a@1.0')
        expect(componentLabel(finding({ component_name: 'lib-a' }))).toBe('lib-a')
    })

    it('says a component known only by its UUID is unknown', () => {
        expect(componentLabel(finding({}))).toBe('Unknown component (c157b606)')
    })
})
