import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { GroupedVuln } from '../../types'

const helpers = vi.hoisted(() => ({
    getGroupLifecycle: vi.fn(),
    isPendingReview: vi.fn(),
    hasOpenTeamAssessment: vi.fn(),
    getGroupTechnicalState: vi.fn(),
    normalizeTags: vi.fn(),
    matchesFilters: vi.fn(),
}))

vi.mock('../assessment-helpers', () => helpers)

import {
    classifyGroup,
    computeFilterCounts,
    computeTeamCounts,
    getGroupTechnicalState,
    matchesFilters,
    normalizeTags,
} from '../group-classifier'

type ClassifiableGroup = GroupedVuln & {
    lifecycle: string
    pending?: boolean
    openTeam?: boolean
    technicalState: string
}

function group(
    id: string,
    lifecycle: string,
    technicalState: string,
    options: { tags?: string[]; pending?: boolean; openTeam?: boolean } = {},
): ClassifiableGroup {
    return {
        id,
        lifecycle,
        technicalState,
        pending: options.pending ?? false,
        openTeam: options.openTeam ?? false,
        tags: options.tags,
        affected_versions: [],
    } as unknown as ClassifiableGroup
}

describe('group-classifier', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        helpers.getGroupLifecycle.mockImplementation((item: ClassifiableGroup) => item.lifecycle)
        helpers.isPendingReview.mockImplementation((item: ClassifiableGroup) => item.pending ?? false)
        helpers.hasOpenTeamAssessment.mockImplementation((item: ClassifiableGroup) => item.openTeam ?? false)
        helpers.getGroupTechnicalState.mockImplementation((item: ClassifiableGroup) => item.technicalState)
        helpers.normalizeTags.mockImplementation((tags: string[]) => tags)
    })

    it.each([
        ['open lifecycle', group('open', 'OPEN', 'NOT_SET'), true],
        ['assessed lifecycle', group('assessed', 'ASSESSED', 'RESOLVED'), false],
        [
            'pending review with open team work',
            group('pending-open', 'ASSESSED', 'IN_TRIAGE', { pending: true, openTeam: true }),
            true,
        ],
        [
            'pending review with completed team work',
            group('pending-assessed', 'ASSESSED', 'RESOLVED', { pending: true }),
            false,
        ],
    ])('classifies %s consistently', (_label, item, expectedOpen) => {
        const mapping = { component: ['Primary', 'Alias'] }

        expect(classifyGroup(item, mapping)).toEqual({
            lifecycle: item.lifecycle,
            isPending: item.pending ?? false,
            isOpen: expectedOpen,
            technicalState: item.technicalState,
        })
        expect(helpers.getGroupLifecycle).toHaveBeenCalledWith(item, item.tags ?? [], mapping)
        expect(helpers.hasOpenTeamAssessment).toHaveBeenCalledTimes(item.pending ? 1 : 0)
    })

    it('counts every lifecycle, pending review, and technical state without active filters', () => {
        const groups = [
            group('open', 'OPEN', 'NOT_SET'),
            group('assessed', 'ASSESSED', 'EXPLOITABLE'),
            group('legacy', 'ASSESSED_LEGACY', 'IN_TRIAGE'),
            group('incomplete', 'INCOMPLETE', 'RESOLVED'),
            group('inconsistent', 'INCONSISTENT', 'FALSE_POSITIVE'),
            group('pending', 'OPEN', 'NOT_AFFECTED', { pending: true }),
        ]

        expect(computeFilterCounts(groups, {}, [])).toEqual({
            OPEN: 2,
            ASSESSED: 1,
            ASSESSED_LEGACY: 1,
            INCOMPLETE: 1,
            INCONSISTENT: 1,
            NOT_SET: 1,
            EXPLOITABLE: 1,
            IN_TRIAGE: 1,
            RESOLVED: 1,
            FALSE_POSITIVE: 1,
            NOT_AFFECTED: 1,
            NEEDS_APPROVAL: 1,
        })
    })

    it('scopes technical counts to matching lifecycle and pending-review filters', () => {
        const groups = [
            group('open', 'OPEN', 'NOT_SET'),
            group('assessed', 'ASSESSED', 'RESOLVED'),
            group('pending', 'INCOMPLETE', 'IN_TRIAGE', { pending: true }),
        ]

        const assessed = computeFilterCounts(groups, {}, ['ASSESSED'])
        expect(assessed.RESOLVED).toBe(1)
        expect(assessed.NOT_SET).toBe(0)
        expect(assessed.IN_TRIAGE).toBe(0)

        const pending = computeFilterCounts(groups, {}, ['NEEDS_APPROVAL'])
        expect(pending.IN_TRIAGE).toBe(1)
        expect(pending.NOT_SET).toBe(0)
        expect(pending.RESOLVED).toBe(0)

        const combined = computeFilterCounts(groups, {}, ['OPEN', 'NEEDS_APPROVAL'])
        expect(combined.NOT_SET).toBe(1)
        expect(combined.IN_TRIAGE).toBe(1)
    })

    it('counts normalized teams once per group and skips unowned groups', () => {
        helpers.normalizeTags.mockImplementation((tags: string[]) =>
            tags.map(tag => tag === 'Alias' ? 'Primary' : tag),
        )
        const groups = [
            group('open', 'OPEN', 'NOT_SET', { tags: ['Alias', 'Security'] }),
            group('assessed', 'ASSESSED', 'RESOLVED', { tags: ['Primary'] }),
            group('pending-open', 'ASSESSED', 'IN_TRIAGE', {
                tags: ['Security'],
                pending: true,
                openTeam: true,
            }),
            group('unowned', 'OPEN', 'NOT_SET'),
        ]

        expect(computeTeamCounts(groups, { component: ['Primary', 'Alias'] })).toEqual({
            Primary: { open: 1, assessed: 1 },
            Security: { open: 2, assessed: 0 },
        })
        expect(helpers.getGroupLifecycle).toHaveBeenCalledTimes(3)
    })

    it('re-exports the shared filtering and normalization helpers', () => {
        expect(matchesFilters).toBe(helpers.matchesFilters)
        expect(normalizeTags).toBe(helpers.normalizeTags)
        expect(getGroupTechnicalState).toBe(helpers.getGroupTechnicalState)
    })
})
