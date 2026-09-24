import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import VulnGroupCardHeader from '../VulnGroupCardHeader.vue'

const mountHeader = (displayState: string) => mount(VulnGroupCardHeader, {
    props: {
        group: {
            id: 'CVE-TEST', tags: ['Team A', 'Team B'], affected_versions: [],
            list_metadata: { lifecycle: displayState, assessed_teams: ['Team A'] },
        },
        displayState, technicalState: 'NOT_AFFECTED',
        isRescoredOrModified: false, currentDisplayScore: 5, pendingScore: null,
        stableRescoredScore: null, hasStableRescore: false,
        normalizedTags: ['Team A', 'Team B'], assessedTeams: new Set(['Team A']),
        expanded: false, canApprove: false, isPendingReview: false,
        dependencyRelationship: 'UNKNOWN', assignees: [],
    },
})

describe('lifecycle presentation', () => {
    it.each([
        ['OPEN', 'Open'], ['INCOMPLETE', 'Incomplete'],
        ['INCONSISTENT', 'Conflicting'], ['NEEDS_APPROVAL', 'Ready for approval'],
        ['ASSESSED', 'Assessed'], ['ASSESSED_LEGACY', 'Assessed'],
    ])('labels %s as %s', (state, label) => {
        const wrapper = mountHeader(state)
        expect(wrapper.get('[data-testid="lifecycle-badge"]').text()).toBe(label)
        expect(wrapper.find('[data-testid="legacy-assessment-badge"]').exists()).toBe(state === 'ASSESSED_LEGACY')
        wrapper.unmount()
    })

    it('explains missing teams from summary metadata without claiming General is required', () => {
        const wrapper = mountHeader('INCOMPLETE')
        expect(wrapper.find('[data-testid="team-coverage-context"]').exists()).toBe(false)
        const title = wrapper.get('[data-testid="lifecycle-badge"]').attributes('title')
        expect(title).toContain('No completed assessment for Team B.')
        expect(title).not.toContain('Team A')
        expect(title).not.toContain('General')
        wrapper.unmount()
    })
})
