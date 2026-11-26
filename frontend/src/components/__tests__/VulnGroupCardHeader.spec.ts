import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import VulnGroupCardHeader from '../VulnGroupCardHeader.vue'

const mountHeader = (displayState: string, affected_versions: any[] = []) => mount(VulnGroupCardHeader, {
    props: {
        group: {
            id: 'CVE-TEST', tags: ['Team A', 'Team B'], affected_versions,
            list_metadata: { lifecycle: displayState, assessed_teams: ['Team A'] },
        },
        displayState, technicalState: 'NOT_AFFECTED',
        normalizedTags: ['Team A', 'Team B'], assessedTeams: new Set(['Team A']),
        expanded: false, canApprove: false, isPendingReview: false,
        dependencyRelationship: 'UNKNOWN',
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

describe('new findings', () => {
    it('counts findings added after the assessment and names their version', () => {
        const wrapper = mountHeader('INCOMPLETE', [
            { project_version: '7.1.0', components: [{ component_name: 'ffmpeg', component_version: '7.1.1' }] },
            {
                project_version: '7.1.2',
                components: [{
                    component_name: 'ffmpeg', component_version: '7.1.1',
                    is_new_finding: true, attributed_on: Date.UTC(2026, 10, 18),
                }],
            },
        ])
        const chip = wrapper.get('[data-testid="new-findings-chip"]')
        expect(chip.text()).toBe('1 new')
        expect(chip.attributes('title')).toContain('version 7.1.2')
        expect(chip.attributes('title')).toContain('first reported 2026-11-18')
        wrapper.unmount()
    })

    it('shows nothing when no finding is new', () => {
        const wrapper = mountHeader('INCOMPLETE', [
            { project_version: '7.1.0', components: [{ component_name: 'ffmpeg', component_version: '7.1.1' }] },
        ])
        expect(wrapper.find('[data-testid="new-findings-chip"]').exists()).toBe(false)
        wrapper.unmount()
    })
})
