import { describe, expect, it } from 'vitest'
import lifecycleCasesJson from './fixtures/lifecycle_cases.json'
import stateOrder from './fixtures/state_order.json'
import { getGroupGlobalDecision, getGroupInconsistencyReasons, getGroupLifecycle, STATE_PRIORITY } from '../assessment-helpers'
import { classifyGroup } from '../group-classifier'
import { getApprovalUnavailableReason, getGroupAssessmentSyncIssues } from '../assessmentSyncIssues'

// The lifecycle decision table (docs/assessment-model.md#lifecycle-decision-table).
// fixtures/lifecycle_cases.json is also read by the server's tests
// (tests/test_lifecycle_decision_table.py): the card classifies a
// vulnerability as the server's list does.
interface LifecycleCase {
    name: string
    rule: string
    tags: string[]
    team_mapping?: Record<string, string | string[]>
    instances: Array<Record<string, any>>
    lifecycle: string
    is_pending: boolean
    is_approval_ready: boolean
    approvable: boolean
    covers_all_teams: boolean
    global_decision: {
        source: string; state: string; justification: string; teams: string[]
        derived_state: string; derived_teams: string[]
    }
    inconsistency_reasons: string[]
}
const cases = lifecycleCasesJson as LifecycleCase[]

const groupOf = (lifecycleCase: LifecycleCase): any => ({
    id: 'CVE-CASE',
    tags: lifecycleCase.tags,
    affected_versions: lifecycleCase.instances.map(instance => ({
        project_name: 'Project',
        project_version: instance.project_version,
        components: [{ component_name: 'library', tags: lifecycleCase.tags, ...instance }],
    })),
})

const caseNamed = (name: string) => cases.find(item => item.name === name)!

describe('the lifecycle decision table', () => {
    it('has a case for every rule', () => {
        expect(new Set(cases.map(item => item.rule))).toEqual(
            new Set(['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'R11']),
        )
    })

    for (const lifecycleCase of cases) {
        it(`classifies as the server does: ${lifecycleCase.name}`, () => {
            const group = groupOf(lifecycleCase)
            const mapping = lifecycleCase.team_mapping || {}
            const classification = classifyGroup(group, mapping)

            expect(getGroupLifecycle(group, lifecycleCase.tags, mapping)).toBe(lifecycleCase.lifecycle)
            expect(classification.lifecycle).toBe(lifecycleCase.lifecycle)
            expect(classification.isPending).toBe(lifecycleCase.is_pending)
            expect(classification.isApprovalReady).toBe(lifecycleCase.is_approval_ready)
            expect(getGroupInconsistencyReasons(group)).toEqual(lifecycleCase.inconsistency_reasons)
            expect(classification.coversAllTeams).toBe(lifecycleCase.covers_all_teams)
            // Approve is offered exactly when the server accepts it.
            const reason = getApprovalUnavailableReason(group, { requiredTeamsOrTags: lifecycleCase.tags, teamMapping: mapping })
            expect(reason === '').toBe(lifecycleCase.approvable || !lifecycleCase.is_pending)
            const decision = getGroupGlobalDecision(group)
            const expected = lifecycleCase.global_decision
            expect({
                source: decision.source, state: decision.state,
                justification: decision.justification, teams: decision.teams,
                derived_state: decision.derived?.state || 'NOT_SET', derived_teams: decision.derived?.teams || [],
            }).toEqual(expected)
        })
    }

    it('uses the one worst-state order', () => {
        const order = Object.keys(STATE_PRIORITY).sort((left, right) => STATE_PRIORITY[left]! - STATE_PRIORITY[right]!)
        expect(order).toEqual(stateOrder)
    })

    it('says that approving the Global assessment completes a group it covers', () => {
        const group = groupOf(caseNamed('pending global decision covers a team without its own assessment'))

        expect(getGroupAssessmentSyncIssues(group, { requiredTeamsOrTags: group.tags })).toEqual([{
            code: 'GLOBAL_AWAITS_APPROVAL',
            kind: 'approval',
            label: 'Covered by the pending Global assessment',
            detail: 'No assessment of their own for TeamB. Approve the Global assessment to complete it.',
        }])
    })

    it('says nothing extra for a group whose every team has assessed', () => {
        const group = groupOf(caseNamed('pending, every team assessed'))

        expect(getGroupAssessmentSyncIssues(group, { requiredTeamsOrTags: group.tags })).toEqual([])
    })

    it('names the pending Global assessment for teams of an incomplete group', () => {
        const group = groupOf(caseNamed('pending global decision, a team without a block and a finding without a state'))
        const [teams, findings] = getGroupAssessmentSyncIssues(group, { requiredTeamsOrTags: group.tags })

        expect(teams!.detail).toBe(
            'No assessment of their own for TeamB; the pending Global assessment covers them once approved.',
        )
        expect(findings!.code).toBe('UNASSESSED_FINDINGS')
    })

    it('keeps the plain reason when no General block decides', () => {
        const group = groupOf(caseNamed('pending, a team without a block and a General block without a decision'))
        const [teams] = getGroupAssessmentSyncIssues(group, { requiredTeamsOrTags: group.tags })

        expect(teams!.detail).toBe('No completed assessment for TeamB.')
    })
})
