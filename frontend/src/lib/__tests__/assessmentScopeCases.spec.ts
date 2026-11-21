import { describe, expect, it } from 'vitest'
import scopeCasesJson from './fixtures/assessment_scope_cases.json'
import {
    comparableAssessmentText,
    getGroupInconsistencyReasons,
    getGroupLifecycle,
    getGroupTechnicalState,
    getScopedAssessment,
} from '../assessment-helpers'
import { getAssessmentScopes } from '../assessmentScopes'

// fixtures/assessment_scope_cases.json is also read by the server's tests
// (tests/test_assessment_comparison.py): both sides must compare the findings
// of a vulnerability the same way. The file stays inside the frontend tree:
// the Docker image builds the frontend without the repository's tests/ folder.
interface ScopeCase {
    name: string
    tags: string[]
    instances: Array<Record<string, any>>
    inconsistency_reasons: string[]
    lifecycle: string
    technical_state: string
    scopes?: Array<{ name: string; lifecycle: string; override_gaps?: string[] }>
}
const scopeCases = scopeCasesJson as ScopeCase[]

const groupOf = (instances: ScopeCase['instances'], tags: string[]): any => ({
    id: 'CVE-CASE',
    tags,
    affected_versions: instances.map(instance => ({
        project_name: 'Project',
        project_version: instance.project_version,
        components: [{ component_name: 'library', tags, ...instance }],
    })),
})

describe('what the findings of a vulnerability must agree on', () => {
    it('has cases of each kind', () => {
        const lifecycles = new Set(scopeCases.map(scopeCase => scopeCase.lifecycle))
        for (const lifecycle of ['ASSESSED', 'INCONSISTENT', 'INCOMPLETE', 'NEEDS_APPROVAL']) {
            expect(lifecycles.has(lifecycle)).toBe(true)
        }
    })

    for (const scopeCase of scopeCases) {
        it(`compares as the server does: ${scopeCase.name}`, () => {
            const group = groupOf(scopeCase.instances, scopeCase.tags)

            expect(getGroupInconsistencyReasons(group)).toEqual(scopeCase.inconsistency_reasons)
            expect(getGroupLifecycle(group, scopeCase.tags)).toBe(scopeCase.lifecycle)
            expect(getGroupTechnicalState(group)).toBe(scopeCase.technical_state)
        })

        it(`does not depend on the order of the findings: ${scopeCase.name}`, () => {
            const group = groupOf([...scopeCase.instances].reverse(), scopeCase.tags)

            expect(getGroupLifecycle(group, scopeCase.tags)).toBe(scopeCase.lifecycle)
            expect(getGroupTechnicalState(group)).toBe(scopeCase.technical_state)
            expect([...getGroupInconsistencyReasons(group)].sort())
                .toEqual([...scopeCase.inconsistency_reasons].sort())
        })
    }

    for (const scopeCase of scopeCases.filter(item => item.scopes)) {
        it(`derives the scopes as the server does: ${scopeCase.name}`, () => {
            const group = groupOf(scopeCase.instances, scopeCase.tags)
            const scoped = getScopedAssessment(group, getAssessmentScopes(group), scopeCase.tags)

            expect(scoped.scopes.map(scope => scope.name)).toEqual(scopeCase.scopes!.map(scope => scope.name))
            for (const expected of scopeCase.scopes!) {
                const scope = scoped.scopes.find(item => item.name === expected.name)!
                expect(scope.lifecycle).toBe(expected.lifecycle)
                expect(scope.gaps).toEqual(expected.override_gaps || [])
            }
        })
    }

    it('finds no overrides in the cases without scopes', () => {
        for (const scopeCase of scopeCases.filter(item => !item.scopes)) {
            expect(getAssessmentScopes(groupOf(scopeCase.instances, scopeCase.tags)).hasOverrides).toBe(false)
        }
    })

    it('orders states of equal priority by name', () => {
        const states = ['ZULU', 'ALPHA', 'MIKE']
        for (const order of [states, [...states].reverse(), ['ALPHA', 'MIKE', 'ZULU']]) {
            const group = groupOf(order.map((state, index) => ({
                project_uuid: `project-${index}`, component_uuid: 'c', vulnerability_uuid: 'v',
                project_version: `${index}.0`, analysis_state: state, analysis_details: '',
            })), ['TeamB'])
            expect(getGroupTechnicalState(group)).toBe('ALPHA')
        }
    })

    it('leaves records and version coverage out of the compared text', () => {
        const current = '--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] '
            + '[Justification: CODE_NOT_PRESENT] [Version Coverage: 1.0, 2.0] ---\nNot shipped.'
        const record = '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: alice] '
            + '[Justification: NOT_SET] [Historical: yes] ---\nReachable.'

        expect(comparableAssessmentText(`${record}\n\n${current}\n\n[Status: Pending Review]`)).toBe(
            '--- [Team: TeamB] [State: NOT_AFFECTED] [Justification: CODE_NOT_PRESENT] --- Not shipped.',
        )
    })
})
