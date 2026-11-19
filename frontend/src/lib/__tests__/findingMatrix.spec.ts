import { describe, expect, it } from 'vitest'
import { buildFindingMatrix, compareVariants } from '../findingMatrix'

const finding = (overrides: Record<string, unknown> = {}) => ({
    project_version: '1.0',
    component_name: 'lib',
    component_version: '2.0',
    analysis_state: 'NOT_SET',
    analysis_details: '',
    is_suppressed: false,
    ...overrides,
})

const block = (team: string, state: string, body: string, extra = '') =>
    `--- [Team: ${team}] [State: ${state}] [Assessed By: ana]${extra} ---\n${body}`

describe('buildFindingMatrix', () => {
    it('lays findings out as components by project versions', () => {
        const matrix = buildFindingMatrix([
            finding({ project_version: '10.0' }),
            finding({ project_version: '2.0' }),
            finding({ project_version: '2.0', component_name: 'zlib', component_version: '1.3' }),
        ])

        expect(matrix.versions).toEqual(['2.0', '10.0'])
        expect(matrix.rows.map(row => [row.name, row.version])).toEqual([['lib', '2.0'], ['zlib', '1.3']])
        expect(matrix.rows[1]!.cells['10.0']).toBeUndefined()
        expect(matrix.rows[1]!.cells['2.0']!.state).toBe('NOT_SET')
        expect(matrix.variants).toHaveLength(1)
        expect(matrix.differingCount).toBe(0)
        expect(matrix.total).toBe(3)
    })

    it('names the component version per cell when it changes between project versions', () => {
        const matrix = buildFindingMatrix([
            finding({ project_version: '1.0', component_version: '2.0' }),
            finding({ project_version: '2.0', component_version: '2.1' }),
        ])

        expect(matrix.rows[0]!.version).toBe('')
        expect(matrix.rows[0]!.cells['2.0']!.componentVersions).toEqual(['2.1'])
    })

    it('labels the assessments by how common they are and marks the findings that differ', () => {
        const common = block('General', 'NOT_AFFECTED', 'Not shipped.')
        const matrix = buildFindingMatrix([
            finding({ project_version: '1.0', analysis_state: 'EXPLOITABLE', analysis_details: block('General', 'EXPLOITABLE', 'Reachable.') }),
            finding({ project_version: '2.0', analysis_state: 'NOT_AFFECTED', analysis_details: common }),
            // The same assessment with other white space is not a difference.
            finding({ project_version: '3.0', analysis_state: 'NOT_AFFECTED', analysis_details: common.replace('\n', '\n\n') }),
            finding({ project_version: '4.0', is_new_finding: true }),
        ])

        expect(matrix.variants.map(variant => [variant.label, variant.state, variant.instances.length]))
            .toEqual([['A', 'NOT_AFFECTED', 2], ['B', 'EXPLOITABLE', 1], ['C', 'NOT_SET', 1]])
        expect(matrix.differingCount).toBe(2)
        const cells = matrix.rows[0]!.cells
        expect([cells['1.0']!.differs, cells['2.0']!.differs, cells['3.0']!.differs, cells['4.0']!.differs])
            .toEqual([true, false, false, true])
        expect(cells['1.0']!.variantLabels).toEqual(['B'])
        expect(cells['4.0']!.isNew).toBe(true)
    })

    it('shows the worst state when one cell holds several findings', () => {
        const matrix = buildFindingMatrix([
            finding({ component_version: '2.0', analysis_state: 'NOT_AFFECTED', analysis_details: 'a' }),
            finding({ component_version: '2.1', analysis_state: 'EXPLOITABLE', analysis_details: 'b', is_suppressed: true }),
        ])

        const cell = matrix.rows[0]!.cells['1.0']!
        expect(cell.state).toBe('EXPLOITABLE')
        expect(cell.instances).toHaveLength(2)
        expect(cell.variantLabels).toEqual(['A', 'B'])
        expect(cell.differs).toBe(true)
        expect(cell.suppressed).toBe(true)
    })

    it('handles no findings', () => {
        expect(buildFindingMatrix([])).toEqual({ versions: [], rows: [], variants: [], differingCount: 0, total: 0 })
    })
})

describe('compareVariants', () => {
    it('names the fields in which the assessments differ', () => {
        const matrix = buildFindingMatrix([
            finding({
                project_version: '1.0',
                analysis_state: 'NOT_AFFECTED',
                analysis_details: `[Rescored: 4.0]\n\n${block('General', 'NOT_AFFECTED', 'Not shipped.', ' [Justification: CODE_NOT_PRESENT]')}\n\n${block('Security', 'NOT_AFFECTED', 'Same text.')}`,
            }),
            finding({
                project_version: '2.0',
                analysis_state: 'NOT_AFFECTED',
                analysis_details: `[Rescored: 5.5]\n\n${block('General', 'NOT_AFFECTED', 'Not shipped.', ' [Justification: CODE_NOT_PRESENT]')}\n\n${block('Security', 'NOT_AFFECTED', 'Same text.')}`,
            }),
        ])
        const rows = compareVariants(matrix.variants)

        expect(rows.filter(row => row.differs).map(row => [row.label, row.values]))
            .toEqual([['Rescored score', ['4', '5.5']]])
        expect(rows.find(row => row.key === 'team:General:state')).toEqual({
            key: 'team:General:state', label: 'Global · state', values: ['NOT AFFECTED', 'NOT AFFECTED'], differs: false,
        })
        expect(rows.map(row => row.label)).toContain('Security · rationale')
    })

    it('shows a team assessment that only one version has', () => {
        const matrix = buildFindingMatrix([
            finding({ project_version: '1.0', analysis_state: 'IN_TRIAGE', analysis_details: block('Security', 'IN_TRIAGE', 'Looking.') }),
            finding({ project_version: '2.0' }),
            finding({ project_version: '3.0' }),
        ])
        const rows = compareVariants(matrix.variants)

        expect(rows.find(row => row.key === 'state')!.values).toEqual(['NOT SET', 'IN TRIAGE'])
        expect(rows.find(row => row.key === 'team:Security:details')).toMatchObject({ values: ['', 'Looking.'], differs: true })
    })
})
