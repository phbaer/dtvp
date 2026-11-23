import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import EarlierAssessments from '../EarlierAssessments.vue'
import { getEarlierAssessments } from '../../lib/api'

vi.mock('../../lib/api', () => ({ getEarlierAssessments: vi.fn() }))

const entry = (overrides: Record<string, unknown> = {}) => ({
    component_uuid: '36977e35', component_name: null, component_version: null, component_purl: null,
    vulnerability_uuid: 'v-tar', vuln_id: 'CVE-2024-28863', alias: false, gone_at: '2026-11-22T09:42:20Z',
    state: 'NOT_AFFECTED', justification: 'CODE_NOT_REACHABLE', response: 'WILL_NOT_FIX', suppressed: false,
    date: '2026-08-11T15:27:11Z',
    teams: [{ team: 'General', state: 'NOT_AFFECTED', justification: 'CODE_NOT_REACHABLE', details: 'tar is not used.' }],
    details: 'tar is not used.', preview: 'tar is not used.',
    ...overrides,
})

describe('EarlierAssessments', () => {
    it('lists the earlier assessments of each version once and offers them as a draft', async () => {
        vi.mocked(getEarlierAssessments).mockResolvedValue([
            entry(),
            entry({ component_uuid: 'c-2', component_name: 'tar', component_version: '6.2.0', state: 'FALSE_POSITIVE', justification: 'NOT_SET' }),
        ] as any)
        const wrapper = mount(EarlierAssessments, {
            props: {
                findings: [
                    { project_uuid: 'p-720', vulnerability_uuid: 'v-tar', project_version: '7.2.0' },
                    // The same version and vulnerability on another component: asked once.
                    { project_uuid: 'p-720', vulnerability_uuid: 'v-tar', project_version: '7.2.0' },
                ],
            },
        })
        await flushPromises()

        expect(getEarlierAssessments).toHaveBeenCalledTimes(1)
        expect(getEarlierAssessments).toHaveBeenCalledWith('p-720', 'v-tar')
        const rows = wrapper.findAll('[data-testid="earlier-assessment"]').map(row => row.text().replace(/\s+/g, ' '))
        expect(rows[0]).toContain('unknown component · 7.2.0 · NOT AFFECTED · CODE NOT REACHABLE')
        expect(rows[0]).toContain('tar is not used.')
        expect(rows[1]).toContain('tar 6.2.0 · 7.2.0 · FALSE POSITIVE')
        expect(rows[1]).not.toContain('NOT SET')

        await wrapper.findAll('[data-testid="use-earlier-assessment"]')[0].trigger('click')
        expect(wrapper.emitted('use')![0][0]).toMatchObject({ component_uuid: '36977e35', state: 'NOT_AFFECTED' })
    })

    it('shows nothing when DTVP holds no earlier assessment', async () => {
        vi.mocked(getEarlierAssessments).mockResolvedValue([])
        const wrapper = mount(EarlierAssessments, {
            props: { findings: [{ project_uuid: 'p1', vulnerability_uuid: 'v1' }] },
        })
        await flushPromises()
        expect(wrapper.find('[data-testid="earlier-assessments"]').exists()).toBe(false)
    })
})
