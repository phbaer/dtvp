import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import GoneFindingsStatistics from '../GoneFindingsStatistics.vue'
import { getGoneFindings } from '../../lib/api'

vi.mock('../../lib/api', () => ({ getGoneFindings: vi.fn() }))

const version = (project_uuid: string, summary: Record<string, unknown>, trend: unknown[]) => ({
    version: project_uuid, project_uuid, last_read: null, gone: {}, findings: [], summary, trend,
})

describe('GoneFindingsStatistics', () => {
    beforeEach(() => vi.clearAllMocks())

    it('adds up the versions: reasons, assessments and a trend per day', async () => {
        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [
                version('p1', {
                    by_reason: { component_removed: 3, recreated: 2 },
                    by_carry_over: { undetermined: 3, carried: 2 },
                    needs_attention: 2, acknowledged: 1,
                }, [
                    { day: '2026-11-18', went: { component_removed: 3 } },
                    { day: '2026-11-20', went: { replaced: 2 } },
                ]),
                version('p2', {
                    by_reason: { replaced: 1 },
                    by_carry_over: { conflict: 1 },
                    needs_attention: 1, acknowledged: 0,
                }, [{ day: '2026-11-20', went: { replaced: 1 } }]),
            ],
        } as any)
        const wrapper = mount(GoneFindingsStatistics, { props: { projectName: 'App' } })
        await flushPromises()

        expect(wrapper.get('[data-testid="gone-findings-statistics-total"]').text())
            .toBe('6 gone in all versions; 3 need attention, 1 acknowledged.')
        expect(wrapper.findAll('[data-testid="gone-findings-statistics-reasons"] li').map(li => li.text())).toEqual([
            'Component removed3', 'Recreated by Dependency-Track2', 'Replaced1',
        ])
        expect(wrapper.findAll('[data-testid="gone-findings-statistics-carry-over"] li').map(li => li.text())).toEqual([
            'Component unknown, not carried3', 'Carried over, pending review2', 'Assessments differ, not carried1',
        ])
        const bars = wrapper.findAll('[data-testid="gone-findings-statistics-trend"] > div')
        expect(bars.map(bar => bar.attributes('title'))).toEqual([
            '2026-11-18: 3 went (3 component removed)',
            '2026-11-20: 3 went (3 replaced)',
        ])
    })

    it('names a version in which many findings went no longer matched', async () => {
        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [version('6.15.6', {
                by_reason: { no_longer_matched: 1743 }, by_carry_over: {}, needs_attention: 1, acknowledged: 0,
                mass_disappearance: { reason: 'no_longer_matched', count: 1743, share: 0.425, findings_before: 4098 },
            }, [])],
        } as any)
        const wrapper = mount(GoneFindingsStatistics, { props: { projectName: 'App' } })
        await flushPromises()
        expect(wrapper.get('[data-testid="gone-findings-statistics-mass"]').text()).toBe(
            '6.15.6: 1743 findings went no longer matched at the last read (43% of the findings).',
        )
    })

    it('is hidden with nothing gone and says when loading failed', async () => {
        vi.mocked(getGoneFindings).mockResolvedValue({ name: 'App', versions: [] } as any)
        const empty = mount(GoneFindingsStatistics, { props: { projectName: 'App' } })
        await flushPromises()
        expect(empty.find('[data-testid="gone-findings-statistics"]').exists()).toBe(false)

        vi.mocked(getGoneFindings).mockRejectedValue(new Error('down'))
        const failed = mount(GoneFindingsStatistics, { props: { projectName: 'App' } })
        await flushPromises()
        expect(failed.get('[role="alert"]').text()).toContain('could not be loaded')
    })
})
