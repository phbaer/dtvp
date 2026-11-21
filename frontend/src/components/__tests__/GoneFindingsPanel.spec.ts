import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import GoneFindingsPanel from '../GoneFindingsPanel.vue'
import { getGoneFindings } from '../../lib/api'

vi.mock('../../lib/api', () => ({ getGoneFindings: vi.fn() }))

const READ = {
    read_at: '2026-11-20T10:00:00+00:00',
    went: { replaced: 2, component_removed: 1 },
    returned: 0,
    carried_over: 2,
    not_carried: 0,
}

const finding = (overrides: Record<string, unknown>) => ({
    component_uuid: 'c-old',
    component_name: 'lib-a',
    component_version: '1.0',
    component_purl: 'pkg:npm/lib-a@1.0',
    vulnerability_uuid: 'v1',
    vuln_id: 'CVE-2026-1',
    reason: 'replaced',
    gone_at: '2026-11-20T10:00:00+00:00',
    last_seen_at: '2026-11-19T10:00:00+00:00',
    carry_over: null,
    successor: null,
    assessment: { sync_status: 'inactive', state: 'NOT_AFFECTED', revision: 1 },
    ...overrides,
})

const mountPanel = async () => {
    const wrapper = mount(GoneFindingsPanel, { props: { projectName: 'App' }, attachTo: document.body })
    await flushPromises()
    return wrapper
}

describe('GoneFindingsPanel', () => {
    beforeEach(() => vi.clearAllMocks())

    it('counts gone findings across versions and lists them with reasons when opened', async () => {
        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [
                {
                    version: '1.0', project_uuid: 'p1', last_read: READ,
                    gone: { replaced: 2, component_removed: 1 },
                    findings: [
                        finding({
                            carry_over: 'carried',
                            successor: { component_uuid: 'c-new', component_name: 'lib-a', component_version: '1.1' },
                            assessment: { sync_status: 'superseded', state: 'NOT_AFFECTED', revision: 0 },
                        }),
                        finding({ component_uuid: 'c-2', vuln_id: 'CVE-2026-2', carry_over: 'conflict' }),
                        finding({ component_uuid: 'c-3', reason: 'component_removed', vuln_id: 'CVE-2026-3', assessment: null }),
                    ],
                },
                {
                    version: '2.0', project_uuid: 'p2', last_read: { ...READ, went: {} }, gone: {},
                    findings: [finding({ reason: 'no_longer_matched' }), finding({ reason: 'undetermined', component_uuid: 'c-4' }),
                        finding({ reason: 'missing_at_export', component_uuid: 'c-5', own: 1 }),
                        finding({ reason: 'replaced', component_uuid: 'c-6', carry_over: 'own_assessment' })],
                },
            ],
        } as any)
        const wrapper = await mountPanel()

        expect(getGoneFindings).toHaveBeenCalledWith('App')
        expect(wrapper.get('[data-testid="gone-findings-count"]').text()).toBe('3')
        // Closed by default.
        expect(wrapper.find('[data-testid="gone-findings-panel"]').exists()).toBe(false)

        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')
        const versions = wrapper.findAll('[data-testid="gone-findings-version"]')
        expect(versions.map(item => item.find('div').text())).toEqual(['2.0', '1.0'])
        expect(versions[1].get('[data-testid="gone-findings-read"]').text())
            .toContain('3 went (2 replaced, 1 component removed)')
        const reasons = wrapper.findAll('[data-testid="gone-finding-reason"]').map(item => item.text())
        expect(reasons).toEqual([
            'No longer matched', 'Not yet determined', 'Missing at export', 'Replaced',
            'Replaced by lib-a@1.1', 'Replaced', 'Component removed',
        ])
        const notes = wrapper.findAll('[data-testid="gone-finding-carry-over"]').map(item => item.text())
        expect(notes).toEqual([
            'Successor has its own assessment',
            'Carried over, pending review',
            'Assessments differ, not carried',
        ])
        expect(wrapper.text()).toContain('NOT_AFFECTED · superseded')
        expect(wrapper.text()).toContain('No assessment')

        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')
        expect(wrapper.find('[data-testid="gone-findings-panel"]').exists()).toBe(false)
        wrapper.unmount()
    })

    it('says a component recreated with the same version was not replaced', async () => {
        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [{
                version: '1.0', project_uuid: 'p1',
                last_read: { ...READ, went: { replaced: 1 } },
                gone: { replaced: 1 },
                findings: [finding({
                    carry_over: 'carried',
                    successor: { component_uuid: 'c-new', component_name: 'lib-a', component_version: '1.0' },
                })],
            }],
        } as any)
        const wrapper = await mountPanel()

        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')
        expect(wrapper.get('[data-testid="gone-finding-reason"]').text())
            .toBe('Recreated by Dependency-Track (same version, new component ID)')
        expect(wrapper.get('[data-testid="gone-finding-carry-over"]').text())
            .toBe('Carried over to the recreated component')
        wrapper.unmount()
    })

    it('says when the component of an old record is unknown', async () => {
        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [{
                version: '1.0', project_uuid: 'p1',
                last_read: { ...READ, went: { component_removed: 1 } },
                gone: { component_removed: 1 },
                findings: [{
                    component_uuid: 'c1', component_name: 'lib-a', component_version: null, component_purl: null,
                    vulnerability_uuid: 'v1', vuln_id: 'CVE-2026-9', reason: 'component_removed',
                    gone_at: '2026-11-20T09:00:00+00:00', last_seen_at: null, carry_over: 'undetermined',
                    successor: null, assessment: { sync_status: 'inactive', state: 'NOT_AFFECTED', revision: 1 },
                }],
            }],
        } as any)
        const wrapper = await mountPanel()

        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')
        expect(wrapper.get('[data-testid="gone-findings-read"]').text())
            .toContain('1 went (1 component removed)')
        expect(wrapper.text()).toContain('Component unknown, not carried')
        wrapper.unmount()
    })

    it('is disabled with nothing gone and reports a failed load', async () => {
        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [{ version: '1.0', project_uuid: 'p1', last_read: { ...READ, went: {} }, gone: {}, findings: [] }],
        } as any)
        const quiet = await mountPanel()
        const button = quiet.get('[data-testid="gone-findings-button"]')
        expect(button.attributes('disabled')).toBeDefined()
        await button.trigger('click')
        expect(quiet.find('[data-testid="gone-findings-panel"]').exists()).toBe(false)
        quiet.unmount()

        vi.mocked(getGoneFindings).mockRejectedValue(new Error('down'))
        const failed = await mountPanel()
        expect(failed.get('[data-testid="gone-findings-count"]').text()).toBe('!')
        await failed.get('[data-testid="gone-findings-button"]').trigger('click')
        expect(failed.get('[role="alert"]').text()).toContain('could not be loaded')
        vi.mocked(getGoneFindings).mockResolvedValue({ name: 'App', versions: [] } as any)
        await failed.get('[role="alert"] button').trigger('click')
        await flushPromises()
        expect(getGoneFindings).toHaveBeenCalledTimes(3)
        failed.unmount()
    })
})
