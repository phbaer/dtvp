import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import GoneFindingsPanel from '../GoneFindingsPanel.vue'
import { acknowledgeGoneFindings, applyGoneFindingToAlias, getGoneFindings } from '../../lib/api'

vi.mock('../../lib/api', () => ({
    getGoneFindings: vi.fn(), acknowledgeGoneFindings: vi.fn(), applyGoneFindingToAlias: vi.fn(),
}))

const READ = {
    read_at: '2026-11-20T10:00:00+00:00',
    went: { replaced: 2, component_removed: 1 },
    returned: 0,
    carried_over: 2,
    not_carried: 1,
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
    acknowledged_by: null,
    acknowledged_at: null,
    needs_attention: false,
    ...overrides,
})

const PROJECT = {
    name: 'App',
    versions: [
        {
            version: '1.0', project_uuid: 'p1', last_read: READ,
            gone: { replaced: 2, component_removed: 2 },
            findings: [
                finding({
                    carry_over: 'carried',
                    successor: { component_uuid: 'c-new', component_name: 'lib-a', component_version: '1.1' },
                    assessment: { sync_status: 'superseded', state: 'NOT_AFFECTED', revision: 0 },
                }),
                finding({ component_uuid: 'c-2', vuln_id: 'CVE-2026-2', carry_over: 'conflict', needs_attention: true }),
                finding({
                    component_uuid: 'c-3', component_name: 'lib-c', reason: 'component_removed',
                    vuln_id: 'CVE-2026-3', carry_over: 'undetermined', needs_attention: true,
                }),
                finding({
                    component_uuid: 'c-3', component_name: 'lib-c', reason: 'component_removed',
                    vulnerability_uuid: 'v4', vuln_id: 'CVE-2026-4', carry_over: 'undetermined',
                    acknowledged_by: 'rita', acknowledged_at: '2026-11-20T11:00:00+00:00',
                }),
            ],
        },
        {
            version: '2.0', project_uuid: 'p2', last_read: { ...READ, went: {} }, gone: { replaced: 1 },
            findings: [
                finding({
                    component_uuid: 'c-5', recreated: true, carry_over: 'carried',
                    successor: { component_uuid: 'c-6', component_name: 'lib-a', component_version: '1.0' },
                }),
            ],
        },
    ],
}

const dialog = () => document.body.querySelector('[data-testid="gone-findings-panel"]') as HTMLElement | null
const all = (selector: string) => [...document.body.querySelectorAll(selector)] as HTMLElement[]
const texts = (selector: string) => all(selector).map(element => element.textContent?.trim())
const click = async (element: Element | null | undefined) => {
    ;(element as HTMLElement).click()
    await flushPromises()
}

const mountPanel = async (canAcknowledge = true) => {
    const wrapper = mount(GoneFindingsPanel, { props: { projectName: 'App', canAcknowledge }, attachTo: document.body })
    await flushPromises()
    return wrapper
}

describe('GoneFindingsPanel', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(getGoneFindings).mockResolvedValue(structuredClone(PROJECT) as any)
        vi.mocked(acknowledgeGoneFindings).mockResolvedValue({ changed: 1 })
    })
    afterEach(() => {
        document.body.innerHTML = ''
    })

    it('counts what needs attention and opens above the page', async () => {
        const wrapper = await mountPanel()

        expect(getGoneFindings).toHaveBeenCalledWith('App')
        expect(wrapper.get('[data-testid="gone-findings-count"]').text()).toBe('2')
        expect(wrapper.get('[data-testid="gone-findings-button"]').attributes('title'))
            .toBe('2 gone finding(s) need attention, 5 gone in all')
        expect(dialog()).toBeNull()

        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')
        // Teleported to the body, outside every stacking context of the page.
        expect(dialog()).not.toBeNull()
        expect(wrapper.element.contains(dialog())).toBe(false)
        expect(dialog()!.closest('[data-testid="gone-findings-backdrop"]')!.parentElement).toBe(document.body)
        expect(dialog()!.getAttribute('role')).toBe('dialog')

        // Needs attention: only the two of 1.0, small enough to show open.
        expect(texts('[data-testid="gone-findings-version"] .font-mono.text-xs')).toEqual(['1.0'])
        // Groups by size, then name.
        expect(texts('[data-testid="gone-finding"] .font-mono.font-semibold')).toEqual(['CVE-2026-3', 'CVE-2026-2'])
        expect(texts('[data-testid="gone-findings-reason-chip"]')).toEqual(['Component removed · 1', 'Replaced · 1'])
        expect(texts('[data-testid="gone-finding-carry-over"]')).toEqual([
            'Component unknown, not carried',
            'Assessments differ, not carried',
        ])

        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
        await flushPromises()
        expect(dialog()).toBeNull()
        wrapper.unmount()
    })

    it('shows everything, acknowledged findings and filters on request', async () => {
        const wrapper = await mountPanel()
        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')

        await click(document.body.querySelector('[data-testid="gone-findings-view-all"]'))
        // Acknowledged ones stay hidden until asked for.
        expect(texts('[data-testid="gone-finding"] .font-mono.font-semibold'))
            .toEqual(['CVE-2026-1', 'CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3'])
        expect(texts('[data-testid="gone-finding-reason"]')).toContain(
            'Recreated by Dependency-Track (same version, new component ID)',
        )
        expect(texts('[data-testid="gone-finding-carry-over"]')).toContain('Carried over to the recreated component')

        const show = document.body.querySelector('[data-testid="gone-findings-show-acknowledged"]') as HTMLInputElement
        show.click()
        await flushPromises()
        expect(texts('[data-testid="gone-finding-acknowledged"]')[0]).toContain('Acknowledged by rita')

        // Reason chips filter.
        const chips = all('[data-testid="gone-findings-reason-chip"]')
        await click(chips.find(chip => chip.textContent?.startsWith('Component removed')))
        expect(texts('[data-testid="gone-finding"] .font-mono.font-semibold')).toEqual(['CVE-2026-3', 'CVE-2026-4'])

        // Search.
        const search = document.body.querySelector('[data-testid="gone-findings-search"]') as HTMLInputElement
        search.value = '2026-4'
        search.dispatchEvent(new Event('input'))
        await flushPromises()
        expect(texts('[data-testid="gone-finding"] .font-mono.font-semibold')).toEqual(['CVE-2026-4'])
        wrapper.unmount()
    })

    it('groups by version, reason and component, collapsed when long', async () => {
        const many = Array.from({ length: 30 }, (_, index) => finding({
            component_uuid: `c-${index % 3}`, component_name: `lib-${index % 3}`,
            vulnerability_uuid: `v-${index}`, vuln_id: `CVE-2026-${100 + index}`,
            reason: 'component_removed', carry_over: 'undetermined', needs_attention: true,
        }))
        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [{ version: '1.0', project_uuid: 'p1', last_read: READ, gone: { component_removed: 30 }, findings: many }],
        } as any)
        const wrapper = await mountPanel()
        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')

        expect(texts('[data-testid="gone-findings-reason-toggle"]')[0])
            .toContain('Component removed · 30 finding(s), 3 component(s)')
        expect(all('[data-testid="gone-finding"]')).toHaveLength(0)

        await click(document.body.querySelector('[data-testid="gone-findings-reason-toggle"]'))
        expect(texts('[data-testid="gone-findings-component-toggle"]')).toEqual(['lib-0@1.0 · 10', 'lib-1@1.0 · 10', 'lib-2@1.0 · 10'])
        await click(document.body.querySelector('[data-testid="gone-findings-component-toggle"]'))
        expect(all('[data-testid="gone-finding"]')).toHaveLength(10)

        // A whole component at once.
        await click(document.body.querySelector('[data-testid="gone-findings-acknowledge-component"]'))
        expect(acknowledgeGoneFindings).toHaveBeenCalledWith(
            'p1',
            many.filter(item => item.component_uuid === 'c-0')
                .map(item => ({ component_uuid: 'c-0', vulnerability_uuid: item.vulnerability_uuid })),
            true,
        )
        expect(getGoneFindings).toHaveBeenCalledTimes(2)
        wrapper.unmount()
    })

    it('acknowledges and withdraws single findings, and reports failures', async () => {
        const wrapper = await mountPanel()
        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')

        await click(document.body.querySelector('[data-testid="gone-finding-acknowledge"]'))
        expect(acknowledgeGoneFindings).toHaveBeenLastCalledWith(
            'p1', [{ component_uuid: 'c-3', vulnerability_uuid: 'v1' }], true,
        )

        ;(document.body.querySelector('[data-testid="gone-findings-show-acknowledged"]') as HTMLInputElement).click()
        await flushPromises()
        await click(document.body.querySelector('[data-testid="gone-finding-withdraw"]'))
        expect(acknowledgeGoneFindings).toHaveBeenLastCalledWith(
            'p1', [{ component_uuid: 'c-3', vulnerability_uuid: 'v4' }], false,
        )

        vi.mocked(acknowledgeGoneFindings).mockRejectedValueOnce(new Error('down'))
        await click(document.body.querySelector('[data-testid="gone-finding-acknowledge"]'))
        expect(dialog()!.querySelector('[role="alert"]')!.textContent).toContain('could not be acknowledged')
        wrapper.unmount()
    })

    it('offers acknowledging to reviewers only', async () => {
        const wrapper = await mountPanel(false)
        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')
        await flushPromises()

        expect(document.body.querySelector('[data-testid="gone-finding"]')).not.toBeNull()
        for (const id of ['gone-finding-acknowledge', 'gone-finding-withdraw', 'gone-findings-acknowledge-component', 'gone-findings-acknowledge-reason']) {
            expect(document.body.querySelector(`[data-testid="${id}"]`)).toBeNull()
        }
        wrapper.unmount()
    })

    it('flags a mass disappearance, names the cause, and applies to an alias', async () => {
        const dompurify = {
            component_uuid: 'c-d', component_name: 'dompurify', component_version: '3.2.7',
            component_purl: 'pkg:npm/dompurify@3.2.7', reason: 'no_longer_matched',
        }
        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [{
                version: '6.15.6', project_uuid: 'p1',
                last_read: {
                    ...READ, went: { no_longer_matched: 1743 },
                    mass_disappearance: { reason: 'no_longer_matched', count: 1743, share: 0.425, findings_before: 4098 },
                },
                gone: { no_longer_matched: 1743 },
                alias_disagreements: [{
                    component_uuid: 'c-d', component_name: 'dompurify', component_version: '3.2.7',
                    findings: [
                        { vulnerability_uuid: 'va', vuln_id: 'CVE-2026-65913', state: 'NOT_AFFECTED' },
                        { vulnerability_uuid: 'vb', vuln_id: 'GHSA-v9jr-rg53-9pgp', state: 'EXPLOITABLE' },
                    ],
                }],
                findings: [finding({
                    ...dompurify, vulnerability_uuid: 'v-cve', vuln_id: 'CVE-2026-65901',
                    needs_attention: true, tickets: ['VP-61182'],
                    assessment: { sync_status: 'inactive', state: 'EXPLOITABLE', revision: 2 },
                    cause: 'CPE changed from cpe:2.3:a:cure53:dompurify:3.2.7 to cpe:2.3:a:dompurify:dompurify:3.2.7',
                    alias: {
                        component_uuid: 'c-d', vulnerability_uuid: 'v-ghsa', vuln_id: 'GHSA-x4vx-rjvf-j5p4',
                        state: 'NOT_AFFECTED', tickets: [], disagrees: true, proposal: 'blocks',
                    },
                })],
            }],
        } as any)
        vi.mocked(applyGoneFindingToAlias).mockResolvedValue({ kind: 'blocks' })
        const wrapper = await mountPanel()

        expect(wrapper.get('[data-testid="gone-findings-button"]').attributes('title')).toContain(
            '6.15.6: 1743 findings went no longer matched at the last read (43% of the findings)',
        )
        await wrapper.get('[data-testid="gone-findings-button"]').trigger('click')
        expect(texts('[data-testid="gone-findings-mass"]')[0]).toContain('1743 findings went no longer matched')
        expect(texts('[data-testid="gone-findings-disagreements"]')[0]).toContain(
            'CVE-2026-65913 NOT_AFFECTED · GHSA-v9jr-rg53-9pgp EXPLOITABLE',
        )
        expect(texts('[data-testid="gone-finding-cause"]')).toEqual([
            'CPE changed from cpe:2.3:a:cure53:dompurify:3.2.7 to cpe:2.3:a:dompurify:dompurify:3.2.7',
        ])
        expect(texts('[data-testid="gone-finding-tickets"]')).toEqual(['Tickets: VP-61182'])
        expect(texts('[data-testid="gone-finding-alias"]')[0]).toContain(
            'Still reported as GHSA-x4vx-rjvf-j5p4: NOT_AFFECTED, a different assessment',
        )

        await click(document.body.querySelector('[data-testid="gone-finding-apply-alias"]'))
        expect(applyGoneFindingToAlias).toHaveBeenCalledWith('p1', 'c-d', 'v-cve', 'v-ghsa', 'c-d')
        expect(texts('[data-testid="gone-finding-applied"]')).toEqual(['Applied, pending review'])
        wrapper.unmount()

        // Analysts see the proposal, not the action.
        const analyst = await mountPanel(false)
        await analyst.get('[data-testid="gone-findings-button"]').trigger('click')
        expect(document.body.querySelector('[data-testid="gone-finding-alias"]')).not.toBeNull()
        expect(document.body.querySelector('[data-testid="gone-finding-apply-alias"]')).toBeNull()
        analyst.unmount()
    })

    it('says when nothing needs attention, and is disabled with nothing gone', async () => {
        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [{ ...PROJECT.versions[1] }],
        } as any)
        const calm = await mountPanel()
        expect(calm.get('[data-testid="gone-findings-count"]').text()).toBe('0')
        await calm.get('[data-testid="gone-findings-button"]').trigger('click')
        expect(dialog()!.querySelector('[data-testid="gone-findings-empty"]')!.textContent)
            .toContain('Nothing needs attention')
        calm.unmount()

        vi.mocked(getGoneFindings).mockResolvedValue({
            name: 'App',
            versions: [{ version: '1.0', project_uuid: 'p1', last_read: { ...READ, went: {} }, gone: {}, findings: [] }],
        } as any)
        const quiet = await mountPanel()
        expect(quiet.get('[data-testid="gone-findings-button"]').attributes('disabled')).toBeDefined()
        quiet.unmount()

        vi.mocked(getGoneFindings).mockRejectedValue(new Error('down'))
        const failed = await mountPanel()
        expect(failed.get('[data-testid="gone-findings-count"]').text()).toBe('!')
        await failed.get('[data-testid="gone-findings-button"]').trigger('click')
        expect(dialog()!.querySelector('[role="alert"]')!.textContent).toContain('could not be loaded')
        failed.unmount()
    })
})
