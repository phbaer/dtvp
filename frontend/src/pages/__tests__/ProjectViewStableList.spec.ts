import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { getGroupedVulns, getTaskVulnGroups } from '../../lib/api'
import { EVIDENCE_UPDATED_EVENT } from '../../lib/evidence'
import { useRoute } from 'vue-router'
import { mountProjectView } from './projectViewTestUtils'

vi.mock('../../lib/api', () => ({
    drainTaskVulnGroupDetails: vi.fn(),
    drainTaskVulnGroups: vi.fn(() => Promise.resolve([])),
    getGroupedVulns: vi.fn(),
    getAssessmentDetails: vi.fn(),
    getTaskVulnGroup: vi.fn(async (_task: string, id: string) => ({ id, title: id, affected_versions: [], description: 'full' })),
    getTaskVulnGroups: vi.fn(),
    getStatistics: vi.fn(() => Promise.resolve({})),
    getTaskStatistics: vi.fn(() => Promise.resolve({})),
    getCacheStatus: vi.fn(() => Promise.resolve({ fully_cached: false, last_refreshed_at: null, projects: 0, active_projects: 0, cached_findings: 0, cached_boms: 0, cached_analyses: 0, pending_updates: 0 })),
    getTeamMapping: vi.fn(() => Promise.resolve({})),
    getRescoreRules: vi.fn(() => Promise.resolve({ transitions: [] })),
    getTMRescoreProposals: vi.fn(() => Promise.resolve({ proposals: {} })),
}))

const replaceSpy = vi.fn(() => Promise.resolve())
vi.mock('vue-router', () => ({
    useRoute: vi.fn(() => ({ params: {}, query: {} })),
    useRouter: vi.fn(() => ({ replace: replaceSpy })),
    RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../components/VulnRowCompact.vue', () => ({
    default: {
        name: 'VulnRowCompact',
        template: `<div class="vuln-card" :data-group-id="item.id" @click="$emit('select', item.group)">{{ item.id }}</div>`,
        props: ['item', 'selected', 'reloading', 'reloadError'],
        emits: ['select', 'update', 'update:assessment', 'reload'],
    },
}))

vi.mock('../../components/VulnDetailInspector.vue', () => ({
    default: {
        name: 'VulnDetailInspector',
        template: `
            <aside data-testid="detail-inspector">
                <span data-testid="detail-id">{{ group.id }}</span>
                <button data-testid="approve" @click="$emit('update:assessment', { analysis_state: 'NOT_AFFECTED', analysis_details: 'approved' })">approve</button>
            </aside>
        `,
        props: ['group'],
        emits: ['close', 'update', 'update:assessment'],
    },
}))

vi.mock('../../components/BulkWorkflowModal.vue', () => ({
    default: { name: 'BulkWorkflowModal', template: '<div />', props: ['show', 'taskId', 'query'] },
}))

const group = (id: string, evidence = ['NOT_CHECKED']) => ({
    id,
    title: id,
    evidence_sources: evidence,
    list_metadata: { lifecycle: 'NEEDS_APPROVAL', is_pending: true, is_approval_ready: true, technical_state: 'NOT_AFFECTED' },
    affected_versions: [],
})

const counts = (total: number) => ({
    total,
    lifecycle: { READY_FOR_APPROVAL: total },
    analysis: { NOT_AFFECTED: total },
    dependency_relationship: { direct: 0, transitive: 0, unknown: total },
    cvss_version_mismatch: 0,
    versions: {}, tags: {}, assignees: {}, components: {},
})

let listed: string[] = []
const serveList = () => vi.mocked(getTaskVulnGroups).mockImplementation(async () => ({
    items: listed.map(id => group(id)),
    total: listed.length,
    filtered: listed.length,
    counts: { all: counts(listed.length), filtered: counts(listed.length) },
    offset: 0,
    limit: 250,
    sort: 'rescored-severity',
    order: 'desc',
}) as any)

const mountList = async (ids: string[]) => {
    listed = [...ids]
    serveList()
    const wrapper = await mountProjectView({ routeName: 'TestProject' })
    await flushPromises()
    return wrapper
}

const select = async (wrapper: any, id: string) => {
    await wrapper.get(`.vuln-card[data-group-id="${id}"]`).trigger('click')
    await flushPromises()
}

const selectedId = (wrapper: any) => (wrapper.vm as any).$?.setupState?.selectedGroupId
    ?? wrapper.find('[data-testid="detail-id"]').text()

describe('ProjectView keeps the list steady', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(useRoute).mockReturnValue({ params: { name: 'TestProject' }, query: {} } as any)
        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, _progress, options: any) => {
            options?.onTaskId?.('task-stable')
            return [] as any
        })
    })

    it('asks for what awaits review when a reviewer opens a project', async () => {
        const wrapper = await mountList(['A'])
        expect(vi.mocked(getTaskVulnGroups).mock.calls[0]?.[1]).toMatchObject({ awaiting_review: true })
        expect(wrapper.text()).toContain('Awaiting review')
        wrapper.unmount()
    })

    it('selecting a vulnerability does not ask for the list again', async () => {
        const wrapper = await mountList(['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003'])
        const calls = vi.mocked(getTaskVulnGroups).mock.calls.length
        await select(wrapper, 'CVE-2026-0002')
        expect(wrapper.get('[data-testid="detail-id"]').text()).toBe('CVE-2026-0002')
        expect(replaceSpy).toHaveBeenLastCalledWith({ query: expect.objectContaining({ vuln: 'CVE-2026-0002' }) })
        // The opened card looks the exploitation evidence up (SSVC calculator);
        // this used to reload the list from the top.
        globalThis.dispatchEvent(new CustomEvent(EVIDENCE_UPDATED_EVENT, {
            detail: { cves: ['CVE-2026-0002'], sources: ['NOT_CHECKED'] },
        }))
        await new Promise(resolve => setTimeout(resolve, 300))
        await flushPromises()
        expect(getTaskVulnGroups).toHaveBeenCalledTimes(calls)
        wrapper.unmount()
    })

    it('an evidence lookup that changes nothing the list shows does not reload it', async () => {
        const wrapper = await mountList(['CVE-2026-0001', 'CVE-2026-0002'])
        const calls = vi.mocked(getTaskVulnGroups).mock.calls.length
        globalThis.dispatchEvent(new CustomEvent(EVIDENCE_UPDATED_EVENT, {
            detail: { cves: ['CVE-2026-0001'], sources: ['NOT_CHECKED'] },
        }))
        await flushPromises()
        expect(getTaskVulnGroups).toHaveBeenCalledTimes(calls)

        globalThis.dispatchEvent(new CustomEvent(EVIDENCE_UPDATED_EVENT, {
            detail: { cves: ['CVE-2026-0001'], sources: ['KEV'] },
        }))
        await flushPromises()
        expect(getTaskVulnGroups).toHaveBeenCalledTimes(calls + 1)
        // In place: from the start, every loaded row.
        expect(vi.mocked(getTaskVulnGroups).mock.lastCall?.[1]).toMatchObject({ offset: 0, limit: 250 })
        wrapper.unmount()
    })

    it('selects the next vulnerability when an approval takes the selected one out of the list', async () => {
        const wrapper = await mountList(['A', 'B', 'C'])
        await select(wrapper, 'B')
        listed = ['A', 'C']
        await wrapper.get('[data-testid="approve"]').trigger('click')
        await flushPromises()
        await flushPromises()
        expect(wrapper.get('[data-testid="detail-id"]').text()).toBe('C')
        expect(replaceSpy).toHaveBeenLastCalledWith({ query: expect.objectContaining({ vuln: 'C' }) })
        expect(wrapper.get('[data-testid="list-announcement"]').text())
            .toBe('B left the list; selected C, the next vulnerability.')
        wrapper.unmount()
    })

    it('selects the previous one when the last vulnerability leaves', async () => {
        const wrapper = await mountList(['A', 'B', 'C'])
        await select(wrapper, 'C')
        listed = ['A', 'B']
        await wrapper.get('[data-testid="approve"]').trigger('click')
        await flushPromises()
        await flushPromises()
        expect(wrapper.get('[data-testid="detail-id"]').text()).toBe('B')
        wrapper.unmount()
    })

    it('keeps the selection when the vulnerability stays, and keeps it open when the list empties', async () => {
        const wrapper = await mountList(['A', 'B', 'C'])
        await select(wrapper, 'B')
        listed = ['B', 'A', 'C']
        await wrapper.get('[data-testid="approve"]').trigger('click')
        await flushPromises()
        expect(wrapper.get('[data-testid="detail-id"]').text()).toBe('B')
        expect(wrapper.get('[data-testid="list-announcement"]').text()).toBe('')

        listed = []
        await wrapper.get('[data-testid="approve"]').trigger('click')
        await flushPromises()
        await flushPromises()
        expect(wrapper.get('[data-testid="list-announcement"]').text())
            .toBe('B left the list; no other vulnerability is listed.')
        expect(selectedId(wrapper)).toBe('B')
        wrapper.unmount()
    })
})
