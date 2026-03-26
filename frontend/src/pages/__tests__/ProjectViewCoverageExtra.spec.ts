
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ProjectView from '../ProjectView.vue'
import { getGroupedVulns } from '../../lib/api'
import { calculateScoreFromVector } from '../../lib/cvss'
import { useRoute } from 'vue-router'

vi.mock('../../lib/api', () => ({
    getGroupedVulns: vi.fn(),
    getTeamMapping: vi.fn(() => Promise.resolve({})),
    getRescoreRules: vi.fn(() => Promise.resolve({ transitions: [] }))
}))

vi.mock('../../lib/cvss', () => ({
    calculateScoreFromVector: vi.fn(() => 7.5)
}))

vi.mock('vue-router', () => ({
    useRoute: vi.fn(() => ({ params: { name: 'Test' }, query: {} })),
    useRouter: vi.fn(() => ({ replace: vi.fn(() => Promise.resolve()) })),
    RouterLink: { template: '<a data-testid="router-link"><slot/></a>' }
}))

vi.mock('../../components/VulnGroupCard.vue', () => ({
    default: {
        template: '<div class="vuln-card"></div>',
        props: ['group'],
        emits: ['update:assessment']
    }
}))

describe('ProjectView Coverage Extra Detailed', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(useRoute).mockReturnValue({ params: { name: 'Test' }, query: {} } as any)
    })

    it('auto-calculates rescored_cvss if missing but vector exists', async () => {
        const mockGroups = [
            {
                id: 'V1',
                rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                rescored_cvss: null,
                affected_versions: []
            }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })
        await flushPromises()

        expect(calculateScoreFromVector).toHaveBeenCalledWith('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
        const groups = (wrapper.vm as any).groups
        expect(groups[0].rescored_cvss).toBe(7.5)
    })

    it('handles global search when name is _all_', async () => {
        vi.mocked(useRoute).mockReturnValue({ params: { name: '_all_' }, query: {} } as any)
        vi.mocked(getGroupedVulns).mockResolvedValue([])

        mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: '_all_' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        expect(getGroupedVulns).toHaveBeenCalledWith('', undefined, expect.any(Function))
    })

    it('reports progress updates during fetch', async () => {
        let progressCallback: any
        vi.mocked(getGroupedVulns).mockImplementation(async (_name, _cve, cb) => {
            progressCallback = cb
            return new Promise(resolve => setTimeout(() => resolve([]), 10))
        })

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await wrapper.vm.$nextTick()
        if (progressCallback) {
            progressCallback('Analyzing...', 42)
        }
        await wrapper.vm.$nextTick()

        expect(wrapper.text()).toContain('Analyzing...')
        expect(wrapper.text()).toContain('42%')
    })

    it('sorts by analysis state correctly', async () => {
        const mockGroups = [
            { id: 'V1', affected_versions: [{ components: [{ analysis_state: 'NOT_SET' }] }] },
            { id: 'V2', affected_versions: [{ components: [{ analysis_state: 'EXPLOITABLE' }] }] }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })
        await flushPromises()
            ; (wrapper.vm as any).lifecycleFilters = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT']
            ; (wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'OLD', 'NEW', 'UNKNOWN_STATE']
        await wrapper.vm.$nextTick()

        ;(wrapper.vm as any).sortBy = 'analysis'
        await wrapper.vm.$nextTick()

        const sorted = (wrapper.vm as any).filteredGroups
        // EXPLOITABLE (0) < NOT_SET (4)
        expect(sorted[0].id).toBe('V2')
        expect(sorted[1].id).toBe('V1')
    })

    it('sorts by tags correctly', async () => {
        const mockGroups = [
            { id: 'V1', tags: ['Beta'] },
            { id: 'V2', tags: ['Alpha'] },
            { id: 'V3', tags: [] },
            { id: 'V4', tags: null }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })
        await flushPromises()
            ; (wrapper.vm as any).lifecycleFilters = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT']
            ; (wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'OLD', 'NEW', 'UNKNOWN_STATE']
        await wrapper.vm.$nextTick()

        ;(wrapper.vm as any).sortBy = 'tags'
        await wrapper.vm.$nextTick()

        const sorted = (wrapper.vm as any).filteredGroups
        // '', '', Alpha, Beta
        expect(sorted[2].id).toBe('V2')
        expect(sorted[3].id).toBe('V1')
    })

    it('sorts by score fallbacks correctly', async () => {
        const mockGroups = [
            { id: 'V1', rescored_cvss: 5.0 },
            { id: 'V2', cvss_score: 9.0 },
            { id: 'V3', cvss: 2.0 },
            { id: 'V4', rescored_cvss: null, cvss_score: null, cvss: null }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })
        await flushPromises()
            ; (wrapper.vm as any).lifecycleFilters = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT']
            ; (wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'OLD', 'NEW', 'UNKNOWN_STATE']
        await wrapper.vm.$nextTick()

        ;(wrapper.vm as any).sortBy = 'score'
        await wrapper.vm.$nextTick()

        const sorted = (wrapper.vm as any).filteredGroups
        // 0, 2.0, 5.0, 9.0
        expect(sorted[0].id).toBe('V4')
        expect(sorted[1].id).toBe('V3')
        expect(sorted[2].id).toBe('V1')
        expect(sorted[3].id).toBe('V2')
    })

    it('sorts by severity fallbacks correctly', async () => {
        const mockGroups = [
            { id: 'V1', severity: 'CRITICAL' },
            { id: 'V2', severity: null }, // Falls back to UNKNOWN
            { id: 'V3', severity: 'HIGH' }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })
        await flushPromises()
            ; (wrapper.vm as any).lifecycleFilters = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT']
            ; (wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'OLD', 'NEW', 'UNKNOWN_STATE']
        await wrapper.vm.$nextTick()

        ;(wrapper.vm as any).sortBy = 'severity'
        await wrapper.vm.$nextTick()

        const sorted = (wrapper.vm as any).filteredGroups
        // CRITICAL (0), HIGH (1), UNKNOWN (5)
        expect(sorted[0].id).toBe('V1')
        expect(sorted[1].id).toBe('V3')
        expect(sorted[2].id).toBe('V2')
    })

    it('sorts by score additional fallbacks correctly', async () => {
        const mockGroups = [
            { id: 'V1', cvss: 5.0 },
            { id: 'V2', cvss_score: 3.0 },
            { id: 'V3', rescored_cvss: 1.0 }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })
        await flushPromises()
            ; (wrapper.vm as any).lifecycleFilters = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT']
            ; (wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'OLD', 'NEW', 'UNKNOWN_STATE']
        await wrapper.vm.$nextTick()

        ;(wrapper.vm as any).sortBy = 'score'
        await wrapper.vm.$nextTick()

        const sorted = (wrapper.vm as any).filteredGroups
        // 1.0, 3.0, 5.0
        expect(sorted[0].id).toBe('V3')
        expect(sorted[1].id).toBe('V2')
        expect(sorted[2].id).toBe('V1')
    })

    it('sorts by analysis state with unknown state fallback', async () => {
        const mockGroups = [
            { id: 'V1', affected_versions: [{ components: [{ analysis_state: 'UNKNOWN_STATE' }] }] },
            { id: 'V2', affected_versions: [{ components: [{ analysis_state: 'EXPLOITABLE' }] }] }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })
        await flushPromises()
            ; (wrapper.vm as any).lifecycleFilters = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT']
            ; (wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED', 'UNKNOWN_STATE']
        await wrapper.vm.$nextTick()
        ;(wrapper.vm as any).sortBy = 'analysis'
        await wrapper.vm.$nextTick()
        const sorted = (wrapper.vm as any).filteredGroups
        expect(sorted[1].id).toBe('V1') // Unknown (99) comes last
    })

    it('sorts by tags with various empty cases', async () => {
        const mockGroups = [
            { id: 'V1', tags: ['A'] },
            { id: 'V2', tags: [null] }, // tags[0] is null
            { id: 'V3', tags: [] },      // tags.length is 0
            { id: 'V4', tags: null }     // tags is null
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'Test' }, query: {} } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })
        await flushPromises()
            ; (wrapper.vm as any).lifecycleFilters = ['OPEN', 'ASSESSED', 'ASSESSED_LEGACY', 'INCOMPLETE', 'INCONSISTENT']
            ; (wrapper.vm as any).analysisFilters = ['NOT_SET', 'EXPLOITABLE', 'IN_TRIAGE', 'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED']
        await wrapper.vm.$nextTick()
        ;(wrapper.vm as any).sortBy = 'tags'
        await wrapper.vm.$nextTick()
        const sorted = (wrapper.vm as any).filteredGroups
        expect(sorted.length).toBe(4)
    })
})
