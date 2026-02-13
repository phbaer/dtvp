import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ProjectView from '../ProjectView.vue'
import { getGroupedVulns } from '../../lib/api'
import { useRoute } from 'vue-router'

vi.mock('../../lib/api', () => ({
    getGroupedVulns: vi.fn()
}))

vi.mock('vue-router', () => ({
    useRoute: vi.fn(),
    RouterLink: { template: '<a><slot /></a>' }
}))

// Mock child component to show group info for verification
vi.mock('../../components/VulnGroupCard.vue', () => ({
    default: {
        template: '<div class="vuln-group-card" :data-id="group.id">{{ group.id }}</div>',
        props: ['group']
    }
}))

describe('ProjectView.vue Sorting', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        vi.mocked(useRoute).mockReturnValue({
            params: { name: 'TestProject' }
        } as any)
    })

    const mockGroups = [
        {
            id: 'CVE-2023-0001',
            severity: 'HIGH',
            cvss_score: 8.0,
            tags: ['Team-A'],
            affected_versions: [{ components: [{ analysis_state: 'IN_TRIAGE' }] }]
        },
        {
            id: 'CVE-2023-0002',
            severity: 'CRITICAL',
            cvss_score: 9.8,
            tags: ['Team-B'],
            affected_versions: [{ components: [{ analysis_state: 'EXPLOITABLE' }] }]
        },
        {
            id: 'CVE-2023-0003',
            severity: 'MEDIUM',
            cvss_score: 5.0,
            tags: ['Team-A'],
            affected_versions: [{ components: [{ analysis_state: 'NOT_SET' }] }]
        },
    ]

    it('sorts by severity (default asc)', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'TestProject' } } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises()
            ; (wrapper.vm as any).hideAssessed = false
            ; (wrapper.vm as any).hideMixed = false
        await wrapper.vm.$nextTick()

        const cards = wrapper.findAll('.vuln-group-card')
        expect(cards[0]!.attributes('data-id')).toBe('CVE-2023-0002') // CRITICAL
        expect(cards[1]!.attributes('data-id')).toBe('CVE-2023-0001') // HIGH
        expect(cards[2]!.attributes('data-id')).toBe('CVE-2023-0003') // MEDIUM
    })

    it('sorts by score (asc/desc)', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'TestProject' } } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises()
            ; (wrapper.vm as any).hideAssessed = false
            ; (wrapper.vm as any).hideMixed = false
        await wrapper.vm.$nextTick()

        // Change sortBy to score
        const select = wrapper.find('select')
        await select.setValue('score')

        let cards = wrapper.findAll('.vuln-group-card')
        // Default sortOrder is asc, so score 5.0 -> 8.0 -> 9.8
        expect(cards[0]!.attributes('data-id')).toBe('CVE-2023-0003')
        expect(cards[1]!.attributes('data-id')).toBe('CVE-2023-0001')
        expect(cards[2]!.attributes('data-id')).toBe('CVE-2023-0002')

        // Toggle sortOrder to desc
        await wrapper.find('button[title="Ascending"]').trigger('click')

        cards = wrapper.findAll('.vuln-group-card')
        expect(cards[0]!.attributes('data-id')).toBe('CVE-2023-0002') // 9.8
        expect(cards[1]!.attributes('data-id')).toBe('CVE-2023-0001') // 8.0
        expect(cards[2]!.attributes('data-id')).toBe('CVE-2023-0003') // 5.0
    })

    it('sorts by CVE ID', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'TestProject' } } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises()
            ; (wrapper.vm as any).hideAssessed = false
            ; (wrapper.vm as any).hideMixed = false
        await wrapper.vm.$nextTick()

        const select = wrapper.find('select')
        await select.setValue('id')

        const cards = wrapper.findAll('.vuln-group-card')
        expect(cards[0]!.attributes('data-id')).toBe('CVE-2023-0001')
        expect(cards[1]!.attributes('data-id')).toBe('CVE-2023-0002')
        expect(cards[2]!.attributes('data-id')).toBe('CVE-2023-0003')
    })

    it('sorts by analysis state', async () => {
        vi.mocked(getGroupedVulns).mockResolvedValue(mockGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'TestProject' } } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises()
            ; (wrapper.vm as any).hideAssessed = false
            ; (wrapper.vm as any).hideMixed = false
        await wrapper.vm.$nextTick()

        const select = wrapper.find('select')
        await select.setValue('analysis')

        const cards = wrapper.findAll('.vuln-group-card')
        // Order: EXPLOITABLE -> IN_TRIAGE -> NOT_SET
        expect(cards[0]!.attributes('data-id')).toBe('CVE-2023-0002') // EXPLOITABLE
        expect(cards[1]!.attributes('data-id')).toBe('CVE-2023-0001') // IN_TRIAGE
        expect(cards[2]!.attributes('data-id')).toBe('CVE-2023-0003') // NOT_SET
    })
    it('sorts by ID when severity is equal (stability check)', async () => {
        const stableGroups = [
            {
                id: 'CVE-2023-BBB',
                severity: 'HIGH',
                cvss_score: 8.0,
                tags: [],
                affected_versions: []
            },
            {
                id: 'CVE-2023-AAA',
                severity: 'HIGH',
                cvss_score: 8.0,
                tags: [],
                affected_versions: []
            }
        ]
        vi.mocked(getGroupedVulns).mockResolvedValue(stableGroups as any)

        const wrapper = mount(ProjectView, {
            global: {
                stubs: { RouterLink: true },
                mocks: { $route: { params: { name: 'TestProject' } } },
                provide: {
                    user: { value: { role: 'REVIEWER' } }
                }
            }
        })

        await flushPromises()
            ; (wrapper.vm as any).hideAssessed = false
            ; (wrapper.vm as any).hideMixed = false
        await wrapper.vm.$nextTick()

        let cards = wrapper.findAll('.vuln-group-card')
        // Default sort is severity check (HIGH vs HIGH) -> fall back to ID asc
        expect(cards[0]!.attributes('data-id')).toBe('CVE-2023-AAA')
        expect(cards[1]!.attributes('data-id')).toBe('CVE-2023-BBB')

        // Toggle sort order (should still use ID asc for tie-breaker)
        await wrapper.find('button[title="Ascending"]').trigger('click')

        cards = wrapper.findAll('.vuln-group-card')
        // Severity desc (HIGH vs HIGH) -> tie-breaker ID asc
        expect(cards[0]!.attributes('data-id')).toBe('CVE-2023-AAA')
        expect(cards[1]!.attributes('data-id')).toBe('CVE-2023-BBB')
    })
})
