import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'

// Partial mock of updates
const mockUpdateAssessment = vi.fn()
vi.mock('../../lib/api', () => ({
    updateAssessment: (...args: any[]) => mockUpdateAssessment(...args),
    getAssessmentDetails: vi.fn(),
    calculateScoreFromVector: (v: string) => 5.0 // dummy
}))

// Mock inject
const mockUser = { value: { username: 'testuser', role: 'USER' } }

describe('VulnGroupCard Tags', () => {
    beforeEach(() => {
        vi.clearAllMocks()
        mockUpdateAssessment.mockResolvedValue([{ status: 'success' }])
        mockUser.value.role = 'USER' // Reset role
    })

    const defaultGroup = {
        id: 'CVE-TEST',
        severity: 'HIGH',
        affected_versions: []
    }

    const mountCard = (props = {}) => {
        return mount(VulnGroupCard, {
            props: {
                group: defaultGroup,
                ...props
            },
            global: {
                provide: {
                    user: mockUser
                },
                stubs: {
                    DependencyChainViewer: true
                }
            }
        })
    }

    it('includes Rescored tag when score is changed', async () => {
        const wrapper = mountCard({
            group: {
                ...defaultGroup,
                // Set rescored_cvss to ensure initial state
                rescored_cvss: 5.0,
                affected_versions: [{
                    components: [{
                        analysis_details: '',
                        analysis_state: 'NOT_SET',
                        project_uuid: 'p1', component_uuid: 'c1', project_name: 'P1'
                    }]
                }]
            }
        })

        await wrapper.find('.cursor-pointer').trigger('click')
        await flushPromises()

        vi.spyOn(window, 'confirm').mockImplementation(() => true)
        vi.spyOn(window, 'alert').mockImplementation(() => { })

        await wrapper.find('button.bg-blue-600').trigger('click')
        await flushPromises()

        const payload = mockUpdateAssessment.mock.calls[0]![0]
        // Frontend should just send the tag for the current pending score
        expect(payload.details).toContain('[Rescored: 5]')
    })

    // Obsolete tests removed:
    // - updates Assessed By tag (Moved to backend)
    // - consolidates Rescored tags (Moved to backend)
    // - prefers user input (Frontend now just sends user input alongside existing text, backend merges)
    // - adds Reviewed By tag (Moved to backend)
})
