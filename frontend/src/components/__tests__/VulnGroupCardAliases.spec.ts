import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'

// Mock dependencies
vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(),
    getAssessmentDetails: vi.fn(),
    calculateScoreFromVector: vi.fn(() => 5.0)
}))

const mockUser = { value: { username: 'testuser', role: 'USER' } }

describe('VulnGroupCard Aliases', () => {
    it('renders aliases when present', () => {
        const group = {
            id: 'CVE-2023-1234',
            severity: 'HIGH',
            aliases: ['GHSA-XXXX-XXXX', 'RUSTSEC-2023-0001'],
            affected_versions: []
        }

        const wrapper = mount(VulnGroupCard, {
            props: { group },
            global: {
                provide: {
                    user: mockUser
                },
                stubs: {
                    DependencyChainViewer: true,
                    RefreshCw: true,
                    ChevronDown: true,
                    ChevronUp: true,
                    Shield: true,
                    Calculator: true,
                    ExternalLink: true,
                    AlertTriangle: true
                }
            }
        })

        const text = wrapper.text()
        expect(text).toContain('CVE-2023-1234')
        expect(text).toContain('GHSA-XXXX-XXXX')
        expect(text).toContain('RUSTSEC-2023-0001')
    })
})
