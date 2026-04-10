import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import VulnGroupCard from '../VulnGroupCard.vue'

// Mock icons
vi.mock('lucide-vue-next', () => ({
    ChevronDown: { template: '<span />' },
    ChevronUp: { template: '<span />' },
    Shield: { template: '<span />' },
    Calculator: { template: '<span />' },
    CheckCircle: { template: '<span />' },
    ExternalLink: { template: '<span />' },
    Box: { template: '<span />' },
    ShieldAlert: { template: '<span />' },
    RefreshCw: { template: '<span />' },
    AlertTriangle: { template: '<span />' },
    RotateCcw: { template: '<span />' },
    History: { template: '<span />' }
}))

vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(),
    getAssessmentDetails: vi.fn(() => Promise.resolve([]))
}))

describe('VulnGroupCard Severity Colors', () => {
    it('renders MEDIUM severity color correctly', async () => {
        const mediumGroup = {
            id: 'V1',
            severity: 'MEDIUM',
            affected_versions: [],
            cvss: 0,
            cvss_score: 0,
            tags: []
        }
        const wrapper = mount(VulnGroupCard, { props: { group: mediumGroup } })

        const badge = wrapper.find('.ring-1')
        expect(badge.classes()).toContain('bg-yellow-600')
    })
})
