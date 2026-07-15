import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import BulkResolveIncompleteModal from '../BulkResolveIncompleteModal.vue'

vi.mock('../../lib/api', () => ({
    updateAssessment: vi.fn(),
}))

describe('BulkResolveIncompleteModal', () => {
    it('shows why each vulnerability is incomplete', async () => {
        const wrapper = mount(BulkResolveIncompleteModal, {
            props: {
                show: false,
                incompleteGroups: [{
                    id: 'CVE-2026-0001',
                    title: 'Incomplete coverage',
                    tags: ['Platform', 'Runtime'],
                    list_metadata: { lifecycle: 'INCOMPLETE' },
                    affected_versions: [{
                        project_name: 'Example',
                        project_version: '2.0.0',
                        project_uuid: 'project-1',
                        components: [
                            {
                                project_name: 'Example',
                                project_version: '2.0.0',
                                project_uuid: 'project-1',
                                component_name: 'library-a',
                                component_version: '1.0.0',
                                component_uuid: 'component-1',
                                vulnerability_uuid: 'vulnerability-1',
                                finding_uuid: 'finding-1',
                                analysis_state: 'EXPLOITABLE',
                                analysis_details: '--- [Team: Platform] [State: EXPLOITABLE] ---',
                                is_suppressed: false,
                            },
                            {
                                project_name: 'Example',
                                project_version: '2.0.0',
                                project_uuid: 'project-1',
                                component_name: 'library-b',
                                component_version: '1.0.0',
                                component_uuid: 'component-2',
                                vulnerability_uuid: 'vulnerability-1',
                                finding_uuid: 'finding-2',
                                analysis_state: 'NOT_SET',
                                analysis_details: '',
                                is_suppressed: false,
                            },
                        ],
                    }],
                }],
            },
        })

        await wrapper.setProps({ show: true })

        const reasons = wrapper.get('[data-testid="sync-reasons-CVE-2026-0001"]')
        expect(reasons.text()).toContain('Missing team assessments')
        expect(reasons.text()).toContain('Runtime')
        expect(reasons.text()).toContain('Unassessed findings')
        expect(reasons.text()).toContain('1 of 2 finding instances')
        expect(reasons.text()).toContain('Missing global assessment')
    })
})
