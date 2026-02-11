import { describe, it, expect, beforeEach } from 'vitest'
import { mount, config } from '@vue/test-utils'
import { ref } from 'vue'
import VulnGroupCard from '../VulnGroupCard.vue'

// Mock types to satisfy linting
const createMockComponent = (uuid: string, name: string, version: string, paths: string[] | null) => ({
    component_uuid: uuid,
    component_name: name,
    component_version: version,
    usage_paths: paths,
    // Add missing properties required by AffectedVersion component type
    project_name: 'Project A',
    project_version: '1.0',
    project_uuid: 'p1',
    finding_uuid: 'f-' + uuid,
    vulnerability_uuid: 'v-test',
    analysis_state: 'NOT_SET',
    analysis_details: '',
    analysis_comments: [],
    is_suppressed: false
})

describe('VulnGroupCard Helper Logic', () => {
    beforeEach(() => {
        config.global.provide = {
            user: ref({ username: 'testuser', role: 'ADMIN' })
        }
    })

    it('handles duplicate component versions by merging usage paths', () => {
        const groupData = {
            id: 'CVE-TEST',
            affected_versions: [
                {
                    project_name: 'Project A',
                    project_version: '1.0',
                    project_uuid: 'p1',
                    components: [
                        createMockComponent('uuid-1', 'LibA', '1.0', ['path/a']),
                        createMockComponent('uuid-1', 'LibA', '1.0', ['path/b'])
                    ]
                }
            ]
        }

        const wrapper = mount(VulnGroupCard, {
            props: {
                group: groupData as any, // Type assertion to bypass strict validation if needed
            },
            global: {
                stubs: {
                    DependencyChainViewer: true
                }
            }
        })

        // Search text content for deduplication verification
        const cardText = wrapper.text()
        const matches = (cardText.match(/LibA 1.0/g) || []).length
        expect(matches).toBe(1)
    })

    it('handles missing usage paths gracefully', () => {
        const groupData = {
            id: 'CVE-TEST-2',
            affected_versions: [
                {
                    project_name: 'Project A',
                    project_version: '1.0',
                    project_uuid: 'p1',
                    components: [
                        createMockComponent('uuid-2', 'LibB', '2.0', null)
                    ]
                }
            ]
        }

        const wrapper = mount(VulnGroupCard, {
            props: {
                group: groupData as any,
            },
            global: {
                stubs: {
                    DependencyChainViewer: true
                }
            }
        })

        // Should not crash and show 1 instance
        const cardText = wrapper.text()
        expect(cardText).toContain('LibB 2.0')
    })
})
