import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import ConflictResolutionModal from '../ConflictResolutionModal.vue'


const mountModal = (canForce: boolean) => mount(ConflictResolutionModal, {
    props: {
        show: true,
        conflictData: [],
        canForce,
    },
    global: {
        stubs: { teleport: true },
    },
})


describe('ConflictResolutionModal', () => {
    it('does not offer force overwrite to analysts', () => {
        expect(mountModal(false).text()).not.toContain('Force Overwrite')
    })

    it('offers force overwrite to reviewers', () => {
        expect(mountModal(true).text()).toContain('Force Overwrite')
    })
})
