import { mount } from '@vue/test-utils'
import { computed, defineComponent, ref } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useApprovalConfirmation } from '../useApprovalConfirmation'

const harness = () => {
    const snapshot = ref('finding-1:revision-1:draft-1')
    const enabled = ref(true)
    let confirmation!: ReturnType<typeof useApprovalConfirmation>
    const wrapper = mount(defineComponent({
        setup() {
            confirmation = useApprovalConfirmation(computed(() => snapshot.value), computed(() => enabled.value))
            return {}
        }, template: '<div />',
    }))
    return { wrapper, snapshot, enabled, confirmation }
}

describe('inline approval confirmation', () => {
    beforeEach(() => vi.useFakeTimers())
    afterEach(() => vi.useRealTimers())

    it('requires the delay and a separate activation, and consumes approval only once', () => {
        const { wrapper, confirmation } = harness()
        confirmation.arm()
        expect(confirmation.consume()).toBe(false)
        vi.advanceTimersByTime(699)
        expect(confirmation.consume()).toBe(false)
        vi.advanceTimersByTime(1)
        expect(confirmation.armed.value).toBe(true)
        expect(confirmation.ready.value).toBe(true)
        expect(confirmation.consume()).toBe(true)
        expect(confirmation.consume()).toBe(false)
        wrapper.unmount()
    })

    it.each(['finding-2:revision-1:draft-1', 'finding-1:revision-2:draft-1', 'finding-1:revision-1:draft-2'])('invalidates the review when its context changes to %s', next => {
        const { wrapper, snapshot, confirmation } = harness()
        confirmation.arm()
        vi.advanceTimersByTime(700)
        snapshot.value = next
        expect(confirmation.armed.value).toBe(false)
        expect(confirmation.consume()).toBe(false)
        wrapper.unmount()
    })

    it('cancels on loading/lost eligibility, cancellation and unmount; an old timer cannot re-arm', () => {
        const { wrapper, enabled, confirmation } = harness()
        confirmation.arm()
        enabled.value = false
        vi.advanceTimersByTime(700)
        expect(confirmation.ready.value).toBe(false)
        enabled.value = true
        confirmation.arm()
        confirmation.cancel()
        vi.advanceTimersByTime(700)
        expect(confirmation.armed.value).toBe(false)
        confirmation.arm()
        wrapper.unmount()
        vi.advanceTimersByTime(700)
        expect(confirmation.ready.value).toBe(false)
    })
})
