import { onBeforeUnmount, ref, watch, type ComputedRef } from 'vue'

/** Two deliberate activations of one unchanged approval, never a timed save. */
export function useApprovalConfirmation(fingerprint: ComputedRef<string>, enabled: ComputedRef<boolean>) {
    const armed = ref(false)
    const ready = ref(false)
    let reviewed = ''
    let availableAt = 0
    let timer: ReturnType<typeof setTimeout> | undefined
    const cancel = () => {
        if (timer !== undefined) clearTimeout(timer)
        timer = undefined
        armed.value = false
        ready.value = false
        reviewed = ''
    }
    const arm = () => {
        cancel()
        if (!enabled.value) return
        reviewed = fingerprint.value
        availableAt = Date.now() + 700
        armed.value = true
        timer = setTimeout(() => {
            timer = undefined
            if (armed.value && enabled.value && fingerprint.value === reviewed) ready.value = true
            else cancel()
        }, 700)
    }
    const consume = () => {
        if (!armed.value || !ready.value || Date.now() < availableAt || !enabled.value || fingerprint.value !== reviewed) return false
        cancel() // Consume synchronously, before the network request can start.
        return true
    }
    watch(() => armed.value ? fingerprint.value : null, value => {
        if (armed.value && value !== reviewed) cancel()
    }, { flush: 'sync' })
    watch(enabled, value => { if (!value) cancel() }, { flush: 'sync' })
    onBeforeUnmount(cancel)
    return { armed, ready, arm, consume, cancel }
}
