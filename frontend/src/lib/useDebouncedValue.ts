import { onScopeDispose, ref, watch, type Ref } from 'vue'

export interface DebouncedValueOptions<T> {
    delayMs?: number
    immediateWhen?: (value: T, previousValue: T | undefined) => boolean
}

export interface DebouncedValue<T> {
    value: Ref<T>
    flush: () => void
    cancel: () => void
}

export const useDebouncedValue = <T>(
    source: Ref<T>,
    {
        delayMs = 120,
        immediateWhen,
    }: DebouncedValueOptions<T> = {},
): DebouncedValue<T> => {
    const value = ref(source.value) as Ref<T>
    let timer: ReturnType<typeof setTimeout> | null = null

    const cancel = () => {
        if (!timer) return
        clearTimeout(timer)
        timer = null
    }

    const flush = () => {
        cancel()
        value.value = source.value
    }

    watch(source, (nextValue, previousValue) => {
        if (immediateWhen?.(nextValue, previousValue)) {
            flush()
            return
        }

        cancel()
        timer = setTimeout(() => {
            timer = null
            value.value = nextValue
        }, Math.max(0, delayMs))
    }, { flush: 'sync' })

    onScopeDispose(cancel, true)

    return {
        value,
        flush,
        cancel,
    }
}
