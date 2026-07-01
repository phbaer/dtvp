import { afterEach, describe, expect, it, vi } from 'vitest'
import { effectScope, ref, type Ref } from 'vue'
import { useDebouncedValue, type DebouncedValue } from '../useDebouncedValue'

describe('useDebouncedValue', () => {
    afterEach(() => {
        vi.useRealTimers()
    })

    it('delays publishing source changes until the debounce window elapses', () => {
        vi.useFakeTimers()
        const source = ref('')
        const { value } = useDebouncedValue(source, { delayMs: 100 })

        source.value = 'cve'
        expect(value.value).toBe('')

        vi.advanceTimersByTime(99)
        expect(value.value).toBe('')

        vi.advanceTimersByTime(1)
        expect(value.value).toBe('cve')
    })

    it('keeps only the latest pending source value', () => {
        vi.useFakeTimers()
        const source = ref('')
        const { value } = useDebouncedValue(source, { delayMs: 100 })

        source.value = 'team:a'
        vi.advanceTimersByTime(60)
        source.value = 'team:app'
        vi.advanceTimersByTime(99)

        expect(value.value).toBe('')

        vi.advanceTimersByTime(1)
        expect(value.value).toBe('team:app')
    })

    it('can flush immediately for explicit actions', () => {
        vi.useFakeTimers()
        const source = ref('')
        const debounced = useDebouncedValue(source, { delayMs: 100 })

        source.value = 'component:core'
        debounced.flush()

        expect(debounced.value.value).toBe('component:core')
        vi.advanceTimersByTime(100)
        expect(debounced.value.value).toBe('component:core')
    })

    it('supports immediate publishing for selected values', () => {
        vi.useFakeTimers()
        const source = ref('initial')
        const { value } = useDebouncedValue(source, {
            delayMs: 100,
            immediateWhen: next => next.length === 0,
        })

        source.value = ''

        expect(value.value).toBe('')
    })

    it('cancels pending work when the effect scope stops', () => {
        vi.useFakeTimers()
        const scope = effectScope()
        let source!: Ref<string>
        let debounced!: DebouncedValue<string>

        scope.run(() => {
            source = ref('')
            debounced = useDebouncedValue(source, { delayMs: 100 })
        })

        source.value = 'late'
        scope.stop()
        vi.advanceTimersByTime(100)

        expect(debounced.value.value).toBe('')
    })
})
