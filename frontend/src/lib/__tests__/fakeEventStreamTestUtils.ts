import { onUnmounted, ref } from 'vue'
import type { EventStreamStatus, ServerEvent } from '../eventStream'

/**
 * A stand-in for the `eventStream` module: a status ref the test sets and an
 * emitter the test fires. Use it from `vi.mock('…/eventStream', …)`.
 */
export function createFakeEventStreamModule() {
    const status = ref<EventStreamStatus>('idle')
    const handlers = new Map<string, Set<(event: ServerEvent) => void>>()
    const on = (types: string | string[], handler: (event: ServerEvent) => void) => {
        const list = Array.isArray(types) ? types : [types]
        for (const type of list) {
            if (!handlers.has(type)) handlers.set(type, new Set())
            handlers.get(type)!.add(handler)
        }
        return () => list.forEach(type => handlers.get(type)?.delete(handler))
    }
    const emit = (type: string, data: any = {}) => {
        const event: ServerEvent = { id: `t:${type}`, seq: 1, type, at: '', product: null, data }
        for (const handler of [...(handlers.get(type) || [])]) handler(event)
    }
    const eventStream = {
        status,
        start: () => undefined,
        stop: () => undefined,
        on,
        cursor: null,
    }
    const useServerEvents = (types: string | string[], handler: (event: ServerEvent) => void) => {
        const off = on(types, handler)
        onUnmounted(off)
    }
    const reset = () => {
        status.value = 'idle'
        handlers.clear()
    }
    return { eventStream, useServerEvents, emit, status, reset }
}
