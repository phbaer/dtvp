/**
 * The app-wide live-update stream (`GET /api/events`, ADR 0004).
 *
 * One tab per browser and DTVP instance holds the stream: tabs elect a
 * leader with the Web Locks API and share events, the cursor, and the status
 * over a BroadcastChannel. Both names carry the API base, because locks and
 * channels are scoped to the origin and two instances may share one under
 * different context paths. When the leader's tab closes, the lock passes to
 * another tab, which resumes from the last cursor it saw. Without these APIs
 * each tab holds its own stream.
 *
 * The leader reconnects with full-jitter backoff (1-30 s), after a 503 or 429
 * at Retry-After plus up to the same time again, and within a few seconds
 * after a server rotation, so browsers do not return together. A response
 * whose headers do not arrive in time counts as a failure. After three
 * failures in a row it also polls `/api/events/poll` every 15 seconds until a
 * stream is live again. A 401 or an `auth` frame signs every tab out.
 */
import {
    onActivated,
    onDeactivated,
    onMounted,
    onUnmounted,
    ref,
    type Ref,
} from 'vue'
import { API_BASE } from './apiBase'
import { notifyAuthExpired } from './authSession'
import { readStreamLines } from './streamLines'

export type EventStreamStatus = 'idle' | 'connecting' | 'live' | 'polling' | 'stopped'

export interface ServerEvent<T = any> {
    id: string
    seq: number
    type: string
    at: string
    product: string | null
    data: T
}

type TimerId = ReturnType<typeof setTimeout>

export interface EventStreamDeps {
    fetch: (input: string, init?: RequestInit) => Promise<Response>
    locks?: LockManager | null
    createChannel?: ((name: string) => BroadcastChannel) | null
    setTimeout: (fn: () => void, ms: number) => TimerId
    clearTimeout: (id: TimerId) => void
    random: () => number
    now: () => number
    apiBase: string
    onAuthExpired: () => void
}

export type StopReason = 'logout' | 'auth' | 'manual'

export interface EventStream {
    status: Readonly<Ref<EventStreamStatus>>
    start(): void
    stop(reason?: StopReason): void
    on(types: string | string[], handler: (event: ServerEvent) => void): () => void
    readonly cursor: string | null
}

export const EVENT_LOCK_NAME = 'dtvp:events:leader'
export const EVENT_CHANNEL_NAME = 'dtvp:events'
/** The leader lock of one DTVP instance (its API base) on this origin. */
export const eventLockName = (apiBase: string) => `${EVENT_LOCK_NAME}:${apiBase}`
/** The BroadcastChannel of one DTVP instance (its API base) on this origin. */
export const eventChannelName = (apiBase: string) => `${EVENT_CHANNEL_NAME}:${apiBase}`
export const IDLE_TIMEOUT_MS = 35_000
/** A proxy that holds the response would otherwise keep `connect` waiting
 * until the server rotates the stream. */
export const HEADERS_TIMEOUT_MS = 35_000
export const ROTATION_MIN_MS = 10_000
export const MAX_BACKOFF_MS = 30_000
export const POLL_INTERVAL_MS = 15_000
/** A poll that hangs (a proxy holding it) is given up, and the next one
 * scheduled, instead of ending the fallback. */
export const POLL_TIMEOUT_MS = 20_000
export const FAILURES_BEFORE_POLLING = 3
const DEFAULT_RETRY_AFTER_MS = 30_000
export const ROTATION_JITTER_MS = 5_000

type ChannelMessage =
    | { v: 1; kind: 'sync?' }
    | { v: 1; kind: 'event'; event: ServerEvent; cursor: string | null }
    | { v: 1; kind: 'status'; status: EventStreamStatus; cursor: string | null }
    | { v: 1; kind: 'auth-expired' }
    | { v: 1; kind: 'logout' }

interface SseFrame {
    id?: string
    event?: string
    data: string[]
}

/** Feeds SSE lines; calls ``onFrame`` at every blank line that ends a frame. */
export function createSseParser(onFrame: (frame: SseFrame) => void) {
    let frame: SseFrame = { data: [] }
    let hasFields = false
    return (line: string) => {
        if (line === '') {
            if (hasFields) onFrame(frame)
            frame = { data: [] }
            hasFields = false
            return
        }
        if (line.startsWith(':')) return
        const colon = line.indexOf(':')
        const field = colon === -1 ? line : line.slice(0, colon)
        let value = colon === -1 ? '' : line.slice(colon + 1)
        if (value.startsWith(' ')) value = value.slice(1)
        if (field === 'data') frame.data.push(value)
        else if (field === 'id') frame.id = value
        else if (field === 'event') frame.event = value
        else return
        hasFields = true
    }
}

const SYNTHETIC_TYPES = new Set(['hello', 'resync'])

function toServerEvent(id: string, type: string, payload: any): ServerEvent {
    if (SYNTHETIC_TYPES.has(type)) {
        return {
            id,
            seq: Number(payload?.seq ?? 0),
            type,
            at: '',
            product: null,
            data: payload,
        }
    }
    return {
        id,
        seq: Number(payload?.seq ?? 0),
        type: String(payload?.type ?? type),
        at: String(payload?.at ?? ''),
        product: payload?.product ?? null,
        data: payload?.data,
    }
}

function parseRetryAfter(value: string | null): number {
    const seconds = Number(value)
    return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : DEFAULT_RETRY_AFTER_MS
}

export function createEventStream(deps: EventStreamDeps): EventStream {
    const status = ref<EventStreamStatus>('idle')
    const handlers = new Map<string, Set<(event: ServerEvent) => void>>()
    let cursor: string | null = null
    let started = false
    let generation = 0
    let isLeader = false
    let channel: BroadcastChannel | null = null
    let lockAbort: AbortController | null = null
    let releaseLeader: (() => void) | null = null
    let fetchAbort: AbortController | null = null
    let reconnectTimer: TimerId | null = null
    let pollTimer: TimerId | null = null
    let polling = false
    let failures = 0

    const post = (message: ChannelMessage) => {
        try {
            channel?.postMessage(message)
        } catch (error) {
            console.warn('Live update channel failed', error)
        }
    }

    const setStatus = (next: EventStreamStatus) => {
        status.value = next
        if (isLeader) post({ v: 1, kind: 'status', status: next, cursor })
    }

    const dispatch = (event: ServerEvent) => {
        for (const handler of [...(handlers.get(event.type) || [])]) {
            try {
                handler(event)
            } catch (error) {
                console.error('Live update handler failed', error)
            }
        }
    }

    const publish = (event: ServerEvent) => {
        if (isLeader) post({ v: 1, kind: 'event', event, cursor })
        dispatch(event)
    }

    const clearTimers = () => {
        if (reconnectTimer !== null) deps.clearTimeout(reconnectTimer)
        if (pollTimer !== null) deps.clearTimeout(pollTimer)
        reconnectTimer = null
        pollTimer = null
    }

    const expire = () => {
        post({ v: 1, kind: 'auth-expired' })
        deps.onAuthExpired()
        stop('auth')
    }

    // -- polling fallback --------------------------------------------------

    const schedulePoll = (delay: number) => {
        if (!polling) return
        if (pollTimer !== null) deps.clearTimeout(pollTimer)
        pollTimer = deps.setTimeout(() => {
            pollTimer = null
            void pollOnce()
        }, delay)
    }

    const pollOnce = async () => {
        const gen = generation
        let more = false
        const abort = new AbortController()
        const timer = deps.setTimeout(() => abort.abort(), POLL_TIMEOUT_MS)
        try {
            const query = cursor ? `?since=${encodeURIComponent(cursor)}` : ''
            const response = await deps.fetch(`${deps.apiBase}/events/poll${query}`, {
                credentials: 'include',
                headers: { Accept: 'application/json' },
                signal: abort.signal,
            })
            if (gen !== generation || !polling) return
            if (response.status === 401) {
                expire()
                return
            }
            if (response.ok) {
                const body = await response.json()
                if (gen !== generation || !polling) return
                if (body.resync) {
                    cursor = body.cursor ?? cursor
                    publish(toServerEvent(cursor || '', 'resync', {
                        seq: Number(String(body.cursor || '').split(':').pop() || 0),
                        reason: body.resync,
                    }))
                }
                for (const envelope of body.events || []) {
                    const id = `${body.boot_id}:${envelope.seq}`
                    cursor = id
                    publish(toServerEvent(id, String(envelope.type), envelope))
                }
                cursor = body.cursor ?? cursor
                more = Boolean(body.more)
            }
        } catch (error) {
            if (gen !== generation) return
            console.warn('Live update poll failed', error)
        } finally {
            deps.clearTimeout(timer)
        }
        if (gen === generation) schedulePoll(more ? 0 : POLL_INTERVAL_MS)
    }

    const startPolling = () => {
        if (polling) return
        polling = true
        setStatus('polling')
        schedulePoll(0)
    }

    const stopPolling = () => {
        polling = false
        if (pollTimer !== null) deps.clearTimeout(pollTimer)
        pollTimer = null
    }

    // -- the stream --------------------------------------------------------

    const scheduleReconnect = (delay: number) => {
        if (!started || !isLeader) return
        if (reconnectTimer !== null) deps.clearTimeout(reconnectTimer)
        reconnectTimer = deps.setTimeout(() => {
            reconnectTimer = null
            void connect()
        }, delay)
    }

    const backoff = () => deps.random() * Math.min(MAX_BACKOFF_MS, 1000 * 2 ** Math.max(0, failures - 1))

    const fail = (delay?: number) => {
        failures += 1
        if (failures >= FAILURES_BEFORE_POLLING) startPolling()
        else if (!polling) setStatus('connecting')
        scheduleReconnect(delay ?? backoff())
    }

    const handleFrame = (frame: SseFrame) => {
        if (frame.id) cursor = frame.id
        if (!frame.event && frame.data.length === 0) {
            // An id without an event (the heartbeat): the cursor moved past
            // events this user cannot see. Hand it to the other tabs.
            if (isLeader) post({ v: 1, kind: 'status', status: status.value, cursor })
            return
        }
        const type = frame.event || 'message'
        if (type === 'auth') {
            expire()
            return
        }
        let payload: any
        try {
            payload = JSON.parse(frame.data.join('\n'))
        } catch (error) {
            console.warn('Skipping a live update that is not JSON', error)
            return
        }
        const event = toServerEvent(frame.id || cursor || '', type, payload)
        if (type === 'hello') {
            failures = 0
            stopPolling()
            setStatus('live')
        }
        publish(event)
    }

    const connect = async () => {
        if (!started || !isLeader) return
        const gen = generation
        if (!polling) setStatus('connecting')
        fetchAbort?.abort()
        const abort = new AbortController()
        fetchAbort = abort
        const openedAt = deps.now()
        let headersTimer: TimerId | null = deps.setTimeout(() => {
            headersTimer = null
            abort.abort()
        }, HEADERS_TIMEOUT_MS)
        const clearHeadersTimer = () => {
            if (headersTimer !== null) deps.clearTimeout(headersTimer)
            headersTimer = null
        }
        try {
            const query = cursor ? `?since=${encodeURIComponent(cursor)}` : ''
            const response = await deps.fetch(`${deps.apiBase}/events${query}`, {
                credentials: 'include',
                headers: { Accept: 'text/event-stream' },
                signal: abort.signal,
            })
            clearHeadersTimer()
            if (gen !== generation) return
            if (response.status === 401) {
                expire()
                return
            }
            if (response.status === 503 || response.status === 429) {
                const retryAfter = parseRetryAfter(response.headers.get('Retry-After'))
                fail(retryAfter + deps.random() * retryAfter)
                return
            }
            if (!response.ok || !response.body) {
                fail()
                return
            }
            const parse = createSseParser(frame => {
                if (gen === generation) handleFrame(frame)
            })
            await readStreamLines(response.body, line => {
                if (gen === generation) parse(line)
            }, {
                idleTimeoutMs: IDLE_TIMEOUT_MS,
                idleMessage: 'Live update stream became idle',
                signal: abort.signal,
            })
            if (gen !== generation) return
            if (deps.now() - openedAt >= ROTATION_MIN_MS) {
                // The server rotates streams; come back at once.
                scheduleReconnect(deps.random() * ROTATION_JITTER_MS)
                return
            }
            fail()
        } catch (error) {
            if (gen !== generation) return
            console.warn('Live update stream failed', error)
            fail()
        } finally {
            clearHeadersTimer()
            abort.abort()
            if (fetchAbort === abort) fetchAbort = null
        }
    }

    const runLeader = (): Promise<void> => {
        if (!started) return Promise.resolve()
        isLeader = true
        return new Promise<void>(resolve => {
            releaseLeader = resolve
            void connect()
        })
    }

    // -- the channel -------------------------------------------------------

    const onChannelMessage = (message: ChannelMessage) => {
        if (!message || message.v !== 1) return
        switch (message.kind) {
            case 'sync?':
                if (isLeader) post({ v: 1, kind: 'status', status: status.value, cursor })
                break
            case 'event':
                if (!isLeader) {
                    cursor = message.cursor ?? cursor
                    dispatch(message.event)
                }
                break
            case 'status':
                if (!isLeader) {
                    cursor = message.cursor ?? cursor
                    status.value = message.status
                }
                break
            case 'auth-expired':
                deps.onAuthExpired()
                stop('auth')
                break
            case 'logout':
                stop('manual')
                deps.onAuthExpired()
                break
        }
    }

    // -- public ------------------------------------------------------------

    function start() {
        if (started) return
        started = true
        generation += 1
        failures = 0
        status.value = 'connecting'
        if (deps.locks && deps.createChannel) {
            channel = deps.createChannel(eventChannelName(deps.apiBase))
            channel.onmessage = (event: MessageEvent) => onChannelMessage(event.data)
            post({ v: 1, kind: 'sync?' })
            const abort = new AbortController()
            lockAbort = abort
            deps.locks
                .request(eventLockName(deps.apiBase), { signal: abort.signal }, () => runLeader())
                .catch(() => undefined)
        } else {
            void runLeader()
        }
    }

    function stop(reason: StopReason = 'manual') {
        if (!started) return
        if (reason === 'logout') post({ v: 1, kind: 'logout' })
        started = false
        generation += 1
        isLeader = false
        stopPolling()
        clearTimers()
        fetchAbort?.abort()
        fetchAbort = null
        releaseLeader?.()
        releaseLeader = null
        lockAbort?.abort()
        lockAbort = null
        if (channel) {
            channel.onmessage = null
            channel.close()
            channel = null
        }
        status.value = 'stopped'
    }

    function on(types: string | string[], handler: (event: ServerEvent) => void) {
        const list = Array.isArray(types) ? types : [types]
        for (const type of list) {
            if (!handlers.has(type)) handlers.set(type, new Set())
            handlers.get(type)!.add(handler)
        }
        return () => {
            for (const type of list) handlers.get(type)?.delete(handler)
        }
    }

    return {
        status,
        start,
        stop,
        on,
        get cursor() {
            return cursor
        },
    }
}

const browserLocks = (): LockManager | null =>
    typeof navigator !== 'undefined' && navigator.locks ? navigator.locks : null

export const eventStream: EventStream = createEventStream({
    fetch: (input, init) => globalThis.fetch(input, init),
    locks: browserLocks(),
    createChannel: typeof BroadcastChannel !== 'undefined'
        ? (name: string) => new BroadcastChannel(name)
        : null,
    setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
    clearTimeout: id => globalThis.clearTimeout(id),
    random: () => Math.random(),
    now: () => Date.now(),
    apiBase: API_BASE,
    onAuthExpired: () => notifyAuthExpired(),
})

/** Subscribe a component while it is mounted and active. */
export function useServerEvents(
    types: string | string[],
    handler: (event: ServerEvent) => void,
    stream: EventStream = eventStream,
): void {
    let off: (() => void) | null = null
    const subscribe = () => {
        if (!off) off = stream.on(types, handler)
    }
    const unsubscribe = () => {
        off?.()
        off = null
    }
    onMounted(subscribe)
    onActivated(subscribe)
    onDeactivated(unsubscribe)
    onUnmounted(unsubscribe)
}
