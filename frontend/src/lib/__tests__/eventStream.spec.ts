import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createEventStream, type EventStream, type ServerEvent } from '../eventStream'

const encoder = new TextEncoder()

/** A Web Locks stand-in: one holder per name, waiters in FIFO order. */
class FakeLockManager {
    private held = new Map<string, boolean>()
    private queues = new Map<string, Array<() => void>>()

    request(name: string, options: { signal?: AbortSignal }, callback: () => Promise<void>): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            let granted = false
            const grant = () => {
                granted = true
                this.held.set(name, true)
                Promise.resolve()
                    .then(callback)
                    .then(() => resolve(), reject)
                    .finally(() => this.release(name))
            }
            options.signal?.addEventListener('abort', () => {
                if (granted) return
                const queue = this.queues.get(name) || []
                this.queues.set(name, queue.filter(entry => entry !== grant))
                reject(new DOMException('Aborted', 'AbortError'))
            })
            if (!this.held.get(name)) grant()
            else this.queues.set(name, [...(this.queues.get(name) || []), grant])
        })
    }

    private release(name: string) {
        this.held.set(name, false)
        const queue = this.queues.get(name) || []
        const next = queue.shift()
        this.queues.set(name, queue)
        next?.()
    }
}

/** BroadcastChannels of one browser: a message reaches every other open
 * channel of the same name, never its sender. */
class FakeBus {
    private channels = new Set<FakeChannel>()
    channel(name: string) {
        const channel = new FakeChannel(this, name)
        this.channels.add(channel)
        return channel as unknown as BroadcastChannel
    }
    deliver(sender: FakeChannel, message: unknown) {
        for (const channel of this.channels) {
            if (channel === sender || channel.closed || channel.name !== sender.name) continue
            const data = structuredClone(message)
            queueMicrotask(() => {
                if (!channel.closed) channel.onmessage?.({ data } as MessageEvent)
            })
        }
    }
    remove(channel: FakeChannel) {
        this.channels.delete(channel)
    }
}

class FakeChannel {
    closed = false
    onmessage: ((event: MessageEvent) => void) | null = null
    private bus: FakeBus
    readonly name: string
    constructor(bus: FakeBus, name: string) {
        this.bus = bus
        this.name = name
    }
    postMessage(message: unknown) {
        if (this.closed) throw new Error('closed')
        this.bus.deliver(this, message)
    }
    close() {
        this.closed = true
        this.bus.remove(this)
    }
}

interface StreamCall {
    url: string
    push: (text: string) => void
    close: () => void
}

class Server {
    calls: StreamCall[] = []
    polls: string[] = []
    /** Responses for the next stream requests; default: 200 with an open stream. */
    next: Array<() => Response> = []
    pollBody: any = { boot_id: 'b', cursor: 'b:0', events: [], resync: null, more: false }

    /** Bodies of ``PUT /events/interest``, in order. */
    interest: Array<{ client_id: string; products: string[] }> = []

    fetch = vi.fn(async (url: string, init?: RequestInit) => {
        if (url.includes('/events/interest')) {
            this.interest.push(JSON.parse(String(init?.body)))
            return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
        }
        if (url.includes('/events/poll')) {
            this.polls.push(url)
            return new Response(JSON.stringify(this.pollBody), {
                status: 200,
                headers: { 'content-type': 'application/json' },
            })
        }
        let controller!: ReadableStreamDefaultController<Uint8Array>
        const body = new ReadableStream<Uint8Array>({
            start(c) {
                controller = c
            },
        })
        let closed = false
        const call: StreamCall = {
            url,
            push: text => {
                if (!closed) controller.enqueue(encoder.encode(text))
            },
            close: () => {
                if (!closed) {
                    closed = true
                    controller.close()
                }
            },
        }
        init?.signal?.addEventListener('abort', () => {
            if (!closed) {
                closed = true
                controller.error(new DOMException('Aborted', 'AbortError'))
            }
        })
        this.calls.push(call)
        const responder = this.next.shift()
        if (responder) return responder()
        return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
    })

    get streamCalls() {
        return this.calls.length
    }
    last() {
        return this.calls[this.calls.length - 1]
    }
}

const hello = (seq: number, boot = 'b') =>
    `id: ${boot}:${seq}\nevent: hello\ndata: ${JSON.stringify({ boot_id: boot, seq, build: 't', source: { dt: 'ok' } })}\n\n`

const frame = (seq: number, type: string, data: unknown, boot = 'b') =>
    `id: ${boot}:${seq}\nevent: ${type}\ndata: ${JSON.stringify({ seq, at: 't', type, product: null, data })}\n\n`

interface Tab {
    stream: EventStream
    onAuthExpired: ReturnType<typeof vi.fn>
    received: ServerEvent[]
}

function openTab(server: Server, options: { locks?: FakeLockManager | null; bus?: FakeBus | null; random?: number } = {}): Tab {
    const onAuthExpired = vi.fn()
    const stream = createEventStream({
        fetch: server.fetch as any,
        locks: (options.locks ?? null) as unknown as LockManager | null,
        createChannel: options.bus ? (name: string) => options.bus!.channel(name) : null,
        setTimeout: (fn, ms) => setTimeout(fn, ms),
        clearTimeout: id => clearTimeout(id),
        random: () => options.random ?? 0.5,
        now: () => Date.now(),
        apiBase: '/api',
        onAuthExpired,
    })
    const received: ServerEvent[] = []
    stream.on(['hello', 'resync', 'projects.changed', 'export.state'], event => received.push(event))
    return { stream, onAuthExpired, received }
}

const settle = () => vi.advanceTimersByTimeAsync(0)

describe('eventStream', () => {
    let server: Server
    const tabs: Tab[] = []
    const tab = (options: Parameters<typeof openTab>[1] = {}) => {
        const created = openTab(server, options)
        tabs.push(created)
        return created
    }

    beforeEach(() => {
        vi.useFakeTimers()
        server = new Server()
        vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    })

    afterEach(() => {
        for (const created of tabs.splice(0)) created.stream.stop()
        vi.useRealTimers()
        vi.restoreAllMocks()
    })

    it('holds one stream per browser and hands it over with the last cursor', async () => {
        const locks = new FakeLockManager()
        const bus = new FakeBus()
        const leader = tab({ locks, bus })
        const follower = tab({ locks, bus })
        leader.stream.start()
        follower.stream.start()
        await settle()
        expect(server.streamCalls).toBe(1)
        expect(server.last().url).toBe('/api/events')

        server.last().push(hello(1) + frame(2, 'projects.changed', { count: 2 }))
        await settle()

        expect(leader.stream.status.value).toBe('live')
        expect(follower.stream.status.value).toBe('live')
        expect(leader.received.map(event => event.type)).toEqual(['hello', 'projects.changed'])
        expect(follower.received.map(event => event.type)).toEqual(['hello', 'projects.changed'])
        expect(follower.received[1]).toMatchObject({ id: 'b:2', seq: 2, data: { count: 2 } })
        expect(follower.stream.cursor).toBe('b:2')

        leader.stream.stop()
        await settle()
        expect(server.streamCalls).toBe(2)
        expect(server.last().url).toBe('/api/events?since=b%3A2')
    })

    it('a tab that joins later learns the status from the leader', async () => {
        const locks = new FakeLockManager()
        const bus = new FakeBus()
        const leader = tab({ locks, bus })
        leader.stream.start()
        await settle()
        server.last().push(hello(1))
        await settle()

        const late = tab({ locks, bus })
        late.stream.start()
        await settle()
        expect(late.stream.status.value).toBe('live')
        expect(late.stream.cursor).toBe('b:1')
        expect(server.streamCalls).toBe(1)
    })

    it('parses multi-line data, comments, and frames split across chunks', async () => {
        const single = tab()
        single.stream.start()
        await settle()
        const call = server.last()
        call.push(hello(1))
        call.push(': hb\n\n')
        call.push('id: b:2\nevent: projects.ch')
        call.push('anged\ndata: {"seq":2,"at":"t",\ndata: "type":"projects.changed","product":null,"data":{"n":1}}\n')
        call.push('\n')
        call.push('id: b:3\nevent: projects.changed\ndata: not json\n\n')
        await settle()

        const changed = single.received.filter(event => event.type === 'projects.changed')
        expect(changed).toHaveLength(1)
        expect(changed[0]).toMatchObject({ id: 'b:2', seq: 2, data: { n: 1 } })
        // The skipped frame still moves the cursor.
        expect(single.stream.cursor).toBe('b:3')
    })

    it('backs off with full jitter and resets after hello', async () => {
        const single = tab({ random: 0.5 })
        server.next.push(
            () => new Response('no', { status: 500 }),
            () => new Response('no', { status: 502 }),
        )
        single.stream.start()
        await settle()
        expect(server.streamCalls).toBe(1)

        await vi.advanceTimersByTimeAsync(499)
        expect(server.streamCalls).toBe(1)
        await vi.advanceTimersByTimeAsync(1)
        expect(server.streamCalls).toBe(2)

        // Second failure: up to 2 s, here half of it.
        await vi.advanceTimersByTimeAsync(999)
        expect(server.streamCalls).toBe(2)
        await vi.advanceTimersByTimeAsync(1)
        expect(server.streamCalls).toBe(3)

        server.last().push(hello(1))
        await settle()
        expect(single.stream.status.value).toBe('live')

        // A stream that ends quickly counts as a failure, again from 1 s.
        await vi.advanceTimersByTimeAsync(1000)
        server.last().close()
        await settle()
        expect(single.stream.status.value).toBe('connecting')
        await vi.advanceTimersByTimeAsync(499)
        expect(server.streamCalls).toBe(3)
        await vi.advanceTimersByTimeAsync(1)
        expect(server.streamCalls).toBe(4)
    })

    it('reconnects within the rotation jitter after a server rotation and keeps the failure count', async () => {
        const single = tab({ random: 0.5 })
        single.stream.start()
        await settle()
        server.last().push(hello(1))
        await vi.advanceTimersByTimeAsync(10_000)
        server.last().close()
        await settle()

        // Spread over 5 s, so streams that rotate together do not return together.
        await vi.advanceTimersByTimeAsync(2_499)
        expect(server.streamCalls).toBe(1)
        await vi.advanceTimersByTimeAsync(1)
        expect(server.streamCalls).toBe(2)
        expect(server.last().url).toBe('/api/events?since=b%3A1')

        // The next failure is the first one.
        server.next.push(() => new Response('no', { status: 500 }))
        server.last().close()
        await settle()
        await vi.advanceTimersByTimeAsync(500)
        expect(server.streamCalls).toBe(3)
    })

    it('a 401 signs every tab out and does not reconnect', async () => {
        const locks = new FakeLockManager()
        const bus = new FakeBus()
        const leader = tab({ locks, bus })
        const follower = tab({ locks, bus })
        server.next.push(() => new Response('', { status: 401 }))
        leader.stream.start()
        follower.stream.start()
        await settle()

        expect(leader.onAuthExpired).toHaveBeenCalledTimes(1)
        expect(follower.onAuthExpired).toHaveBeenCalledTimes(1)
        expect(leader.stream.status.value).toBe('stopped')
        expect(follower.stream.status.value).toBe('stopped')
        await vi.advanceTimersByTimeAsync(120_000)
        expect(server.streamCalls).toBe(1)
    })

    it('an auth frame acts like a 401', async () => {
        const locks = new FakeLockManager()
        const bus = new FakeBus()
        const leader = tab({ locks, bus })
        const follower = tab({ locks, bus })
        leader.stream.start()
        follower.stream.start()
        await settle()
        server.last().push(hello(1) + 'event: auth\ndata: {"status":401}\n\n')
        await settle()

        expect(leader.onAuthExpired).toHaveBeenCalledTimes(1)
        expect(follower.onAuthExpired).toHaveBeenCalledTimes(1)
        await vi.advanceTimersByTimeAsync(120_000)
        expect(server.streamCalls).toBe(1)
    })

    it('waits for Retry-After plus jitter on 503 and 429', async () => {
        for (const [status, random, expected] of [[503, 0.5, 7_500], [429, 0, 5_000], [503, 1, 10_000]] as const) {
            server = new Server()
            const single = tab({ random })
            server.next.push(() => new Response('{}', { status, headers: { 'Retry-After': '5' } }))
            single.stream.start()
            await settle()
            await vi.advanceTimersByTimeAsync(expected - 1)
            expect(server.streamCalls).toBe(1)
            await vi.advanceTimersByTimeAsync(1)
            expect(server.streamCalls).toBe(2)
            single.stream.stop()
        }
    })

    it('counts a response whose headers never arrive as a failure and falls back to polling', async () => {
        const single = tab({ random: 0 })
        const hang = vi.fn((_url: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
        }))
        const original = server.fetch.getMockImplementation()!
        server.fetch.mockImplementation(async (url: string, init?: RequestInit) => {
            if (url.includes('/events/poll')) return original(url, init)
            return hang(url, init)
        })
        single.stream.start()
        await settle()
        expect(single.stream.status.value).toBe('connecting')

        await vi.advanceTimersByTimeAsync(2 * 35_000)
        expect(single.stream.status.value).toBe('connecting')
        expect(server.polls).toHaveLength(0)
        await vi.advanceTimersByTimeAsync(35_000 + 1_000)
        // Three timed-out attempts; the stream keeps retrying beside the polls.
        expect(hang).toHaveBeenCalledTimes(4)
        expect(single.stream.status.value).toBe('polling')
        expect(server.polls.length).toBeGreaterThan(0)
    })

    it('gives up a poll that hangs and schedules the next one', async () => {
        const single = tab({ random: 0 })
        const pollCalls: string[] = []
        server.fetch.mockImplementation((url: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
            if (url.includes('/events/poll')) pollCalls.push(url)
            init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
        }))
        vi.spyOn(console, 'warn').mockImplementation(() => {})
        single.stream.start()
        await settle()
        // Three stream attempts time out; polling starts and its first poll hangs.
        await vi.advanceTimersByTimeAsync(3 * 35_000 + 1_000)
        expect(single.stream.status.value).toBe('polling')
        expect(pollCalls).toHaveLength(1)

        // Without a poll timeout no second poll would ever be made.
        await vi.advanceTimersByTimeAsync(20_000 + 15_000 + 1_000)
        expect(pollCalls.length).toBeGreaterThanOrEqual(2)
        single.stream.stop()
    })

    it('an id without an event moves the cursor of every tab', async () => {
        const locks = new FakeLockManager()
        const bus = new FakeBus()
        const leader = tab({ locks, bus })
        const follower = tab({ locks, bus })
        leader.stream.start()
        follower.stream.start()
        await settle()
        server.last().push(hello(1) + 'id: b:9\n: hb\n\n')
        await settle()

        expect(leader.stream.cursor).toBe('b:9')
        expect(follower.stream.cursor).toBe('b:9')
        expect(leader.received.map(event => event.type)).toEqual(['hello'])
        expect(console.warn).not.toHaveBeenCalled()

        leader.stream.stop()
        await settle()
        expect(server.last().url).toBe('/api/events?since=b%3A9')
    })

    it('keeps instances under different context paths apart', async () => {
        const locks = new FakeLockManager()
        const bus = new FakeBus()
        const make = (apiBase: string) => {
            const onAuthExpired = vi.fn()
            const stream = createEventStream({
                fetch: server.fetch as any,
                locks: locks as unknown as LockManager,
                createChannel: (name: string) => bus.channel(name),
                setTimeout: (fn, ms) => setTimeout(fn, ms),
                clearTimeout: id => clearTimeout(id),
                random: () => 0.5,
                now: () => Date.now(),
                apiBase,
                onAuthExpired,
            })
            tabs.push({ stream, onAuthExpired, received: [] })
            return { stream, onAuthExpired }
        }
        const a = make('/a/api')
        const b = make('/b/api')
        a.stream.start()
        b.stream.start()
        await settle()

        // Both are leaders of their own instance.
        expect(server.calls.map(call => call.url).sort()).toEqual(['/a/api/events', '/b/api/events'])

        a.stream.stop('logout')
        await settle()
        expect(b.onAuthExpired).not.toHaveBeenCalled()
        expect(b.stream.status.value).not.toBe('stopped')
    })

    it('polls after three failures and returns to the stream on hello', async () => {
        const single = tab({ random: 0.5 })
        server.next.push(
            () => new Response('', { status: 500 }),
            () => new Response('', { status: 500 }),
            () => new Response('', { status: 500 }),
        )
        server.pollBody = {
            boot_id: 'b',
            cursor: 'b:7',
            events: [{ seq: 7, at: 't', type: 'export.state', product: null, data: { failed: 4 } }],
            resync: null,
            more: false,
        }
        single.stream.start()
        await settle() // failure 1
        await vi.advanceTimersByTimeAsync(500) // failure 2
        await vi.advanceTimersByTimeAsync(1000) // failure 3
        await vi.advanceTimersByTimeAsync(1) // the first poll runs at once
        expect(server.streamCalls).toBe(3)
        expect(single.stream.status.value).toBe('polling')
        expect(server.polls).toEqual(['/api/events/poll'])

        const exportEvents = single.received.filter(event => event.type === 'export.state')
        expect(exportEvents).toHaveLength(1)
        expect(exportEvents[0]).toMatchObject({ id: 'b:7', data: { failed: 4 } })
        expect(single.stream.cursor).toBe('b:7')

        server.pollBody = { ...server.pollBody, events: [] }
        await vi.advanceTimersByTimeAsync(15_000)
        expect(server.polls).toEqual(['/api/events/poll', '/api/events/poll?since=b%3A7'])

        // The stream is retried meanwhile (0.5 * 4 s); it works now.
        expect(server.streamCalls).toBe(4)
        server.last().push(hello(8))
        await settle()
        expect(single.stream.status.value).toBe('live')
        const polls = server.polls.length
        await vi.advanceTimersByTimeAsync(60_000)
        expect(server.polls.length).toBe(polls)
    })

    it('reconnects after 35 seconds without data', async () => {
        const single = tab({ random: 0.5 })
        single.stream.start()
        await settle()
        server.last().push(hello(1))
        await settle()
        await vi.advanceTimersByTimeAsync(34_999)
        expect(server.streamCalls).toBe(1)
        await vi.advanceTimersByTimeAsync(1)
        expect(single.stream.status.value).toBe('connecting')
        await vi.advanceTimersByTimeAsync(500)
        expect(server.streamCalls).toBe(2)
    })

    it('without locks or a channel every tab holds its own stream', async () => {
        tab().stream.start()
        tab().stream.start()
        await settle()
        expect(server.streamCalls).toBe(2)
    })

    it('a logout stops every tab', async () => {
        const locks = new FakeLockManager()
        const bus = new FakeBus()
        const leader = tab({ locks, bus })
        const follower = tab({ locks, bus })
        leader.stream.start()
        follower.stream.start()
        await settle()
        server.last().push(hello(1))
        await settle()

        follower.stream.stop('logout')
        await settle()
        expect(follower.onAuthExpired).not.toHaveBeenCalled()
        expect(leader.onAuthExpired).toHaveBeenCalledTimes(1)
        expect(leader.stream.status.value).toBe('stopped')
        await vi.advanceTimersByTimeAsync(60_000)
        expect(server.streamCalls).toBe(1)
    })

    it('start is idempotent and unsubscribing stops delivery', async () => {
        const single = tab()
        const seen: string[] = []
        const off = single.stream.on('projects.changed', event => seen.push(event.id))
        single.stream.start()
        single.stream.start()
        await settle()
        expect(server.streamCalls).toBe(1)
        server.last().push(hello(1) + frame(2, 'projects.changed', {}))
        await settle()
        off()
        server.last().push(frame(3, 'projects.changed', {}))
        await settle()
        expect(seen).toEqual(['b:2'])
    })
    describe('product interest', () => {
        const lastInterest = () => server.interest[server.interest.length - 1]

        it('sends the union of the tabs as one lease, renewed while not empty', async () => {
            const locks = new FakeLockManager()
            const bus = new FakeBus()
            const leader = tab({ locks, bus })
            const other = tab({ locks, bus })
            leader.stream.setInterest(['App'])
            other.stream.setInterest(['Lib', ' Lib ', ''])
            leader.stream.start()
            other.stream.start()
            await settle()

            expect(lastInterest()).toMatchObject({ products: ['App', 'Lib'] })
            expect(new Set(server.interest.map(body => body.client_id)).size).toBe(1)
            const sent = server.interest.length

            // Nothing changed: renewed once a minute, not more.
            await vi.advanceTimersByTimeAsync(30_000)
            expect(server.interest.length).toBe(sent)
            await vi.advanceTimersByTimeAsync(31_000)
            expect(server.interest.length).toBe(sent + 1)
            expect(lastInterest().products).toEqual(['App', 'Lib'])
        })

        it('follows tabs that change, leave or go silent', async () => {
            const locks = new FakeLockManager()
            const bus = new FakeBus()
            const leader = tab({ locks, bus })
            const leaving = tab({ locks, bus })
            const silent = tab({ locks, bus })
            leader.stream.setInterest(['App'])
            leaving.stream.setInterest(['Lib'])
            silent.stream.setInterest(['Tool'])
            leader.stream.start()
            leaving.stream.start()
            let silentChannel: { postMessage: (message: unknown) => void } | null = null
            const open = bus.channel.bind(bus)
            bus.channel = (name: string) => {
                const channel = open(name)
                silentChannel = channel as any
                return channel
            }
            silent.stream.start()
            bus.channel = open
            await settle()
            expect(lastInterest().products).toEqual(['App', 'Lib', 'Tool'])

            leaving.stream.setInterest(['Other'])
            await settle()
            expect(lastInterest().products).toEqual(['App', 'Other', 'Tool'])

            leaving.stream.stop()  // says goodbye
            await settle()
            expect(lastInterest().products).toEqual(['App', 'Tool'])

            // The silent tab stops reporting (its page froze): no goodbye,
            // its messages no longer arrive; the leader drops it after 2 minutes.
            silentChannel!.postMessage = () => undefined
            await vi.advanceTimersByTimeAsync(181_000)
            expect(lastInterest().products).toEqual(['App'])
        })

        it('starts a new lease with a new leader and ends the old one', async () => {
            const locks = new FakeLockManager()
            const bus = new FakeBus()
            const first = tab({ locks, bus })
            const second = tab({ locks, bus })
            first.stream.setInterest(['App'])
            second.stream.setInterest(['Lib'])
            first.stream.start()
            second.stream.start()
            await settle()
            const firstTerm = lastInterest().client_id

            first.stream.stop()
            await settle()
            const ended = server.interest.find(body => body.client_id === firstTerm && body.products.length === 0)
            expect(ended).toBeDefined()
            expect(lastInterest().client_id).not.toBe(firstTerm)
            expect(lastInterest().products).toEqual(['Lib'])
        })

        it('sends nothing while no tab shows a product', async () => {
            const single = tab()
            single.stream.start()
            await settle()
            await vi.advanceTimersByTimeAsync(130_000)
            expect(server.interest).toEqual([])
        })
    })
})
