import { afterEach, describe, expect, it, vi } from 'vitest'
import { readStreamLines } from '../streamLines'

const encoder = new TextEncoder()

function controllable() {
    let controller!: ReadableStreamDefaultController<Uint8Array>
    let cancelled = false
    const body = new ReadableStream<Uint8Array>({
        start(c) {
            controller = c
        },
        cancel() {
            cancelled = true
        },
    })
    return {
        body,
        push: (text: string) => controller.enqueue(encoder.encode(text)),
        close: () => controller.close(),
        get cancelled() {
            return cancelled
        },
    }
}

describe('readStreamLines', () => {
    afterEach(() => {
        vi.useRealTimers()
    })

    it('joins lines split across chunks, strips CR, and flushes the remainder', async () => {
        const source = controllable()
        const lines: string[] = []
        const done = readStreamLines(source.body, line => {
            lines.push(line)
        })
        source.push('first li')
        source.push('ne\r\nsecond\n\nthi')
        source.push('rd')
        source.close()
        await done
        expect(lines).toEqual(['first line', 'second', '', 'third'])
    })

    it('decodes multi-byte characters split between chunks', async () => {
        const bytes = encoder.encode('grüße\n')
        const body = new ReadableStream<Uint8Array>({
            start(c) {
                c.enqueue(bytes.slice(0, 3))
                c.enqueue(bytes.slice(3))
                c.close()
            },
        })
        const lines: string[] = []
        await readStreamLines(body, line => {
            lines.push(line)
        })
        expect(lines).toEqual(['grüße'])
    })

    it('rejects with the idle message when no chunk arrives in time and cancels the reader', async () => {
        vi.useFakeTimers()
        const source = controllable()
        const done = readStreamLines(source.body, () => undefined, {
            idleTimeoutMs: 1000,
            idleMessage: 'went idle',
        })
        const outcome = done.catch(error => error)
        source.push('a\n')
        await vi.advanceTimersByTimeAsync(900)
        source.push('b\n')
        await vi.advanceTimersByTimeAsync(900)
        expect(source.cancelled).toBe(false)
        await vi.advanceTimersByTimeAsync(200)
        const error = await outcome
        expect(error).toBeInstanceOf(Error)
        expect((error as Error).message).toBe('went idle')
        expect(source.cancelled).toBe(true)
    })

    it('stops without an error when its signal aborts', async () => {
        const source = controllable()
        const abort = new AbortController()
        const lines: string[] = []
        const done = readStreamLines(source.body, line => {
            lines.push(line)
        }, { signal: abort.signal })
        source.push('one\n')
        await new Promise(resolve => setTimeout(resolve, 0))
        abort.abort()
        await expect(done).resolves.toBeUndefined()
        expect(lines).toEqual(['one'])
        expect(source.cancelled).toBe(true)
    })

    it('cancels the reader when the line handler throws', async () => {
        const source = controllable()
        const done = readStreamLines(source.body, () => {
            throw new Error('bad line')
        })
        source.push('x\n')
        await expect(done).rejects.toThrow('bad line')
        expect(source.cancelled).toBe(true)
    })
})
