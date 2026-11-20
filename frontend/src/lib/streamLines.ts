/**
 * Line reader shared by the streams the backend sends: the task progress
 * streams (one JSON document per line) and the app-wide event stream
 * (Server-Sent Events).
 */
export interface ReadLinesOptions {
    /** Reject when no chunk arrives within this time. */
    idleTimeoutMs?: number
    idleMessage?: string
    /** Stop reading when aborted; resolves without an error. */
    signal?: AbortSignal
}

export async function readStreamLines(
    body: ReadableStream<Uint8Array>,
    onLine: (line: string) => void | Promise<void>,
    opts: ReadLinesOptions = {},
): Promise<void> {
    const reader = body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    const onAbort = () => {
        void reader.cancel().catch(() => undefined)
    }
    opts.signal?.addEventListener('abort', onAbort)

    const emitLines = async () => {
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''
        for (const line of lines) {
            await onLine(line.endsWith('\r') ? line.slice(0, -1) : line)
        }
    }

    try {
        while (true) {
            if (opts.signal?.aborted) return
            let idleTimer: ReturnType<typeof setTimeout> | undefined
            let chunk: ReadableStreamReadResult<Uint8Array>
            try {
                if (opts.idleTimeoutMs && opts.idleTimeoutMs > 0) {
                    const idleTimeout = new Promise<never>((_resolve, reject) => {
                        idleTimer = setTimeout(() => {
                            reject(new Error(opts.idleMessage || 'Stream became idle'))
                        }, opts.idleTimeoutMs)
                    })
                    chunk = await Promise.race([reader.read(), idleTimeout])
                } else {
                    chunk = await reader.read()
                }
            } finally {
                if (idleTimer !== undefined) clearTimeout(idleTimer)
            }
            const { done, value } = chunk
            if (value) {
                buffer += decoder.decode(value, { stream: !done })
                await emitLines()
            }
            if (done) break
        }
        buffer += decoder.decode()
        if (buffer) {
            const rest = buffer
            buffer = ''
            await onLine(rest.endsWith('\r') ? rest.slice(0, -1) : rest)
        }
    } finally {
        opts.signal?.removeEventListener('abort', onAbort)
        await reader.cancel().catch(() => undefined)
    }
}
