export const AUTH_EXPIRED_EVENT = 'dtvp:auth-expired'

const AUTH_RETURN_PATH_KEY = 'dtvp:auth-return-path'
let expirationNotified = false

const safeReturnPath = (path: string): string | null => {
    const normalized = String(path || '').trim()
    if (!normalized.startsWith('/') || normalized.startsWith('//')) return null
    if (normalized === '/login' || normalized.startsWith('/login?')) return null
    return normalized
}

export const rememberAuthReturnPath = (path: string) => {
    const safePath = safeReturnPath(path)
    if (!safePath || typeof window === 'undefined') return
    window.sessionStorage?.setItem(AUTH_RETURN_PATH_KEY, safePath)
}

export const consumeAuthReturnPath = (): string | null => {
    if (typeof window === 'undefined') return null
    const stored = window.sessionStorage?.getItem(AUTH_RETURN_PATH_KEY) || ''
    window.sessionStorage?.removeItem(AUTH_RETURN_PATH_KEY)
    return safeReturnPath(stored)
}

export const notifyAuthExpired = () => {
    if (expirationNotified || typeof window === 'undefined') return
    expirationNotified = true
    window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT))
}

export const resetAuthExpiredNotification = () => {
    expirationNotified = false
}
