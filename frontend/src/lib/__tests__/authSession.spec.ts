import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
    AUTH_EXPIRED_EVENT,
    consumeAuthReturnPath,
    notifyAuthExpired,
    rememberAuthReturnPath,
    resetAuthExpiredNotification,
} from '../authSession'

describe('authSession', () => {
    beforeEach(() => {
        window.sessionStorage.clear()
        resetAuthExpiredNotification()
    })

    it('notifies listeners once for a burst of expired requests', () => {
        const listener = vi.fn()
        window.addEventListener(AUTH_EXPIRED_EVENT, listener)

        notifyAuthExpired()
        notifyAuthExpired()

        expect(listener).toHaveBeenCalledTimes(1)
        window.removeEventListener(AUTH_EXPIRED_EVENT, listener)
    })

    it('round-trips a safe post-login route once', () => {
        rememberAuthReturnPath('/project/Example?vuln=CVE-1')

        expect(consumeAuthReturnPath()).toBe('/project/Example?vuln=CVE-1')
        expect(consumeAuthReturnPath()).toBeNull()
    })

    it('rejects external and login return paths', () => {
        rememberAuthReturnPath('//other.example/path')
        rememberAuthReturnPath('/login?expired=1')

        expect(consumeAuthReturnPath()).toBeNull()
    })
})
