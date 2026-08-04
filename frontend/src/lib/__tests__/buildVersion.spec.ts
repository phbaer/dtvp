import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', () => ({
    getVersion: vi.fn(),
}))

const loadModule = async () => {
    const api = await import('../api')
    const buildVersion = await import('../buildVersion')
    return { api: api as any, buildVersion }
}

describe('buildVersion', () => {
    beforeEach(() => {
        vi.resetModules()
        vi.clearAllMocks()
    })

    it('stays quiet while the server keeps reporting the boot identity', async () => {
        const { buildVersion } = await loadModule()

        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'abc123' })
        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'abc123' })

        expect(buildVersion.buildVersionStore.updateAvailable.value).toBe(false)
    })

    it('flags an update when the server identity drifts after boot', async () => {
        const { buildVersion } = await loadModule()

        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'abc123' })
        buildVersion.recordServerIdentity({ version: '1.5.0', build: 'def456' })

        expect(buildVersion.buildVersionStore.updateAvailable.value).toBe(true)
    })

    it('flags a same-version redeploy that only changes the build commit', async () => {
        const { buildVersion } = await loadModule()

        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'abc123' })
        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'def456' })

        expect(buildVersion.buildVersionStore.updateAvailable.value).toBe(true)
    })

    it('stays latched once flagged, so a rolling deploy cannot clear the banner', async () => {
        const { buildVersion } = await loadModule()

        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'abc123' })
        buildVersion.recordServerIdentity({ version: '1.5.0', build: 'def456' })
        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'abc123' })

        expect(buildVersion.buildVersionStore.updateAvailable.value).toBe(true)
    })

    it('ignores an "unknown" build on either side rather than flagging spuriously', async () => {
        const { buildVersion } = await loadModule()

        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'unknown' })
        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'unknown' })

        expect(buildVersion.buildVersionStore.updateAvailable.value).toBe(false)
    })

    it('throttles repeated checks to one server call', async () => {
        const { api, buildVersion } = await loadModule()
        api.getVersion.mockResolvedValue({ version: '1.4.0', build: 'abc123' })

        await buildVersion.checkForUpdate()
        await buildVersion.checkForUpdate()
        await buildVersion.checkForUpdate()

        expect(api.getVersion).toHaveBeenCalledTimes(1)
    })

    it('stops probing once an update has been detected', async () => {
        const { api, buildVersion } = await loadModule()
        api.getVersion.mockResolvedValue({ version: '1.5.0', build: 'def456' })

        buildVersion.recordServerIdentity({ version: '1.4.0', build: 'abc123' })
        await buildVersion.checkForUpdate(true)
        expect(buildVersion.buildVersionStore.updateAvailable.value).toBe(true)

        await buildVersion.checkForUpdate(true)
        expect(api.getVersion).toHaveBeenCalledTimes(1)
    })

    it('swallows probe failures so the poll tick it rides on survives', async () => {
        const { api, buildVersion } = await loadModule()
        api.getVersion.mockRejectedValue(new Error('backend down'))

        await expect(buildVersion.checkForUpdate(true)).resolves.toBeUndefined()
        expect(buildVersion.buildVersionStore.updateAvailable.value).toBe(false)
    })
})
