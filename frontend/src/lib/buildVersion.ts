import { shallowRef } from 'vue'
import { getVersion } from './api'

/**
 * Detects that the tab is running a bundle the server has since replaced.
 *
 * Long-lived tabs are the failure mode this guards against: the SPA never
 * reloads on its own, removed-but-still-routed endpoints keep answering 200,
 * and so a tab opened weeks ago can keep polling a superseded API forever.
 */

const UNKNOWN_BUILDS = new Set(['', 'unknown'])

/** Baked in at image build time by the Dockerfile's frontend stage. */
const BUNDLE_BUILD = String(import.meta.env.VITE_BUILD_COMMIT ?? '').trim()

/** Upper bound on how often the server is asked, regardless of tick rate. */
const CHECK_MIN_INTERVAL = 60000

const updateAvailable = shallowRef(false)

/** Server identity observed when this tab first booted. */
let loadedIdentity: string | null = null
let lastCheckedAt = 0
let checkInFlight: Promise<void> | null = null

export interface ServerIdentity {
    version: string
    build: string
}

function identityOf(identity: ServerIdentity): string {
    return `${identity.version}@${identity.build}`
}

/**
 * Feed a `/version` response into the staleness check.
 *
 * Two independent signals, because neither alone is reliable everywhere:
 *
 * - Build mismatch: the server reports a different commit than the one baked
 *   into this bundle. Works from the very first response, but only when both
 *   sides carry a real commit (they fall back to "unknown" outside CI).
 * - Identity drift: the server's version/build changed while this tab was
 *   open. Needs no build plumbing at all, and covers same-commit redeploys
 *   that a build comparison would miss.
 */
export function recordServerIdentity(identity: ServerIdentity): void {
    const current = identityOf(identity)
    if (loadedIdentity === null) {
        loadedIdentity = current
    }

    const buildMismatch =
        !UNKNOWN_BUILDS.has(BUNDLE_BUILD)
        && !UNKNOWN_BUILDS.has(identity.build)
        && identity.build !== BUNDLE_BUILD

    if (buildMismatch || current !== loadedIdentity) {
        // Latched: a rolling deploy can briefly serve either side, and a banner
        // that flickers away is worse than one that stays until the reload.
        updateAvailable.value = true
    }
}

/**
 * Ask the server for its identity, at most once per {@link CHECK_MIN_INTERVAL}.
 * Cheap enough to call on every queue poll tick.
 */
export async function checkForUpdate(force = false): Promise<void> {
    if (updateAvailable.value) return
    if (checkInFlight) return checkInFlight

    const now = Date.now()
    if (!force && now - lastCheckedAt < CHECK_MIN_INTERVAL) return

    checkInFlight = (async () => {
        try {
            lastCheckedAt = Date.now()
            recordServerIdentity(await getVersion())
        } catch {
            // Version probing is best-effort; a failed check must never break
            // the poll tick it is riding on.
        } finally {
            checkInFlight = null
        }
    })()

    return checkInFlight
}

/** Test seam — resets the module-level snapshot. */
export function resetBuildVersionState(): void {
    updateAvailable.value = false
    loadedIdentity = null
    lastCheckedAt = 0
    checkInFlight = null
}

export const buildVersionStore = {
    updateAvailable,
    bundleBuild: BUNDLE_BUILD,
    recordServerIdentity,
    checkForUpdate,
}
