import {
    computed,
    onActivated,
    onDeactivated,
    onMounted,
    onUnmounted,
    ref,
    watch,
} from 'vue'
import { getCacheStatus } from './api'
import { eventStream, useServerEvents } from './eventStream'
import type { CacheStatus } from '../types'

// While the live-update stream is up, events trigger refetches; a background
// refresh announces itself with `cache.refreshed`. A slow safety refetch stays
// for changes that publish no event yet (ADR 0004, step 5).
const LIVE_SAFETY_REFRESH_MS = 300_000
const CLOCK_TICK_MS = 30_000
const EVENT_DEBOUNCE_MS = 1_000
const CACHE_STATUS_EVENTS = [
    'hello',
    'resync',
    'projects.changed',
    'source.state',
    'export.state',
    'assessments.changed',
    'cache.refreshed',
]

interface UseCacheStatusOptions {
    pollIntervalMs?: number
}

export function useCacheStatus({ pollIntervalMs = 30_000 }: UseCacheStatusOptions = {}) {
    const cacheStatus = ref<CacheStatus | null>(null)
    const cacheStatusLoading = ref(false)
    const cacheStatusError = ref('')
    const now = ref(Date.now())
    const cacheStatusTimer = ref<ReturnType<typeof setInterval> | null>(null)
    const cacheStatusRefreshInProgress = ref(false)
    let visibilityListenerAttached = false
    let active = false
    let clockTimer: ReturnType<typeof setInterval> | null = null
    let eventDebounce: ReturnType<typeof setTimeout> | null = null

    const cacheLastRefreshedDate = computed(() => {
        if (!cacheStatus.value?.last_refreshed_at) return null
        const date = new Date(cacheStatus.value.last_refreshed_at)
        return Number.isNaN(date.getTime()) ? null : date
    })

    const cacheAgeSeconds = computed(() => {
        if (!cacheLastRefreshedDate.value) return null
        return Math.max(0, Math.floor((now.value - cacheLastRefreshedDate.value.getTime()) / 1000))
    })

    const cacheAgeLabel = computed(() => {
        if (cacheAgeSeconds.value === null) return ''
        if (cacheAgeSeconds.value < 60) {
            return '< 1 min ago'
        }
        const minutes = Math.floor(cacheAgeSeconds.value / 60)
        if (minutes < 60) {
            return `${minutes}m ago`
        }
        const hours = Math.floor(minutes / 60)
        return `${hours}h ago`
    })

    const cacheStatusText = computed(() => {
        if (cacheStatusLoading.value && !cacheStatus.value) {
            return 'Loading…'
        }
        if (!cacheStatus.value) {
            return cacheStatusError.value || 'Unknown'
        }

        const age = cacheAgeLabel.value ? `updated ${cacheAgeLabel.value}` : 'updated Unknown'
        const statusLabel = cacheStatus.value.fully_cached ? 'Cache in sync' : 'Partially cached'
        return `${statusLabel}\n${age}`
    })

    const cacheStatusState = computed<'cached' | 'partial' | 'unknown' | 'loading'>(() => {
        if (cacheStatusLoading.value && !cacheStatus.value) return 'loading'
        if (cacheStatusError.value || !cacheStatus.value) return 'unknown'
        return cacheStatus.value.fully_cached ? 'cached' : 'partial'
    })

    const cacheStatusLabel = computed(() => {
        if (cacheStatusLoading.value && !cacheStatus.value) return 'Loading…'
        if (!cacheStatus.value) return cacheStatusError.value || 'Cache out of sync'
        return cacheStatus.value.fully_cached ? 'Cache in sync' : 'Partially cached'
    })

    const cacheStatusAge = computed(() => {
        if (!cacheStatus.value) {
            return cacheStatusLoading.value ? '' : (cacheStatusError.value || '')
        }
        return cacheAgeLabel.value ? `updated ${cacheAgeLabel.value}` : 'updated Unknown'
    })

    const refreshCacheStatus = async () => {
        if (cacheStatusRefreshInProgress.value) return
        cacheStatusRefreshInProgress.value = true

        const showLoading = !cacheStatus.value
        if (showLoading) cacheStatusLoading.value = true
        cacheStatusError.value = ''
        try {
            cacheStatus.value = await getCacheStatus()
        } catch (err: any) {
            cacheStatusError.value = 'Unable to load cache freshness'
            console.error('Failed to fetch cache status:', err)
        } finally {
            if (showLoading) cacheStatusLoading.value = false
            cacheStatusRefreshInProgress.value = false
        }
    }

    const handleVisibilityChange = () => {
        now.value = Date.now()
        if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
            void refreshCacheStatus()
        }
    }

    const isVisible = () => typeof document === 'undefined' || document.visibilityState === 'visible'

    const scheduleCacheStatusPolling = () => {
        if (cacheStatusTimer.value !== null) {
            globalThis.clearInterval(cacheStatusTimer.value)
        }
        const interval = eventStream.status.value === 'live' ? LIVE_SAFETY_REFRESH_MS : pollIntervalMs
        cacheStatusTimer.value = globalThis.setInterval(() => {
            if (isVisible()) void refreshCacheStatus()
        }, interval)
    }

    const startCacheStatusPolling = () => {
        if (active) return
        active = true
        void refreshCacheStatus()
        scheduleCacheStatusPolling()
        clockTimer = globalThis.setInterval(() => {
            now.value = Date.now()
        }, CLOCK_TICK_MS)

        if (typeof document !== 'undefined' && !visibilityListenerAttached) {
            document.addEventListener('visibilitychange', handleVisibilityChange)
            visibilityListenerAttached = true
        }
    }

    const stopCacheStatusPolling = () => {
        active = false
        if (cacheStatusTimer.value !== null) {
            globalThis.clearInterval(cacheStatusTimer.value)
            cacheStatusTimer.value = null
        }
        if (clockTimer !== null) {
            globalThis.clearInterval(clockTimer)
            clockTimer = null
        }
        if (eventDebounce !== null) {
            globalThis.clearTimeout(eventDebounce)
            eventDebounce = null
        }
        if (typeof document !== 'undefined' && visibilityListenerAttached) {
            document.removeEventListener('visibilitychange', handleVisibilityChange)
            visibilityListenerAttached = false
        }
    }

    // Poll often only while no live stream is up.
    watch(() => eventStream.status.value, () => {
        if (active) scheduleCacheStatusPolling()
    })

    useServerEvents(CACHE_STATUS_EVENTS, () => {
        if (!active || eventDebounce !== null) return
        eventDebounce = globalThis.setTimeout(() => {
            eventDebounce = null
            now.value = Date.now()
            if (active && isVisible()) void refreshCacheStatus()
        }, EVENT_DEBOUNCE_MS)
    })

    onMounted(startCacheStatusPolling)
    onActivated(startCacheStatusPolling)
    onDeactivated(stopCacheStatusPolling)
    onUnmounted(stopCacheStatusPolling)

    return {
        cacheStatus,
        cacheStatusLoading,
        cacheStatusError,
        cacheStatusText,
        cacheStatusState,
        cacheStatusLabel,
        cacheStatusAge,
        refreshCacheStatus,
    }
}
