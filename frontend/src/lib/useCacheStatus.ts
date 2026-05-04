import { computed, onMounted, onUnmounted, ref } from 'vue'
import { getCacheStatus } from './api'
import type { CacheStatus } from '../types'

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

    onMounted(() => {
        void refreshCacheStatus()

        cacheStatusTimer.value = globalThis.setInterval(() => {
            now.value = Date.now()
            if (typeof document === 'undefined' || document.visibilityState === 'visible') {
                void refreshCacheStatus()
            }
        }, pollIntervalMs)

        if (typeof document !== 'undefined') {
            document.addEventListener('visibilitychange', handleVisibilityChange)
        }
    })

    onUnmounted(() => {
        if (cacheStatusTimer.value !== null) {
            globalThis.clearInterval(cacheStatusTimer.value)
        }
        if (typeof document !== 'undefined') {
            document.removeEventListener('visibilitychange', handleVisibilityChange)
        }
    })

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