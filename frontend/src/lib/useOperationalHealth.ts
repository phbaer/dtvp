import { computed, onMounted, onUnmounted, ref, watch, type ComputedRef } from 'vue'
import { getOperationalHealth } from './api'
import type { OperationalHealthSummary } from '../types'

interface WarningSummary {
    key: keyof OperationalHealthSummary['checks']
    target: string
    text: string
    severity: 'ok' | 'warning' | 'critical'
}

const severityOrder: Record<WarningSummary['severity'], number> = {
    critical: 0,
    warning: 1,
    ok: 2,
}

const warningDescriptions: Record<keyof OperationalHealthSummary['checks'], string> = {
    pending_updates_backlog: 'Pending DT updates backlog',
    knowledge_store_write_backlog: 'Knowledge-store write backlog',
    knowledge_store_orphans: 'Orphaned retained assessments',
    knowledge_store_maintenance_freshness: 'Knowledge-store maintenance freshness',
}

const warningTargets: Record<keyof OperationalHealthSummary['checks'], string> = {
    pending_updates_backlog: '#cache-status',
    knowledge_store_write_backlog: '#cache-status',
    knowledge_store_orphans: '#knowledge-store-status',
    knowledge_store_maintenance_freshness: '#operational-health',
}

const operationalHealth = ref<OperationalHealthSummary | null>(null)
const loading = ref(false)
const loadError = ref(false)
const now = ref(Date.now())
const refreshInProgress = ref(false)
const pollTimer = ref<ReturnType<typeof setInterval> | null>(null)
const subscriberCount = ref(0)
const consecutiveWarningPolls = ref(0)
const dismissedWarningFingerprint = ref('')

const buildWarningSummary = (
    key: keyof OperationalHealthSummary['checks'],
    check: OperationalHealthSummary['checks'][keyof OperationalHealthSummary['checks']]
) => {
    const label = warningDescriptions[key]
    if (key === 'pending_updates_backlog' || key === 'knowledge_store_write_backlog') {
        const count = check.count ?? 0
        const oldestAge = check.oldest_age_seconds ?? 0
        return `${label}: ${count} queued, oldest ${Math.round(oldestAge)}s.`
    }
    if (key === 'knowledge_store_orphans') {
        return `${label}: ${check.count ?? 0} records detected.`
    }
    if (check.last_maintenance_at) {
        return `${label}: last run ${check.last_maintenance_at}.`
    }
    return `${label}: no successful maintenance run recorded.`
}

const warningSummaries = computed<WarningSummary[]>(() => {
    if (!operationalHealth.value) return []
    return Object.entries(operationalHealth.value.checks)
        .filter(([, check]) => check.status === 'warning')
        .map(([key, check]) => {
            const typedKey = key as keyof OperationalHealthSummary['checks']
            const typedCheck = check as OperationalHealthSummary['checks'][keyof OperationalHealthSummary['checks']]
            return {
                key: typedKey,
                target: warningTargets[typedKey],
                text: buildWarningSummary(typedKey, typedCheck),
                severity: typedCheck.severity,
            }
        })
        .sort((left, right) => severityOrder[left.severity] - severityOrder[right.severity])
})

const warningFingerprint = computed(() => warningSummaries.value.map((warning) => warning.key).join('|'))

const warningCount = computed(() => warningSummaries.value.length)

const firstWarningSummary = computed(() => warningSummaries.value[0]?.text ?? '')

const indicatorState = computed<'idle' | 'healthy' | 'warning' | 'error'>(() => {
    if (loading.value && !operationalHealth.value) return 'idle'
    if (loadError.value) return 'error'
    if (operationalHealth.value?.status === 'warning') return 'warning'
    if (operationalHealth.value?.status === 'ok') return 'healthy'
    return 'idle'
})

const overallSeverity = computed<'ok' | 'warning' | 'critical'>(() => {
    return operationalHealth.value?.severity ?? 'ok'
})

const criticalWarningCount = computed(() => {
    return warningSummaries.value.filter(
        (warning) => operationalHealth.value?.checks[warning.key].severity === 'critical'
    ).length
})

const indicatorLabel = computed(() => {
    if (indicatorState.value === 'warning') {
        return `${warningCount.value} warning${warningCount.value === 1 ? '' : 's'}`
    }
    if (indicatorState.value === 'healthy') return 'Healthy'
    if (indicatorState.value === 'error') return 'Unknown'
    return 'Checking'
})

const checkedAtDate = computed(() => {
    if (!operationalHealth.value?.checked_at) return null
    const parsed = new Date(operationalHealth.value.checked_at)
    return Number.isNaN(parsed.getTime()) ? null : parsed
})

const checkedAtAgeLabel = computed(() => {
    if (!checkedAtDate.value) return 'freshness unknown'
    const ageSeconds = Math.max(0, Math.floor((now.value - checkedAtDate.value.getTime()) / 1000))
    if (ageSeconds < 60) {
        return `checked ${ageSeconds}s ago`
    }
    const minutes = Math.floor(ageSeconds / 60)
    if (minutes < 60) {
        return `checked ${minutes}m ago`
    }
    const hours = Math.floor(minutes / 60)
    return `checked ${hours}h ago`
})

const indicatorTitle = computed(() => {
    if (indicatorState.value === 'warning') {
        return `Operational health has ${warningCount.value} warning${warningCount.value === 1 ? '' : 's'}. ${checkedAtAgeLabel.value}. ${firstWarningSummary.value} Open Settings for details.`
    }
    if (indicatorState.value === 'healthy') {
        return `Operational health is healthy, ${checkedAtAgeLabel.value}. Open Settings for details.`
    }
    if (indicatorState.value === 'error') {
        return 'Operational health is unavailable. Open Settings to retry.'
    }
    return 'Checking operational health.'
})

const persistentWarningVisible = computed(() => {
    return (
        consecutiveWarningPolls.value >= 2
        && warningCount.value > 0
        && dismissedWarningFingerprint.value !== warningFingerprint.value
    )
})

const refreshOperationalHealth = async () => {
    if (refreshInProgress.value) return

    refreshInProgress.value = true
    if (!operationalHealth.value) loading.value = true
    loadError.value = false
    try {
        const nextHealth = await getOperationalHealth()
        operationalHealth.value = nextHealth
        if (nextHealth.status === 'warning') {
            consecutiveWarningPolls.value += 1
        } else {
            consecutiveWarningPolls.value = 0
            dismissedWarningFingerprint.value = ''
        }
    } catch (error) {
        console.error('Failed to fetch operational health', error)
        loadError.value = true
    } finally {
        loading.value = false
        refreshInProgress.value = false
    }
}

const ensurePolling = () => {
    if (pollTimer.value !== null) return
    pollTimer.value = globalThis.setInterval(() => {
        now.value = Date.now()
        if (
            typeof document === 'undefined'
            || document.visibilityState !== 'hidden'
        ) {
            void refreshOperationalHealth()
        }
    }, 30_000)
}

const stopPolling = () => {
    if (pollTimer.value !== null) {
        globalThis.clearInterval(pollTimer.value)
        pollTimer.value = null
    }
}

const dismissPersistentWarning = () => {
    dismissedWarningFingerprint.value = warningFingerprint.value
}

export function useOperationalHealth(isEnabled: ComputedRef<boolean>) {
    const isSubscribed = ref(false)

    const subscribe = () => {
        if (isSubscribed.value) return
        now.value = Date.now()
        subscriberCount.value += 1
        isSubscribed.value = true
        void refreshOperationalHealth()
        ensurePolling()
    }

    const unsubscribe = () => {
        if (!isSubscribed.value) return
        subscriberCount.value = Math.max(0, subscriberCount.value - 1)
        isSubscribed.value = false
        if (subscriberCount.value === 0) {
            stopPolling()
        }
    }

    onMounted(() => {
        if (isEnabled.value) {
            subscribe()
        }
    })

    onUnmounted(() => {
        unsubscribe()
    })

    watch(isEnabled, (enabled) => {
        if (enabled) {
            subscribe()
            return
        }
        unsubscribe()
    })

    return {
        operationalHealth,
        loading,
        loadError,
        warningCount,
        criticalWarningCount,
        warningSummaries,
        firstWarningSummary,
        indicatorState,
        overallSeverity,
        indicatorLabel,
        checkedAtAgeLabel,
        indicatorTitle,
        persistentWarningVisible,
        refreshOperationalHealth,
        dismissPersistentWarning,
    }
}