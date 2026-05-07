<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref, watch } from 'vue'
import { AlertTriangle, CheckCircle2, HeartPulse } from 'lucide-vue-next'
import { getOperationalHealth } from '../lib/api'
import type { OperationalHealthSummary } from '../types'

const realRole = inject<any>('realRole', ref('ANALYST'))

const operationalHealth = ref<OperationalHealthSummary | null>(null)
const loading = ref(false)
const loadError = ref(false)
const pollTimer = ref<ReturnType<typeof setInterval> | null>(null)
const refreshInProgress = ref(false)
const now = ref(Date.now())

const warningCount = computed(() => {
    if (!operationalHealth.value) return 0
    return Object.values(operationalHealth.value.checks).filter(
        (check) => check.status === 'warning'
    ).length
})

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

const warningSummaries = computed(() => {
    if (!operationalHealth.value) return []
    return Object.entries(operationalHealth.value.checks)
        .filter(([, check]) => check.status === 'warning')
        .map(([key, check]) => ({
            key,
            target: warningTargets[key as keyof OperationalHealthSummary['checks']],
            text: buildWarningSummary(
                key as keyof OperationalHealthSummary['checks'],
                check as OperationalHealthSummary['checks'][keyof OperationalHealthSummary['checks']]
            ),
        }))
})

const firstWarningSummary = computed(() => {
    return warningSummaries.value[0]?.text ?? ''
})

const indicatorState = computed<'idle' | 'healthy' | 'warning' | 'error'>(() => {
    if (loading.value && !operationalHealth.value) return 'idle'
    if (loadError.value) return 'error'
    if (operationalHealth.value?.status === 'warning') return 'warning'
    if (operationalHealth.value?.status === 'ok') return 'healthy'
    return 'idle'
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
    const ageSeconds = Math.max(
        0,
        Math.floor((now.value - checkedAtDate.value.getTime()) / 1000)
    )
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

const indicatorClass = computed(() => {
    if (indicatorState.value === 'warning') {
        return 'bg-amber-500/10 text-amber-300 border-amber-500/30 hover:bg-amber-500/20'
    }
    if (indicatorState.value === 'healthy') {
        return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/20'
    }
    if (indicatorState.value === 'error') {
        return 'bg-red-500/10 text-red-300 border-red-500/30 hover:bg-red-500/20'
    }
    return 'bg-slate-950/20 text-slate-400 border-white/10 hover:bg-slate-950/30 hover:text-slate-200'
})

const indicatorIcon = computed(() => {
    if (indicatorState.value === 'warning') return AlertTriangle
    if (indicatorState.value === 'healthy') return CheckCircle2
    return HeartPulse
})

const refreshOperationalHealth = async () => {
    if (realRole?.value !== 'REVIEWER' || refreshInProgress.value) return

    refreshInProgress.value = true
    if (!operationalHealth.value) loading.value = true
    loadError.value = false
    try {
        operationalHealth.value = await getOperationalHealth()
    } catch (error) {
        console.error('Failed to fetch operational health', error)
        loadError.value = true
    } finally {
        loading.value = false
        refreshInProgress.value = false
    }
}

const startPolling = () => {
    if (pollTimer.value !== null) return
    pollTimer.value = globalThis.setInterval(() => {
        now.value = Date.now()
        if (typeof document === 'undefined' || document.visibilityState === 'visible') {
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

onMounted(() => {
    now.value = Date.now()
    if (realRole?.value === 'REVIEWER') {
        void refreshOperationalHealth()
        startPolling()
    }
})

onUnmounted(() => {
    stopPolling()
})

watch(realRole, (role) => {
    if (role === 'REVIEWER') {
        void refreshOperationalHealth()
        startPolling()
        return
    }
    stopPolling()
})
</script>

<template>
    <div v-if="realRole === 'REVIEWER'" class="relative group">
        <router-link
            to="/settings"
            data-testid="operational-health-indicator"
            class="relative h-8 px-3 inline-flex items-center gap-2 rounded-full border text-[11px] font-semibold uppercase tracking-widest transition-all whitespace-nowrap"
            :class="indicatorClass"
            :title="indicatorTitle"
        >
            <component :is="indicatorIcon" :size="14" />
            <span class="hidden lg:inline">Ops</span>
            <span>{{ indicatorLabel }}</span>
            <span class="hidden xl:inline text-[10px] font-medium normal-case tracking-normal opacity-80">
                {{ checkedAtAgeLabel }}
            </span>
            <span
                v-if="indicatorState === 'warning' && warningCount > 0"
                class="absolute -top-1 -right-1 min-w-[16px] h-4 flex items-center justify-center rounded-full bg-amber-500 text-[9px] font-bold text-white px-1"
            >
                {{ warningCount }}
            </span>
        </router-link>

        <div
            v-if="warningSummaries.length > 0"
            data-testid="operational-health-panel"
            class="pointer-events-none absolute left-0 top-full z-50 mt-2 hidden min-w-[320px] rounded-xl border border-amber-500/20 bg-gray-950/95 p-3 text-xs text-gray-200 shadow-2xl group-hover:block group-focus-within:block"
        >
            <div class="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-amber-300">
                <AlertTriangle :size="12" />
                Active Warnings
            </div>
            <div class="mb-3 text-[11px] text-gray-500">
                {{ checkedAtAgeLabel }}
            </div>
            <ul class="space-y-2">
                <li
                    v-for="warning in warningSummaries"
                    :key="warning.key"
                    class="list-none"
                >
                    <router-link
                        :to="{ path: '/settings', hash: warning.target }"
                        :data-warning-target="warning.target"
                        class="pointer-events-auto block rounded-lg border border-white/5 bg-white/[0.03] px-2.5 py-2 leading-relaxed transition-colors hover:border-amber-400/30 hover:bg-amber-500/10"
                    >
                        {{ warning.text }}
                    </router-link>
                </li>
            </ul>
        </div>
    </div>
</template>