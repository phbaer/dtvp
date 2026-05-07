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

const warningCount = computed(() => {
    if (!operationalHealth.value) return 0
    return Object.values(operationalHealth.value.checks).filter(
        (check) => check.status === 'warning'
    ).length
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

const indicatorTitle = computed(() => {
    if (indicatorState.value === 'warning') {
        return `Operational health has ${warningCount.value} warning${warningCount.value === 1 ? '' : 's'}. Open Settings for details.`
    }
    if (indicatorState.value === 'healthy') {
        return 'Operational health is healthy. Open Settings for details.'
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
    <router-link
        v-if="realRole === 'REVIEWER'"
        to="/settings"
        data-testid="operational-health-indicator"
        class="relative h-8 px-3 inline-flex items-center gap-2 rounded-full border text-[11px] font-semibold uppercase tracking-widest transition-all whitespace-nowrap"
        :class="indicatorClass"
        :title="indicatorTitle"
    >
        <component :is="indicatorIcon" :size="14" />
        <span class="hidden lg:inline">Ops</span>
        <span>{{ indicatorLabel }}</span>
        <span
            v-if="indicatorState === 'warning' && warningCount > 0"
            class="absolute -top-1 -right-1 min-w-[16px] h-4 flex items-center justify-center rounded-full bg-amber-500 text-[9px] font-bold text-white px-1"
        >
            {{ warningCount }}
        </span>
    </router-link>
</template>