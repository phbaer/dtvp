<script setup lang="ts">
import { computed, inject, ref } from 'vue'
import { AlertTriangle, CheckCircle2, HeartPulse } from 'lucide-vue-next'
import { useOperationalHealth } from '../lib/useOperationalHealth'

const realRole = inject<any>('realRole', ref('ANALYST'))

const isReviewer = computed(() => realRole?.value === 'REVIEWER')

const {
    warningCount,
    warningSummaries,
    indicatorState,
    indicatorLabel,
    checkedAtAgeLabel,
    indicatorTitle,
} = useOperationalHealth(isReviewer)

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