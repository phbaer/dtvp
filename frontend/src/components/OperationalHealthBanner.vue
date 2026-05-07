<script setup lang="ts">
import { computed, inject, ref } from 'vue'
import { AlertTriangle, X } from 'lucide-vue-next'
import { useOperationalHealth } from '../lib/useOperationalHealth'

const realRole = inject<any>('realRole', ref('ANALYST'))
const isReviewer = computed(() => realRole?.value === 'REVIEWER')

const {
    warningCount,
    warningSummaries,
    criticalWarningCount,
    checkedAtAgeLabel,
    overallSeverity,
    persistentWarningVisible,
    dismissPersistentWarning,
} = useOperationalHealth(isReviewer)
</script>

<template>
    <div
        v-if="isReviewer && persistentWarningVisible"
        data-testid="operational-health-banner"
        class="border-b backdrop-blur-xl"
        :class="overallSeverity === 'critical' ? 'border-red-500/20 bg-red-500/10' : 'border-amber-500/20 bg-amber-500/10'"
    >
        <div class="px-6 sm:px-8 py-3 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
            <div class="flex items-start gap-3 min-w-0">
                <div
                    class="mt-0.5 rounded-full p-2"
                    :class="overallSeverity === 'critical' ? 'bg-red-500/15 text-red-300' : 'bg-amber-500/15 text-amber-300'"
                >
                    <AlertTriangle :size="16" />
                </div>
                <div class="min-w-0">
                    <div class="flex flex-wrap items-center gap-2">
                        <h2
                            class="text-sm font-semibold"
                            :class="overallSeverity === 'critical' ? 'text-red-100' : 'text-amber-100'"
                        >
                            {{ overallSeverity === 'critical' ? 'Critical operational warnings are still active' : 'Operational warnings are still active' }}
                        </h2>
                        <span
                            class="rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider"
                            :class="overallSeverity === 'critical' ? 'border-red-500/30 bg-red-500/10 text-red-200' : 'border-amber-500/30 bg-amber-500/10 text-amber-200'"
                        >
                            {{ warningCount }} active
                        </span>
                        <span
                            v-if="criticalWarningCount > 0"
                            class="rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-red-200"
                        >
                            {{ criticalWarningCount }} critical
                        </span>
                        <span :class="['text-[11px]', overallSeverity === 'critical' ? 'text-red-200/80' : 'text-amber-200/80']">{{ checkedAtAgeLabel }}</span>
                    </div>
                    <p :class="['mt-1 text-xs', overallSeverity === 'critical' ? 'text-red-100/85' : 'text-amber-100/85']">
                        {{ overallSeverity === 'critical' ? 'At least one critical condition persisted across multiple health checks.' : 'These warnings persisted across multiple health checks.' }} Review the affected sections below.
                    </p>
                    <div class="mt-3 flex flex-wrap gap-2">
                        <router-link
                            v-for="warning in warningSummaries"
                            :key="warning.key"
                            :to="{ path: '/settings', hash: warning.target }"
                            :data-warning-target="warning.target"
                            class="rounded-full border bg-slate-950/40 px-3 py-1.5 text-xs transition-colors hover:bg-slate-950/60"
                            :class="overallSeverity === 'critical' ? 'border-red-400/30 text-red-100' : 'border-amber-400/30 text-amber-100'"
                        >
                            {{ warning.text }}
                        </router-link>
                    </div>
                </div>
            </div>
            <button
                type="button"
                @click="dismissPersistentWarning"
                class="self-start inline-flex items-center gap-1 rounded-full border border-white/10 bg-slate-950/30 px-3 py-1.5 text-xs transition-colors hover:bg-slate-950/50"
                :class="overallSeverity === 'critical' ? 'text-red-100' : 'text-amber-100'"
            >
                <X :size="12" />
                Dismiss
            </button>
        </div>
    </div>
</template>