<script setup lang="ts">
import { computed, inject, ref } from 'vue'
import { AlertTriangle, X } from 'lucide-vue-next'
import { useOperationalHealth } from '../lib/useOperationalHealth'

const realRole = inject<any>('realRole', ref('ANALYST'))
const isReviewer = computed(() => realRole?.value === 'REVIEWER')

const {
    warningCount,
    warningSummaries,
    checkedAtAgeLabel,
    persistentWarningVisible,
    dismissPersistentWarning,
} = useOperationalHealth(isReviewer)
</script>

<template>
    <div
        v-if="isReviewer && persistentWarningVisible"
        data-testid="operational-health-banner"
        class="border-b border-amber-500/20 bg-amber-500/10 backdrop-blur-xl"
    >
        <div class="px-6 sm:px-8 py-3 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
            <div class="flex items-start gap-3 min-w-0">
                <div class="mt-0.5 rounded-full bg-amber-500/15 p-2 text-amber-300">
                    <AlertTriangle :size="16" />
                </div>
                <div class="min-w-0">
                    <div class="flex flex-wrap items-center gap-2">
                        <h2 class="text-sm font-semibold text-amber-100">Operational warnings are still active</h2>
                        <span class="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-200">
                            {{ warningCount }} active
                        </span>
                        <span class="text-[11px] text-amber-200/80">{{ checkedAtAgeLabel }}</span>
                    </div>
                    <p class="mt-1 text-xs text-amber-100/85">
                        These warnings persisted across multiple health checks. Review the affected sections below.
                    </p>
                    <div class="mt-3 flex flex-wrap gap-2">
                        <router-link
                            v-for="warning in warningSummaries"
                            :key="warning.key"
                            :to="{ path: '/settings', hash: warning.target }"
                            :data-warning-target="warning.target"
                            class="rounded-full border border-amber-400/30 bg-slate-950/40 px-3 py-1.5 text-xs text-amber-100 transition-colors hover:bg-slate-950/60"
                        >
                            {{ warning.text }}
                        </router-link>
                    </div>
                </div>
            </div>
            <button
                type="button"
                @click="dismissPersistentWarning"
                class="self-start inline-flex items-center gap-1 rounded-full border border-white/10 bg-slate-950/30 px-3 py-1.5 text-xs text-amber-100 transition-colors hover:bg-slate-950/50"
            >
                <X :size="12" />
                Dismiss
            </button>
        </div>
    </div>
</template>