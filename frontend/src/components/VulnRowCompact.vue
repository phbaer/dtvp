<script setup lang="ts">
import { computed } from 'vue'
import type { GroupedVuln } from '../types'
import type { VulnListItem } from '../lib/vulnListIndex'
import VulnGroupCardHeader from './VulnGroupCardHeader.vue'
import { CheckCircle, RefreshCw } from 'lucide-vue-next'

const props = defineProps<{
    item: VulnListItem
    selected?: boolean
    reloading?: boolean
    reloadError?: string
}>()

const emit = defineEmits<{
    (e: 'update', group?: GroupedVuln): void
    (e: 'update:assessment', data: any): void
    (e: 'select', group: GroupedVuln): void
    (e: 'reload', group: GroupedVuln): void
}>()

const listItem = computed(() => props.item)
const group = computed(() => props.item.group)

const normalizedTags = computed(() => listItem.value.normalizedTags)
const assessedTeams = computed(() => listItem.value.assessedTeams)
const dependencyRelationship = computed(() => listItem.value.dependencyRelationship)
const displayState = computed(() => listItem.value.lifecycle)
const technicalState = computed(() => listItem.value.technicalState)
const isPendingReview = computed(() => listItem.value.isPending)
const isAssessed = computed(() => listItem.value.isAssessed)
const stableRescoredScore = computed(() => listItem.value.stableRescoredScore)
const hasStableRescore = computed(() => listItem.value.hasStableRescore)
const currentDisplayScore = computed(() => listItem.value.currentDisplayScore)
const isRescoredOrModified = computed(() => listItem.value.isRescoredOrModified)

const cardStyle = computed(() => props.selected
    ? 'bg-blue-950/40 border-blue-500/70 ring-1 ring-blue-400/50'
    : 'bg-gray-800 border-gray-700 hover:bg-gray-700/80'
)

// Severity colours for badge
const severityHexMap: Record<string, string> = {
    'CRITICAL': '#dc2626', 'HIGH': '#ea580c', 'MEDIUM': '#ca8a04',
    'LOW': '#16a34a', 'INFO': '#2563eb', 'UNKNOWN': '#4b5563',
}

const hexToRgba = (hex: string, alpha: number) => {
    const cleaned = hex.replace('#', '').trim()
    const normalized = cleaned.length === 3
        ? cleaned.split('').map((char) => char + char).join('')
        : cleaned
    if (normalized.length !== 6) return hex
    const r = Number.parseInt(normalized.slice(0, 2), 16)
    const g = Number.parseInt(normalized.slice(2, 4), 16)
    const b = Number.parseInt(normalized.slice(4, 6), 16)
    return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

const originalSeverity = computed(() => listItem.value.originalSeverity)
const originalSeverityFill = computed(() => hexToRgba(severityHexMap[originalSeverity.value] ?? '#4b5563', 0.4))

const rescoredSeverity = computed(() => listItem.value.rescoredSeverity)
const rescoredSeverityHex = computed(() => {
    if (!rescoredSeverity.value) return hexToRgba('#6b7280', 0.4)
    return hexToRgba(severityHexMap[rescoredSeverity.value] ?? '#4b5563', 0.4)
})

const handleClick = () => emit('select', group.value)
const handleReload = () => emit('reload', group.value)
</script>

<template>
    <div
        :class="['vuln-card relative min-h-[5rem] border rounded-lg transition-colors overflow-hidden cursor-pointer hover:brightness-110', cardStyle]"
        :data-group-id="group.id"
        :aria-selected="selected ? 'true' : 'false'"
        @click="handleClick"
    >
        <!-- Criticality Badges -->
        <div class="absolute inset-y-0 left-0 z-20 pointer-events-none flex">
            <!-- Original severity badge -->
            <div class="relative z-20 h-full w-8 flex items-center justify-center" data-testid="severity-badge">
                <svg class="absolute inset-0 w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 32 100">
                    <defs>
                        <filter id="badge-chevron-shadow-compact" x="-8" y="-8" width="56" height="116" filterUnits="userSpaceOnUse">
                            <feDropShadow dx="3" dy="2" stdDeviation="4" flood-color="rgba(0,0,0,0.45)" />
                        </filter>
                    </defs>
                    <polygon :fill="originalSeverityFill" filter="url(#badge-chevron-shadow-compact)" points="0,0 25.6,0 32,50 25.6,100 0,100" />
                </svg>
                <span class="relative z-10 text-[8px] font-black uppercase tracking-[0.18em] [writing-mode:vertical-rl] rotate-180 whitespace-nowrap text-white">
                    {{ originalSeverity }}
                </span>
            </div>
            <!-- Rescored severity badge -->
            <div class="relative z-10 h-full w-7 -ml-1.5 flex items-center justify-end" data-testid="rescored-severity-badge">
                <div
                    class="absolute inset-0"
                    :style="{
                        backgroundColor: rescoredSeverityHex,
                        clipPath: 'polygon(0 0, 77.78% 0, 100% 50%, 77.78% 100%, 0 100%, 22.22% 50%)'
                    }"
                ></div>
                <span class="relative z-10 pl-2.5 text-[7px] font-black uppercase tracking-[0.14em] [writing-mode:vertical-rl] rotate-180 whitespace-nowrap text-white">
                    {{ rescoredSeverity || 'N/A' }}
                </span>
            </div>
        </div>

        <!-- Assessed corner fold -->
        <div v-if="isAssessed" class="absolute top-0 right-0 pointer-events-none z-20">
            <div
                class="w-8 h-8 flex justify-end items-start p-1"
                :class="displayState === 'ASSESSED_LEGACY' ? 'bg-sky-600' : displayState === 'INCOMPLETE' ? 'bg-green-600/30' : 'bg-green-600'"
                style="clip-path: polygon(100% 0, 0 0, 100% 100%)"
            >
                <CheckCircle :size="12" :class="displayState === 'INCOMPLETE' ? 'text-white/40' : 'text-white'" />
            </div>
        </div>

        <!-- Header row -->
        <div class="pl-[62px] pr-3 py-2 flex items-center gap-2 relative overflow-hidden">
            <div class="min-w-0 flex-1">
                <VulnGroupCardHeader
                    :group="group"
                    :displayState="displayState"
                    :technicalState="technicalState"
                    :isRescoredOrModified="isRescoredOrModified || hasStableRescore"
                    :currentDisplayScore="currentDisplayScore"
                    :pendingScore="null"
                    :stableRescoredScore="stableRescoredScore"
                    :hasStableRescore="hasStableRescore"
                    :normalizedTags="normalizedTags"
                    :assessedTeams="assessedTeams"
                    :expanded="false"
                    :canApprove="false"
                    :isPendingReview="isPendingReview"
                    :dependencyRelationship="dependencyRelationship"
                    :assignees="group.assignees || []"
                    :baseScoreDisplayOverride="listItem.baseScoreDisplay"
                    :rescoredScoreDisplayOverride="listItem.rescoredScoreDisplay"
                    :instanceCountOverride="listItem.instanceCount"
                    :oldestAttributedOnMsOverride="listItem.oldestAttributedOnMs"
                    :componentSummaryOverride="listItem.componentSummary"
                    :hasAutomaticAssessment="listItem.hasAutomaticAssessment"
                    :automaticAssessmentStatus="listItem.automaticAssessmentStatus"
                    :hasTmrescoreAnalysis="listItem.hasTmrescoreProposal"
                    compact
                />
            </div>
            <button
                type="button"
                data-testid="reload-vulnerability"
                class="relative z-30 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border bg-gray-950/50 transition-colors disabled:cursor-wait disabled:opacity-70"
                :class="reloadError
                    ? 'border-red-500/50 text-red-300 hover:bg-red-950/40'
                    : 'border-gray-600/70 text-gray-400 hover:border-blue-400/50 hover:bg-blue-950/40 hover:text-blue-200'"
                :disabled="reloading"
                :title="reloadError || 'Reload vulnerability assessments from Dependency-Track'"
                :aria-label="reloading ? `Reloading ${group.id}` : `Reload ${group.id}`"
                @click.stop="handleReload"
            >
                <RefreshCw :size="14" :class="{ 'animate-spin': reloading }" />
            </button>
            <span v-if="reloadError" class="sr-only" role="status">{{ reloadError }}</span>
        </div>
    </div>
</template>
