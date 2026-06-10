<script setup lang="ts">
import { computed, inject, ref } from 'vue'
import type { GroupedVuln } from '../types'
import {
    getAssessedTeams,
    getGroupLifecycle,
    getGroupTechnicalState,
    isPendingReview as isPendingReviewHelper,
    hasGlobalAssessment,
} from '../lib/assessment-helpers'
import { buildMergedAssessmentData } from '../lib/mergedAssessmentData'
import { useVulnDependencyInfo } from '../lib/useVulnDependencyInfo'
import VulnGroupCardHeader from './VulnGroupCardHeader.vue'
import { CheckCircle } from 'lucide-vue-next'

const props = defineProps<{
    group: GroupedVuln
    selected?: boolean
}>()

const emit = defineEmits<{
    (e: 'update', group?: GroupedVuln): void
    (e: 'update:assessment', data: any): void
    (e: 'select', group: GroupedVuln): void
}>()

const teamMapping = inject<any>('teamMapping', ref({}))

const groupRef = computed(() => props.group)
const dependencyInfo = useVulnDependencyInfo({
    group: groupRef,
    teamMapping,
})
const normalizedTags = dependencyInfo.normalizedTags
const dependencyRelationship = dependencyInfo.dependencyRelationship

const mergedAssessmentData = computed(() => buildMergedAssessmentData(
    props.group.affected_versions?.flatMap(v => v.components) ?? [], 0
))

const displayState = computed(() =>
    getGroupLifecycle(props.group, normalizedTags.value, teamMapping?.value)
)
const technicalState = computed(() => getGroupTechnicalState(props.group))
const isPendingReview = computed(() => isPendingReviewHelper(props.group))
const isAssessed = computed(() =>
    (hasGlobalAssessment(mergedAssessmentData.value.blocks) && !isPendingReview.value) ||
    displayState.value === 'ASSESSED_LEGACY'
)
const stableRescoredScore = computed<number | null>(() => props.group.rescored_cvss ?? null)
const hasStableRescore = computed(() => {
    const base = props.group.cvss ?? props.group.cvss_score
    const rescored = stableRescoredScore.value
    if (rescored == null || base == null) return false
    return Math.abs(rescored - base) > 0.05
})
const currentDisplayScore = computed(() =>
    props.group.rescored_cvss ?? (props.group.cvss || props.group.cvss_score) ?? 'N/A'
)
const isRescoredOrModified = computed(() => {
    const base = props.group.cvss || props.group.cvss_score
    const current = currentDisplayScore.value
    if (current === 'N/A' || base === undefined) return false
    return Math.abs(Number(current) - Number(base)) > 0.05
})

const hasAssessedAliasForTag = (tag: string, assessed: Set<string>) => {
    if (!teamMapping?.value) return false
    for (const mappingVal of Object.values(teamMapping.value)) {
        if (!Array.isArray(mappingVal) || mappingVal.length <= 1 || mappingVal[0] !== tag) continue
        return (mappingVal as string[]).slice(1).some(alias => assessed.has(alias))
    }
    return false
}
const assessedTeams = computed(() => {
    const assessed = getAssessedTeams(props.group)
    const matched = new Set<string>()
    for (const tag of normalizedTags.value) {
        if (assessed.has(tag) || hasAssessedAliasForTag(tag, assessed)) matched.add(tag)
    }
    return matched
})

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

const scoreSeverity = (score: number): string => {
    if (score >= 9) return 'CRITICAL'
    if (score >= 7) return 'HIGH'
    if (score >= 4) return 'MEDIUM'
    if (score >= 0.1) return 'LOW'
    return 'INFO'
}

const originalSeverity = computed(() => {
    const base = props.group.cvss ?? props.group.cvss_score
    if (base != null && !Number.isNaN(Number(base))) return scoreSeverity(Number(base))
    return 'UNKNOWN'
})
const originalSeverityFill = computed(() => hexToRgba(severityHexMap[originalSeverity.value] ?? '#4b5563', 0.4))

const rescoredSeverity = computed(() => {
    if (hasStableRescore.value) {
        return scoreSeverity(stableRescoredScore.value!)
    }
    if (!isRescoredOrModified.value) return null
    const score = Number(currentDisplayScore.value)
    if (Number.isNaN(score)) return null
    return scoreSeverity(score)
})
const rescoredSeverityHex = computed(() => {
    if (!rescoredSeverity.value) return hexToRgba('#6b7280', 0.4)
    return hexToRgba(severityHexMap[rescoredSeverity.value] ?? '#4b5563', 0.4)
})

const handleClick = () => emit('select', props.group)
</script>

<template>
    <div
        :class="['vuln-card relative border rounded-lg transition-colors overflow-hidden cursor-pointer hover:brightness-110', cardStyle]"
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
        <div class="pl-[62px] pr-3 py-2 flex items-start relative overflow-hidden">
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
                compact
            />
        </div>
    </div>
</template>
