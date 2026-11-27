<script setup lang="ts">
import { computed } from 'vue'
import type { GroupedVuln } from '../types'
import { scoreSeverity, type VulnListItem } from '../lib/vulnListIndex'
import { cardSeverityTint, savedRescoredScore } from '../lib/vulnCardSeverity'
import VulnGroupCardHeader from './VulnGroupCardHeader.vue'
import { CheckCircle, RefreshCw } from '@lucide/vue'
import { analysisQueueStore } from '../lib/analysisQueueStore'

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
const rescore = computed(() => savedRescoredScore(group.value))
const rescoredSeverity = computed(() => rescore.value == null ? null : scoreSeverity(rescore.value))
const tint = computed(() => cardSeverityTint(listItem.value.originalSeverity, rescoredSeverity.value))
const missingAssessmentTeams = computed(() => {
    if (listItem.value.coversAllTeams) return []
    const recorded = new Set([...assessedTeams.value].map(team => team.toLocaleLowerCase()))
    return normalizedTags.value.filter(team =>
        team.toLocaleLowerCase() !== 'unassigned' && !recorded.has(team.toLocaleLowerCase()),
    )
})
const suppressedCount = computed(() => (group.value.affected_versions || []).reduce((count, version) =>
    count + (version.components || []).filter(component => component.is_suppressed).length, 0))
const syncFailed = computed(() => (group.value.affected_versions || []).some(version =>
    (version.components || []).some(component =>
        ['error', 'failed'].includes(component.dtvp_sync_status || component.sync_status || '')),
))

const handleClick = () => emit('select', group.value)
const handleReload = () => emit('reload', group.value)

type WorkflowTone = 'amber' | 'cyan' | 'blue' | 'green' | 'purple' | 'indigo'
const activeAnalyses = computed(() => {
    const vulnerabilityIds = new Set(
        [group.value.id, ...(group.value.aliases || [])]
            .map(value => String(value || '').trim().toLocaleLowerCase())
            .filter(Boolean),
    )
    return analysisQueueStore.items.value.filter(item =>
        (item.status === 'queued' || item.status === 'running')
        && vulnerabilityIds.has(String(item.vuln_id || '').trim().toLocaleLowerCase()),
    ).map(item => ({
        ...item,
        percent: item.status === 'running' && Number.isFinite(item.progress?.percent)
            ? Math.round(Math.max(0, Math.min(100, item.progress!.percent))) : null,
        activity: item.status === 'queued'
            ? `Queued${item.position > 0 ? ` · position ${item.position}` : ''}`
            : item.progress?.current_activity || item.progress?.current_title || 'Waiting for analyzer progress',
    }))
})
const workflowState = computed<{ label: string; tone: WorkflowTone }>(() => {
    if (displayState.value === 'INCONSISTENT') return { label: 'Conflicting', tone: 'indigo' }
    if (listItem.value.changesRequestedTeams?.length) return { label: 'Changes requested', tone: 'amber' }
    if (listItem.value.isApprovalReady) return { label: 'Ready for approval', tone: 'purple' }
    if (isAssessed.value && !isPendingReview.value) return { label: 'Assessed', tone: 'green' }
    if (activeAnalyses.value.length) return {
        label: activeAnalyses.value.some(item => item.status === 'running') ? 'Analysis running' : 'Analysis queued',
        tone: 'cyan',
    }
    if (isPendingReview.value || technicalState.value !== 'NOT_SET') return { label: 'Review needed', tone: 'purple' }
    if (normalizedTags.value.filter(team => team.toLocaleLowerCase() !== 'automation').length === 0) {
        return { label: 'Needs mapping', tone: 'amber' }
    }
    if (listItem.value.hasAutomaticAssessment) return { label: 'Result ready', tone: 'cyan' }
    if (technicalState.value === 'NOT_SET') return { label: 'Needs analysis', tone: 'amber' }
    return { label: 'Review needed', tone: 'purple' }
})

const workflowStateClass = computed(() => ({
    amber: 'text-amber-300',
    cyan: 'text-cyan-300',
    blue: 'text-blue-300',
    green: 'text-emerald-300',
    purple: 'text-violet-300',
    indigo: 'text-indigo-300',
}[workflowState.value.tone]))
const showAssessedCorner = computed(() => workflowState.value.label === 'Assessed')
</script>

<template>
    <div
        class="vuln-card relative min-w-0 cursor-pointer rounded-lg border bg-gray-800 transition-colors"
        :class="selected ? 'border-blue-400' : 'border-gray-700 hover:border-gray-500'"
        :style="{ backgroundColor: tint }"
        :data-group-id="group.id"
        :aria-selected="selected ? 'true' : 'false'"
        @click="handleClick"
    >
        <div class="min-w-0 px-3 py-1.5" data-testid="compact-vulnerability-header">
            <VulnGroupCardHeader
                :group="group"
                :displayState="displayState"
                :technicalState="technicalState"
                :originalSeverity="listItem.originalSeverity"
                :rescoredSeverity="rescoredSeverity"
                :rescoredScore="rescore"
                :normalizedTags="normalizedTags"
                :assessedTeams="assessedTeams"
                :missingAssessmentTeams="missingAssessmentTeams"
                :changesRequestedTeams="listItem.changesRequestedTeams"
                :expanded="false"
                :canApprove="false"
                :isPendingReview="isPendingReview"
                :dependencyRelationship="dependencyRelationship"
                :instanceCountOverride="listItem.instanceCount"
                :oldestAttributedOnMsOverride="listItem.oldestAttributedOnMs"
                :componentSummaryOverride="listItem.componentSummary"
                :hasAutomaticAssessment="listItem.hasAutomaticAssessment"
                :automaticAssessmentStatus="listItem.automaticAssessmentStatus"
                :syncFailed="syncFailed"
                :suppressedCount="suppressedCount"
                :workflowLabel="workflowState.label"
                :reserveCornerSpace="showAssessedCorner && !activeAnalyses.length"
                compact
            >
                <template #actions>
                    <span
                        data-testid="workflow-state-badge"
                        :class="['font-semibold', workflowStateClass]"
                    ><span
                        :data-testid="['Conflicting', 'Ready for approval', 'Assessed'].includes(workflowState.label) ? 'lifecycle-badge' : undefined"
                    >{{ workflowState.label }}</span></span>
                    <button
                        type="button"
                        data-testid="reload-vulnerability"
                        class="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded text-gray-300 hover:bg-white/10 disabled:cursor-wait disabled:opacity-70"
                        :class="{ 'text-red-300': reloadError }"
                        :disabled="reloading"
                        :title="reloadError || 'Reload vulnerability assessments from Dependency-Track'"
                        :aria-label="reloading ? `Reloading ${group.id}` : `Reload ${group.id}`"
                        @click.stop="handleReload"
                    >
                        <RefreshCw :size="14" :class="{ 'animate-spin': reloading }" />
                    </button>
                </template>
            </VulnGroupCardHeader>
            <div v-if="activeAnalyses.length" class="mt-2 space-y-2 text-xs text-cyan-200" :class="{ 'pr-4': showAssessedCorner }" data-testid="analysis-progress">
                <div v-for="analysis in activeAnalyses" :key="analysis.queue_id" :title="analysis.job_id ? `Analyzer job ${analysis.job_id}` : undefined">
                    <div class="flex min-w-0 gap-2">
                        <span class="min-w-0 flex-1 truncate" :title="`${analysis.component_name}: ${analysis.activity}`">{{ analysis.component_name }}: {{ analysis.activity }}</span>
                        <span v-if="analysis.percent !== null" class="shrink-0 font-mono">{{ analysis.percent }}%</span>
                    </div>
                    <div v-if="analysis.percent !== null" class="mt-1 h-1 rounded bg-gray-700" role="progressbar" :aria-label="`${analysis.component_name} analysis steps completed`" :aria-valuenow="analysis.percent" :aria-valuemin="0" :aria-valuemax="100">
                        <div class="h-full rounded bg-cyan-400 transition-all" :style="{ width: `${analysis.percent}%` }"></div>
                    </div>
                </div>
            </div>
            <span v-if="reloadError" class="sr-only" role="status">{{ reloadError }}</span>
        </div>
        <span
            v-if="showAssessedCorner"
            data-testid="assessed-corner"
            aria-hidden="true"
            class="pointer-events-none absolute right-0 bottom-0 flex size-7 items-end justify-end rounded-br-[7px] bg-emerald-700 p-[3px] text-emerald-50 [clip-path:polygon(100%_0,100%_100%,0_100%)]"
        ><CheckCircle :size="11" /></span>
    </div>
</template>
