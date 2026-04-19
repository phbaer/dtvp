<script setup lang="ts">
import { computed, toRefs } from 'vue'
import { CheckCircle, ChevronDown, ChevronUp, AlertTriangle, CircleDot, Search, ShieldCheck, ShieldOff, Bug, GitBranch, Layers, Eye, Package, User } from 'lucide-vue-next'
import type { GroupedVuln } from '../types'

const props = defineProps<{
  group: GroupedVuln
  displayState: string
  technicalState: string
  isRescoredOrModified: boolean
  currentDisplayScore: number | string
  pendingScore: number | null
  stableRescoredScore: number | null
  hasStableRescore: boolean
  normalizedTags: string[]
  assessedTeams: Set<string>
  expanded: boolean
  canApprove: boolean
  isPendingReview: boolean
  dependencyRelationship: 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'
  assignees: string[]
}>()

const {
  group,
  displayState,
  technicalState,
  isRescoredOrModified,
  currentDisplayScore,
  pendingScore,
  stableRescoredScore,
  hasStableRescore,
  normalizedTags,
  assessedTeams,
  expanded,
  canApprove,
  isPendingReview,
  dependencyRelationship,
  assignees,
} = toRefs(props)

const emit = defineEmits<{
  (e: 'approve-assessment', event: Event): void
  (e: 'copy-id'): void
}>()

const baseScoreDisplay = computed(() => {
  const baseScore = group.value.cvss ?? group.value.cvss_score
  return baseScore == null ? '—' : String(baseScore)
})

const rescoredScoreDisplay = computed(() => {
  // Prefer stable group data, fallback to computed display score for pending edits
  if (hasStableRescore.value && stableRescoredScore.value != null) {
    return String(stableRescoredScore.value)
  }
  const score = currentDisplayScore.value
  return score === undefined || score === null || score === '' || score === 'N/A' ? '—' : String(score)
})

const lifecycleClass = computed(() => {
  switch (displayState.value) {
    case 'OPEN':
    case 'NOT_SET': return 'bg-red-500/15 text-red-400 border-red-500/30'
    case 'INCOMPLETE': return 'bg-amber-500/15 text-amber-400 border-amber-500/30'
    case 'INCONSISTENT': return 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30'
    case 'ASSESSED': return 'bg-green-500/15 text-green-400 border-green-500/30'
    case 'ASSESSED_LEGACY': return 'bg-sky-500/15 text-sky-400 border-sky-500/30'
    case 'NEEDS_APPROVAL': return 'bg-purple-500/15 text-purple-400 border-purple-500/30'
    default: return 'bg-gray-500/15 text-gray-400 border-gray-500/30'
  }
})

const lifecycleLabel = computed(() => {
  switch (displayState.value) {
    case 'OPEN':
    case 'NOT_SET': return 'Open'
    case 'INCOMPLETE': return 'Incomplete'
    case 'INCONSISTENT': return 'Inconsistent'
    case 'ASSESSED': return 'Assessed'
    case 'ASSESSED_LEGACY': return 'Assessed (Legacy)'
    case 'NEEDS_APPROVAL': return 'Needs Approval'
    default: return displayState.value
  }
})

const analysisStateClass = computed(() => {
  switch (technicalState.value) {
    case 'EXPLOITABLE': return 'bg-red-500/15 text-red-400 border-red-500/30'
    case 'IN_TRIAGE': return 'bg-amber-500/15 text-amber-400 border-amber-500/30'
    case 'FALSE_POSITIVE': return 'bg-teal-500/15 text-teal-400 border-teal-500/30'
    case 'RESOLVED': return 'bg-purple-500/15 text-purple-400 border-purple-500/30'
    case 'NOT_AFFECTED': return 'bg-green-500/15 text-green-400 border-green-500/30'
    default: return ''
  }
})

const analysisStateLabel = computed(() => {
  switch (technicalState.value) {
    case 'EXPLOITABLE': return 'Exploitable'
    case 'IN_TRIAGE': return 'In Triage'
    case 'FALSE_POSITIVE': return 'False Positive'
    case 'RESOLVED': return 'Resolved'
    case 'NOT_AFFECTED': return 'Not Affected'
    default: return ''
  }
})

const lifecycleTooltip = computed(() => {
  switch (displayState.value) {
    case 'OPEN':
    case 'NOT_SET': return 'Lifecycle: Open — no assessment has been started'
    case 'INCOMPLETE': return 'Lifecycle: Incomplete — some teams have assessed, others have not'
    case 'INCONSISTENT': return 'Lifecycle: Inconsistent — teams disagree on the analysis state'
    case 'ASSESSED': return 'Lifecycle: Assessed — all required teams have completed their assessment'
    case 'ASSESSED_LEGACY': return 'Lifecycle: Assessed (Legacy) — assessed before the multi-team workflow was introduced'
    case 'NEEDS_APPROVAL': return 'Lifecycle: Needs Approval — analyst assessment awaiting reviewer sign-off'
    default: return `Lifecycle: ${displayState.value}`
  }
})

const analysisStateTooltip = computed(() => {
  switch (technicalState.value) {
    case 'EXPLOITABLE': return 'Analysis: Exploitable — the vulnerability is exploitable in this context'
    case 'IN_TRIAGE': return 'Analysis: In Triage — currently being investigated'
    case 'FALSE_POSITIVE': return 'Analysis: False Positive — this finding does not apply'
    case 'RESOLVED': return 'Analysis: Resolved — the vulnerability has been mitigated'
    case 'NOT_AFFECTED': return 'Analysis: Not Affected — the component is not impacted'
    default: return ''
  }
})

const instanceCount = computed(() =>
  group.value.affected_versions?.reduce((sum, v) => sum + (v.components?.length || 0), 0) || 0
)

const componentSummary = computed(() => {
  const names = new Set<string>()
  for (const v of group.value.affected_versions || []) {
    for (const c of v.components || []) {
      if (c.component_name) names.add(c.component_name)
    }
  }
  const arr = Array.from(names)
  if (arr.length === 0) return ''
  if (arr.length === 1) return arr[0]
  if (arr.length === 2) return arr.join(', ')
  return `${arr[0]}, ${arr[1]} +${arr.length - 2}`
})
</script>

<template>
  <div class="flex items-start gap-3 min-w-0 flex-1">
    <div class="flex-1 min-w-0">
      <!-- Primary row: ID + component context -->
      <div class="flex items-center gap-2 flex-wrap">
        <span data-testid="vuln-primary-id" class="min-w-0 shrink overflow-hidden text-ellipsis whitespace-nowrap text-base font-black text-yellow-400 tracking-tight leading-none cursor-pointer hover:underline" title="Click to copy ID" @click.stop="emit('copy-id')">
          {{ group.id }}
        </span>

        <span v-if="componentSummary" class="inline-flex items-center gap-1 text-[10px] text-gray-500 font-medium truncate max-w-[20rem]" :title="componentSummary">
          <Package :size="9" class="shrink-0 text-gray-600" />
          {{ componentSummary }}
        </span>
      </div>

      <!-- Status row: lifecycle | analysis state | meta -->
      <div class="flex items-center gap-1.5 mt-1.5 flex-wrap">
        <!-- Lifecycle group -->
        <span :class="['inline-flex items-center gap-1 px-1.5 py-0.5 rounded-l text-[10px] font-bold uppercase tracking-wide border-y border-l shrink-0', lifecycleClass]" data-testid="lifecycle-badge" :title="lifecycleTooltip">
          <CircleDot :size="9" />
          {{ lifecycleLabel }}
        </span>
        <!-- Analysis state (joined to lifecycle visually) -->
        <span v-if="analysisStateLabel" :class="['inline-flex items-center gap-1 px-1.5 py-0.5 rounded-r text-[10px] font-bold uppercase tracking-wide border-y border-r -ml-1.5 shrink-0', analysisStateClass]" data-testid="analysis-state-badge" :title="analysisStateTooltip">
          <Bug v-if="technicalState === 'EXPLOITABLE'" :size="9" />
          <Search v-else-if="technicalState === 'IN_TRIAGE'" :size="9" />
          <ShieldOff v-else-if="technicalState === 'FALSE_POSITIVE'" :size="9" />
          <ShieldCheck v-else-if="technicalState === 'NOT_AFFECTED' || technicalState === 'RESOLVED'" :size="9" />
          {{ analysisStateLabel }}
        </span>
        <!-- Close lifecycle pill if no analysis state -->
        <span v-else class="-ml-1.5"></span>

        <span class="w-px h-3.5 bg-gray-700 mx-0.5 shrink-0"></span>

        <!-- Meta badges -->
        <span v-if="dependencyRelationship !== 'UNKNOWN'"
          :class="['inline-flex items-center gap-1 text-[9px] font-bold uppercase px-1 py-0.5 rounded border shrink-0',
            dependencyRelationship === 'DIRECT' ? 'bg-orange-500/10 text-orange-400/70 border-orange-500/20' : 'bg-gray-500/10 text-gray-500 border-gray-500/20']"
          data-testid="dep-badge"
          :title="dependencyRelationship === 'DIRECT' ? 'Direct dependency — used directly by the project' : 'Transitive dependency — pulled in indirectly through another package'"
        >
          <GitBranch :size="9" />
          {{ dependencyRelationship === 'DIRECT' ? 'Direct' : 'Trans.' }}
        </span>

        <span class="inline-flex items-center gap-1 text-[10px] text-gray-600 shrink-0 tabular-nums" data-testid="instance-count" :title="`${instanceCount} affected component instance${instanceCount !== 1 ? 's' : ''} across all project versions`">
          <Layers :size="9" />
          {{ instanceCount }}&times;
        </span>

        <span v-if="isPendingReview && !canApprove" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold bg-yellow-900/50 text-yellow-300 border border-yellow-700/50 uppercase tracking-wide shrink-0" title="Assessment submitted by an analyst, awaiting reviewer approval">
          <Eye :size="9" />
          Review
        </span>

        <button v-if="canApprove" @click.stop="emit('approve-assessment', $event)"
          class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-green-600/20 text-green-400 border border-green-500/30 hover:bg-green-600/30 transition-colors shrink-0 cursor-pointer ml-auto"
          data-testid="approve-btn"
          title="Approve this assessment and remove the pending review status"
        >
          <CheckCircle :size="9" />
          Approve
        </button>
      </div>

      <!-- Score row -->
      <div class="flex items-center gap-1.5 mt-1" data-testid="header-cvss-block" title="CVSS base score">
        <span class="text-sm font-black text-gray-100 tabular-nums" data-testid="base-score-value">{{ baseScoreDisplay }}</span>
        <template v-if="isRescoredOrModified">
          <span class="text-[10px] text-gray-600" data-testid="rescored-arrow">&rarr;</span>
          <span :class="['text-sm font-black tabular-nums', pendingScore !== null ? 'text-purple-400' : 'text-purple-500']" data-testid="rescored-value-badge" title="Rescored CVSS score after contextual analysis">
            {{ rescoredScoreDisplay }}
          </span>
        </template>
      </div>

      <!-- Team tags row -->
      <div v-if="normalizedTags.length > 0" class="flex flex-wrap items-center gap-1 mt-1.5">
        <span
          v-for="tag in normalizedTags"
          :key="tag"
          class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-tight transition-all border"
          :class="assessedTeams.has(tag)
            ? 'bg-green-500/10 text-green-400 border-green-500/20'
            : 'bg-red-500/8 text-red-400/70 border-red-500/15'"
          data-testid="team-tag"
        >
          <CheckCircle v-if="assessedTeams.has(tag)" :size="10" class="text-green-400" />
          <AlertTriangle v-else :size="9" class="text-red-400/60" />
          {{ tag }}
        </span>
      </div>

      <!-- Assignee chips row -->
      <div v-if="assignees.length > 0" class="flex flex-wrap items-center gap-1 mt-1">
        <span
          v-for="assignee in assignees"
          :key="assignee"
          class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border bg-blue-500/10 text-blue-300 border-blue-500/20"
          data-testid="assignee-chip"
        >
          <User :size="9" class="text-blue-400" />
          {{ assignee }}
        </span>
      </div>
    </div>

    <!-- Expand indicator -->
    <component :is="expanded ? ChevronUp : ChevronDown" :size="16" class="text-gray-600 shrink-0 mt-0.5" />
  </div>
</template>
