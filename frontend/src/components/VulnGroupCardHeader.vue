<script setup lang="ts">
import { computed, toRefs } from 'vue'
import { Bot, CalendarClock, CheckCircle, ChevronDown, ChevronUp, AlertTriangle, CircleDot, Search, ShieldCheck, ShieldOff, Bug, GitBranch, Layers, Eye, Package, User } from 'lucide-vue-next'
import type { GroupedVuln } from '../types'
import { parseAttributionTimestamp } from '../lib/vulnListIndex'
import { getGroupInconsistencyReasons } from '../lib/assessment-helpers'
import { inconsistencyReasonLabel } from '../lib/inconsistency'

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
  compact?: boolean
  showExpandToggle?: boolean
  baseScoreDisplayOverride?: string
  rescoredScoreDisplayOverride?: string
  scoreTitle?: string
  hasUnsavedDraft?: boolean
  instanceCountOverride?: number
  oldestAttributedOnMsOverride?: number | null
  componentSummaryOverride?: string
  hasAutomaticAssessment?: boolean
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
  compact,
  showExpandToggle,
} = toRefs(props)

const emit = defineEmits<{
  (e: 'approve-assessment', event: Event): void
  (e: 'copy-id'): void
}>()

const baseScoreDisplay = computed(() => {
  if (props.baseScoreDisplayOverride !== undefined) return props.baseScoreDisplayOverride
  const baseScore = group.value.cvss ?? group.value.cvss_score
  return baseScore == null ? '—' : String(baseScore)
})

const rescoredScoreDisplay = computed(() => {
  if (props.rescoredScoreDisplayOverride !== undefined) return props.rescoredScoreDisplayOverride
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
    case 'INCONSISTENT': {
      const labels = getGroupInconsistencyReasons(group.value).map(inconsistencyReasonLabel)
      return labels.length > 0
        ? `Lifecycle: Inconsistent — ${labels.join('; ')}`
        : 'Lifecycle: Inconsistent — assessments disagree across findings'
    }
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
  props.instanceCountOverride !== undefined
    ? props.instanceCountOverride
    : group.value.affected_versions?.reduce((sum, v) => sum + (v.components?.length || 0), 0) || 0
)

const DAY_MS = 24 * 60 * 60 * 1000

const oldestAttributedOnMs = computed(() => {
  if (props.oldestAttributedOnMsOverride !== undefined) {
    return props.oldestAttributedOnMsOverride
  }
  const values = (group.value.affected_versions || [])
    .flatMap(version => version.components || [])
    .map(component => parseAttributionTimestamp(component.attributed_on))
    .filter((value): value is number => value != null)

  return values.length ? Math.min(...values) : null
})

const attributionAgeDays = computed(() => {
  if (oldestAttributedOnMs.value == null) return null
  return Math.max(0, Math.floor((Date.now() - oldestAttributedOnMs.value) / DAY_MS))
})

const formatAttributionAge = (days: number) => {
  if (days <= 0) return 'today'
  if (days < 14) return `${days}d`
  if (days < 70) {
    const weeks = Math.floor(days / 7)
    const remainingDays = days % 7
    return remainingDays > 0 ? `${weeks}w ${remainingDays}d` : `${weeks}w`
  }
  if (days < 365) return `${Math.floor(days / 30)}mo`

  const years = Math.floor(days / 365)
  const months = Math.floor((days % 365) / 30)
  return months > 0 ? `${years}y ${months}mo` : `${years}y`
}

const attributionAgeLabel = computed(() => {
  if (attributionAgeDays.value == null) return ''
  return formatAttributionAge(attributionAgeDays.value)
})

const attributionAgeTitle = computed(() => {
  if (oldestAttributedOnMs.value == null || attributionAgeDays.value == null) return ''
  const date = new Date(oldestAttributedOnMs.value).toISOString().slice(0, 10)
  const age = formatAttributionAge(attributionAgeDays.value)
  return `Oldest attribution: ${date} (${attributionAgeDays.value === 0 ? age : `${age} ago`})`
})

const componentSummary = computed(() => {
  if (props.componentSummaryOverride !== undefined) return props.componentSummaryOverride
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
  <div :class="['flex min-w-0 flex-1', compact ? 'items-center gap-2' : 'items-start gap-3']">
    <div class="flex-1 min-w-0">
      <!-- Primary row: ID + component context -->
      <div :class="['flex items-center min-w-0', compact ? 'gap-1.5' : 'gap-2 flex-wrap']">
        <span
          data-testid="vuln-primary-id"
          :class="[
            'min-w-0 shrink overflow-hidden text-ellipsis whitespace-nowrap font-black text-yellow-400 tracking-tight leading-none cursor-pointer hover:underline',
            compact ? 'text-sm' : 'text-base'
          ]"
          title="Click to copy ID"
          @click.stop="emit('copy-id')"
        >
          {{ group.id }}
        </span>

        <span v-if="compact" class="inline-flex shrink-0 items-center gap-1 rounded border border-gray-700/70 bg-gray-950/40 px-1.5 py-0.5 text-[10px] font-bold tabular-nums text-gray-200" data-testid="header-cvss-block" :title="props.scoreTitle || 'CVSS base score'">
          <span class="text-gray-500">CVSS</span>
          <span data-testid="base-score-value">{{ baseScoreDisplay }}</span>
          <template v-if="isRescoredOrModified">
            <span class="text-gray-600" data-testid="rescored-arrow">&rarr;</span>
            <span :class="pendingScore !== null ? 'text-purple-400' : 'text-purple-500'" data-testid="rescored-value-badge" title="Rescored CVSS score after contextual analysis">
              {{ rescoredScoreDisplay }}
            </span>
          </template>
        </span>

        <span v-if="componentSummary" :class="['inline-flex min-w-0 items-center gap-1 text-[10px] text-gray-500 font-medium truncate', compact ? 'max-w-[16rem]' : 'max-w-[20rem]']" :title="componentSummary">
          <Package :size="9" class="shrink-0 text-gray-600" />
          {{ componentSummary }}
        </span>
      </div>

      <!-- Status row: lifecycle | analysis state | meta -->
      <div :class="['flex items-center flex-wrap', compact ? 'gap-1 mt-1 max-h-[3.1rem] overflow-hidden' : 'gap-1.5 mt-1.5']">
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

        <span
          v-if="!compact"
          class="inline-flex items-center gap-1 rounded border border-gray-700/70 bg-gray-950/50 px-1.5 py-0.5 text-[10px] font-bold tabular-nums text-gray-200 shrink-0"
          data-testid="header-cvss-block"
          :title="props.scoreTitle || 'CVSS base score'"
        >
          <span class="text-gray-500">CVSS</span>
          <span data-testid="base-score-value">{{ baseScoreDisplay }}</span>
          <template v-if="isRescoredOrModified">
            <span class="text-gray-600" data-testid="rescored-arrow">&rarr;</span>
            <span :class="pendingScore !== null ? 'text-purple-400' : 'text-purple-500'" data-testid="rescored-value-badge" title="Rescored CVSS score after contextual analysis">
              {{ rescoredScoreDisplay }}
            </span>
          </template>
        </span>

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

        <span v-if="attributionAgeLabel" class="inline-flex items-center gap-1 rounded border border-cyan-500/20 bg-cyan-500/10 px-1 py-0.5 text-[9px] font-bold uppercase tracking-wide text-cyan-300 shrink-0 tabular-nums" data-testid="attribution-age-chip" :title="attributionAgeTitle">
          <CalendarClock :size="9" />
          Age {{ attributionAgeLabel }}
        </span>

        <span v-if="isPendingReview && !canApprove" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold bg-yellow-900/50 text-yellow-300 border border-yellow-700/50 uppercase tracking-wide shrink-0" title="Assessment submitted by an analyst, awaiting reviewer approval">
          <Eye :size="9" />
          Review
        </span>

        <span
          v-if="props.hasAutomaticAssessment"
          class="inline-flex items-center gap-1 rounded border border-cyan-500/25 bg-cyan-500/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-cyan-300 shrink-0"
          data-testid="automatic-assessment-badge"
          title="Automatic code-analysis assessment is available"
        >
          <Bot :size="9" />
          Auto
        </span>

        <span
          v-if="props.hasUnsavedDraft"
          class="inline-flex items-center gap-1 rounded border border-amber-700/40 bg-amber-950/30 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-amber-200 shrink-0"
          data-testid="header-draft-chip"
          title="This expanded card has local assessment edits that have not been applied"
        >
          <AlertTriangle :size="9" />
          Unsaved draft
        </span>

        <template v-if="compact">
          <span
            v-for="tag in normalizedTags"
            :key="tag"
            class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-tight transition-all border"
            :class="assessedTeams.has(tag)
              ? 'bg-green-500/10 text-green-400 border-green-500/20'
              : 'bg-red-500/8 text-red-400/70 border-red-500/15'"
            data-testid="team-tag"
          >
            <CheckCircle v-if="assessedTeams.has(tag)" :size="9" class="text-green-400" />
            <AlertTriangle v-else :size="8" class="text-red-400/60" />
            {{ tag }}
          </span>

          <span
            v-for="assignee in assignees"
            :key="assignee"
            class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium border bg-blue-500/10 text-blue-300 border-blue-500/20"
            data-testid="assignee-chip"
          >
            <User :size="8" class="text-blue-400" />
            {{ assignee }}
          </span>
        </template>

        <button v-if="canApprove" @click.stop="emit('approve-assessment', $event)"
          class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-green-600/20 text-green-400 border border-green-500/30 hover:bg-green-600/30 transition-colors shrink-0 cursor-pointer ml-auto"
          data-testid="approve-btn"
          title="Approve this assessment and remove the pending review status"
        >
          <CheckCircle :size="9" />
          Approve
        </button>
      </div>

      <!-- Team tags row -->
      <div v-if="!compact && normalizedTags.length > 0" class="flex flex-wrap items-center gap-1 mt-1.5">
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
      <div v-if="!compact && assignees.length > 0" class="flex flex-wrap items-center gap-1 mt-1">
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

    <slot name="actions"></slot>

    <!-- Expand indicator -->
    <component v-if="!compact && showExpandToggle !== false" :is="expanded ? ChevronUp : ChevronDown" :size="16" class="text-gray-600 shrink-0 mt-0.5" />
  </div>
</template>
