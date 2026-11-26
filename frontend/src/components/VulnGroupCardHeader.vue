<script setup lang="ts">
import { computed, toRefs } from 'vue'
import { Bot, CheckCircle, ChevronDown, ChevronUp, Layers, Package, RotateCcw } from '@lucide/vue'
import type { GroupedVuln } from '../types'
import { parseAttributionTimestamp, type AutomaticAssessmentStatus } from '../lib/vulnListIndex'
import { getGroupGlobalDecision, getGroupInconsistencyReasons } from '../lib/assessment-helpers'
import { inconsistencyReasonLabel } from '../lib/inconsistency'
import { getGroupAssessmentSyncIssues } from '../lib/assessmentSyncIssues'
import { evidenceLabel, evidenceSources } from '../lib/evidence'
import { severityTextColour } from '../lib/vulnCardSeverity'
import VulnCardDates from './VulnCardDates.vue'
import { originalSeverityOf } from '../lib/vulnListIndex'

const props = defineProps<{
  group: GroupedVuln
  displayState: string
  technicalState: string
  rescoredScore?: number | null
  rescoredSeverity?: string | null
  originalSeverity?: string
  normalizedTags: string[]
  assessedTeams: Set<string>
  expanded: boolean
  canApprove: boolean
  isPendingReview: boolean
  dependencyRelationship: 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'
  compact?: boolean
  workflowLabel?: string
  reserveCornerSpace?: boolean
  showExpandToggle?: boolean
  scoreTitle?: string
  hasUnsavedDraft?: boolean
  instanceCountOverride?: number
  versionCount?: number
  suppressedCount?: number
  changesRequestedTeams?: string[]
  syncFailed?: boolean
  oldestAttributedOnMsOverride?: number | null
  componentSummaryOverride?: string
  hasAutomaticAssessment?: boolean
  automaticAssessmentStatus?: AutomaticAssessmentStatus | null
  /** Why a pending vulnerability cannot be approved yet, for reviewers. */
  approvalUnavailableReason?: string
}>()

const codeAssessmentStatus = computed<AutomaticAssessmentStatus | null>(() =>
  props.automaticAssessmentStatus || (props.hasAutomaticAssessment ? 'auto' : null)
)
const codeAssessmentAvailable = computed(() => codeAssessmentStatus.value !== null)
const codeAssessmentTitle = computed(() => {
  switch (codeAssessmentStatus.value) {
    case 'auto': return 'Automatic code-analysis assessment is available'
    case 'manual': return 'Reviewer-started code-analysis assessment is available'
    case 'mixed': return 'Automatic and reviewer-started code-analysis assessments are available'
    case 'partial': return 'A code-analysis assessment is available with partial coverage or metadata'
    default: return 'No code-analysis assessment is available'
  }
})
const {
  group,
  displayState,
  technicalState,
  normalizedTags,
  assessedTeams,
  canApprove,
  dependencyRelationship,
} = toRefs(props)

const emit = defineEmits<{
  (e: 'approve-assessment', event: Event): void
  (e: 'copy-id'): void
}>()

const baseScore = computed(() => group.value.cvss ?? group.value.cvss_score)
const formatScore = (score: number | null | undefined) =>
  typeof score === 'number' && Number.isFinite(score) ? score.toFixed(1) : '—'
const original = computed(() => props.originalSeverity || originalSeverityOf(group.value))
const severityLabel = (severity: string) => severity === 'INFO' ? 'Info'
  : severity.charAt(0) + severity.slice(1).toLowerCase()
const advisoryTitle = computed(() => {
  const title = group.value.title?.trim()
  return title && title !== group.value.id ? title : ''
})
const kev = computed(() => evidenceSources(group.value).includes('KEV'))
const teamKey = (team: string) => team.trim().toLowerCase()
const assessed = computed(() => new Set([...assessedTeams.value].map(teamKey)))
const returned = computed(() => new Set((props.changesRequestedTeams || []).map(teamKey)))
const mcpTeams = computed(() => new Set((group.value.list_metadata?.mcp_assessment_teams || []).map(teamKey)))
const teamStatus = (team: string) => returned.value.has(teamKey(team)) ? 'Changes requested'
  : assessed.value.has(teamKey(team)) ? 'Assessment recorded' : 'Missing assessment'

const lifecycleClass = computed(() => {
  switch (displayState.value) {
    case 'OPEN':
    case 'NOT_SET': return 'text-red-300'
    case 'INCOMPLETE': return 'text-amber-300'
    case 'INCONSISTENT': return 'text-indigo-300'
    case 'ASSESSED': return 'text-emerald-300'
    case 'ASSESSED_LEGACY': return 'text-sky-300'
    case 'NEEDS_APPROVAL': return 'text-violet-300'
    default: return 'text-gray-400'
  }
})

const lifecycleLabel = computed(() => {
  switch (displayState.value) {
    case 'OPEN':
    case 'NOT_SET': return 'Open'
    case 'INCOMPLETE': return 'Incomplete'
    case 'INCONSISTENT': return 'Conflicting'
    case 'ASSESSED': return 'Assessed'
    case 'ASSESSED_LEGACY': return 'Assessed'
    case 'NEEDS_APPROVAL': return 'Ready for approval'
    default: return displayState.value
  }
})

const analysisStateClass = computed(() => {
  switch (technicalState.value) {
    case 'EXPLOITABLE': return 'text-red-300'
    case 'IN_TRIAGE': return 'text-amber-300'
    case 'FALSE_POSITIVE': return 'text-teal-300'
    case 'RESOLVED': return 'text-emerald-300'
    case 'NOT_AFFECTED': return 'text-emerald-300'
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
    default: return 'Not Set'
  }
})

const lifecycleTooltip = computed(() => {
  switch (displayState.value) {
    case 'OPEN':
    case 'NOT_SET': return 'Lifecycle: Open — no assessment has been started'
    case 'INCOMPLETE': return `Lifecycle: Incomplete — ${getGroupAssessmentSyncIssues(group.value, {
      lifecycle: 'INCOMPLETE', requiredTeamsOrTags: normalizedTags.value,
    }).map(issue => issue.detail).join(' ')}`
    case 'INCONSISTENT': {
      const labels = getGroupInconsistencyReasons(group.value).map(inconsistencyReasonLabel)
      return labels.length > 0
        ? `Lifecycle: Conflicting — ${labels.join('; ')}`
        : 'Lifecycle: Conflicting — assessments disagree across findings'
    }
    case 'ASSESSED': return 'Lifecycle: Assessed — approved globally or all required teams have completed their assessment'
    case 'ASSESSED_LEGACY': return 'Lifecycle: Assessed (Legacy) — assessed before the multi-team workflow was introduced'
    case 'NEEDS_APPROVAL': {
      const approval = getGroupAssessmentSyncIssues(group.value, {
        lifecycle: 'NEEDS_APPROVAL', requiredTeamsOrTags: normalizedTags.value,
      })
      return approval.length > 0
        ? `Lifecycle: Ready for approval — ${approval.map(issue => issue.detail).join(' ')}`
        : 'Lifecycle: Ready for approval — all required assessments complete; reviewer sign-off pending'
    }
    default: return `Lifecycle: ${displayState.value}`
  }
})

/** The effective Global decision; a derived one is marked on the state chip. */
const globalDecision = computed(() => getGroupGlobalDecision(group.value))
const derivedDecision = computed(() => globalDecision.value.source === 'derived'
  && globalDecision.value.state === technicalState.value)
const analysisStateTooltip = computed(() => {
  const base = analysisStateBaseTooltip.value
  return base && derivedDecision.value
    ? `${base}. Derived: no reviewer has set the Global decision; it is the worst of the team assessments (${globalDecision.value.teams.join(', ')}).`
    : base
})
const analysisStateBaseTooltip = computed(() => {
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

// Findings added after the vulnerability was assessed and still unassessed.
const suppressedCount = computed(() => props.suppressedCount ?? 0)
const suppressedTitle = computed(() => (
  `${suppressedCount.value} finding${suppressedCount.value === 1 ? ' is' : 's are'} suppressed in Dependency-Track`
))
const newFindings = computed(() =>
  (group.value.affected_versions || []).flatMap(version =>
    (version.components || [])
      .filter(component => component.is_new_finding)
      .map(component => ({
        version: String(version.project_version || component.project_version || ''),
        reported: parseAttributionTimestamp(component.attributed_on),
      })),
  ),
)

const newFindingsTitle = computed(() => {
  const versions = [...new Set(newFindings.value.map(finding => finding.version).filter(Boolean))]
  const dates = newFindings.value
    .map(finding => finding.reported)
    .filter((value): value is number => value != null)
  const since = dates.length ? `, first reported ${new Date(Math.min(...dates)).toISOString().slice(0, 10)}` : ''
  const count = newFindings.value.length
  return `${count} finding${count !== 1 ? 's were' : ' was'} added after this vulnerability was assessed`
    + `${versions.length ? ` (version ${versions.join(', ')})` : ''}${since}. Not assessed yet.`
})

const scopeTitle = computed(() => {
  const relationship = dependencyRelationship.value
  const oldest = props.oldestAttributedOnMsOverride
  return [
    relationship === 'UNKNOWN' ? '' : relationship === 'DIRECT' ? 'Direct dependency' : 'Transitive dependency',
    oldest == null ? '' : `Oldest attribution: ${new Date(oldest).toISOString().slice(0, 10)}`,
  ].filter(Boolean).join(' · ')
})

const publishedOnMs = computed(() => {
  const publication = group.value.list_metadata?.cutoff_dates?.published
  const dates = publication
    ? Object.values(publication.by_version || {}).map(([earliest]) => earliest)
    : (group.value.affected_versions || []).flatMap(version =>
        (version.components || []).map(component => component.published_ms))
  const known = dates.filter((date): date is number => typeof date === 'number' && Number.isFinite(date) && date > 0)
  return known.length ? Math.min(...known) : null
})

const showCompactDates = computed(() => props.compact && (publishedOnMs.value != null || props.oldestAttributedOnMsOverride != null))
const showFooter = computed(() => (props.compact || props.showExpandToggle !== false)
  && (normalizedTags.value.length > 0 || codeAssessmentAvailable.value || showCompactDates.value))
const newCount = computed(() => Math.max(newFindings.value.length, group.value.list_metadata?.new_finding_count || 0))

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
  <div class="@container min-w-0 flex-1 space-y-0.5">
    <div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
      <div class="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <button
          v-if="!compact"
          type="button"
          data-testid="vuln-primary-id"
          class="text-left font-mono text-sm font-bold text-blue-200 [overflow-wrap:anywhere] hover:underline"
          title="Copy vulnerability ID"
          @click.stop="emit('copy-id')"
        >{{ group.id }}</button>
        <span
          v-else
          data-testid="vuln-primary-id"
          class="font-mono text-sm font-bold text-blue-200 [overflow-wrap:anywhere]"
        >{{ group.id }}</span>
        <h2 v-if="advisoryTitle && !compact" class="text-sm font-semibold text-gray-100 [overflow-wrap:anywhere]">{{ advisoryTitle }}</h2>
      </div>
      <div class="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
        <template v-if="!compact">
          <span v-if="lifecycleLabel !== 'Assessed' || (!isPendingReview && !returned.size)" data-testid="lifecycle-badge" :class="['font-semibold', lifecycleClass]" :title="lifecycleTooltip">
            {{ lifecycleLabel }}
          </span>
          <span v-if="displayState === 'ASSESSED_LEGACY'" class="text-sky-300" data-testid="legacy-assessment-badge">Legacy</span>
          <span
            v-if="isPendingReview && displayState !== 'NEEDS_APPROVAL'"
            data-testid="header-review-chip"
            class="text-violet-300"
            :title="approvalUnavailableReason || 'Assessment submitted for reviewer approval'"
          >Awaiting review</span>
          <span v-if="hasUnsavedDraft" data-testid="header-draft-chip" class="font-semibold text-amber-300">Unsaved draft</span>
          <button
            v-if="canApprove && !expanded"
            type="button"
            data-testid="approve-btn"
            class="rounded border border-green-600/50 px-2 py-1 font-semibold text-green-300 hover:bg-green-600/20"
            title="Open the Global assessment to check and approve it"
            @click.stop="emit('approve-assessment', $event)"
          >Approve</button>
        </template>
        <slot name="actions"></slot>
        <component v-if="!compact && showExpandToggle !== false" :is="expanded ? ChevronUp : ChevronDown" :size="14" class="text-gray-400" />
      </div>
    </div>

    <span v-if="compact && workflowLabel !== lifecycleLabel" data-testid="lifecycle-badge" class="sr-only" :title="lifecycleTooltip">{{ lifecycleLabel }}</span>
    <span v-if="compact && displayState === 'ASSESSED_LEGACY'" data-testid="legacy-assessment-badge" class="sr-only">Legacy</span>
    <div :class="compact
      ? 'space-y-0.5'
      : 'grid gap-x-5 gap-y-0.5 @[34rem]:grid-cols-[20rem_minmax(0,1fr)] @[34rem]:items-center @[34rem]:border-t @[34rem]:border-gray-700/80 @[34rem]:pt-0.5'"
    >
      <div
        class="min-w-0 text-[11px] text-gray-300"
        :class="compact
          ? 'flex flex-wrap items-baseline gap-x-2'
          : 'grid w-fit max-w-full grid-cols-[minmax(5.5rem,1fr)_minmax(5.5rem,auto)] items-start gap-x-3 @[34rem]:col-start-2 @[34rem]:row-start-1 @[34rem]:justify-self-end'"
      >
        <div v-if="(compact && advisoryTitle) || componentSummary" class="flex min-w-0 max-w-full items-baseline gap-x-2" :class="compact ? 'grow basis-32' : ''">
          <span v-if="compact && advisoryTitle" class="min-w-0 truncate font-medium text-gray-100" :title="advisoryTitle">
            {{ advisoryTitle }}
          </span>
          <span v-if="componentSummary" class="inline-flex min-w-0 items-center gap-1" data-testid="component-summary" :title="componentSummary">
            <Package v-if="!compact" :size="12" class="shrink-0 text-gray-400" aria-hidden="true" />
            <span class="truncate">{{ componentSummary }}</span>
          </span>
        </div>
        <span data-testid="instance-count" class="inline-flex items-start gap-1 tabular-nums" :class="compact ? 'shrink-0 whitespace-nowrap' : 'col-start-2 row-start-1 min-w-0'" :title="scopeTitle || undefined">
          <Layers v-if="!compact" :size="12" class="mt-[2px] shrink-0 text-gray-400" aria-hidden="true" />
          <span>
            {{ instanceCount }} {{ instanceCount === 1 ? 'finding' : 'findings' }}
            <template v-if="!compact && versionCount"> across {{ versionCount }} {{ versionCount === 1 ? 'version' : 'versions' }}</template>
          </span>
        </span>
        <VulnCardDates v-if="!compact" :publishedOnMs="publishedOnMs" :attributedOnMs="oldestAttributedOnMsOverride" />
        <div v-if="newCount || suppressedCount || kev || syncFailed" :class="compact ? 'contents' : 'col-span-2 flex flex-wrap gap-x-2'">
          <span v-if="newCount" class="text-emerald-300" data-testid="new-findings-chip" :title="newFindingsTitle || undefined">{{ newCount }} new</span>
          <span v-if="suppressedCount" class="text-gray-300" data-testid="suppressed-chip" :title="suppressedTitle">{{ suppressedCount }} suppressed</span>
          <span v-if="kev" data-testid="evidence-badge" class="font-semibold text-amber-300" :title="`Listed in CISA KEV. ${evidenceSources(group).map(evidenceLabel).join('; ')}`">
            {{ compact ? 'KEV' : 'Known exploited (CISA KEV)' }}
          </span>
          <span v-if="syncFailed" data-testid="header-sync-failed" class="font-semibold text-red-300">Export failed</span>
        </div>
      </div>

      <dl
        data-testid="header-cvss-block"
        class="grid max-w-[20rem] grid-cols-[minmax(0,1.2fr)_repeat(2,minmax(0,1fr))] gap-x-2 border-t border-gray-700/80 pt-0.5"
        :class="[
          reserveCornerSpace && !showFooter ? 'w-[calc(100%_-_1rem)]' : 'w-full',
          !compact && '@[34rem]:col-start-1 @[34rem]:row-start-1 @[34rem]:border-0 @[34rem]:pt-0',
        ]"
        :title="scoreTitle"
      >
        <div class="min-w-0">
          <dt class="text-[10px] text-gray-300">Effective verdict</dt>
          <dd data-testid="analysis-state-badge" :title="analysisStateTooltip" :class="['text-xs font-semibold', analysisStateClass || 'text-gray-300']">
            {{ analysisStateLabel }}
            <span v-if="derivedDecision" data-testid="analysis-state-derived" class="text-[10px] font-normal text-gray-300">· Derived</span>
          </dd>
        </div>
        <div class="min-w-0">
          <dt class="text-[10px] text-gray-300">Original severity</dt>
          <dd class="flex flex-wrap items-baseline gap-x-1 text-xs">
            <span class="text-[10px] tabular-nums text-gray-300">
              <span class="sr-only">CVSS </span><span data-testid="base-score-value">{{ formatScore(baseScore) }}</span>
            </span>
            <span data-testid="severity-badge" :class="['font-semibold', severityTextColour(original)]">{{ severityLabel(original) }}</span>
          </dd>
        </div>
        <div class="min-w-0">
          <dt class="text-[10px] text-gray-300">Rescored severity</dt>
          <dd v-if="rescoredSeverity && rescoredScore != null" class="flex flex-wrap items-baseline gap-x-1 text-xs">
            <span class="text-[10px] tabular-nums text-gray-300">
              <span class="sr-only">CVSS </span><span data-testid="rescored-value-badge">{{ formatScore(rescoredScore) }}</span>
            </span>
            <span data-testid="rescored-severity-badge" :class="['font-semibold', severityTextColour(rescoredSeverity)]">
              {{ severityLabel(rescoredSeverity) }}
            </span>
          </dd>
          <dd v-else data-testid="rescored-severity-badge" class="text-xs font-semibold text-gray-400">Not rescored</dd>
        </div>
      </dl>
    </div>

    <div v-if="showFooter" class="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-0.5 text-[11px] text-gray-300" :class="{ 'pr-4': reserveCornerSpace }">
      <span
        v-for="team in normalizedTags"
        :key="team"
        data-testid="team-tag"
        class="inline-flex max-w-full items-center gap-1 [overflow-wrap:anywhere]"
        :title="`${team}: ${teamStatus(team)}`"
        role="img"
        :aria-label="`${team}: ${teamStatus(team)}${mcpTeams.has(teamKey(team)) ? ', submitted via MCP' : ''}`"
      >
        <span>{{ team }}</span>
        <RotateCcw v-if="returned.has(teamKey(team))" :size="10" class="shrink-0 text-red-300" aria-hidden="true" />
        <CheckCircle v-else-if="assessed.has(teamKey(team))" :size="10" class="shrink-0 text-emerald-300" aria-hidden="true" />
        <span v-else class="size-2 shrink-0 rounded-full border border-amber-300" aria-hidden="true"></span>
        <span v-if="mcpTeams.has(teamKey(team))" data-testid="team-mcp" class="shrink-0 font-semibold text-violet-300" title="Current team assessment submitted via MCP">MCP</span>
      </span>
      <VulnCardDates
        v-if="showCompactDates"
        class="ml-auto"
        :publishedOnMs="publishedOnMs"
        :attributedOnMs="oldestAttributedOnMsOverride"
        compact
      />
      <span
        v-if="codeAssessmentAvailable"
        data-testid="automatic-assessment-badge"
        class="inline-flex shrink-0 items-center text-blue-300"
        :class="{ 'ml-auto': !showCompactDates }"
        data-availability="available"
        :data-assessment-status="codeAssessmentStatus || undefined"
        role="img"
        :title="codeAssessmentTitle"
        :aria-label="codeAssessmentTitle"
      ><Bot :size="15" aria-hidden="true" /></span>
    </div>
  </div>
</template>
