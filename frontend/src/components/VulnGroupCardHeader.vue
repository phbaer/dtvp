<script setup lang="ts">
import { toRefs } from 'vue'
import { CheckCircle, ChevronDown, ChevronUp, RefreshCw } from 'lucide-vue-next'
import type { GroupedVuln } from '../types'

const props = defineProps<{
  group: GroupedVuln
  displayState: string
  technicalState: string
  severityColor: string
  isRescoredOrModified: boolean
  currentDisplayScore: number | string
  pendingScore: number | null
  rescoredVectorSegments: { bold: string; normal: string }
  normalizedTags: string[]
  assessedTeams: Set<string>
  affectedComponentNames: string
  expanded: boolean
  canApprove: boolean
  isPendingReview: boolean
  dependencyRelationship: 'DIRECT' | 'TRANSITIVE' | 'UNKNOWN'
}>()

const {
  group,
  displayState,
  technicalState,
  severityColor,
  isRescoredOrModified,
  currentDisplayScore,
  pendingScore,
  rescoredVectorSegments,
  normalizedTags,
  assessedTeams,
  affectedComponentNames,
  expanded,
  canApprove,
  isPendingReview,
  dependencyRelationship,
} = toRefs(props)

const emit = defineEmits<{
  (e: 'refresh-details'): void
  (e: 'approve-assessment', event: Event): void
}>()
</script>

<template>
  <div class="flex-1 min-w-0">
    <div class="flex flex-wrap items-center gap-x-6 gap-y-2 mb-2">
      <!-- ID & Aliases -->
      <div class="flex flex-col min-w-0 shrink-0">
        <span class="text-xl font-black text-yellow-400 tracking-tight leading-none transition-colors truncate">
          {{ group.id }}
        </span>
        <div v-if="group.aliases?.length" class="text-[10px] text-gray-500 font-bold uppercase tracking-widest mt-1 flex flex-wrap gap-1.5 overflow-hidden">
          <span v-for="alias in group.aliases" :key="alias" class="whitespace-nowrap opacity-60 hover:opacity-100 transition-opacity">
            {{ alias }}
          </span>
        </div>
      </div>

      <!-- Criticality -->
      <div class="flex flex-col items-center gap-1 shrink-0">
        <span class="text-[9px] font-black text-gray-600 uppercase tracking-[0.2em] leading-none">Criticality</span>
        <span :class="['px-3 py-0.5 rounded-lg text-[10px] font-black uppercase tracking-tight border text-center', severityColor]">
          {{ group.severity || 'UNKNOWN' }}
        </span>
      </div>

      <!-- CVSS Base Score -->
      <div class="flex flex-col items-center gap-1 shrink-0">
        <span class="text-[9px] font-black text-gray-600 uppercase tracking-[0.2em] leading-none">CVSS Base</span>
        <div class="flex items-center gap-1.5">
          <span
            v-if="isRescoredOrModified"
            :class="['px-2 py-0.5 rounded-lg text-xs font-black transition-all duration-300 border',
              (pendingScore !== null)
                ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                : 'bg-purple-500/5 text-purple-500 border-purple-500/20'
            ]"
            data-testid="rescored-value-badge"
          >
            {{ currentDisplayScore }}
          </span>
          <span v-else class="text-lg font-black text-gray-100">
            {{ currentDisplayScore }}
          </span>
          <span v-if="isRescoredOrModified" class="text-[10px] text-gray-600 line-through font-bold opacity-40">
            {{ group.cvss || group.cvss_score }}
          </span>
        </div>
      </div>

      <!-- Team Consensus Badges -->
      <div v-if="normalizedTags.length > 0" class="flex items-center gap-2 flex-1 min-w-0 pl-4 border-l border-white/5">
        <div class="flex gap-1.5 flex-wrap">
          <span
            v-for="tag in normalizedTags"
            :key="tag"
            class="px-2 py-0.5 rounded-lg text-[10px] font-black uppercase tracking-tight flex items-center gap-1.5 transition-all"
            :class="assessedTeams.has(tag)
              ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
              : 'bg-white/2 text-gray-600 border border-white/5'"
            data-testid="team-tag"
          >
            <CheckCircle v-if="assessedTeams.has(tag)" :size="10" class="text-blue-400" />
            {{ tag }}
          </span>
        </div>
      </div>
    </div>

    <div class="text-sm text-gray-400 line-clamp-1 font-mono pl-0.5">
      {{ affectedComponentNames }}
    </div>

    <div v-if="expanded && (group.rescored_vector || group.cvss_vector)" class="mt-2 flex flex-col gap-1.5">
      <div v-if="group.rescored_vector && group.rescored_vector !== group.cvss_vector" class="font-mono text-[10px] text-purple-300 break-all bg-purple-900/20 p-1.5 rounded border border-purple-500/30 flex items-center gap-2">
        <span class="text-purple-400/70 uppercase font-bold shrink-0">Rescored Vector:</span>
        <span class="tracing-tight">
          <span class="font-bold rescored-bold-segment">{{ rescoredVectorSegments.bold }}</span>{{ rescoredVectorSegments.normal }}
        </span>
      </div>
      <div class="font-mono text-[10px] text-gray-500 break-all bg-gray-900/50 p-1.5 rounded border border-gray-700/50 flex items-center gap-2">
        <span class="text-gray-600 uppercase font-bold shrink-0">{{ group.rescored_vector ? 'Original Vector:' : 'Vector:' }}</span>
        <span :class="{ 'line-through opacity-50': group.rescored_vector }">{{ group.cvss_vector || 'N/A' }}</span>
      </div>
    </div>
  </div>

  <div class="flex items-start gap-6 shrink-0">
    <div class="text-right shrink-0">
      <div class="text-[10px] text-gray-500 font-bold uppercase tracking-wider mb-0.5">Analysis</div>
      <div
        :id="'state-' + group.id"
        :class="['font-bold text-sm truncate analysis-state-value cursor-help', technicalState === 'NOT_AFFECTED' ? 'text-green-400' : technicalState === 'EXPLOITABLE' ? 'text-red-400' : technicalState === 'NOT_SET' ? 'text-red-500/80' : technicalState === 'IN_TRIAGE' ? 'text-amber-400' : technicalState === 'FALSE_POSITIVE' ? 'text-teal-400' : technicalState === 'RESOLVED' ? 'text-purple-400' : technicalState === 'INCOMPLETE' ? 'text-amber-500' : technicalState === 'INCONSISTENT' ? 'text-indigo-400' : 'text-gray-300']"
        :title="technicalState"
      >
        {{ technicalState }}
      </div>
      <div class="text-[9px] font-black uppercase tracking-tighter mt-1 opacity-40 px-1 border border-white/5 rounded inline-block analysis-lifecycle-value" :title="displayState">
        {{ displayState }}
      </div>
    </div>

    <div class="text-right shrink-0">
      <div class="text-[10px] text-gray-500 font-bold uppercase tracking-wider mb-0.5">Affected</div>
      <div class="font-bold text-sm text-gray-300" data-testid="affected-version-summary">
        {{ group.affected_versions?.length || 0 }} Versions
      </div>

      <div class="mt-1">
        <span v-if="dependencyRelationship === 'DIRECT'" class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wide text-white bg-red-600 border border-red-500">
          Direct
        </span>
        <span v-else-if="dependencyRelationship === 'TRANSITIVE'" class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide text-gray-200 bg-purple-600/20 border border-purple-600/30">
          Transitive
        </span>
        <span v-else class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide text-gray-400 bg-gray-700/30 border border-gray-600/30">
          Relation: N/A
        </span>
      </div>

      <div class="mt-1 flex flex-col items-end gap-1">
        <div v-if="isPendingReview">
          <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-yellow-900/50 text-yellow-300 border border-yellow-700/50 uppercase tracking-wide">
            Pending Review
          </span>
        </div>
      </div>

      <button
        v-if="canApprove"
        @click="$emit('approve-assessment', $event)"
        class="mt-1 px-2 py-0.5 text-xs bg-green-700 hover:bg-green-600 text-white rounded font-bold transition-colors w-full z-10 relative"
      >
        Approve
      </button>
    </div>

    <div class="pt-1 flex items-center gap-2">
      <button
        @click.stop="$emit('refresh-details')"
        class="p-1 hover:bg-gray-700 rounded text-gray-400 hover:text-white transition-colors"
        title="Refresh Analysis Details"
      >
        <RefreshCw :size="16" />
      </button>
      <component :is="expanded ? ChevronUp : ChevronDown" class="text-gray-500" :size="20" />
    </div>
  </div>
</template>
