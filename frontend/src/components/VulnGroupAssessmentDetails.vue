<script setup lang="ts">
import { ref, computed } from 'vue'
import { History, ClipboardCopy, Plus } from 'lucide-vue-next'
import { parseAssessmentBlocks, type AssessmentBlock } from '../lib/assessment-helpers'
import VulnGroupCardDependencies from './VulnGroupCardDependencies.vue'

const props = defineProps<{
  assessment: any
  isReviewer?: boolean
}>()

const emit = defineEmits<{
  (e: 'apply-all', details: string, state: string, justification: string): void
  (e: 'adopt-team', block: AssessmentBlock): void
}>()
const showAuditLog = ref(false)

const stateAccent = computed(() => {
  const s = props.assessment.state
  if (s === 'NOT_AFFECTED') return 'border-l-green-500'
  if (s === 'EXPLOITABLE') return 'border-l-red-500'
  if (s === 'IN_TRIAGE') return 'border-l-amber-500'
  if (s === 'FALSE_POSITIVE') return 'border-l-teal-500'
  if (s === 'NOT_SET') return 'border-l-gray-500'
  return 'border-l-gray-500'
})

const stateHeaderBg = computed(() => {
  const s = props.assessment.state
  if (s === 'NOT_AFFECTED') return 'bg-gray-850'
  if (s === 'EXPLOITABLE') return 'bg-gray-850'
  if (s === 'IN_TRIAGE') return 'bg-gray-850'
  if (s === 'FALSE_POSITIVE') return 'bg-gray-850'
  return 'bg-gray-850'
})

const resolveTeamAlias = (name: string): string => {
  return name
}

const getComponentSummary = (instances: { component_name: string, component_version: string }[]) => {
  const map = new Map<string, Set<string>>()
  instances.forEach(i => {
    if (!map.has(i.component_name)) map.set(i.component_name, new Set())
    map.get(i.component_name)!.add(i.component_version)
  })
  return Array.from(map.entries()).map(([name, versions]) => ({
    name,
    versions: Array.from(versions).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
  }))
}

const getVersionGroupedInstances = (instances: any[]) => {
  const map = new Map<string, any[]>()
  instances.forEach(i => {
    const ver = i.project_version || '(unknown)'
    if (!map.has(ver)) map.set(ver, [])
    map.get(ver)!.push(i)
  })
  return Array.from(map.entries())
    .sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
    .map(([version, insts]) => ({ version, components: getComponentSummary(insts) }))
}

const parsedBlocks = computed(() => parseAssessmentBlocks(props.assessment.details))
</script>

<template>
  <div :class="['mb-3 last:mb-0 rounded-lg border border-gray-700 border-l-[3px] bg-gray-850 overflow-hidden', stateAccent]" data-testid="grouped-assessment">
    <!-- Card header: version chips + state accent -->
    <div :class="['flex flex-wrap items-center gap-1 px-3 py-1.5 border-b border-gray-700/30', stateHeaderBg]">
      <span
        v-for="vg in getVersionGroupedInstances(props.assessment.instances)"
        :key="vg.version"
        class="px-1.5 py-px text-[10px] font-mono font-bold bg-blue-900/30 text-blue-300 rounded border border-blue-800/30"
        :title="vg.components.map(c => c.name + '@' + c.versions.join(', ')).join(' · ')"
        data-testid="assessment-version-chip"
      >{{ vg.version }}</span>
      <span class="text-[9px] text-gray-600 ml-1">·</span>
      <span
        v-for="comp in getComponentSummary(props.assessment.instances)"
        :key="comp.name"
        class="px-1 py-px text-[10px] font-mono text-gray-500"
        data-testid="assessment-instance-badge"
      >{{ comp.name }}<span class="text-gray-600">@{{ comp.versions.join(', ') }}</span></span>
      <span class="flex-1"></span>
      <button
        v-if="props.isReviewer && (props.assessment.state !== 'NOT_SET' || props.assessment.details)"
        @click.stop="emit('apply-all', props.assessment.details, props.assessment.state, parsedBlocks[0]?.justification || 'NOT_SET')"
        class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wide bg-indigo-900/30 text-indigo-300 border border-indigo-700/40 hover:bg-indigo-800/40 hover:text-indigo-200 transition-colors cursor-pointer shrink-0"
        title="Apply this entire assessment to the form"
      >
        <ClipboardCopy :size="9" />
        Apply
      </button>
    </div>

    <!-- Card body -->
    <div class="px-3 py-2 space-y-1.5">
      <!-- Assessment blocks -->
      <div v-if="props.assessment.state !== 'NOT_SET' || props.assessment.details || props.assessment.comments.length > 0">
        <div v-if="props.assessment.state !== 'NOT_SET' || props.assessment.details" class="space-y-1.5">
          <div v-for="block in parsedBlocks" :key="block.team">
            <!-- Single-line header: team, state, justification, user, date -->
            <div class="flex items-center gap-1.5 text-[10px]">
              <span class="px-1.5 py-px rounded font-bold uppercase tracking-wider bg-blue-900/30 text-blue-300 border border-blue-800/40 shrink-0">
                {{ block.team === 'General' ? 'Global' : resolveTeamAlias(block.team) }}
              </span>
              <span
                v-if="block.state && block.state !== 'NOT_SET'"
                class="px-1.5 py-px rounded font-bold shrink-0"
                :class="{
                  'bg-green-900/40 text-green-200 border border-green-600/50': block.state === 'NOT_AFFECTED',
                  'bg-red-900/40 text-red-200 border border-red-600/50': block.state === 'EXPLOITABLE',
                  'bg-amber-900/40 text-amber-200 border border-amber-600/50': block.state === 'IN_TRIAGE',
                  'bg-teal-900/40 text-teal-200 border border-teal-600/50': block.state === 'FALSE_POSITIVE',
                  'bg-gray-800/60 text-gray-300 border border-gray-600/50': !['NOT_AFFECTED','EXPLOITABLE','IN_TRIAGE','FALSE_POSITIVE'].includes(block.state)
                }"
              >{{ block.state.replace(/_/g, ' ') }}</span>
              <span
                v-if="block.justification && block.justification !== 'NOT_SET'"
                class="text-gray-500 shrink-0"
              >· {{ block.justification.replace(/_/g, ' ') }}</span>
              <span class="flex-1"></span>
              <span v-if="block.user" class="text-gray-500 font-mono shrink-0">{{ block.user }}</span>
              <span v-if="block.timestamp" class="text-gray-600 font-mono shrink-0">{{ new Date(typeof block.timestamp === 'number' ? block.timestamp : parseInt(block.timestamp)).toLocaleDateString() }}</span>
              <button
                v-if="props.isReviewer"
                @click.stop="emit('adopt-team', block)"
                class="inline-flex items-center gap-0.5 px-1 py-0.5 rounded text-[8px] font-bold uppercase tracking-wide bg-teal-900/25 text-teal-400 border border-teal-700/40 hover:bg-teal-800/40 hover:text-teal-200 transition-colors cursor-pointer shrink-0 ml-auto"
                title="Merge this team assessment into the current form details"
              >
                <Plus :size="8" />
                Adopt
              </button>
            </div>
            <!-- Details text -->
            <div v-if="block.details && block.details.trim()" class="text-[11px] text-gray-400 mt-1 pl-2 border-l-2 border-gray-600/40 whitespace-pre-wrap break-words leading-snug">{{ block.details }}</div>
          </div>
        </div>
        <div v-else-if="props.assessment.comments.length > 0" class="text-[10px] text-gray-600 italic">
          No assessment state — comments only.
        </div>

        <!-- Audit trail -->
        <div v-if="props.assessment.comments.length > 0" class="mt-1.5">
          <button
            @click="showAuditLog = !showAuditLog"
            class="text-[9px] font-bold uppercase tracking-widest text-gray-600 hover:text-gray-400 transition-colors flex items-center gap-1"
          >
            <History :size="9" />
            {{ showAuditLog ? 'Hide' : 'Show' }} audit trail ({{ props.assessment.comments.length }})
          </button>

          <div v-if="showAuditLog" class="mt-1 space-y-0.5 max-h-[200px] overflow-y-auto bg-gray-950 p-2 rounded border border-gray-800">
            <div v-for="(c, ci) in props.assessment.comments" :key="ci" class="text-[10px] text-gray-500 pl-2 border-l border-gray-700/50 py-0.5 leading-snug">
              <span class="text-gray-400">{{ c.comment }}</span>
              <span class="text-gray-600 font-mono ml-1">{{ new Date(c.timestamp).toLocaleDateString() }}</span>
            </div>
          </div>
        </div>
      </div>
      <div v-else class="text-[10px] text-gray-600 italic">No assessment recorded.</div>

      <VulnGroupCardDependencies :instances="props.assessment.instances" />
    </div>
  </div>
</template>

<style scoped>
</style>
