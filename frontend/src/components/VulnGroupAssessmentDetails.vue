<script setup lang="ts">
import { ref } from 'vue'
import { History } from 'lucide-vue-next'
import { parseAssessmentBlocks } from '../lib/assessment-helpers'
import VulnGroupCardDependencies from './VulnGroupCardDependencies.vue'

const props = defineProps<{
  assessment: any
}>()

const showAuditLog = ref(false)

const getDistinctSortedProjectVersions = (instances: { project_version: string }[]) => {
  const allVersions = instances
    .map(i => i.project_version)
    .filter((v): v is string => !!v)

  const distinct = Array.from(new Set(allVersions))
  return distinct.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
}

const resolveTeamAlias = (name: string): string => {
  return name
}

const getStateDescription = (stateValue: string | undefined) => {
  if (!stateValue) return ''
  return ''
}

const getJustificationDescription = (justValue: string | undefined) => {
  if (!justValue) return ''
  return ''
}

const getVersionToComponentTooltip = (version: string, instances: any[]) => {
  const dataForVersion = instances.filter(i => i.project_version === version)
  const unique = Array.from(new Set(dataForVersion.map(i => `${i.component_name}@${i.component_version}`)))
  return unique.length ? unique.join(', ') : 'No components for this version'
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
</script>

<template>
  <div class="mb-8 last:mb-0 border-l-2 border-gray-700 pl-4 py-2 bg-gray-900/10 rounded-r-lg" data-testid="grouped-assessment">
    <div class="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Affected in</div>
    <div v-if="getDistinctSortedProjectVersions(props.assessment.instances).length === 0" class="text-xs text-gray-500 italic mt-1">
      Loading versions...
    </div>
    <div v-else class="flex flex-wrap gap-1 mt-1">
      <span
        v-for="ver in getDistinctSortedProjectVersions(props.assessment.instances)"
        :key="ver"
        class="px-1.5 py-0.5 text-[10px] font-mono font-semibold bg-blue-900/30 text-blue-300 rounded border border-blue-800/30"
        :title="getVersionToComponentTooltip(ver, props.assessment.instances)"
        data-testid="assessment-version-chip"
      >
        {{ ver }}
      </span>
    </div>

    <div class="mb-3 mt-4">
      <span class="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Components</span>
      <div class="flex flex-wrap gap-1.5 mt-1">
        <span
          v-for="comp in getComponentSummary(props.assessment.instances)"
          :key="comp.name"
          class="px-1.5 py-0.5 text-[10px] font-mono text-gray-300 bg-gray-800 rounded border border-gray-700"
          data-testid="assessment-instance-badge"
        >
          {{ comp.name }}<span class="text-gray-500">@{{ comp.versions.join(', ') }}</span>
        </span>
      </div>
    </div>

    <div v-if="props.assessment.state !== 'NOT_SET' || props.assessment.details || props.assessment.comments.length > 0" class="space-y-3">
      <div v-if="props.assessment.state !== 'NOT_SET' || props.assessment.details" class="space-y-3">
        <div v-for="block in parseAssessmentBlocks(props.assessment.details)" :key="block.team" class="bg-gray-800/60 rounded border border-gray-700/50 p-3">
          <div class="flex justify-between items-start mb-2">
            <div class="flex flex-wrap items-center gap-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-blue-900/40 text-blue-300 border border-blue-800/50">
                {{ block.team === 'General' ? 'Global Policy' : resolveTeamAlias(block.team) }}
              </span>
              <span
                v-if="block.state && block.state !== 'NOT_SET'"
                class="px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 bg-gray-700/50 text-gray-300 border border-gray-600/50 cursor-help"
                :title="getStateDescription(block.state)"
              >
                State: <span :class="block.state === 'NOT_AFFECTED' ? 'text-green-400' : (block.state === 'EXPLOITABLE' ? 'text-red-400' : 'text-gray-200')">{{ block.state }}</span>
              </span>
              <span
                v-if="block.justification && block.justification !== 'NOT_SET'"
                class="px-2 py-0.5 rounded text-[10px] font-bold text-gray-400 border border-gray-700 bg-gray-900/30 cursor-help"
                :title="getJustificationDescription(block.justification)"
              >
                {{ block.justification.replace(/_/g, ' ') }}
              </span>
            </div>
            <div class="text-[10px] text-gray-500 font-mono text-right shrink-0">
              <div v-if="block.user" class="text-gray-400">{{ block.user }}</div>
              <div v-if="block.timestamp">{{ new Date(typeof block.timestamp === 'number' ? block.timestamp : parseInt(block.timestamp)).toLocaleString() }}</div>
            </div>
          </div>
          <div v-if="block.details && block.details.trim()" class="text-sm text-gray-300 pl-2 border-l-2 border-gray-600 whitespace-pre-wrap break-words mt-2">
            {{ block.details }}
          </div>
        </div>
      </div>
      <div v-else-if="props.assessment.comments.length > 0" class="text-xs text-gray-500 italic opacity-50 pl-1 mb-2">
        No assessment state recorded, but comments available.
      </div>

      <div v-if="props.assessment.comments.length > 0" class="mt-4">
        <div class="flex items-center justify-between mb-2">
          <h5 class="text-[10px] font-black uppercase tracking-[0.2em] text-gray-600">Audit Trail ({{ props.assessment.comments.length }})</h5>
          <button
            @click="showAuditLog = !showAuditLog"
            class="text-[9px] font-black uppercase tracking-widest text-blue-500/70 hover:text-blue-400 transition-all flex items-center gap-1.5"
          >
            <History :size="10" />
            {{ showAuditLog ? 'Collapse Trail' : 'Expand Trail' }}
          </button>
        </div>

        <div v-if="showAuditLog" class="space-y-2 mt-2 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar bg-black/20 p-3 rounded-lg border border-white/5">
          <div v-for="(c, ci) in props.assessment.comments" :key="ci" class="text-xs text-gray-400 italic pl-3 border-l border-gray-700 py-0.5">
            {{ c.comment }} <span class="text-[10px] text-gray-600 not-italic block mt-0.5 font-bold">Assessed on {{ new Date(c.timestamp).toLocaleDateString() }}</span>
          </div>
        </div>
      </div>
    </div>
    <div v-else class="text-xs text-gray-500 italic opacity-50 pl-1">
      No assessment recorded for these versions.
    </div>

    <VulnGroupCardDependencies :instances="props.assessment.instances" />
  </div>
</template>

<style scoped>
</style>
