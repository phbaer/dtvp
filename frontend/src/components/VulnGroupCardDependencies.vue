<script setup lang="ts">
import { ref, toRefs } from 'vue'
import { ChevronDown } from 'lucide-vue-next'
import DependencyChainViewer from './DependencyChainViewer.vue'

const props = defineProps<{
  instances: any[]
}>()

const { instances } = toRefs(props)
const expandedChains = ref(new Set<string>())

const getComponentKey = (prefix: string, inst: any) => `${prefix}-${inst.component_name}-${inst.component_version}`

const partitionByRelationship = (instances: { component_name: string; component_version: string; is_direct_dependency?: boolean | null }[]) => {
  const direct: typeof instances = []
  const transitive: typeof instances = []
  const unknown: typeof instances = []
  const seenDirect = new Set<string>()
  const seenTransitive = new Set<string>()
  const seenUnknown = new Set<string>()

  instances.forEach(i => {
    const key = `${i.component_name}@${i.component_version}`
    if (i.is_direct_dependency === true) {
      if (!seenDirect.has(key)) { direct.push(i); seenDirect.add(key) }
    } else if (i.is_direct_dependency === false) {
      if (!seenTransitive.has(key)) { transitive.push(i); seenTransitive.add(key) }
    } else {
      if (!seenUnknown.has(key)) { unknown.push(i); seenUnknown.add(key) }
    }
  })

  return { direct, transitive, unknown }
}

const getUniqueComponentInstances = (instances: { component_name: string; component_version: string; component_uuid: string; project_uuid: string; project_name: string; dependency_chains?: string[] }[]) => {
  const seen = new Set<string>()
  return instances.filter(i => {
    const key = `${i.component_name}@${i.component_version}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

const toggleChainForComponent = (id: string) => {
  if (expandedChains.value.has(id)) {
    expandedChains.value.delete(id)
  } else {
    expandedChains.value.add(id)
  }
}

const isChainExpanded = (id: string) => {
  return expandedChains.value.has(id)
}
</script>

<template>
  <div class="mt-4 pt-2 border-t border-gray-800/50">
    <div class="text-[10px] font-bold text-gray-600 uppercase tracking-widest mb-2">
      Dependencies
    </div>
    <template v-for="(rel, relIdx) in [partitionByRelationship(instances)]" :key="relIdx">
      <template v-if="rel.direct.length > 0">
        <div v-for="inst in rel.direct" :key="getComponentKey('d', inst)" class="mb-1">
          <div class="flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0"></span>
            <span class="text-[10px] font-mono font-semibold text-gray-200">
              {{ inst.component_name }}<span class="text-gray-500">@{{ inst.component_version }}</span>
            </span>
            <span class="px-1 py-0 text-[8px] font-black uppercase text-red-400 bg-red-600/15 rounded border border-red-600/25">Direct</span>
            <button
              @click.stop="toggleChainForComponent(getComponentKey('d', inst))"
              class="ml-auto text-[9px] text-blue-500 hover:text-blue-400 font-semibold flex items-center gap-0.5 shrink-0"
              title="Show dependency chains"
            >
              <ChevronDown :size="10" :class="isChainExpanded(getComponentKey('d', inst)) ? 'rotate-180' : ''" class="transition-transform" />
              chains
            </button>
          </div>
          <div v-if="isChainExpanded(getComponentKey('d', inst))" class="ml-4 mt-1">
            <DependencyChainViewer
              v-for="ui in getUniqueComponentInstances(instances).filter(u => u.component_name === inst.component_name && u.component_version === inst.component_version)"
              :key="'chain-d-' + ui.component_uuid"
              :project-uuid="ui.project_uuid"
              :component-uuid="ui.component_uuid"
              :project-name="ui.project_name"
              :paths="ui.dependency_chains"
            />
          </div>
        </div>
      </template>
      <template v-if="rel.transitive.length > 0">
        <div v-for="inst in rel.transitive" :key="getComponentKey('t', inst)" class="mb-1">
          <div class="flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-purple-500/60 shrink-0"></span>
            <span class="text-[10px] font-mono text-gray-400">
              {{ inst.component_name }}<span class="text-gray-600">@{{ inst.component_version }}</span>
            </span>
            <span class="px-1 py-0 text-[8px] font-bold uppercase text-purple-400/70 bg-purple-600/10 rounded border border-purple-600/20">Transitive</span>
            <button
              @click.stop="toggleChainForComponent(getComponentKey('t', inst))"
              class="ml-auto text-[9px] text-blue-500 hover:text-blue-400 font-semibold flex items-center gap-0.5 shrink-0"
              title="Show dependency chains"
            >
              <ChevronDown :size="10" :class="isChainExpanded(getComponentKey('t', inst)) ? 'rotate-180' : ''" class="transition-transform" />
              chains
            </button>
          </div>
          <div v-if="isChainExpanded(getComponentKey('t', inst))" class="ml-4 mt-1">
            <DependencyChainViewer
              v-for="ui in getUniqueComponentInstances(instances).filter(u => u.component_name === inst.component_name && u.component_version === inst.component_version)"
              :key="'chain-t-' + ui.component_uuid"
              :project-uuid="ui.project_uuid"
              :component-uuid="ui.component_uuid"
              :project-name="ui.project_name"
              :paths="ui.dependency_chains"
            />
          </div>
        </div>
      </template>
      <template v-if="rel.unknown.length > 0">
        <div v-for="inst in rel.unknown" :key="getComponentKey('u', inst)" class="mb-1">
          <div class="flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-gray-600 shrink-0"></span>
            <span class="text-[10px] font-mono text-gray-500">
              {{ inst.component_name }}<span class="text-gray-600">@{{ inst.component_version }}</span>
            </span>
            <span class="px-1 py-0 text-[8px] font-bold uppercase text-gray-500 bg-gray-700/20 rounded border border-gray-600/25">Unknown</span>
            <button
              @click.stop="toggleChainForComponent(getComponentKey('u', inst))"
              class="ml-auto text-[9px] text-blue-500 hover:text-blue-400 font-semibold flex items-center gap-0.5 shrink-0"
              title="Show dependency chains"
            >
              <ChevronDown :size="10" :class="isChainExpanded(getComponentKey('u', inst)) ? 'rotate-180' : ''" class="transition-transform" />
              chains
            </button>
          </div>
          <div v-if="isChainExpanded(getComponentKey('u', inst))" class="ml-4 mt-1">
            <DependencyChainViewer
              v-for="ui in getUniqueComponentInstances(instances).filter(u => u.component_name === inst.component_name && u.component_version === inst.component_version)"
              :key="'chain-u-' + ui.component_uuid"
              :project-uuid="ui.project_uuid"
              :component-uuid="ui.component_uuid"
              :project-name="ui.project_name"
              :paths="ui.dependency_chains"
            />
          </div>
        </div>
      </template>
    </template>
  </div>
</template>
