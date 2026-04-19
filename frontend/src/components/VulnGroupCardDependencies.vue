<script setup lang="ts">
import { ref, toRefs, inject, type Ref } from 'vue'
import { ChevronDown } from 'lucide-vue-next'
import DependencyChainViewer from './DependencyChainViewer.vue'
import { updateTeamMapping } from '../lib/api'
import { getClosestAffectedTeamsForInstance } from '../lib/dependency-team-selection'

const props = defineProps<{
  instances: any[]
}>()

const user = inject<any>('user', { role: 'ANALYST' })
const teamMapping = inject<Ref<Record<string, string | string[]>>>('teamMapping', ref({}))
const canEditMapping = user?.role === 'REVIEWER'

const getAssignedTeams = (inst: any) => {
  return getClosestAffectedTeamsForInstance(inst, teamMapping.value || {}).join(', ')
}

const editingComponentKey = ref<string | null>(null)
const tagInput = ref('')
const savingTag = ref(false)
const tagMessage = ref('')
const tagError = ref('')

const { instances } = toRefs(props)
const expandedChains = ref(new Set<string>())

const getComponentKey = (prefix: string, inst: any) => {
  const uuidPart = inst.component_uuid || inst.project_uuid || ''
  return `${prefix}-${uuidPart}-${inst.component_name}-${inst.component_version}`
}

const getCurrentMainTag = (componentName: string) => {
  const existing = teamMapping.value?.[componentName]
  if (Array.isArray(existing)) {
    return existing[0] || ''
  }
  return typeof existing === 'string' ? existing : ''
}

const getCurrentAliases = (componentName: string) => {
  const existing = teamMapping.value?.[componentName]
  return Array.isArray(existing) ? existing.slice(1) : []
}

const beginTagEdit = (componentKey: string, componentName: string) => {
  editingComponentKey.value = componentKey
  tagInput.value = getCurrentMainTag(componentName)
  tagMessage.value = ''
  tagError.value = ''
}

const cancelTagEdit = () => {
  editingComponentKey.value = null
  tagInput.value = ''
  tagMessage.value = ''
  tagError.value = ''
}

const saveComponentTeamTag = async (_componentKey: string, componentName: string) => {
  if (!canEditMapping) return

  savingTag.value = true
  tagMessage.value = ''
  tagError.value = ''

  try {
    const aliases = getCurrentAliases(componentName)
    const mainTag = tagInput.value.trim()
    const updatedMapping = { ...teamMapping.value }

    if (mainTag) {
      updatedMapping[componentName] = aliases.length > 0 ? [mainTag, ...aliases] : mainTag
    } else {
      delete updatedMapping[componentName]
    }

    const res = await updateTeamMapping(updatedMapping)
    if (res.status === 'success') {
      teamMapping.value = updatedMapping
      tagMessage.value = 'Team tag saved.'
      editingComponentKey.value = null
    } else {
      throw new Error(res.message)
    }
  } catch (err: any) {
    tagError.value = err.message || 'Failed to save team tag.'
  } finally {
    savingTag.value = false
  }
}

const partitionByRelationship = (instances: Array<{
  component_name: string
  component_version: string
  component_uuid?: string
  project_uuid?: string
  project_name?: string
  dependency_chains?: string[]
  is_direct_dependency?: boolean | null
}>) => {
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
    const key = i.component_uuid
      ? `${i.project_uuid || ''}:${i.component_uuid}`
      : `${i.project_uuid || ''}:${i.component_name}@${i.component_version}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

const getViewerSourcesForComponent = (componentName: string, componentVersion: string) => {
  return getUniqueComponentInstances(instances.value)
    .filter(i => i.component_name === componentName && i.component_version === componentVersion)
    .map(i => ({
      projectUuid: i.project_uuid,
      componentUuid: i.component_uuid,
      projectName: i.project_name,
      paths: i.dependency_chains,
    }))
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
          <div class="flex flex-col gap-2">
            <div class="flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0"></span>
              <span class="text-[10px] font-mono font-semibold text-gray-200">
                {{ inst.component_name }}<span class="text-gray-500">@{{ inst.component_version }}</span>
              </span>
              <span class="px-1 py-0 text-[8px] font-black uppercase text-red-400 bg-red-600/15 rounded border border-red-600/25">Direct</span>
              <div class="ml-auto flex items-center gap-2">
                <span class="text-[9px] text-gray-400">Team:</span>
                <span class="text-[9px] font-semibold uppercase text-blue-300">
                  {{ getAssignedTeams(inst) || 'none' }}
                </span>
                <button
                  v-if="canEditMapping"
                  type="button"
                  @click.stop="beginTagEdit(getComponentKey('d', inst), inst.component_name)"
                  class="text-[9px] text-blue-400 hover:text-blue-300 font-semibold transition-colors"
                >
                  Edit tag
                </button>
                <button
                  @click.stop="toggleChainForComponent(getComponentKey('d', inst))"
                  class="text-[9px] text-blue-500 hover:text-blue-400 font-semibold flex items-center gap-0.5 shrink-0"
                  title="Show dependency chains"
                >
                  <ChevronDown :size="10" :class="isChainExpanded(getComponentKey('d', inst)) ? 'rotate-180' : ''" class="transition-transform" />
                  chains
                </button>
              </div>
            </div>
            <div v-if="editingComponentKey === getComponentKey('d', inst)" class="ml-6 grid gap-2 md:grid-cols-[1fr_auto] items-end">
              <div>
                <label class="text-[9px] text-gray-400">Main team tag</label>
                <input
                  v-model="tagInput"
                  class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs text-gray-100"
                  placeholder="Primary tag"
                />
              </div>
              <div class="flex items-center gap-2">
                <button
                  @click="saveComponentTeamTag(getComponentKey('d', inst), inst.component_name)"
                  :disabled="savingTag"
                  class="rounded bg-green-600 hover:bg-green-700 text-white text-xs font-semibold px-3 py-2 transition-colors"
                >
                  Save
                </button>
                <button
                  @click="cancelTagEdit"
                  type="button"
                  class="rounded bg-gray-700 hover:bg-gray-600 text-gray-200 text-xs font-semibold px-3 py-2 transition-colors"
                >
                  Cancel
                </button>
              </div>
              <div class="col-span-full text-xs text-green-300" v-if="tagMessage && editingComponentKey === getComponentKey('d', inst)">{{ tagMessage }}</div>
              <div class="col-span-full text-xs text-red-400" v-if="tagError && editingComponentKey === getComponentKey('d', inst)">{{ tagError }}</div>
            </div>
          </div>
          <div v-if="isChainExpanded(getComponentKey('d', inst))" class="ml-4 mt-1">
            <DependencyChainViewer
              :key="'chain-d-' + inst.component_name + '-' + inst.component_version"
              :project-name="inst.project_name || ''"
              :sources="getViewerSourcesForComponent(inst.component_name, inst.component_version)"
            />
          </div>
        </div>
      </template>
      <template v-if="rel.transitive.length > 0">
        <div v-for="inst in rel.transitive" :key="getComponentKey('t', inst)" class="mb-1">
          <div class="flex flex-col gap-2">
            <div class="flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-purple-500/60 shrink-0"></span>
              <span class="text-[10px] font-mono text-gray-400">
                {{ inst.component_name }}<span class="text-gray-600">@{{ inst.component_version }}</span>
              </span>
              <span class="px-1 py-0 text-[8px] font-bold uppercase text-purple-400/70 bg-purple-600/10 rounded border border-purple-600/20">Transitive</span>
              <div class="ml-auto flex items-center gap-2">
                <span class="text-[9px] text-gray-400">Team:</span>
                <span class="text-[9px] font-semibold uppercase text-blue-300">
                  {{ getAssignedTeams(inst) || 'none' }}
                </span>
                <button
                  v-if="canEditMapping"
                  type="button"
                  @click.stop="beginTagEdit(getComponentKey('t', inst), inst.component_name)"
                  class="text-[9px] text-blue-400 hover:text-blue-300 font-semibold transition-colors"
                >
                  Edit tag
                </button>
                <button
                  @click.stop="toggleChainForComponent(getComponentKey('t', inst))"
                  class="text-[9px] text-blue-500 hover:text-blue-400 font-semibold flex items-center gap-0.5 shrink-0"
                  title="Show dependency chains"
                >
                  <ChevronDown :size="10" :class="isChainExpanded(getComponentKey('t', inst)) ? 'rotate-180' : ''" class="transition-transform" />
                  chains
                </button>
              </div>
            </div>
            <div v-if="editingComponentKey === getComponentKey('t', inst)" class="ml-6 grid gap-2 md:grid-cols-[1fr_auto] items-end">
              <div>
                <label class="text-[9px] text-gray-400">Main team tag</label>
                <input
                  v-model="tagInput"
                  class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs text-gray-100"
                  placeholder="Primary tag"
                />
              </div>
              <div class="flex items-center gap-2">
                <button
                  @click="saveComponentTeamTag(getComponentKey('t', inst), inst.component_name)"
                  :disabled="savingTag"
                  class="rounded bg-green-600 hover:bg-green-700 text-white text-xs font-semibold px-3 py-2 transition-colors"
                >
                  Save
                </button>
                <button
                  @click="cancelTagEdit"
                  type="button"
                  class="rounded bg-gray-700 hover:bg-gray-600 text-gray-200 text-xs font-semibold px-3 py-2 transition-colors"
                >
                  Cancel
                </button>
              </div>
              <div class="col-span-full text-xs text-green-300" v-if="tagMessage && editingComponentKey === getComponentKey('t', inst)">{{ tagMessage }}</div>
              <div class="col-span-full text-xs text-red-400" v-if="tagError && editingComponentKey === getComponentKey('t', inst)">{{ tagError }}</div>
            </div>
          </div>
          <div v-if="isChainExpanded(getComponentKey('t', inst))" class="ml-4 mt-1">
            <DependencyChainViewer
              :key="'chain-t-' + inst.component_name + '-' + inst.component_version"
              :project-name="inst.project_name || ''"
              :sources="getViewerSourcesForComponent(inst.component_name, inst.component_version)"
            />
          </div>
        </div>
      </template>
      <template v-if="rel.unknown.length > 0">
        <div v-for="inst in rel.unknown" :key="getComponentKey('u', inst)" class="mb-1">
          <div class="flex flex-col gap-2">
            <div class="flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-gray-600 shrink-0"></span>
              <span class="text-[10px] font-mono text-gray-500">
                {{ inst.component_name }}<span class="text-gray-600">@{{ inst.component_version }}</span>
              </span>
              <span class="px-1 py-0 text-[8px] font-bold uppercase text-gray-500 bg-gray-700/20 rounded border border-gray-600/25">Unknown</span>
              <div class="ml-auto flex items-center gap-2">
                <span class="text-[9px] text-gray-400">Team:</span>
                <span class="text-[9px] font-semibold uppercase text-blue-300">
                  {{ getAssignedTeams(inst) || 'none' }}
                </span>
                <button
                  v-if="canEditMapping"
                  type="button"
                  @click.stop="beginTagEdit(getComponentKey('u', inst), inst.component_name)"
                  class="text-[9px] text-blue-400 hover:text-blue-300 font-semibold transition-colors"
                >
                  Edit tag
                </button>
                <button
                  @click.stop="toggleChainForComponent(getComponentKey('u', inst))"
                  class="text-[9px] text-blue-500 hover:text-blue-400 font-semibold flex items-center gap-0.5 shrink-0"
                  title="Show dependency chains"
                >
                  <ChevronDown :size="10" :class="isChainExpanded(getComponentKey('u', inst)) ? 'rotate-180' : ''" class="transition-transform" />
                  chains
                </button>
              </div>
            </div>
            <div v-if="editingComponentKey === getComponentKey('u', inst)" class="ml-6 grid gap-2 md:grid-cols-[1fr_auto] items-end">
              <div>
                <label class="text-[9px] text-gray-400">Main team tag</label>
                <input
                  v-model="tagInput"
                  class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs text-gray-100"
                  placeholder="Primary tag"
                />
              </div>
              <div class="flex items-center gap-2">
                <button
                  @click="saveComponentTeamTag(getComponentKey('u', inst), inst.component_name)"
                  :disabled="savingTag"
                  class="rounded bg-green-600 hover:bg-green-700 text-white text-xs font-semibold px-3 py-2 transition-colors"
                >
                  Save
                </button>
                <button
                  @click="cancelTagEdit"
                  type="button"
                  class="rounded bg-gray-700 hover:bg-gray-600 text-gray-200 text-xs font-semibold px-3 py-2 transition-colors"
                >
                  Cancel
                </button>
              </div>
              <div class="col-span-full text-xs text-green-300" v-if="tagMessage && editingComponentKey === getComponentKey('u', inst)">{{ tagMessage }}</div>
              <div class="col-span-full text-xs text-red-400" v-if="tagError && editingComponentKey === getComponentKey('u', inst)">{{ tagError }}</div>
            </div>
          </div>
          <div v-if="isChainExpanded(getComponentKey('u', inst))" class="ml-4 mt-1">
            <DependencyChainViewer
              :key="'chain-u-' + inst.component_name + '-' + inst.component_version"
              :project-name="inst.project_name || ''"
              :sources="getViewerSourcesForComponent(inst.component_name, inst.component_version)"
            />
          </div>
        </div>
      </template>
    </template>
  </div>
</template>
