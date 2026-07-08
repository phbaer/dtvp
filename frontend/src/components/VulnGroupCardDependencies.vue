<script setup lang="ts">
import { computed, ref, toRefs, inject, type Ref } from 'vue'
import { ChevronDown } from 'lucide-vue-next'
import DependencyChainViewer from './DependencyChainViewer.vue'
import { updateTeamMapping } from '../lib/api'
import {
  findTeamMappingEntryForComponent,
  getClosestAffectedTeamsForInstance,
  getPathParts,
} from '../lib/dependency-team-selection'

const props = defineProps<{
  instances: any[]
  mode?: 'dependencies' | 'mapping'
  embedded?: boolean
  showTitle?: boolean
}>()

const emit = defineEmits<{
  (e: 'mapping-updated'): void
}>()

const user = inject<any>('user', { role: 'ANALYST' })
const teamMapping = inject<Ref<Record<string, string | string[]>>>('teamMapping', ref({}))
const canEditMapping = computed(() => {
  const currentUser = user?.value ?? user
  return currentUser?.role === 'REVIEWER'
})
const isMappingMode = computed(() => props.mode === 'mapping')
const showMappingControls = computed(() => canEditMapping.value && isMappingMode.value)

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

const hasOwn = (value: any, key: string) => Object.prototype.hasOwnProperty.call(value || {}, key)

const getComponentKey = (prefix: string, inst: any) => {
  const uuidPart = inst.component_uuid || inst.project_uuid || ''
  return `${prefix}-${uuidPart}-${inst.component_name}-${inst.component_version}`
}

const buildMappingKey = (
  componentName: string,
  componentGroup?: string | null,
  groupKnown = false,
) => {
  const name = componentName.trim()
  const group = String(componentGroup || '').trim()
  if (groupKnown && group) return `${group}:${name}`
  return name
}

const findMappingEntry = (
  componentName: string,
  componentGroup?: string | null,
  groupKnown = false,
  componentPurl?: string | null,
) => findTeamMappingEntryForComponent(
  componentName,
  teamMapping.value || {},
  componentGroup,
  groupKnown,
  componentPurl,
)

const getCurrentMainTag = (
  componentName: string,
  componentGroup?: string | null,
  groupKnown = false,
  componentPurl?: string | null,
) => {
  const existing = findMappingEntry(componentName, componentGroup, groupKnown, componentPurl)?.value
  if (Array.isArray(existing)) {
    return existing[0] || ''
  }
  return typeof existing === 'string' ? existing : ''
}

const getCurrentAliases = (
  componentName: string,
  componentGroup?: string | null,
  groupKnown = false,
  componentPurl?: string | null,
) => {
  const existing = findMappingEntry(componentName, componentGroup, groupKnown, componentPurl)?.value
  return Array.isArray(existing) ? existing.slice(1) : []
}

const vulnScopedComponents = computed(() => {
  const seen = new Set<string>()
  const collected: Array<{
    key: string
    label: string
    mappingKey: string
    name: string
    group?: string | null
    purl?: string | null
    groupKnown: boolean
  }> = []

  const addComponent = (
    componentName: any,
    componentGroup?: any,
    groupKnown = false,
    componentPurl?: any,
  ) => {
    const name = String(componentName || '').trim()
    if (!name) return
    const group = String(componentGroup || '').trim()
    const mappingKey = buildMappingKey(name, group || null, groupKnown)
    const key = `${groupKnown ? group || '<nogroup>' : '<unknown>'}:${name}`.toLowerCase()
    if (seen.has(key)) return
    seen.add(key)
    collected.push({
      key,
      label: mappingKey,
      mappingKey,
      name,
      group: group || null,
      purl: String(componentPurl || '').trim() || null,
      groupKnown,
    })
  }

  instances.value.forEach((inst) => {
    if (inst.component_name) {
      addComponent(
        inst.component_name,
        inst.component_group,
        hasOwn(inst, 'component_group'),
        inst.component_purl,
      )
    }

    ;(inst.dependency_chains || []).forEach((path: string) => {
      const parts = getPathParts(path)
      parts.forEach((part, index) => {
        if (index === 0) return
        if (index === parts.length - 1) return
        addComponent(part)
      })
    })
  })

  return collected
    .sort((left, right) => left.label.localeCompare(right.label))
})

const beginTagEdit = (
  componentKey: string,
  componentName: string,
  componentGroup?: string | null,
  groupKnown = false,
  componentPurl?: string | null,
) => {
  editingComponentKey.value = componentKey
  tagInput.value = getCurrentMainTag(componentName, componentGroup, groupKnown, componentPurl)
  tagMessage.value = ''
  tagError.value = ''
}

const cancelTagEdit = () => {
  editingComponentKey.value = null
  tagInput.value = ''
  tagMessage.value = ''
  tagError.value = ''
}

const saveComponentTeamTag = async (
  _componentKey: string,
  componentName: string,
  componentGroup?: string | null,
  groupKnown = false,
  componentPurl?: string | null,
) => {
  if (!canEditMapping.value) return

  savingTag.value = true
  tagMessage.value = ''
  tagError.value = ''

  try {
    const existingEntry = findMappingEntry(componentName, componentGroup, groupKnown, componentPurl)
    const mappingKey = existingEntry?.key || buildMappingKey(componentName, componentGroup, groupKnown)
    const aliases = getCurrentAliases(componentName, componentGroup, groupKnown, componentPurl)
    const mainTag = tagInput.value.trim()
    const updatedMapping = { ...teamMapping.value }

    if (mainTag) {
      updatedMapping[mappingKey] = aliases.length > 0 ? [mainTag, ...aliases] : mainTag
    } else {
      delete updatedMapping[mappingKey]
    }

    const res = await updateTeamMapping(updatedMapping)
    if (res.status === 'success') {
      teamMapping.value = updatedMapping
      tagMessage.value = 'Team tag saved.'
      editingComponentKey.value = null
      emit('mapping-updated')
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
  component_group?: string | null
  component_purl?: string | null
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

const getUniqueComponentInstances = (instances: { component_name: string; component_purl?: string | null; component_version: string; component_uuid: string; project_uuid: string; project_name: string; dependency_chains?: string[] }[]) => {
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
  <div v-if="isMappingMode" class="rounded border border-gray-700 bg-gray-900/45 p-3">
    <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
      <div>
        <h5 class="text-xs font-bold uppercase tracking-wider text-gray-400">Component Team Mapping</h5>
        <p class="mt-1 text-[10px] text-gray-500">Reviewer-only ownership tags for components seen in this vulnerability.</p>
      </div>
      <span class="text-[10px] font-semibold text-gray-500">{{ vulnScopedComponents.length }} component{{ vulnScopedComponents.length === 1 ? '' : 's' }}</span>
    </div>

    <div v-if="showMappingControls" class="space-y-3">
      <div class="max-h-96 overflow-y-auto divide-y divide-gray-800 rounded border border-gray-800 bg-gray-950/35">
        <div
          v-for="component in vulnScopedComponents"
          :key="component.key"
          data-testid="component-team-mapping-row"
          class="p-2"
        >
          <div class="flex flex-wrap items-center gap-2">
            <span class="min-w-0 flex-1 truncate font-mono text-xs text-gray-200">{{ component.label }}</span>
            <span class="text-[9px] text-gray-500">Team:</span>
            <span class="rounded border border-blue-800/40 bg-blue-950/20 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-blue-300">
              {{ getCurrentMainTag(component.name, component.group, component.groupKnown, component.purl) || 'none' }}
            </span>
            <button
              type="button"
              @click.stop="beginTagEdit(component.key, component.name, component.group, component.groupKnown, component.purl)"
              class="text-[10px] font-semibold text-blue-400 transition-colors hover:text-blue-300"
            >
              Edit tag
            </button>
          </div>
          <div v-if="editingComponentKey === component.key" class="mt-2 grid gap-2 md:grid-cols-[1fr_auto] items-end">
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
                @click="saveComponentTeamTag(component.key, component.name, component.group, component.groupKnown, component.purl)"
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
            <div class="col-span-full text-xs text-green-300" v-if="tagMessage && editingComponentKey === component.key">{{ tagMessage }}</div>
            <div class="col-span-full text-xs text-red-400" v-if="tagError && editingComponentKey === component.key">{{ tagError }}</div>
          </div>
        </div>
        <div v-if="vulnScopedComponents.length === 0" class="px-3 py-4 text-xs text-gray-500">
          No component identities are available for this vulnerability.
        </div>
      </div>
      <div v-if="tagMessage && !editingComponentKey" class="text-xs text-green-300">{{ tagMessage }}</div>
    </div>

    <div v-else class="text-xs text-gray-500">
      Team mapping edits are available to reviewers.
    </div>
  </div>

  <div v-else :class="[props.embedded !== false ? 'mt-4 pt-2 border-t border-gray-800/50' : '']">
    <div v-if="props.showTitle !== false" class="text-[10px] font-bold text-gray-600 uppercase tracking-widest mb-2">
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
                  @click.stop="toggleChainForComponent(getComponentKey('d', inst))"
                  class="text-[9px] text-blue-500 hover:text-blue-400 font-semibold flex items-center gap-0.5 shrink-0"
                  title="Show dependency chains"
                >
                  <ChevronDown :size="10" :class="isChainExpanded(getComponentKey('d', inst)) ? 'rotate-180' : ''" class="transition-transform" />
                  chains
                </button>
              </div>
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
                  @click.stop="toggleChainForComponent(getComponentKey('t', inst))"
                  class="text-[9px] text-blue-500 hover:text-blue-400 font-semibold flex items-center gap-0.5 shrink-0"
                  title="Show dependency chains"
                >
                  <ChevronDown :size="10" :class="isChainExpanded(getComponentKey('t', inst)) ? 'rotate-180' : ''" class="transition-transform" />
                  chains
                </button>
              </div>
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
                  @click.stop="toggleChainForComponent(getComponentKey('u', inst))"
                  class="text-[9px] text-blue-500 hover:text-blue-400 font-semibold flex items-center gap-0.5 shrink-0"
                  title="Show dependency chains"
                >
                  <ChevronDown :size="10" :class="isChainExpanded(getComponentKey('u', inst)) ? 'rotate-180' : ''" class="transition-transform" />
                  chains
                </button>
              </div>
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
