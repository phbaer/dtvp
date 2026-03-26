<script setup lang="ts">
import { computed, ref } from 'vue'

const props = defineProps<{
  paths: string[]
  projectName?: string
  teamMappedNames?: Map<string, string[]>
}>()

const isTeamMapped = (name: string): boolean => {
  return !!props.teamMappedNames?.has(name)
}

const getTeamNames = (name: string): string => {
  const teams = props.teamMappedNames?.get(name)
  return teams?.[0] || ''
}

interface ParsedChain {
  parts: string[]       // all parts without project root
  directDep: string     // first part (the direct dependency)
  affected: string      // last part (the vulnerable component)
  intermediates: string[] // parts between directDep and affected
}

const parsedChains = computed<ParsedChain[]>(() => {
  if (!props.paths?.length) return []

  return props.paths
    .map(p => {
      const parts = p.split(' -> ').map(s => s.trim())
      const withoutRoot = parts.slice(1)
      if (withoutRoot.length === 0) return null

      return {
        parts: withoutRoot,
        directDep: withoutRoot[0],
        affected: withoutRoot[withoutRoot.length - 1],
        intermediates: withoutRoot.length > 2 ? withoutRoot.slice(1, -1) : []
      } as ParsedChain
    })
    .filter((c): c is ParsedChain => c !== null)
    .sort((a, b) => a.parts.length - b.parts.length)
})

interface ChainGroup {
  directDep: string
  isDirect: boolean
  chains: ParsedChain[]
  shortestDepth: number
}

const groupedChains = computed<ChainGroup[]>(() => {
  const groups = new Map<string, ChainGroup>()

  for (const chain of parsedChains.value) {
    const key = chain.directDep
    if (!groups.has(key)) {
      groups.set(key, {
        directDep: key,
        isDirect: false,
        chains: [],
        shortestDepth: chain.parts.length
      })
    }
    const group = groups.get(key)!
    group.chains.push(chain)
    group.shortestDepth = Math.min(group.shortestDepth, chain.parts.length)
    if (chain.parts.length === 1) group.isDirect = true
  }

  return Array.from(groups.values()).sort((a, b) => {
    if (a.isDirect !== b.isDirect) return a.isDirect ? -1 : 1
    if (a.shortestDepth !== b.shortestDepth) return a.shortestDepth - b.shortestDepth
    return a.directDep.localeCompare(b.directDep)
  })
})

const INITIAL_GROUPS = 8
const INITIAL_CHAINS = 3
const showAllGroups = ref(false)
const expandedGroups = ref(new Set<string>())

const visibleGroups = computed(() => {
  if (showAllGroups.value) return groupedChains.value
  return groupedChains.value.slice(0, INITIAL_GROUPS)
})

const hiddenGroupCount = computed(() =>
  Math.max(0, groupedChains.value.length - INITIAL_GROUPS)
)

const toggleGroup = (key: string) => {
  const s = new Set(expandedGroups.value)
  if (s.has(key)) s.delete(key)
  else s.add(key)
  expandedGroups.value = s
}

const getVisibleChains = (key: string, chains: ParsedChain[]) => {
  if (expandedGroups.value.has(key) || chains.length <= INITIAL_CHAINS) return chains
  return chains.slice(0, INITIAL_CHAINS)
}
</script>

<template>
  <div class="text-xs">
    <div v-if="parsedChains.length === 0" class="text-gray-500 italic">
      No dependency chains found.
    </div>

    <div v-else class="space-y-2">
      <div v-for="group in visibleGroups" :key="group.directDep">
        <!-- Direct dep row -->
        <div class="flex items-center gap-1.5">
          <span class="w-1.5 h-1.5 rounded-full shrink-0" :class="group.isDirect ? 'bg-red-500' : 'bg-orange-400'"></span>
          <span class="text-[11px] font-semibold font-mono" :class="group.isDirect ? 'text-red-300' : 'text-orange-300'">{{ group.directDep }}</span>
          <span v-if="isTeamMapped(group.directDep)" class="px-1 py-0 text-[8px] font-bold uppercase text-teal-400 bg-teal-600/15 rounded border border-teal-600/25" :title="'Team-mapped component (' + getTeamNames(group.directDep) + ') \u2014 direct dependencies of this component are classified as direct'">{{ getTeamNames(group.directDep) }}</span>
          <span v-if="group.isDirect" class="text-[9px] font-bold uppercase text-red-400/70">(direct)</span>
          <span v-if="group.chains.length > 1" class="text-[9px] text-gray-600">{{ group.chains.length }} paths</span>
        </div>

        <!-- Chain paths under this direct dep -->
        <div v-if="!group.isDirect" class="ml-3 mt-0.5 space-y-0.5">
          <div
            v-for="(chain, ci) in getVisibleChains(group.directDep, group.chains)"
            :key="ci"
            class="flex items-center gap-0 text-[10px] font-mono text-gray-500 leading-relaxed flex-wrap"
          >
            <span class="text-gray-600 mx-0.5">→</span>
            <template v-for="(mid, mi) in chain.intermediates" :key="mi">
              <span :class="isTeamMapped(mid) ? 'text-teal-400 font-semibold' : 'text-gray-500'" :title="isTeamMapped(mid) ? 'Team: ' + getTeamNames(mid) : undefined">{{ mid }}</span>
              <span v-if="isTeamMapped(mid)" class="px-0.5 py-0 text-[7px] font-bold uppercase text-teal-400/70 ml-0.5">{{ getTeamNames(mid) }}</span>
              <span v-if="mi < chain.intermediates.length - 1" class="text-gray-600 mx-0.5">→</span>
            </template>
          </div>

          <!-- Show more paths toggle -->
          <button
            v-if="group.chains.length > INITIAL_CHAINS"
            @click="toggleGroup(group.directDep)"
            class="text-[9px] text-blue-500 hover:text-blue-400 ml-2"
          >
            {{ expandedGroups.has(group.directDep) ? 'show less' : `+${group.chains.length - INITIAL_CHAINS} more` }}
          </button>
        </div>
      </div>

      <!-- Show more groups toggle -->
      <button
        v-if="hiddenGroupCount > 0"
        @click="showAllGroups = !showAllGroups"
        class="text-[9px] text-blue-500 hover:text-blue-400 mt-1"
      >
        {{ showAllGroups ? 'show fewer' : `+${hiddenGroupCount} more dependencies` }}
      </button>
    </div>
  </div>
</template>
