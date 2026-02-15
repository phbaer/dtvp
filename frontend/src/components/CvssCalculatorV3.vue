<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  instance: any
  canEditBase: boolean
}>()

const emit = defineEmits(['update', 'reset'])

const structuredGroups = computed(() => {
  const instance = props.instance
  if (!instance) return null

  try {
    const map = instance.getRegisteredComponents()
    const allComponents: any[] = []
    for (const [_, list] of map.entries()) {
      allComponents.push(...list)
    }

    const getComp = (shortName: string) => allComponents.find(c => c.shortName === shortName)
    const mkRow = (base: string, mod?: string, req?: string) => ({
      base: getComp(base),
      mod: mod ? getComp(mod) : undefined,
      req: req ? getComp(req) : undefined
    })

    return {
      rows: [
        mkRow('AV', 'MAV'),
        mkRow('AC', 'MAC'),
        mkRow('PR', 'MPR'),
        mkRow('UI', 'MUI'),
        mkRow('S', 'MS'),
        mkRow('C', 'MC', 'CR'),
        mkRow('I', 'MI', 'IR'),
        mkRow('A', 'MA', 'AR')
      ].filter(r => r.base),
      temporal: [
        getComp('E'), getComp('RL'), getComp('RC')
      ].filter(Boolean)
    }
  } catch (e) {
    console.error("Error getting components", e)
    return null
  }
})
</script>

<template>
  <div v-if="structuredGroups" class="space-y-6">
    <!-- Base & Environmental/Modified Metrics Table -->
    <div class="bg-gray-900/50 rounded border border-gray-700/50 overflow-hidden">
      <div class="p-3 bg-gray-800/50 border-b border-gray-700/50 flex justify-between items-center">
        <h4 class="font-bold text-gray-400 tracking-wide uppercase text-xs">Correction / Rescoring</h4>
        <button @click="emit('reset')" class="text-[10px] text-blue-400 hover:text-blue-300 font-bold uppercase tracking-wider">Reset All</button>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse text-xs">
          <thead>
            <tr class="text-gray-500 uppercase font-bold bg-gray-800/30 border-b border-gray-700/50">
              <th class="py-2 px-3 w-1/4">Metric</th>
              <th class="py-2 px-3 w-1/4">Base (Read Only)</th>
              <th class="py-2 px-3 w-1/4 text-indigo-300">Requirement</th>
              <th class="py-2 px-3 w-1/4 text-purple-300">Modified</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in structuredGroups.rows" :key="row.base.shortName" class="border-b border-gray-800 last:border-0 hover:bg-gray-800/20 transition-colors">
              <td class="py-2 px-3 font-bold text-gray-400" :title="row.base.description">
                {{ row.base.name }} <span class="text-gray-600 ml-1">({{ row.base.shortName }})</span>
              </td>
              <td class="py-2 px-3">
                <div v-if="!canEditBase" class="font-mono bg-gray-900 px-2 py-1 rounded border border-gray-700 text-gray-300 w-fit inline-block">
                  {{ instance.getComponent(row.base).name }}
                </div>
                <select 
                  v-else
                  :id="`metric-${row.base.shortName}`"
                  :value="instance.getComponent(row.base).shortName" 
                  @change="emit('update', row.base.shortName, ($event.target as HTMLSelectElement).value)"
                  class="w-full p-1.5 rounded bg-gray-900 border border-gray-600 text-gray-300 focus:border-blue-400 focus:ring-1 focus:ring-blue-400 outline-none cursor-pointer"
                >
                  <option v-for="val in row.base.values" :key="val.shortName" :value="val.shortName" :title="val.description">
                    {{ val.name }}
                  </option>
                </select>
              </td>
              <td class="py-2 px-3">
                <select 
                  v-if="row.req"
                  :id="`metric-${row.req.shortName}`"
                  :value="instance.getComponent(row.req).shortName" 
                  @change="emit('update', row.req.shortName, ($event.target as HTMLSelectElement).value)"
                  class="w-full p-1.5 rounded bg-gray-900 border border-gray-600 text-indigo-100 focus:border-indigo-400 focus:ring-1 focus:ring-indigo-400 outline-none cursor-pointer"
                >
                  <option v-for="val in row.req.values" :key="val.shortName" :value="val.shortName" :title="val.description">
                    {{ val.name }}
                  </option>
                </select>
                <span v-else class="text-gray-700 select-none">-</span>
              </td>
              <td class="py-2 px-3">
                <select 
                  v-if="row.mod"
                  :id="`metric-${row.mod.shortName}`"
                  :value="instance.getComponent(row.mod).shortName" 
                  @change="emit('update', row.mod.shortName, ($event.target as HTMLSelectElement).value)"
                  class="w-full p-1.5 rounded bg-gray-900 border border-gray-600 text-purple-100 focus:border-purple-400 focus:ring-1 focus:ring-purple-400 outline-none cursor-pointer"
                >
                  <option v-for="val in row.mod.values" :key="val.shortName" :value="val.shortName" :title="val.description">
                    {{ val.name }}
                  </option>
                </select>
                <span v-else class="text-gray-700 select-none">-</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Temporal Group -->
    <div v-if="structuredGroups.temporal?.length" class="bg-gray-850 rounded p-4 border border-gray-700">
      <h4 class="font-bold text-blue-400 border-b border-gray-700 pb-2 mb-3 tracking-wide uppercase text-xs">
        Temporal Metrics
      </h4>
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div v-for="comp in structuredGroups.temporal" :key="comp.shortName">
          <label class="block text-xs font-bold text-gray-400 mb-1" :title="comp.description">
            {{ comp.name }}
          </label>
          <select 
            :value="instance.getComponent(comp).shortName" 
            @change="emit('update', comp.shortName, ($event.target as HTMLSelectElement).value)"
            class="w-full p-1.5 rounded bg-gray-900 border border-gray-600 text-xs text-gray-200 focus:border-blue-500 cursor-pointer"
          >
            <option v-for="val in comp.values" :key="val.shortName" :value="val.shortName" :title="val.description">
              {{ val.name }} ({{ val.shortName }})
            </option>
          </select>
        </div>
      </div>
    </div>
  </div>
</template>
