<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  instance: any
}>()

const emit = defineEmits(['update'])

const structuredGroups = computed(() => {
  const instance = props.instance
  if (!instance) return null

  try {
    const map = instance.getRegisteredComponents()
    const groups: { category: string, components: any[] }[] = []
    for (const [cat, list] of map.entries()) {
      groups.push({
        category: cat.name,
        components: list
      })
    }
    return { generic: groups }
  } catch (e) {
    console.error("Error getting components", e)
    return null
  }
})
</script>

<template>
  <div v-if="structuredGroups?.generic" class="space-y-6">
    <div v-for="group in structuredGroups.generic" :key="group.category" class="bg-gray-850 rounded p-4 border border-gray-700">
      <h4 class="font-bold text-blue-400 border-b border-gray-700 pb-2 mb-3 tracking-wide uppercase text-xs">
        {{ group.category }} Metrics
      </h4>
      
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div v-for="comp in group.components" :key="comp.shortName" class="border-b border-gray-700 pb-2 border-opacity-50 last:border-0">
          <label :for="`metric-${comp.shortName}`" class="block text-sm font-bold text-gray-300 mb-1" :title="comp.description">
            {{ comp.name }} ({{ comp.shortName }})
          </label>
          <select 
            :id="`metric-${comp.shortName}`"
            :value="instance.getComponent(comp).shortName" 
            @change="emit('update', comp.shortName, ($event.target as HTMLSelectElement).value)"
            class="w-full p-2 rounded bg-gray-900 border border-gray-600 text-sm text-gray-200 focus:border-blue-500"
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
