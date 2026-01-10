<script setup lang="ts">
import { computed } from 'vue'
import { Box, ShieldAlert } from 'lucide-vue-next'

const props = defineProps<{
  paths: string[]
  projectName?: string
}>()

const parsedPaths = computed(() => {
  return props.paths.map(p => {
    // Input: Child -> Parent -> Root
    // Reverse: [Root, Parent, Child]
    const parts = p.split(' -> ').reverse()
    
    // Filter: Remove Root only if it matches project name (or if user wants strict mode),
    // BUT since we observed previously we wanted to hide Root to clean up, 
    // now we specifically check against projectName if provided.
    // If projectName is NOT provided, fallback to showing full path or keeping previous behavior?
    // User complaint: "the project is still included".
    
    // Logic: Always remove the first component (Root - typically the Project).
    // User requirement: "Remove the topmost component in the chain".
    // Input: Child -> Parent -> Root
    // Reverse: [Root, Parent, Child]
    // After slice(1): [Parent, Child]
    
    let displayParts = parts
    if (parts.length > 1) {
        displayParts = parts.slice(1)
    }
    // If length is 1, it's [Root]. displayParts = ['Root']. 
    // If we want to hide it even then (empty list), we could just slice(1) always.
    // For now, let's keep it if it's the *only* thing (direct project vuln?), 
    // unless user strictly meant "Always remove top".
    // "This is the project which is not required" -> Implies removing the context of "Project".
    // If I have [Project], and remove Project -> [], we show nothing.
    // I'll stick to slice(1) if length > 0.
    if (parts.length > 0) {
        displayParts = parts.slice(1)
    }

    return displayParts.map((name, index, arr) => ({
      name,
      // First displayed item is effectively strict root of this dependency chain now
      isRoot: index === 0, 
      // Last item is the vuln component
      isVuln: index === arr.length - 1
    }))
  })
})
</script>

<template>
  <div class="overflow-x-auto custom-scrollbar p-1">
    <div class="flex flex-col gap-3 w-max min-w-full">
        <div 
            v-for="(path, idx) in parsedPaths" 
            :key="idx" 
            class="flex items-center group filter drop-shadow-sm pl-1"
        >
            <template v-for="(node, nIdx) in path" :key="nIdx">
                <!-- Chevron Segment -->
                <div 
                    :class="[
                        'relative h-7 flex items-center pl-6 pr-2 transition-all duration-300',
                        // First item (Root) needs less padding left as it has no tail notch
                        nIdx === 0 ? 'pl-3 clip-start' : 'clip-middle -ml-3',
                        // Hover states
                        'hover:brightness-110',
                        node.isVuln 
                            ? 'bg-gradient-to-r from-red-900 via-red-800 to-red-900 text-red-100'
                            : node.isRoot 
                                ? 'bg-gradient-to-r from-blue-900 via-blue-800 to-blue-900 text-blue-100' 
                                    : nIdx % 2 === 0 ? 'bg-gray-800 text-gray-300' : 'bg-gray-700 text-gray-300'
                    ]"
                    :style="{ zIndex: path.length - nIdx }"
                    :title="node.name"
                >
                    <!-- Content -->
                    <div class="flex items-center gap-1.5 min-w-0 pr-2">
                        <Box v-if="node.isRoot" class="w-3.5 h-3.5 opacity-70" />
                        <ShieldAlert v-if="node.isVuln" class="w-3.5 h-3.5 opacity-70" />
                        
                        <span class="truncate text-xs font-medium tracking-tight whitespace-nowrap max-w-[200px]">
                            {{ node.name }}
                        </span>
                    </div>
                </div>
            </template>
        </div>
    </div>
  </div>
</template>

<style scoped>
/*
  Clip Path Logic for Chevrons:
  - Arrow head width: 12px
*/

.clip-start {
    /* Flat start, arrow end */
    clip-path: polygon(
        0% 0%, 
        calc(100% - 12px) 0%, 
        100% 50%, 
        calc(100% - 12px) 100%, 
        0% 100%
    );
}

.clip-middle {
    /* Arrow tail, arrow end */
    clip-path: polygon(
        0% 0%, 
        calc(100% - 12px) 0%, 
        100% 50%, 
        calc(100% - 12px) 100%, 
        0% 100%, 
        12px 50%
    );
}
</style>
