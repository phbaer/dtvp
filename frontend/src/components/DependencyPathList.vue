<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  paths: string[]
  projectName?: string
}>()

type TreeNode = {
  name: string
  children: TreeNode[]
}

const normalizedPaths = computed(() => {
  return props.paths.map(p => {
    const parts = p.split(' -> ').reverse()
    if (parts.length > 0) {
      return parts.slice(1) // strip project root
    }
    return []
  }).filter(parts => parts.length > 0)
})

const treeNodes = computed<TreeNode[]>(() => {
  const root: TreeNode[] = []

  for (const path of normalizedPaths.value) {
    let level = root
    for (const part of path) {
      let node = level.find(item => item.name === part)
      if (!node) {
        node = { name: part, children: [] }
        level.push(node)
      }
      level = node.children
    }
  }

  return root
})

const flattenedTree = computed(() => {
  const result: { name: string; depth: number; hasChildren: boolean }[] = []

  const process = (nodes: TreeNode[], depth = 0) => {
    for (const node of nodes) {
      result.push({ name: node.name, depth, hasChildren: node.children.length > 0 })
      if (node.children.length > 0) {
        process(node.children, depth + 1)
      }
    }
  }

  process(treeNodes.value)
  return result
})
</script>

<template>
  <div class="p-1">
    <div v-if="flattenedTree.length === 0" class="text-xs text-gray-500 italic">
      No dependency chains found.
    </div>

    <ul v-else class="list-none space-y-1 text-xs">
      <li
        v-for="node in flattenedTree"
        :key="`${node.name}-${node.depth}`"
        :style="{ paddingLeft: `${node.depth * 1}rem` }"
        class="flex items-center gap-2 text-gray-100"
      >
        <span class="h-1.5 w-1.5 rounded-full" :class="node.hasChildren ? 'bg-blue-400' : 'bg-gray-500'" />
        <span class="font-medium truncate">{{ node.name }}</span>
      </li>
    </ul>
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
