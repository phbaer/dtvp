<script setup lang="ts">
import { computed, defineComponent, type PropType, type VNodeChild, h } from 'vue'

const props = defineProps<{
  paths: string[]
  projectName?: string
  teamMappedNames?: Map<string, string[]>
}>()

const normalizeName = (name: string): string => name.trim().toLowerCase()

const normalizedTeamMappedNames = computed(() => {
  const map = new Map<string, string[]>()
  if (!props.teamMappedNames) return map

  for (const [key, val] of props.teamMappedNames.entries()) {
    map.set(normalizeName(key), Array.isArray(val) ? val : [val])
  }
  return map
})

const isTeamMapped = (name: string): boolean => {
  return normalizedTeamMappedNames.value.has(normalizeName(name))
}

const getTeamNames = (name: string): string => {
  const teams = normalizedTeamMappedNames.value.get(normalizeName(name))
  return teams?.[0] || ''
}

interface TreeNode {
  name: string
  children: Map<string, TreeNode>
  teamNames?: string[]
  isPrimary?: boolean
  isVulnerable?: boolean
  isRoot?: boolean
}

const rootNodes = computed((): TreeNode[] => {
  if (!props.paths?.length) return []

  const roots = new Map<string, TreeNode>()

  for (const path of props.paths) {
    const rawParts = path.split(' -> ').map(s => s.trim()).filter(Boolean)
    const parts = rawParts.filter((part, index) => {
      if (index === 0) return true
      return normalizeName(part) !== normalizeName(rawParts[index - 1])
    })
    if (parts.length <= 1) continue

    const primaryTeamIndex = parts.findIndex(part => isTeamMapped(part))
    const rootName = parts[0]
    const rootKey = normalizeName(rootName)
    let root = roots.get(rootKey)

    if (!root) {
      root = {
        name: rootName,
        children: new Map(),
        isVulnerable: true,
      }
      if (isTeamMapped(rootName)) {
        root.teamNames = [getTeamNames(rootName)]
      }
      roots.set(rootKey, root)
    }

    let current = root
    for (let index = 1; index < parts.length; index += 1) {
      const part = parts[index]
      const normalizedPart = normalizeName(part)
      if (normalizedPart === normalizeName(current.name)) {
        continue
      }

      let child = current.children.get(normalizedPart)

      if (!child) {
        child = { name: part, children: new Map() }
        if (isTeamMapped(part)) {
          child.teamNames = [getTeamNames(part)]
        }
        current.children.set(normalizedPart, child)
      }
      if (index === primaryTeamIndex) child.isPrimary = true
      if (index === parts.length - 1) child.isRoot = true

      current = child
    }
  }

  return Array.from(roots.values())
})

const PathNode: ReturnType<typeof defineComponent> = defineComponent({
  name: 'PathNode',
  props: {
    node: {
      type: Object as PropType<TreeNode>,
      required: true,
    },
  },
  setup(props): () => VNodeChild {
    return () => {
      const node = props.node
      const labelClass = [
        'text-[10px] font-mono',
        node.isPrimary ? 'text-cyan-300 font-semibold' : node.teamNames ? 'text-teal-300' : 'text-gray-500',
      ]

      const badges = []
      if (node.isPrimary) {
        badges.push(
          h('span', { class: 'ml-1 px-1 py-0 rounded bg-cyan-600/15 text-[8px] uppercase tracking-[0.12em] text-cyan-200' }, 'primary')
        )
      } else if (node.teamNames) {
        badges.push(
          h('span', { class: 'ml-1 px-1 py-0 rounded bg-teal-600/10 text-[8px] uppercase tracking-[0.12em] text-teal-200' }, 'team')
        )
      }

      if (node.teamNames) {
        badges.push(
          h('span', { class: 'ml-1 px-0.5 py-0 text-[7px] font-bold uppercase text-teal-300/80' }, node.teamNames[0])
        )
      }

      if (node.isRoot) {
        badges.push(
          h('span', { class: 'ml-1 px-1 py-0 rounded bg-slate-700/40 text-[8px] uppercase tracking-[0.12em] text-slate-300' }, 'root')
        )
      }

      const children = Array.from(node.children.values())

      return h('div', {}, [
        h('div', { class: 'flex items-center gap-1.5' }, [
          h('span', { class: labelClass, title: node.teamNames ? 'Team: ' + node.teamNames[0] : undefined }, node.name),
          ...badges,
        ]),
        children.length > 0
          ? h('div', { class: 'relative ml-[7px] pl-[13px]' },
              children.map((child, idx) => {
                const isLast = idx === children.length - 1
                return h('div', { key: child.name, class: 'relative mt-1' }, [
                  // Vertical line segment: full-height for non-last, partial for last
                  h('div', {
                    class: 'absolute border-l border-gray-700/60',
                    style: isLast
                      ? 'left: -13px; top: 0; height: 8px;'
                      : 'left: -13px; top: 0; bottom: 0;',
                  }),
                  // Horizontal connector at the label midpoint
                  h('div', {
                    class: 'absolute border-t border-gray-700/60',
                    style: 'left: -13px; top: 8px; width: 10px;',
                  }),
                  h(PathNode, { node: child }),
                ])
              })
            )
          : null,
      ])
    }
  },
})
</script>

<template>
  <div class="text-xs">
    <div v-if="rootNodes.length === 0" class="text-gray-500 italic">
      No dependency chains found.
    </div>

    <div v-else class="space-y-3">
      <template v-for="root in rootNodes" :key="root.name">
        <div v-if="root.children.size" class="space-y-1">
          <PathNode v-for="child in Array.from(root.children.values())" :key="child.name" :node="child" />
        </div>
      </template>
    </div>
  </div>
</template>
