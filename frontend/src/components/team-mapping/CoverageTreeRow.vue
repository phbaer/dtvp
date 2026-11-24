<script setup lang="ts">
// One row of the coverage tree: a treeitem of the ARIA tree pattern (the
// browser owns focus and keys). Its name for screen readers says the
// component, its owner and why, and its findings.
import { computed } from 'vue'
import { Check, ChevronDown, ChevronRight } from '@lucide/vue'
import type { TreeNode, TreeOwner } from '../../lib/team-mapping-insights'
import { plural } from '../../lib/team-mapping-editing'
import TeamChip from './TeamChip.vue'

const props = defineProps<{
    id: string
    node: TreeNode
    depth: number
    expanded: boolean
    focused: boolean
    picked: boolean
    highlighted: boolean
    posinset: number
    setsize: number
}>()
const emit = defineEmits<{ toggle: []; pick: []; focus: [] }>()

const why = (owner: TreeOwner): string => {
    if (owner.kind === 'component') return `own entry ${owner.key}`
    if (owner.kind === 'inherited') return `inherited from ${(owner.from || []).join(', ')}`
    if (owner.kind === 'project') return 'the project'
    if (owner.kind === 'wildcard') return 'catch-all, unowned'
    return 'no owner'
}
const reason = computed(() => why(props.node.owner))
const before = computed(() => props.node.saved_owner)

const label = computed(() => [
    props.node.name,
    props.node.root ? 'project root' : '',
    `owner ${props.node.owner.team || 'none'}, ${reason.value}`,
    before.value ? `unsaved, was ${before.value.team || 'no owner'}` : '',
    plural(props.node.findings, 'finding'),
    props.node.unowned ? `${props.node.unowned} unowned` : '',
].filter(Boolean).join(', '))

const onClick = () => {
    emit('focus')
    emit('pick')
}
</script>

<template>
  <li
    :id="id"
    role="treeitem"
    :aria-level="depth + 1"
    :aria-setsize="setsize"
    :aria-posinset="posinset"
    :aria-expanded="node.children > 0 ? expanded : undefined"
    :aria-selected="picked"
    :aria-label="label"
    :tabindex="focused ? 0 : -1"
    :data-testid="`coverage-node-${node.name}`"
    :class="[
      'group flex cursor-pointer items-center gap-2 rounded px-1 py-1 text-xs outline-none',
      'focus-visible:ring-2 focus-visible:ring-blue-400',
      picked ? 'bg-blue-900/50' : highlighted ? 'bg-amber-900/20 ring-1 ring-amber-400' : 'hover:bg-gray-700/40',
    ]"
    @click="onClick"
  >
    <span class="flex min-w-0 flex-1 items-center gap-1.5" :style="{ paddingLeft: `${depth * 16}px` }">
      <span
        v-if="node.children > 0"
        aria-hidden="true"
        class="rounded text-gray-400 hover:bg-gray-700 hover:text-gray-100"
        :title="expanded ? 'Collapse' : 'Expand'"
        @click.stop="emit('focus'); emit('toggle')"
      >
        <ChevronDown v-if="expanded" :size="14" />
        <ChevronRight v-else :size="14" />
      </span>
      <span v-else class="inline-block w-[14px]" aria-hidden="true" />
      <span
        aria-hidden="true"
        :class="[
          'flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-sm border',
          picked ? 'border-blue-400 bg-blue-500 text-white' : 'border-gray-500 opacity-0 group-hover:opacity-100 group-focus-visible:opacity-100',
        ]"
      ><Check v-if="picked" :size="11" /></span>
      <span class="truncate font-medium text-gray-100" :title="node.purl || node.name">{{ node.name }}</span>
      <span v-if="node.root" class="shrink-0 rounded bg-gray-700 px-1 text-[10px] uppercase text-gray-200">project root</span>
      <span v-if="node.unlinked" class="shrink-0 text-[11px] text-gray-400" title="No dependency in the BOM links to it">unlinked</span>
      <span v-if="node.group" class="truncate text-gray-400">{{ node.group }}</span>
    </span>
    <span class="flex w-56 shrink-0 xl:w-72 items-center gap-1.5 overflow-hidden" :title="before ? `Unsaved; the saved owner is ${before.team || 'none'}. ${reason}` : reason">
      <TeamChip :team="node.owner.team" :kind="node.owner.kind" />
      <span v-if="before" data-testid="coverage-node-unsaved" class="shrink-0 rounded bg-amber-900/60 px-1 text-[10px] font-semibold text-amber-100">was {{ before.team || 'no owner' }}</span>
      <span class="truncate text-[11px] text-gray-300">{{ reason }}</span>
    </span>
    <span class="w-16 shrink-0 text-right tabular-nums text-gray-200">{{ node.findings }}</span>
    <span :class="['w-16 shrink-0 text-right tabular-nums', node.unowned ? 'font-semibold text-amber-300' : 'text-gray-400']">
      {{ node.unowned || '–' }}
    </span>
  </li>
</template>
