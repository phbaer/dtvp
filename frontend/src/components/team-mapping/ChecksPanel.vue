<script setup lang="ts">
// The checks of the draft, grouped by kind (errors first, then by the
// findings concerned), each with a jump to what it is about and, where the
// action is unambiguous, a fix that edits the draft.
import { ref } from 'vue'
import { ChevronDown, ChevronRight, CircleAlert, TriangleAlert } from '@lucide/vue'
import { plural, type CheckFix, type CheckGroup, type CheckTarget } from '../../lib/team-mapping-editing'

defineProps<{ groups: CheckGroup[] }>()
const emit = defineEmits<{
    jump: [target: CheckTarget]
    fix: [fix: CheckFix]
    'assign-project': [project: string]
}>()

const collapsed = ref(new Set<string>())
const toggle = (kind: string) => {
    const next = new Set(collapsed.value)
    if (next.has(kind)) next.delete(kind)
    else next.add(kind)
    collapsed.value = next
}
const jumpLabel = (target: CheckTarget) =>
    target.entry ? `Show ${target.entry}` : target.team ? `Show ${target.team}` : `Show ${target.project}`
</script>

<template>
  <section data-testid="validation-panel" aria-label="Checks" class="space-y-3">
    <p v-if="!groups.length" class="rounded border border-gray-700 bg-gray-900/40 p-4 text-xs text-gray-200">
      No problems found: no conflicts, stale or duplicate entries, and every finding has an owner.
    </p>
    <div
      v-for="group in groups"
      :key="group.kind"
      :data-testid="`check-group-${group.kind}`"
      :class="['rounded border bg-gray-900/40', group.level === 'error' ? 'border-red-700' : 'border-gray-700']"
    >
      <h4>
        <button
          type="button"
          class="flex w-full items-center gap-2 px-3 py-2 text-left text-xs focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
          :aria-expanded="!collapsed.has(group.kind)"
          @click="toggle(group.kind)"
        >
          <ChevronRight v-if="collapsed.has(group.kind)" :size="14" class="text-gray-400" aria-hidden="true" />
          <ChevronDown v-else :size="14" class="text-gray-400" aria-hidden="true" />
          <CircleAlert v-if="group.level === 'error'" :size="14" class="text-red-300" aria-hidden="true" />
          <TriangleAlert v-else :size="14" class="text-amber-300" aria-hidden="true" />
          <span class="font-semibold text-gray-100">{{ group.title }}</span>
          <span :class="['rounded px-1.5 font-semibold', group.level === 'error' ? 'bg-red-900/70 text-red-100' : 'bg-gray-700 text-gray-100']">
            {{ group.items.length }}
          </span>
          <span v-if="group.level === 'error'" class="text-red-200">blocks saving</span>
          <span class="ml-2 hidden truncate font-normal text-gray-300 lg:inline">{{ group.help }}</span>
        </button>
      </h4>
      <ul v-if="!collapsed.has(group.kind)" class="space-y-1 border-t border-gray-800 px-3 py-2 text-xs">
        <li
          v-for="item in group.items"
          :key="item.id"
          :data-testid="`validation-${group.level}`"
          class="flex flex-wrap items-center gap-x-3 gap-y-1 rounded px-1 py-1 hover:bg-gray-800/60"
        >
          <span class="min-w-0 flex-1 text-gray-100">{{ item.message }}</span>
          <span v-if="item.impact && group.kind !== 'coverage'" class="text-gray-400">{{ plural(item.impact, 'finding') }}</span>
          <span class="flex flex-wrap items-center gap-1">
            <button
              v-for="fix in item.fixes"
              :key="fix.label"
              type="button"
              class="rounded border border-gray-600 bg-gray-800 px-2 py-0.5 text-gray-100 hover:border-blue-400 hover:bg-gray-700"
              @click="emit('fix', fix)"
            >{{ fix.label }}</button>
            <button
              v-if="item.assignProject"
              type="button"
              class="rounded border border-gray-600 bg-gray-800 px-2 py-0.5 text-gray-100 hover:border-blue-400 hover:bg-gray-700"
              @click="emit('assign-project', item.assignProject)"
            >Assign project…</button>
            <button
              v-if="item.target"
              type="button"
              class="px-1 text-blue-300 hover:underline"
              @click="emit('jump', item.target)"
            >{{ jumpLabel(item.target) }}</button>
          </span>
        </li>
      </ul>
    </div>
  </section>
</template>
