<script setup lang="ts">
// A team as a chip: its name, a stable colour, and an icon and border for
// how it owns (own entry, inherited, the project, the catch-all), so the
// meaning never rests on colour alone.
import { computed } from 'vue'
import { CircleDashed, CornerDownRight, Folder } from '@lucide/vue'
import { teamColour, type TreeOwner } from '../../lib/team-mapping-insights'

const props = defineProps<{ team: string; kind?: TreeOwner['kind'] }>()

const unowned = computed(() => props.kind === 'wildcard' || props.kind === 'none' || !props.team)
const label = computed(() => props.team || 'no owner')
</script>

<template>
  <span
    :class="[
      'inline-flex max-w-full items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-semibold leading-none',
      teamColour(team, kind),
      kind === 'inherited' ? 'bg-transparent' : '',
    ]"
  >
    <CircleDashed v-if="unowned" :size="11" aria-hidden="true" />
    <CornerDownRight v-else-if="kind === 'inherited'" :size="11" aria-hidden="true" />
    <Folder v-else-if="kind === 'project'" :size="11" aria-hidden="true" />
    <span class="truncate">{{ label }}</span>
  </span>
</template>
