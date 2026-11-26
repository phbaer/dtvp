<script setup lang="ts">
import { computed } from 'vue'
import { CalendarDays, PackageSearch } from '@lucide/vue'

const props = defineProps<{
  publishedOnMs: number | null
  attributedOnMs?: number | null
  compact?: boolean
}>()

const findingDates = computed(() => {
  const entries = [
    { kind: 'publication', label: 'Published', timestamp: props.publishedOnMs },
    { kind: 'attribution', label: 'First attributed', timestamp: props.attributedOnMs },
  ]
  const now = new Date()
  return entries.flatMap(({ kind, label, timestamp }) => {
    if (timestamp == null || !Number.isFinite(timestamp) || timestamp <= 0) return []
    const when = new Date(timestamp)
    if (!Number.isFinite(when.getTime())) return []
    const date = when.toISOString().slice(0, 10)
    const days = Math.floor(now.getTime() / 86_400_000) - Math.floor(timestamp / 86_400_000)
    const months = (now.getUTCFullYear() - when.getUTCFullYear()) * 12
      + now.getUTCMonth() - when.getUTCMonth() - Number(now.getUTCDate() < when.getUTCDate())
    const age = months >= 12 ? `${Math.floor(months / 12)}y`
      : months > 0 ? `${months}mo`
        : days > 0 ? `${days}d` : days === 0 ? 'today' : date
    return [{ kind, label, date, age }]
  })
})
</script>

<template>
  <span v-if="findingDates.length" data-testid="vulnerability-dates" class="tabular-nums" :class="compact ? 'inline-flex flex-wrap gap-x-2' : 'col-span-2 grid grid-cols-subgrid'">
    <time
      v-for="entry in findingDates"
      :key="entry.kind"
      :datetime="entry.date"
      :title="`${entry.label} ${entry.date}`"
      class="inline-flex items-center gap-1 whitespace-nowrap"
      :class="{ 'col-start-2': !compact && entry.kind === 'attribution' }"
    >
      <CalendarDays v-if="entry.kind === 'publication'" :size="12" class="text-gray-400" aria-hidden="true" />
      <PackageSearch v-else :size="12" class="text-gray-400" aria-hidden="true" />
      <span>
        <span class="sr-only">{{ entry.label + ' ' }}</span>{{ compact ? entry.age : entry.date }}
        <span v-if="compact && entry.age !== entry.date" class="sr-only"> ({{ entry.date }})</span>
      </span>
    </time>
  </span>
</template>
