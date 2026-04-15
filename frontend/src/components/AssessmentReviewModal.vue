<template>
  <teleport to="body">
    <div v-if="show" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-[100] overflow-y-auto">
      <div class="bg-gray-800 w-full max-w-2xl rounded-lg border border-gray-700 shadow-2xl overflow-hidden scale-in-center">
        <div class="p-4 border-b border-gray-700 bg-gray-800 flex justify-between items-center">
          <h3 class="font-bold text-lg text-gray-200">Review Assessment Before Submitting</h3>
          <button @click="$emit('cancel')" class="text-gray-400 hover:text-white transition-colors cursor-pointer">✕</button>
        </div>

        <!-- Summary bar -->
        <div class="px-4 py-2 bg-gray-900 border-b border-gray-700 flex flex-wrap items-center gap-2 text-[10px]">
          <span class="font-bold uppercase tracking-wider text-gray-500">State:</span>
          <span
            class="px-1.5 py-px rounded font-bold"
            :class="{
              'bg-green-900/40 text-green-200 border border-green-600/50': aggregatedState === 'NOT_AFFECTED',
              'bg-red-900/40 text-red-200 border border-red-600/50': aggregatedState === 'EXPLOITABLE',
              'bg-amber-900/40 text-amber-200 border border-amber-600/50': aggregatedState === 'IN_TRIAGE',
              'bg-cyan-900/40 text-cyan-200 border border-cyan-600/50': aggregatedState === 'FALSE_POSITIVE',
              'bg-gray-800/60 text-gray-300 border border-gray-600/50': !['NOT_AFFECTED','EXPLOITABLE','IN_TRIAGE','FALSE_POSITIVE'].includes(aggregatedState)
            }"
          >{{ aggregatedState.replace(/_/g, ' ') }}</span>
          <span class="text-gray-600">·</span>
          <span class="text-gray-400">{{ visibleBlocks.length }} team block{{ visibleBlocks.length !== 1 ? 's' : '' }}</span>
          <span v-if="duplicatesRemoved > 0" class="text-amber-400">
            · {{ duplicatesRemoved }} duplicate{{ duplicatesRemoved !== 1 ? 's' : '' }} removed
          </span>
        </div>

        <!-- Blocks display -->
        <div class="p-4 bg-gray-850 space-y-2 max-h-[50vh] overflow-y-auto">
          <div v-for="block in visibleBlocks" :key="block.team" class="rounded border border-gray-700/50 bg-gray-800/50 overflow-hidden">
            <div class="flex items-center gap-1.5 px-3 py-1.5 border-b border-gray-700/30 bg-gray-800/80 text-[10px]">
              <span class="px-1.5 py-px rounded font-bold uppercase tracking-wider bg-blue-900/30 text-blue-300 border border-blue-800/40 shrink-0">
                {{ block.team === 'General' ? 'Global' : block.team }}
              </span>
              <span
                v-if="block.state && block.state !== 'NOT_SET'"
                class="px-1.5 py-px rounded font-bold shrink-0"
                :class="{
                  'bg-green-900/40 text-green-200 border border-green-600/50': block.state === 'NOT_AFFECTED',
                  'bg-red-900/40 text-red-200 border border-red-600/50': block.state === 'EXPLOITABLE',
                  'bg-amber-900/40 text-amber-200 border border-amber-600/50': block.state === 'IN_TRIAGE',
                  'bg-cyan-900/40 text-cyan-200 border border-cyan-600/50': block.state === 'FALSE_POSITIVE',
                  'bg-gray-800/60 text-gray-300 border border-gray-600/50': !['NOT_AFFECTED','EXPLOITABLE','IN_TRIAGE','FALSE_POSITIVE'].includes(block.state)
                }"
              >{{ block.state.replace(/_/g, ' ') }}</span>
              <span
                v-if="block.justification && block.justification !== 'NOT_SET'"
                class="text-gray-500 shrink-0"
              >· {{ block.justification.replace(/_/g, ' ') }}</span>
              <span class="flex-1"></span>
              <span v-if="block.user" class="text-gray-500 font-mono shrink-0">{{ block.user }}</span>
            </div>
            <div v-if="block.details && block.details.trim()" class="px-3 py-2 text-[11px] text-gray-400 whitespace-pre-wrap break-words leading-snug font-mono">{{ block.details }}</div>
          </div>

          <div v-if="visibleBlocks.length === 0" class="text-gray-500 text-center py-4 italic text-sm">
            No assessment blocks to submit.
          </div>
        </div>

        <!-- Raw text preview (collapsed) -->
        <details class="border-t border-gray-700">
          <summary class="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-gray-600 hover:text-gray-400 cursor-pointer select-none">
            Raw details text
          </summary>
          <div class="px-4 py-2 bg-black/20 max-h-[200px] overflow-y-auto">
            <pre class="text-[10px] text-gray-500 font-mono whitespace-pre-wrap break-words">{{ sanitizedText }}</pre>
          </div>
        </details>

        <div class="p-4 bg-gray-900 border-t border-gray-700 flex justify-end gap-3">
          <button
            @click="$emit('cancel')"
            class="px-4 py-2 rounded bg-gray-700 hover:bg-gray-600 text-white text-sm font-bold transition-colors cursor-pointer"
          >
            Cancel
          </button>
          <button
            @click="$emit('confirm')"
            class="px-6 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold shadow-lg shadow-blue-900/20 transition-all active:scale-95 cursor-pointer"
          >
            Submit
          </button>
        </div>
      </div>
    </div>
  </teleport>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { AssessmentBlock } from '../lib/assessment-helpers'

const props = defineProps<{
  show: boolean
  blocks: AssessmentBlock[]
  aggregatedState: string
  sanitizedText: string
  duplicatesRemoved: number
  isReviewer?: boolean
  selectedTeam?: string
}>()

defineEmits<{
  (e: 'confirm'): void
  (e: 'cancel'): void
}>()

const visibleBlocks = computed(() => {
  if (props.isReviewer) return props.blocks
  if (!props.selectedTeam) return props.blocks
  return props.blocks.filter(b => b.team === props.selectedTeam)
})
</script>
