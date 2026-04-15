<template>
  <teleport to="body">
    <div v-if="show" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 overflow-y-auto">
      <div class="bg-gray-800 w-full max-w-4xl max-h-[90vh] flex flex-col rounded-lg border border-red-500 shadow-2xl">
        <div class="p-4 border-b border-gray-700 flex justify-between items-center bg-gray-800">
          <h3 class="font-bold text-lg text-red-400 flex items-center gap-2">
            <slot name="icon">
              <!-- fallback icon if needed -->
            </slot>
            Conflict Detected
          </h3>
          <button @click="$emit('close')" class="text-gray-400 hover:text-white text-xl font-bold">✕</button>
        </div>

        <div class="p-4 bg-red-900/20 border-b border-red-900/50 text-red-200 text-sm">
          The analysis data on the server has changed since you started editing. Please review the differences below and choose how to proceed.
        </div>

        <div class="flex-1 overflow-y-auto p-4 bg-gray-800 space-y-4">
          <div v-for="conflict in conflictData || []" :key="conflict.finding_uuid" class="bg-gray-900 border border-gray-700 rounded p-4">
            <div class="font-bold text-gray-300 mb-2 border-b border-gray-700 pb-1">
              {{ conflict.project_name }} {{ conflict.project_version }} - {{ conflict.component_name }}
            </div>

            <div class="grid grid-cols-2 gap-4">
              <div class="space-y-2">
                <h4 class="text-xs font-bold uppercase text-gray-500">Server State (New)</h4>
                <div class="text-sm">
                  <span class="text-gray-400">State:</span>
                  <span class="font-mono text-blue-300">{{ conflict.current.analysisState }}</span>
                </div>
                <div class="text-sm">
                  <span class="text-gray-400">Suppressed:</span>
                  <span class="font-mono text-blue-300">{{ conflict.current.isSuppressed }}</span>
                </div>
                <div class="text-sm bg-gray-800 p-2 rounded border border-gray-700 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-xs">
                  {{ conflict.current.analysisDetails || '(No details)' }}
                </div>
              </div>

              <div class="space-y-2">
                <h4 class="text-xs font-bold uppercase text-gray-500">Your Changes</h4>
                <div class="text-sm">
                  <span class="text-gray-400">State:</span>
                  <span class="font-mono text-green-300">{{ conflict.your_change.analysisState }}</span>
                </div>
                <div class="text-sm">
                  <span class="text-gray-400">Suppressed:</span>
                  <span class="font-mono text-green-300">{{ conflict.your_change.isSuppressed }}</span>
                </div>
                <div class="text-sm bg-gray-800 p-2 rounded border border-gray-700 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-xs">
                  {{ conflict.your_change.analysisDetails || '(No details)' }}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="p-4 border-t border-gray-700 bg-gray-850 flex justify-end gap-4">
          <button
            @click="$emit('use-server-state')"
            class="px-4 py-2 rounded bg-gray-700 hover:bg-gray-600 text-white font-bold transition-colors"
          >
            Discard My Changes (Use Server)
          </button>
          <button
            @click="$emit('force-overwrite')"
            class="px-4 py-2 rounded bg-red-600 hover:bg-red-700 text-white font-bold transition-colors disabled:opacity-50"
          >
            Force Overwrite
          </button>
        </div>
      </div>
    </div>
  </teleport>
</template>

<script setup lang="ts">

const props = defineProps<{
  show: boolean
  conflictData: Array<any> | null
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'use-server-state'): void
  (e: 'force-overwrite'): void
}>()
</script>
