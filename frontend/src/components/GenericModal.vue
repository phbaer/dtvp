<template>
  <teleport to="body">
    <div v-if="show" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-[100] overflow-y-auto">
      <div class="bg-gray-800 w-full max-w-md rounded-lg border border-gray-700 shadow-2xl overflow-hidden scale-in-center">
        <div class="p-4 border-b border-gray-700 bg-gray-800 flex justify-between items-center">
          <h3 class="font-bold text-lg text-gray-200">{{ title }}</h3>
          <button @click="$emit('response', false)" class="text-gray-400 hover:text-white transition-colors">✕</button>
        </div>
        <div class="p-6 bg-gray-850 text-gray-300">
          <p class="text-sm leading-relaxed">{{ message }}</p>
        </div>
        <div class="p-4 bg-gray-900 border-t border-gray-700 flex justify-end gap-3">
          <button
            v-if="!confirmOnly"
            @click="$emit('response', false)"
            class="px-4 py-2 rounded bg-gray-700 hover:bg-gray-600 text-white text-sm font-bold transition-colors"
          >
            Cancel
          </button>
          <button
            @click="$emit('response', true)"
            class="px-6 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold shadow-lg shadow-blue-900/20 transition-all active:scale-95"
          >
            {{ confirmOnly ? 'Close' : 'Confirm' }}
          </button>
        </div>
      </div>
    </div>
  </teleport>
</template>

<script setup lang="ts">

const props = defineProps<{
  show: boolean
  title: string
  message: string
  confirmOnly: boolean
}>()

const emit = defineEmits<{
  (e: 'response', value: boolean): void
}>()
</script>
