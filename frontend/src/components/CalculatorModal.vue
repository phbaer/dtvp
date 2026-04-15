<template>
  <teleport to="body">
    <div v-if="show" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
      <div class="bg-gray-800 w-full max-w-3xl max-h-[90vh] flex flex-col rounded-lg border border-gray-700 shadow-2xl">
        <div class="p-4 border-b border-gray-700 flex justify-between items-center bg-gray-800">
          <h3 class="font-bold text-lg text-gray-300">CVSS v{{ activeVersion }} Calculator</h3>
          <div class="flex items-center gap-3">
            <button
              @click="$emit('clear')"
              class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs font-bold text-gray-300 transition-colors"
              title="Clear vector to unlock all versions"
            >
              Clear
            </button>
            <button
              @click="$emit('reset')"
              class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs font-bold text-gray-300 transition-colors"
              title="Reset to original CVE vector"
            >
              Reset
            </button>
            <button @click="$emit('close')" class="text-gray-400 hover:text-white text-xl font-bold cursor-pointer">✕</button>
          </div>
        </div>

        <div class="flex border-b border-gray-700 bg-gray-850">
          <button
            v-for="v in visibleVersions"
            :key="v"
            @click="$emit('switch-version', v)"
            :class="[
              'px-4 py-2 text-sm font-bold border-r border-gray-700 transition-colors',
              activeVersion === v ? 'bg-gray-700 text-white' : 'bg-gray-850 text-gray-400 hover:bg-gray-800'
            ]"
          >
            CVSS v{{ v }}
          </button>
        </div>

        <div class="flex-1 overflow-y-auto p-4 bg-gray-800">
          <div v-if="activeVersion === '2.0'">
            <CvssCalculatorV2
              :instance="cvssInstance"
              :can-edit-base="canEditBase"
              @update="onUpdate"
              @reset="$emit('reset')"
            />
          </div>
          <div v-else-if="activeVersion === '3.1' || activeVersion === '3.0'">
            <CvssCalculatorV3
              :instance="cvssInstance"
              :can-edit-base="canEditBase"
              @update="onUpdate"
              @reset="$emit('reset')"
            />
          </div>
          <div v-else-if="activeVersion === '4.0'">
            <CvssCalculatorV4
              :instance="cvssInstance"
              :can-edit-base="canEditBase"
              @update="onUpdate"
              @reset="$emit('reset')"
            />
          </div>
        </div>

        <div class="p-4 border-t border-gray-700 bg-gray-850">
          <div class="flex justify-between items-center">
            <div>
              <div class="text-xs text-gray-500 font-mono mb-1">Current Vector</div>
              <div class="text-sm font-mono font-bold text-white break-all mb-2">{{ pendingVector }}</div>
            </div>
            <div class="text-right ml-4">
              <div class="text-xs text-gray-500 uppercase">Score</div>
              <div class="text-2xl font-bold text-yellow-400">{{ pendingScore ?? 'N/A' }}</div>
            </div>
          </div>
          <button
            @click="$emit('close')"
            class="w-full mt-4 bg-green-600 hover:bg-green-700 text-white font-bold py-2 rounded transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  </teleport>
</template>

<script setup lang="ts">
import CvssCalculatorV2 from './CvssCalculatorV2.vue'
import CvssCalculatorV3 from './CvssCalculatorV3.vue'
import CvssCalculatorV4 from './CvssCalculatorV4.vue'

const props = defineProps<{
  show: boolean
  activeVersion: '4.0' | '3.1' | '3.0' | '2.0'
  visibleVersions: Array<'4.0' | '3.1' | '3.0' | '2.0'>
  canEditBase: boolean
  pendingVector: string
  pendingScore: number | null
  cvssInstance: any
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'clear'): void
  (e: 'reset'): void
  (e: 'switch-version', version: '4.0' | '3.1' | '3.0' | '2.0'): void
  (e: 'update-vector', componentShortName: string, value: string): void
}>()

const onUpdate = (componentShortName: string, value: string) => {
  emit('update-vector', componentShortName, value)
}
</script>
