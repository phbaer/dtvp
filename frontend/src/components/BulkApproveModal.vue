<script setup lang="ts">
import { ref, watch } from 'vue'
import { CheckCircle, X } from 'lucide-vue-next'
import type { GroupedVuln } from '../types'

const props = defineProps<{
  show: boolean
  needsApprovalGroups: GroupedVuln[]
}>()

const emit = defineEmits(['close', 'updated'])
const selectedIds = ref<Set<string>>(new Set())

watch(() => props.show, (newVal) => {
  if (newVal) {
    selectedIds.value = new Set(props.needsApprovalGroups.map(g => g.id))
  }
})

const toggleId = (id: string) => {
  const set = new Set(selectedIds.value)
  if (set.has(id)) set.delete(id)
  else set.add(id)
  selectedIds.value = set
}

const applyApproval = () => {
  const updates = props.needsApprovalGroups
    .filter(group => selectedIds.value.has(group.id))
    .map(group => ({ id: group.id, data: {} }))

  emit('updated', updates)
}
</script>

<template>
  <div v-if="show" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
    <div class="w-full max-w-3xl bg-slate-950 border border-slate-800 rounded-3xl shadow-2xl overflow-hidden">
      <div class="flex items-center justify-between px-6 py-4 border-b border-slate-800">
        <div>
          <h2 class="text-lg font-bold text-white">Bulk Approve Findings</h2>
          <p class="text-sm text-slate-400">Select findings to approve in a single action.</p>
        </div>
        <button @click="$emit('close')" class="text-slate-400 hover:text-white">
          <X :size="20" />
        </button>
      </div>

      <div class="p-6 space-y-4 max-h-[60vh] overflow-y-auto">
        <div v-if="!props.needsApprovalGroups.length" class="text-slate-400">No findings need approval.</div>
        <div v-for="group in props.needsApprovalGroups" :key="group.id" class="flex items-center justify-between p-4 rounded-2xl bg-slate-900 border border-slate-800">
          <div>
            <div class="font-semibold text-white">{{ group.id }}</div>
            <div class="text-sm text-slate-500">{{ group.severity || 'Unknown severity' }}</div>
          </div>
          <button
            type="button"
            @click="toggleId(group.id)"
            :class="['px-3 py-1.5 rounded-full text-sm font-semibold transition', selectedIds.has(group.id) ? 'bg-emerald-500 text-slate-950' : 'bg-slate-800 text-slate-400 hover:bg-slate-700']"
          >
            {{ selectedIds.has(group.id) ? 'Selected' : 'Select' }}
          </button>
        </div>
      </div>

      <div class="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-800 bg-slate-950">
        <button @click="$emit('close')" class="px-4 py-2 rounded-2xl bg-slate-800 text-slate-300 hover:bg-slate-700">Cancel</button>
        <button
          @click="applyApproval"
          :disabled="selectedIds.size === 0"
          class="px-4 py-2 rounded-2xl bg-emerald-500 text-slate-950 font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <span class="inline-flex items-center gap-2">
            <CheckCircle :size="16" />
            Approve Selected
          </span>
        </button>
      </div>
    </div>
  </div>
</template>
