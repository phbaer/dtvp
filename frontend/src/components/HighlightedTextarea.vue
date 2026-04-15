<script setup lang="ts">
import { ref, computed } from 'vue'

const props = defineProps<{
  modelValue: string
  placeholder?: string
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
  (e: 'input'): void
}>()

const textareaEl = ref<HTMLTextAreaElement | null>(null)
const backdropEl = ref<HTMLDivElement | null>(null)

const onInput = (event: Event) => {
  const target = event.target as HTMLTextAreaElement
  emit('update:modelValue', target.value)
  emit('input')
}

const onScroll = () => {
  if (textareaEl.value && backdropEl.value) {
    backdropEl.value.scrollTop = textareaEl.value.scrollTop
    backdropEl.value.scrollLeft = textareaEl.value.scrollLeft
  }
}

const highlightedHtml = computed(() => {
  const text = props.modelValue || ''
  if (!text) return ''

  const escaped = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

  return escaped
    // Full header lines: --- [Team: ...] ... ---
    .replace(
      /^(---\s*(?:\[[^\]]*\]\s*)+---)$/gm,
      '<span class="hl-header">$1</span>'
    )
    // Metadata tags: [Key: Value]
    .replace(
      /(\[(?:Team|State|Assessed By|Date|Justification|Rescored|Rescored Vector|Status|Comment):\s*[^\]]*\])/g,
      '<span class="hl-tag">$1</span>'
    )
    // Status tags without colon: [Status: Pending Review]
    // Already covered above, but catch standalone [TMRescore Proposal Applied] etc.
    .replace(
      /(\[(?:TMRescore Proposal Applied)\])/g,
      '<span class="hl-marker">$1</span>'
    )
    // Key-value labels at start of line: Reasoning:, Vector:, Score:, Analysis:, etc.
    .replace(
      /^((?:Reasoning|Vector|Score|Suggested state|Justification|Analysis):)/gm,
      '<span class="hl-label">$1</span>'
    )
    // Trailing newline to keep height in sync
    + '\n'
})
</script>

<template>
  <div class="highlighted-textarea relative">
    <div
      ref="backdropEl"
      class="backdrop absolute inset-0 p-2 overflow-hidden pointer-events-none whitespace-pre-wrap break-words text-sm leading-[1.5] border border-transparent rounded"
      aria-hidden="true"
      v-html="highlightedHtml"
    ></div>
    <textarea
      ref="textareaEl"
      :value="modelValue"
      @input="onInput"
      @scroll="onScroll"
      :placeholder="placeholder"
      spellcheck="false"
      class="relative w-full p-2 rounded bg-transparent border border-gray-600 focus:border-blue-500 h-48 resize-y text-sm leading-[1.5] caret-white text-transparent selection:bg-blue-500/30"
    ></textarea>
  </div>
</template>

<style scoped>
.highlighted-textarea {
  position: relative;
}

.backdrop {
  background: rgb(31 41 55);
  color: rgb(209 213 219); /* gray-300 — default text */
  font-family: inherit;
  word-break: break-word;
}

.backdrop :deep(.hl-header) {
  color: rgb(147 130 220); /* purple-ish for full header lines */
  opacity: 0.7;
}

.backdrop :deep(.hl-tag) {
  color: rgb(125 167 225); /* blue for metadata tags */
  font-weight: 600;
}

.backdrop :deep(.hl-marker) {
  color: rgb(94 204 163); /* teal for special markers */
  font-weight: 700;
}

.backdrop :deep(.hl-label) {
  color: rgb(196 167 107); /* amber for key-value labels */
  font-weight: 600;
}

textarea {
  background: transparent !important;
  position: relative;
  z-index: 1;
}
</style>
