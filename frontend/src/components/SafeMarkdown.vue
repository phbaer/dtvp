<script setup lang="ts">
import { computed } from 'vue'
import { renderSafeMarkdown } from '../lib/safeMarkdown'

const props = defineProps<{ markdown: string }>()
const rendered = computed(() => renderSafeMarkdown(props.markdown))
</script>

<template>
    <!-- Sanitised by renderSafeMarkdown; see lib/safeMarkdown.ts. -->
    <div class="safe-markdown min-w-0 max-w-full overflow-x-auto break-words text-xs leading-relaxed text-gray-300" data-testid="safe-markdown" v-html="rendered"></div>
</template>

<style scoped>
.safe-markdown :deep(h1) { font-size: 1rem; font-weight: 700; margin: 0 0 0.75rem; }
.safe-markdown :deep(h2), .safe-markdown :deep(h3) { font-size: 0.875rem; font-weight: 700; margin: 1.25rem 0 0.5rem; }
.safe-markdown :deep(h4), .safe-markdown :deep(h5), .safe-markdown :deep(h6) { font-weight: 700; margin: 1rem 0 0.4rem; }
.safe-markdown :deep(p) { margin: 0.5rem 0; }
.safe-markdown :deep(ul) { list-style: disc; padding-left: 1.25rem; margin: 0.5rem 0; }
.safe-markdown :deep(ol) { list-style: decimal; padding-left: 1.25rem; margin: 0.5rem 0; }
.safe-markdown :deep(table) { border-collapse: collapse; margin: 0.75rem 0; width: 100%; }
.safe-markdown :deep(th), .safe-markdown :deep(td) { border: 1px solid #374151; padding: 0.4rem; text-align: left; vertical-align: top; }
.safe-markdown :deep(a) { color: #67e8f9; text-decoration: underline; }
.safe-markdown :deep(pre) { overflow-x: auto; background: rgb(3 7 18 / 0.6); padding: 0.5rem; border-radius: 0.25rem; }
.safe-markdown :deep(code) { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.safe-markdown :deep(blockquote) { border-left: 2px solid #4b5563; padding-left: 0.75rem; color: #9ca3af; }
</style>
