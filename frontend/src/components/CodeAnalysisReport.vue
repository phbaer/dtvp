<script setup lang="ts">
import SafeMarkdown from './SafeMarkdown.vue'

defineProps<{ markdown: string }>()
</script>

<template>
    <section class="mt-3 min-w-0 max-w-full" data-testid="assessment-report">
        <h4 class="mb-2 text-[10px] font-bold uppercase tracking-wide text-gray-400">Full assessment</h4>
        <SafeMarkdown class="assessment-report" :markdown="markdown" />
    </section>
</template>
