<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { marked } from 'marked';

const props = defineProps<{
    changelog: string;
}>();

const emit = defineEmits<{
    (e: 'acknowledge'): void;
}>();

const renderedChangelog = ref('');

onMounted(async () => {
    renderedChangelog.value = await marked.parse(props.changelog);
});
</script>

<template>
    <div class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-[100]">
        <div class="bg-gray-800 border border-gray-700 rounded-lg shadow-2xl max-w-2xl w-full max-h-[80vh] flex flex-col">
            <!-- Header -->
            <div class="p-4 border-b border-gray-700 flex justify-between items-center">
                <h3 class="font-bold text-lg text-blue-400">What's New</h3>
                <button @click="$emit('acknowledge')" class="text-gray-400 hover:text-white transition-colors">✕</button>
            </div>

            <!-- Content -->
            <div class="p-6 overflow-y-auto prose prose-invert prose-sm max-w-none changelog-content">
                <div v-html="renderedChangelog"></div>
            </div>

            <!-- Footer -->
            <div class="p-4 border-t border-gray-700 flex justify-end">
                <button 
                    @click="$emit('acknowledge')"
                    class="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-md font-medium transition-colors shadow-lg active:scale-95"
                >
                    Got it!
                </button>
            </div>
        </div>
    </div>
</template>

<style scoped>
@reference "../style.css";
.changelog-content :deep(h1) { @apply text-2xl font-bold mb-4 text-blue-400 border-b border-gray-700 pb-2; }
.changelog-content :deep(h2) { @apply text-xl font-bold mt-6 mb-3 text-blue-300; }
.changelog-content :deep(h3) { @apply text-lg font-bold mt-4 mb-2 text-gray-200; }
.changelog-content :deep(p) { @apply mb-3 text-gray-300 leading-relaxed; }
.changelog-content :deep(ul) { @apply list-disc ml-5 mb-4 space-y-1 text-gray-300; }
.changelog-content :deep(li) { @apply pl-1; }
.changelog-content :deep(code) { @apply bg-gray-900 px-1.5 py-0.5 rounded text-pink-400 font-mono text-sm; }
.changelog-content :deep(strong) { @apply font-bold text-gray-100; }
</style>
