<script setup lang="ts">
defineProps<{
    title: string
    description?: string
    step?: string
    bodyClass?: string
}>()
</script>

<template>
    <section class="overflow-hidden rounded-lg border border-gray-700/70 bg-gray-900/45 shadow-sm shadow-black/10">
        <header class="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
            <div class="min-w-0">
                <div v-if="step" class="mb-1 text-[10px] font-black uppercase tracking-[0.18em] text-cyan-500/80">
                    {{ step }}
                </div>
                <h4 class="text-sm font-bold text-gray-100">{{ title }}</h4>
                <p v-if="description" class="mt-1 max-w-4xl text-xs leading-relaxed text-gray-500">
                    {{ description }}
                </p>
            </div>
            <slot name="actions" />
        </header>
        <div class="border-t border-gray-800/90 p-4" :class="bodyClass">
            <slot />
        </div>
    </section>
</template>
