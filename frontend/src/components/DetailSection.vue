<script setup lang="ts">
import { useId } from 'vue'
import { Info } from '@lucide/vue'

defineProps<{
    title: string
    /** What the section is for: a tooltip on the info icon, and the
     * section's description for screen readers. */
    help?: string
    bodyClass?: string
}>()

const id = useId()
</script>

<template>
    <section
        class="overflow-hidden rounded-lg border border-gray-700/70 bg-gray-900/45 shadow-sm shadow-black/10"
        :aria-labelledby="`${id}-title`"
        :aria-describedby="help ? `${id}-help` : undefined"
    >
        <header class="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5">
            <div class="flex min-w-0 items-center gap-1.5">
                <h4 :id="`${id}-title`" class="text-sm font-bold text-gray-100">{{ title }}</h4>
                <span
                    v-if="help"
                    data-testid="detail-section-help"
                    class="inline-flex cursor-help text-gray-500 hover:text-gray-300"
                    :title="help"
                >
                    <Info :size="12" aria-hidden="true" />
                </span>
                <span v-if="help" :id="`${id}-help`" class="sr-only">{{ help }}</span>
            </div>
            <slot name="actions" />
        </header>
        <div class="border-t border-gray-800/90 p-4" :class="bodyClass">
            <slot />
        </div>
    </section>
</template>
