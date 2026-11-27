<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Info } from '@lucide/vue'
import type { TaggedComponentInfo } from '../lib/useVulnDependencyInfo'

const props = defineProps<{ components: TaggedComponentInfo[] }>()
const showAll = ref(false)
const expanded = ref(new Set<string>())
const visible = computed(() => showAll.value ? props.components : props.components.slice(0, 4))
const keyOf = (component: TaggedComponentInfo) => JSON.stringify([component.name, component.tag])
const toggle = (component: TaggedComponentInfo) => {
    const key = keyOf(component)
    const next = new Set(expanded.value)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    expanded.value = next
}
watch(() => props.components, () => { showAll.value = false; expanded.value = new Set() })
</script>

<template>
    <div v-if="components.length" data-testid="triggering-team-components" class="min-w-0 space-y-2 rounded border border-gray-800/80 bg-gray-950/30 p-3">
        <h5 class="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-500">
            Team-mapped components
            <span title="The components whose team mapping assigns the teams above: the reported component itself or one above it in a dependency chain. Without a mapping the catch-all '*' assigns the team.">
                <Info :size="11" aria-hidden="true" />
            </span>
        </h5>
        <div class="max-h-64 space-y-1.5 overflow-auto" role="region" aria-label="Team-mapped components" tabindex="0">
            <div
                v-for="component in visible" :key="keyOf(component)"
                data-testid="triggering-team-component" :data-catch-all="component.catchAll ? 'true' : undefined"
                class="min-w-0 max-w-full rounded border px-2 py-1 text-[11px]"
                :class="component.catchAll ? 'border-amber-700/50 bg-amber-950/30 text-amber-100' : 'border-gray-700 bg-gray-800 text-gray-300'"
                :title="component.catchAll ? `The catch-all '*' assigns ${component.tag}; no component in this chain has an explicit team mapping.` : undefined"
            >
                <span class="break-all font-mono">{{ component.name }}<span v-if="component.versions.length" class="text-gray-500">@{{ component.versions.slice(0, 3).join(', ') }}</span></span>
                <span v-if="component.under?.length" class="ml-1 break-words text-amber-200/70">under {{ component.under.slice(0, 3).join(', ') }}</span>
                <span class="ml-2" :class="component.catchAll ? 'text-amber-300' : 'text-blue-300'">({{ component.tag }}<template v-if="component.catchAll">; no team mapping, catch-all '*'</template>)</span>
                <button
                    v-if="component.versions.length > 3 || (component.under?.length || 0) > 3"
                    type="button" :aria-expanded="expanded.has(keyOf(component))"
                    class="ml-2 rounded px-1 text-blue-300 underline hover:text-blue-100"
                    @click="toggle(component)"
                >{{ expanded.has(keyOf(component)) ? 'Hide details' : `Show all (${component.versions.length} component versions${component.under?.length ? `, ${component.under.length} product versions` : ''})` }}</button>
                <div v-if="expanded.has(keyOf(component))" class="mt-2 space-y-1 border-t border-gray-700 pt-2 text-gray-300">
                    <p v-if="component.versions.length" class="break-words">Component versions: {{ component.versions.join(', ') }}</p>
                    <p v-if="component.under?.length" class="break-words">Under: {{ component.under.join(', ') }}</p>
                </div>
            </div>
        </div>
        <button v-if="components.length > 4" type="button" :aria-expanded="showAll" class="rounded px-1 py-1 text-xs text-blue-300 underline hover:text-blue-100" @click="showAll = !showAll">
            {{ showAll ? 'Show fewer components' : `Show all ${components.length} components (${components.length - 4} more)` }}
        </button>
    </div>
</template>
