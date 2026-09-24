<script setup lang="ts">
import { computed, ref } from 'vue'
import { resolveTeamTerm } from '../lib/teamSelection'
const props = defineProps<{ modelValue: readonly string[], options: readonly string[], aliases?: Readonly<Record<string, readonly string[]>> }>()
const emit = defineEmits<{ 'update:modelValue': [teams: string[]] }>()
const search = ref('')
const available = computed(() => [...new Set([...props.modelValue, ...resolveTeamTerm('', props.options, props.aliases).matches])])
const filtered = computed(() => available.value.filter(team => [team, ...(props.aliases?.[team] || [])]
    .some(name => name.toLowerCase().includes(search.value.toLowerCase()))))
function toggle(team: string) {
    emit('update:modelValue', props.modelValue.includes(team) ? props.modelValue.filter(value => value !== team) : [...props.modelValue, team])
}
</script>
<template>
    <details class="rounded border border-gray-700 bg-gray-900/60 p-2" data-testid="team-filter-select">
        <summary class="cursor-pointer text-sm text-gray-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400">
            Teams: {{ modelValue.length ? modelValue.join(', ') : 'All' }}
        </summary>
        <label class="mt-2 block text-xs text-gray-400">Search teams
            <input v-model="search" type="search" class="mt-1 w-full rounded border border-gray-600 bg-gray-950 p-2 text-gray-100" />
        </label>
        <fieldset class="mt-2 max-h-52 overflow-auto space-y-1">
            <legend class="sr-only">Select teams</legend>
            <label v-for="team in filtered" :key="team" class="flex items-center gap-2 p-1 text-sm text-gray-200">
                <input type="checkbox" :checked="modelValue.includes(team)" @change="toggle(team)" />
                {{ team }}
            </label>
            <p v-if="!filtered.length" class="text-xs text-gray-400">No matching teams.</p>
        </fieldset>
        <button v-if="modelValue.length" type="button" class="mt-2 text-xs text-blue-300 underline" @click="emit('update:modelValue', [])">Clear teams</button>
    </details>
</template>
