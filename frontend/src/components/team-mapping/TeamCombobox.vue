<script setup lang="ts">
// Picks a team: the existing teams (found by name or alias) and, for a
// name no team has, "Create team …". The ARIA combobox pattern with a
// list box: arrows move, Enter picks, Escape closes.
import { computed, nextTick, ref, useId, watch } from 'vue'
import { ChevronDown, Plus } from '@lucide/vue'
import type { Team } from '../../lib/team-config'

const props = defineProps<{
    teams: Team[]
    label: string
    testid?: string
}>()
const model = defineModel<string>({ required: true })

const id = useId()
const open = ref(false)
const active = ref(0)
const text = ref(model.value)
watch(model, (value) => {
    if (value !== text.value) text.value = value
})

const lower = (value: string) => value.trim().toLowerCase()

interface Option {
    id: string
    value: string
    label: string
    hint: string
    create: boolean
}

const options = computed<Option[]>(() => {
    const needle = lower(text.value)
    const named = props.teams.filter(team => team.name.trim())
    const matching = named.filter(team => !needle
        || lower(team.name).includes(needle)
        || team.aliases.some(alias => lower(alias).includes(needle)))
    const result: Option[] = matching.map((team, index) => {
        const alias = needle && !lower(team.name).includes(needle)
            ? team.aliases.find(item => lower(item).includes(needle))
            : undefined
        const entries = team.components.filter(key => key !== '*').length
        const owns = [
            team.projects.length ? `${team.projects.length} ${team.projects.length === 1 ? 'project' : 'projects'}` : '',
            team.components.includes('*') ? 'catch-all' : '',
            `${entries} ${entries === 1 ? 'entry' : 'entries'}`,
        ].filter(Boolean).join(' · ')
        return {
            id: `${id}-option-${index}`,
            value: team.name,
            label: team.name,
            hint: alias ? `former name ${alias} · ${owns}` : owns,
            create: false,
        }
    })
    const exact = named.some(team => lower(team.name) === needle || team.aliases.some(alias => lower(alias) === needle))
    if (needle && !exact) {
        result.push({ id: `${id}-option-new`, value: text.value.trim(), label: `Create team “${text.value.trim()}”`, hint: 'new team', create: true })
    }
    return result
})

watch(options, (list) => {
    if (active.value >= list.length) active.value = Math.max(0, list.length - 1)
})

const choose = (option: Option) => {
    text.value = option.value
    model.value = option.value
    open.value = false
}

const onInput = (event: Event) => {
    text.value = (event.target as HTMLInputElement).value
    open.value = true
    active.value = 0
    // A typed name that is a team (or a former name of one) is that team.
    const needle = lower(text.value)
    const team = props.teams.find(item => lower(item.name) === needle)
        || props.teams.find(item => item.aliases.some(alias => lower(alias) === needle))
    model.value = team ? team.name : text.value.trim()
}

const listbox = ref<HTMLElement | null>(null)
const scrollActive = async () => {
    await nextTick()
    listbox.value?.querySelector(`#${CSS.escape(options.value[active.value]?.id || '')}`)?.scrollIntoView?.({ block: 'nearest' })
}

const onKeydown = (event: KeyboardEvent) => {
    const count = options.value.length
    if (event.key === 'ArrowDown') {
        event.preventDefault()
        if (!open.value) { open.value = true; return }
        active.value = count ? (active.value + 1) % count : 0
        scrollActive()
    } else if (event.key === 'ArrowUp') {
        event.preventDefault()
        if (!open.value) { open.value = true; return }
        active.value = count ? (active.value - 1 + count) % count : 0
        scrollActive()
    } else if (event.key === 'Enter') {
        if (open.value && options.value[active.value]) {
            event.preventDefault()
            choose(options.value[active.value])
        }
    } else if (event.key === 'Escape') {
        if (open.value) {
            event.preventDefault()
            event.stopPropagation()
            open.value = false
        }
    }
}

const isNew = computed(() => Boolean(model.value.trim())
    && !props.teams.some(team => lower(team.name) === lower(model.value)))
</script>

<template>
  <div class="relative">
    <label :for="`${id}-input`" class="mb-1 block text-xs text-gray-300">{{ label }}</label>
    <div class="relative">
      <input
        :id="`${id}-input`"
        :value="text"
        role="combobox"
        type="text"
        autocomplete="off"
        :data-testid="testid"
        :aria-expanded="open"
        :aria-controls="`${id}-listbox`"
        aria-autocomplete="list"
        :aria-activedescendant="open && options[active] ? options[active].id : undefined"
        placeholder="Choose or create a team"
        class="w-full rounded border border-gray-600 bg-gray-900 py-1 pl-2 pr-7 text-xs text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
        @input="onInput"
        @click="open = true"
        @blur="open = false"
        @keydown="onKeydown"
      />
      <ChevronDown :size="14" class="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-gray-400" aria-hidden="true" />
    </div>
    <ul
      v-show="open && options.length"
      :id="`${id}-listbox`"
      ref="listbox"
      role="listbox"
      :aria-label="label"
      class="absolute z-40 mt-1 max-h-60 w-full min-w-[16rem] overflow-y-auto rounded border border-gray-600 bg-gray-900 py-1 text-xs shadow-xl"
    >
      <li
        v-for="(option, index) in options"
        :id="option.id"
        :key="option.id"
        role="option"
        :aria-selected="index === active"
        :data-testid="option.create ? 'team-option-new' : `team-option-${option.value}`"
        :class="['flex cursor-pointer items-center gap-2 px-2 py-1', index === active ? 'bg-blue-700 text-white' : 'text-gray-200 hover:bg-gray-700']"
        @mousedown.prevent="choose(option)"
        @mousemove="active = index"
      >
        <Plus v-if="option.create" :size="12" aria-hidden="true" />
        <span class="font-medium">{{ option.label }}</span>
        <span :class="['ml-auto truncate', index === active ? 'text-blue-100' : 'text-gray-400']">{{ option.hint }}</span>
      </li>
    </ul>
    <p v-if="isNew" class="mt-1 text-[11px] text-amber-200">A new team {{ model.trim() }} is created.</p>
  </div>
</template>
