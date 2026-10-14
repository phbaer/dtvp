<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { api } from '../api'

type Option = { id: string; name?: string; version?: string; workspace?: string }
const props = defineProps<{ modelValue: string; label: string; selectedLabel?: string; endpoint: string; allowClear?: boolean; disabled?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: string]; select: [option: Option] }>()
const open = ref(false), query = ref(''), options = ref<Option[]>([]), cursor = ref<string | null>(null)
const loading = ref(false), error = ref(''), active = ref(-1)
const root = ref<HTMLElement>(), input = ref<HTMLInputElement>()
const id = `select-${props.label.toLowerCase().replaceAll(' ', '-')}`
const selected = computed(() => props.selectedLabel || (props.allowClear ? 'All' : 'Select…'))
let sequence = 0, timer: ReturnType<typeof setTimeout>
async function load(append = false) {
  const current = ++sequence
  loading.value = true; error.value = ''
  try {
    const params = new URLSearchParams({ q: query.value, limit: '25' })
    if (append && cursor.value) params.set('cursor', cursor.value)
    const result = await api<{ items: Option[]; next_cursor: string | null }>(`${props.endpoint}?${params}`)
    if (current !== sequence) return
    options.value = append ? [...options.value, ...result.items] : result.items
    cursor.value = result.next_cursor; active.value = -1
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Search failed' }
  finally { if (current === sequence) loading.value = false }
}
async function toggle() {
  open.value = !open.value
  if (open.value) { query.value = ''; await load(); await nextTick(); input.value?.focus() }
}
function choose(option: Option) { emit('update:modelValue', option.id); emit('select', option); open.value = false; root.value?.querySelector<HTMLButtonElement>('button')?.focus() }
function keys(event: KeyboardEvent) {
  if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); open.value = false; root.value?.querySelector<HTMLButtonElement>('button')?.focus() }
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); active.value = Math.max(0, Math.min(options.value.length - 1, active.value + (event.key === 'ArrowDown' ? 1 : -1))); document.getElementById(`${id}-${active.value}`)?.scrollIntoView({ block: 'nearest' }) }
  if (event.key === 'Enter' && active.value >= 0) { event.preventDefault(); choose(options.value[active.value]!) }
}
function outside(event: Event) { if (!root.value?.contains(event.target as Node)) open.value = false }
watch(query, () => { clearTimeout(timer); timer = setTimeout(() => { void load() }, 180) })
watch(() => props.endpoint, () => { options.value = []; cursor.value = null; if (open.value) void load() })
watch(open, value => { if (value) document.addEventListener('pointerdown', outside); else { sequence++; loading.value = false; document.removeEventListener('pointerdown', outside) } })
onBeforeUnmount(() => { clearTimeout(timer); sequence++; document.removeEventListener('pointerdown', outside) })
</script>
<template>
  <div ref="root" class="search-select">
    <span :id="`${id}-label`" class="field-label">{{ label }}</span>
    <button type="button" :disabled="disabled || !endpoint" :aria-labelledby="`${id}-label ${id}-value`" :aria-expanded="open" aria-haspopup="listbox" @click="toggle"><span :id="`${id}-value`">{{ selected }}</span><span aria-hidden="true">⌄</span></button>
    <div v-if="open" class="select-menu" @keydown="keys">
      <input ref="input" v-model="query" type="search" role="combobox" :aria-label="`Search ${label.toLowerCase()}`" aria-autocomplete="list" aria-expanded="true" :aria-controls="`${id}-options`" :aria-activedescendant="active >= 0 ? `${id}-${active}` : undefined" placeholder="Type to search…">
      <button v-if="allowClear" type="button" @click="emit('update:modelValue', ''); open = false">All</button>
      <div :id="`${id}-options`" role="listbox" :aria-label="label">
        <button v-for="(option, index) in options" :id="`${id}-${index}`" :key="option.id" type="button" role="option" :aria-selected="modelValue === option.id" :class="{ active: active === index }" @click="choose(option)">{{ option.name || option.version }}<small v-if="option.workspace">{{ option.workspace }}</small></button>
      </div>
      <p v-if="error" role="alert">{{ error }}</p><p v-else-if="loading" role="status">Searching…</p><p v-else-if="!options.length">No results.</p>
      <button v-if="cursor" type="button" :disabled="loading" @click="load(true)">More results</button>
    </div>
  </div>
</template>
