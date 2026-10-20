<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api, send } from '../api'
import type { Me } from '../types'

type Product = { id: string; name: string; workspace_id: string }
const props = defineProps<{ actor: string; teams: Me['workspaces']; disabled?: boolean }>()
const emit = defineEmits<{ locked: [boolean]; created: [Product] }>()
const eligible = computed(() => props.teams.filter(team => team.capabilities.includes('write')))
const name = ref(''), team = ref(''), busy = ref(false), error = ref(''), inspected = ref(false)
const attempted = ref<{ actor: string; workspace_id: string; name: string } | null>(null)
const matches = ref<Product[]>([]), nextCursor = ref<string | null>(null), inspectionStarted = ref(false)
const locked = computed(() => busy.value || !!name.value || !!attempted.value)
watch(locked, value => emit('locked', value), { immediate: true, flush: 'sync' })
watch(eligible, values => { if (!attempted.value && !values.some(value => value.id === team.value)) team.value = values[0]?.id || '' }, { immediate: true })
let sequence = 0
function discard() {
  if (busy.value) return
  ++sequence; name.value = ''; attempted.value = null; error.value = ''; inspected.value = false; matches.value = []; nextCursor.value = null; inspectionStarted.value = false
}
async function create() {
  if (busy.value || props.disabled || attempted.value || !name.value.trim() || !eligible.value.some(value => value.id === team.value)) return
  const capture = { actor: props.actor, workspace_id: team.value, name: name.value.trim() }
  attempted.value = capture; busy.value = true; error.value = ''; const current = ++sequence
  try {
    const result = await api<Product>('/projects', send({ workspace_id: capture.workspace_id, name: capture.name }))
    if (current !== sequence || capture.actor !== props.actor) return
    if (typeof result.id !== 'string' || !result.id || result.name !== capture.name || result.workspace_id !== capture.workspace_id) throw new Error('Project response does not match the captured creation.')
    busy.value = false; discard(); emit('created', result)
  } catch {
    if (current === sequence) error.value = 'Creation was not confirmed. It may already have succeeded. Inspect the product catalog before starting another attempt; this request will not be retried.'
  } finally { if (current === sequence) busy.value = false }
}
async function inspect(append = false) {
  if (busy.value || !attempted.value || attempted.value.actor !== props.actor) return
  const capture = attempted.value, cursor = append ? nextCursor.value : null
  if (append && !cursor) return
  busy.value = true; const current = ++sequence
  try {
    const params = new URLSearchParams({ q: capture.name, workspace_id: capture.workspace_id, limit: '25' })
    if (cursor) params.set('cursor', cursor)
    const result = await api<{ items: Product[]; next_cursor: string | null }>(`/catalog/projects?${params}`)
    if (current !== sequence || capture.actor !== props.actor) return
    // Catalog scope is server-authorized; do not treat partial pages as absence.
    const scoped = result.items.filter(item => item.workspace_id === capture.workspace_id)
    matches.value = append ? [...matches.value, ...scoped] : scoped
    nextCursor.value = result.next_cursor; inspected.value = true; inspectionStarted.value = true
  } catch { if (current === sequence) error.value = 'Catalog inspection failed. The captured creation attempt remains retained; no creation was retried.' }
  finally { if (current === sequence) busy.value = false }
}
function select(product: Product) {
  if (busy.value || !attempted.value || attempted.value.actor !== props.actor) return
  discard(); emit('created', product)
}
watch(() => props.actor, () => { ++sequence; busy.value = false; discard() }, { flush: 'sync' })
onBeforeUnmount(() => { ++sequence; emit('locked', false) })
</script>
<template>
  <details v-if="eligible.length || locked" class="knowledge-create-product" aria-label="Create native product">
    <summary>Add product</summary>
    <form aria-label="Create product" @submit.prevent="create">
      <fieldset :disabled="busy || disabled || !!attempted">
        <label>Product owner team<select v-model="team"><option v-for="item in eligible" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
        <label>Product name<input v-model="name" required maxlength="200" autocomplete="off"></label>
        <button :disabled="!name.trim() || !team">Create product</button>
      </fieldset>
    </form>
    <p v-if="error" role="alert">{{ error }}</p>
    <section v-if="attempted" aria-label="Captured product creation">
      <p>{{ attempted.name }} · {{ teams.find(item => item.id === attempted?.workspace_id)?.name || attempted.workspace_id }}</p>
      <button :disabled="busy" @click="inspect()">Inspect product catalog</button>
      <p v-if="inspected" role="status">{{ matches.length }} matching products loaded{{ nextCursor ? '; more results remain' : '' }}. Catalog results do not establish whether a delayed request is still running.</p>
      <ul v-if="matches.length"><li v-for="item in matches" :key="item.id"><span>{{ item.name }}</span> <button :disabled="busy" @click="select(item)">Open {{ item.name }}</button></li></ul>
      <button v-if="nextCursor && inspectionStarted" :disabled="busy" @click="inspect(true)">More matching products</button>
    </section>
    <button v-if="locked" :disabled="busy" @click="discard">{{ attempted ? 'Discard creation attempt' : 'Discard product draft' }}</button>
  </details>
</template>
<style scoped>
.knowledge-create-product{margin:12px 0;min-width:0}.knowledge-create-product fieldset{display:flex;align-items:end;gap:12px;flex-wrap:wrap;border:0;padding:12px 0;min-width:0}.knowledge-create-product label{display:flex;flex-direction:column;gap:4px;max-width:100%}.knowledge-create-product input,.knowledge-create-product select{max-width:100%;box-sizing:border-box}.knowledge-create-product p,.knowledge-create-product li{overflow-wrap:anywhere}.knowledge-create-product button{margin:4px 0}.knowledge-create-product ul{padding-left:20px}
</style>
