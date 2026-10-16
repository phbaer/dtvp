<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeConfigurationEditor from './KnowledgeConfigurationEditor.vue'
type Context = { inventory_state: string; configuration_state: string; digest: string; total: number; unmapped: number; next_offset: number | null; rows: { component_ref: string; context_id: string | null; status: string; mappings: { mapping_id: string; model_id: string; model_revision: string; entity_ids: string[] }[] }[] }
const props = defineProps<{ project: string; actor: string; state?: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [boolean]; refresh: [] }>()
const editorLocked = ref(false), busy = ref(false), configuration = ref(''), report = ref<Context | null>(null), error = ref('')
let generation = 0
const locked = computed(() => editorLocked.value || busy.value)
watch(locked, value => emit('locked', value), { immediate: true })
watch(() => [props.project, props.actor], () => { ++generation; configuration.value = ''; report.value = null; busy.value = false; editorLocked.value = false; error.value = '' })
watch(() => props.state, () => { ++generation; report.value = null; busy.value = false; error.value = '' })
function loaded(value: Record<string, unknown>) { configuration.value = typeof value.configuration_state === 'string' ? value.configuration_state : ''; report.value = null }
async function inspect(offset = 0) {
  if (busy.value || props.disabled || editorLocked.value || !props.state || !configuration.value) return
  const state = props.state, pin = configuration.value, previous = report.value?.digest, current = ++generation; busy.value = true; error.value = ''
  try {
    const value = await knowledgeApi<Context>(`/projects/${encodeURIComponent(props.project)}/states/${state}/pipeline-context?configuration=${pin}&offset=${offset}&limit=20`)
    if (current !== generation) return
    if (value.inventory_state !== state || value.configuration_state !== pin || (offset && value.digest !== previous)) throw new Error('Resolved context changed its requested inventory/configuration pins.')
    report.value = value
  } catch (err) { if (current === generation) error.value = err instanceof Error ? err.message : 'Resolved context unavailable' }
  finally { if (current === generation) busy.value = false }
}
onBeforeUnmount(() => { ++generation; emit('locked', false) })
</script>
<template>
  <section aria-label="Pipeline configuration and context">
    <KnowledgeConfigurationEditor :project="project" :actor="actor" kind="pipeline" :disabled="disabled || busy" @locked="editorLocked = $event" @refresh="emit('refresh')" @loaded="loaded" />
    <details v-if="configuration && state"><summary>Resolved threat-model mappings</summary>
      <p v-if="error" role="alert">{{ error }}</p>
      <button :disabled="disabled || busy || editorLocked" @click="inspect()">Inspect pinned model mappings</button>
      <section v-if="report" aria-label="Resolved pipeline context">
        <p>{{ report.total }} contexts · {{ report.unmapped }} unmapped · user/CI declared</p>
        <ul><li v-for="row in report.rows" :key="row.context_id || row.component_ref">{{ row.component_ref }} · {{ row.status }}<p v-for="mapping in row.mappings" :key="mapping.mapping_id">{{ mapping.model_id }} · {{ mapping.model_revision }} · {{ mapping.entity_ids.join(', ') }}</p></li></ul>
        <button v-if="report.next_offset !== null" :disabled="disabled || busy || editorLocked" @click="inspect(report.next_offset)">Next resolved model mappings</button>
        <details><summary>Exact mapping pins</summary><p>Inventory: <code>{{ report.inventory_state }}</code></p><p>Configuration: <code>{{ report.configuration_state }}</code></p><p>Digest: <code>{{ report.digest }}</code></p></details>
      </section>
    </details>
  </section>
</template>
<style scoped>
section{min-width:0}summary{cursor:pointer}code{overflow-wrap:anywhere}li{overflow-wrap:anywhere;margin-block:.6rem}
</style>
