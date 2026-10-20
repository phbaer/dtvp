<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { ref, onBeforeUnmount, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import { send } from '../api'
const props = defineProps<{ project: string; actor: string; disabled: boolean; editable: boolean }>()
const emit = defineEmits<{ locked: [boolean] }>()
const state = ref<string | null>(null), draft = ref(''), original = ref(''), loaded = ref(false), busy = ref(false), error = ref(''), notice = ref('')
const pending = ref<{ request_id: string; expected_policy: string | null; config: object } | null>(null)
let alive = true
watch(() => busy.value || !!pending.value || draft.value !== original.value, value => emit('locked', value), { immediate: true })
async function load() {
  if (loaded.value || busy.value) return
  busy.value = true; error.value = ''
  try { const result = await knowledgeApi<{ state: string | null; config: object }>(`/projects/${encodeURIComponent(props.project)}/scoring-policy`); if (alive) { state.value = result.state; draft.value = JSON.stringify(result.config, null, 2); original.value = draft.value; loaded.value = true } }
  catch (err) { if (alive) error.value = String(err) } finally { if (alive) busy.value = false }
}
async function save() {
  if (busy.value || props.disabled || !props.editable) return
  error.value = ''; notice.value = ''
  try {
    if (!pending.value) pending.value = { request_id: crypto.randomUUID(), expected_policy: state.value, config: JSON.parse(draft.value) }
    busy.value = true
    const receipt = await knowledgeApi<{ committed: boolean; projection: string }>(`/projects/${encodeURIComponent(props.project)}/scoring-policy`, { ...send(pending.value), method: 'PUT' })
    if (!alive) return
    if (receipt.committed !== true || receipt.projection !== 'current') { notice.value = 'Outcome pending; retry the exact captured policy or inspect the current policy.'; return }
    pending.value = null; loaded.value = false; notice.value = 'Scoring rules saved. Existing published scores remain retained.'; busy.value = false; await load()
  } catch (err) { if (alive) error.value = String(err) } finally { if (alive) busy.value = false }
}
onBeforeUnmount(() => { alive = false; emit('locked', false) })
</script>
<template><TaskSurface @active="open => { if (open && !loaded) void load() }" title="Contextual scoring rules"><section aria-label="Project scoring policy"><p class="hint">Versioned project rules propose contextual vectors from approved applicability. Coordinators still preview and explicitly publish each score.</p><p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p><label v-if="loaded">Scoring policy JSON<textarea v-model="draft" rows="16" spellcheck="false" maxlength="262144" :disabled="!editable || disabled || busy || !!pending"></textarea></label><div class="knowledge-actions"><button v-if="editable" :disabled="disabled || busy || !loaded" @click="save">{{ pending ? 'Retry exact scoring policy' : 'Save scoring rules (manage required)' }}</button><button v-if="pending || draft !== original" :disabled="busy" @click="pending = null; draft = original; notice = 'Captured policy discarded locally. Inspect current policy before editing again.'">Discard captured policy</button></div></section></TaskSurface></template>
