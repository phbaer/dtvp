<script setup lang="ts">
import { ref, watch } from 'vue'
import { api } from '../api'
const props = defineProps<{ projectId: string; disabled: boolean }>()
const text = ref(''), version = ref(0), defaults = ref<Record<string, unknown>>({}), loaded = ref(false), busy = ref(false), error = ref(''), notice = ref('')
let sequence = 0
async function load() {
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    const result = await api<{ version: number; config: Record<string, unknown>; default_config: Record<string, unknown> }>(`/projects/${props.projectId}/rescore-policy`)
    if (current !== sequence) return
    text.value = JSON.stringify(result.config, null, 2); defaults.value = result.default_config; version.value = result.version; loaded.value = true
  } catch (err) { error.value = err instanceof Error ? err.message : 'Rules unavailable' }
  finally { if (current === sequence) busy.value = false }
}
async function save() {
  busy.value = true; error.value = ''; notice.value = ''
  try {
    await api(`/projects/${props.projectId}/rescore-policy`, { method: 'PUT', body: JSON.stringify({ expected_version: version.value, config: JSON.parse(text.value) }) })
    notice.value = 'Rules saved. Existing rule-based decisions require revalidation when the policy changes.'; await load()
  } catch (err) { error.value = err instanceof Error ? err.message : 'Rules could not be saved' }
  finally { busy.value = false }
}
watch(() => props.projectId, () => { sequence++; loaded.value = false; text.value = ''; error.value = ''; notice.value = '' })
</script>
<template>
  <details class="panel" @toggle="event => { if ((event.target as HTMLDetailsElement).open && !loaded) load() }"><summary>Version-aware rescoring rules</summary><p class="hint">Project-owned contextual rules for CVSS 2.0, 3.0, 3.1 and 4.0. Base metrics cannot be changed. Rules generate proposals; they never submit or approve an assessment.</p><p v-if="error" role="alert" class="warning">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p><label>Rule configuration (JSON) <textarea v-model="text" rows="16" :disabled="busy || disabled || !loaded"></textarea></label><div class="approval-actions"><button :disabled="busy || disabled || !loaded" @click="save">Save rescoring rules</button><button :disabled="busy || disabled || !loaded" @click="text = JSON.stringify(defaults, null, 2)">Use v1 defaults</button><button :disabled="busy || disabled" @click="load">Reload rules</button></div><p class="hint">Policy version {{ version }}. Concurrent edits are rejected.</p></details>
</template>
