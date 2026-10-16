<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
type Listing = { items: { assessment_id: string; reason: string; actor_id: string; archived_at: string; revision_count: number }[]; total: number; next_offset: number | null; capabilities: string[] }
type Candidate = { assessment_id: string; status: string; candidate: boolean; revisions: string[]; active_targets: unknown[]; tagged_references: string[] }
type Plan = { plan_hash: string; project_refs: Record<string, string>; assessments: Candidate[]; statistics: Record<string, number>; total: number; next_offset: number | null; limitations: string[] }
type Detail = { manifest: { assessment_id: string }; next_offset: number | null; [key: string]: unknown }
type Capture = { endpoint: string; body: { request_id: string; plan_hash: string; project_refs: Record<string, string>; assessment_ids: string[]; reason: string } }
const props = defineProps<{ project: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [boolean]; changed: [] }>()
const listing = ref<Listing | null>(null), plan = ref<Plan | null>(null), detail = ref<Detail | null>(null)
const busy = ref(false), error = ref(''), notice = ref(''), stale = ref(false), confirmed = ref(false), reason = ref('')
const selected = ref<string[]>([]), captured = ref<Capture | null>(null)
let sequence = 0
const endpoint = `/projects/${encodeURIComponent(props.project)}/maintenance/assessment-archive`
const locked = computed(() => busy.value || captured.value !== null || plan.value !== null)
const canPreview = computed(() => listing.value?.capabilities.includes('preview'))
const canApply = computed(() => listing.value?.capabilities.includes('apply'))
watch(locked, value => emit('locked', value), { immediate: true })
async function read(offset = 0) {
  if (busy.value || captured.value) return
  const token = ++sequence; busy.value = true; error.value = ''
  try { const result = await knowledgeApi<Listing>(`${endpoint}?offset=${offset}&limit=25`); if (token === sequence) listing.value = result }
  catch (e) { if (token === sequence) error.value = String(e instanceof Error ? e.message : e) }
  finally { if (token === sequence) busy.value = false }
}
function toggle(event: Event) { if ((event.target as HTMLDetailsElement).open && !listing.value) void read() }
async function inspect(offset = 0) {
  if (busy.value || props.disabled || captured.value || !canPreview.value || (offset > 0 && stale.value) || (offset === 0 && plan.value !== null)) return
  const token = ++sequence; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<Plan>(`${endpoint}/preview?offset=${offset}&limit=25`, send({}))
    if (token !== sequence) return
    if (offset > 0 && result.plan_hash !== plan.value?.plan_hash) { stale.value = true; throw new Error('Archive plan changed. Discard the selection and preview current references.') }
    if (offset === 0) { selected.value = []; confirmed.value = false; reason.value = ''; stale.value = false }
    plan.value = result
  } catch (e) { if (token === sequence) error.value = String(e instanceof Error ? e.message : e) }
  finally { if (token === sequence) busy.value = false }
}
function choose(id: string) {
  if (busy.value || captured.value || stale.value || props.disabled) return
  selected.value = selected.value.includes(id) ? selected.value.filter(item => item !== id) : selected.value.length < 100 ? [...selected.value, id] : selected.value
  confirmed.value = false
}
async function publish() {
  if (busy.value || props.disabled || (!captured.value && (!canApply.value || stale.value || !confirmed.value || !reason.value.trim() || !selected.value.length || !plan.value))) return
  if (!captured.value) captured.value = { endpoint: `${endpoint}/apply`, body: { request_id: crypto.randomUUID(), plan_hash: plan.value!.plan_hash, project_refs: JSON.parse(JSON.stringify(plan.value!.project_refs)), assessment_ids: [...selected.value], reason: reason.value } }
  const request = captured.value!, token = ++sequence; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<{ committed?: boolean; projection?: string }>(request.endpoint, send(request.body))
    if (token !== sequence) return
    if (result.committed !== true || result.projection !== 'current') throw new Error('Commit or projection is not confirmed current.')
    captured.value = null; plan.value = null; selected.value = []; confirmed.value = false; detail.value = null
    notice.value = 'Assessments archived. Immutable history remains; no physical storage was deleted.'
    emit('changed')
  } catch { if (token === sequence) error.value = 'Archive publication failed, conflicts or is uncertain. Retry the identical captured request or explicitly discard; its references and request ID remain fixed.' }
  finally { if (token === sequence) busy.value = false }
  if (!captured.value) await read()
}
function discard() { if (busy.value) return; captured.value = null; plan.value = null; selected.value = []; confirmed.value = false; reason.value = ''; stale.value = false; error.value = '' }
async function show(id: string, offset = 0) {
  if (busy.value) return
  const token = ++sequence; busy.value = true; error.value = ''
  try { const result = await knowledgeApi<Detail>(`${endpoint}/${encodeURIComponent(id)}?offset=${offset}&limit=25`); if (token === sequence) detail.value = result }
  catch (e) { if (token === sequence) error.value = String(e instanceof Error ? e.message : e) }
  finally { if (token === sequence) busy.value = false }
}
onBeforeUnmount(() => { ++sequence; emit('locked', false) })
</script>
<template>
  <details class="knowledge-archive" aria-label="Assessment archive" @toggle="toggle">
    <summary>Assessment archive</summary>
    <p class="hint">Retained evidence, not current approval. Logical retirement preserves history and does not reclaim disk space.</p>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <template v-if="listing">
      <p>{{ listing.total }} archived assessments</p>
      <button :disabled="busy || !!captured" @click="read()">Refresh archived assessments</button>
      <ul><li v-for="item in listing.items" :key="item.assessment_id"><button :disabled="busy" @click="show(item.assessment_id)">{{ item.assessment_id }}</button> · {{ item.revision_count }} revisions · {{ item.reason }}<small>{{ item.actor_id }} · {{ item.archived_at }}</small></li></ul>
      <button v-if="listing.next_offset != null" :disabled="busy || !!captured" @click="read(listing.next_offset)">More archived assessments</button>
      <details v-if="detail"><summary>Retained assessment and review evidence</summary><pre>{{ JSON.stringify(detail, null, 2) }}</pre><button v-if="typeof detail.next_offset === 'number'" :disabled="busy" @click="show(detail.manifest.assessment_id, detail.next_offset)">More retained evidence</button></details>
      <button v-if="canPreview" :disabled="busy || disabled || !!captured || !!plan" @click="inspect()">Preview unused assessment retirement</button>
    </template>
    <section v-if="plan" aria-label="Assessment retirement preview">
      <p>{{ plan.total }} logical assessments · {{ selected.length }} explicitly selected (maximum 100)</p>
      <p class="hint">{{ Object.entries(plan.statistics).map(([key, count]) => `${key.replaceAll('_', ' ')}: ${count}`).join(' · ') }}</p>
      <ul><li v-for="item in plan.assessments" :key="item.assessment_id"><label><input type="checkbox" :checked="selected.includes(item.assessment_id)" :disabled="busy || disabled || !!captured || stale || !item.candidate || (!selected.includes(item.assessment_id) && selected.length >= 100)" @change="choose(item.assessment_id)"> {{ item.assessment_id }} · {{ item.status.replaceAll('_', ' ') }}</label><details><summary>Coverage and protection</summary><pre>{{ JSON.stringify(item, null, 2) }}</pre></details></li></ul>
      <button v-if="plan.next_offset != null" :disabled="busy || disabled || !!captured || stale" @click="inspect(plan.next_offset)">More retirement candidates</button>
      <section v-if="selected.length" aria-label="Selected assessment IDs"><strong>Selected assessment IDs</strong><ul><li v-for="id in selected" :key="id">{{ id }}</li></ul></section>
      <label>Archival reason<textarea v-model="reason" maxlength="6000" rows="2" :disabled="busy || !!captured" @input="confirmed = false" /></label>
      <label><input v-model="confirmed" type="checkbox" :disabled="busy || !!captured"> I checked selected assessments and retained history; remove their current pointers.</label>
      <button v-if="canApply" :disabled="busy || disabled || (!captured && (stale || !confirmed || !reason.trim() || !selected.length))" @click="publish">{{ captured ? 'Retry exact assessment archival' : 'Archive selected assessments' }}</button>
      <details><summary>Plan pins and limitations</summary><code>{{ plan.plan_hash }}</code><pre>{{ JSON.stringify(plan.project_refs, null, 2) }}</pre><p v-for="item in plan.limitations" :key="item">{{ item }}</p><pre v-if="captured">{{ JSON.stringify(captured.body, null, 2) }}</pre></details>
      <button :disabled="busy" @click="discard">Discard archive plan and captured request</button>
    </section>
    <p v-if="busy" role="status">Loading archive request…</p>
  </details>
</template>
<style scoped>
.knowledge-archive{min-width:0;padding:12px;border:1px solid var(--line);border-radius:8px}.knowledge-archive summary{cursor:pointer}.knowledge-archive label,.knowledge-archive small{display:block;margin:8px 0}.knowledge-archive textarea{width:100%;box-sizing:border-box}.knowledge-archive input[type=checkbox]{width:auto}.knowledge-archive button{margin:5px 8px 5px 0}.knowledge-archive pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:300px;overflow:auto;font-size:.75rem}.knowledge-archive code{overflow-wrap:anywhere}.knowledge-archive ul{padding-left:20px}.hint{color:var(--muted);font-size:.8rem}
</style>
