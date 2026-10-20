<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Source = { source: string; part_id: string | null; state: string; build_number?: number; subject_declaration?: unknown; baseline?: { build_number?: number; [key: string]: unknown } }
type Sources = { items: Source[]; digest: string; head: string; next_offset: number | null; total: number; capabilities: string[] }
type Preview = { project_id: string; version: string; expected: string; configuration: string | null; preview_digest: string; human_decisions_changed: boolean; reports: { source: string; part_id: string | null; report: { summary?: Record<string, number>; [key: string]: unknown }; bounded_sample?: boolean }[] }
type Capture = { kind: 'import'; endpoint: string; metadata: string; file: File } | { kind: 'selection'; endpoint: string; input: Record<string, unknown>; applyBody?: string }
const props = defineProps<{ project: string; version: string; state: string; actor: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [boolean]; refresh: [] }>()
const loaded = ref(false), writable = ref(false), busy = ref(false), error = ref(''), notice = ref(''), confirmed = ref(false), attempted = ref(false)
const configuration = ref<string | null>(null), sources = ref<Sources | null>(null), metadata = ref(''), selection = ref(''), initialMetadata = ref(''), initialSelection = ref('')
const file = ref<File | null>(null), fileKey = ref(0), captured = ref<Capture | null>(null), preview = ref<Preview | null>(null)
let generation = 0
const importDirty = computed(() => !!file.value || metadata.value !== initialMetadata.value)
const selectionDirty = computed(() => selection.value !== initialSelection.value)
const dirty = computed(() => importDirty.value || selectionDirty.value)
const locked = computed(() => busy.value || !!captured.value || dirty.value)
const blocked = computed(() => busy.value || !!props.disabled)
watch(locked, value => emit('locked', value), { immediate: true })
const path = () => `/projects/${encodeURIComponent(props.project)}/versions/${encodeURIComponent(props.version)}`
function clearCapture() { captured.value = null; preview.value = null; attempted.value = false; confirmed.value = false }
function reset() { ++generation; loaded.value = false; writable.value = false; busy.value = false; clearCapture(); file.value = null; fileKey.value++; sources.value = null; configuration.value = null; metadata.value = ''; selection.value = ''; initialMetadata.value = ''; initialSelection.value = ''; error.value = ''; notice.value = '' }
watch(() => [props.project, props.version, props.actor], reset)
watch(() => props.state, () => { ++generation; busy.value = false; loaded.value = false; sources.value = null; if (captured.value) error.value = 'Inventory changed. Captured request retains its original pins; retry its receipt or discard explicitly.' })
function object(text: string) { if (text.length > 2 * 1024 * 1024) throw new Error('JSON exceeds 2 MiB.'); const value: unknown = JSON.parse(text); if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('JSON object required.'); return value as Record<string, unknown> }
async function load(offset = 0) {
  if (blocked.value || captured.value || importDirty.value || (dirty.value && !offset)) return
  const current = ++generation, expected = props.state, digest = sources.value?.digest; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<Sources>(`${path()}/observation-sources?offset=${offset}&limit=20`)
    if (current !== generation) return
    if (result.head !== expected || !/^[a-f0-9]{64}$/.test(result.digest) || (offset && result.digest !== digest)) throw new Error('Observation listing changed; refresh its complete source pins.')
    if (!offset) {
      const [config, accepted] = await Promise.all([
        knowledgeApi<{ configuration_state: string | null }>(`/projects/${encodeURIComponent(props.project)}/pipeline-config`),
        knowledgeApi<{ state: string; selection: { sources?: Record<string, unknown> } | null }>(`${path()}/observation-selection`),
      ])
      if (current !== generation) return
      if (accepted.state !== expected) throw new Error('Accepted observation selection changed its inventory pin.')
      configuration.value = config.configuration_state
      initialMetadata.value = metadata.value = JSON.stringify({ source: '', part_id: null, expected: null, expected_authority: expected, expected_configuration: config.configuration_state, build_number: 1, occurred_at: new Date().toISOString(), context: {}, subject_declaration: null }, null, 2)
      initialSelection.value = selection.value = JSON.stringify({ expected, expected_configuration: config.configuration_state, sources: Object.values(accepted.selection?.sources || {}), removal_reason: '' }, null, 2)
    }
    sources.value = result; writable.value = result.capabilities.includes('write'); loaded.value = true
  } catch (err) { if (current === generation) error.value = err instanceof Error ? err.message : 'Observation sources unavailable' }
  finally { if (current === generation) busy.value = false }
}
function toggle(open: boolean) { if (open && !loaded.value) void load() }
function choose(event: Event) { if (!blocked.value && !captured.value) file.value = (event.target as HTMLInputElement).files?.[0] || null }
function select(source: Source) {
  if (blocked.value || captured.value || !writable.value || importDirty.value) return
  try {
    const input = object(selection.value)
    if (!Array.isArray(input.sources)) throw new Error('Selection requires a sources array.')
    if (input.sources.some(item => item.source === source.source && item.part_id === source.part_id)) throw new Error('Source already selected. Edit its pinned state explicitly to replace it.')
    input.sources.push({ source: source.source, part_id: source.part_id, state: source.state, accepted_components: [], accepted_relationships: [], reason: '' })
    selection.value = JSON.stringify(input, null, 2); preview.value = null
  } catch (err) { error.value = err instanceof Error ? err.message : 'Invalid selection' }
}
async function importFile() {
  if (blocked.value || !writable.value || selectionDirty.value || (captured.value && captured.value.kind !== 'import')) return
  const current = ++generation; busy.value = true; error.value = ''; notice.value = ''
  try {
    if (!captured.value) {
      if (!file.value) throw new Error('Choose an exact SBOM file.')
      const input = object(metadata.value)
      if (input.expected_authority !== props.state || input.expected_configuration !== configuration.value) throw new Error('Import metadata must retain the loaded inventory and configuration pins.')
      if (typeof input.source !== 'string' || !input.source.trim()) throw new Error('Declare the observation source in import metadata.')
      captured.value = { kind: 'import', endpoint: `${path()}/observation-files`, metadata: JSON.stringify({ ...input, request_id: crypto.randomUUID() }), file: file.value }
    }
    const input = captured.value
    if (input.kind !== 'import') return
    attempted.value = true
    const body = new FormData(); body.set('metadata', input.metadata); body.set('file', input.file, input.file.name)
    const receipt = await knowledgeApi<{ committed: boolean; projection?: string }>(input.endpoint, { method: 'POST', body })
    if (current !== generation) return
    if (receipt.committed !== true) throw new Error('Import outcome uncertain.')
    if (receipt.projection !== 'current') { notice.value = 'Observation committed; projection pending. Exact upload retained for receipt retry.'; return }
    clearCapture(); file.value = null; fileKey.value++; metadata.value = initialMetadata.value; selection.value = initialSelection.value; loaded.value = false
    notice.value = 'Observation retained. Product inventory and approvals were not changed.'; emit('refresh')
  } catch (err) { if (current === generation) error.value = `${err instanceof Error ? err.message : 'Observation import unavailable'}. Captured upload retained when present; retry identically or discard.` }
  finally { if (current === generation) busy.value = false }
}
async function inspect() {
  if (blocked.value || !writable.value || importDirty.value || (captured.value && captured.value.kind !== 'selection')) return
  const current = ++generation; busy.value = true; error.value = ''; notice.value = ''
  try {
    if (!captured.value) {
      const input = object(selection.value)
      if (input.expected !== props.state || input.expected_configuration !== configuration.value) throw new Error('Selection must retain the loaded inventory and configuration pins.')
      if ('preview_digest' in input || 'request_id' in input) throw new Error('Request and preview IDs are captured by this workflow; remove them from the draft.')
      captured.value = { kind: 'selection', endpoint: `${path()}/observation-selection`, input: { ...input, request_id: crypto.randomUUID() } }
    }
    const input = captured.value
    if (input.kind !== 'selection' || input.applyBody) return
    const result = await knowledgeApi<Preview>(`${input.endpoint}/preview`, { method: 'POST', body: JSON.stringify(input.input) })
    if (current !== generation) return
    if (result.project_id !== props.project || result.version !== props.version || result.expected !== input.input.expected || result.configuration !== input.input.expected_configuration || result.human_decisions_changed !== false || !/^[a-f0-9]{64}$/.test(result.preview_digest)) throw new Error('Preview does not describe the captured source selection and pins.')
    preview.value = result; confirmed.value = false
  } catch (err) { if (current === generation) error.value = `${err instanceof Error ? err.message : 'Preview unavailable'}. Captured selection retained.` }
  finally { if (current === generation) busy.value = false }
}
async function publish() {
  if (blocked.value || !writable.value || captured.value?.kind !== 'selection' || !preview.value || !confirmed.value) return
  if (!attempted.value && captured.value.input.expected !== props.state) { error.value = 'Inventory changed. Discard and review a fresh selection.'; return }
  const current = ++generation, input = captured.value; busy.value = true; attempted.value = true; error.value = ''
  input.applyBody ||= JSON.stringify({ ...input.input, preview_digest: preview.value.preview_digest })
  try {
    const receipt = await knowledgeApi<{ committed: boolean; projection?: string }>(input.endpoint, { method: 'POST', body: input.applyBody })
    if (current !== generation) return
    if (receipt.committed !== true) throw new Error('Publication outcome uncertain.')
    if (receipt.projection !== 'current') { notice.value = 'Selection committed; projection pending. Exact request retained for receipt retry.'; return }
    clearCapture(); file.value = null; fileKey.value++; metadata.value = initialMetadata.value; selection.value = initialSelection.value; loaded.value = false
    notice.value = 'Observation selection committed. No human assessment or approval was applied.'; emit('refresh')
  } catch (err) { if (current === generation) error.value = `${err instanceof Error ? err.message : 'Publication unavailable'}. Exact apply request and preview retained; retry identically or discard.` }
  finally { if (current === generation) busy.value = false }
}
function discard() { if (busy.value) return; ++generation; clearCapture(); file.value = null; fileKey.value++; metadata.value = initialMetadata.value; selection.value = initialSelection.value; error.value = ''; notice.value = '' }
onBeforeUnmount(() => { ++generation; emit('locked', false) })
</script>
<template>
  <TaskSurface class="knowledge-observations" @active="toggle" title="SBOM observations and reconciliation">
    <section aria-label="SBOM observations and reconciliation">
      <p class="hint">CI/user metadata binds observations to a delivery part/build. Inventory additions and relationships require explicit selection; source claims never become approvals.</p>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
      <button :disabled="blocked || !!captured || dirty" @click="load()">Refresh observation sources</button>
      <p v-if="sources">{{ sources.total }} source bindings</p>
      <ul><li v-for="item in sources?.items || []" :key="`${item.part_id}:${item.source}`">{{ item.source }} · {{ item.part_id || 'whole product' }} · build {{ item.baseline?.build_number ?? item.build_number ?? 'unknown' }}
        <button v-if="writable" :disabled="blocked || !!captured || importDirty" @click="select(item)">Select source {{ item.source }}</button>
        <details><summary>Source provenance and pins</summary><pre>{{ JSON.stringify(item, null, 2) }}</pre></details>
      </li></ul>
      <button v-if="sources?.next_offset !== null && sources?.next_offset !== undefined" :disabled="blocked || !!captured || importDirty" @click="load(sources.next_offset)">Next observation sources</button>
      <template v-if="(loaded && writable) || captured?.kind === 'import'">
        <details><summary>Import an observation file</summary>
          <label>Observation SBOM file<input :key="fileKey" type="file" :disabled="blocked || !!captured || selectionDirty" @change="choose"></label>
          <label>Observation import metadata JSON<textarea v-model="metadata" rows="10" spellcheck="false" :disabled="blocked || !!captured || selectionDirty" /></label>
          <button :disabled="blocked || selectionDirty || (captured?.kind === 'selection')" @click="importFile">{{ captured?.kind === 'import' ? 'Retry identical observation upload' : 'Import observation file' }}</button>
        </details>
        <details open><summary>Review selected observations</summary>
          <label>Observation selection JSON<textarea v-model="selection" rows="8" spellcheck="false" :disabled="blocked || !!captured || importDirty" /></label>
          <p class="hint">Use source-local refs in accepted_components/accepted_relationships. Explain adoption or removal in reason/removal_reason. Matching and conflict decisions run on the server.</p>
          <button v-if="!preview" :disabled="blocked || importDirty || captured?.kind === 'import'" @click="inspect">{{ captured ? 'Retry identical observation preview' : 'Preview observation selection' }}</button>
        </details>
      </template>
      <section v-if="preview" aria-label="Observation reconciliation preview">
        <p>No human decisions changed. Review all conflicts and proposed inventory/topology changes before publication.</p>
        <article v-for="item in preview.reports" :key="`${item.part_id}:${item.source}`"><strong>{{ item.source }} · {{ item.part_id || 'whole product' }}</strong>
          <dl><template v-for="(value, key) in item.report.summary || {}" :key="key"><dt>{{ key }}</dt><dd>{{ value }}</dd></template></dl>
          <details><summary>Conflict and proposal samples</summary><p v-if="item.bounded_sample" class="hint">Lists are bounded samples; summary counts and preview digest cover the complete report.</p><pre>{{ JSON.stringify(item.report, null, 2) }}</pre></details>
        </article>
        <details><summary>Exact publication pins</summary><pre>{{ JSON.stringify({ expected: preview.expected, configuration: preview.configuration, preview_digest: preview.preview_digest }, null, 2) }}</pre></details>
        <label class="confirmation"><input v-model="confirmed" type="checkbox" :disabled="blocked">I reviewed the observation selection and adoption reasons</label>
        <button :disabled="blocked || !confirmed" @click="publish">{{ attempted ? 'Retry identical observation publication' : 'Publish observation selection' }}</button>
      </section>
      <button v-if="captured || dirty" :disabled="busy" @click="discard">Discard observation changes</button>
    </section>
  </TaskSurface>
</template>
<style scoped>
.knowledge-observations{margin-block:1rem}summary{cursor:pointer}.hint{font-size:.875rem;opacity:.8}label{display:grid;gap:.35rem;margin-block:.65rem}.confirmation{display:flex;align-items:center}textarea{width:100%;box-sizing:border-box;font-family:monospace;resize:vertical}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:24rem;overflow:auto}button{margin:.4rem .5rem .4rem 0}li{overflow-wrap:anywhere}dl{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.25rem 1rem;font-size:.875rem;max-width:36rem}dd{margin:0}
</style>
