<script setup lang="ts">
import { API_PREFIX } from '../apiContract'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
import KnowledgeCpeCatalog from './KnowledgeCpeCatalog.vue'
type Source = { source: string; revision: string; occurred_at: string; artifact_sha256: string; records: number; losses: Record<string, number> }
type Input = { request_id: string; expected: string | null; kind: string; source: string; revision: string; occurred_at: string; reason: string; artifact_sha256: string; content_base64: string; acquisition?: Record<string, unknown> | null; preview_digest?: string }
type Preview = { preview_digest: string; policy_state: string | null; committed: false; source: Source; replaces: Source | null; limitations: string[] }
type Page = { policy_state: string; source: Source | null; items: unknown[]; total: number; next_offset: number | null; limitations: string[] }
const props = defineProps<{ project: string; policy: string | null; sources?: Record<string, Source>; canConfigure: boolean; disabled?: boolean }>()
const emit = defineEmits<{ locked: [boolean]; refresh: [] }>()
const catalogLocked = ref(false)
const kind = ref('dictionary'), source = ref(''), revision = ref(''), observed = ref(new Date().toISOString()), reason = ref('')
const mode = ref('offline'), keyword = ref('')
const refreshDraft = ref<{ endpoint: string; input: { request_id: string; expected: string | null; keyword: string; reason: string } } | null>(null)
const fileKey = ref(0)
const file = ref<File | null>(null), busy = ref(false), error = ref(''), notice = ref(''), confirmed = ref(false)
const captured = ref<{ endpoint: string; input: Input } | null>(null), preview = ref<Preview | null>(null), attempted = ref(false), committed = ref(false)
const historical = ref(''), pageKind = ref('dictionary'), pageSourceKind = ref('dictionary'), page = ref<Page | null>(null), pagePin = ref(''), pageOffset = ref(0)
let sequence = 0
const locked = computed(() => !committed.value && (busy.value || !!captured.value || !!file.value || !!source.value || !!revision.value || !!reason.value || !!keyword.value || !!refreshDraft.value))
watch(() => locked.value || catalogLocked.value, value => emit('locked', value), { immediate: true })
const blocked = computed(() => busy.value || catalogLocked.value || props.disabled === true)
const stale = computed(() => !!captured.value && captured.value.input.expected !== props.policy)
const path = () => `/projects/${encodeURIComponent(props.project)}/cpe/sources`
function choose(event: Event) { if (!captured.value && !blocked.value) file.value = (event.target as HTMLInputElement).files?.[0] || null }
function clear() {
  captured.value = null; preview.value = null; attempted.value = false; committed.value = false; confirmed.value = false
  refreshDraft.value = null; keyword.value = ''; file.value = null; fileKey.value++; source.value = ''; revision.value = ''; reason.value = ''; error.value = ''; notice.value = ''
}
function discard() { if (!busy.value) clear() }
async function inspect() {
  if (blocked.value || !props.canConfigure) return
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    let result: Preview
    if (!captured.value && mode.value === 'nvd') {
      if (!refreshDraft.value) {
        if (keyword.value.trim().length < 3 || !reason.value.trim()) throw new Error('Provide a scoped keyword of at least three characters and a replacement reason.')
        refreshDraft.value = { endpoint: path(), input: { request_id: crypto.randomUUID(), expected: props.policy, keyword: keyword.value.trim(), reason: reason.value } }
      }
      const draft = refreshDraft.value
      const response = await knowledgeApi<{ format: string; committed: false; source_input: Input; preview: Preview }>(`${draft.endpoint}/refresh`, send(draft.input))
      if (current !== sequence) return
      const input = response.source_input
      if (response.format !== 'dtvp.cpe-scoped-capture/1' || response.committed !== false || input.expected !== draft.input.expected || input.request_id !== draft.input.request_id || input.kind !== 'dictionary' || !input.acquisition || input.acquisition.keyword !== draft.input.keyword || !/^[0-9a-f]{64}$/.test(input.artifact_sha256) || input.content_base64.length > 4 * Math.ceil(2 * 1024 * 1024 / 3)) throw new Error('CPE capture does not match the requested scope and policy pin.')
      const bytes = Uint8Array.from(atob(input.content_base64), char => char.charCodeAt(0))
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), value => value.toString(16).padStart(2, '0')).join('')
      if (current !== sequence) return
      if (hash !== input.artifact_sha256) throw new Error('CPE capture bytes differ from their digest.')
      captured.value = { endpoint: draft.endpoint, input }; refreshDraft.value = null
      result = response.preview
    } else {
    if (!captured.value) {
      if (!file.value || file.value.size > 2 * 1024 * 1024) throw new Error('Choose a curated JSON dictionary or mapping CSV of at most 2 MiB.')
      if (!source.value.trim() || !revision.value.trim() || !reason.value.trim() || !/(Z|[+-]\d\d:\d\d)$/.test(observed.value)) throw new Error('Provide source, revision, reason and an observation time with timezone.')
      const expected = props.policy, endpoint = path()
      const bytes = new Uint8Array(await file.value.arrayBuffer())
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), value => value.toString(16).padStart(2, '0')).join('')
      let text = ''; for (let offset = 0; offset < bytes.length; offset += 32768) text += String.fromCharCode(...bytes.subarray(offset, offset + 32768))
      if (current !== sequence) return
      captured.value = { endpoint, input: { request_id: crypto.randomUUID(), expected, kind: kind.value, source: source.value, revision: revision.value, occurred_at: observed.value, reason: reason.value, artifact_sha256: hash, content_base64: btoa(text) } }
    }
    result = await knowledgeApi<Preview>(`${captured.value.endpoint}/preview`, send(captured.value.input))
    }
    if (current !== sequence) return
    if (result.committed !== false || result.policy_state !== captured.value.input.expected || result.source.artifact_sha256 !== captured.value.input.artifact_sha256) throw new Error('Source preview does not describe the captured bytes and policy pin.')
    preview.value = result; confirmed.value = false
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Source preview unavailable; captured input retained.' }
  finally { if (current === sequence) busy.value = false }
}
async function publish() {
  if (blocked.value || !captured.value || !preview.value || !confirmed.value || !props.canConfigure || (stale.value && !attempted.value)) return
  const current = ++sequence; busy.value = true; attempted.value = true; error.value = ''
  captured.value.input.preview_digest = preview.value.preview_digest
  try {
    const receipt = await knowledgeApi<{ committed: boolean; projection?: string }>(`${captured.value.endpoint}/apply`, send(captured.value.input))
    if (current !== sequence) return
    if (receipt.committed !== true) throw new Error('Publication uncertain. Retry the identical captured request.')
    committed.value = true
    if (receipt.projection !== 'current') { notice.value = 'Source committed; projection is pending. The exact request is retained for receipt refresh.'; return }
    clear(); notice.value = 'Offline source committed. No mapping rules, component identities or approvals were adopted.'; emit('refresh')
  } catch { if (current === sequence) error.value = 'Publication failed or conflicts. Retry the identical captured request, or explicitly discard it; refresh never repins it.' }
  finally { if (current === sequence) busy.value = false }
}
async function read(offset = 0, capturedPage = false) {
  if (busy.value) return
  const pin = capturedPage ? pagePin.value : historical.value.trim() || props.policy
  const selectedKind = capturedPage ? pageSourceKind.value : pageKind.value
  if (!pin || !/^[0-9a-f]{64}$/.test(pin)) { error.value = 'Choose an exact retained CPE policy SHA.'; return }
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<Page>(`${path()}/${pin}/${selectedKind}?offset=${offset}&limit=25`)
    if (current !== sequence) return
    if (result.policy_state !== pin) throw new Error('Historical source response changed its requested policy pin.')
    page.value = result; pagePin.value = pin; pageSourceKind.value = selectedKind; pageOffset.value = offset
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Retained source unavailable' }
  finally { if (current === sequence) busy.value = false }
}
onBeforeUnmount(() => { ++sequence; emit('locked', false) })
</script>
<template>
  <details class="cpe-sources" aria-label="Offline curated CPE sources">
    <summary>Offline curated sources</summary>
    <p class="hint">Up to 2,000 records; not a complete national dictionary. Source revisions are declared claims. Scoped NVD capture is optional and requires the enabled provider. No approval or vulnerability applicability is inferred.</p>
    <p v-for="(item, name) in sources || {}" :key="name">{{ name }}: {{ item.source }} · {{ item.revision }} · {{ item.records }} records</p>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <KnowledgeCpeCatalog :project="project" :disabled="busy || props.disabled || locked" @locked="catalogLocked = $event" />
    <form v-if="canConfigure" aria-label="Import offline CPE source" @submit.prevent="inspect">
      <fieldset :disabled="blocked || !!captured || !!refreshDraft">
        <label>Capture method<select v-model="mode"><option value="offline">Local source file</option><option value="nvd">Scoped official NVD query</option></select></label>
        <template v-if="mode === 'offline'">
        <label>Source kind<select v-model="kind"><option value="dictionary">Curated dictionary JSON</option><option value="mapping_history">Standalone mapping history CSV</option></select></label>
        <label>Exact source file<input :key="fileKey" type="file" @change="choose"></label>
        <label>Source attribution<input v-model="source" maxlength="200"></label><label>Declared source revision<input v-model="revision" maxlength="200"></label>
        <label>Observed at, with timezone<input v-model="observed"></label></template>
        <template v-else><label>NVD query keyword<input v-model="keyword" minlength="3" maxlength="200"></label><p class="hint">Captures the complete returned keyword subset, up to 2,000 records / 2 MiB. Narrow overly broad queries. Preview and publication stay separate; the replacement does not change reviewed mappings.</p></template>
        <label>Replacement reason<textarea v-model="reason" maxlength="2000" rows="2" /></label>
      </fieldset>
      <button v-if="!preview" :disabled="blocked">{{ captured ? 'Retry identical source preview' : mode === 'nvd' ? (refreshDraft ? 'Retry scoped NVD capture' : 'Capture scoped NVD source') : 'Preview offline source replacement' }}</button>
    </form>
    <section v-if="preview && captured" aria-label="Offline source replacement preview">
      <p>{{ preview.source.records }} records · {{ preview.source.source }} · {{ preview.source.revision }}</p>
      <p v-if="preview.replaces">Replaces {{ preview.replaces.source }} · {{ preview.replaces.revision }} ({{ preview.replaces.records }} records). Earlier captures remain retained.</p>
      <p v-if="stale" role="status">Current policy changed; this request retains its original policy pin.</p>
      <details><summary>Captured source pins and limitations</summary><code>{{ captured.input.artifact_sha256 }}</code><code>{{ captured.input.expected || 'No previous policy' }}</code><code>{{ preview.preview_digest }}</code><pre v-if="captured.input.acquisition">{{ JSON.stringify(captured.input.acquisition, null, 2) }}</pre><pre>{{ JSON.stringify(preview.source.losses, null, 2) }}</pre><ul><li v-for="item in preview.limitations" :key="item">{{ item }}</li></ul></details>
      <label><input v-model="confirmed" type="checkbox" :disabled="blocked || attempted"> I checked this source replacement and its disclosure to current and future project readers. Mapping history remains unverified.</label>
      <button :disabled="blocked || !confirmed || (stale && !attempted)" @click="publish">{{ committed ? 'Refresh committed source receipt' : attempted ? 'Retry identical source publication' : 'Publish previewed offline source' }}</button>
    </section>
    <button v-if="locked || captured" :disabled="busy" @click="discard">Discard offline source draft</button>
    <details><summary>Browse retained source claims</summary>
      <label>Retained policy SHA (empty uses current)<input v-model="historical" :disabled="busy" placeholder="Current CPE policy"></label>
      <label>Retained source kind<select v-model="pageKind" aria-label="Retained source kind" :disabled="busy"><option value="dictionary">Dictionary</option><option value="mapping_history">Mapping history</option></select></label>
      <button :disabled="busy" @click="read()">Read retained source</button>
      <template v-if="page"><p>{{ page.total }} retained records · {{ page.source?.source || 'No source captured' }} · {{ page.source?.revision }}</p><code>{{ pagePin }}</code><a v-if="page.source" :href="`${API_PREFIX}${path()}/${pagePin}/${pageSourceKind}/artifact`" download>Download exact retained source</a><pre>{{ JSON.stringify(page.items, null, 2) }}</pre><button :disabled="busy || pageOffset === 0" @click="read(Math.max(0, pageOffset - 25), true)">Previous source records</button><button :disabled="busy || page.next_offset === null" @click="read(page.next_offset || 0, true)">Next source records</button></template>
    </details>
  </details>
</template>
<style scoped>
.cpe-sources{margin-top:12px;min-width:0}.cpe-sources label{display:block;margin:8px 0}.cpe-sources input:not([type=checkbox]),.cpe-sources textarea,.cpe-sources select{max-width:100%;width:100%;box-sizing:border-box}.cpe-sources fieldset{border:0;padding:0;min-width:0}.cpe-sources code{display:block;overflow-wrap:anywhere;font-size:.75rem}.cpe-sources pre{max-height:250px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:.75rem}.cpe-sources button{margin:6px 8px 6px 0}.hint{color:var(--muted);font-size:.8rem}
</style>
