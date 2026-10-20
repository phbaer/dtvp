<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { API_PREFIX } from '../apiContract'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError, send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
type Payload = { document_id: string; title: string; purpose: string; rationale: string; renderer: { name: string; version: string; source_revision?: string | null }; issued_receipt_sha: string; artifact_sha256: string; configuration_sha256: string; filename: string; media_type: string; source_state: string; bundle_sha256: string; actor_id: string }
type Record = { revision: string; stage: string; payload: Payload }
type Row = { document_id: string; status: string; document: Record; approved_document: Record | null; source_current: boolean; approved_source_current: boolean; pending: boolean; capabilities: string[]; review?: { rationale: string; action: string; review_revision: string } | null }
type Registry = { items: Row[]; total: number; next_offset: number | null; capabilities: string[] }
type Issuance = { receipt_sha256: string; source_state: string; files: { [name: string]: { sha256: string; url: string } } }
const props = defineProps<{ project: string; version: string; state: string }>()
const emit = defineEmits<{ changed: [] }>()
const expanded = ref(false), busy = ref(false), result = ref<Registry | null>(null), selectedId = ref(''), editing = ref(false)
const error = ref(''), notice = ref(''), reviewRationale = ref(''), acknowledge = ref(false), file = ref<File | null>(null), fileInput = ref<HTMLInputElement | null>(null)
const offset = ref(0), previous = ref<number[]>([]), issued = ref<Issuance | null>(null)
const empty = () => ({ document_id: crypto.randomUUID() as string, title: '', purpose: 'architecture', rationale: '', issued_receipt_sha: '', renderer_name: '', renderer_version: '', renderer_revision: '', configuration: '' })
const form = ref(empty()), expectedRevision = ref<string | null>(null)
const selected = computed(() => result.value?.items.find(row => row.document_id === selectedId.value))
const can = (cap: string) => result.value?.capabilities.includes(cap)
const human = (value: string) => value.replaceAll('_', ' ')
const root = computed(() => `/projects/${encodeURIComponent(props.project)}`)
const artifact = (sha: string) => `${API_PREFIX}${root.value}/states/${encodeURIComponent(props.state)}/artifacts/${encodeURIComponent(sha)}`
let sequence = 0, pending: { signature: string; requestId: string } | null = null
function reset() { form.value = empty(); expectedRevision.value = null; file.value = null; if (fileInput.value) fileInput.value.value = ''; issued.value = null; pending = null }
function create() { reset(); selectedId.value = ''; editing.value = true; error.value = ''; notice.value = '' }
function open(row: Row) { selectedId.value = row.document_id; editing.value = false; acknowledge.value = false; reviewRationale.value = ''; error.value = ''; notice.value = ''; pending = null }
function revise() {
  const row = selected.value; if (!row?.capabilities.includes('revise')) return
  const p = row.document.payload; reset(); expectedRevision.value = row.document.revision
  form.value = { document_id: p.document_id, title: p.title, purpose: p.purpose, rationale: '', issued_receipt_sha: p.issued_receipt_sha, renderer_name: p.renderer.name, renderer_version: p.renderer.version, renderer_revision: p.renderer.source_revision || '', configuration: '' }
  editing.value = true
}
async function load(page = 0) {
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Registry>(`${root.value}/states/${encodeURIComponent(props.state)}/documents?offset=${page}&limit=20`)
    if (current !== sequence) return false
    result.value = data; offset.value = page; return true
  } catch (err) { if (current === sequence) error.value = err instanceof Error ? err.message : 'Document registry unavailable'; return false }
  finally { if (current === sequence) busy.value = false }
}
function toggle(open: boolean) { expanded.value = open; if (expanded.value && !result.value && !busy.value) void load() }
async function paginate(next: boolean) {
  const page = next ? result.value?.next_offset : previous.value.at(-1); if (page == null) return
  const prior = offset.value
  if (await load(page)) { editing.value = false; selectedId.value = ''; if (next) previous.value.push(prior); else previous.value.pop() }
}
function report(err: unknown) { error.value = err instanceof ApiError && err.status === 409 ? 'Document or baseline changed. Refresh the baseline explicitly; your input is retained.' : err instanceof Error ? err.message : 'Document operation failed' }
async function issue() {
  if (busy.value) return
  const current = ++sequence; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Issuance>(`${root.value}/states/${encodeURIComponent(props.state)}/exports/bundle`, send({}))
    if (current !== sequence) return
    issued.value = data; form.value.issued_receipt_sha = data.receipt_sha256
    notice.value = 'Exact input bundle issued. Render it externally, then register the resulting bytes.'
  } catch (err) { if (current === sequence) report(err) }
  finally { if (current === sequence) busy.value = false }
}
async function mutate(action: 'draft' | 'submit' | 'approve' | 'request_changes') {
  if (busy.value) return
  const current = ++sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    const reviewing = action === 'approve' || action === 'request_changes'
    let body: object, upload: File | null = null, fileHash = ''
    if (reviewing) {
      const row = selected.value; if (!row) return
      body = { expected: props.state, document_id: row.document_id, revision: row.document.revision, action, rationale: reviewRationale.value, acknowledge_historical: acknowledge.value }
    } else {
      upload = file.value; if (!upload) throw new Error('Select the exact generated document file.')
      if (upload.size > 32 * 1024 * 1024) throw new Error('Document exceeds the 32 MiB limit.')
      const configuration: unknown = JSON.parse(form.value.configuration)
      if (!configuration || typeof configuration !== 'object' || Array.isArray(configuration)) throw new Error('Renderer configuration must be a JSON object.')
      const hash = await crypto.subtle.digest('SHA-256', await upload.arrayBuffer())
      fileHash = Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('')
      body = { expected: props.state, expected_revision: expectedRevision.value, document_id: form.value.document_id, issued_receipt_sha: form.value.issued_receipt_sha, renderer: { name: form.value.renderer_name, version: form.value.renderer_version, source_revision: form.value.renderer_revision || null }, configuration, title: form.value.title, purpose: form.value.purpose, rationale: form.value.rationale, filename: upload.name, media_type: upload.type || 'application/octet-stream' }
    }
    if (current !== sequence) return
    const endpoint = `${root.value}/versions/${encodeURIComponent(props.version)}/documents/${reviewing ? 'reviews' : action}`
    const signature = JSON.stringify({ endpoint, body, fileHash })
    if (pending?.signature !== signature) pending = { signature, requestId: crypto.randomUUID() }
    const metadata = { ...body, request_id: pending.requestId }
    let options: RequestInit
    if (upload) { const data = new FormData(); data.append('metadata', JSON.stringify(metadata)); data.append('file', upload); options = { method: 'POST', body: data } }
    else options = send(metadata)
    await knowledgeApi(endpoint, options)
    if (current !== sequence) return
    pending = null; editing.value = false; file.value = null
    notice.value = reviewing ? (action === 'approve' ? 'Exact document revision approved.' : 'Document changes requested.') : action === 'draft' ? 'Document draft registered.' : 'Document submitted for independent review.'
    emit('changed')
  } catch (err) { if (current === sequence) report(err) }
  finally { if (current === sequence) busy.value = false }
}
watch(() => [props.project, props.version, props.state], (value, prior) => {
  ++sequence; busy.value = false; result.value = null; offset.value = 0; previous.value = []; acknowledge.value = false
  if (value[0] !== prior[0] || value[1] !== prior[1]) { reset(); selectedId.value = ''; editing.value = false; notice.value = ''; error.value = '' }
  if (expanded.value) void load()
})
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <TaskSurface class="knowledge-documents" @active="toggle" title="Controlled documents">
    <section aria-label="Controlled document registry" :aria-busy="busy">
      <p class="hint">Register externally rendered architecture, SOUP or license documents against an exact issued input bundle. Approval covers these bytes and inputs; it does not certify correctness, compliance or the release.</p>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
      <template v-if="result">
        <div class="actions"><span>{{ result.total }} documents in this pinned version state</span><button type="button" :disabled="busy" @click="load(offset)">Refresh document registry</button><button v-if="can('documentary_assess')" type="button" :disabled="busy" @click="create">Register document</button></div>
        <div class="document-list"><button v-for="row in result.items" :key="row.document_id" :disabled="busy" :aria-pressed="selectedId === row.document_id" @click="open(row)"><strong>{{ row.document.payload.title }}</strong><span>{{ human(row.status) }} · {{ row.source_current ? 'Current material inputs' : 'Historical inputs' }}<template v-if="row.pending"> · Pending revision; approved bytes retained</template></span></button></div>
        <nav aria-label="Document pages"><button type="button" :disabled="busy || !previous.length" @click="paginate(false)">Previous documents</button><button type="button" :disabled="busy || result.next_offset == null" @click="paginate(true)">Next documents</button></nav>
        <article v-if="selected" aria-label="Controlled document detail">
          <h3>{{ selected.document.payload.title }}</h3><p>Current recorded revision: {{ human(selected.document.stage) }} · {{ selected.document.payload.purpose }}</p>
          <p class="rationale">{{ selected.document.payload.rationale }}</p><p class="hint">Renderer: {{ selected.document.payload.renderer.name }} {{ selected.document.payload.renderer.version }}. Identity/configuration are producer declarations, not verified execution.</p>
          <a :href="artifact(selected.document.payload.artifact_sha256)" download>Download exact recorded document</a>
          <details><summary>Input and artifact pins</summary><dl><dt>Document revision</dt><dd>{{ selected.document.revision }}</dd><dt>Artifact SHA-256</dt><dd>{{ selected.document.payload.artifact_sha256 }}</dd><dt>Source state</dt><dd>{{ selected.document.payload.source_state }}</dd><dt>Issued receipt</dt><dd>{{ selected.document.payload.issued_receipt_sha }}</dd><dt>Bundle SHA-256</dt><dd>{{ selected.document.payload.bundle_sha256 }}</dd></dl><a :href="artifact(selected.document.payload.configuration_sha256)" download>Download exact renderer configuration</a></details>
          <details v-if="selected.approved_document"><summary>Retained approved document</summary><p>{{ selected.approved_source_current ? 'Current material inputs' : 'Historical inputs' }} · Approval is pinned to revision {{ selected.approved_document.revision }}.</p><p class="rationale">{{ selected.approved_document.payload.rationale }}</p><a :href="artifact(selected.approved_document.payload.artifact_sha256)" download>Download exact approved document</a></details>
          <p v-if="selected.review" class="rationale">{{ human(selected.review.action) }}: {{ selected.review.rationale }}</p>
          <button v-if="selected.capabilities.includes('revise')" type="button" :disabled="busy" @click="revise">Register replacement revision</button>
          <form v-if="selected.capabilities.includes('review')" aria-label="Independent documentary review" @submit.prevent="mutate('approve')">
            <p>Review exact submitted bytes and the input pins. Authors cannot review their own documents.</p>
            <label>Document review rationale<textarea v-model="reviewRationale" required maxlength="6000" /></label>
            <label v-if="!selected.source_current" class="confirm"><input v-model="acknowledge" type="checkbox">I explicitly acknowledge this document uses historical inputs.</label>
            <div class="actions"><button type="submit" :disabled="busy || !reviewRationale.trim() || (!selected.source_current && !acknowledge)">Approve document revision</button><button type="button" :disabled="busy || !reviewRationale.trim() || (!selected.source_current && !acknowledge)" @click="mutate('request_changes')">Request document changes</button></div>
          </form>
        </article>
        <form v-if="editing && can('documentary_assess')" aria-label="Document registration" @submit.prevent="mutate('submit')">
          <h3>{{ expectedRevision ? 'Replacement document revision' : 'New document' }}</h3>
          <label>Document title<input v-model="form.title" required maxlength="1000"></label><label>Document purpose<select v-model="form.purpose"><option value="architecture">Architecture</option><option value="soup">SOUP</option><option value="license">License</option><option value="combined">Combined</option></select></label>
          <label>Issued input receipt SHA-256<input v-model="form.issued_receipt_sha" required pattern="[0-9a-f]{64}"></label><button type="button" :disabled="busy" @click="issue">Issue input bundle for this state</button>
          <ul v-if="issued"><li v-for="(item, name) in issued.files" :key="name"><a :href="`${API_PREFIX}${root}/issued-exports/${encodeURIComponent(issued.receipt_sha256)}/files/${encodeURIComponent(name)}`" download>Download issued {{ name }}</a> · <code>{{ item.sha256 }}</code></li></ul>
          <div class="renderer"><label>Renderer name<input v-model="form.renderer_name" required maxlength="200"></label><label>Renderer version<input v-model="form.renderer_version" required maxlength="200"></label></div>
          <details><summary>Renderer source revision</summary><label>Declared renderer source revision<input v-model="form.renderer_revision" maxlength="1000"></label></details>
          <label>Exact renderer configuration (JSON object)<textarea v-model="form.configuration" required spellcheck="false" placeholder='{"template": "reviewed-template"}' /></label>
          <label>Generated document file<input ref="fileInput" type="file" required @change="file = ($event.target as HTMLInputElement).files?.[0] || null"></label>
          <label>Document rationale<textarea v-model="form.rationale" required maxlength="6000" /></label>
          <div class="actions"><button type="button" :disabled="busy" @click="mutate('draft')">Save document draft</button><button type="submit" :disabled="busy">Submit document for review</button></div>
        </form>
      </template>
      <button v-if="error && !result" type="button" :disabled="busy" @click="load()">Retry document registry</button>
      <button v-if="error" type="button" :disabled="busy" @click="emit('changed')">Refresh document baseline, retain input</button>
    </section>
  </TaskSurface>
</template>
<style scoped>
.knowledge-documents { margin-block: .75rem; padding: .8rem; border: 1px solid var(--line); border-radius: .65rem; min-width: 0; }
summary { cursor: pointer; font-weight: 600; } section, article { min-width: 0; overflow-wrap: anywhere; } .hint { font-size: .85rem; color: var(--muted); }
.actions, nav { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; margin-block: .7rem; }.document-list { display: grid; gap: .4rem; }.document-list button { text-align: left; display: grid; gap: .3rem; }
article, form { margin-top: .8rem; padding-top: .5rem; border-top: 1px solid var(--line); } label { display: grid; gap: .3rem; margin-block: .6rem; } input, textarea, select { width: 100%; min-width: 0; box-sizing: border-box; } textarea { min-height: 4rem; }.renderer { display: grid; grid-template-columns: repeat(auto-fit,minmax(170px,1fr)); gap: .7rem; }.confirm { display: flex; align-items: flex-start; }.confirm input { width: auto; } dd { margin-left: 0; overflow-wrap: anywhere; }.rationale { white-space: pre-wrap; } code { font-size: .75rem; overflow-wrap: anywhere; }
</style>
