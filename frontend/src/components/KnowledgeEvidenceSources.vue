<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import { send } from '../api'
type Pins = { expected_evidence: string | null; expected_versions: Record<string, string> }
type Document = { artifact_sha: string; active: boolean; source: string; source_revision: number; representation: string; identity_basis: string; superseded_by?: string; withdrawal?: { reason: string }; document: { format: string; document_id: string | null; publisher: string | null; revision: unknown; losses: unknown[] } }
type Registry = { evidence_state: string | null; versions: Record<string, string>; documents: Document[]; total: number; next_offset: number | null; capabilities: string[] }
type Conformance = { profile: string; valid: boolean; schema_validation: string; signature_verification: string; diagnostics: { path: string; code: string }[]; warnings: { path: string; code: string }[]; limitations: string[] }
type Preview = Pins & { conformance?: Conformance; artifact_sha: string; preview_digest: string; source: string; source_revision: number; active: boolean; document: Document['document']; trust: string; limitations: string[]; application: Record<string, { application: { selection?: string; matched: number; unresolved: number; statements: unknown[] }; unmatched: unknown[]; contradictions: unknown[]; would_apply: unknown[] }> }
type Metadata = Pins & { request_id: string; source: string; revision: number; validation_profile?: string }
const props = defineProps<{ project: string; state?: string }>()
const emit = defineEmits<{ changed: [] }>()
const expanded = ref(false), busy = ref(false), error = ref(''), notice = ref(''), registry = ref<Registry | null>(null)
const offset = ref(0), previous = ref<number[]>([]), source = ref(''), ordinal = ref(''), file = ref<File | null>(null), fileInput = ref<HTMLInputElement | null>(null)
const upload = ref<{ metadata: Metadata; file: File } | null>(null), candidate = ref<Preview | null>(null), importTried = ref(false), imported = ref(false)
const validationProfile = ref('')
const validationProfiles = ['dtvp-cyclonedx-1.5-exact/1', 'dtvp-cyclonedx-1.6-exact/1', 'dtvp-openvex-0.2.0-exact/1', 'dtvp-csaf-2.0-vex-exact/1']
const selected = ref(''), retained = ref<Preview | null>(null), withdrawal = ref(''), reason = ref(''), withdrawalAttempt = ref<(Pins & { request_id: string; artifact_sha: string; reason: string }) | null>(null)
let sequence = 0
const root = () => `/projects/${encodeURIComponent(props.project)}/evidence`
const can = (action: string) => registry.value?.capabilities.includes(action)
const pins = (): Pins => ({ expected_evidence: registry.value!.evidence_state, expected_versions: { ...registry.value!.versions } })
const pinsKey = (value: Pins) => JSON.stringify([value.expected_evidence, Object.entries(value.expected_versions).sort()])
const staleUpload = computed(() => Boolean(upload.value && registry.value && (pinsKey(upload.value.metadata) !== pinsKey(pins()) || Boolean(props.state && !Object.values(upload.value.metadata.expected_versions).includes(props.state)))))
function fail(value: unknown) { error.value = value instanceof Error ? value.message : 'Evidence request failed' }
function bytesOptions(value: { metadata: Metadata; file: File }) { const body = new FormData(); body.append('metadata', JSON.stringify(value.metadata)); body.append('file', value.file); return { method: 'POST', body } }
async function load(page = 0, refresh = false) {
  if (busy.value) return false
  const current = sequence; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<Registry>(`${root()}?offset=${page}&limit=20`)
    if (current !== sequence) return false
    if (!refresh && registry.value && pinsKey({ expected_evidence: result.evidence_state, expected_versions: result.versions }) !== pinsKey(pins())) throw new Error('Evidence or version selection changed. Refresh the registry explicitly; frozen requests are retained.')
    registry.value = result; offset.value = page
    if (refresh) { previous.value = []; retained.value = null; selected.value = '' }
    return true
  } catch (err) { if (current === sequence) fail(err); return false }
  finally { if (current === sequence) busy.value = false }
}
function toggle(event: Event) { expanded.value = (event.currentTarget as HTMLDetailsElement).open; if (expanded.value && !registry.value) void load() }
async function page(next: boolean) { const target = next ? registry.value?.next_offset : previous.value.at(-1); if (target == null) return; const prior = offset.value; if (await load(target)) { if (next) previous.value.push(prior); else previous.value.pop() } }
function editUpload() { upload.value = null; candidate.value = null; importTried.value = false; imported.value = false; error.value = ''; notice.value = '' }
async function previewFile() {
  if (busy.value || !registry.value || !can('import') || withdrawalAttempt.value) return
  const current = sequence; busy.value = true; error.value = ''; notice.value = ''
  try {
    if (!upload.value) {
      if (!file.value) throw new Error('Select a supported JSON evidence file.')
      if (file.value.size > 32 * 1024 * 1024) throw new Error('Evidence file exceeds 32 MiB.')
      const revision = Number(ordinal.value)
      if (!/^\d+$/.test(ordinal.value) || !Number.isSafeInteger(revision)) throw new Error('Producer ordinal must be a nonnegative safe integer.')
      if (!source.value.trim()) throw new Error('An attributed source is required.')
      const original = file.value, bytes = await original.arrayBuffer()
      if (current !== sequence) return
      const frozen = new File([bytes], original.name, { type: original.type || 'application/json' })
      file.value = frozen; upload.value = { metadata: { ...pins(), request_id: crypto.randomUUID(), source: source.value.trim(), revision, ...(validationProfile.value ? { validation_profile: validationProfile.value } : {}) }, file: frozen }
    }
    const frozen = upload.value
    const result = await knowledgeApi<Preview>(`${root()}/files/preview`, bytesOptions(frozen))
    if (!globalThis.crypto?.subtle) throw new Error('File integrity verification requires HTTPS or localhost.')
    const hash = await crypto.subtle.digest('SHA-256', await frozen.file.arrayBuffer())
    if (current !== sequence) return
    const sha = Array.from(new Uint8Array(hash), value => value.toString(16).padStart(2, '0')).join('')
    if (result.artifact_sha !== sha || pinsKey(result) !== pinsKey(frozen.metadata) || result.source !== frozen.metadata.source || result.source_revision !== frozen.metadata.revision) throw new Error('Evidence preview differs from the frozen bytes or attribution/pins.')
    if (frozen.metadata.validation_profile && (result.conformance?.profile !== frozen.metadata.validation_profile || result.conformance.valid !== true)) throw new Error('Conformance preview differs from the frozen declared profile.')
    candidate.value = result
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
async function importFile() {
  if (busy.value || !upload.value || !candidate.value || imported.value || withdrawalAttempt.value || !can('import')) return
  const current = sequence; busy.value = true; error.value = ''; notice.value = ''; importTried.value = true
  try {
    await knowledgeApi(`${root()}/files`, bytesOptions(upload.value))
    if (current !== sequence) return
    imported.value = true; notice.value = 'Evidence imported as unverified source assertions. No human assessment or approval was created.'; emit('changed')
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
  if (current === sequence && imported.value) await load(0, true)
}
async function inspect(row: Document) {
  if (busy.value || !registry.value) return
  const current = sequence; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<Preview>(`${root()}/${encodeURIComponent(row.artifact_sha)}/preview`, send(pins()))
    if (current === sequence) { retained.value = result; selected.value = row.artifact_sha }
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
}
function chooseWithdrawal(row: Document) { withdrawal.value = row.artifact_sha; reason.value = ''; error.value = '' }
async function withdraw() {
  if (busy.value || !registry.value || !can('withdraw') || (importTried.value && !imported.value)) return
  const current = sequence; busy.value = true; error.value = ''; notice.value = ''; let succeeded = false
  try {
    if (!withdrawalAttempt.value) {
      if (!withdrawal.value || !reason.value.trim()) throw new Error('Select an active document and give a meaningful withdrawal reason.')
      withdrawalAttempt.value = { ...pins(), request_id: crypto.randomUUID(), artifact_sha: withdrawal.value, reason: reason.value }
    }
    await knowledgeApi(`${root()}/withdrawals`, send(withdrawalAttempt.value))
    if (current !== sequence) return
    succeeded = true; withdrawalAttempt.value = null; withdrawal.value = ''; reason.value = ''; notice.value = 'Evidence withdrawn from current application. Original bytes and historical assessments remain retained.'; emit('changed')
  } catch (err) { if (current === sequence) fail(err) }
  finally { if (current === sequence) busy.value = false }
  if (current === sequence && succeeded) await load(0, true)
}
const download = (row: Document) => `/api/v3${root()}/artifacts/${encodeURIComponent(row.artifact_sha)}?expected_evidence=${encodeURIComponent(registry.value!.evidence_state || '')}`
watch(() => props.project, () => { ++sequence; busy.value = false; registry.value = null; editUpload(); selected.value = ''; retained.value = null; withdrawal.value = ''; reason.value = ''; withdrawalAttempt.value = null; source.value = ''; ordinal.value = ''; validationProfile.value = ''; file.value = null; if (fileInput.value) fileInput.value.value = ''; previous.value = []; offset.value = 0; if (expanded.value) void load() })
onBeforeUnmount(() => { ++sequence })
</script>
<template>
  <details class="knowledge-evidence" @toggle="toggle"><summary>VDR, VEX and advisory evidence files</summary>
    <section aria-label="Evidence source files">
      <p class="hint">Supported JSON semantic subsets only: CycloneDX VDR/VEX, CSAF, OpenVEX and native advisory documents. Publisher/signature and context applicability remain unverified. Import never creates human approvals.</p>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
      <button type="button" :disabled="busy" @click="load(0, true)">Refresh evidence registry and pins</button>
      <template v-if="registry">
        <p>{{ registry.total }} retained evidence documents · current and inactive revisions</p>
        <details><summary>Selected evidence and product version pins</summary><pre>{{ JSON.stringify(pins(), null, 2) }}</pre></details>
        <form v-if="can('import')" aria-label="Preview evidence file" @submit.prevent="previewFile">
          <details><summary>Import a source evidence revision</summary><label>Attributed evidence source<input v-model="source" required maxlength="200" :disabled="busy || Boolean(upload) || Boolean(withdrawalAttempt)"></label><label>Producer revision ordinal<input v-model="ordinal" required inputmode="numeric" pattern="[0-9]+" :disabled="busy || Boolean(upload) || Boolean(withdrawalAttempt)"></label><label>Evidence JSON file<input ref="fileInput" type="file" required accept=".json,application/json" :disabled="busy || Boolean(upload) || Boolean(withdrawalAttempt)" @change="file = ($event.target as HTMLInputElement).files?.[0] || null"></label><p class="hint">Ordering is explicit for this source/publisher/document identity; arrival time is not authoritative. Files lacking a document ID use content identity and do not imply supersession.</p><details><summary>Supported-subset validation profile</summary><label>Evidence validation profile<select v-model="validationProfile" :disabled="busy || Boolean(upload) || Boolean(withdrawalAttempt)"><option value="">Existing semantic subset (default)</option><option v-for="profile in validationProfiles" :key="profile" :value="profile">{{ profile }}</option></select></label><p class="hint">Optional DTVP consumed-field contracts. They reject unsupported scopes; they do not establish full schema conformance, signature validity or publisher trust.</p></details><div class="actions"><button type="submit" :disabled="busy || !file || !source.trim() || !ordinal || Boolean(withdrawalAttempt)">Preview exact evidence bytes</button><button v-if="upload" type="button" :disabled="busy" @click="editUpload">Edit evidence request</button></div></details>
        </form>
        <section v-if="candidate" aria-label="Candidate evidence preview">
          <strong>Semantic scope preview only — source supersession and producer ordering are checked on import.</strong><p>{{ candidate.document.format }} · publisher {{ candidate.document.publisher || 'Unknown' }} · {{ candidate.document.document_id || 'No document ID; content identity only' }}</p><p v-for="text in candidate.limitations" :key="text" class="hint">{{ text }}</p>
<details v-if="candidate.conformance" aria-label="Evidence conformance report"><summary>DTVP supported-subset validation · {{ candidate.conformance.valid ? 'passed' : 'failed' }}</summary><p>{{ candidate.conformance.profile }} · signature verification: {{ candidate.conformance.signature_verification.replaceAll('_', ' ') }}</p><ul><li v-for="(item, index) in [...candidate.conformance.diagnostics, ...candidate.conformance.warnings]" :key="index">{{ item.path }} · {{ item.code.replaceAll('_', ' ') }}</li><li v-for="limit in candidate.conformance.limitations" :key="limit">{{ limit }}</li></ul></details>
          <p v-if="staleUpload" class="hint">Current evidence/version pins differ from this frozen preview. Retrying an uncertain import keeps its original request; edit and preview explicitly for a new operation.</p>
          <details><summary>Frozen evidence preview and input pins</summary><pre>{{ JSON.stringify({ metadata: upload?.metadata, preview: candidate }, null, 2) }}</pre></details>
          <p v-for="(item, version) in candidate.application" :key="version">{{ version }} · {{ item.application.matched }} matched occurrences · {{ item.application.unresolved }} unresolved statements · {{ item.contradictions.length }} reported contradictions</p>
          <details><summary>Unsupported-field losses</summary><pre>{{ JSON.stringify(candidate.document.losses, null, 2) }}</pre></details>
          <button v-if="!imported" type="button" :disabled="busy || Boolean(withdrawalAttempt) || (!importTried && staleUpload)" @click="importFile">{{ importTried ? 'Resend identical evidence import' : 'Import exact previewed evidence' }}</button>
        </section>
        <article v-for="row in registry.documents" :key="row.artifact_sha" :aria-label="`Evidence document ${row.artifact_sha}`"><strong>{{ row.document.document_id || 'Content-addressed document' }} · {{ row.active ? 'Active source selection' : 'Inactive historical selection' }}</strong><p>{{ row.document.format }} · {{ row.source }} · producer ordinal {{ row.source_revision }} · publisher {{ row.document.publisher || 'Unknown' }}</p><p v-if="row.superseded_by" class="hint">Superseded by {{ row.superseded_by }}</p><p v-if="row.withdrawal">Withdrawal: {{ row.withdrawal.reason }}</p><div class="actions"><a :href="download(row)" download>Download exact source bytes</a><button type="button" :disabled="busy" @click="inspect(row)">Inspect application and losses</button><button v-if="can('withdraw') && row.active" type="button" :disabled="busy || Boolean(withdrawalAttempt) || (importTried && !imported)" @click="chooseWithdrawal(row)">Prepare evidence withdrawal</button></div><details><summary>Original attribution, representation and losses</summary><pre>{{ JSON.stringify(row, null, 2) }}</pre></details>
          <section v-if="selected === row.artifact_sha && retained" aria-label="Retained evidence application"><p>{{ retained.active ? 'Active' : 'Inactive' }} · semantic application in the selected current version states; no historical approval is inferred.</p><p v-for="(item, version) in retained.application" :key="version">{{ version }} · {{ item.application.selection || 'Selected' }} · {{ item.application.matched }} matched occurrences · {{ item.application.unresolved }} unresolved statements</p><details><summary>Matched, unmatched, conflicting statements and losses</summary><pre>{{ JSON.stringify(retained, null, 2) }}</pre></details></section>
        </article>
        <form v-if="withdrawal && can('withdraw')" aria-label="Withdraw evidence selection" @submit.prevent="withdraw"><label>Evidence withdrawal reason<textarea v-model="reason" required maxlength="6000" :disabled="busy || Boolean(withdrawalAttempt)" /></label><p>Exact artifact {{ withdrawal }}. Withdrawal removes current application, preserving original bytes and past assessments.</p><details v-if="withdrawalAttempt"><summary>Frozen withdrawal request</summary><pre>{{ JSON.stringify(withdrawalAttempt, null, 2) }}</pre></details><div class="actions"><button :disabled="busy || !reason.trim() || (importTried && !imported)">{{ withdrawalAttempt ? 'Resend identical evidence withdrawal' : 'Withdraw selected evidence' }}</button><button v-if="withdrawalAttempt" type="button" :disabled="busy" @click="withdrawalAttempt = null">Edit evidence withdrawal request</button></div></form>
        <nav class="actions" aria-label="Evidence document pages"><button type="button" :disabled="busy || !previous.length" @click="page(false)">Previous evidence documents</button><button type="button" :disabled="busy || registry.next_offset == null" @click="page(true)">Next evidence documents</button></nav>
      </template>
    </section>
  </details>
</template>
<style scoped>
.knowledge-evidence { margin-block: .75rem; padding: .8rem; border: 1px solid var(--line); border-radius: .65rem; min-width: 0; } summary { cursor: pointer; font-weight: 600; } section, article, form { min-width: 0; overflow-wrap: anywhere; }.hint { font-size: .85rem; color: var(--muted); }.actions { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; margin-block: .6rem; } label { display: grid; gap: .3rem; margin-block: .7rem; } input, textarea, select { width: 100%; min-width: 0; box-sizing: border-box; }textarea { min-height: 4rem; } article { border-top: 1px solid var(--line); padding-block: .8rem; }pre { overflow-wrap: anywhere; white-space: pre-wrap; max-height: 19rem; overflow: auto; font-size: .75rem; }
</style>
