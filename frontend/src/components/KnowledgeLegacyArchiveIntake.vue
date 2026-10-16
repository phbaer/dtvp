<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Entry = { source_entry_id: string; entry_index: number; counts: Record<string, number>; losses: string[]; normalization: { status: string }; member_pins: Record<string, unknown> }
type Inspection = { archive_sha256: string; preview_digest: string; items: Entry[]; total: number; next_offset: number | null; limitations: string[] }
type Preview = { preview_digest: string; archive_sha256: string; source_entry_id: string; target: { project_id: string; version: string; source: string; build_number: number }; statistics: Record<string, number>; coverage: unknown; losses: string[]; disclosure: { audience: string; retains_submitted_sanitized_zip: boolean; retained_member_count: number }; limitations: string[] }
type Capture = { raw: Uint8Array<ArrayBuffer>; project: string; filename: string; policy: string | null; evidence: string | null }
type RequestCapture = { endpoint: string; header: string; version: string; applyHeader?: string }
const props = defineProps<{ project: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [value: boolean]; imported: [value: { version: string; part_id: null }] }>()
const file = ref<File | null>(null), inputKey = ref(0), busy = ref(false), error = ref(''), notice = ref('')
const captured = ref<Capture | null>(null), request = ref<RequestCapture | null>(null), report = ref<Inspection | null>(null), preview = ref<Preview | null>(null), selected = ref<Entry | null>(null), committed = ref(false)
const version = ref(''), source = ref(''), build = ref(''), observed = ref(''), reason = ref(''), sanitized = ref(false), reviewed = ref(false), disclosed = ref(false)
let generation = 0
const msg = (e: unknown) => e instanceof Error ? e.message : 'Archive request failed'
const ascii = (value: unknown) => { const result = JSON.stringify(value).replace(/[\u007f-\uffff]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`); if (result.length > 8192) throw new Error('Migration metadata exceeds the 8192-byte header limit.'); return result }
async function inspect(offset = 0) {
  if (busy.value || props.disabled || request.value || !captured.value && !file.value) return
  const current = generation; busy.value = true; error.value = ''; emit('locked', true)
  try {
    if (!captured.value) {
      const original = file.value!
      if (original.size > 64 * 1024 * 1024) throw new Error('ZIP exceeds the 64 MiB upload limit.')
      const raw = new Uint8Array(await original.arrayBuffer())
      const [policy, evidence] = await Promise.all([knowledgeApi<{ policy_state: string | null }>(`/projects/${encodeURIComponent(props.project)}/ownership`), knowledgeApi<{ evidence_state: string | null }>(`/projects/${encodeURIComponent(props.project)}/evidence`)])
      if (current !== generation) return
      captured.value = { raw, filename: original.name, project: props.project, policy: policy.policy_state, evidence: evidence.evidence_state }
    }
    const capture = captured.value!
    const data = await knowledgeApi<Inspection>(`/projects/${encodeURIComponent(capture.project)}/migration/v1-archive/preview?offset=${offset}&limit=20`, { method: 'POST', headers: { 'Content-Type': 'application/zip' }, body: capture.raw })
    if (current !== generation) return
    if (report.value && report.value.preview_digest !== data.preview_digest) throw new Error('Archive inspection changed; discard and inspect again.')
    report.value = data
  } catch (e) { if (current === generation) error.value = msg(e) }
  finally { if (current === generation) { busy.value = false; if (!captured.value) emit('locked', false) } }
}
async function prepare() {
  if (busy.value || props.disabled || !captured.value || !report.value || report.value.total !== 1 || !selected.value || !sanitized.value || !reviewed.value || !disclosed.value) return
  const current = generation; busy.value = true; error.value = ''
  try {
    if (!request.value) {
      const sequence = Number(build.value)
      if (!/^\d+$/.test(build.value) || !Number.isSafeInteger(sequence)) throw new Error('Source sequence requires a nonnegative safe integer.')
      if (!/(Z|[+-]\d{2}:\d{2})$/i.test(observed.value) || !Number.isFinite(Date.parse(observed.value))) throw new Error('Observed time requires an explicit timezone.')
      if (!version.value.trim() || !source.value.trim() || !reason.value.trim()) throw new Error('New version, source and review reason are required.')
      const header = ascii({ request_id: crypto.randomUUID(), archive_sha256: report.value.archive_sha256, source_entry_id: selected.value.source_entry_id, expected: null, expected_policy: captured.value.policy, expected_evidence: captured.value.evidence, source: source.value.trim(), build_number: sequence, occurred_at: observed.value, reason: reason.value, acknowledge_sanitized_export: true, acknowledge_operator_review: true, acknowledge_project_reader_disclosure: true })
      request.value = { endpoint: `/projects/${encodeURIComponent(captured.value.project)}/versions/${encodeURIComponent(version.value.trim())}/migration/v1-archive`, header, version: version.value.trim() }
    }
    const capture = request.value
    const data = await knowledgeApi<Preview>(`${capture.endpoint}/preview`, { method: 'POST', headers: { 'Content-Type': 'application/zip', 'X-DTVP-Migration': capture.header }, body: captured.value.raw })
    if (current !== generation) return
    if (data.archive_sha256 !== report.value.archive_sha256 || data.source_entry_id !== selected.value.source_entry_id || data.target.version !== capture.version) throw new Error('Preview does not match the captured selection.')
    capture.applyHeader = ascii({ ...JSON.parse(capture.header), preview_digest: data.preview_digest }); preview.value = data
  } catch (e) { if (current === generation) error.value = `${msg(e)} Captured bytes and metadata remain unchanged.` }
  finally { if (current === generation) busy.value = false }
}
async function apply() {
  if (busy.value || props.disabled || !request.value?.applyHeader || !captured.value || committed.value) return
  const current = generation, capture = request.value; busy.value = true; error.value = ''
  try {
    const result = await knowledgeApi<{ committed: boolean | null; projection?: string }>(`${capture.endpoint}/apply`, { method: 'POST', headers: { 'Content-Type': 'application/zip', 'X-DTVP-Migration': capture.applyHeader! }, body: captured.value.raw })
    if (current !== generation) return
    if (result.committed !== true) throw new Error('Publication uncertain; retry this exact captured request.')
    committed.value = true; emit('locked', false); notice.value = 'Reviewed archive published as historical source evidence. No native assessments, reviews or scores were adopted.'
    if (result.projection === 'pending') notice.value += ' Projection pending; publication is committed.'
    emit('imported', { version: capture.version, part_id: null })
  } catch (e) { if (current === generation) error.value = `${msg(e)} Exact ZIP, metadata, pins and request ID are retained; retry unchanged or explicitly discard.` }
  finally { if (current === generation) busy.value = false }
}
function discard() { if (busy.value) return; ++generation; captured.value = null; request.value = null; report.value = null; preview.value = null; selected.value = null; file.value = null; committed.value = false; sanitized.value = false; reviewed.value = false; disclosed.value = false; ++inputKey.value; error.value = ''; notice.value = ''; emit('locked', false) }
onBeforeUnmount(() => { ++generation; emit('locked', false) })
</script>
<template>
  <details class="legacy-archive-intake"><summary>Reviewed v1 archive</summary><section aria-label="Reviewed v1 archive intake">
    <p class="hint">Publish an operator-sanitized v1 export containing exactly one version. The submitted ZIP is retained for current and future project readers. Legacy identities, approval labels and scores remain historical evidence.</p>
    <fieldset :disabled="busy || !!captured || disabled"><label>Sanitized v1 ZIP<input :key="inputKey" type="file" accept=".zip,application/zip" @change="file = ($event.target as HTMLInputElement).files?.[0] || null"></label><button :disabled="!file" @click="inspect()">Inspect sanitized archive</button></fieldset>
    <p v-if="busy" role="status">Working…</p><p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <button v-if="captured && !report" :disabled="busy || disabled" @click="inspect()">Retry captured archive inspection</button>
    <template v-if="report"><p v-if="report.total !== 1" role="alert">Publication requires a single-version export. Sanitize and export exactly one version, then discard this capture and inspect the new ZIP.</p><p>{{ report.total }} source versions · {{ captured?.filename }}</p><p v-if="selected">Selected source entry {{ selected.entry_index }} · {{ selected.source_entry_id }}</p>
      <fieldset :disabled="busy || !!request || disabled"><label v-for="entry in report.items" :key="entry.source_entry_id"><input type="radio" name="legacy-source-entry" :checked="selected?.source_entry_id === entry.source_entry_id" @change="selected = entry">Source entry {{ entry.entry_index }} · {{ entry.normalization.status }} · {{ Object.entries(entry.counts).map(([key, count]) => `${key}: ${count}`).join(' · ') }}</label><button v-if="report.next_offset !== null" @click="inspect(report.next_offset)">More archive source versions</button></fieldset>
      <details v-if="selected"><summary>Source pins and known losses</summary><pre>{{ JSON.stringify(selected.member_pins, null, 2) }}</pre><ul><li v-for="loss in selected.losses" :key="loss">{{ loss.replaceAll('_', ' ') }}</li></ul></details>
      <form @submit.prevent="prepare"><fieldset :disabled="busy || !!request || disabled"><label>New archive target version<input v-model="version" required maxlength="200"></label><label>Archive source identity<input v-model="source" required maxlength="200"></label><label>Archive source sequence<input v-model="build" required inputmode="numeric"></label><label>Archive observed time<input v-model="observed" required placeholder="2026-10-16T10:00:00Z"></label><label>Operator review reason<textarea v-model="reason" required maxlength="2000" rows="2" /></label><label><input v-model="sanitized" type="checkbox" required>I sanitized the entire submitted ZIP, including its single exported version and every retained member.</label><label><input v-model="reviewed" type="checkbox" required>I reviewed this source selection, mapping coverage and known migration losses.</label><label><input v-model="disclosed" type="checkbox" required>I authorize disclosure of the submitted sanitized ZIP to all current and future project readers.</label><button :disabled="report.total !== 1 || !selected || !sanitized || !reviewed || !disclosed">Preview reviewed publication</button></fieldset></form>
    </template>
    <button v-if="request && !preview" :disabled="busy || disabled" @click="prepare">Retry captured publication preview</button>
    <section v-if="preview" aria-label="Archive publication preview"><h3>Review publication</h3><p>{{ preview.target.version }} · {{ preview.target.source }} · sequence {{ preview.target.build_number }}</p><dl><template v-for="(count, key) in preview.statistics" :key="key"><dt>{{ key.replaceAll('_', ' ') }}</dt><dd>{{ count }}</dd></template></dl><p>Audience: {{ preview.disclosure.audience.replaceAll('_', ' ') }} · retained members: {{ preview.disclosure.retained_member_count }} · submitted ZIP retained: {{ preview.disclosure.retains_submitted_sanitized_zip ? 'yes' : 'no' }}</p><p class="hint">Imported legacy records remain historical source evidence; no native assessments, approvals or scoring records are created.</p><details><summary>Known migration losses and limitations</summary><ul><li v-for="loss in preview.losses" :key="loss">{{ loss.replaceAll('_', ' ') }}</li><li v-for="limit in preview.limitations" :key="limit">{{ limit }}</li></ul></details><details><summary>Exact coverage, pins and captured request</summary><pre>{{ JSON.stringify(preview.coverage, null, 2) }}</pre><code>{{ preview.preview_digest }}</code><pre>{{ request?.applyHeader }}</pre></details><button v-if="!committed" :disabled="busy || disabled" @click="apply">Publish captured reviewed archive</button></section>
    <p v-if="request && !committed" class="hint">Captured ZIP bytes, source pins, metadata and request ID stay fixed across retries. Discarding does not cancel a publication that may already have committed.</p><button v-if="captured" :disabled="busy" @click="discard">{{ committed ? 'Start another archive' : 'Discard archive capture' }}</button>
  </section></details>
</template>
<style scoped>
.legacy-archive-intake { border-top:1px solid var(--border); margin-top:1rem; padding-top:.8rem; min-width:0 } section { min-width:0; overflow-wrap:anywhere } summary { cursor:pointer } fieldset { border:0; padding:0; display:grid; gap:.6rem; min-width:0 } label { display:grid; gap:.3rem; min-width:0 } input,textarea { max-width:100%; box-sizing:border-box } input[type=checkbox],input[type=radio] { width:auto; justify-self:start } pre,code { white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word } pre { max-height:20rem; overflow:auto } button { margin:.3rem .5rem .3rem 0 } dl { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:.3rem } dd { margin:0 }
</style>
