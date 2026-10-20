<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import KnowledgeLegacyArchiveIntake from './KnowledgeLegacyArchiveIntake.vue'
import { knowledgeApi } from '../knowledgeApi'

type Target = { defaults: { source: string; build_number: number; occurred_at: string; completeness: 'complete' }; project_id: string; version: string; part_id: string | null; kind: 'product' | 'part'; state: string | null; source_authority: string; scope_template?: Record<string, unknown>; blocked_reasons: string[]; baseline: { source: string | null; build_number: number | null; occurred_at: string | null; collection: unknown }; capabilities: string[]; max_upload_bytes: number; formats: string[] }
type Frozen = { project: string; version: string; part: string; metadata: Record<string, unknown>; raw: Uint8Array<ArrayBuffer>; filename: string; sha: string }
const props = defineProps<{ project: string; version: string; disabled?: boolean }>()
const emit = defineEmits<{ locked: [value: boolean]; imported: [value: { version: string; part_id: string | null }] }>()
const nativeLocked = ref(false), archiveLocked = ref(false)
function setNativeLock(value: boolean) { nativeLocked.value = value; emit('locked', value || archiveLocked.value) }
function setArchiveLock(value: boolean) { archiveLocked.value = value; emit('locked', value || nativeLocked.value) }
const opened = ref(false), busy = ref(false), target = ref<Target | null>(null), error = ref(''), notice = ref('')
const selectedVersion = ref(''), mode = ref('product'), part = ref(''), source = ref(''), build = ref(''), observed = ref(''), context = ref(''), predecessor = ref(''), replace = ref(false)
const file = ref<File | null>(null), inputKey = ref(0), frozen = ref<Frozen | null>(null), committed = ref(false)
const versionOptions = ref<string[]>([]), partOptions = ref<string[]>([])
let sequence = 0, timer: ReturnType<typeof setTimeout> | undefined
const base = () => `/projects/${encodeURIComponent(props.project)}`
const message = (value: unknown) => value instanceof Error ? value.message : 'Intake request failed'
function changed() { target.value = null; error.value = ''; notice.value = '' }
async function suggestions() {
  const current = sequence, selectedProject = props.project, version = selectedVersion.value
  try {
    const [versions, parts] = await Promise.allSettled([
      knowledgeApi<{ items: { version: string }[] }>(`${base()}/versions?${new URLSearchParams({ q: version, limit: '20' })}`),
      mode.value === 'part' && version ? knowledgeApi<{ items: { part_id: string }[] }>(`${base()}/intake-parts?${new URLSearchParams({ version, q: part.value, limit: '20' })}`) : Promise.resolve({ items: [] }),
    ])
    if (current !== sequence || selectedProject !== props.project || version !== selectedVersion.value) return
    if (versions.status === 'fulfilled') versionOptions.value = versions.value.items.map(item => item.version)
    if (parts.status === 'fulfilled') partOptions.value = parts.value.items.map(item => item.part_id)
  } catch { /* Inspect target reports authoritative request failures. */ }
}
function search() { changed(); clearTimeout(timer); timer = setTimeout(() => void suggestions(), 200) }
async function inspect() {
  if (busy.value || props.disabled || archiveLocked.value || frozen.value || !selectedVersion.value.trim() || mode.value === 'part' && !part.value.trim()) return
  const current = ++sequence
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const query = new URLSearchParams({ version: selectedVersion.value.trim() })
    if (mode.value === 'part') query.set('part_id', part.value.trim())
    const result = await knowledgeApi<Target>(`${base()}/intake-target?${query}`)
    if (current !== sequence) return
    target.value = result; source.value = result.defaults.source; build.value = String(result.defaults.build_number); observed.value = result.defaults.occurred_at; context.value = result.state && result.scope_template ? JSON.stringify(result.scope_template, null, 2) : ''; await suggestions()
  } catch (value) { if (current === sequence) error.value = message(value) }
  finally { if (current === sequence) busy.value = false }
}
function selectedFile(event: Event) { file.value = (event.target as HTMLInputElement).files?.[0] || null; error.value = '' }
async function prepare() {
  if (busy.value || props.disabled || archiveLocked.value || frozen.value || !target.value?.capabilities.includes('import') || !file.value || !replace.value) return
  const current = sequence, chosen = target.value, original = file.value
  busy.value = true; error.value = ''; setNativeLock(true)
  try {
    if (original.size > chosen.max_upload_bytes) throw new Error('File exceeds the server upload limit.')
    const nextBuild = build.value.trim() || String(chosen.defaults.build_number)
    const number = Number(nextBuild), time = observed.value.trim() || chosen.defaults.occurred_at
    if (!/^\d+$/.test(nextBuild) || !Number.isSafeInteger(number)) throw new Error('Source sequence requires a nonnegative safe integer.')
    if (!/(?:Z|[+-]\d{2}:\d{2})$/i.test(time) || !Number.isFinite(Date.parse(time))) throw new Error('Observed time requires ISO 8601 with an explicit timezone.')
    const fields: Record<string, unknown> = { request_id: crypto.randomUUID(), expected: chosen.state, source: chosen.baseline.source || source.value.trim() || chosen.defaults.source, build_number: number, occurred_at: time, completeness: 'complete' }
    if (context.value.trim()) { const value: unknown = JSON.parse(context.value); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Collection scope must be a JSON object.'); fields.context = value }
    if (!chosen.state && predecessor.value.trim()) fields.predecessor = predecessor.value.trim()
    const raw = new Uint8Array(await original.arrayBuffer()), hash = await crypto.subtle.digest('SHA-256', raw)
    if (current !== sequence) return
    frozen.value = { project: props.project, version: chosen.version, part: chosen.part_id || '', metadata: fields, raw, filename: original.name, sha: [...new Uint8Array(hash)].map(value => value.toString(16).padStart(2, '0')).join('') }
  } catch (value) { if (current === sequence) error.value = message(value) }
  finally { if (current === sequence) { busy.value = false; if (!frozen.value) setNativeLock(false) } }
}
async function publish() {
  if (busy.value || !frozen.value || committed.value) return
  const selected = frozen.value, current = sequence
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const body = new FormData()
    body.append('metadata', JSON.stringify(selected.metadata)); body.append('file', new Blob([selected.raw]), selected.filename)
    const path = `/projects/${encodeURIComponent(selected.project)}/versions/${encodeURIComponent(selected.version)}${selected.part ? `/parts/${encodeURIComponent(selected.part)}` : ''}/files`
    const result = await knowledgeApi<{ committed: boolean | null; projection?: string }>(path, { method: 'POST', body })
    if (current !== sequence) return
    if (result.committed !== true) throw new Error('Publication is uncertain. Retry this exact captured request; do not create a replacement request.')
    committed.value = true; setNativeLock(false)
    notice.value = selected.part ? 'Source part imported. The assembled product is unchanged; select this part explicitly when assembling.' : 'Product baseline imported. Historical assessments remain retained; current coverage is evaluated by the backend.'
    if (result.projection === 'pending') notice.value += ' Projection is pending; the authoritative import is committed.'
    emit('imported', { version: selected.version, part_id: selected.part || null })
  } catch (value) { if (current === sequence) error.value = `${message(value)} Captured bytes, metadata and request ID are retained. Retry unchanged, or explicitly start a new import after reviewing the target.` }
  finally { if (current === sequence) busy.value = false }
}
function reset() { if (busy.value) return; ++sequence; frozen.value = null; committed.value = false; target.value = null; file.value = null; ++inputKey.value; replace.value = false; error.value = ''; notice.value = ''; setNativeLock(false) }
function toggle(event: Event) { opened.value = (event.currentTarget as HTMLDetailsElement).open; if (opened.value && !selectedVersion.value) selectedVersion.value = props.version; if (opened.value) void suggestions() }
watch(() => props.project, () => { ++sequence; busy.value = false; reset(); selectedVersion.value = props.version; versionOptions.value = []; partOptions.value = [] })
onBeforeUnmount(() => { ++sequence; clearTimeout(timer); setNativeLock(false) })
</script>
<template>
  <details v-if="project" class="knowledge-intake" @toggle="toggle">
    <summary>Import composition</summary>
    <section aria-label="Native composition intake"><fieldset class="native-intake-fields" :disabled="archiveLocked">
      <p class="hint">Import original CycloneDX or SPDX files into an existing or new product version. Complete source documents replace the selected baseline; missing components do not establish remediation.</p>
      <form aria-label="Select composition target" @submit.prevent="inspect"><fieldset :disabled="busy || !!frozen || disabled">
        <label>Product version (existing or new)<input v-model="selectedVersion" list="intake-versions" required maxlength="200" @input="search"><datalist id="intake-versions"><option v-for="value in versionOptions" :key="value" :value="value" /></datalist></label>
        <label>Import target<select v-model="mode" @change="search"><option value="product">Complete product baseline</option><option value="part">Isolated source part</option></select></label>
        <label v-if="mode === 'part'">Source part ID<input v-model="part" list="intake-parts" required maxlength="200" @input="search"><datalist id="intake-parts"><option v-for="value in partOptions" :key="value" :value="value" /></datalist></label>
        <button>Inspect target</button>
      </fieldset></form>
      <p v-if="busy" role="status">Working…</p><p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
      <template v-if="target">
        <p>{{ target.state ? 'Existing source baseline' : 'New source baseline' }} · {{ target.version }}<span v-if="target.part_id"> · part {{ target.part_id }}</span> · authority: {{ target.source_authority }}</p>
        <p v-if="target.baseline.build_number != null">Last accepted source sequence: {{ target.baseline.build_number }}. The next import sequence is filled automatically.</p>
        <ul v-if="target.blocked_reasons.length"><li v-for="reason in target.blocked_reasons" :key="reason">{{ ({ assembled_product_requires_explicit_part_selection_not_baseline_replacement: 'This product is assembled. Import a source part, then select it explicitly when assembling.', connector_owned_source_requires_explicit_authority_policy_to_replace_with_file: 'This source is connector-owned. File replacement requires an explicit authority policy; it cannot be changed here.', reserved_product_version_name: 'Product version names beginning with @ are reserved.' } as Record<string, string>)[reason] || reason.replaceAll('_', ' ') }}</li></ul>
        <p v-else-if="!target.capabilities.includes('import')">Your current permissions allow viewing this target only.</p>
        <form v-if="target.capabilities.includes('import') && !frozen" aria-label="Prepare composition import" @submit.prevent="prepare"><fieldset :disabled="busy || disabled">
          <label>Original SBOM file<input :key="inputKey" type="file" required accept=".json,.xml,.cdx,.spdx" @change="selectedFile"></label>
          <p class="hint">{{ target.formats.join(' · ') }}. Upload limit: {{ target.max_upload_bytes }} bytes.</p>
          <details><summary>Advanced import metadata</summary><p class="hint">Defaults use the current file source, the next import sequence and upload preparation time. This time is not a verified CI build timestamp. Override these when the producer supplies them.</p>
          <label>Source identity<input v-model="source" maxlength="200" :readonly="!!target.baseline.source" placeholder="Stable pipeline or file-source name"></label>
          <label>Source sequence<input v-model="build" inputmode="numeric"></label>
          <label>Observed at (ISO 8601 with timezone)<input v-model="observed" placeholder="Defaults to upload preparation time"></label>
          </details>
          <details><summary>Collection scope and branch predecessor</summary><p class="hint">Optional typed collection JSON records producer claims; it does not verify source, build or discovery completeness. Existing boundary fields are prefilled; previous commits, build digests, runs and coverage claims are not reused. Leave other fields unknown unless supported by this import.</p><label>Collection scope JSON<textarea v-model="context" rows="5" placeholder='{"subject_kind":"build","collector":"CI"}' /></label><label>Predecessor state (new versions only)<input v-model="predecessor" maxlength="64" :disabled="!!target.state"></label><details v-if="target.baseline.collection"><summary>Previously declared collection scope</summary><pre>{{ JSON.stringify(target.baseline.collection, null, 2) }}</pre></details></details>
          <label><input v-model="replace" type="checkbox" required> Replace this exact source baseline with the complete document.</label>
          <p v-if="mode === 'part'" class="hint">Importing this source part does not publish an assembled product.</p><button class="primary">Review captured import</button>
        </fieldset></form>
      </template>
      <section v-if="frozen" aria-label="Captured composition import"><h3>{{ committed ? 'Import recorded' : 'Review import' }}</h3><p>{{ frozen.version }}<span v-if="frozen.part"> · source part {{ frozen.part }}</span> · {{ frozen.filename }} · {{ frozen.raw.byteLength }} bytes</p><details><summary>Exact request and file digest</summary><code>SHA-256 {{ frozen.sha }}</code><pre>{{ JSON.stringify(frozen.metadata, null, 2) }}</pre></details><p v-if="!committed" class="hint">This captured request stays fixed across retries. A conflict requires explicit target review before starting a new import.</p><button v-if="!committed" class="primary" :disabled="busy" @click="publish">Commit captured import</button><button :disabled="busy" @click="reset">{{ committed ? 'Start another import' : 'Discard capture and start a new import' }}</button></section>
    </fieldset><KnowledgeLegacyArchiveIntake :key="project" :project="project" :disabled="disabled || busy || nativeLocked" @locked="setArchiveLock" @imported="emit('imported', $event)" /></section>
  </details>
</template>
<style scoped>
.knowledge-intake { border-block: 1px solid var(--border, #64748b33); padding: .8rem 0; min-width: 0; }
summary { cursor: pointer; } form, section { min-width: 0; } fieldset { min-width: 0; border: 0; padding: 0; display: grid; gap: .6rem; } label { display: grid; gap: .3rem; min-width: 0; } input, select, textarea { max-width: 100%; box-sizing: border-box; } input[type=checkbox] { width: auto; justify-self: start; } pre, code { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; } pre { max-height: 20rem; overflow: auto; } button { margin-right: .5rem; margin-block: .3rem; }
</style>
