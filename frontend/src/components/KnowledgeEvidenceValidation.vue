<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi } from '../knowledgeApi'
type Key = { subject: string; key_id: string; algorithm: string; public_key_thumbprint: string }
type Policy = { project_id: string; trust_policy_sha256: string; keys: Key[] }
type Report = { format: string; report_digest: string; validation_profile?: string; valid?: boolean; verified?: boolean; diagnostic?: string; document_sha256?: string; artifact_sha256?: string; compact_jws_sha256?: string; trust_policy_sha256?: string; expected_artifact_sha256?: string; project_id?: string; configured_signer_subject?: string; diagnostics?: { path: string; code: string }[]; diagnostics_truncated?: boolean; limitations: string[]; committed: boolean }
type Capture = { project: string; state: string; mode: string; file: File; sha: string; profile: string; signature?: File; signatureSha?: string; subject?: string; policy?: string; document?: Record<string, unknown> }
const props = defineProps<{ project: string; state?: string; disabled?: boolean }>()
const emit = defineEmits<{ busy: [value: boolean] }>()
const mode = ref('schema'), profile = ref('cyclonedx-1.6-json-schema/1'), subject = ref('')
const file = ref<File | null>(null), signature = ref<File | null>(null), fileInput = ref<HTMLInputElement | null>(null), signatureInput = ref<HTMLInputElement | null>(null)
const busy = ref(false), error = ref(''), policy = ref<Policy | null>(null), capture = ref<Capture | null>(null), report = ref<Report | null>(null)
const profiles = ['cyclonedx-1.5-json-schema/1', 'cyclonedx-1.6-json-schema/1', 'openvex-0.2.0-json-schema/1', 'csaf-2.0-json-schema/1']
const subjects = computed(() => [...new Set(policy.value?.keys.map(key => key.subject) || [])])
const locked = computed(() => busy.value || props.disabled || Boolean(capture.value))
const resultLabel = computed(() => report.value ? capture.value?.mode === 'schema' ? report.value.valid ? 'Schema check passed' : 'Schema check failed' : report.value.verified ? 'Signature verified under configured policy' : 'Signature not verified' : '')
let sequence = 0
let controller: AbortController | null = null
const isSha = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
const root = (project = props.project) => `/projects/${encodeURIComponent(project)}/evidence`
function working(value: boolean) { busy.value = value; emit('busy', value) }
async function sha(bytes: ArrayBuffer) {
  if (!globalThis.crypto?.subtle) throw new Error('Integrity checks require HTTPS or localhost.')
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), value => value.toString(16).padStart(2, '0')).join('')
}
function discard() {
  ++sequence; controller?.abort(); controller = null; working(false)
  capture.value = null; report.value = null; error.value = ''; file.value = null; signature.value = null
  if (fileInput.value) fileInput.value.value = ''
  if (signatureInput.value) signatureInput.value.value = ''
}
async function loadPolicy() {
  if (busy.value || props.disabled || capture.value) return
  const token = sequence, project = props.project
  working(true); error.value = ''; controller = new AbortController()
  try {
    const value = await knowledgeApi<Policy>(`${root(project)}/signature-policy`, { signal: controller.signal })
    if (token !== sequence) return
    if (value.project_id !== project || !isSha(value.trust_policy_sha256) || !Array.isArray(value.keys)) throw new Error('Signer policy differs from the selected project.')
    policy.value = value; subject.value = subjects.value[0] || ''
  } catch (err) { if (token === sequence) error.value = err instanceof Error ? err.message : 'Policy request failed' }
  finally { if (token === sequence) working(false) }
}
async function validate() {
  if (busy.value || props.disabled) return
  const token = sequence
  working(true); error.value = ''; report.value = null; controller = new AbortController()
  try {
    if (!capture.value) {
      if (!file.value) throw new Error('Select the exact source artifact.')
      const maximum = mode.value === 'signature' ? 8 * 1024 * 1024 : 32 * 1024 * 1024
      if (!file.value.size || file.value.size > maximum) throw new Error(`Artifact must contain 1 byte–${maximum / 1024 / 1024} MiB.`)
      const chosen = file.value, bytes = await chosen.arrayBuffer(), checksum = await sha(bytes)
      if (token !== sequence) return
      const frozen: Capture = { project: props.project, state: props.state || '', mode: mode.value, profile: profile.value, file: new File([bytes], chosen.name, { type: chosen.type }), sha: checksum }
      if (mode.value === 'schema') {
        const document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
        if (!document || Array.isArray(document) || typeof document !== 'object') throw new Error('Schema validation requires a JSON object.')
        frozen.document = document
      } else {
        if (!policy.value || !subject.value || !subjects.value.includes(subject.value)) throw new Error('Load and select a deployment-trusted signer first.')
        if (!signature.value || !signature.value.size || signature.value.size > 12 * 1024 * 1024) throw new Error('Select a compact JWS file of at most 12 MiB.')
        const chosenSignature = signature.value, signatureBytes = await chosenSignature.arrayBuffer()
        frozen.signature = new File([signatureBytes], chosenSignature.name, { type: 'text/plain' }); frozen.signatureSha = await sha(signatureBytes)
        frozen.subject = subject.value; frozen.policy = policy.value.trust_policy_sha256
      }
      if (token !== sequence) return
      capture.value = frozen
    }
    const frozen = capture.value
    let value: Report
    if (frozen.mode === 'schema') {
      value = await knowledgeApi<Report>(`${root(frozen.project)}/schema-validation`, { ...send({ document: frozen.document, validation_profile: frozen.profile }), signal: controller.signal })
      if (token !== sequence) return
      if (value.format !== 'dtvp.official-schema-validation/1' || value.validation_profile !== frozen.profile || typeof value.valid !== 'boolean' || !isSha(value.document_sha256)) throw new Error('Schema report differs from the captured profile or lacks its canonical document pin.')
    } else {
      const body = new FormData(); body.set('file', frozen.file); body.set('signature', frozen.signature!); body.set('trusted_subject', frozen.subject!); body.set('expected_artifact_sha256', frozen.sha); body.set('expected_trust_policy_sha256', frozen.policy!)
      value = await knowledgeApi<Report>(`${root(frozen.project)}/signature-verification`, { method: 'POST', body, signal: controller.signal })
      if (token !== sequence) return
      if (value.format !== 'dtvp.artifact-signature-verification/1' || value.project_id !== frozen.project || value.artifact_sha256 !== frozen.sha || value.expected_artifact_sha256 !== frozen.sha || value.compact_jws_sha256 !== frozen.signatureSha || value.trust_policy_sha256 !== frozen.policy || typeof value.verified !== 'boolean' || value.verified && value.configured_signer_subject !== frozen.subject) throw new Error('Signature report differs from the captured bytes, project, signer or policy.')
    }
    if (value.committed !== false || !isSha(value.report_digest) || !Array.isArray(value.limitations)) throw new Error('Validation response does not identify a read-only pinned report.')
    report.value = value
  } catch (err) { if (token === sequence) error.value = err instanceof Error ? err.message : 'Validation request failed' }
  finally { if (token === sequence) working(false) }
}
watch(() => [props.project, props.state], () => { discard(); policy.value = null; subject.value = '' })
onBeforeUnmount(() => { ++sequence; controller?.abort(); emit('busy', false) })
</script>
<template>
  <details class="evidence-validation"><summary>Optional schema and signature checks</summary>
    <section aria-label="Read-only evidence validation">
      <p class="hint">Checks selected local files. Does not import, approve or change evidence trust. Schema and signature results are separate.</p>
      <p v-if="error" role="alert">{{ error }}</p>
      <form aria-label="Validate local evidence" @submit.prevent="validate">
        <label>Validation check<select v-model="mode" :disabled="locked"><option value="schema">Official JSON Schema</option><option value="signature">Exact-artifact JWS signature</option></select></label>
        <label>Source artifact for validation<input ref="fileInput" type="file" :disabled="locked" @change="file = ($event.target as HTMLInputElement).files?.[0] || null"></label>
        <template v-if="mode === 'schema'"><label>Official schema profile<select v-model="profile" :disabled="locked"><option v-for="item in profiles" :key="item" :value="item">{{ item }}</option></select></label><p class="hint">JSON Schema only; supported intake semantics and signature authenticity require separate checks.</p></template>
        <template v-else><div class="actions"><button type="button" :disabled="locked" @click="loadPolicy">Load trusted signer policy</button></div><p v-if="policy && !subjects.length" class="hint">No deployment-trusted signers are configured for this project.</p><label>Deployment-trusted signer<select v-model="subject" :disabled="locked || !subjects.length"><option value="" disabled>Select a configured signer</option><option v-for="item in subjects" :key="item">{{ item }}</option></select></label><label>Compact JWS signature file<input ref="signatureInput" type="file" :disabled="locked" @change="signature = ($event.target as HTMLInputElement).files?.[0] || null"></label><p class="hint">Encoded compact JWS over exact bytes; no detached, embedded JSF, DSSE or Sigstore verification.</p></template>
        <div class="actions"><button :disabled="busy || disabled || !file || mode === 'signature' && (!policy || !subject || !signature)">{{ capture ? 'Repeat captured validation' : 'Run read-only validation' }}</button><button type="button" @click="discard">{{ busy ? 'Cancel and discard validation' : 'Discard validation inputs and report' }}</button></div>
      </form>
      <section v-if="report && capture" aria-label="Evidence validation result"><strong>{{ resultLabel }}</strong><p v-if="report.diagnostic">{{ report.diagnostic.replaceAll('_', ' ') }}</p><ul v-if="report.diagnostics?.length"><li v-for="(item, index) in report.diagnostics" :key="index"><code>{{ item.path }}</code> · {{ item.code }}</li></ul><p v-if="report.diagnostics_truncated">Additional diagnostics omitted; the document remains invalid.</p><details><summary>Captured inputs, scope and complete report</summary><dl><dt>Project</dt><dd>{{ capture.project }}</dd><dt>Selected workspace state</dt><dd>{{ capture.state || 'No version selected' }} (presentation context only)</dd><dt>Exact local source SHA-256</dt><dd>{{ capture.sha }}</dd></dl><p v-if="capture.mode === 'schema'" class="hint">The report's document SHA-256 covers server-canonical JSON; the local source hash above covers the original bytes.</p><pre>{{ JSON.stringify(report, null, 2) }}</pre></details><p v-for="item in report.limitations" :key="item" class="hint">{{ item }}</p></section>
    </section>
  </details>
</template>
<style scoped>
.evidence-validation{margin-block:.7rem;border-top:1px solid var(--line);padding-top:.7rem;min-width:0}.evidence-validation summary{cursor:pointer;font-weight:600}.evidence-validation label{display:grid;gap:.3rem;margin-block:.7rem}.evidence-validation input,.evidence-validation select{width:100%;min-width:0;box-sizing:border-box}.actions{display:flex;flex-wrap:wrap;gap:.6rem;margin-block:.7rem}.hint{color:var(--muted);font-size:.85rem}.evidence-validation p,.evidence-validation li,.evidence-validation dd{overflow-wrap:anywhere}.evidence-validation dd{margin:0}.evidence-validation pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:20rem;overflow:auto;font-size:.75rem}
</style>
