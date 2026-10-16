<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { send } from '../api'
import { knowledgeApi, type KnowledgeFinding } from '../knowledgeApi'
import KnowledgeAnalysisJobs from './KnowledgeAnalysisJobs.vue'

type Candidate = { cpe: string; identification_basis: string; basis_verification: string; provenance: Record<string, unknown> }
type CpeResult = { inventory_state: string; policy_state: string | null; proposal: { algorithm_version: string; content_digest: string; catalog_content_digest: string; rules_content_digest: string; requested_purl: string | null; resolved_purl: string | null; candidates: Candidate[]; rejected_candidates: unknown[]; reviewed_rules: unknown[]; limitations: string[] } }
type VScorerResult = { eligible: boolean; sbom: unknown; cves: unknown; dtvp_source: { state: string; artifacts: { sbom_sha256: string; cves_sha256: string } } | null; coverage: { included: string[]; excluded: { vulnerability_id: string; reason: string }[]; verification: string; remote_authenticity: string }; files?: Record<string, string> }
type AgentyzerResult = { ready_to_submit: boolean; request: unknown; receipt: { state: string; request_sha256: string | null }; coverage: { reasons: string[]; limitations: string[]; source_verification: string; repository_authorization: string } }
const props = defineProps<{ project: string; state: string; version: string; finding: KnowledgeFinding }>()
const emit = defineEmits<{ locked: [boolean] }>()
const cpe = ref<CpeResult | null>(null), vscorer = ref<VScorerResult | null>(null), agentyzer = ref<AgentyzerResult | null>(null)
const cpeBusy = ref(false), vscorerBusy = ref(false), agentyzerBusy = ref(false)
const cpeError = ref(''), vscorerError = ref(''), agentyzerError = ref(''), sourceBase = ref(''), exactFiles = ref(false)
let sequence = 0, vectorSequence = 0
const label = (value: string) => value.replaceAll('_', ' ')
const componentRef = computed(() => typeof props.finding.context.component_ref === 'string' ? props.finding.context.component_ref : (props.finding.component as { 'bom-ref'?: string })['bom-ref'] || '')
const endpoint = () => `/projects/${encodeURIComponent(props.project)}/states/${encodeURIComponent(props.state)}`
const vectors = computed(() => [...new Set(props.finding.source_ratings.map(item => item.vector).filter((value): value is string => Boolean(value)))])
function ratingLabels(vector: string) {
  return props.finding.source_ratings.filter(item => item.vector === vector).map(item => `${typeof item.source === 'string' ? item.source : item.source?.name || item.observed_source || 'Unattributed source'} · ${item.score ?? 'Unknown score'}`).join('; ')
}
function errorMessage(error: unknown) { return error instanceof Error ? error.message : 'Specialist input request failed' }
function reset() { ++sequence; ++vectorSequence; cpe.value = null; vscorer.value = null; agentyzer.value = null; sourceBase.value = ''; exactFiles.value = false; cpeError.value = ''; vscorerError.value = ''; agentyzerError.value = ''; cpeBusy.value = false; vscorerBusy.value = false; agentyzerBusy.value = false }
async function loadCpe() {
  if (!componentRef.value || cpeBusy.value) return
  const current = sequence
  cpeBusy.value = true; cpeError.value = ''
  try {
    const result = await knowledgeApi<CpeResult>(`${endpoint()}/cpe?${new URLSearchParams({ component_ref: componentRef.value })}`)
    if (current === sequence) cpe.value = result
  } catch (error) { if (current === sequence) cpeError.value = errorMessage(error) }
  finally { if (current === sequence) cpeBusy.value = false }
}
async function sha256(text: string) {
  if (!globalThis.crypto?.subtle) throw new Error('Artifact downloads require browser SHA-256 support in a secure context.')
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))].map(value => value.toString(16).padStart(2, '0')).join('')
}
async function prepareVScorer() {
  if (!componentRef.value || !sourceBase.value || vscorerBusy.value) return
  const current = sequence, vector = ++vectorSequence
  vscorerBusy.value = true; vscorerError.value = ''; vscorer.value = null; exactFiles.value = false
  try {
    const result = await knowledgeApi<VScorerResult>(`${endpoint()}/vscorer-input`, send({ context_id: props.finding.context_id, component_ref: componentRef.value, base_selections: { [props.finding.vulnerability_id]: sourceBase.value } }))
    if (current !== sequence || vector !== vectorSequence) return
    vscorer.value = result
    if (result.eligible) {
      const files = result.files, artifacts = result.dtvp_source?.artifacts
      if (!files || !artifacts || !files['sbom.cdx.json'] || !files['cves.json'] || !files['dtvp-source.json']) throw new Error('Exact artifact files unavailable. The derivation result can be downloaded for inspection.')
      const valid = await sha256(files['sbom.cdx.json']) === artifacts.sbom_sha256 && await sha256(files['cves.json']) === artifacts.cves_sha256
      if (current !== sequence || vector !== vectorSequence) return
      if (!valid) throw new Error('Returned artifact bytes do not match the source receipt; file downloads are withheld.')
      exactFiles.value = true
    }
  } catch (error) { if (current === sequence && vector === vectorSequence) vscorerError.value = errorMessage(error) }
  finally { if (current === sequence && vector === vectorSequence) vscorerBusy.value = false }
}
async function prepareAgentyzer() {
  if (agentyzerBusy.value) return
  const current = sequence
  agentyzerBusy.value = true; agentyzerError.value = ''; agentyzer.value = null
  try {
    const result = await knowledgeApi<AgentyzerResult>(`${endpoint()}/agentyzer-input`, send({ context_id: props.finding.context_id, vulnerability_id: props.finding.vulnerability_id }))
    if (current === sequence) agentyzer.value = result
  } catch (error) { if (current === sequence) agentyzerError.value = errorMessage(error) }
  finally { if (current === sequence) agentyzerBusy.value = false }
}
function download(text: string, name: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json;charset=utf-8' })), link = document.createElement('a')
  link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
}
function downloadJson(value: unknown, name: string) { download(JSON.stringify(value, null, 2), name) }
watch(() => [props.project, props.state, props.finding.context_id, props.finding.vulnerability_id, componentRef.value], reset)
watch(sourceBase, () => { ++vectorSequence; vscorer.value = null; exactFiles.value = false; vscorerError.value = ''; vscorerBusy.value = false })
onBeforeUnmount(() => { ++sequence; ++vectorSequence; emit('locked', false) })
</script>

<template>
  <details class="knowledge-specialists">
    <summary>Specialist inputs and CPE candidates</summary>
    <p class="hint">Preparing or downloading specialist inputs does not submit work or adopt an assessment, identity or score. External analysis needs a separate explicit job request.</p>
    <p v-if="!componentRef" class="hint">The source component reference is unavailable; CPE and VScorer inputs cannot be prepared.</p>
    <details>
      <summary>CPE candidate discovery</summary>
      <p class="hint">Offline discovery uses the selected inventory and the current discovery policy. Refresh explicitly to use an updated policy.</p>
      <button :disabled="cpeBusy || !componentRef" @click="loadCpe">{{ cpeBusy ? 'Loading candidates…' : cpe ? 'Refresh CPE candidates' : 'Load CPE candidates' }}</button>
      <p v-if="cpeError" role="alert">{{ cpeError }}</p>
      <template v-if="cpe">
        <p v-if="!cpe.proposal.candidates.length">No CPE candidates from these inputs. This does not establish that no matching identity exists.</p>
        <article v-for="(candidate, index) in cpe.proposal.candidates" :key="index"><code>{{ candidate.cpe }}</code><p>{{ label(candidate.identification_basis) }} · {{ label(candidate.basis_verification) }}</p><details><summary>Candidate attribution</summary><pre>{{ JSON.stringify(candidate.provenance, null, 2) }}</pre></details></article>
        <ul><li v-for="limit in cpe.proposal.limitations" :key="limit">{{ limit }}</li></ul>
        <details><summary>CPE input and policy pins</summary><dl><dt>Inventory state</dt><dd><code>{{ cpe.inventory_state }}</code></dd><dt>Policy state</dt><dd><code>{{ cpe.policy_state || 'No configured policy' }}</code></dd><dt>Algorithm</dt><dd>{{ cpe.proposal.algorithm_version }}</dd><dt>Candidate digest</dt><dd><code>{{ cpe.proposal.content_digest }}</code></dd></dl><pre>{{ JSON.stringify({ requested_purl: cpe.proposal.requested_purl, resolved_purl: cpe.proposal.resolved_purl, catalog_digest: cpe.proposal.catalog_content_digest, rules_digest: cpe.proposal.rules_content_digest, reviewed_rules: cpe.proposal.reviewed_rules, rejected_candidates: cpe.proposal.rejected_candidates }, null, 2) }}</pre></details>
        <button @click="downloadJson(cpe, 'dtvp-cpe-candidates.json')">Download CPE candidate JSON</button>
      </template>
    </details>
    <details>
      <summary>VScorer input files</summary>
      <p class="hint">Select an original source Base explicitly for {{ finding.vulnerability_id }}. The backend validates it; other context vulnerabilities remain explicit exclusions. No published or contextual score is substituted.</p>
      <label>Original source Base<select v-model="sourceBase" :disabled="vscorerBusy"><option value="" disabled>Select a source vector</option><option v-for="vector in vectors" :key="vector" :value="vector">{{ ratingLabels(vector) }} · {{ vector }}</option></select></label>
      <code v-if="sourceBase">{{ sourceBase }}</code><p v-if="!vectors.length">No original source vectors are available for selection.</p>
      <button :disabled="vscorerBusy || !sourceBase || !componentRef" @click="prepareVScorer">{{ vscorerBusy ? 'Preparing files…' : 'Prepare VScorer inputs' }}</button>
      <p v-if="vscorerError" role="alert">{{ vscorerError }}</p>
      <template v-if="vscorer">
        <p>{{ vscorer.eligible ? 'Focused input prepared; no analysis has been submitted.' : 'No eligible VScorer worklist was produced.' }}</p>
        <p>Included: {{ vscorer.coverage.included.join(', ') || 'None' }}</p><ul v-if="vscorer.coverage.excluded.length"><li v-for="(item, index) in vscorer.coverage.excluded" :key="index">{{ item.vulnerability_id }} · {{ label(item.reason) }}</li></ul>
        <p class="hint">Receipt hashes identify input bytes; remote authenticity and provider identity are not verified.</p>
        <div v-if="exactFiles && vscorer.files" class="specialist-actions"><button @click="download(vscorer.files['sbom.cdx.json']!, 'sbom.cdx.json')">Download CycloneDX SBOM</button><button @click="download(vscorer.files['cves.json']!, 'cves.json')">Download CVE list</button><button @click="download(vscorer.files['dtvp-source.json']!, 'dtvp-source.json')">Download VScorer source receipt</button></div>
        <button @click="downloadJson(vscorer, 'dtvp-vscorer-input.json')">Download derivation result JSON</button>
      </template>
    </details>
    <details>
      <summary>Agentyzer repository input</summary>
      <p class="hint">A producer-qualified repository and exact commit are required. Input preparation does not authorize or submit work; a configured worker validates the repository binding when a job is requested.</p>
      <button :disabled="agentyzerBusy" @click="prepareAgentyzer">{{ agentyzerBusy ? 'Preparing input…' : 'Prepare Agentyzer input' }}</button>
      <p v-if="agentyzerError" role="alert">{{ agentyzerError }}</p>
      <template v-if="agentyzer">
        <p>{{ agentyzer.ready_to_submit ? 'Repository input prepared; no analysis has been submitted.' : 'Repository input is not ready for submission.' }}</p>
        <ul><li v-for="reason in agentyzer.coverage.reasons" :key="reason">{{ label(reason) }}</li><li v-for="limit in agentyzer.coverage.limitations" :key="limit">{{ limit }}</li></ul>
        <details><summary>Agentyzer source pin and request</summary><pre>{{ JSON.stringify({ receipt: agentyzer.receipt, request: agentyzer.request }, null, 2) }}</pre></details>
        <button @click="downloadJson(agentyzer, 'dtvp-agentyzer-input.json')">Download Agentyzer input JSON</button>
      </template>
      <KnowledgeAnalysisJobs :project="project" :state="state" :version="version" :context-id="finding.context_id" :vulnerability-id="finding.vulnerability_id" :source-ready="agentyzer?.ready_to_submit === true" @locked="emit('locked', $event)" />
    </details>
  </details>
</template>

<style scoped>
.knowledge-specialists { padding: 1rem; border-block: 1px solid var(--border, #64748b33); min-width: 0; }
summary { cursor: pointer; overflow-wrap: anywhere; }
.knowledge-specialists > details { margin-top: .75rem; }
label { display: grid; gap: .3rem; margin-block: .6rem; min-width: 0; }
select { width: 100%; min-width: 0; }
code, pre { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; font-size: .8rem; }
pre { max-height: 24rem; overflow: auto; }
article { margin-block: .75rem; }
article p { margin-block: .3rem; }
dl { display: grid; grid-template-columns: minmax(5rem, 1fr) minmax(0, 2fr); gap: .4rem; }
dd { margin: 0; overflow-wrap: anywhere; }
.specialist-actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-block: .5rem; }
@media (max-width: 650px) { dl { grid-template-columns: minmax(0, 1fr); } }
</style>
