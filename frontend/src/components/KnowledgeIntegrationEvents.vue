<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
import { send } from '../api'
type Event = { event_id: string; source: string; target: string; source_version: string; target_version: string; source_pin: { repository: string; commit: string }; target_pin: { repository: string; commit: string; subject_digest: string; pipeline_run: string }; declaration: { integration_kind: string; occurred_at: string; rationale: string }; git_ancestry: { status: string; verification: string; path?: string[]; limitations: string[] }; software_integration_verified: boolean; limitations: string[] }
type Catalog = { state: string; items: Event[]; total: number; next_offset: number | null; limitations: string[] }
type Proposal = { id: string; category: string; vulnerability_id?: string; source_context_id?: string; target_context_id?: string; reasons: string[]; requires_new_target_review: boolean }
type Preview = { integration_event: Event; basis_selection: string; apply_supported: false; limitations: string[]; proposals: { source: string; target: string; basis: string | null; preview_digest: string; items: Proposal[]; total: number; next_offset: number | null; summary: { by_category: Record<string, number> }; limitations: string[] } }
type Capture = { endpoint: string; body: { target: string; basis: string | null; context_mapping: Record<string, string> }; event: Event }
const props = defineProps<{ project: string; state: string; disabled?: boolean }>()
const opened = ref(false), busy = ref(false), error = ref(''), registry = ref<Catalog | null>(null), pin = ref<{ project: string; state: string } | null>(null), selected = ref<Event | null>(null)
const basis = ref(''), mapping = ref('{}'), captured = ref<Capture | null>(null), result = ref<Preview | null>(null), listOffset = ref(0), previewOffset = ref(0), attemptedOffset = ref(0), previous = ref<number[]>([]), previewPrevious = ref<number[]>([])
let generation = 0
const stale = computed(() => Boolean(pin.value && (pin.value.project !== props.project || pin.value.state !== props.state)))
const human = (value: string) => value.replaceAll('_', ' ')
const message = (value: unknown) => value instanceof Error ? value.message : 'Integration evidence unavailable'
async function list(offset = 0, refresh = false) {
  if (busy.value || props.disabled) return
  if (refresh || !pin.value) { ++generation; pin.value = { project: props.project, state: props.state }; registry.value = null; selected.value = null; captured.value = null; result.value = null; previous.value = []; previewPrevious.value = [] }
  const scope = pin.value!, current = generation; busy.value = true; error.value = ''
  try {
    const data = await knowledgeApi<Catalog>(`/projects/${encodeURIComponent(scope.project)}/states/${encodeURIComponent(scope.state)}/integration-events?offset=${offset}&limit=20`)
    if (current !== generation) return
    if (data.state !== scope.state) throw new Error('Event list does not match the selected immutable state.')
    registry.value = data; listOffset.value = offset
  } catch (value) { if (current === generation) error.value = message(value) }
  finally { if (current === generation) busy.value = false }
}
async function listPage(next: boolean) {
  const offset = next ? registry.value?.next_offset : previous.value.at(-1)
  if (offset == null) return
  const before = listOffset.value, current = generation; await list(offset)
  if (current === generation && listOffset.value === offset) { if (next) previous.value.push(before); else previous.value.pop() }
}
function choose(event: Event) { if (!captured.value && !props.disabled && !busy.value) selected.value = JSON.parse(JSON.stringify(event)) as Event }
function discard() { if (busy.value) return; ++generation; captured.value = null; result.value = null; previewPrevious.value = []; error.value = '' }
async function preview(offset = 0) {
  if (busy.value || props.disabled || !pin.value || !selected.value || (!captured.value && stale.value)) return
  const current = generation; busy.value = true; error.value = ''; attemptedOffset.value = offset
  try {
    if (!captured.value) {
      const chosenBasis = basis.value.trim(), value: unknown = JSON.parse(mapping.value)
      if (chosenBasis && !/^[a-f0-9]{64}$/.test(chosenBasis)) throw new Error('Explicit basis must be a lowercase SHA-256 state reference.')
      if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length > 1000 || Object.entries(value).some(([key, item]) => !/^[a-f0-9]{64}$/.test(key) || typeof item !== 'string' || !/^[a-f0-9]{64}$/.test(item))) throw new Error('Context mapping requires a JSON object of at most 1000 exact context SHA pairs.')
      captured.value = { endpoint: `/projects/${encodeURIComponent(pin.value.project)}/integration-events/${encodeURIComponent(selected.value.event_id)}/synchronization-preview`, body: { target: pin.value.state, basis: chosenBasis || null, context_mapping: value as Record<string, string> }, event: JSON.parse(JSON.stringify(selected.value)) as Event }
    }
    const capture = captured.value
    const data = await knowledgeApi<Preview>(`${capture.endpoint}?offset=${offset}&limit=20`, send(capture.body))
    if (current !== generation) return
    if (data.integration_event.event_id !== capture.event.event_id || data.proposals.source !== capture.event.source || data.proposals.target !== capture.body.target || data.proposals.basis !== capture.body.basis || data.apply_supported !== false) throw new Error('Preview differs from the captured event and state selection.')
    if (result.value && result.value.proposals.preview_digest !== data.proposals.preview_digest) throw new Error('Proposal report changed; previous results remain. Discard the preview before explicitly preparing another report.')
    result.value = data; previewOffset.value = offset
  } catch (value) { if (current === generation) error.value = `${message(value)} Captured event, target, basis and mapping stay unchanged.` }
  finally { if (current === generation) busy.value = false }
}
async function proposalPage(next: boolean) {
  const offset = next ? result.value?.proposals.next_offset : previewPrevious.value.at(-1)
  if (offset == null) return
  const before = previewOffset.value, current = generation; await preview(offset)
  if (current === generation && previewOffset.value === offset) { if (next) previewPrevious.value.push(before); else previewPrevious.value.pop() }
}
function toggle(event: EventTarget | null) { opened.value = (event as HTMLDetailsElement).open; if (opened.value && !registry.value && !busy.value) void list() }
watch(() => props.state, () => { ++generation; busy.value = false; error.value = '' })
watch(() => props.project, () => { ++generation; busy.value = false; pin.value = null; registry.value = null; selected.value = null; captured.value = null; result.value = null; basis.value = ''; mapping.value = '{}'; previous.value = []; previewPrevious.value = []; if (opened.value) void list() })
onBeforeUnmount(() => { ++generation })
</script>
<template>
  <details class="integration-events" @toggle="toggle($event.currentTarget)"><summary>Pipeline integration observations</summary><section aria-label="Pipeline integration evidence">
    <p class="hint">Recorded producer declarations and optional offline commit-object consistency. They do not verify software integration, patch equivalence or assessment applicability.</p>
    <button :disabled="busy || disabled" @click="list(0, true)">Refresh integration events for workspace state</button>
    <p v-if="pin" class="hint">Displayed target state: {{ pin.state }}</p><p v-if="stale" role="status">Workspace state changed. Retained events and previews keep their previous pins; refresh explicitly to select the new state.</p>
    <p v-if="busy" role="status">Loading…</p><p v-if="error" role="alert">{{ error }}</p>
    <template v-if="registry"><p>{{ registry.total }} retained integration observations</p><fieldset :disabled="busy || disabled || !!captured"><label v-for="event in registry.items" :key="event.event_id"><input type="radio" name="integration-event" :checked="selected?.event_id === event.event_id" @change="choose(event)">{{ event.source_version }} → {{ event.target_version }} · {{ human(event.declaration.integration_kind) }} · {{ event.event_id.slice(0, 12) }}</label></fieldset><nav><button :disabled="busy || disabled || !previous.length" @click="listPage(false)">Previous integration events</button><button :disabled="busy || disabled || registry.next_offset === null" @click="listPage(true)">Next integration events</button></nav></template>
    <section v-if="selected" aria-label="Selected pipeline integration observation"><p>{{ selected.source_version }} → {{ selected.target_version }} · event {{ selected.event_id }}</p><p><strong>Integration: producer declared, not verified.</strong> Commit proof: {{ human(selected.git_ancestry.status) }}</p><details><summary>Declared commits and proof limits</summary><p>Source {{ selected.source_pin.repository }} · {{ selected.source_pin.commit }}</p><p>Target {{ selected.target_pin.repository }} · {{ selected.target_pin.commit }} · {{ selected.target_pin.subject_digest }}</p><p>{{ selected.declaration.rationale }}</p><p>{{ selected.git_ancestry.verification }}</p><ul><li v-for="limit in [...selected.limitations, ...selected.git_ancestry.limitations]" :key="limit">{{ limit }}</li></ul><pre>{{ JSON.stringify(selected, null, 2) }}</pre></details>
      <fieldset :disabled="busy || disabled || !!captured"><details><summary>Explicit synchronization basis and context mapping</summary><label>Integration comparison basis (optional state SHA)<input v-model="basis" maxlength="64" placeholder="No inferred common basis"></label><label>Integration context mapping JSON<textarea v-model="mapping" rows="3" spellcheck="false" /></label></details></fieldset>
      <button v-if="!captured" :disabled="busy || disabled || stale" @click="preview()">Preview event-bound assessment comparison</button><button v-else :disabled="busy || disabled" @click="preview(attemptedOffset)">Retry captured integration preview</button><button v-if="captured" :disabled="busy || disabled" @click="discard">Discard integration preview</button>
    </section>
    <section v-if="result" aria-label="Integration assessment comparison"><p>{{ human(result.basis_selection) }} · {{ result.proposals.total }} scoped proposals · no changes published</p><p class="hint">Content comparison only. No automatic draft, assessment, approval or score transfer is available.</p><p>{{ Object.entries(result.proposals.summary.by_category).map(([key, count]) => `${human(key)}: ${count}`).join(' · ') }}</p><article v-for="row in result.proposals.items" :key="row.id"><strong>{{ row.vulnerability_id || 'Unresolved assessment scope' }} · {{ human(row.category) }}</strong><p>{{ row.reasons.map(human).join(' · ') }}</p><details><summary>Exact proposal scope and evidence</summary><pre>{{ JSON.stringify(row, null, 2) }}</pre></details></article><nav><button :disabled="busy || disabled || !previewPrevious.length" @click="proposalPage(false)">Previous integration proposals</button><button :disabled="busy || disabled || result.proposals.next_offset === null" @click="proposalPage(true)">Next integration proposals</button></nav><details><summary>Captured comparison pins and limits</summary><pre>{{ JSON.stringify(captured?.body, null, 2) }}</pre><code>{{ result.proposals.preview_digest }}</code><ul><li v-for="limit in [...result.limitations, ...result.proposals.limitations]" :key="limit">{{ limit }}</li></ul></details></section>
  </section></details>
</template>
<style scoped>
.integration-events { border-top:1px solid var(--line); margin-top:1rem; padding-top:.8rem; min-width:0 } section,article,fieldset { min-width:0; overflow-wrap:anywhere } fieldset { border:0; padding:0 } label { display:grid; gap:.3rem; margin-block:.5rem } input,textarea { max-width:100%; width:100%; min-width:0; box-sizing:border-box } input[type=radio] { width:auto; justify-self:start } button { margin:.3rem .5rem .3rem 0 } summary { cursor:pointer } pre,code { white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word } pre { max-height:18rem; overflow:auto } article { border-top:1px solid var(--line); padding-block:.5rem }.hint { font-size:.85rem; color:var(--muted) }
</style>
