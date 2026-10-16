<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { knowledgeApi } from '../knowledgeApi'
type Match = { kind: 'component'; source_id: string; target_id: string; basis: string; scope: { part_id: string | null; role: string } }
type Report = { format: string; source: string; target: string; report_digest: string; summary: Record<string, number | boolean>; items: Match[]; total: number; next_offset: number | null; unresolved: { current_ref: string; reason: string; candidate_count?: number; conflicts?: string[] }[]; diagnostics_truncated: boolean; limitations: string[] }
const props = defineProps<{ project: string; source: string; target: string; disabled?: boolean }>()
const report = ref<Report | null>(null), busy = ref(false), error = ref(''), offset = ref(0), previous = ref<number[]>([])
let generation = 0
const human = (text: string) => text.replaceAll('_', ' ')
function reset() { ++generation; report.value = null; busy.value = false; error.value = ''; offset.value = 0; previous.value = [] }
async function load(page = 0, refresh = false): Promise<boolean> {
  if (busy.value || props.disabled || !props.project || !props.source || !props.target) return false
  if (refresh) reset()
  const current = generation, source = props.source, target = props.target, project = props.project
  busy.value = true; error.value = ''
  try {
    const params = new URLSearchParams({ source, offset: String(page), limit: '20' })
    const data = await knowledgeApi<Report>(`/projects/${encodeURIComponent(project)}/states/${encodeURIComponent(target)}/identity-matches?${params}`)
    if (current !== generation) return false
    if (data.format !== 'dtvp.identity-matches/1' || data.source !== source || data.target !== target) throw new Error('Identity report does not match the selected immutable states.')
    if (!/^[a-f0-9]{64}$/.test(data.report_digest)) throw new Error('Identity report is missing a valid content digest.')
    if (report.value && report.value.report_digest !== data.report_digest) throw new Error('Identity report changed between pages. Refresh explicitly before inspecting a different report.')
    report.value = data; offset.value = page; return true
  } catch (value) { if (current === generation) error.value = value instanceof Error ? value.message : 'Identity comparison unavailable'; return false }
  finally { if (current === generation) busy.value = false }
}
async function page(next: boolean) {
  const selected = next ? report.value?.next_offset : previous.value.at(-1)
  if (selected == null) return
  const before = offset.value, current = generation
  if (await load(selected) && current === generation) { if (next) previous.value.push(before); else previous.value.pop() }
}
watch(() => [props.project, props.source, props.target], reset)
onBeforeUnmount(() => { ++generation })
</script>
<template>
  <details class="identity-matches"><summary>Component identity continuity</summary>
    <section aria-label="Component identity comparison">
      <p class="hint">Compare exact package or artifact markers within matching delivery scopes. This read-only report does not merge components or transfer assessments, ownership or approvals.</p>
      <p v-if="!source" class="hint">Select a source branch, tag or historical state above.</p>
      <button type="button" :disabled="busy || disabled || !source || !target" @click="load(0, true)">Inspect component identity matches</button>
      <p v-if="busy" role="status">Comparing component identities…</p><p v-if="error" role="alert">{{ error }}</p>
      <template v-if="report">
        <p>{{ Object.entries(report.summary).map(([key, count]) => `${human(key)}: ${count}`).join(' · ') }}</p>
        <p>{{ report.total }} uniquely matched occurrences · no changes published</p>
        <article v-for="item in report.items" :key="item.source_id + ':' + item.target_id">
          <strong>{{ human(item.basis) }}</strong><p><code>{{ item.source_id }}</code> → <code>{{ item.target_id }}</code></p>
          <small>{{ human(item.scope.role) }} · {{ item.scope.part_id || 'Single delivery scope' }}</small>
        </article>
        <nav aria-label="Identity match pages"><button type="button" :disabled="busy || disabled || !previous.length" @click="page(false)">Previous identity matches</button><button type="button" :disabled="busy || disabled || report.next_offset == null" @click="page(true)">Next identity matches</button></nav>
        <details v-if="report.unresolved.length || report.diagnostics_truncated"><summary>Unresolved component markers (bounded sample)</summary><p v-if="report.diagnostics_truncated" role="status">Only the first 100 unresolved diagnostics are shown; summary counts cover the complete comparison.</p><article v-for="(item, index) in report.unresolved" :key="index"><strong>{{ item.current_ref }}</strong><p>{{ human(item.reason) }}</p><small v-if="item.candidate_count != null">Candidate count: {{ item.candidate_count }}</small><p v-if="item.conflicts?.length">{{ item.conflicts.map(human).join(' · ') }}</p></article></details>
        <details><summary>Identity comparison pins and limits</summary><p>Source <code>{{ report.source }}</code></p><p>Target <code>{{ report.target }}</code></p><p>Report <code>{{ report.report_digest }}</code></p><p v-for="limit in report.limitations" :key="limit">{{ limit }}</p></details>
      </template>
    </section>
  </details>
</template>
<style scoped>
.identity-matches { border-top:1px solid var(--line); margin-top:1rem; padding-top:.8rem; min-width:0 } section,article,nav { min-width:0; overflow-wrap:anywhere } article { border-top:1px solid var(--line); padding-block:.5rem } code { white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word; font-size:.75rem } button { margin:.3rem .5rem .3rem 0 } summary { cursor:pointer } .hint,small { font-size:.85rem; color:var(--muted) }
</style>
