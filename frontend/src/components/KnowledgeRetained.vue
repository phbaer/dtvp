<script setup lang="ts">
import TaskSurface from './TaskSurface.vue'
import { onBeforeUnmount, ref, watch } from 'vue'
import { justificationLabel } from '../assessmentReasons'
import { knowledgeApi } from '../knowledgeApi'

type Target = { version: string; context_id: string; vulnerability_id: string; team_id?: string; lineage?: { coordinate?: string; component_ref?: string; root_ref?: string } }
type Record = { assessment_id: string; revision: string; availability: 'absent' | 'present' | 'out_of_scope' | 'unknown_scope'; assessment: { revision: string; stage: string; payload: { state: string; rationale: string; justification?: string; author_id?: string; targets?: Target[]; [key: string]: unknown } }; targets: Target[] }
type Retained = { state: string; items: Record[]; total: number; next_offset: number | null }
const props = withDefaults(defineProps<{ project: string; state: string; team?: string }>(), { team: '' })
const expanded = ref(false), busy = ref(false), error = ref(''), result = ref<Retained | null>(null)
const offset = ref(0), previous = ref<number[]>([])
let sequence = 0
const human = (value: string) => value.replaceAll('_', ' ')
async function load(nextOffset = 0) {
  if (!props.project || !props.state) return false
  const request = ++sequence
  busy.value = true; error.value = ''
  try {
    const query = new URLSearchParams({ absent_only: 'true', offset: String(nextOffset), limit: '20' })
    if (props.team) query.set('team_id', props.team)
    const data = await knowledgeApi<Retained>(`/projects/${encodeURIComponent(props.project)}/states/${encodeURIComponent(props.state)}/retained-assessments?${query}`)
    if (request !== sequence) return false
    result.value = data; offset.value = nextOffset
    return true
  } catch (err) { if (request === sequence) error.value = err instanceof Error ? err.message : 'Retained assessment request failed'; return false }
  finally { if (request === sequence) busy.value = false }
}
function toggle(open: boolean) {
  expanded.value = open
  if (expanded.value && !result.value && !busy.value) void load()
}
async function paginate(forward: boolean) {
  const target = forward ? result.value?.next_offset : previous.value.at(-1)
  if (target == null) return
  const prior = offset.value
  if (await load(target)) { if (forward) previous.value.push(prior); else previous.value.pop() }
}
watch(() => [props.project, props.state, props.team], () => {
  ++sequence; result.value = null; previous.value = []; offset.value = 0; busy.value = false; error.value = ''
  if (expanded.value) void load()
})
onBeforeUnmount(() => { ++sequence })
</script>

<template>
  <TaskSurface class="knowledge-retained" @active="toggle" title="Retained assessments for absent findings">
    <section aria-label="Retained absent assessments" :aria-busy="busy">
      <p class="hint">Recorded history for targets absent from this selected state. These records do not establish a current approval.</p>
      <p v-if="error" role="alert">{{ error }}</p>
      <p v-if="busy" role="status">Loading retained assessments…</p>
      <template v-if="result">
        <p aria-label="Retained assessment total"><strong>{{ result.total }}</strong> retained assessments in this scope</p>
        <p v-if="result.total === 0" role="status">No retained absent assessments in this scope.</p>
        <article v-for="item in result.items" :key="`${item.assessment_id}:${item.revision}`" class="retained-row">
          <header><strong>{{ item.targets[0]?.vulnerability_id || item.assessment_id }}</strong><span>Recorded {{ human(item.assessment.payload.state) }} · {{ human(item.assessment.stage) }}</span></header>
          <small class="retained-scope">{{ item.targets[0]?.version || 'Version not recorded' }} · Recorded team {{ item.targets[0]?.team_id || 'unknown' }}<template v-if="item.targets[0]?.lineage?.coordinate"> · {{ item.targets[0].lineage?.coordinate }}</template><template v-else-if="item.targets[0]?.lineage?.component_ref"> · {{ item.targets[0].lineage?.component_ref }}</template></small>
          <p v-if="item.assessment.payload.state === 'not_affected'" class="retained-reason">{{ justificationLabel(item.assessment.payload.justification) }}</p>
          <p class="retained-rationale">{{ item.assessment.payload.rationale || 'No rationale recorded.' }}</p>
          <details><summary>Recorded scope and full assessment</summary><p v-if="item.targets.length > 1" class="hint">Additional recorded targets are included below.</p><pre>{{ JSON.stringify({ availability: item.availability, revision: item.revision, targets: item.targets, assessment: item.assessment }, null, 2) }}</pre></details>
        </article>
        <nav v-if="result.total > 0" aria-label="Retained assessment pages"><button :disabled="busy || previous.length === 0" @click="paginate(false)">Previous retained assessments</button><button :disabled="busy || result.next_offset === null" @click="paginate(true)">Next retained assessments</button></nav>
      </template>
      <button v-if="error && !result" :disabled="busy" @click="load()">Retry retained assessments</button>
    </section>
  </TaskSurface>
</template>

<style scoped>
.knowledge-retained { margin-block: .75rem; padding: .7rem .9rem; border: 1px solid var(--border, #64748b55); border-radius: .65rem; min-width: 0; }
.knowledge-retained > summary { cursor: pointer; font-weight: 600; }
.knowledge-retained section { padding-top: .35rem; min-width: 0; }
.retained-row { border-top: 1px solid var(--border, #64748b33); padding-block: .65rem; overflow-wrap: anywhere; }
.retained-row header { display: flex; flex-wrap: wrap; gap: .35rem 1rem; align-items: baseline; }
.retained-row header span, .retained-scope { font-size: .85rem; opacity: .8; }
.retained-scope { display: block; margin-top: .3rem; }
.retained-rationale { white-space: pre-wrap; margin-block: .45rem; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
.retained-reason { margin-block: .45rem; font-size: .9rem; }
.retained-row details { font-size: .85rem; }
.retained-row pre { max-height: 24rem; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
.knowledge-retained nav { display: flex; flex-wrap: wrap; gap: .6rem; margin-top: .65rem; }
</style>
