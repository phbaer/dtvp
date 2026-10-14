<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api, send } from '../api'
import type { Finding, RescoreProposal, RescoreRequest } from '../types'
import RescoreEditor from './RescoreEditor.vue'
const props = defineProps<{ finding: Finding; busy: boolean }>()
const emit = defineEmits<{ refresh: []; teamsChanged: [] }>()
const score = ref<RescoreRequest | null>(null), preview = ref<RescoreProposal | null>(null)
const error = ref(''), saving = ref(false), editing = ref(false)
const teams = ref<{id: string; name: string}[]>([]), selected = ref<string[]>([])
const coverage = computed(() => props.finding.review_coverage)
watch(() => props.finding.state_version, () => { score.value = null; preview.value = null; editing.value = false })
async function editTeams() {
  error.value = ''
  try {
    teams.value = (await api<{items: {id: string; name: string}[]}>(`/findings/${props.finding.id}/review-teams`)).items
    selected.value = coverage.value.teams.map(team => team.workspace_id); editing.value = true
  } catch (err) { error.value = err instanceof Error ? err.message : 'Teams unavailable' }
}
async function saveTeams() {
  saving.value = true; error.value = ''
  try {
    await api(`/findings/${props.finding.id}/review-teams`, { method: 'PUT', body: JSON.stringify({expected_version: props.finding.state_version, workspace_ids: selected.value}) })
    editing.value = false; emit('teamsChanged')
  } catch (err) { error.value = err instanceof Error ? err.message : 'Team assignment failed' }
  finally { saving.value = false }
}
async function publish() {
  saving.value = true; error.value = ''
  try {
    await api(`/findings/${props.finding.id}/rescoring`, send({expected_version: props.finding.state_version, rescoring: score.value}))
    emit('refresh')
  } catch (err) { error.value = err instanceof Error ? err.message : 'Publication failed' }
  finally { saving.value = false }
}
</script>
<template>
  <section class="assessment-column">
    <h2>Required team reviews</h2>
    <p class="hint">Each team assesses and independently approves this occurrence. Rescoring unlocks when every required team has approved the current evidence.</p>
    <ul class="team-reviews"><li v-for="team in coverage.teams" :key="team.workspace_id"><strong>{{ team.team }}</strong> <span class="badge" :class="team.status">{{ team.status.replaceAll('_', ' ') }}</span><small v-if="team.state">{{ team.state.replaceAll('_', ' ') }}</small></li></ul>
    <template v-if="finding.capabilities.includes('manage')">
      <button v-if="!editing" :disabled="busy || saving" @click="editTeams">Change required teams</button>
      <fieldset v-else><legend>Required teams</legend><label v-for="team in teams" :key="team.id" class="toggle"><input v-model="selected" type="checkbox" :value="team.id" :disabled="busy || saving">{{ team.name }}</label><p class="hint">Changing responsibility requires fresh team assessments and invalidates prior scoring.</p><button :disabled="busy || saving || !selected.length" @click="saveTeams">Save required teams</button><button :disabled="saving" @click="editing = false">Cancel</button></fieldset>
    </template>
    <template v-if="finding.capabilities.includes('rescore')">
      <h2>Coordinator rescoring</h2>
      <p v-if="!coverage.ready || !finding.active" class="hint">Waiting for required team reviews.</p>
      <template v-else><p class="hint">Consolidated applicability: {{ coverage.state.replaceAll('_', ' ') }}. Original source scores remain unchanged.</p><RescoreEditor :key="finding.state_version" :finding="finding" :state="coverage.state" v-model="score" :disabled="busy || saving" assessment-rationale="" @preview="preview = $event" /><button class="primary" :disabled="busy || saving || !score || !preview" @click="publish">Publish contextual score</button></template>
    </template>
    <section v-if="finding.adopted_rescoring" class="score-preview"><h3>Published contextual score</h3><p>CVSS {{ finding.adopted_rescoring.version }} · {{ finding.adopted_rescoring.base_score }} → {{ finding.adopted_rescoring.score }}</p><p>{{ finding.adopted_rescoring.rationale }}</p></section>
    <details v-if="finding.rescoring_history.length"><summary>Scoring history</summary><article v-for="record in finding.rescoring_history" :key="record.id"><p>{{ new Date(record.created_at).toLocaleString() }} · {{ record.proposal.score }} · Evidence revision {{ record.evidence_revision }}</p><p>{{ record.proposal.rationale }}</p><code>{{ record.proposal.vector }}</code></article></details>
    <p v-if="error" role="alert" class="warning">{{ error }}</p>
  </section>
</template>
