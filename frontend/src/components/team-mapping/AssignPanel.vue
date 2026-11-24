<script setup lang="ts">
// "Assign to a team" for the components and projects picked in the
// coverage browser: each with its entry (suggested, editable) and what the
// entry matches in plain words, a team picked from the existing ones or
// created, and the effect on findings, previewed while the draft changes.
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { X } from '@lucide/vue'
import { previewTeamMapping } from '../../lib/api'
import { documentFromTeams, type Team } from '../../lib/team-config'
import { describeEntry, plural } from '../../lib/team-mapping-editing'
import { assignEntries, entryFromKey, type MappingPreview, type SuggestedEntry } from '../../lib/team-mapping-insights'
import TeamCombobox from './TeamCombobox.vue'

export interface PickedItem {
    id: string
    /** The component or project, for people. */
    name: string
    project: string
    /** The entry in selector syntax; ``project::X`` owns the project. */
    key: string
}

const props = defineProps<{ picked: PickedItem[]; teams: Team[] }>()
const emit = defineEmits<{
    unpick: [id: string]
    cancel: []
    'update-key': [id: string, key: string]
    apply: [team: string, entries: SuggestedEntry[]]
}>()

const team = ref('')
const entries = computed(() => props.picked.map(item => entryFromKey(item.key.trim())))
const descriptions = computed(() => props.picked.map(item => describeEntry(item.key)))
const invalid = computed(() => descriptions.value.some(item => item.error))
const canApply = computed(() => Boolean(team.value.trim()) && props.picked.length > 0 && !invalid.value)

// -- the effect, previewed while the draft changes ---------------------------

const preview = ref<MappingPreview | null>(null)
const previewing = ref(false)
const previewError = ref('')
let timer: ReturnType<typeof setTimeout> | null = null
let request = 0

const runPreview = async () => {
    const current = ++request
    if (!canApply.value) {
        preview.value = null
        previewing.value = false
        return
    }
    previewing.value = true
    previewError.value = ''
    try {
        const draft = documentFromTeams(assignEntries(props.teams, team.value, entries.value))
        // Projects and project-scoped entries change only their projects.
        const scoped = entries.value.every(entry => entry.kind === 'project' || entry.value.toLowerCase().startsWith('project:'))
        const projects = scoped ? [...new Set(props.picked.map(item => item.project).filter(Boolean))] : undefined
        const result = await previewTeamMapping(draft, projects)
        if (current === request) preview.value = result
    } catch (err: any) {
        if (current === request) previewError.value = err?.response?.data?.detail || err?.message || 'The preview failed.'
    } finally {
        if (current === request) previewing.value = false
    }
}

watch([team, () => props.picked.map(item => item.key).join('\n'), () => props.teams], () => {
    preview.value = null
    previewError.value = ''
    if (timer) clearTimeout(timer)
    previewing.value = canApply.value
    timer = setTimeout(runPreview, 400)
}, { immediate: true, deep: true })
onBeforeUnmount(() => {
    if (timer) clearTimeout(timer)
    request += 1
})

// Opening below the tree, the panel scrolls into view as far as needed.
const panel = ref<HTMLElement | null>(null)
onMounted(() => panel.value?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' }))

const apply = () => {
    if (!canApply.value) return
    emit('apply', team.value.trim(), entries.value)
}

const heading = computed(() => props.picked.length === 1
    ? `Assign ${props.picked[0].name} to a team`
    : `Assign ${props.picked.length} picks to a team`)
</script>

<template>
  <section ref="panel" data-testid="assign-panel" aria-labelledby="assign-panel-heading" class="mt-4 rounded border border-blue-700 bg-blue-950/30 p-3 text-xs">
    <div class="mb-2 flex items-center gap-2">
      <h5 id="assign-panel-heading" class="font-semibold text-gray-100">{{ heading }}</h5>
      <button type="button" data-testid="assign-cancel" class="ml-auto rounded px-2 py-0.5 text-gray-300 hover:bg-gray-700 hover:text-white" @click="emit('cancel')">
        Cancel
      </button>
    </div>
    <ul class="mb-3 space-y-2">
      <li v-for="(item, index) in picked" :key="item.id" class="rounded border border-gray-700 bg-gray-900/60 p-2">
        <div class="flex items-center gap-2">
          <span class="font-medium text-gray-100">{{ item.name }}</span>
          <span v-if="item.project" class="text-gray-400">in {{ item.project }}</span>
          <button
            v-if="picked.length > 1"
            type="button"
            class="ml-auto rounded p-0.5 text-gray-400 hover:bg-gray-700 hover:text-white"
            :aria-label="`Leave ${item.name} out`"
            :title="`Leave ${item.name} out`"
            @click="emit('unpick', item.id)"
          ><X :size="14" /></button>
        </div>
        <label class="mt-1 flex flex-wrap items-center gap-2 text-gray-300">
          <span class="w-12 shrink-0">Entry</span>
          <input
            :value="item.key"
            :data-testid="`assign-entry-${item.name}`"
            spellcheck="false"
            :aria-describedby="`assign-entry-help-${index}`"
            class="min-w-[14rem] flex-1 rounded border border-gray-600 bg-gray-900 px-2 py-0.5 font-mono text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
            @input="emit('update-key', item.id, ($event.target as HTMLInputElement).value)"
          />
        </label>
        <p :id="`assign-entry-help-${index}`" :class="['mt-1 pl-14', descriptions[index].error ? 'text-red-300' : 'text-gray-300']">
          {{ descriptions[index].error || `Owns: ${descriptions[index].text}.` }}
        </p>
      </li>
    </ul>

    <div class="flex flex-wrap items-end gap-3">
      <div class="w-64">
        <TeamCombobox v-model="team" :teams="teams" label="Team" testid="assign-team" />
      </div>
      <button
        type="button"
        data-testid="assign-apply"
        :disabled="!canApply"
        class="rounded bg-blue-600 px-3 py-1.5 font-semibold text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
        @click="apply"
      >Add to {{ team.trim() || 'team' }}</button>
    </div>

    <div class="mt-3 border-t border-gray-700 pt-2" aria-live="polite" data-testid="assign-preview-result">
      <p v-if="!team.trim()" class="text-gray-300">Choose a team to see how many findings change owner.</p>
      <p v-else-if="invalid" class="text-red-300">Correct the entry to see its effect.</p>
      <p v-else-if="previewing" class="text-gray-300">Working out the effect…</p>
      <p v-else-if="previewError" class="text-red-300">{{ previewError }}</p>
      <template v-else-if="preview">
        <p class="text-gray-200">
          <span class="font-semibold">{{ plural(preview.changed, 'finding') }}</span> of {{ preview.findings }} change owner:
          <span v-for="(move, moveIndex) in preview.moves" :key="`${move.from}-${move.to}`">
            {{ move.from || 'no owner' }} → {{ move.to || 'no owner' }} ({{ move.findings }})<span v-if="moveIndex < preview.moves.length - 1">, </span>
          </span><span v-if="!preview.moves.length">none.</span>
        </p>
        <p v-if="preview.projects.length" class="mt-0.5 text-gray-400">
          In {{ preview.projects.map(project => `${project.name} (${project.changed})`).join(', ') }}. Compared with the saved mapping; nothing is saved yet.
        </p>
      </template>
    </div>
  </section>
</template>
