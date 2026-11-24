<script setup lang="ts">
// The teams as collapsible cards: aliases, projects and component entries,
// each entry with what it matches and its flags. Edits change ``teams`` in
// place (the editor owns the draft).
import { computed, nextTick, ref, watch } from 'vue'
import { ChevronDown, ChevronRight, Trash2, X } from '@lucide/vue'
import type { Team } from '../../lib/team-config'
import type { TeamMapping } from '../../lib/team-mapping'
import {
    componentCompletions,
    insightKey,
    previewSelector,
    projectCompletions,
    type EntryInsight,
    type Inventory,
    type MappingReport,
} from '../../lib/team-mapping-insights'
import { plural } from '../../lib/team-mapping-editing'
import TeamChip from './TeamChip.vue'

const props = defineProps<{
    teams: Team[]
    report: MappingReport | null
    inventory: Inventory
    mapping: TeamMapping
    insights: Map<string, EntryInsight>
    selectedEntry: { team: string; key: string } | null
    focusTeam: string | null
}>()
const emit = defineEmits<{
    select: [entry: { team: string; key: string } | null]
    remove: [team: Team]
    add: []
}>()

const query = ref('')
const projectFilter = ref('')
const flaggedOnly = ref(false)
const open = ref(new Set<string>())
const cardIds = new WeakMap<Team, string>()
let nextCardId = 1
const cardId = (team: Team) => {
    if (!cardIds.has(team)) cardIds.set(team, `team-card-${nextCardId++}`)
    return cardIds.get(team)!
}

const flagsOf = (team: Team, key: string) => props.insights.get(insightKey(team.name, key))?.flags || []
const teamFlagCount = (team: Team) => team.components.reduce((sum, key) => sum + flagsOf(team, key).length, 0)

const ownedFindings = (team: Team): string => {
    if (!props.report) return 'findings not known yet'
    const entries = props.report.entries
    return plural(team.components.reduce((sum, key) => sum + (entries[key]?.findings || 0), 0)
        + team.projects.reduce((sum, name) => sum + (entries[`project::${name}`]?.findings || 0), 0), 'finding')
}
const entryCount = (team: Team) => team.components.filter(key => key !== '*').length

const matchesProject = (team: Team, project: string) => {
    const needle = project.toLowerCase()
    return team.projects.some(name => name.toLowerCase() === needle)
        || team.components.some(key => (props.insights.get(insightKey(team.name, key))?.preview.projects || [])
            .some(name => name.toLowerCase() === needle))
}

const visibleTeams = computed(() => {
    const needle = query.value.trim().toLowerCase()
    return props.teams.filter((team) => {
        if (needle && ![team.name, ...team.aliases, ...team.projects, ...team.components]
            .some(text => text.toLowerCase().includes(needle))) return false
        if (projectFilter.value && !matchesProject(team, projectFilter.value)) return false
        if (flaggedOnly.value && teamFlagCount(team) === 0) return false
        return true
    })
})

const toggle = (team: Team) => {
    const id = cardId(team)
    const next = new Set(open.value)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    open.value = next
}

watch(() => props.focusTeam, async (name) => {
    const team = props.teams.find(item => item.name === name)
    if (!team) return
    query.value = ''
    flaggedOnly.value = false
    projectFilter.value = ''
    open.value = new Set([...open.value, cardId(team)])
    await nextTick()
    document.getElementById(cardId(team))?.scrollIntoView?.({ block: 'center', behavior: 'smooth' })
})

// -- editing ------------------------------------------------------------------

const newProject = ref<Record<string, string>>({})
const newComponent = ref<Record<string, string>>({})
const projectNames = computed(() => (props.report?.projects || []).map(project => project.name))

const aliasesText = (team: Team) => team.aliases.join(', ')
const setAliases = (team: Team, text: string) => {
    team.aliases = text.split(',').map(item => item.trim()).filter(Boolean)
}
const addProject = (team: Team) => {
    const id = cardId(team)
    const name = (newProject.value[id] || '').trim()
    if (name && !team.projects.includes(name)) team.projects.push(name)
    newProject.value = { ...newProject.value, [id]: '' }
}
const addComponent = (team: Team) => {
    const id = cardId(team)
    const key = (newComponent.value[id] || '').trim()
    if (key && !team.components.includes(key)) team.components.push(key)
    newComponent.value = { ...newComponent.value, [id]: '' }
}
const removeFrom = (list: string[], value: string) => {
    const index = list.indexOf(value)
    if (index >= 0) list.splice(index, 1)
}

const draftPreview = (team: Team) => {
    const key = (newComponent.value[cardId(team)] || '').trim()
    // Ranked against the mapping with the typed entry in it.
    return key ? previewSelector(key, props.inventory, { ...props.mapping, [key]: team.name || 'new team' }) : null
}
const overriddenText = (overriddenBy: Map<string, number>) =>
    [...overriddenBy.entries()].map(([key, count]) => `${key} (${count})`).join(', ')

const describe = (team: Team, key: string) => {
    if (key === '*') return 'catch-all: every finding no entry or project owns'
    const preview = props.insights.get(insightKey(team.name, key))?.preview
    if (!preview) return ''
    const owned = props.report?.entries[key]?.findings
    return [
        `${plural(preview.matched.length, 'component')} in ${plural(preview.projects.length, 'project')}`,
        owned !== undefined ? `owns ${plural(owned, 'finding')}` : '',
        preview.unownedBelow ? `${preview.unownedBelow} unowned below` : '',
    ].filter(Boolean).join(' · ')
}

const isSelected = (team: Team, key: string) =>
    props.selectedEntry?.team === team.name && props.selectedEntry?.key === key
const select = (team: Team, key: string) =>
    emit('select', isSelected(team, key) ? null : { team: team.name, key })

const FLAG_STYLE: Record<string, string> = {
    invalid: 'bg-red-900/60 text-red-200',
    stale: 'bg-gray-700 text-gray-200',
    broad: 'bg-amber-900/60 text-amber-200',
    shadowed: 'bg-purple-900/60 text-purple-200',
    duplicate: 'bg-orange-900/60 text-orange-200',
    disagreement: 'bg-red-900/40 text-red-200',
}
</script>

<template>
  <section data-testid="team-cards">
    <div class="mb-3 flex flex-wrap items-center gap-2">
      <label for="team-cards-search" class="sr-only">Search teams, aliases, entries</label>
      <input
        id="team-cards-search"
        v-model="query"
        data-testid="team-cards-search"
        placeholder="Search teams, aliases, entries"
        class="min-w-[14rem] flex-1 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-100"
      />
      <select v-model="projectFilter" class="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-100" aria-label="Filter by project">
        <option value="">All projects</option>
        <option v-for="name in projectNames" :key="name" :value="name">{{ name }}</option>
      </select>
      <label class="flex items-center gap-1 text-xs text-gray-300">
        <input v-model="flaggedOnly" type="checkbox" class="accent-blue-500" data-testid="team-cards-flagged" />
        Flagged entries only
      </label>
      <button type="button" class="rounded bg-blue-600 px-3 py-1 text-xs font-semibold text-white hover:bg-blue-700" @click="emit('add')">
        Add team
      </button>
    </div>

    <div class="grid items-start gap-2 xl:grid-cols-2">
      <article
        v-for="team in visibleTeams"
        :id="cardId(team)"
        :key="cardId(team)"
        :data-testid="`team-card-${team.name}`"
        class="rounded border border-gray-700 bg-gray-800"
      >
        <header class="flex items-center gap-2 px-3 py-2">
          <button type="button" class="text-gray-400 hover:text-gray-200" :aria-expanded="open.has(cardId(team))" :aria-label="`Toggle ${team.name || 'new team'}`" @click="toggle(team)">
            <ChevronDown v-if="open.has(cardId(team))" :size="14" />
            <ChevronRight v-else :size="14" />
          </button>
          <TeamChip :team="team.name || 'new team'" :kind="team.components.includes('*') ? 'wildcard' : 'component'" />
          <span v-if="team.components.includes('*')" class="text-[11px] text-gray-300">owns the catch-all</span>
          <span v-if="team.aliases.length" class="truncate text-[11px] text-gray-400">formerly {{ team.aliases.join(', ') }}</span>
          <span class="ml-auto text-[11px] text-gray-300">
            {{ plural(team.projects.length, 'project') }} · {{ plural(entryCount(team), 'entry', 'entries') }} · {{ ownedFindings(team) }}
          </span>
          <span v-if="teamFlagCount(team)" class="rounded bg-amber-900/60 px-1.5 text-[10px] font-semibold text-amber-200" :title="`${teamFlagCount(team)} flags`">
            {{ teamFlagCount(team) }} flagged
          </span>
        </header>

        <div v-if="open.has(cardId(team))" class="space-y-3 border-t border-gray-700 px-3 py-2 text-xs">
          <div class="grid gap-2 md:grid-cols-2">
            <label class="text-gray-300">Team
              <input v-model="team.name" :data-testid="`team-name-${team.name}`" class="mt-0.5 w-full rounded border border-gray-700 bg-gray-900 px-2 py-1 text-gray-100" />
            </label>
            <label class="text-gray-300">Aliases (former names, comma separated)
              <input :value="aliasesText(team)" class="mt-0.5 w-full rounded border border-gray-700 bg-gray-900 px-2 py-1 text-gray-100" @change="setAliases(team, ($event.target as HTMLInputElement).value)" />
            </label>
          </div>

          <div>
            <div class="mb-1 font-semibold text-gray-200">Projects <span class="font-normal text-gray-400">— own the project's findings no component entry owns</span></div>
            <div class="flex flex-wrap gap-1">
              <span v-for="name in team.projects" :key="name" class="inline-flex items-center gap-1 rounded border border-gray-600 bg-gray-900 px-2 py-0.5">
                {{ name }}
                <span class="text-gray-400" :title="'Findings it owns'">{{ report?.entries[`project::${name}`]?.findings ?? '–' }}</span>
                <button type="button" class="text-gray-400 hover:text-red-300" :aria-label="`Remove project ${name}`" @click="removeFrom(team.projects, name)"><X :size="12" /></button>
              </span>
            </div>
            <div class="mt-1 flex gap-1">
              <input
                v-model="newProject[cardId(team)]"
                :list="`${cardId(team)}-projects`"
                placeholder="Dependency-Track project"
                class="flex-1 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-gray-100"
                @keydown.enter.prevent="addProject(team)"
              />
              <datalist :id="`${cardId(team)}-projects`">
                <option v-for="name in projectCompletions(newProject[cardId(team)] || '', projectNames)" :key="name" :value="name" />
              </datalist>
              <button type="button" class="rounded bg-gray-700 px-2 text-gray-100 hover:bg-gray-600" @click="addProject(team)">Add project</button>
            </div>
          </div>

          <div>
            <div class="mb-1 font-semibold text-gray-200">Component entries</div>
            <ul class="space-y-1">
              <li
                v-for="key in team.components"
                :key="key"
                :data-testid="`team-entry-${key}`"
                :class="['rounded border px-2 py-1', isSelected(team, key) ? 'border-amber-400 bg-amber-900/20' : 'border-gray-700']"
              >
                <div class="flex items-center gap-2">
                  <button type="button" class="truncate font-mono text-blue-300 hover:underline" :title="'Show its matches in the projects view'" @click="select(team, key)">{{ key }}</button>
                  <span
                    v-for="flag in flagsOf(team, key)"
                    :key="flag.kind + flag.message"
                    :class="['rounded px-1 text-[10px] font-semibold', FLAG_STYLE[flag.kind]]"
                    :title="flag.message"
                  >{{ flag.kind }}</span>
                  <button type="button" class="ml-auto text-gray-400 hover:text-red-300" :aria-label="`Remove ${key}`" @click="removeFrom(team.components, key)"><X :size="12" /></button>
                </div>
                <div class="text-[11px] text-gray-400">{{ describe(team, key) }}</div>
              </li>
            </ul>
            <div class="mt-1 flex gap-1">
              <input
                v-model="newComponent[cardId(team)]"
                :list="`${cardId(team)}-components`"
                :data-testid="`team-add-component-${team.name}`"
                placeholder="name, group:name, purl::pkg:…, project:<project>::name"
                class="flex-1 rounded border border-gray-700 bg-gray-900 px-2 py-1 font-mono text-gray-100"
                @keydown.enter.prevent="addComponent(team)"
              />
              <datalist :id="`${cardId(team)}-components`">
                <option v-for="item in componentCompletions(newComponent[cardId(team)] || '', inventory)" :key="item" :value="item" />
              </datalist>
              <button type="button" class="rounded bg-gray-700 px-2 text-gray-100 hover:bg-gray-600" @click="addComponent(team)">Add component</button>
            </div>
            <div v-if="draftPreview(team)" :data-testid="`team-draft-preview-${team.name}`" class="mt-1 text-[11px] text-gray-400">
              <template v-if="draftPreview(team)!.selector.error">
                <span class="text-red-400">{{ draftPreview(team)!.selector.error }}</span>
              </template>
              <template v-else>
                Matches {{ plural(draftPreview(team)!.matched.length, 'component') }} in {{ plural(draftPreview(team)!.projects.length, 'project') }}
                <span v-if="draftPreview(team)!.projects.length">({{ draftPreview(team)!.projects.slice(0, 5).join(', ') }}<span v-if="draftPreview(team)!.projects.length > 5">, …</span>)</span>,
                {{ plural(draftPreview(team)!.findingsBelow, 'finding') }} below, {{ draftPreview(team)!.unownedBelow }} unowned.
                <span v-if="draftPreview(team)!.overriddenBy.size" class="text-purple-300">
                  More specific entries win {{ overriddenText(draftPreview(team)!.overriddenBy) }}.
                </span>
              </template>
            </div>
          </div>

          <div class="flex justify-end">
            <button type="button" class="inline-flex items-center gap-1 text-red-300 hover:text-red-200" @click="emit('remove', team)">
              <Trash2 :size="12" /> Remove team
            </button>
          </div>
        </div>
      </article>
    </div>
    <p v-if="!visibleTeams.length" class="text-xs text-gray-300">{{ teams.length ? 'No team matches the filter.' : 'No teams yet. Add one, or assign unowned components to a new team.' }}</p>
  </section>
</template>
