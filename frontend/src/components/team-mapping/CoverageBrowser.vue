<script setup lang="ts">
// The coverage browser, in two views the editor switches between:
// "projects" (the projects by coverage on the left, a version's BOM tree on
// the right, loaded one level at a time with each component's owner and
// findings) and "unowned" (the project roots and topmost components above
// the findings no team owns, across projects). Picked components and rows
// open "Assign to a team". With a draft, the tree shows the draft's owners
// and marks those that differ from the saved mapping.
import { computed, nextTick, reactive, ref, useId, watch } from 'vue'
import { getTeamMappingTree } from '../../lib/api'
import type { Team, TeamEntry } from '../../lib/team-config'
import type { TeamMappingSelector } from '../../lib/team-mapping'
import { plural } from '../../lib/team-mapping-editing'
import {
    selectorMatchesItem,
    suggestEntry,
    type MappingReport,
    type ReportProject,
    type SuggestedEntry,
    type TreeNode,
    type UnmappedRow,
} from '../../lib/team-mapping-insights'
import AssignPanel, { type PickedItem } from './AssignPanel.vue'
import CoverageTreeRow from './CoverageTreeRow.vue'

export interface AssignFeedback {
    text: string
    canUndo: boolean
}

const props = defineProps<{
    report: MappingReport | null
    teams: Team[]
    mode: 'projects' | 'unowned'
    highlight: { key: string; selector: TeamMappingSelector; projects: string[] } | null
    focusProject: string | null
    /** A project to pick for assignment (from the checks). */
    pickProject: string | null
    /** The draft when it differs from the saved mapping. */
    draft: Record<string, TeamEntry> | null
    feedback: AssignFeedback | null
}>()
const emit = defineEmits<{
    assign: [team: string, entries: SuggestedEntry[]]
    undo: []
    'dismiss-feedback': []
}>()

const uid = useId()
const projectQuery = ref('')
const belowFullOnly = ref(false)
const unownedOnly = ref(false)

const coverage = (project: ReportProject) =>
    project.findings ? (project.findings - project.unmapped) / project.findings : 1
const percent = (project: ReportProject) => Math.floor(coverage(project) * 100)

const projects = computed(() => {
    const needle = projectQuery.value.trim().toLowerCase()
    return [...(props.report?.projects || [])]
        .filter(project => !needle || project.name.toLowerCase().includes(needle))
        .filter(project => !belowFullOnly.value || project.unmapped > 0)
        .sort((left, right) => right.unmapped - left.unmapped || left.name.localeCompare(right.name))
})

const selectedProject = ref<string | null>(null)
const selectedVersion = ref<string | null>(null)
const project = computed(() => props.report?.projects.find(item => item.name === selectedProject.value) || null)

const selectProject = (name: string) => {
    if (selectedProject.value === name) return
    selectedProject.value = name
    const found = props.report?.projects.find(item => item.name === name)
    const versions = found?.versions || []
    selectedVersion.value = versions.length ? versions[versions.length - 1].uuid : null
}

watch(() => props.focusProject, (name) => {
    if (name) selectProject(name)
})
// The projects view opens on the project with the most unowned findings.
watch([() => props.mode, () => props.report], () => {
    if (props.mode === 'projects' && !selectedProject.value && projects.value.length) selectProject(projects.value[0].name)
}, { immediate: true })

// -- the tree --------------------------------------------------------------

interface LevelState { loading: boolean; error: string; nodes: TreeNode[]; total: number }
const root = ref<TreeNode | null>(null)
const rootState = ref<{ loading: boolean; error: string }>({ loading: false, error: '' })
/** Children per component ref ('' is the top of a BOM without a root). */
const levels = reactive(new Map<string, LevelState>())
/** Expanded rows, by path (a component can sit below several parents). */
const expanded = reactive(new Set<string>())

const fetchLevel = (ref?: string) => getTeamMappingTree(selectedVersion.value!, ref, props.draft || undefined)
const errorText = (err: any, fallback: string) => err?.response?.data?.detail || err?.message || fallback

const loadRoot = async () => {
    root.value = null
    levels.clear()
    expanded.clear()
    focusedPath.value = ''
    if (!selectedVersion.value) return
    const version = selectedVersion.value
    rootState.value = { loading: true, error: '' }
    try {
        const level = await fetchLevel()
        if (version !== selectedVersion.value) return
        if (level.root) {
            root.value = level.root
            expanded.add(level.root.ref)
            await loadLevel(level.root.ref)
        } else {
            // No root component: its unlinked components are the top.
            levels.set('', { loading: false, error: '', nodes: level.nodes || [], total: level.total || 0 })
        }
        rootState.value = { loading: false, error: '' }
    } catch (err: any) {
        rootState.value = { loading: false, error: errorText(err, 'Unable to load the tree.') }
    }
}

const loadLevel = async (nodeRef: string) => {
    if (!selectedVersion.value) return
    levels.set(nodeRef, { loading: true, error: '', nodes: [], total: 0 })
    try {
        const level = await fetchLevel(nodeRef)
        levels.set(nodeRef, { loading: false, error: '', nodes: level.nodes || [], total: level.total || 0 })
    } catch (err: any) {
        levels.set(nodeRef, { loading: false, error: errorText(err, 'Unable to load.'), nodes: [], total: 0 })
    }
}

/** Loads what is shown again (the draft changed), keeping what is open. */
const refreshTree = async () => {
    if (!selectedVersion.value || rootState.value.loading) return
    const version = selectedVersion.value
    const open = [...new Set(rows.value.filter(row => row.type === 'node' && expanded.has(row.path)).map(row => row.node!.ref))]
    try {
        const [first, ...rest] = await Promise.all([fetchLevel(), ...open.map(item => fetchLevel(item))])
        if (version !== selectedVersion.value) return
        if (first.root) root.value = first.root
        for (const key of [...levels.keys()]) {
            if (key !== '' && !open.includes(key)) levels.delete(key)
        }
        if (!first.root) levels.set('', { loading: false, error: '', nodes: first.nodes || [], total: first.total || 0 })
        open.forEach((item, index) => {
            levels.set(item, { loading: false, error: '', nodes: rest[index].nodes || [], total: rest[index].total || 0 })
        })
    } catch {
        // Keep what is shown; the next change tries again.
    }
}

watch(selectedVersion, loadRoot)
let draftTimer: ReturnType<typeof setTimeout> | null = null
watch(() => JSON.stringify(props.draft), () => {
    if (draftTimer) clearTimeout(draftTimer)
    draftTimer = setTimeout(refreshTree, 300)
})

const visible = (nodes: TreeNode[]) => unownedOnly.value ? nodes.filter(node => node.unowned > 0) : nodes

interface Row {
    type: 'node' | 'status'
    path: string
    depth: number
    parentPath: string | null
    node?: TreeNode
    text?: string
    posinset: number
    setsize: number
    /** A component already on the way to it (a cycle in the BOM). */
    cycle?: boolean
}

const rows = computed<Row[]>(() => {
    const result: Row[] = []
    const walk = (nodes: TreeNode[], depth: number, parentPath: string | null, ancestors: Set<string>) => {
        nodes.forEach((node, index) => {
            const path = parentPath === null ? node.ref : `${parentPath}\u0000${node.ref}`
            const cycle = ancestors.has(node.ref)
            result.push({ type: 'node', path, depth, parentPath, node, posinset: index + 1, setsize: nodes.length, cycle })
            if (cycle || !expanded.has(path)) return
            const level = levels.get(node.ref)
            if (!level || level.loading) {
                result.push({ type: 'status', path: `${path}\u0001loading`, depth: depth + 1, parentPath: path, text: 'Loading…', posinset: 0, setsize: 0 })
            } else if (level.error) {
                result.push({ type: 'status', path: `${path}\u0001error`, depth: depth + 1, parentPath: path, text: level.error, posinset: 0, setsize: 0 })
            } else {
                walk(visible(level.nodes), depth + 1, path, new Set([...ancestors, node.ref]))
                if (level.total > level.nodes.length) {
                    result.push({
                        type: 'status', path: `${path}\u0001more`, depth: depth + 1, parentPath: path,
                        text: `${level.total - level.nodes.length} more not shown`, posinset: 0, setsize: 0,
                    })
                }
            }
        })
    }
    if (root.value) walk([root.value], 0, null, new Set())
    else walk(visible(levels.get('')?.nodes || []), 0, null, new Set())
    return result
})
const nodeRows = computed(() => rows.value.filter(row => row.type === 'node'))

const toggle = (row: Row) => {
    const node = row.node!
    if (node.children === 0 || row.cycle) return
    if (expanded.has(row.path)) {
        expanded.delete(row.path)
        return
    }
    expanded.add(row.path)
    if (!levels.has(node.ref)) loadLevel(node.ref)
}

// -- focus and keys (the ARIA tree pattern) ----------------------------------

const focusedPath = ref('')
const rowIds = new Map<string, string>()
const rowId = (path: string) => {
    if (!rowIds.has(path)) rowIds.set(path, `${uid}-row-${rowIds.size}`)
    return rowIds.get(path)!
}
const currentPath = computed(() =>
    nodeRows.value.some(row => row.path === focusedPath.value) ? focusedPath.value : (nodeRows.value[0]?.path || ''))

const pendingChildOf = ref('')
watch(nodeRows, (list) => {
    if (!pendingChildOf.value) return
    const child = list.find(row => row.parentPath === pendingChildOf.value)
    if (child) {
        pendingChildOf.value = ''
        focusRow(child.path)
    }
})

const focusRow = async (path: string) => {
    pendingChildOf.value = ''
    focusedPath.value = path
    await nextTick()
    document.getElementById(rowId(path))?.focus()
}

const onTreeKeydown = (event: KeyboardEvent) => {
    const list = nodeRows.value
    const index = list.findIndex(row => row.path === currentPath.value)
    const row = list[index]
    if (!row) return
    const node = row.node!
    const isOpen = expanded.has(row.path)
    switch (event.key) {
        case 'ArrowDown':
            if (index < list.length - 1) focusRow(list[index + 1].path)
            break
        case 'ArrowUp':
            if (index > 0) focusRow(list[index - 1].path)
            break
        case 'Home':
            focusRow(list[0].path)
            break
        case 'End':
            focusRow(list[list.length - 1].path)
            break
        case 'ArrowRight':
            if (node.children > 0 && !row.cycle && !isOpen) toggle(row)
            else if (isOpen && list[index + 1]?.parentPath === row.path) focusRow(list[index + 1].path)
            // Still loading: move once the children are there.
            else if (isOpen && levels.get(node.ref)?.loading) pendingChildOf.value = row.path
            break
        case 'ArrowLeft':
            if (isOpen) toggle(row)
            else if (row.parentPath) focusRow(row.parentPath)
            break
        case ' ':
        case 'Enter':
            togglePick(node)
            break
        default:
            return
    }
    event.preventDefault()
}

// -- picking ---------------------------------------------------------------

const picked = reactive(new Map<string, PickedItem>())
const pickedList = computed(() => [...picked.values()])
const nodeId = (node: TreeNode) => `${selectedVersion.value}:${node.ref}`
const keyOf = (entry: SuggestedEntry) => entry.kind === 'project' ? `project::${entry.value}` : entry.value

const togglePick = (node: TreeNode) => {
    const id = nodeId(node)
    if (picked.has(id)) {
        picked.delete(id)
        return
    }
    const projectName = selectedProject.value || ''
    picked.set(id, { id, name: node.name, project: projectName, key: keyOf(suggestEntry(node, projectName)) })
    emit('dismiss-feedback')
}

const pickProjectRoot = (name: string) => {
    const id = `project:${name}`
    if (!picked.has(id)) picked.set(id, { id, name, project: name, key: `project::${name}` })
    emit('dismiss-feedback')
}
watch(() => props.pickProject, (name) => {
    if (!name) return
    selectProject(name)
    pickProjectRoot(name)
})

const highlightMatches = (node: TreeNode) => {
    const highlight = props.highlight
    if (!highlight || !selectedProject.value) return false
    const selector = highlight.selector
    if (selector.projectFallback) {
        return node.root && (selector.project || '').toLowerCase() === selectedProject.value.toLowerCase()
    }
    return selectorMatchesItem(selector, {
        name: node.name,
        group: node.group,
        purl: node.purl,
        project: selectedProject.value,
        below: 0,
        unownedBelow: 0,
        flags: 0,
    })
}

// -- the findings no team owns, across projects -------------------------------

const unownedQuery = ref('')
const unownedKind = ref<'all' | 'root' | 'component'>('all')
const unownedRows = computed(() => {
    const needle = unownedQuery.value.trim().toLowerCase()
    return (props.report?.unmapped || []).filter(row =>
        (unownedKind.value === 'all' || row.kind === unownedKind.value)
        && (!needle || [row.name, row.group, row.purl, ...row.projects.map(item => item.name)]
            .some(text => text.toLowerCase().includes(needle))))
})
const unownedId = (row: UnmappedRow) => `unowned:${row.kind}:${row.name}:${row.group}:${row.purl}`
const toggleRow = (row: UnmappedRow) => {
    const id = unownedId(row)
    if (picked.has(id)) {
        picked.delete(id)
        return
    }
    picked.set(id, { id, name: row.name, project: row.projects[0]?.name || '', key: row.suggested_key })
    emit('dismiss-feedback')
}
/** The team the draft already gives a row's suggested entry to. */
const draftOwner = (row: UnmappedRow): string | null => {
    const key = row.suggested_key
    const projectName = key.toLowerCase().startsWith('project::') ? key.slice('project::'.length).toLowerCase() : null
    const team = props.teams.find(item => projectName
        ? item.projects.some(name => name.toLowerCase() === projectName) || item.components.includes(key)
        : item.components.includes(key))
    return team?.name || null
}

// -- assigning -------------------------------------------------------------

const updateKey = (id: string, key: string) => {
    const item = picked.get(id)
    if (item) picked.set(id, { ...item, key })
}
const apply = (team: string, entries: SuggestedEntry[]) => {
    emit('assign', team, entries)
    picked.clear()
}
</script>

<template>
  <section data-testid="coverage-browser">
    <div v-if="!report" class="rounded border border-gray-700 bg-gray-900/40 p-4 text-xs text-gray-300">
      The coverage report is not built yet; it shows here as soon as it is ready.
    </div>

    <div v-else-if="mode === 'projects'" class="grid gap-4 lg:grid-cols-[14rem_minmax(0,1fr)] xl:grid-cols-[17rem_minmax(0,1fr)]">
      <div class="min-w-0">
        <label :for="`${uid}-project-filter`" class="sr-only">Filter projects</label>
        <input
          :id="`${uid}-project-filter`"
          v-model="projectQuery"
          placeholder="Filter projects"
          class="mb-2 w-full rounded border border-gray-600 bg-gray-900 px-2 py-1 text-xs text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <label class="mb-2 flex items-center gap-2 text-xs text-gray-300">
          <input v-model="belowFullOnly" type="checkbox" class="accent-blue-500" />
          Only projects with unowned findings
        </label>
        <ul class="max-h-[28rem] space-y-1 overflow-y-auto pr-1 lg:max-h-[36rem]" aria-label="Projects by unowned findings">
          <li v-for="item in projects" :key="item.name">
            <button
              type="button"
              :data-testid="`coverage-project-${item.name}`"
              :aria-current="selectedProject === item.name ? 'true' : undefined"
              :aria-label="`${item.name}: ${percent(item)}% owned, ${item.unmapped} of ${item.findings} findings unowned`"
              :class="[
                'w-full rounded border px-2 py-1.5 text-left text-xs focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400',
                selectedProject === item.name ? 'border-blue-500 bg-blue-900/30' : 'border-gray-700 hover:bg-gray-700/40',
                highlight?.projects.includes(item.name) ? 'ring-1 ring-amber-400' : '',
              ]"
              @click="selectProject(item.name)"
            >
              <div class="flex items-center justify-between gap-2">
                <span class="truncate font-medium text-gray-100">{{ item.name }}</span>
                <span class="tabular-nums text-gray-300">{{ percent(item) }}% owned</span>
              </div>
              <div class="mt-1 h-1.5 w-full overflow-hidden rounded bg-amber-700/60" aria-hidden="true">
                <div class="h-full bg-emerald-500" :style="{ width: `${coverage(item) * 100}%` }" />
              </div>
              <div class="mt-1 text-[11px] text-gray-400">
                {{ plural(item.versions.length, 'version') }} · {{ plural(item.findings, 'finding') }}<span v-if="item.unmapped" class="text-amber-300"> · {{ item.unmapped }} unowned</span>
              </div>
            </button>
          </li>
          <li v-if="!projects.length" class="text-xs text-gray-400">No project matches the filter.</li>
        </ul>
      </div>

      <div class="min-w-0">
        <div v-if="!project" class="text-xs text-gray-300">Pick a project to see its components and owners.</div>
        <template v-else>
          <div class="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
            <h5 class="text-sm font-semibold text-gray-100">{{ project.name }}</h5>
            <label class="flex items-center gap-1 text-gray-300">
              Version
              <select v-model="selectedVersion" data-testid="coverage-version" class="rounded border border-gray-600 bg-gray-900 px-1 py-0.5 text-gray-100">
                <option v-for="version in project.versions" :key="version.uuid" :value="version.uuid">{{ version.version || version.uuid }}</option>
              </select>
            </label>
            <label class="flex items-center gap-1 text-gray-300">
              <input v-model="unownedOnly" type="checkbox" class="accent-blue-500" />
              Only components with unowned findings
            </label>
            <span v-if="project.fallback_key" class="text-gray-300">Owned as a project: {{ project.fallback_key }}</span>
            <button
              v-else
              type="button"
              data-testid="coverage-assign-project"
              class="rounded border border-gray-600 px-2 py-0.5 text-gray-200 hover:bg-gray-700"
              @click="pickProjectRoot(project.name)"
            >Assign the whole project…</button>
          </div>
          <p class="mb-2 text-[11px] text-gray-300">
            Pick components to assign them to a team: click a row, or press Space. Arrow keys move, open and close.
            <span v-if="draft" class="text-amber-200">Owners include your unsaved changes.</span>
          </p>
          <div class="flex items-end gap-2 border-b border-gray-700 px-1 pb-1 text-[11px] font-semibold text-gray-300" aria-hidden="true">
            <span class="flex-1">Component</span>
            <span class="w-56 xl:w-72">Owner and why</span>
            <span class="w-16 text-right">Findings</span>
            <span class="w-16 text-right">Unowned</span>
          </div>
          <div v-if="rootState.loading" class="py-2 text-xs text-gray-300">Loading the components…</div>
          <div v-else-if="rootState.error" class="py-2 text-xs text-red-300">
            {{ rootState.error }}
            <button type="button" class="ml-2 text-blue-300 hover:underline" @click="loadRoot">Try again</button>
          </div>
          <ul
            v-else
            role="tree"
            aria-multiselectable="true"
            :aria-label="`Components of ${project.name}`"
            class="max-h-[36rem] overflow-y-auto py-1"
            data-testid="coverage-tree"
            @keydown="onTreeKeydown"
          >
            <template v-for="row in rows" :key="row.path">
              <CoverageTreeRow
                v-if="row.type === 'node'"
                :id="rowId(row.path)"
                :node="row.node!"
                :depth="row.depth"
                :expanded="expanded.has(row.path)"
                :focused="row.path === currentPath"
                :picked="picked.has(nodeId(row.node!))"
                :highlighted="highlightMatches(row.node!)"
                :posinset="row.posinset"
                :setsize="row.setsize"
                @toggle="toggle(row)"
                @pick="togglePick(row.node!)"
                @focus="focusedPath = row.path"
              />
              <li
                v-else
                role="none"
                :class="['py-0.5 text-[11px]', row.path.endsWith('error') ? 'text-red-300' : 'text-gray-400']"
                :style="{ paddingLeft: `${row.depth * 16 + 40}px` }"
              >{{ row.text }}</li>
            </template>
            <li v-if="!rows.length" role="none" class="py-2 text-xs text-gray-400">
              {{ unownedOnly ? 'No component here has unowned findings.' : 'This version has no components.' }}
            </li>
          </ul>
        </template>
      </div>
    </div>

    <div v-else data-testid="coverage-unowned">
      <p class="mb-2 text-xs text-gray-300">
        The project roots and topmost components above the findings no team owns, by unowned findings. Picking a row
        preselects the suggested entry.
      </p>
      <div class="mb-2 flex flex-wrap gap-2">
        <label :for="`${uid}-unowned-filter`" class="sr-only">Filter by name, purl or project</label>
        <input
          :id="`${uid}-unowned-filter`"
          v-model="unownedQuery"
          placeholder="Filter by name, purl or project"
          class="min-w-[16rem] flex-1 rounded border border-gray-600 bg-gray-900 px-2 py-1 text-xs text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <select v-model="unownedKind" aria-label="Show" class="rounded border border-gray-600 bg-gray-900 px-2 py-1 text-xs text-gray-100">
          <option value="all">Projects and components</option>
          <option value="root">Whole projects</option>
          <option value="component">Components</option>
        </select>
      </div>
      <table class="w-full text-xs">
        <thead class="border-b border-gray-700 text-left text-[11px] text-gray-300">
          <tr>
            <th class="w-8 py-1"><span class="sr-only">Pick</span></th>
            <th class="px-2 py-1 font-semibold">Component</th>
            <th class="px-2 py-1 font-semibold">Projects (versions)</th>
            <th class="px-2 py-1 text-right font-semibold">Unowned</th>
            <th class="px-2 py-1 font-semibold">Suggested entry</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in unownedRows"
            :key="unownedId(row)"
            :data-testid="`unowned-row-${row.name}`"
            :class="['cursor-pointer border-t border-gray-800 align-top', picked.has(unownedId(row)) ? 'bg-blue-900/40' : 'hover:bg-gray-700/30']"
            @click="toggleRow(row)"
          >
            <td class="py-1.5 pl-1">
              <input
                type="checkbox"
                class="accent-blue-500"
                :aria-label="`Pick ${row.name}`"
                :checked="picked.has(unownedId(row))"
                @click.stop
                @change="toggleRow(row)"
              />
            </td>
            <td class="px-2 py-1.5">
              <span class="font-medium text-gray-100">{{ row.name }}</span>
              <span v-if="row.kind === 'root'" class="ml-1 rounded bg-gray-700 px-1 text-[10px] uppercase text-gray-200">project root</span>
              <span v-if="!row.in_bom" class="ml-1 text-[11px] text-gray-400">not in the BOM</span>
              <div v-if="row.group || row.purl" class="text-[11px] text-gray-400">{{ [row.group, row.purl].filter(Boolean).join(' · ') }}</div>
              <div v-if="draftOwner(row)" class="mt-0.5 text-[11px] text-amber-200">Given to {{ draftOwner(row) }} in your unsaved changes</div>
            </td>
            <td class="px-2 py-1.5 text-gray-200">
              <span v-for="item in row.projects" :key="item.name" class="mr-2 inline-block">
                {{ item.name }} <span class="text-gray-400">({{ item.versions.join(', ') }})</span>
              </span>
            </td>
            <td class="px-2 py-1.5 text-right font-semibold tabular-nums text-amber-300">{{ row.findings }}</td>
            <td class="px-2 py-1.5">
              <code class="font-mono text-[11px] text-blue-200">{{ row.suggested_key }}</code>
              <div class="text-[11px] text-gray-400">{{ row.suggestion_reason }}</div>
            </td>
          </tr>
          <tr v-if="!unownedRows.length">
            <td colspan="5" class="py-3 text-center text-gray-300">
              {{ report.unmapped.length ? 'Nothing matches the filter.' : 'Every finding has an owner.' }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div
      v-if="feedback && !picked.size"
      data-testid="assign-feedback"
      role="status"
      class="mt-4 flex flex-wrap items-center gap-2 rounded border border-emerald-700 bg-emerald-950/40 p-3 text-xs text-emerald-100"
    >
      <span>{{ feedback.text }}</span>
      <button v-if="feedback.canUndo" type="button" data-testid="assign-undo" class="ml-auto rounded border border-emerald-600 px-2 py-0.5 hover:bg-emerald-900" @click="emit('undo')">Undo</button>
      <button type="button" :class="['rounded px-2 py-0.5 hover:bg-emerald-900', feedback.canUndo ? '' : 'ml-auto']" aria-label="Dismiss" @click="emit('dismiss-feedback')">Dismiss</button>
    </div>

    <AssignPanel
      v-if="picked.size"
      :picked="pickedList"
      :teams="teams"
      @unpick="picked.delete($event)"
      @cancel="picked.clear()"
      @update-key="updateKey"
      @apply="apply"
    />
  </section>
</template>
