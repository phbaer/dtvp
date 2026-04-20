<script setup lang="ts">
import { computed, ref } from 'vue'
import { DEFAULT_REPRESENTATIVE_PATH_LIMIT, getFirstMappedTeamOnPath, getPathParts, selectRepresentativePaths } from '../lib/dependency-team-selection'

const props = defineProps<{
  paths: string[]
  projectName?: string
  teamMappedNames?: Map<string, string[]>
}>()

type GraphNode = {
  id: string
  name: string
  teamNames: string[]
  tooltip: string
  preview: GapPreview | null
  depth: number
  x: number
  y: number
  width: number
  height: number
  isSource: boolean
  isRoot: boolean
  isPrimary: boolean
  isTagged: boolean
}

type GraphEdge = {
  id: string
  from: string
  to: string
}

type DisplayStep = {
  id: string
  name: string
  teamNames: string[]
  tooltip: string
  preview: GapPreview | null
  isSource: boolean
  isRoot: boolean
  isPrimary: boolean
  isTagged: boolean
  isGap: boolean
}

type GapPreview = {
  before: PreviewPart
  omittedParts: PreviewPart[]
  after: PreviewPart
}

type PreviewPart = {
  name: string
  teamNames: string[]
}

type HoveredPreview = GapPreview & {
  x: number
  y: number
}

const normalizeName = (name: string): string => name.trim().toLowerCase()
const REPRESENTATIVE_PATH_LIMIT = DEFAULT_REPRESENTATIVE_PATH_LIMIT
const MAX_DISPLAY_BUBBLES = 5
const H_PADDING = 22
const V_PADDING = 18
const COL_GAP = 54
const ROW_GAP = 34
const TOOLTIP_WIDTH = 280
const TOOLTIP_HEIGHT = 150

const normalizedTeamMappedNames = computed(() => {
  const map = new Map<string, string[]>()
  if (!props.teamMappedNames) return map

  for (const [key, val] of props.teamMappedNames.entries()) {
    map.set(normalizeName(key), Array.isArray(val) ? val : [val])
  }
  return map
})

const containerRef = ref<HTMLElement | null>(null)
const hoveredPreview = ref<HoveredPreview | null>(null)

const getTeamNames = (name: string): string[] => {
  const teams = normalizedTeamMappedNames.value.get(normalizeName(name))
  return teams ? [...teams] : []
}

const getTeamLabel = (teamNames: string[]): string => {
  if (teamNames.length === 0) return ''
  if (teamNames.length <= 2) return teamNames.join(' / ')
  return `${teamNames.slice(0, 2).join(' / ')} +${teamNames.length - 2}`
}

const toPreviewPart = (name: string): PreviewPart => ({
  name,
  teamNames: getTeamNames(name),
})

const teamMappingRecord = computed(() => {
  const record: Record<string, string[]> = {}
  for (const [key, val] of normalizedTeamMappedNames.value.entries()) {
    record[key] = val
  }
  return record
})

const uniquePathCount = computed(() => {
  const unique = new Set(
    (props.paths || [])
      .map(path => getPathParts(path))
      .filter(parts => parts.length > 1)
      .map(parts => parts.map(normalizeName).join(' -> '))
  )
  return unique.size
})

const selectedPaths = computed(() => {
  return selectRepresentativePaths(props.paths, teamMappingRecord.value, REPRESENTATIVE_PATH_LIMIT)
})

const graphRows = computed(() => {
  return selectedPaths.value
    .map(path => getPathParts(path))
    .filter(parts => parts.length > 1)
    .map((parts) => ({
      key: parts.join(' -> '),
      parts,
      firstMapped: getFirstMappedTeamOnPath(parts, teamMappingRecord.value),
    }))
})

const displayedPathCount = computed(() => graphRows.value.length)

const getDisplayedTeamNames = (
  row: { firstMapped: { index: number } | null; parts: string[] },
  index: number,
) => {
  return getTeamNames(row.parts[index] || '')
}

const getDisplayStepCount = (indexes: number[]) => {
  if (indexes.length === 0) return 0
  const sorted = [...indexes].sort((left, right) => left - right)
  let gaps = 0
  for (let index = 0; index < sorted.length - 1; index += 1) {
    if (sorted[index + 1] - sorted[index] > 1) gaps += 1
  }
  return sorted.length + gaps
}

const displayRows = computed(() => {
  return graphRows.value.map((row) => {
    let keepIndexes: number[]

    if (row.parts.length <= MAX_DISPLAY_BUBBLES) {
      keepIndexes = row.parts.map((_, index) => index)
    } else {
      const primaryIndex = row.firstMapped?.index

      const chosen = new Set<number>([0, row.parts.length - 1])
      if (typeof primaryIndex === 'number') chosen.add(primaryIndex)

      const fillerIndexes: number[] = []
      for (let offset = 1; offset < row.parts.length - 1; offset += 1) {
        fillerIndexes.push(offset)
        fillerIndexes.push(row.parts.length - 1 - offset)
      }

      fillerIndexes.forEach((index) => {
        if (index <= 0 || index >= row.parts.length - 1 || chosen.has(index)) return
        const nextIndexes = [...chosen, index]
        if (getDisplayStepCount(nextIndexes) <= MAX_DISPLAY_BUBBLES) chosen.add(index)
      })

      keepIndexes = Array.from(chosen)
    }

    const sortedIndexes = keepIndexes.sort((left, right) => left - right)
    const steps: DisplayStep[] = []

    sortedIndexes.forEach((index, position) => {
      const part = row.parts[index]
      const teamNames = getDisplayedTeamNames(row, index)
      steps.push({
        id: `${normalizeName(part)}:${index}`,
        name: part,
        teamNames,
        tooltip: '',
        preview: null,
        isSource: index === 0,
        isRoot: index === row.parts.length - 1,
        isPrimary: row.firstMapped?.index === index,
        isTagged: teamNames.length > 0,
        isGap: false,
      })

      const nextIndex = sortedIndexes[position + 1]
      if (typeof nextIndex === 'number' && nextIndex - index > 1) {
        const omittedParts = row.parts.slice(index + 1, nextIndex)
        steps.push({
          id: `gap:${normalizeName(part)}:${omittedParts.map(normalizeName).join(':')}:${normalizeName(row.parts[nextIndex])}`,
          name: '...',
          teamNames: [],
          tooltip: omittedParts.join(' -> '),
          preview: {
            before: toPreviewPart(part),
            omittedParts: omittedParts.map(toPreviewPart),
            after: toPreviewPart(row.parts[nextIndex]),
          },
          isSource: false,
          isRoot: false,
          isPrimary: false,
          isTagged: false,
          isGap: true,
        })
      }
    })

    return {
      key: row.key,
      steps,
    }
  })
})

const graphModel = computed(() => {
  const nodeBuckets = new Map<string, {
    id: string
    name: string
    teamNames: string[]
    tooltip: string
    preview: GapPreview | null
    depth: number
    positions: number[]
    isSource: boolean
    isRoot: boolean
    isPrimary: boolean
    isTagged: boolean
  }>()
  const edges = new Map<string, GraphEdge>()

  displayRows.value.forEach((row, rowIndex) => {
    row.steps.forEach((step, partIndex) => {
      const nodeId = step.isGap ? step.id : normalizeName(step.name)
      const teamNames = step.teamNames
      const existing = nodeBuckets.get(nodeId)
      const isSource = step.isSource
      const isRoot = step.isRoot
      const isPrimary = step.isPrimary

      if (!existing) {
        nodeBuckets.set(nodeId, {
          id: nodeId,
          name: step.name,
          teamNames,
          tooltip: step.tooltip,
          preview: step.preview,
          depth: partIndex,
          positions: [rowIndex],
          isSource,
          isRoot,
          isPrimary,
          isTagged: teamNames.length > 0,
        })
      } else {
        existing.depth = Math.max(existing.depth, partIndex)
        existing.positions.push(rowIndex)
        existing.isSource = existing.isSource || isSource
        existing.isRoot = existing.isRoot || isRoot
        existing.isPrimary = existing.isPrimary || isPrimary
        existing.isTagged = existing.isTagged || teamNames.length > 0
        if (existing.teamNames.length === 0 && teamNames.length > 0) existing.teamNames = teamNames
        if (!existing.tooltip && step.tooltip) existing.tooltip = step.tooltip
        if (!existing.preview && step.preview) existing.preview = step.preview
      }

      if (partIndex < row.steps.length - 1) {
        const nextStep = row.steps[partIndex + 1]
        const nextId = nextStep.isGap ? nextStep.id : normalizeName(nextStep.name)
        const edgeId = `${nodeId}->${nextId}`
        if (!edges.has(edgeId)) {
          edges.set(edgeId, {
            id: edgeId,
            from: nodeId,
            to: nextId,
          })
        }
      }
    })
  })

  const nodes: GraphNode[] = Array.from(nodeBuckets.values())
    .map((bucket) => {
      const rowCenter = bucket.positions.reduce((sum, value) => sum + value, 0) / bucket.positions.length
      const labelLength = Math.max(bucket.name.length, getTeamLabel(bucket.teamNames).length)
      const width = Math.max(118, Math.min(190, labelLength * 7 + 34))
      const height = bucket.teamNames.length > 0 || bucket.isSource || bucket.isRoot ? 54 : 42
      return {
        id: bucket.id,
        name: bucket.name,
        teamNames: bucket.teamNames,
        tooltip: bucket.tooltip,
        preview: bucket.preview,
        depth: bucket.depth,
        x: H_PADDING + bucket.depth * (190 + COL_GAP),
        y: V_PADDING + rowCenter * (54 + ROW_GAP),
        width,
        height,
        isSource: bucket.isSource,
        isRoot: bucket.isRoot,
        isPrimary: bucket.isPrimary,
        isTagged: bucket.isTagged,
      }
    })
    .sort((left, right) => left.depth - right.depth || left.y - right.y)

  const nodeMap = new Map(nodes.map(node => [node.id, node]))
  const edgeList = Array.from(edges.values())

  const maxX = nodes.reduce((max, node) => Math.max(max, node.x + node.width), 0)
  const maxY = nodes.reduce((max, node) => Math.max(max, node.y + node.height), 0)

  return {
    nodes,
    nodeMap,
    edges: edgeList,
    width: Math.max(360, maxX + H_PADDING),
    height: Math.max(120, maxY + V_PADDING),
  }
})

const pathSummary = computed(() => {
  return displayRows.value.map(row => row.steps.map(step => step.name).join(' -> ')).join('\n')
})

const labelSummary = computed(() => {
  return graphModel.value.nodes
    .map(node => [node.name, node.isSource ? 'SOURCE' : node.isRoot ? 'ROOT' : getTeamLabel(node.teamNames), node.isPrimary ? 'PRIMARY' : ''].filter(Boolean).join(' | '))
    .join('\n')
})

const previewSequence = (preview: GapPreview) => {
  return [preview.before, ...preview.omittedParts, preview.after]
}

const updatePreviewPosition = (event: MouseEvent) => {
  if (!containerRef.value || !hoveredPreview.value) return

  const bounds = containerRef.value.getBoundingClientRect()
  const relativeX = event.clientX - bounds.left
  const relativeY = event.clientY - bounds.top
  hoveredPreview.value = {
    ...hoveredPreview.value,
    x: Math.min(Math.max(8, relativeX + 14), Math.max(8, bounds.width - TOOLTIP_WIDTH - 8)),
    y: Math.min(Math.max(8, relativeY + 14), Math.max(8, bounds.height - TOOLTIP_HEIGHT - 8)),
  }
}

const showPreview = (preview: GapPreview | null, event: MouseEvent) => {
  if (!preview) return
  hoveredPreview.value = {
    ...preview,
    x: 8,
    y: 8,
  }
  updatePreviewPosition(event)
}

const hidePreview = () => {
  hoveredPreview.value = null
}

const edgePath = (edge: GraphEdge) => {
  const fromNode = graphModel.value.nodeMap.get(edge.from)
  const toNode = graphModel.value.nodeMap.get(edge.to)
  if (!fromNode || !toNode) return ''

  const startX = fromNode.x + fromNode.width
  const startY = fromNode.y + fromNode.height / 2
  const endX = toNode.x
  const endY = toNode.y + toNode.height / 2
  const curveX = startX + (endX - startX) / 2

  return `M ${startX} ${startY} C ${curveX} ${startY}, ${curveX} ${endY}, ${endX} ${endY}`
}
</script>

<template>
  <div ref="containerRef" class="relative text-xs">
    <div v-if="graphRows.length === 0" class="text-gray-500 italic">
      No dependency chains found.
    </div>

    <div v-else class="rounded-lg border border-slate-800/80 bg-slate-950/30 p-3 space-y-3">
      <div v-if="uniquePathCount > displayedPathCount" class="text-[10px] text-slate-500">
        Showing {{ displayedPathCount }} representative path{{ displayedPathCount === 1 ? '' : 's' }} from {{ uniquePathCount }} unique chain{{ uniquePathCount === 1 ? '' : 's' }}.
      </div>

      <div class="overflow-x-auto rounded-md border border-slate-800/70 bg-slate-900/45 p-2">
        <svg
          data-testid="dependency-graph"
          :viewBox="`0 0 ${graphModel.width} ${graphModel.height}`"
          class="min-w-[24rem] h-auto w-full"
          role="img"
          aria-label="Dependency graph"
        >
          <defs>
            <marker id="dependency-arrow" markerWidth="7" markerHeight="7" refX="6.5" refY="3.5" orient="auto" markerUnits="strokeWidth">
              <path d="M 0 0 L 7 3.5 L 0 7 z" fill="#475569" />
            </marker>
          </defs>

          <path
            v-for="edge in graphModel.edges"
            :key="edge.id"
            :d="edgePath(edge)"
            fill="none"
            stroke="#475569"
            stroke-width="2.25"
            marker-end="url(#dependency-arrow)"
            opacity="0.95"
          />

          <g v-for="node in graphModel.nodes" :key="node.id">
            <rect
              :data-testid="node.preview ? 'gap-node' : undefined"
              :x="node.x"
              :y="node.y"
              :width="node.width"
              :height="node.height"
              @mouseenter="node.preview ? showPreview(node.preview, $event) : undefined"
              @mousemove="node.preview ? updatePreviewPosition($event) : undefined"
              @mouseleave="node.preview ? hidePreview() : undefined"
              rx="12"
              :fill="node.isSource
                ? '#3b2f0a'
                : node.isRoot
                  ? '#0f2340'
                  : node.name === '...'
                    ? '#0f172a'
                  : node.isPrimary
                    ? '#082f49'
                    : node.isTagged
                      ? '#042f2e'
                      : '#1e293b'"
              :stroke="node.isSource
                ? '#f59e0b'
                : node.isRoot
                  ? '#38bdf8'
                  : node.name === '...'
                    ? '#64748b'
                  : node.isPrimary
                    ? '#22d3ee'
                    : node.isTagged
                      ? '#2dd4bf'
                      : '#475569'"
              :stroke-width="node.isPrimary ? 3 : 2"
            />
            <text
              :x="node.x + node.width / 2"
              :y="node.y + (node.teamNames.length > 0 || node.isSource || node.isRoot ? 18 : 24)"
              text-anchor="middle"
              font-size="11"
              font-family="ui-monospace, SFMono-Regular, Menlo, monospace"
              fill="#e5e7eb"
            >
              {{ node.name }}
            </text>
            <text
              v-if="node.teamNames.length > 0 || node.isSource || node.isRoot"
              :x="node.x + node.width / 2"
              :y="node.y + 34"
              text-anchor="middle"
              font-size="9"
              font-family="ui-monospace, SFMono-Regular, Menlo, monospace"
              :fill="node.isSource ? '#fcd34d' : node.isRoot ? '#7dd3fc' : node.isPrimary ? '#67e8f9' : '#5eead4'"
            >
              {{ node.isSource ? 'SOURCE' : node.isRoot ? 'ROOT' : getTeamLabel(node.teamNames) }}
            </text>
            <text
              v-if="node.isPrimary"
              :x="node.x + node.width / 2"
              :y="node.y + node.height - 8"
              text-anchor="middle"
              font-size="8"
              font-family="ui-monospace, SFMono-Regular, Menlo, monospace"
              fill="#67e8f9"
            >
              PRIMARY
            </text>
          </g>
        </svg>
      </div>

      <div
        v-if="hoveredPreview"
        data-testid="gap-preview"
        class="pointer-events-none absolute z-20 w-[280px] rounded-lg border border-slate-700 bg-slate-950/95 p-3 shadow-2xl backdrop-blur-sm"
        :style="{ left: `${hoveredPreview.x}px`, top: `${hoveredPreview.y}px` }"
      >
        <div class="mb-2 text-[10px] font-bold uppercase tracking-widest text-slate-400">
          Collapsed dependency chain
        </div>
        <div class="flex flex-wrap items-center gap-2 text-[10px]">
          <template v-for="(part, index) in previewSequence(hoveredPreview)" :key="`${part}-${index}`">
            <div
              class="rounded-full border px-2 py-1 font-mono"
              :class="part.teamNames.length > 0 ? 'border-teal-500/60 bg-teal-950/70 text-teal-100' : 'border-slate-600 bg-slate-900 text-slate-100'"
            >
              <div>{{ part.name }}</div>
              <div v-if="part.teamNames.length > 0" class="text-[9px] text-teal-300">
                {{ getTeamLabel(part.teamNames) }}
              </div>
            </div>
            <span v-if="index < previewSequence(hoveredPreview).length - 1" class="font-mono text-slate-500">-&gt;</span>
          </template>
        </div>
      </div>

      <div class="sr-only" data-testid="graph-source">{{ pathSummary }}</div>
      <div class="sr-only" data-testid="graph-labels">{{ labelSummary }}</div>
    </div>
  </div>
</template>
