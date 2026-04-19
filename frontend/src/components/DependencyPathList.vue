<script setup lang="ts">
import { computed } from 'vue'
import { DEFAULT_REPRESENTATIVE_PATH_LIMIT, getFirstMappedTeamOnPath, getPathParts, selectRepresentativePaths } from '../lib/dependency-team-selection'

const props = defineProps<{
  paths: string[]
  projectName?: string
  teamMappedNames?: Map<string, string[]>
}>()

type GraphNode = {
  id: string
  name: string
  teamName: string
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
  teamName: string
  isSource: boolean
  isRoot: boolean
  isPrimary: boolean
  isTagged: boolean
  isGap: boolean
}

const normalizeName = (name: string): string => name.trim().toLowerCase()
const REPRESENTATIVE_PATH_LIMIT = DEFAULT_REPRESENTATIVE_PATH_LIMIT
const MAX_DISPLAY_BUBBLES = 5
const H_PADDING = 22
const V_PADDING = 18
const COL_GAP = 54
const ROW_GAP = 34

const normalizedTeamMappedNames = computed(() => {
  const map = new Map<string, string[]>()
  if (!props.teamMappedNames) return map

  for (const [key, val] of props.teamMappedNames.entries()) {
    map.set(normalizeName(key), Array.isArray(val) ? val : [val])
  }
  return map
})

const getTeamNames = (name: string): string => {
  const teams = normalizedTeamMappedNames.value.get(normalizeName(name))
  return teams?.[0] || ''
}

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
      const taggedIndexes = row.parts
        .map((part, index) => ({ part, index }))
        .filter(({ index }) => index !== 0 && index !== row.parts.length - 1 && !!getTeamNames(row.parts[index]))
        .map(({ index }) => index)

      const chosen = new Set<number>([0, row.parts.length - 1])
      if (typeof primaryIndex === 'number') chosen.add(primaryIndex)

      const sortedTagged = taggedIndexes
        .filter(index => index !== primaryIndex)
        .sort((left, right) => {
          const primaryDistanceLeft = Math.abs(left - (primaryIndex ?? 0))
          const primaryDistanceRight = Math.abs(right - (primaryIndex ?? 0))
          if (primaryDistanceLeft !== primaryDistanceRight) return primaryDistanceLeft - primaryDistanceRight
          return left - right
        })

      sortedTagged.forEach((index) => {
        const nextIndexes = [...chosen, index]
        if (getDisplayStepCount(nextIndexes) <= MAX_DISPLAY_BUBBLES) chosen.add(index)
      })

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
      const teamName = getTeamNames(part)
      steps.push({
        id: `${normalizeName(part)}:${index}`,
        name: part,
        teamName,
        isSource: index === 0,
        isRoot: index === row.parts.length - 1,
        isPrimary: row.firstMapped?.index === index,
        isTagged: !!teamName,
        isGap: false,
      })

      const nextIndex = sortedIndexes[position + 1]
      if (typeof nextIndex === 'number' && nextIndex - index > 1) {
        steps.push({
          id: `gap:${normalizeName(part)}:${normalizeName(row.parts[nextIndex])}`,
          name: '...',
          teamName: '',
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
    teamName: string
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
      const teamName = step.teamName
      const existing = nodeBuckets.get(nodeId)
      const isSource = step.isSource
      const isRoot = step.isRoot
      const isPrimary = step.isPrimary

      if (!existing) {
        nodeBuckets.set(nodeId, {
          id: nodeId,
          name: step.name,
          teamName,
          depth: partIndex,
          positions: [rowIndex],
          isSource,
          isRoot,
          isPrimary,
          isTagged: !!teamName,
        })
      } else {
        existing.depth = Math.max(existing.depth, partIndex)
        existing.positions.push(rowIndex)
        existing.isSource = existing.isSource || isSource
        existing.isRoot = existing.isRoot || isRoot
        existing.isPrimary = existing.isPrimary || isPrimary
        existing.isTagged = existing.isTagged || !!teamName
        if (!existing.teamName && teamName) existing.teamName = teamName
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
      const labelLength = Math.max(bucket.name.length, bucket.teamName.length)
      const width = Math.max(118, Math.min(190, labelLength * 7 + 34))
      const height = bucket.teamName ? 54 : 42
      return {
        id: bucket.id,
        name: bucket.name,
        teamName: bucket.teamName,
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
    .map(node => [node.name, node.isSource ? 'SOURCE' : node.isRoot ? 'ROOT' : node.teamName, node.isPrimary ? 'PRIMARY' : ''].filter(Boolean).join(' | '))
    .join('\n')
})

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
  <div class="text-xs">
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
            <marker id="dependency-arrow" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto" markerUnits="strokeWidth">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
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
              :x="node.x"
              :y="node.y"
              :width="node.width"
              :height="node.height"
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
              :y="node.y + (node.teamName || node.isSource || node.isRoot ? 18 : 24)"
              text-anchor="middle"
              font-size="11"
              font-family="ui-monospace, SFMono-Regular, Menlo, monospace"
              fill="#e5e7eb"
            >
              {{ node.name }}
            </text>
            <text
              v-if="node.teamName || node.isSource || node.isRoot"
              :x="node.x + node.width / 2"
              :y="node.y + 34"
              text-anchor="middle"
              font-size="9"
              font-family="ui-monospace, SFMono-Regular, Menlo, monospace"
              :fill="node.isSource ? '#fcd34d' : node.isRoot ? '#7dd3fc' : node.isPrimary ? '#67e8f9' : '#5eead4'"
            >
              {{ node.isSource ? 'SOURCE' : node.isRoot ? 'ROOT' : node.teamName }}
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

      <div class="sr-only" data-testid="graph-source">{{ pathSummary }}</div>
  <div class="sr-only" data-testid="graph-labels">{{ labelSummary }}</div>
    </div>
  </div>
</template>
