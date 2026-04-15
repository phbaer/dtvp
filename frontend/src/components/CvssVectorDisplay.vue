<script setup lang="ts">
import { computed } from 'vue'
import { calculateScoreFromVector } from '../lib/cvss'

export interface VectorEntry {
  vector: string
  label: string
  theme: 'purple' | 'teal' | 'gray'
  adjusted?: boolean
}

const props = defineProps<{
  /** List of vectors to display, one line each. The first entry is used for the metric breakdown. */
  vectors: VectorEntry[]
}>()

// --- CVSS v2 labels & values ---
const cvssMetricLabelsV2: Record<string, string> = {
  AV: 'Access Vector', AC: 'Access Complexity', Au: 'Authentication',
  C: 'Confidentiality', I: 'Integrity', A: 'Availability',
}
const cvssValueExpansionsV2: Record<string, Record<string, string>> = {
  AV: { N: 'Network', A: 'Adjacent Network', L: 'Local' },
  AC: { L: 'Low', M: 'Medium', H: 'High' },
  Au: { N: 'None', S: 'Single', M: 'Multiple' },
  C: { N: 'None', P: 'Partial', C: 'Complete' },
  I: { N: 'None', P: 'Partial', C: 'Complete' },
  A: { N: 'None', P: 'Partial', C: 'Complete' },
}
const highDangerV2 = new Set(['N:AV', 'L:AC', 'N:Au', 'C:C', 'C:I', 'C:A'])
const lowDangerV2 = new Set(['L:AV', 'H:AC', 'M:Au', 'N:C', 'N:I', 'N:A'])

// --- CVSS v3 labels & values ---
const cvssMetricLabelsV3: Record<string, string> = {
  AV: 'Attack Vector', AC: 'Attack Complexity', PR: 'Privileges Required',
  UI: 'User Interaction', S: 'Scope', C: 'Confidentiality', I: 'Integrity', A: 'Availability',
}

// --- CVSS v4 labels & values ---
const cvssMetricLabelsV4: Record<string, string> = {
  AV: 'Attack Vector', AC: 'Attack Complexity', AT: 'Attack Requirements',
  PR: 'Privileges Required', UI: 'User Interaction',
  VC: 'Vuln. Confidentiality', VI: 'Vuln. Integrity', VA: 'Vuln. Availability',
  SC: 'Sub. Confidentiality', SI: 'Sub. Integrity', SA: 'Sub. Availability',
  // Threat
  E: 'Exploit Maturity',
  // Supplemental
  S: 'Safety', AU: 'Automatable', R: 'Recovery', V: 'Value Density',
  RE: 'Provider Response Effort', U: 'Provider Urgency',
}

// Shared v3/v4 value expansions (v3 uses S=Scope)
const cvssValueExpansions: Record<string, Record<string, string>> = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  AT: { N: 'None', P: 'Present' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required', P: 'Passive', A: 'Active' },
  S: { U: 'Unchanged', C: 'Changed' },
  C: { N: 'None', L: 'Low', H: 'High' }, I: { N: 'None', L: 'Low', H: 'High' }, A: { N: 'None', L: 'Low', H: 'High' },
  VC: { N: 'None', L: 'Low', H: 'High' }, VI: { N: 'None', L: 'Low', H: 'High' }, VA: { N: 'None', L: 'Low', H: 'High' },
  SC: { N: 'None', L: 'Low', H: 'High', S: 'Safety' }, SI: { N: 'None', L: 'Low', H: 'High', S: 'Safety' }, SA: { N: 'None', L: 'Low', H: 'High', S: 'Safety' },
}

// v4-specific expansions (S=Safety supplemental, plus Threat & Supplemental metrics)
const cvssValueExpansionsV4: Record<string, Record<string, string>> = {
  ...cvssValueExpansions,
  S: { X: 'Not Defined', N: 'Negligible', P: 'Present' },
  E: { X: 'Not Defined', U: 'Unreported', P: 'PoC', A: 'Attacked' },
  AU: { X: 'Not Defined', N: 'No', Y: 'Yes' },
  R: { X: 'Not Defined', A: 'Automatic', U: 'User', I: 'Irrecoverable' },
  V: { X: 'Not Defined', D: 'Diffuse', C: 'Concentrated' },
  RE: { X: 'Not Defined', L: 'Low', M: 'Moderate', H: 'High' },
  U: { X: 'Not Defined', Clear: 'Clear', Green: 'Green', Amber: 'Amber', Red: 'Red' },
}

// Danger maps for v3/v4
const highDangerValues = new Set(['N:AV', 'L:AC', 'N:AT', 'N:PR', 'N:UI', 'C:S', 'H:C', 'H:I', 'H:A', 'H:VC', 'H:VI', 'H:VA', 'H:SC', 'H:SI', 'H:SA', 'S:SC', 'S:SI', 'S:SA',
  'A:E', 'Y:AU', 'I:R', 'C:V', 'Red:U', 'P:S', 'H:RE'])
const lowDangerValues = new Set(['P:AV', 'L:AV', 'H:AC', 'P:AT', 'H:PR', 'R:UI', 'A:UI', 'U:S', 'N:C', 'N:I', 'N:A', 'N:VC', 'N:VI', 'N:VA', 'N:SC', 'N:SI', 'N:SA',
  'U:E', 'N:AU', 'A:R', 'D:V', 'Green:U', 'Clear:U', 'N:S', 'L:RE'])

type CvssVersion = 'v2' | 'v3' | 'v4'

interface CvssMetric {
  key: string
  label: string
  value: string
  short: string
  danger: 'high' | 'medium' | 'low'
}

interface CvssMetricRow {
  entry: VectorEntry
  metricsByKey: Map<string, CvssMetric>
}

interface CvssSection {
  title: string
  keys: string[]
  rows: CvssMetricRow[]
}

// Maps M-prefixed environmental modifiers to their base metric keys
const v3ModifierToBase: Record<string, string> = {
  MAV: 'AV', MAC: 'AC', MPR: 'PR', MUI: 'UI', MS: 'S', MC: 'C', MI: 'I', MA: 'A',
}
const v4ModifierToBase: Record<string, string> = {
  MAV: 'AV', MAC: 'AC', MAT: 'AT', MPR: 'PR', MUI: 'UI',
  MVC: 'VC', MVI: 'VI', MVA: 'VA', MSC: 'SC', MSI: 'SI', MSA: 'SA',
}

function detectVersion(v: string | null): CvssVersion | null {
  if (!v) return null
  if (v.startsWith('CVSS:4.0')) return 'v4'
  if (v.startsWith('CVSS:3.')) return 'v3'
  if (v.startsWith('CVSS:2.0')) return 'v2'
  if (/^(\()?AV:[NAL]/.test(v)) return 'v2'
  return null
}

/** Check if any vector is parseable */
const hasAnyVector = computed(() => props.vectors.some(e => detectVersion(e.vector.trim())))

function parseMetrics(vector: string): Map<string, string> {
  const m = new Map<string, string>()
  let cleaned = vector.replace(/^\(|\)$/g, '')
  cleaned = cleaned.replace(/^CVSS:[234]\.\d\//, '')
  for (const part of cleaned.split('/')) {
    const sep = part.indexOf(':')
    if (sep > 0) {
      m.set(part.substring(0, sep), part.substring(sep + 1))
    }
  }
  return m
}

function hasModifiers(vector: string): boolean {
  const ver = detectVersion(vector.trim())
  if (!ver) return false
  const baseKeys = ver === 'v4' ? new Set(Object.keys(cvssMetricLabelsV4))
    : ver === 'v2' ? new Set(Object.keys(cvssMetricLabelsV2))
    : new Set(Object.keys(cvssMetricLabelsV3))
  const parsed = parseMetrics(vector)
  for (const key of parsed.keys()) {
    if (!baseKeys.has(key)) return true
  }
  return false
}

/** Parse a single vector into its effective base metrics */
function resolveMetrics(vector: string, version: CvssVersion): CvssMetric[] {
  const labels = version === 'v4' ? cvssMetricLabelsV4
    : version === 'v2' ? cvssMetricLabelsV2
    : cvssMetricLabelsV3
  const valueMap = version === 'v4' ? cvssValueExpansionsV4
    : version === 'v2' ? cvssValueExpansionsV2
    : cvssValueExpansions
  const highSet = version === 'v2' ? highDangerV2 : highDangerValues
  const lowSet = version === 'v2' ? lowDangerV2 : lowDangerValues

  const parsed = parseMetrics(vector)

  // Build modifier override map (M-prefixed → base key)
  const modifierMap = version === 'v4' ? v4ModifierToBase
    : version === 'v3' ? v3ModifierToBase
    : {} as Record<string, string>
  const overrides = new Map<string, string>()
  for (const [key, val] of parsed) {
    const baseKey = modifierMap[key]
    if (baseKey && val !== 'X') {
      overrides.set(baseKey, val)
    }
  }

  const baseMetricKeys = new Set(Object.keys(labels))
  const metrics: CvssMetric[] = []

  for (const [key, val] of parsed) {
    if (!baseMetricKeys.has(key)) continue
    const effectiveVal = overrides.get(key) ?? val
    const dangerKey = `${effectiveVal}:${key}`
    const danger = highSet.has(dangerKey) ? 'high' : lowSet.has(dangerKey) ? 'low' : 'medium'
    metrics.push({
      key,
      label: labels[key],
      value: valueMap[key]?.[effectiveVal] || effectiveVal,
      short: effectiveVal,
      danger,
    })
  }
  return metrics
}

/** Fixed superset of all sections — always shown, cells filled when applicable */
const allSections: { title: string, keys: string[] }[] = [
  { title: 'Exploitability', keys: ['AV', 'AC', 'Au', 'AT', 'PR', 'UI'] },
  { title: 'Impact / Vuln. System', keys: ['S', 'C', 'I', 'A', 'VC', 'VI', 'VA'] },
  { title: 'Subseq. System', keys: ['SC', 'SI', 'SA'] },
  { title: 'Threat', keys: ['E'] },
  { title: 'Supplemental', keys: ['AU', 'R', 'V', 'RE', 'U'] },
]

const cvssMetrics = computed<CvssSection[] | null>(() => {
  if (!hasAnyVector.value) return null

  // Build rows: parse each vector with its own version
  const allRows: { entry: VectorEntry, metrics: CvssMetric[] }[] = []
  for (const entry of props.vectors) {
    const ver = detectVersion(entry.vector.trim())
    if (!ver) continue
    allRows.push({ entry, metrics: resolveMetrics(entry.vector, ver) })
  }
  if (!allRows.length) return null

  return allSections.map(def => {
    const keySet = new Set(def.keys)
    const rows: CvssMetricRow[] = allRows.map(r => {
      const byKey = new Map<string, CvssMetric>()
      for (const m of r.metrics) {
        if (keySet.has(m.key)) byKey.set(m.key, m)
      }
      return { entry: r.entry, metricsByKey: byKey }
    })
    return { title: def.title, keys: def.keys, rows }
  })
})

// Flat list of all metric keys across sections, and helpers for the unified table
const allMetricKeys = computed(() => {
  if (!cvssMetrics.value) return [] as string[]
  return cvssMetrics.value.flatMap(s => s.keys)
})

// Track which column indices start a new section (for left padding separator)
const sectionStartIndices = computed(() => {
  if (!cvssMetrics.value) return new Set<number>()
  const starts = new Set<number>()
  let col = 0
  for (const s of cvssMetrics.value) {
    starts.add(col)
    col += s.keys.length
  }
  return starts
})

function isSectionStart(ki: number): boolean {
  return sectionStartIndices.value.has(ki)
}

function sectionIndexAt(ki: number): number {
  let idx = 0
  for (const start of sectionStartIndices.value) {
    if (start === ki) return idx
    if (start < ki) idx++
  }
  return idx
}

function dangerCellClass(danger: 'high' | 'medium' | 'low'): string {
  switch (danger) {
    case 'high': return 'bg-red-500/25 text-red-300'
    case 'medium': return 'bg-amber-500/15 text-amber-300/90'
    case 'low': return 'bg-emerald-500/15 text-emerald-400/80'
  }
}

// Pre-build per-row metric maps for quick lookup
const rowMetricMaps = computed(() => {
  if (!cvssMetrics.value) return [] as Map<string, CvssMetric>[]
  return props.vectors.map((entry) => {
    const ver = detectVersion(entry.vector.trim())
    if (!ver) return new Map<string, CvssMetric>()
    const metrics = resolveMetrics(entry.vector, ver)
    const map = new Map<string, CvssMetric>()
    for (const m of metrics) map.set(m.key, m)
    return map
  })
})

function metricForRow(rowIdx: number, key: string): CvssMetric | undefined {
  return rowMetricMaps.value[rowIdx]?.get(key)
}

function scoreSeverity(score: number): string {
  if (score >= 9.0) return 'CRITICAL'
  if (score >= 7.0) return 'HIGH'
  if (score >= 4.0) return 'MEDIUM'
  if (score >= 0.1) return 'LOW'
  return 'INFO'
}

const severityClasses: Record<string, string> = {
  CRITICAL: 'border-red-800 bg-red-950 text-red-300',
  HIGH: 'border-orange-800 bg-orange-950 text-orange-300',
  MEDIUM: 'border-yellow-800 bg-yellow-950 text-yellow-300',
  LOW: 'border-green-800 bg-green-950 text-green-300',
  INFO: 'border-blue-800 bg-blue-950 text-blue-300',
}

const vectorScores = computed(() => {
  return props.vectors.map(entry => {
    const score = calculateScoreFromVector(entry.vector)
    if (score === null) return null
    const severity = scoreSeverity(score)
    return { score, severity }
  })
})

const themeMap: Record<string, { border: string, bg: string, text: string, label: string }> = {
  purple: { border: 'border-purple-800', bg: 'bg-purple-950', text: 'text-purple-300', label: 'text-purple-400/70' },
  teal: { border: 'border-teal-800', bg: 'bg-teal-950', text: 'text-teal-300', label: 'text-teal-400/70' },
  gray: { border: 'border-gray-700', bg: 'bg-gray-900', text: 'text-gray-500', label: 'text-gray-600' },
}
</script>

<template>
  <div v-if="vectors.length" class="bg-gray-850 rounded border border-gray-700 p-2 overflow-x-auto">
    <table class="border-spacing-0" style="border-collapse: collapse">
      <thead>
        <!-- Section titles row -->
        <tr>
          <th></th>
          <th class="text-[9px] font-bold uppercase tracking-wider text-gray-600 text-left pr-3 pb-1">Vectors</th>
          <template v-if="cvssMetrics">
            <th v-for="(section, si) in cvssMetrics" :key="'title-'+section.title"
              :colspan="section.keys.length"
              class="text-[9px] font-bold uppercase tracking-wider text-gray-600 text-left pb-1"
              :class="si > 0 ? 'pl-3' : 'pl-2'"
            >{{ section.title }}</th>
          </template>
        </tr>
        <!-- Column headers row -->
        <tr>
          <th class="pr-1"></th>
          <th class="pr-3"></th>
          <template v-if="cvssMetrics">
            <th v-for="(key, ki) in allMetricKeys" :key="'hdr-'+key"
              class="text-[8px] font-semibold uppercase tracking-wider text-gray-600/80 text-center pb-0.5"
              :class="isSectionStart(ki) ? (sectionIndexAt(ki) > 0 ? 'pl-3' : 'pl-2') : 'pl-px'"
              style="min-width: 28px"
            >{{ key }}</th>
          </template>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="(entry, idx) in vectors"
          :key="idx"
          class="whitespace-nowrap group"
        >
          <!-- Label -->
          <td class="text-[9px] font-bold uppercase pr-1 align-middle py-0.5 text-right w-16 pt-2"
            :class="themeMap[entry.theme].label"
          >{{ entry.label }}</td>
          <!-- Vector string + badges -->
          <td class="px-0.5 pr-3 align-middle py-0.5">
            <span class="inline-flex items-center gap-1.5">
              <span
                class="font-mono text-[10px] tracking-tight"
                :class="themeMap[entry.theme].text"
              >{{ entry.vector }}</span>
              <span
                v-if="vectorScores[idx]"
                class="rounded-full border px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-[0.1em] shrink-0"
                :class="severityClasses[vectorScores[idx]!.severity]"
              >{{ vectorScores[idx]!.score }} {{ vectorScores[idx]!.severity }}</span>
              <span
                v-if="hasModifiers(entry.vector)"
                class="rounded-full border px-1.5 py-0.5 text-[8px] uppercase tracking-[0.1em] shrink-0"
                :class="entry.theme === 'purple' ? 'border-purple-800 bg-purple-950 text-purple-200'
                  : entry.theme === 'teal' ? 'border-teal-800 bg-teal-950 text-teal-200'
                  : 'border-gray-700 bg-gray-800 text-gray-400'"
              >env.</span>
              <span
                v-if="entry.adjusted"
                class="rounded-full border border-amber-800 bg-amber-950 px-1.5 py-0.5 text-[8px] uppercase tracking-[0.1em] text-amber-200 shrink-0"
              >adj.</span>
            </span>
          </td>
          <!-- Metric cells — compact colored blocks -->
          <template v-if="cvssMetrics">
            <td v-for="(key, ki) in allMetricKeys" :key="'m-'+key"
              class="align-middle py-0.5"
              :class="isSectionStart(ki) ? (sectionIndexAt(ki) > 0 ? 'pl-3' : 'pl-2') : 'pl-px'"
            >
              <div
                v-if="metricForRow(idx, key)"
                class="flex items-center justify-center rounded-sm text-[9px] font-bold font-mono cursor-default"
                style="min-width: 28px; height: 18px"
                :class="dangerCellClass(metricForRow(idx, key)!.danger)"
                :title="`${metricForRow(idx, key)!.label}: ${metricForRow(idx, key)!.value}`"
              >{{ metricForRow(idx, key)!.short }}</div>
              <div v-else class="flex items-center justify-center text-gray-700/50 text-[9px]" style="min-width: 28px; height: 18px">·</div>
            </td>
          </template>
        </tr>
      </tbody>
    </table>
  </div>
</template>
