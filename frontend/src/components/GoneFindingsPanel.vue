<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { CircleSlash, Loader2 } from '@lucide/vue'
import { getGoneFindings } from '../lib/api'
import type { GoneFinding, GoneFindingsOfVersion } from '../types'

// Findings Dependency-Track no longer reports, per version of the project:
// why they went, when, and what became of their assessments.
const props = defineProps<{ projectName: string }>()

const open = ref(false)
const loading = ref(false)
const error = ref('')
const versions = ref<GoneFindingsOfVersion[]>([])
const root = ref<HTMLElement | null>(null)

const REASONS: Record<string, string> = {
    replaced: 'Replaced',
    component_removed: 'Component removed',
    no_longer_matched: 'No longer matched',
    undetermined: 'Not yet determined',
    missing_at_export: 'Missing at export',
}
const CARRY_OVER: Record<string, string> = {
    carried: 'Carried over, pending review',
    conflict: 'Assessments differ, not carried',
    own_assessment: 'Successor has its own assessment',
    undetermined: 'Component unknown, not carried',
}

const total = computed(() =>
    versions.value.reduce(
        (sum, version) => sum + Object.values(version.gone || {}).reduce((a, b) => a + b, 0),
        0,
    ),
)

const byVersionDescending = (left: GoneFindingsOfVersion, right: GoneFindingsOfVersion) =>
    right.version.localeCompare(left.version, undefined, { numeric: true, sensitivity: 'base' })

const load = async () => {
    if (!props.projectName) return
    loading.value = true
    error.value = ''
    try {
        const result = await getGoneFindings(props.projectName)
        versions.value = [...(result.versions || [])].sort(byVersionDescending)
    } catch {
        versions.value = []
        error.value = 'Gone findings could not be loaded.'
    } finally {
        loading.value = false
    }
}

const when = (value: string | null | undefined) => {
    if (!value) return 'unknown'
    const date = new Date(value)
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

// Same name and version under a new ID: Dependency-Track recreated the
// component (a BOM uploaded again), nothing was replaced.
const recreated = (finding: GoneFinding) => {
    const successor = finding.successor
    return Boolean(
        finding.reason === 'replaced'
        && successor?.component_version
        && successor.component_version === finding.component_version
        && successor.component_name === finding.component_name,
    )
}

// The assessment moves to the recreated component as it was.
const carryOverLabel = (finding: GoneFinding) => {
    const carryOver = finding.carry_over || ''
    if (carryOver === 'carried' && recreated(finding)) return 'Carried over to the recreated component'
    return CARRY_OVER[carryOver] || carryOver
}

const reasonLabel = (finding: GoneFinding) => {
    if (finding.reason === 'replaced' && finding.successor) {
        const name = finding.successor.component_name || finding.successor.component_uuid
        const version = finding.successor.component_version
        if (recreated(finding)) {
            return 'Recreated by Dependency-Track (same version, new component ID)'
        }
        return `Replaced by ${name}${version ? `@${version}` : ''}`
    }
    return REASONS[finding.reason] || finding.reason
}

const wentSummary = (went: Record<string, number>) => {
    const entries = Object.entries(went || {}).filter(([, count]) => count > 0)
    const count = entries.reduce((sum, [, value]) => sum + value, 0)
    if (!count) return 'nothing went'
    const parts = entries.map(([reason, value]) => `${value} ${(REASONS[reason] || reason).toLowerCase()}`)
    return `${count} went (${parts.join(', ')})`
}

const readLine = (version: GoneFindingsOfVersion) => {
    const last = version.last_read
    if (!last) return 'Not read since gone findings are recorded.'
    return `Last read ${when(last.read_at)}: ${wentSummary(last.went)}.`
}

const component = (finding: GoneFinding) =>
    `${finding.component_name || finding.component_uuid}${finding.component_version ? `@${finding.component_version}` : ''}`

const assessmentLabel = (finding: GoneFinding) => {
    if (!finding.assessment) return 'No assessment'
    return `${finding.assessment.state} · ${finding.assessment.sync_status}`
}

// Something to show: gone findings, or an error to retry.
const available = computed(() => total.value > 0 || Boolean(error.value))

const toggle = () => {
    if (!available.value) return
    open.value = !open.value
}

const closeOnOutsideClick = (event: MouseEvent) => {
    if (open.value && root.value && !root.value.contains(event.target as Node)) open.value = false
}
const closeOnEscape = (event: KeyboardEvent) => {
    if (event.key === 'Escape') open.value = false
}

watch(() => props.projectName, () => {
    open.value = false
    void load()
})

onMounted(() => {
    void load()
    document.addEventListener('mousedown', closeOnOutsideClick)
    document.addEventListener('keydown', closeOnEscape)
})
onBeforeUnmount(() => {
    document.removeEventListener('mousedown', closeOnOutsideClick)
    document.removeEventListener('keydown', closeOnEscape)
})
</script>

<template>
    <div ref="root" class="relative shrink-0">
        <button
            type="button"
            data-testid="gone-findings-button"
            :title="available ? 'Findings Dependency-Track no longer reports' : 'No gone findings'"
            aria-haspopup="true"
            :aria-expanded="open"
            :disabled="loading || !available"
            class="inline-flex h-10 items-center gap-2 rounded-xl border border-white/10 bg-slate-950/35 px-3 text-xs font-semibold uppercase tracking-wider text-slate-200 transition-colors hover:bg-slate-900/55 hover:text-white disabled:cursor-default disabled:opacity-50 disabled:hover:bg-slate-950/35"
            @click="toggle"
        >
            <Loader2 v-if="loading" :size="14" class="animate-spin" />
            <CircleSlash v-else :size="14" />
            <span class="hidden sm:inline">Gone findings</span>
            <span
                data-testid="gone-findings-count"
                class="rounded-full bg-white/10 px-1.5 py-0.5 font-mono text-[10px]"
            >{{ error ? '!' : total }}</span>
        </button>
        <div
            v-if="open"
            data-testid="gone-findings-panel"
            class="absolute right-0 z-40 mt-2 w-[36rem] max-w-[90vw] rounded-xl border border-white/10 bg-slate-950 p-3 text-left shadow-2xl"
        >
            <div class="text-xs font-semibold text-white">Gone findings per version</div>
            <p class="mt-1 text-[11px] leading-snug text-gray-400">
                Findings Dependency-Track no longer reports. They and their assessments are kept;
                an assessment of a replaced component is carried over, pending review.
            </p>
            <div v-if="error" class="mt-3 text-xs text-red-300" role="alert">
                {{ error }}
                <button type="button" class="ml-2 underline" @click="load">Retry</button>
            </div>
            <div v-else class="mt-3 max-h-96 space-y-3 overflow-y-auto">
                <section
                    v-for="version in versions"
                    :key="version.project_uuid"
                    data-testid="gone-findings-version"
                >
                    <div class="font-mono text-xs text-gray-200">{{ version.version || '(no version)' }}</div>
                    <p data-testid="gone-findings-read" class="text-[11px] text-gray-400">{{ readLine(version) }}</p>
                    <p v-if="version.findings.length === 0" class="text-[11px] text-gray-500">No gone findings.</p>
                    <ul v-else class="mt-1 space-y-1">
                        <li
                            v-for="finding in version.findings"
                            :key="`${finding.component_uuid}/${finding.vulnerability_uuid}`"
                            data-testid="gone-finding"
                            class="rounded-lg border border-white/5 px-2 py-1.5 text-[11px] text-gray-300"
                        >
                            <div class="flex flex-wrap items-baseline gap-x-2">
                                <span class="font-mono font-semibold text-white">{{ finding.vuln_id || finding.vulnerability_uuid }}</span>
                                <span class="font-mono text-gray-300">{{ component(finding) }}</span>
                                <span data-testid="gone-finding-reason" class="text-amber-200">{{ reasonLabel(finding) }}</span>
                            </div>
                            <div class="mt-0.5 text-gray-500">
                                Gone since {{ when(finding.gone_at) }} · last seen {{ when(finding.last_seen_at) }}
                            </div>
                            <div class="mt-0.5 flex flex-wrap gap-x-2 text-gray-400">
                                <span v-if="finding.carry_over" data-testid="gone-finding-carry-over">
                                    {{ carryOverLabel(finding) }}
                                </span>
                                <span>Assessment: {{ assessmentLabel(finding) }}</span>
                            </div>
                        </li>
                    </ul>
                </section>
            </div>
        </div>
    </div>
</template>
