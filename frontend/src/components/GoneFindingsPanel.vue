<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Check, ChevronDown, ChevronRight, CircleSlash, Loader2, Undo2, X } from '@lucide/vue'
import { acknowledgeGoneFindings, applyGoneFindingToAlias, confirmGoneFindingSameIssue, getGoneFindings } from '../lib/api'
import {
    REASONS,
    attentionCount,
    byVersionDescending,
    carryOverLabel,
    componentLabel,
    goneCount,
    groupFindings,
    reasonKey,
    reasonLabel,
} from '../lib/goneFindings'
import type { GoneFinding, GoneFindingsOfVersion } from '../types'

// Findings Dependency-Track no longer reports, per version of the project.
// By default only those that need a person: an assessment that did not
// carry over to anything. Acknowledging one hides it for everyone; the full
// picture is in the project statistics.
// Acknowledging is for reviewers; others see the acknowledgements only.
const props = withDefaults(defineProps<{ projectName: string, canAcknowledge?: boolean }>(), { canAcknowledge: false })

const open = ref(false)
const loading = ref(false)
const error = ref('')
const versions = ref<GoneFindingsOfVersion[]>([])
const view = ref<'attention' | 'all'>('attention')
const showAcknowledged = ref(false)
const reasonFilter = ref<Set<string>>(new Set())
const search = ref('')
const versionFilter = ref('')
const toggled = ref<Set<string>>(new Set())
const busy = ref(false)
const actionError = ref('')

const total = computed(() => goneCount(versions.value))
const attention = computed(() => attentionCount(versions.value))

// Versions in which many findings went no longer matched at the last read:
// a change in matching (other CPEs in a new BOM, an analyzer change).
const massNotices = computed(() =>
    versions.value
        .filter(version => version.last_read?.mass_disappearance)
        .map(version => ({ version, mass: version.last_read!.mass_disappearance! })),
)
const massLine = (notice: { version: GoneFindingsOfVersion, mass: { count: number, share: number } }) =>
    `${notice.version.version || '(no version)'}: ${notice.mass.count} findings went no longer matched at the last read`
    + ` (${Math.round(notice.mass.share * 100)}% of the findings)`

const disagreements = computed(() =>
    versions.value.flatMap(version =>
        (version.alias_disagreements || []).map(item => ({ version, item })),
    ),
)
// Pairs that are probably one issue without an alias: apart, as guesses.
const sameIssueDisagreements = computed(() =>
    versions.value.flatMap(version =>
        (version.same_issue_disagreements || []).map(item => ({ version, item })),
    ),
)

const buttonTitle = computed(() => {
    if (!available.value) return 'No gone findings'
    const lines = [`${attention.value} gone finding(s) need attention, ${total.value} gone in all`]
    for (const notice of massNotices.value) lines.push(massLine(notice))
    return lines.join('\n')
})

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

const assessmentLabel = (finding: GoneFinding) => {
    if (!finding.assessment) return 'No assessment'
    return `${finding.assessment.state} · ${finding.assessment.sync_status}`
}

// Which findings the chosen view shows, before the reason filter.
const inView = (finding: GoneFinding) => {
    if (finding.acknowledged_by) return showAcknowledged.value
    return view.value === 'all' || Boolean(finding.needs_attention)
}

const matchesSearch = (finding: GoneFinding) => {
    const term = search.value.trim().toLowerCase()
    if (!term) return true
    return [finding.vuln_id, finding.vulnerability_uuid, componentLabel(finding), finding.component_purl]
        .some(value => String(value || '').toLowerCase().includes(term))
}

const scopedVersions = computed(() =>
    versions.value.filter(version => !versionFilter.value || version.project_uuid === versionFilter.value),
)

// Counts per reason of what the view shows: the filter chips.
const reasonCounts = computed(() => {
    const counts: Record<string, number> = {}
    for (const version of scopedVersions.value) {
        for (const finding of version.findings) {
            if (!inView(finding) || !matchesSearch(finding)) continue
            const key = reasonKey(finding)
            counts[key] = (counts[key] || 0) + 1
        }
    }
    return Object.entries(counts).sort(
        (a, b) => b[1] - a[1] || (REASONS[a[0]] || a[0]).localeCompare(REASONS[b[0]] || b[0]),
    )
})

const shown = computed(() =>
    scopedVersions.value
        .map(version => {
            const findings = version.findings.filter(finding =>
                inView(finding)
                && matchesSearch(finding)
                && (reasonFilter.value.size === 0 || reasonFilter.value.has(reasonKey(finding))),
            )
            return { version, findings, groups: groupFindings(findings) }
        })
        .filter(item => item.findings.length > 0 || versionFilter.value),
)

const shownCount = computed(() => shown.value.reduce((sum, item) => sum + item.findings.length, 0))

// Small lists open fully; large ones open per group.
const openByDefault = computed(() => shownCount.value <= 25)
const isOpen = (key: string) => openByDefault.value !== toggled.value.has(key)
const toggleGroup = (key: string) => {
    const next = new Set(toggled.value)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    toggled.value = next
}

const toggleReason = (reason: string) => {
    const next = new Set(reasonFilter.value)
    if (next.has(reason)) next.delete(reason)
    else next.add(reason)
    reasonFilter.value = next
}

const acknowledge = async (projectUuid: string, findings: GoneFinding[], acknowledged = true) => {
    const refs = findings
        .filter(finding => Boolean(finding.acknowledged_by) !== acknowledged)
        .map(finding => ({ component_uuid: finding.component_uuid, vulnerability_uuid: finding.vulnerability_uuid }))
    if (refs.length === 0 || busy.value) return
    busy.value = true
    actionError.value = ''
    try {
        await acknowledgeGoneFindings(projectUuid, refs, acknowledged)
        await load()
    } catch {
        actionError.value = acknowledged
            ? 'The findings could not be acknowledged.'
            : 'The acknowledgement could not be withdrawn.'
    } finally {
        busy.value = false
    }
}

const unacknowledged = (findings: GoneFinding[]) => findings.filter(finding => !finding.acknowledged_by)
const riskyOpen = (findings: GoneFinding[]) => unacknowledged(findings).filter(finding => finding.risky)

// A group acknowledge that would cover exploitable, in-triage or ticketed
// findings asks first, naming them; one finding at a time needs no question.
type PendingGroup = { key: string; projectUuid: string; findings: GoneFinding[]; risky: GoneFinding[] }
const pendingGroup = ref<PendingGroup | null>(null)
// Inside v-for the template ref is an array; only one confirm is ever open.
const confirmButton = ref<HTMLButtonElement | HTMLButtonElement[] | null>(null)
const RISKY_LISTED = 5

const acknowledgeGroup = async (key: string, projectUuid: string, findings: GoneFinding[]) => {
    const risky = riskyOpen(findings)
    if (risky.length === 0) {
        await acknowledge(projectUuid, findings)
        return
    }
    pendingGroup.value = { key, projectUuid, findings: unacknowledged(findings), risky }
    await nextTick()
    const button = Array.isArray(confirmButton.value) ? confirmButton.value[0] : confirmButton.value
    button?.focus()
}

const confirmGroup = async () => {
    const pending = pendingGroup.value
    if (!pending) return
    pendingGroup.value = null
    await acknowledge(pending.projectUuid, pending.findings)
}

const cancelGroup = () => {
    pendingGroup.value = null
}

const riskyLine = (finding: GoneFinding) => [
    finding.vuln_id || finding.vulnerability_uuid,
    componentLabel(finding),
    finding.assessment?.state,
    (finding.tickets || []).join(', '),
].filter(Boolean).join(' · ')

const applied = ref<Set<string>>(new Set())
const applyToAlias = async (projectUuid: string, finding: GoneFinding) => {
    const alias = finding.alias
    if (!alias || !alias.proposal || busy.value) return
    busy.value = true
    actionError.value = ''
    try {
        await applyGoneFindingToAlias(
            projectUuid, finding.component_uuid, finding.vulnerability_uuid, alias.vulnerability_uuid, alias.component_uuid,
        )
        applied.value = new Set([...applied.value, `${finding.component_uuid}/${finding.vulnerability_uuid}`])
        await load()
    } catch {
        actionError.value = `The assessment could not be applied to ${alias.vuln_id || 'the other finding'}.`
    } finally {
        busy.value = false
    }
}

// A guess (no source links the two): a reviewer confirms it first, then
// applies it like an alias.
const confirmSameIssue = async (projectUuid: string, finding: GoneFinding, confirmed = true) => {
    const guess = finding.same_issue
    if (!guess || busy.value) return
    busy.value = true
    actionError.value = ''
    try {
        await confirmGoneFindingSameIssue(
            projectUuid, finding.component_uuid, finding.vulnerability_uuid,
            guess.component_uuid, guess.vulnerability_uuid, confirmed,
        )
        await load()
    } catch {
        actionError.value = `The match with ${guess.vuln_id || 'the other finding'} could not be ${confirmed ? 'confirmed' : 'withdrawn'}.`
    } finally {
        busy.value = false
    }
}
const applyToSameIssue = async (projectUuid: string, finding: GoneFinding) => {
    const guess = finding.same_issue
    if (!guess || !guess.confirmed_by || !guess.proposal || busy.value) return
    busy.value = true
    actionError.value = ''
    try {
        await applyGoneFindingToAlias(
            projectUuid, finding.component_uuid, finding.vulnerability_uuid, guess.vulnerability_uuid, guess.component_uuid,
        )
        applied.value = new Set([...applied.value, `${finding.component_uuid}/${finding.vulnerability_uuid}`])
        await load()
    } catch {
        actionError.value = `The assessment could not be applied to ${guess.vuln_id || 'the other finding'}.`
    } finally {
        busy.value = false
    }
}

const available = computed(() => total.value > 0 || Boolean(error.value))

const toggle = () => {
    if (!available.value) return
    open.value = !open.value
}

const closeOnEscape = (event: KeyboardEvent) => {
    if (event.key !== 'Escape') return
    // Escape first cancels an open confirmation, then closes the dialog.
    if (pendingGroup.value) {
        pendingGroup.value = null
        return
    }
    open.value = false
}

watch(() => props.projectName, () => {
    open.value = false
    void load()
})

onMounted(() => {
    void load()
    document.addEventListener('keydown', closeOnEscape)
})
onBeforeUnmount(() => {
    document.removeEventListener('keydown', closeOnEscape)
})
</script>

<template>
    <div class="relative shrink-0">
        <button
            type="button"
            data-testid="gone-findings-button"
            :title="buttonTitle"
            aria-haspopup="dialog"
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
                class="rounded-full px-1.5 py-0.5 font-mono text-[10px]"
                :class="attention > 0 || error ? 'bg-amber-500/25 text-amber-100' : 'bg-white/10'"
            >{{ error ? '!' : attention }}</span>
        </button>
        <Teleport to="body">
            <div
                v-if="open"
                class="fixed inset-0 z-[10000] flex items-start justify-center bg-[#0a0a12]/70 p-4 pt-16 backdrop-blur-sm"
                data-testid="gone-findings-backdrop"
                @mousedown.self="open = false"
            >
                <div
                    data-testid="gone-findings-panel"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="gone-findings-title"
                    class="flex max-h-[85vh] w-full max-w-4xl flex-col overflow-hidden rounded-xl border border-white/10 bg-slate-950 text-left shadow-2xl"
                >
                    <header class="border-b border-white/10 p-4">
                        <div class="flex items-start justify-between gap-3">
                            <div>
                                <h2 id="gone-findings-title" class="text-sm font-semibold text-white">Gone findings</h2>
                                <p class="mt-1 text-[11px] leading-snug text-gray-400">
                                    Findings Dependency-Track no longer reports. Shown first: those whose
                                    assessment did not carry over to anything, and those that were
                                    exploitable, in triage or ticketed, whatever the reason they went.
                                    Acknowledge them once looked at; that hides them for everyone. All
                                    counts and the trend are in the project statistics.
                                </p>
                            </div>
                            <button
                                type="button"
                                class="rounded-lg p-1 text-gray-400 hover:bg-white/10 hover:text-white"
                                aria-label="Close"
                                data-testid="gone-findings-close"
                                @click="open = false"
                            >
                                <X :size="16" />
                            </button>
                        </div>
                        <div class="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
                            <div class="inline-flex overflow-hidden rounded-lg border border-white/10" role="group" aria-label="View">
                                <button
                                    type="button"
                                    data-testid="gone-findings-view-attention"
                                    class="px-2 py-1"
                                    :class="view === 'attention' ? 'bg-amber-500/25 text-amber-100' : 'text-gray-300 hover:bg-white/5'"
                                    :aria-pressed="view === 'attention'"
                                    @click="view = 'attention'"
                                >Needs attention ({{ attention }})</button>
                                <button
                                    type="button"
                                    data-testid="gone-findings-view-all"
                                    class="border-l border-white/10 px-2 py-1"
                                    :class="view === 'all' ? 'bg-white/15 text-white' : 'text-gray-300 hover:bg-white/5'"
                                    :aria-pressed="view === 'all'"
                                    @click="view = 'all'"
                                >All ({{ total }})</button>
                            </div>
                            <label class="inline-flex items-center gap-1 text-gray-300">
                                <input v-model="showAcknowledged" type="checkbox" data-testid="gone-findings-show-acknowledged" />
                                Show acknowledged
                            </label>
                            <select
                                v-if="versions.length > 1"
                                v-model="versionFilter"
                                data-testid="gone-findings-version-filter"
                                class="rounded-lg border border-white/10 bg-slate-900 px-2 py-1 text-gray-200"
                                aria-label="Version"
                            >
                                <option value="">All versions</option>
                                <option v-for="version in versions" :key="version.project_uuid" :value="version.project_uuid">
                                    {{ version.version || '(no version)' }}
                                </option>
                            </select>
                            <input
                                v-model="search"
                                type="search"
                                data-testid="gone-findings-search"
                                placeholder="Search vulnerability or component"
                                class="min-w-[12rem] flex-1 rounded-lg border border-white/10 bg-slate-900 px-2 py-1 text-gray-200 placeholder:text-gray-500"
                            />
                        </div>
                        <div
                            v-for="notice in massNotices"
                            :key="notice.version.project_uuid"
                            data-testid="gone-findings-mass"
                            role="status"
                            class="mt-2 rounded-lg border border-amber-400/40 bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-100"
                        >
                            {{ massLine(notice) }}. A change in matching, such as other CPEs in a new BOM:
                            check that the findings that went were not real issues.
                        </div>
                        <div v-if="reasonCounts.length" class="mt-2 flex flex-wrap gap-1.5" data-testid="gone-findings-reasons">
                            <button
                                v-for="[reason, count] in reasonCounts"
                                :key="reason"
                                type="button"
                                data-testid="gone-findings-reason-chip"
                                class="rounded-full border px-2 py-0.5 text-[11px]"
                                :class="reasonFilter.has(reason)
                                    ? 'border-amber-300/60 bg-amber-500/20 text-amber-100'
                                    : 'border-white/10 text-gray-300 hover:bg-white/5'"
                                :aria-pressed="reasonFilter.has(reason)"
                                @click="toggleReason(reason)"
                            >{{ REASONS[reason] || reason }} · {{ count }}</button>
                        </div>
                    </header>

                    <div class="min-h-0 flex-1 overflow-y-auto p-4">
                        <div v-if="error" class="text-xs text-red-300" role="alert">
                            {{ error }}
                            <button type="button" class="ml-2 underline" @click="load">Retry</button>
                        </div>
                        <template v-else>
                            <div v-if="actionError" class="mb-2 text-xs text-red-300" role="alert">{{ actionError }}</div>
                            <p v-if="shown.length === 0" data-testid="gone-findings-empty" class="text-xs text-gray-400">
                                {{ view === 'attention'
                                    ? 'Nothing needs attention. Choose All to see every gone finding.'
                                    : 'No gone findings match.' }}
                            </p>
                            <section
                                v-for="item in shown"
                                :key="item.version.project_uuid"
                                data-testid="gone-findings-version"
                                class="mb-4"
                            >
                                <div class="flex items-baseline gap-2">
                                    <div class="font-mono text-xs text-gray-200">{{ item.version.version || '(no version)' }}</div>
                                    <span class="text-[11px] text-gray-500">{{ item.findings.length }} shown</span>
                                </div>
                                <p data-testid="gone-findings-read" class="text-[11px] text-gray-400">{{ readLine(item.version) }}</p>
                                <div
                                    v-for="group in item.groups"
                                    :key="group.key"
                                    data-testid="gone-findings-reason-group"
                                    class="mt-2 rounded-lg border border-white/5"
                                >
                                    <div class="flex items-center gap-2 px-2 py-1.5">
                                        <button
                                            type="button"
                                            class="flex flex-1 items-center gap-1 text-left text-[11px] font-semibold text-amber-200"
                                            :aria-expanded="isOpen(`${item.version.project_uuid}|${group.key}`)"
                                            data-testid="gone-findings-reason-toggle"
                                            @click="toggleGroup(`${item.version.project_uuid}|${group.key}`)"
                                        >
                                            <ChevronDown v-if="isOpen(`${item.version.project_uuid}|${group.key}`)" :size="12" />
                                            <ChevronRight v-else :size="12" />
                                            {{ group.label }}
                                            <span class="font-normal text-gray-400">· {{ group.count }} finding(s), {{ group.components.length }} component(s)</span>
                                            <span
                                                v-if="riskyOpen(group.components.flatMap(c => c.findings)).length"
                                                class="font-normal text-red-300"
                                                data-testid="gone-findings-reason-risky"
                                            >· {{ riskyOpen(group.components.flatMap(c => c.findings)).length }} risky</span>
                                        </button>
                                        <button
                                            v-if="props.canAcknowledge && unacknowledged(group.components.flatMap(c => c.findings)).length"
                                            type="button"
                                            :disabled="busy"
                                            data-testid="gone-findings-acknowledge-reason"
                                            class="inline-flex items-center gap-1 rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-200 hover:bg-white/10 disabled:opacity-50"
                                            @click="acknowledgeGroup(`${item.version.project_uuid}|${group.key}`, item.version.project_uuid, group.components.flatMap(c => c.findings))"
                                        ><Check :size="11" /> Acknowledge all</button>
                                    </div>
                                    <div
                                        v-if="pendingGroup && pendingGroup.key === `${item.version.project_uuid}|${group.key}`"
                                        role="alertdialog"
                                        aria-label="Acknowledge risky findings"
                                        data-testid="gone-findings-risky-confirm"
                                        class="mx-2 mb-2 rounded-md border border-amber-400/40 bg-amber-950/40 p-2 text-[11px] text-amber-100"
                                    >
                                        <p>
                                            {{ pendingGroup.risky.length }} of the {{ pendingGroup.findings.length }} finding(s) were exploitable,
                                            in triage or ticketed. Acknowledging hides them for everyone.
                                        </p>
                                        <ul class="mt-1 list-disc pl-4 font-mono text-[10px]" data-testid="gone-findings-risky-list">
                                            <li v-for="finding in pendingGroup.risky.slice(0, RISKY_LISTED)" :key="`${finding.component_uuid}/${finding.vulnerability_uuid}`">
                                                {{ riskyLine(finding) }}
                                            </li>
                                            <li v-if="pendingGroup.risky.length > RISKY_LISTED" class="list-none font-sans text-amber-200/80">
                                                and {{ pendingGroup.risky.length - RISKY_LISTED }} more
                                            </li>
                                        </ul>
                                        <div class="mt-2 flex gap-2">
                                            <button
                                                ref="confirmButton"
                                                type="button"
                                                :disabled="busy"
                                                data-testid="gone-findings-risky-confirm-yes"
                                                class="rounded-md border border-amber-300/50 px-2 py-0.5 text-[10px] font-semibold hover:bg-amber-400/20"
                                                @click="confirmGroup"
                                            >Acknowledge {{ pendingGroup.findings.length }}, including {{ pendingGroup.risky.length }} risky</button>
                                            <button
                                                type="button"
                                                data-testid="gone-findings-risky-confirm-cancel"
                                                class="rounded-md border border-white/10 px-2 py-0.5 text-[10px] hover:bg-white/10"
                                                @click="cancelGroup"
                                            >Cancel</button>
                                        </div>
                                    </div>
                                    <div v-if="isOpen(`${item.version.project_uuid}|${group.key}`)" class="space-y-1 px-2 pb-2">
                                        <div
                                            v-for="component in group.components"
                                            :key="component.key"
                                            data-testid="gone-findings-component-group"
                                            class="rounded-md bg-white/[0.02]"
                                        >
                                            <div class="flex items-center gap-2 px-2 py-1">
                                                <button
                                                    type="button"
                                                    class="flex flex-1 items-center gap-1 text-left font-mono text-[11px] text-gray-200"
                                                    :aria-expanded="isOpen(`${item.version.project_uuid}|${group.key}|${component.key}`)"
                                                    data-testid="gone-findings-component-toggle"
                                                    @click="toggleGroup(`${item.version.project_uuid}|${group.key}|${component.key}`)"
                                                >
                                                    <ChevronDown v-if="isOpen(`${item.version.project_uuid}|${group.key}|${component.key}`)" :size="12" />
                                                    <ChevronRight v-else :size="12" />
                                                    {{ component.label }}
                                                    <span class="font-sans text-gray-500">· {{ component.findings.length }}</span>
                                                    <span
                                                        v-if="riskyOpen(component.findings).length"
                                                        class="font-sans text-red-300"
                                                        data-testid="gone-findings-component-risky"
                                                    >· {{ riskyOpen(component.findings).length }} risky</span>
                                                </button>
                                                <button
                                                    v-if="props.canAcknowledge && unacknowledged(component.findings).length"
                                                    type="button"
                                                    :disabled="busy"
                                                    data-testid="gone-findings-acknowledge-component"
                                                    class="inline-flex items-center gap-1 rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-200 hover:bg-white/10 disabled:opacity-50"
                                                    @click="acknowledgeGroup(`${item.version.project_uuid}|${group.key}|${component.key}`, item.version.project_uuid, component.findings)"
                                                ><Check :size="11" /> Acknowledge</button>
                                            </div>
                                            <div
                                        v-if="pendingGroup && pendingGroup.key === `${item.version.project_uuid}|${group.key}|${component.key}`"
                                        role="alertdialog"
                                        aria-label="Acknowledge risky findings"
                                        data-testid="gone-findings-risky-confirm"
                                        class="mx-2 mb-2 rounded-md border border-amber-400/40 bg-amber-950/40 p-2 text-[11px] text-amber-100"
                                    >
                                        <p>
                                            {{ pendingGroup.risky.length }} of the {{ pendingGroup.findings.length }} finding(s) were exploitable,
                                            in triage or ticketed. Acknowledging hides them for everyone.
                                        </p>
                                        <ul class="mt-1 list-disc pl-4 font-mono text-[10px]" data-testid="gone-findings-risky-list">
                                            <li v-for="finding in pendingGroup.risky.slice(0, RISKY_LISTED)" :key="`${finding.component_uuid}/${finding.vulnerability_uuid}`">
                                                {{ riskyLine(finding) }}
                                            </li>
                                            <li v-if="pendingGroup.risky.length > RISKY_LISTED" class="list-none font-sans text-amber-200/80">
                                                and {{ pendingGroup.risky.length - RISKY_LISTED }} more
                                            </li>
                                        </ul>
                                        <div class="mt-2 flex gap-2">
                                            <button
                                                ref="confirmButton"
                                                type="button"
                                                :disabled="busy"
                                                data-testid="gone-findings-risky-confirm-yes"
                                                class="rounded-md border border-amber-300/50 px-2 py-0.5 text-[10px] font-semibold hover:bg-amber-400/20"
                                                @click="confirmGroup"
                                            >Acknowledge {{ pendingGroup.findings.length }}, including {{ pendingGroup.risky.length }} risky</button>
                                            <button
                                                type="button"
                                                data-testid="gone-findings-risky-confirm-cancel"
                                                class="rounded-md border border-white/10 px-2 py-0.5 text-[10px] hover:bg-white/10"
                                                @click="cancelGroup"
                                            >Cancel</button>
                                        </div>
                                    </div>
                                            <ul v-if="isOpen(`${item.version.project_uuid}|${group.key}|${component.key}`)" class="space-y-1 px-2 pb-1.5">
                                                <li
                                                    v-for="finding in component.findings"
                                                    :key="`${finding.component_uuid}/${finding.vulnerability_uuid}`"
                                                    data-testid="gone-finding"
                                                    class="rounded-md border border-white/5 px-2 py-1 text-[11px] text-gray-300"
                                                    :class="finding.acknowledged_by ? 'opacity-60' : ''"
                                                >
                                                    <div class="flex flex-wrap items-baseline gap-x-2">
                                                        <span class="font-mono font-semibold text-white">{{ finding.vuln_id || finding.vulnerability_uuid }}</span>
                                                        <span data-testid="gone-finding-reason" class="text-amber-200">{{ reasonLabel(finding) }}</span>
                                                        <span v-if="props.canAcknowledge" class="ml-auto">
                                                            <button
                                                                v-if="!finding.acknowledged_by"
                                                                type="button"
                                                                :disabled="busy"
                                                                data-testid="gone-finding-acknowledge"
                                                                class="inline-flex items-center gap-1 rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-200 hover:bg-white/10 disabled:opacity-50"
                                                                @click="acknowledge(item.version.project_uuid, [finding])"
                                                            ><Check :size="11" /> Acknowledge</button>
                                                            <button
                                                                v-else
                                                                type="button"
                                                                :disabled="busy"
                                                                data-testid="gone-finding-withdraw"
                                                                class="inline-flex items-center gap-1 rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-300 hover:bg-white/10 disabled:opacity-50"
                                                                @click="acknowledge(item.version.project_uuid, [finding], false)"
                                                            ><Undo2 :size="11" /> Withdraw</button>
                                                        </span>
                                                    </div>
                                                    <div class="mt-0.5 text-gray-500">
                                                        Gone since {{ when(finding.gone_at) }} · last seen {{ when(finding.last_seen_at) }}
                                                    </div>
                                                    <div class="mt-0.5 flex flex-wrap gap-x-2 text-gray-400">
                                                        <span v-if="finding.carry_over" data-testid="gone-finding-carry-over">
                                                            {{ carryOverLabel(finding) }}
                                                        </span>
                                                        <span>Assessment: {{ assessmentLabel(finding) }}</span>
                                                        <span v-if="finding.tickets?.length" data-testid="gone-finding-tickets">
                                                            Tickets: {{ finding.tickets.join(', ') }}
                                                        </span>
                                                        <span v-if="finding.acknowledged_by" data-testid="gone-finding-acknowledged">
                                                            Acknowledged by {{ finding.acknowledged_by }}, {{ when(finding.acknowledged_at) }}
                                                        </span>
                                                    </div>
                                                    <div v-if="finding.cause" data-testid="gone-finding-cause" class="mt-0.5 break-all text-gray-400">
                                                        {{ finding.cause }}
                                                    </div>
                                                    <div
                                                        v-if="finding.alias"
                                                        data-testid="gone-finding-alias"
                                                        class="mt-0.5 flex flex-wrap items-baseline gap-x-2"
                                                        :class="finding.alias.disagrees ? 'text-amber-200' : 'text-sky-200'"
                                                    >
                                                        <span>
                                                            Still reported as {{ finding.alias.vuln_id }}: {{ finding.alias.state }}{{
                                                                finding.alias.tickets.length ? ` (${finding.alias.tickets.join(', ')})` : '' }}{{
                                                                finding.alias.disagrees ? ', a different assessment' : '' }}
                                                        </span>
                                                        <button
                                                            v-if="props.canAcknowledge && finding.alias.proposal"
                                                            type="button"
                                                            :disabled="busy"
                                                            data-testid="gone-finding-apply-alias"
                                                            class="rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-200 hover:bg-white/10 disabled:opacity-50"
                                                            :title="finding.alias.proposal === 'copy'
                                                                ? 'Copy this assessment to it, pending review'
                                                                : 'Add the team blocks it lacks as historical blocks, pending review'"
                                                            @click="applyToAlias(item.version.project_uuid, finding)"
                                                        >Apply to {{ finding.alias.vuln_id }}</button>
                                                        <span
                                                            v-if="applied.has(`${finding.component_uuid}/${finding.vulnerability_uuid}`)"
                                                            data-testid="gone-finding-applied"
                                                            class="text-emerald-300"
                                                        >Applied, pending review</span>
                                                    </div>
                                                    <div
                                                        v-if="finding.same_issue"
                                                        data-testid="gone-finding-same-issue"
                                                        class="mt-0.5 flex flex-wrap items-baseline gap-x-2"
                                                        :class="finding.same_issue.disagrees ? 'text-amber-200' : 'text-violet-200'"
                                                    >
                                                        <span>
                                                            Probably the same as {{ finding.same_issue.vuln_id }} ({{ finding.same_issue.reason }}):
                                                            {{ finding.same_issue.state }}{{
                                                                finding.same_issue.tickets.length ? ` (${finding.same_issue.tickets.join(', ')})` : '' }}{{
                                                                finding.same_issue.disagrees ? ', a different assessment' : '' }}{{
                                                                finding.same_issue.confirmed_by ? ` · confirmed by ${finding.same_issue.confirmed_by}` : '' }}
                                                        </span>
                                                        <template v-if="props.canAcknowledge">
                                                            <button
                                                                v-if="!finding.same_issue.confirmed_by"
                                                                type="button"
                                                                :disabled="busy"
                                                                data-testid="gone-finding-confirm-same-issue"
                                                                class="rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-200 hover:bg-white/10 disabled:opacity-50"
                                                                title="No source links the two; confirm that they are one issue before applying anything"
                                                                @click="confirmSameIssue(item.version.project_uuid, finding)"
                                                            >Confirm same issue</button>
                                                            <template v-else>
                                                                <button
                                                                    v-if="finding.same_issue.proposal"
                                                                    type="button"
                                                                    :disabled="busy"
                                                                    data-testid="gone-finding-apply-same-issue"
                                                                    class="rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-200 hover:bg-white/10 disabled:opacity-50"
                                                                    :title="finding.same_issue.proposal === 'copy'
                                                                        ? 'Copy this assessment to it, pending review'
                                                                        : 'Add the team blocks it lacks as historical blocks, pending review'"
                                                                    @click="applyToSameIssue(item.version.project_uuid, finding)"
                                                                >Apply to {{ finding.same_issue.vuln_id }}</button>
                                                                <button
                                                                    type="button"
                                                                    :disabled="busy"
                                                                    data-testid="gone-finding-withdraw-same-issue"
                                                                    class="rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] text-gray-300 hover:bg-white/10 disabled:opacity-50"
                                                                    @click="confirmSameIssue(item.version.project_uuid, finding, false)"
                                                                >Not the same</button>
                                                            </template>
                                                        </template>
                                                    </div>
                                                </li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>
                            </section>
                        <!-- Below the findings and collapsed: these lists can be long
                             and must never push the findings out of view. -->
                        <details
                            v-if="disagreements.length || sameIssueDisagreements.length"
                            data-testid="gone-findings-duplicates"
                            class="mt-4 rounded-lg border border-white/10 px-2 py-1.5"
                        >
                            <summary class="cursor-pointer text-[11px] font-semibold text-gray-200">
                                {{ disagreements.length + sameIssueDisagreements.length }}
                                probable duplicate{{ disagreements.length + sameIssueDisagreements.length === 1 ? '' : 's' }}
                                with different assessments
                            </summary>
                            <div class="max-h-60 overflow-y-auto">
                            <div
                                v-if="disagreements.length"
                                data-testid="gone-findings-disagreements"
                                class="mt-2 text-[11px] text-gray-300"
                            >
                                <div class="font-semibold text-gray-200">One vulnerability, two ids, different assessments</div>
                                <div v-for="entry in disagreements" :key="`${entry.version.project_uuid}/${entry.item.component_uuid}/${entry.item.findings.map(f => f.vuln_id).join('/')}`">
                                    <span class="font-mono">{{ entry.item.component_name || entry.item.component_uuid }}{{ entry.item.component_version ? `@${entry.item.component_version}` : '' }}</span>
                                    ({{ entry.version.version || '(no version)' }}):
                                    {{ entry.item.findings.map(f => `${f.vuln_id} ${f.state}`).join(' · ') }}
                                </div>
                            </div>
                            <div
                                v-if="sameIssueDisagreements.length"
                                data-testid="gone-findings-same-issue-disagreements"
                                class="mt-2 text-[11px] text-gray-300"
                            >
                                <div class="font-semibold text-gray-200">Probably one issue, two ids, different assessments</div>
                                <div v-for="entry in sameIssueDisagreements" :key="`${entry.version.project_uuid}/${entry.item.component_uuid}/${entry.item.findings.map(f => f.vuln_id).join('/')}`">
                                    <span class="font-mono">{{ entry.item.component_name || entry.item.component_uuid }}{{ entry.item.component_version ? `@${entry.item.component_version}` : '' }}</span>
                                    ({{ entry.version.version || '(no version)' }}):
                                    {{ entry.item.findings.map(f => `${f.vuln_id} ${f.state}`).join(' · ') }}
                                    <span class="text-gray-500">({{ entry.item.reason }}; no source links them)</span>
                                </div>
                            </div>
                            </div>
                        </details>
                        </template>
                    </div>
                </div>
            </div>
        </Teleport>
    </div>
</template>
