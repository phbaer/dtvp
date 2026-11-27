<script setup lang="ts">
import { computed, inject, ref, watch, type Ref } from 'vue'
import { Brush, Eraser } from '@lucide/vue'
import {
    applyAssessmentCleanup,
    previewAssessmentCleanup,
    type AssessmentCleanupPreview,
    type AssessmentCleanupRequest,
} from '../lib/api'
import {
    assessedTeamsOf,
    cleanupChanges,
    cleanupFindingKey,
    cleanupVersions,
    hasGlobalAssessmentData,
    isGeneral,
    teamStatus,
} from '../lib/assessmentCleanup'

/**
 * Confirms clearing an assessment: one team's (or the Global one), or the
 * whole assessment. Clearing is a new revision with no decision and no
 * text for that scope, exported like any change; the previous assessment
 * stays in the history.
 *
 * In the `cleanup` mode it makes the findings of the vulnerability agree:
 * it lists the versions of the assessment the findings carry, gives the
 * selected findings the version to keep or clears theirs, for the whole
 * assessment, the Global one or one team's, and shows per finding what
 * changes before anything is saved.
 */
const props = defineProps<{
    show: boolean
    /** `clear` (default) clears for every finding; `cleanup` picks versions and findings. */
    mode?: 'clear' | 'cleanup'
    /** The action on the form can clear only the assessment the user opened. */
    scopeOnly?: boolean
    /** Every finding of the vulnerability, with its project version (cleanup). */
    instances?: any[]
    /** The Repair Assessments stages that apply to this vulnerability (cleanup). */
    repairStages?: Array<{ id: string; label: string }>
    /** The team whose tab is open; empty for the General assessment. */
    team: string
    /** Teams that currently have an assessment, including "General". */
    assessedTeams: string[]
    isReviewer: boolean
    findingCount: number
    /** Project versions of the findings it applies to. */
    versions?: string[]
    /** Components of the findings it applies to. */
    components?: string[]
    busy?: boolean
    error?: string
}>()

const emit = defineEmits<{
    (e: 'close'): void
    /** `null` clears the whole assessment. */
    (e: 'confirm', team: string | null): void
    /** A cleanup was saved. */
    (e: 'cleaned'): void
    /** Switch to Repair…, which has a rule-based repair for this vulnerability. */
    (e: 'repair'): void
}>()

const scopeName = computed(() => props.team || 'General')
const scopeLabel = computed(() => scopeName.value.toLocaleLowerCase() === 'general' ? 'Global' : scopeName.value)
const has = (team: string) => props.assessedTeams.some(
    assessed => assessed.toLocaleLowerCase() === team.toLocaleLowerCase())
const canClearScope = computed(() =>
    (has(scopeName.value) || (isGeneral(scopeName.value) && hasGlobalAssessmentData(props.instances || [])))
    && (props.isReviewer || !isGeneral(scopeName.value)))
const canClearAll = computed(() => !props.scopeOnly && props.isReviewer && props.assessedTeams.length > 0)
const clearDialog = ref<HTMLDialogElement | null>(null)
watch(clearDialog, dialog => dialog?.showModal?.())

const choice = ref<'scope' | 'all'>('scope')
watch(() => props.show, (visible) => {
    if (visible) choice.value = canClearScope.value ? 'scope' : 'all'
    else if (clearDialog.value?.open) clearDialog.value.close()
})

const MAX_LISTED = 4
const listed = (values: string[] = []) => values.length > MAX_LISTED
    ? `${values.slice(0, MAX_LISTED).join(', ')} and ${values.length - MAX_LISTED} more`
    : values.join(', ')
const appliesTo = computed(() => {
    const findings = props.findingCount === 1 ? 'the finding' : `all ${props.findingCount} findings`
    const components = listed(props.components)
    const versions = listed(props.versions)
    return [
        findings,
        components ? `of ${components}` : '',
        versions ? `in ${props.versions!.length === 1 ? 'version' : 'versions'} ${versions}` : '',
    ].filter(Boolean).join(' ')
})

const confirm = () => {
    if (props.busy) return
    if (choice.value === 'scope' && canClearScope.value) emit('confirm', scopeName.value)
    else if (choice.value === 'all' && canClearAll.value) emit('confirm', null)
}

// --- cleanup ----------------------------------------------------------------

const WHOLE = '*'
// Repair stages that make the findings of a vulnerability agree; when one
// applies, the rule-based repair is the better first step.
const RESOLVING_REPAIRS = new Set(['sync_findings', 'former_teams', 'unowned_references', 'combine_conflict', 'refer_teams', 'ssvc_record', 'response'])
const resolvingRepairs = computed(() => (props.repairStages || []).filter(stage => RESOLVING_REPAIRS.has(stage.id)))
const teamMapping = inject<Ref<Record<string, string | string[]>>>('teamMapping', ref({}))
const findings = computed(() => props.instances || [])
const versions = computed(() => cleanupVersions(findings.value))
const keep = ref(0)
const kept = computed(() => versions.value[keep.value] ?? versions.value[0])
const labelOf = computed(() => {
    const labels = new Map<any, string>()
    for (const version of versions.value) {
        for (const instance of version.variant.instances) labels.set(instance, version.variant.label)
    }
    return labels
})
const teams = computed(() => assessedTeamsOf(findings.value))
const scopeOptions = computed(() => [
    ...(props.isReviewer ? [{ value: WHOLE, label: 'The whole assessment', status: null }] : []),
    ...(props.isReviewer && hasGlobalAssessmentData(findings.value) && !teams.value.some(isGeneral)
        ? [{ value: 'General', label: 'The Global assessment', status: null }] : []),
    ...teams.value
        .filter(team => props.isReviewer || !isGeneral(team))
        .map(team => ({
            value: team,
            label: isGeneral(team) ? 'The Global assessment' : `${team}'s assessment`,
            status: teamStatus(team, teamMapping.value),
        })),
])
const scope = ref(WHOLE)
const action = ref<'apply' | 'clear'>('apply')
const selected = ref(new Set<string>())
const preview = ref<AssessmentCleanupPreview[] | null>(null)
const previewedFor = ref('')
const cleanupBusy = ref(false)
const cleanupError = ref('')

const keptHasScope = computed(() => {
    if (!kept.value) return false
    if (scope.value === WHOLE) return kept.value.variant.state !== 'NOT_SET' || Boolean(kept.value.variant.details.trim())
    return kept.value.teams.some(team => team.toLocaleLowerCase() === scope.value.toLocaleLowerCase())
})
const scopeLabel2 = computed(() => scopeOptions.value.find(option => option.value === scope.value)?.label || '')

const selectDiffering = () => {
    const keptInstances = new Set(kept.value?.variant.instances || [])
    selected.value = new Set(findings.value.filter(instance => !keptInstances.has(instance)).map(cleanupFindingKey))
}
const selectAll = () => {
    selected.value = new Set(findings.value.map(cleanupFindingKey))
}
const toggle = (instance: any) => {
    const next = new Set(selected.value)
    const key = cleanupFindingKey(instance)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    selected.value = next
}

watch(() => [props.show, props.mode] as const, ([visible, mode]) => {
    if (!visible || mode !== 'cleanup') return
    keep.value = 0
    const own = scopeOptions.value.find(option => option.value.toLocaleLowerCase() === (props.team || '').toLocaleLowerCase())
    scope.value = props.isReviewer ? WHOLE : (own?.value || scopeOptions.value[0]?.value || '')
    action.value = 'apply'
    preview.value = null
    cleanupError.value = ''
    selectDiffering()
}, { immediate: true })
watch(keep, () => {
    selectDiffering()
})

const request = computed<AssessmentCleanupRequest>(() => {
    const source = kept.value?.variant.instances[0]
    return {
        instances: findings.value
            .filter(instance => selected.value.has(cleanupFindingKey(instance)))
            .map(instance => ({
                finding_uuid: instance.finding_uuid,
                project_uuid: instance.project_uuid,
                component_uuid: instance.component_uuid,
                vulnerability_uuid: instance.vulnerability_uuid,
            })),
        action: action.value,
        team: scope.value === WHOLE ? null : scope.value,
        source: action.value === 'apply' && source
            ? { project_uuid: source.project_uuid, component_uuid: source.component_uuid, vulnerability_uuid: source.vulnerability_uuid }
            : null,
    }
})
const requestKey = computed(() => JSON.stringify(request.value))
const previewCurrent = computed(() => preview.value !== null && previewedFor.value === requestKey.value)
const changed = computed(() => (previewCurrent.value ? preview.value!.filter(entry => entry.changed) : []))
const unchangedCount = computed(() => (previewCurrent.value ? preview.value!.length - changed.value.length : 0))
const canPreview = computed(() => (
    !cleanupBusy.value
    && scopeOptions.value.length > 0
    && request.value.instances.length > 0
    && (action.value === 'clear' || keptHasScope.value)
))

const findingOf = (entry: AssessmentCleanupPreview) => findings.value.find(
    instance => cleanupFindingKey(instance) === cleanupFindingKey(entry))
const describe = (instance: any) => [
    instance?.project_version || '(unknown version)',
    [instance?.component_name, instance?.component_version].filter(Boolean).join(' '),
].filter(Boolean).join(' · ')
const stateText = (state: string) => (state || 'NOT_SET').replaceAll('_', ' ').toLowerCase()

const errorText = (err: any, fallback: string) => (err?.response?.status === 409
    ? 'The assessment changed since the preview. Preview again.'
    : err?.response?.data?.detail || err?.message || fallback)

const runPreview = async () => {
    if (!canPreview.value) return
    cleanupBusy.value = true
    cleanupError.value = ''
    const key = requestKey.value
    try {
        preview.value = await previewAssessmentCleanup(request.value)
        previewedFor.value = key
    } catch (err: any) {
        preview.value = null
        cleanupError.value = errorText(err, 'The preview failed.')
    } finally {
        cleanupBusy.value = false
    }
}

const applyCleanup = async () => {
    if (!previewCurrent.value || changed.value.length === 0 || cleanupBusy.value) return
    cleanupBusy.value = true
    cleanupError.value = ''
    const revisions: Record<string, number> = {}
    for (const entry of preview.value!) {
        revisions[cleanupFindingKey(entry)] = entry.revision
        if (request.value.source && entry.source_revision != null) {
            revisions[cleanupFindingKey(request.value.source)] = entry.source_revision
        }
    }
    try {
        await applyAssessmentCleanup({ ...request.value, revisions })
        emit('cleaned')
    } catch (err: any) {
        preview.value = null
        cleanupError.value = errorText(err, 'The cleanup could not be saved.')
    } finally {
        cleanupBusy.value = false
    }
}
</script>

<template>
    <teleport to="body">
        <dialog
            v-if="show && mode !== 'cleanup'"
            ref="clearDialog"
            class="m-auto max-h-[calc(100dvh-2rem)] w-[calc(100%-2rem)] max-w-xl overflow-y-auto rounded-lg border border-red-700 bg-gray-800 text-gray-200 shadow-2xl backdrop:bg-black/80"
            aria-labelledby="clear-assessment-title"
            data-testid="clear-assessment-modal"
            @cancel.prevent="!busy && emit('close')"
        >
            <div>
                <div class="flex items-center justify-between border-b border-gray-700 p-4">
                    <h3 id="clear-assessment-title" class="flex items-center gap-2 text-lg font-bold text-red-300">
                        <Eraser :size="18" aria-hidden="true" />
                        Clear assessment
                    </h3>
                    <button type="button" class="text-xl font-bold text-gray-400 hover:text-white" aria-label="Close" :disabled="busy" @click="emit('close')">✕</button>
                </div>

                <div class="space-y-3 p-4 text-sm text-gray-200">
                    <p v-if="!canClearScope && !canClearAll" data-testid="clear-nothing">
                        There is nothing here you can clear.
                        <template v-if="!isReviewer && assessedTeams.length > 0">
                            Open a team's tab to clear that team's assessment; only reviewers can clear the Global assessment.
                        </template>
                    </p>
                    <template v-else>
                        <label v-if="canClearScope" class="flex items-start gap-2">
                            <input v-model="choice" type="radio" value="scope" class="mt-1" data-testid="clear-scope" />
                            <span>
                                Only the <strong>{{ scopeLabel }}</strong> assessment
                                <span class="block text-xs text-gray-400">
                                    Its decision and text are removed. Other teams' assessments stay as they are.
                                    <template v-if="scopeName.toLocaleLowerCase() === 'general'">
                                        Rescoring, SSVC, response, suppression, Global rationale and Awaiting review are cleared too.
                                        Team decisions, rationale, authors and change requests are kept.
                                        Any remaining team verdicts determine the effective state.
                                    </template>
                                </span>
                            </span>
                        </label>
                        <label v-if="canClearAll" class="flex items-start gap-2">
                            <input v-model="choice" type="radio" value="all" class="mt-1" data-testid="clear-all" />
                            <span>
                                The <strong>whole assessment</strong>
                                <span class="block text-xs text-gray-400">
                                    Every team's assessment, the Global assessment, rescoring, SSVC, and suppression.
                                    The vulnerability is open again.
                                </span>
                            </span>
                        </label>
                        <p class="rounded border border-gray-700 bg-gray-900/60 p-2 text-xs text-gray-300" data-testid="clear-applies-to">
                            This applies to {{ appliesTo }}. It is saved as a new revision without a decision or text
                            for what is cleared and exported, so Dependency-Track is cleared as well.
                            The previous assessment stays in the history.
                            <template v-if="!isReviewer && assessedTeams.length > 1"> What remains of the assessment goes to review.</template>
                        </p>
                    </template>
                    <p v-if="error" role="alert" class="rounded border border-red-800 bg-red-900/30 p-2 text-xs text-red-300">{{ error }}</p>
                </div>

                <div class="flex justify-end gap-3 border-t border-gray-700 p-4">
                    <button type="button" autofocus :disabled="busy" class="rounded bg-gray-700 px-4 py-2 text-sm font-bold text-white hover:bg-gray-600" @click="emit('close')">
                        Cancel
                    </button>
                    <button
                        type="button"
                        class="rounded bg-red-600 px-4 py-2 text-sm font-bold text-white hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                        :disabled="busy || (!canClearScope && !canClearAll)"
                        data-testid="clear-confirm"
                        @click="confirm"
                    >
                        {{ busy ? 'Clearing…' : 'Clear' }}
                    </button>
                </div>
            </div>
        </dialog>
        <div
            v-if="show && mode === 'cleanup'"
            class="fixed inset-0 flex min-h-screen items-center justify-center overflow-y-auto bg-black/80 px-4 py-6"
            style="z-index: 10000"
            role="dialog"
            aria-modal="true"
            aria-labelledby="cleanup-assessment-title"
            data-testid="cleanup-assessment-modal"
            @keydown.esc="emit('close')"
        >
            <div class="flex max-h-[calc(100vh-3rem)] w-full max-w-4xl flex-col rounded-lg border border-indigo-600 bg-gray-800 shadow-2xl">
                <div class="flex items-center justify-between border-b border-gray-700 p-4">
                    <h3 id="cleanup-assessment-title" class="flex items-center gap-2 text-lg font-bold text-indigo-200">
                        <Brush :size="18" aria-hidden="true" />
                        Clean up assessment
                    </h3>
                    <button type="button" class="text-xl font-bold text-gray-400 hover:text-white" aria-label="Close" @click="emit('close')">✕</button>
                </div>

                <div class="min-h-0 flex-1 space-y-4 overflow-y-auto p-4 text-sm text-gray-200">
                    <p class="text-xs text-gray-300" data-testid="cleanup-summary">
                        <template v-if="versions.length > 1">
                            The {{ findings.length }} findings carry {{ versions.length }} versions of the assessment.
                            Keep one, choose the findings to change, and check the preview before saving.
                        </template>
                        <template v-else>
                            {{ findings.length === 1 ? 'The finding carries one assessment.' : `All ${findings.length} findings carry the same assessment.` }} You can still clear one team's assessment from some of them.
                        </template>
                    </p>

                    <div
                        v-if="resolvingRepairs.length > 0"
                        class="flex flex-wrap items-center justify-between gap-2 rounded border border-amber-600/40 bg-amber-950/20 p-2 text-xs text-amber-100"
                        data-testid="cleanup-repair-hint"
                    >
                        <span>
                            Repair Assessments has a rule-based repair for this vulnerability
                            ({{ resolvingRepairs.map(stage => stage.label).join(', ') }}), which may make the findings agree without choosing a version.
                        </span>
                        <button
                            type="button"
                            class="rounded border border-amber-500/60 px-2 py-1 text-[11px] font-bold text-amber-100 hover:bg-amber-900/40"
                            data-testid="cleanup-switch-to-repair"
                            @click="emit('repair')"
                        >
                            Repair instead…
                        </button>
                    </div>

                    <fieldset v-if="versions.length > 0" class="space-y-2">
                        <legend class="mb-1 text-[10px] font-bold uppercase tracking-wider text-gray-500">Versions of the assessment</legend>
                        <label
                            v-for="(version, index) in versions"
                            :key="version.variant.label"
                            class="flex cursor-pointer items-start gap-2 rounded border p-2"
                            :class="keep === index ? 'border-indigo-500/60 bg-indigo-950/30' : 'border-gray-700 bg-gray-900/40'"
                            data-testid="cleanup-version"
                        >
                            <input v-model="keep" type="radio" :value="index" class="mt-1" :aria-label="`Keep version ${version.variant.label}`" data-testid="cleanup-keep" />
                            <span class="min-w-0 flex-1">
                                <span class="flex flex-wrap items-center gap-2">
                                    <span class="rounded bg-indigo-500/25 px-1.5 py-0.5 font-mono text-xs font-bold text-indigo-100">{{ version.variant.label }}</span>
                                    <strong>{{ version.variant.instances.length }} finding{{ version.variant.instances.length === 1 ? '' : 's' }}</strong>
                                    <span class="text-xs text-gray-400">{{ stateText(version.variant.state) }}</span>
                                    <span v-if="keep === index" class="text-[10px] font-bold uppercase text-indigo-300">kept</span>
                                </span>
                                <span class="mt-0.5 block text-[11px] text-gray-400">
                                    {{ [...new Set(version.variant.instances.map(describe))].join(', ') }}
                                </span>
                                <span v-if="version.teams.length" class="mt-0.5 block text-[11px] text-gray-500">
                                    Teams: {{ version.teams.map(team => isGeneral(team) ? 'Global' : team).join(', ') }}
                                </span>
                                <dl v-if="version.differences.length" class="mt-1 grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-3 gap-y-0.5 text-[11px]" data-testid="cleanup-version-differences">
                                    <template v-for="difference in version.differences" :key="difference.key">
                                        <dt class="text-indigo-200/80">{{ difference.label }}</dt>
                                        <dd class="whitespace-pre-wrap break-words" :class="difference.value ? 'text-gray-200' : 'text-gray-500'">{{ difference.value || (difference.key.split(':').length === 2 ? '(no assessment)' : '(none)') }}</dd>
                                    </template>
                                </dl>
                            </span>
                        </label>
                    </fieldset>

                    <div class="grid gap-3 sm:grid-cols-2">
                        <label class="block text-xs">
                            <span class="mb-1 block text-[10px] font-bold uppercase tracking-wider text-gray-500">What to clean up</span>
                            <select v-model="scope" class="w-full rounded border border-gray-600 bg-gray-900 px-2 py-1.5 text-sm text-gray-100" data-testid="cleanup-scope">
                                <option v-for="option in scopeOptions" :key="option.value" :value="option.value">
                                    {{ option.label }}{{ option.status === 'unknown' ? ' (not in the team mapping)' : option.status === 'alias' ? ' (an alias in the team mapping)' : '' }}
                                </option>
                            </select>
                            <span v-if="!isReviewer" class="mt-1 block text-[11px] text-gray-500">Only reviewers clean up the Global or the whole assessment.</span>
                        </label>
                        <fieldset class="text-xs">
                            <legend class="mb-1 text-[10px] font-bold uppercase tracking-wider text-gray-500">On the selected findings</legend>
                            <label class="flex items-start gap-2">
                                <input v-model="action" type="radio" value="apply" class="mt-0.5" data-testid="cleanup-action-apply" />
                                <span>Use version <strong>{{ kept?.variant.label }}</strong> for {{ scopeLabel2.toLocaleLowerCase() }}</span>
                            </label>
                            <label class="mt-1 flex items-start gap-2">
                                <input v-model="action" type="radio" value="clear" class="mt-0.5" data-testid="cleanup-action-clear" />
                                <span>Clear {{ scopeLabel2.toLocaleLowerCase() }}<template v-if="scope === WHOLE">: the findings are open again</template></span>
                            </label>
                            <p v-if="action === 'apply' && !keptHasScope" class="mt-1 text-[11px] text-amber-300" data-testid="cleanup-scope-missing">
                                Version {{ kept?.variant.label }} has no {{ scopeLabel2.toLocaleLowerCase() }} to use. Keep another version, or clear it.
                            </p>
                        </fieldset>
                    </div>

                    <div>
                        <div class="mb-1 flex flex-wrap items-center justify-between gap-2">
                            <span class="text-[10px] font-bold uppercase tracking-wider text-gray-500">Findings ({{ request.instances.length }} of {{ findings.length }} selected)</span>
                            <span class="flex gap-2 text-[11px]">
                                <button type="button" class="text-indigo-300 hover:text-indigo-100" data-testid="cleanup-select-differing" @click="selectDiffering">Those not on {{ kept?.variant.label }}</button>
                                <button type="button" class="text-indigo-300 hover:text-indigo-100" data-testid="cleanup-select-all" @click="selectAll">All</button>
                            </span>
                        </div>
                        <div class="max-h-48 overflow-y-auto rounded border border-gray-700">
                            <table class="w-full text-left text-xs">
                                <tbody>
                                    <tr v-for="instance in findings" :key="cleanupFindingKey(instance)" class="border-t border-gray-800 first:border-t-0" data-testid="cleanup-finding">
                                        <td class="w-6 px-2 py-1">
                                            <input
                                                type="checkbox"
                                                :checked="selected.has(cleanupFindingKey(instance))"
                                                :aria-label="`Change ${describe(instance)}`"
                                                @change="toggle(instance)"
                                            />
                                        </td>
                                        <td class="px-2 py-1 font-mono text-gray-200">{{ describe(instance) }}</td>
                                        <td class="px-2 py-1 text-gray-400">{{ stateText(instance.analysis_state) }}</td>
                                        <td class="px-2 py-1 text-right"><span class="rounded bg-black/30 px-1 font-mono">{{ labelOf.get(instance) }}</span></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div v-if="previewCurrent" class="rounded border border-gray-700 bg-gray-900/60 p-2 text-xs" data-testid="cleanup-preview">
                        <p class="mb-1 font-semibold text-gray-200">
                            {{ changed.length === 0 ? 'Nothing would change.' : `${changed.length} finding${changed.length === 1 ? '' : 's'} would change:` }}
                        </p>
                        <ul class="space-y-1">
                            <li v-for="entry in changed" :key="cleanupFindingKey(entry)" data-testid="cleanup-preview-row">
                                <span class="font-mono text-gray-200">{{ describe(findingOf(entry)) }}</span>:
                                <template v-if="entry.before.state !== entry.after!.state">{{ stateText(entry.before.state) }} → {{ stateText(entry.after!.state) }}</template>
                                <template v-else>{{ stateText(entry.after!.state) }}</template>
                                <span class="text-gray-400">· {{ cleanupChanges(entry.before, entry.after).join(', ') }}</span>
                            </li>
                        </ul>
                        <p v-if="unchangedCount" class="mt-1 text-gray-400">{{ unchangedCount }} selected finding{{ unchangedCount === 1 ? '' : 's' }} already match{{ unchangedCount === 1 ? 'es' : '' }} and stay as {{ unchangedCount === 1 ? 'it is' : 'they are' }}.</p>
                        <p class="mt-1 text-gray-400">
                            Each change is saved as a new revision and exported to Dependency-Track; the previous assessment stays in the history.
                            <template v-if="!isReviewer"> Your change goes to review.</template>
                        </p>
                    </div>
                    <p v-if="cleanupError" role="alert" class="rounded border border-red-800 bg-red-900/30 p-2 text-xs text-red-300">{{ cleanupError }}</p>
                </div>

                <div class="flex justify-end gap-3 border-t border-gray-700 p-4">
                    <button type="button" class="rounded bg-gray-700 px-4 py-2 text-sm font-bold text-white hover:bg-gray-600" @click="emit('close')">
                        Cancel
                    </button>
                    <button
                        type="button"
                        class="rounded border border-indigo-500 px-4 py-2 text-sm font-bold text-indigo-100 hover:bg-indigo-900/50 disabled:cursor-not-allowed disabled:opacity-50"
                        :disabled="!canPreview"
                        data-testid="cleanup-preview-button"
                        @click="runPreview"
                    >
                        {{ cleanupBusy && !previewCurrent ? 'Checking…' : 'Preview' }}
                    </button>
                    <button
                        type="button"
                        class="rounded bg-indigo-600 px-4 py-2 text-sm font-bold text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
                        :disabled="!previewCurrent || changed.length === 0 || cleanupBusy"
                        data-testid="cleanup-confirm"
                        @click="applyCleanup"
                    >
                        {{ cleanupBusy && previewCurrent ? 'Saving…' : changed.length ? `Save for ${changed.length} finding${changed.length === 1 ? '' : 's'}` : 'Save' }}
                    </button>
                </div>
            </div>
        </div>
    </teleport>
</template>
