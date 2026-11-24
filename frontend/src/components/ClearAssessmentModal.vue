<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Eraser } from '@lucide/vue'

/**
 * Confirms clearing an assessment: one team's (or the Global one), or the
 * whole assessment. Clearing is a new revision with no decision and no
 * text for that scope, exported like any change; the previous assessment
 * stays in the history.
 */
const props = defineProps<{
    show: boolean
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
}>()

const scopeName = computed(() => props.team || 'General')
const scopeLabel = computed(() => scopeName.value.toLocaleLowerCase() === 'general' ? 'Global' : scopeName.value)
const has = (team: string) => props.assessedTeams.some(
    assessed => assessed.toLocaleLowerCase() === team.toLocaleLowerCase())
const canClearScope = computed(() =>
    has(scopeName.value) && (props.isReviewer || scopeName.value.toLocaleLowerCase() !== 'general'))
const canClearAll = computed(() => props.isReviewer && props.assessedTeams.length > 0)

const choice = ref<'scope' | 'all'>('scope')
watch(() => props.show, (visible) => {
    if (visible) choice.value = canClearScope.value ? 'scope' : 'all'
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

const confirm = () => emit('confirm', choice.value === 'all' ? null : scopeName.value)
</script>

<template>
    <teleport to="body">
        <div
            v-if="show"
            class="fixed inset-0 flex min-h-screen items-center justify-center overflow-y-auto bg-black/80 px-4 py-6"
            style="z-index: 10000"
            role="dialog"
            aria-modal="true"
            aria-labelledby="clear-assessment-title"
            data-testid="clear-assessment-modal"
            @keydown.esc="emit('close')"
        >
            <div class="w-full max-w-xl rounded-lg border border-red-700 bg-gray-800 shadow-2xl">
                <div class="flex items-center justify-between border-b border-gray-700 p-4">
                    <h3 id="clear-assessment-title" class="flex items-center gap-2 text-lg font-bold text-red-300">
                        <Eraser :size="18" aria-hidden="true" />
                        Clear assessment
                    </h3>
                    <button type="button" class="text-xl font-bold text-gray-400 hover:text-white" aria-label="Close" @click="emit('close')">✕</button>
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
                                        The SSVC decision and the response stored with it are removed too.
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
                    <button type="button" class="rounded bg-gray-700 px-4 py-2 text-sm font-bold text-white hover:bg-gray-600" @click="emit('close')">
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
        </div>
    </teleport>
</template>
