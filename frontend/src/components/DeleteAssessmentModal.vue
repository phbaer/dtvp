<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Trash2 } from '@lucide/vue'

const props = defineProps<{
    show: boolean
    /** The team whose tab is open; empty for the General assessment. */
    team: string
    /** Teams that currently have an assessment, including "General". */
    assessedTeams: string[]
    isReviewer: boolean
    findingCount: number
    busy?: boolean
    error?: string
}>()

const emit = defineEmits<{
    (e: 'close'): void
    /** `null` deletes the whole assessment. */
    (e: 'confirm', team: string | null): void
}>()

const scopeName = computed(() => props.team || 'General')
const has = (team: string) => props.assessedTeams.some(
    assessed => assessed.toLocaleLowerCase() === team.toLocaleLowerCase())
const canDeleteScope = computed(() =>
    has(scopeName.value) && (props.isReviewer || scopeName.value.toLocaleLowerCase() !== 'general'))
const canDeleteAll = computed(() => props.isReviewer && props.assessedTeams.length > 0)

const choice = ref<'scope' | 'all'>('scope')
watch(() => props.show, (visible) => {
    if (visible) choice.value = canDeleteScope.value ? 'scope' : 'all'
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
            aria-labelledby="delete-assessment-title"
            data-testid="delete-assessment-modal"
            @keydown.esc="emit('close')"
        >
            <div class="w-full max-w-xl rounded-lg border border-red-700 bg-gray-800 shadow-2xl">
                <div class="flex items-center justify-between border-b border-gray-700 p-4">
                    <h3 id="delete-assessment-title" class="flex items-center gap-2 text-lg font-bold text-red-300">
                        <Trash2 :size="18" aria-hidden="true" />
                        Delete assessment
                    </h3>
                    <button type="button" class="text-xl font-bold text-gray-400 hover:text-white" aria-label="Close" @click="emit('close')">✕</button>
                </div>

                <div class="space-y-3 p-4 text-sm text-gray-200">
                    <p v-if="!canDeleteScope && !canDeleteAll" data-testid="delete-nothing">
                        There is nothing here you can delete.
                        <template v-if="!isReviewer && assessedTeams.length > 0">
                            Open a team's tab to delete that team's assessment; only reviewers can delete the General assessment.
                        </template>
                    </p>
                    <template v-else>
                        <label v-if="canDeleteScope" class="flex items-start gap-2">
                            <input v-model="choice" type="radio" value="scope" class="mt-1" data-testid="delete-scope" />
                            <span>
                                Only the <strong>{{ scopeName }}</strong> assessment
                                <span class="block text-xs text-gray-400">
                                    Other teams' assessments stay as they are.
                                    <template v-if="scopeName.toLocaleLowerCase() === 'general'">
                                        The SSVC decision stored with it is removed too.
                                    </template>
                                </span>
                            </span>
                        </label>
                        <label v-if="canDeleteAll" class="flex items-start gap-2">
                            <input v-model="choice" type="radio" value="all" class="mt-1" data-testid="delete-all" />
                            <span>
                                The <strong>whole assessment</strong>
                                <span class="block text-xs text-gray-400">
                                    Every team's assessment, the General assessment, rescoring, SSVC, and suppression.
                                    The vulnerability is open again.
                                </span>
                            </span>
                        </label>
                        <p class="rounded border border-gray-700 bg-gray-900/60 p-2 text-xs text-gray-300">
                            This applies to {{ findingCount === 1 ? 'the finding' : `all ${findingCount} findings` }} of this
                            vulnerability and is exported, so it is removed from Dependency-Track as well.
                            The deleted text stays in the history.
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
                        :disabled="busy || (!canDeleteScope && !canDeleteAll)"
                        data-testid="delete-confirm"
                        @click="confirm"
                    >
                        {{ busy ? 'Deleting…' : 'Delete' }}
                    </button>
                </div>
            </div>
        </div>
    </teleport>
</template>
